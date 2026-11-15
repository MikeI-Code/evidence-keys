#!/usr/bin/env python3
"""Verify a Key Regulatory evidence file offline, with nothing but our public key.

Usage:
    kr-verify.py report.pdf --key key-regulatory-evidence.pem
    kr-verify.py --code 'kr5.xxxx.yyyy' --key key-regulatory-evidence.pem

The only dependency is ``cryptography`` (``pip install cryptography``). Nothing is fetched
from the network and nothing is sent to Key Regulatory.

For a PDF it checks, in order:

1. the PDF signature (PAdES): it covers the whole file, the file's digest matches the signed
   digest, and the signature verifies under the key you supplied;
2. the RFC 3161 timestamp token in the signature: it is over this signature, and the
   timestamp authority's signature over it verifies under the certificate the token carries
   (the authority's certificate chain is not checked here: Adobe Reader or
   ``openssl ts -verify`` do that, see VERIFY.md);
3. the ``kr5`` code in the embedded ``record.json``: it verifies under your key;
4. ``record.json``: its payload recomputes the content hash the code signs.

Only the key you pass with ``--key`` is trusted. The ``.pem`` embedded in the PDF is compared
with it and reported, never trusted.

A valid result means Key Regulatory issued this file and it has not been altered since the
timestamped time. It is not a statement about compliance, does not approve publication and
is not legal advice.

Exit status: 0 when every check passed, 1 otherwise, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

NOTICE = (
    "A valid result means Key Regulatory issued this file and it has not been altered since "
    "the timestamped time. It is not a statement about compliance, does not approve "
    "publication and is not legal advice."
)
RECORD_FORMAT = "kr-evidence-record/1"
PEM_MARKER = b"# Key Regulatory evidence signing key"

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
DIGESTS = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
    "1.3.14.3.2.26": hashes.SHA1,
}
SIG_DIGESTS = {  # signature algorithms that name their own digest
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
    "1.2.840.113549.1.1.5": hashes.SHA1,
}


class VerifyError(Exception):
    """A check failed; the message says which."""


# --- DER -----------------------------------------------------------------------------------
class Der:
    """One DER element: ``tag``, ``body`` (contents) and ``raw`` (header plus contents)."""

    def __init__(self, data: bytes, pos: int = 0):
        if pos + 2 > len(data):
            raise VerifyError("truncated DER")
        self.tag = data[pos]
        length = data[pos + 1]
        start = pos + 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4 or start + n > len(data):
                raise VerifyError("unsupported DER length")
            length = int.from_bytes(data[start : start + n], "big")
            start += n
        end = start + length
        if end > len(data):
            raise VerifyError("truncated DER")
        self.body = data[start:end]
        self.raw = data[pos:end]
        self.end = end

    def children(self) -> list[Der]:
        out, pos = [], 0
        while pos < len(self.body):
            child = Der(self.body, pos)
            out.append(child)
            pos = child.end
        return out

    def oid(self) -> str:
        if self.tag != 0x06:
            raise VerifyError("expected an OID")
        b = self.body
        parts = [b[0] // 40, b[0] % 40]
        value = 0
        for byte in b[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(value)
                value = 0
        return ".".join(str(p) for p in parts)


def _attributes(element: Der) -> dict[str, list[Der]]:
    out: dict[str, list[Der]] = {}
    for attr in element.children():
        oid_el, values = attr.children()[:2]
        out[oid_el.oid()] = values.children()
    return out


def _signed_data(content_info: bytes) -> Der:
    ci = Der(content_info)
    kids = ci.children()
    if ci.tag != 0x30 or kids[0].oid() != OID_SIGNED_DATA:
        raise VerifyError("not a CMS SignedData")
    return kids[1].children()[0]


def _parts(signed_data: Der) -> tuple[Der, list[x509.Certificate], Der]:
    """(encapContentInfo, certificates, the one SignerInfo)."""
    encap, certs, signer_infos = None, [], None
    for child in signed_data.children()[2:]:
        if child.tag == 0x30 and encap is None:
            encap = child
        elif child.tag == 0xA0:
            for cert in child.children():
                if cert.tag == 0x30:
                    certs.append(x509.load_der_x509_certificate(cert.raw))
        elif child.tag == 0x31:
            signer_infos = child
    if encap is None or signer_infos is None or len(signer_infos.children()) != 1:
        raise VerifyError("expected exactly one signer")
    return encap, certs, signer_infos.children()[0]


def _signer_info(si: Der) -> dict:
    kids = si.children()
    out = {"digest_oid": kids[2].children()[0].oid(), "signed_attrs": None, "unsigned": {}}
    i = 3
    if kids[i].tag == 0xA0:
        out["signed_attrs"] = kids[i]
        i += 1
    out["sig_alg"] = kids[i].children()[0].oid()
    out["signature"] = kids[i + 1].body
    if len(kids) > i + 2 and kids[i + 2].tag == 0xA1:
        out["unsigned"] = _attributes(kids[i + 2])
    if out["signed_attrs"] is None:
        raise VerifyError("the signature has no signed attributes")
    return out


def _signed_attrs_der(element: Der) -> bytes:
    """Signed attributes as signed: the [0] IMPLICIT tag replaced by SET OF."""
    return b"\x31" + element.raw[1:]


def _hash(algorithm: type[hashes.HashAlgorithm], data: bytes) -> bytes:
    h = hashes.Hash(algorithm())
    h.update(data)
    return h.finalize()


def _verify_with(public, signature: bytes, data: bytes, digest, sig_alg: str) -> None:
    algorithm = SIG_DIGESTS.get(sig_alg, digest)
    if isinstance(public, ec.EllipticCurvePublicKey):
        public.verify(signature, data, ec.ECDSA(algorithm()))
    elif isinstance(public, rsa.RSAPublicKey):
        public.verify(signature, data, padding.PKCS1v15(), algorithm())
    else:
        raise VerifyError("unsupported key type")


# --- Keys and codes -------------------------------------------------------------------------
def load_trusted_key(path: Path) -> ec.EllipticCurvePublicKey:
    data = path.read_bytes()
    m = re.search(rb"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----", data, re.S)
    if m:
        key = serialization.load_pem_public_key(m.group(0))
    else:
        key = x509.load_pem_x509_certificate(data).public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise VerifyError("the key file does not hold an EC public key")
    return key


def fingerprint(key) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    d = hashlib.sha256(der).hexdigest()
    return " ".join(d[i : i + 8] for i in range(0, 64, 8))


def _b64u(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise VerifyError("malformed code")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_code(code: str, key, *, allow_dev: bool) -> dict:
    code = "".join(code.split())
    parts = code.split(".")
    if len(parts) != 3 or parts[0] != "kr5":
        raise VerifyError("not a kr5 code")
    payload, sig = _b64u(parts[1]), _b64u(parts[2])
    if len(sig) != 64:
        raise VerifyError("malformed code signature")
    fields = payload.decode("ascii").split("|")
    if len(fields) != 8 or fields[0] != "kr5":
        raise VerifyError("malformed code payload")
    _, kid, kind, record_id, at_ms, scope, content_hash, hash_version = fields
    if kid.startswith("dev-") and not allow_dev:
        raise VerifyError(f"the code is signed with a development key ({kid})")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        key.verify(der, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerifyError("the code's signature does not verify under this key") from exc
    short = hashlib.sha256(sig).hexdigest()[:8].upper()
    return {
        "kid": kid,
        "kind": kind,
        "id": record_id,
        "generated_at_ms": int(at_ms),
        "scope": scope,
        "content_hash": content_hash,
        "hash_version": hash_version,
        "short_reference": f"{short[:4]}-{short[4:]}",
    }


# --- PDF ------------------------------------------------------------------------------------
_STREAM_RE = re.compile(rb"<<(.*?)>>\s*stream\r?\n", re.S)


def _streams(data: bytes):
    """Every stream in the file as (dictionary bytes, decoded content). Best effort."""
    for m in _STREAM_RE.finditer(data):
        head = m.group(1)
        length = re.search(rb"/Length\s+(\d+)(?!\s+\d+\s+R)", head)
        start = m.end()
        if length:
            body = data[start : start + int(length.group(1))]
        else:
            end = data.find(b"endstream", start)
            body = data[start:end] if end > 0 else b""
        if b"/FlateDecode" in head:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                continue
        yield head, body


def embedded_files(data: bytes) -> dict[str, bytes]:
    """``record.json`` and the ``.pem`` among the PDF's embedded files, by content."""
    out: dict[str, bytes] = {}
    for head, body in _streams(data):
        if b"/EmbeddedFile" not in head:
            continue
        if body.startswith(PEM_MARKER):
            out["pem"] = body
            continue
        try:
            doc = json.loads(body)
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("format") == RECORD_FORMAT:
            if "record" in out:
                raise VerifyError("the file carries more than one record.json")
            out["record"] = body
    return out


def pdf_signature(data: bytes) -> tuple[bytes, bytes]:
    """(the signed bytes, the CMS blob) of the file's one signature, which must cover it all."""
    ranges = re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data)
    if not ranges:
        raise VerifyError("the PDF is not signed")
    if len(ranges) != 1:
        raise VerifyError("the PDF carries more than one signature")
    a, b, c, d = (int(x) for x in ranges[0])
    if a != 0 or c + d != len(data) or not b < c:
        raise VerifyError(
            "the signature does not cover the whole file (it was changed after signing)"
        )
    hole = data[b:c]
    if not (hole.startswith(b"<") and hole.endswith(b">")):
        raise VerifyError("malformed signature placeholder")
    try:
        blob = bytes.fromhex(hole[1:-1].decode("ascii"))
    except ValueError as exc:
        raise VerifyError("malformed signature contents") from exc
    cms = Der(blob)
    return data[a : a + b] + data[c : c + d], cms.raw


def extract(data: bytes, out_dir: Path) -> list[str]:
    """Write the parts ``openssl`` checks (VERIFY.md) into ``out_dir``; returns the names."""
    out_dir.mkdir(parents=True, exist_ok=True)
    signed, cms = pdf_signature(data)
    _, _, si_el = _parts(_signed_data(cms))
    si = _signer_info(si_el)
    parts = {
        "signed-bytes.bin": signed,
        "signature.p7s": cms,
        "signature-value.bin": si["signature"],
    }
    tokens = si["unsigned"].get(OID_TIMESTAMP_TOKEN)
    if tokens:
        parts["timestamp.tst"] = tokens[0].raw
    files = embedded_files(data)
    if "record" in files:
        parts["record.json"] = files["record"]
        code = "".join(json.loads(files["record"])["code"].split()).split(".")
        payload, sig = _b64u(code[1]), _b64u(code[2])
        parts["code-payload.txt"] = payload
        parts["code-signature.der"] = encode_dss_signature(
            int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        )
    if "pem" in files:
        parts["embedded-key.pem"] = files["pem"]
    for name, blob in parts.items():
        (out_dir / name).write_bytes(blob)
    return sorted(parts)


def check_pdf_signature(signed: bytes, cms: bytes, key) -> dict:
    encap, certs, si_el = _parts(_signed_data(cms))
    si = _signer_info(si_el)
    digest = DIGESTS.get(si["digest_oid"])
    if digest is None:
        raise VerifyError("unsupported digest")
    attrs = _attributes(si["signed_attrs"])
    md = attrs.get(OID_MESSAGE_DIGEST)
    if not md or md[0].body != _hash(digest, signed):
        raise VerifyError(
            "the file's digest does not match the signed digest (the file was altered)"
        )
    try:
        _verify_with(
            key, si["signature"], _signed_attrs_der(si["signed_attrs"]), digest, si["sig_alg"]
        )
    except InvalidSignature as exc:
        raise VerifyError("the PDF signature does not verify under this key") from exc
    out = {
        "signer_certificate_matches_key": any(
            c.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            == key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            for c in certs
        )
    }
    tokens = si["unsigned"].get(OID_TIMESTAMP_TOKEN)
    if not tokens:
        raise VerifyError("the signature carries no RFC 3161 timestamp")
    out.update(check_timestamp(tokens[0].raw, si["signature"]))
    return out


def check_timestamp(token: bytes, signature_value: bytes) -> dict:
    encap, certs, si_el = _parts(_signed_data(token))
    kids = encap.children()
    if kids[0].oid() != OID_TST_INFO:
        raise VerifyError("the timestamp token holds no TSTInfo")
    tst_der = kids[1].children()[0].body
    tst = Der(tst_der).children()
    imprint = tst[2].children()
    imprint_alg = DIGESTS.get(imprint[0].children()[0].oid())
    if imprint_alg is None or imprint[1].body != _hash(imprint_alg, signature_value):
        raise VerifyError("the timestamp is not over this signature")
    gen_time = tst[4].body.decode("ascii")
    si = _signer_info(si_el)
    digest = DIGESTS.get(si["digest_oid"])
    if digest is None:
        raise VerifyError("unsupported timestamp digest")
    md = _attributes(si["signed_attrs"]).get(OID_MESSAGE_DIGEST)
    if not md or md[0].body != _hash(digest, tst_der):
        raise VerifyError("the timestamp token was altered")
    signed_attrs = _signed_attrs_der(si["signed_attrs"])
    for cert in certs:
        try:
            _verify_with(cert.public_key(), si["signature"], signed_attrs, digest, si["sig_alg"])
        except (InvalidSignature, VerifyError, TypeError, ValueError):
            continue
        return {
            "timestamp": f"{gen_time[0:4]}-{gen_time[4:6]}-{gen_time[6:8]}T"
            f"{gen_time[8:10]}:{gen_time[10:12]}:{gen_time[12:]}",
            "timestamp_authority": cert.subject.rfc4514_string(),
        }
    raise VerifyError("the timestamp authority's signature does not verify")


def check_record(record_bytes: bytes, code_facts: dict, code: str) -> dict:
    record = json.loads(record_bytes)
    if "".join(str(record.get("code", "")).split()) != "".join(code.split()):
        raise VerifyError("record.json does not carry the code that was checked")
    canon = json.dumps(record["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    recomputed = hashlib.sha256(canon.encode("ascii")).hexdigest()
    if recomputed != code_facts["content_hash"]:
        raise VerifyError("record.json does not recompute the content hash the code signs")
    return {"content_hash_recomputed": recomputed}


def verify_pdf(data: bytes, key, *, allow_dev: bool) -> dict:
    result: dict = {"key_fingerprint": fingerprint(key)}
    signed, cms = pdf_signature(data)
    result.update(check_pdf_signature(signed, cms, key))
    files = embedded_files(data)
    if "record" not in files:
        raise VerifyError("the file carries no record.json")
    record = json.loads(files["record"])
    result["code"] = verify_code(record["code"], key, allow_dev=allow_dev)
    result.update(check_record(files["record"], result["code"], record["code"]))
    if "pem" in files:
        try:
            embedded = load_trusted_key_bytes(files["pem"])
            result["embedded_key_matches"] = fingerprint(embedded) == result["key_fingerprint"]
        except (VerifyError, ValueError):
            result["embedded_key_matches"] = False
    return result


def load_trusted_key_bytes(data: bytes):
    m = re.search(rb"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----", data, re.S)
    if not m:
        raise VerifyError("no public key")
    return serialization.load_pem_public_key(m.group(0))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Key Regulatory evidence file offline.")
    parser.add_argument("pdf", nargs="?", help="the evidence PDF")
    parser.add_argument("--key", help="key-regulatory-evidence.pem you trust")
    parser.add_argument("--code", help="check a kr5 code on its own (from a printout)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--extract", metavar="DIR", help="write the parts openssl checks to DIR")
    parser.add_argument(
        "--allow-dev-key", action="store_true", help="accept a development (dev-) kid"
    )
    args = parser.parse_args(argv)
    if not args.pdf and not args.code:
        parser.error("give a PDF or --code")
    if args.extract:
        if not args.pdf:
            parser.error("--extract needs a PDF")
        for name in extract(Path(args.pdf).read_bytes(), Path(args.extract)):
            print(Path(args.extract) / name)
        return 0
    if not args.key:
        parser.error("--key is required")
    try:
        key = load_trusted_key(Path(args.key))
        if args.pdf:
            result = verify_pdf(Path(args.pdf).read_bytes(), key, allow_dev=args.allow_dev_key)
        else:
            result = {"code": verify_code(args.code, key, allow_dev=args.allow_dev_key)}
        result = {"valid": True, **result, "notice": NOTICE}
    except (VerifyError, ValueError, KeyError, IndexError, OSError) as exc:
        result = {"valid": False, "reason": str(exc) or type(exc).__name__, "notice": NOTICE}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("VALID" if result["valid"] else f"INVALID: {result['reason']}")
        for k, v in result.items():
            if k not in ("valid", "reason", "notice"):
                print(f"  {k}: {v}")
        print(NOTICE)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())

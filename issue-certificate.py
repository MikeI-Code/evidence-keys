#!/usr/bin/env python3
"""Issue the self-issued X.509 certificate for the evidence signing KMS key (owner step).

Usage (as an AWS admin who may call kms:GetPublicKey and kms:Sign on the key):

    issue-certificate.py --kms-key-id alias/kr-evidence-signing --kid kr-evidence-2026-1 \
        --out kr-evidence-2026-1.pem

The certificate is built here and its to-be-signed bytes are signed by KMS (ECDSA_SHA_256), so
the private key never leaves KMS. Set the output as EVIDENCE_SIGNING_CERT_PEM on agent-platform-api
and free-platform-api, and publish it (with its fingerprint) in the public keys repository.
Needs boto3 and asn1crypto (both installed with the services' requirements).

A valid signature under this key means Key Regulatory issued the file unaltered. It is not a
statement about compliance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import secrets
import sys
from collections.abc import Callable

from asn1crypto import keys, x509


def build_certificate(
    public_key_der: bytes, sign_digest: Callable[[bytes], bytes], kid: str, years: int = 10
) -> bytes:
    """DER certificate for ``public_key_der`` (SubjectPublicKeyInfo); ``sign_digest`` returns a
    DER ECDSA signature over a SHA-256 digest."""
    spki = keys.PublicKeyInfo.load(public_key_der)
    name = x509.Name.build(
        {
            "common_name": f"Key Regulatory evidence signing ({kid})",
            "organization_name": "Key Regulatory",
        }
    )
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    algorithm = {"algorithm": "sha256_ecdsa"}
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(secrets.token_bytes(16), "big") >> 1,
            "signature": algorithm,
            "issuer": name,
            "validity": {
                "not_before": x509.Time(name="utc_time", value=now - dt.timedelta(days=1)),
                "not_after": x509.Time(
                    name="general_time", value=now + dt.timedelta(days=365 * years)
                ),
            },
            "subject": name,
            "subject_public_key_info": spki,
            "extensions": [
                {"extn_id": "basic_constraints", "critical": True, "extn_value": {"ca": False}},
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": {"digital_signature", "non_repudiation"},
                },
                {"extn_id": "key_identifier", "extn_value": spki.sha1},
            ],
        }
    )
    signature = sign_digest(hashlib.sha256(tbs.dump()).digest())
    cert = x509.Certificate(
        {"tbs_certificate": tbs, "signature_algorithm": algorithm, "signature_value": signature}
    )
    return cert.dump()


def to_pem(der: bytes) -> str:
    import base64  # noqa: PLC0415

    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kms-key-id", required=True)
    parser.add_argument("--kid", required=True, help="e.g. kr-evidence-2026-1 (never dev-)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--years", type=int, default=10)
    args = parser.parse_args(argv)
    if args.kid.startswith("dev-"):
        parser.error("a production kid may not begin dev-")
    import boto3  # noqa: PLC0415

    kms = boto3.client("kms")
    public = kms.get_public_key(KeyId=args.kms_key_id)["PublicKey"]

    def sign_digest(digest: bytes) -> bytes:
        return kms.sign(
            KeyId=args.kms_key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )["Signature"]

    pem = to_pem(build_certificate(public, sign_digest, args.kid, args.years))
    with open(args.out, "w", encoding="ascii") as fh:
        fh.write(pem)
    print(f"wrote {args.out}; publish it and set EVIDENCE_SIGNING_CERT_PEM to its contents")
    return 0


if __name__ == "__main__":
    sys.exit(main())

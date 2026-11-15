# Verifying a Key Regulatory evidence file

This file is attached to every evidence report Key Regulatory issues. It explains how to check
the report without contacting us and without using our website.

**What a valid result means.** Key Regulatory issued this exact file, and it has not been
altered since the time a third-party timestamp authority vouched for. It is not a statement
about compliance. It does not approve publication, and it is not legal advice. The report
records a human review; the reviewer's decisions are the firm's own.

## What you need

- The PDF.
- Our public key, `key-regulatory-evidence.pem`. A copy is attached to the PDF, but do not
  trust the attached copy on its own: anyone who altered the file could replace it. Obtain the
  key from a source you already trust (our public keys repository, your onboarding material or
  order form, or a copy you saved earlier) and check its fingerprint.

The fingerprint is the SHA-256 of the key's DER SubjectPublicKeyInfo. Compute it with:

```sh
openssl pkey -pubin -in key-regulatory-evidence.pem -outform DER | openssl dgst -sha256
```

It must equal the fingerprint printed in the report's verification section and published in
our DNS record `_evidence-key.keyregulatory.com` (`kid=<kid>; sha256=<fingerprint>`).

## What is attached to the PDF

| File | What it is |
|---|---|
| `VERIFY.md` | These instructions. |
| `key-regulatory-evidence.pem` | The public key and its self-issued certificate. |
| `record.json` | The verification code (`code`), the kind of record, the content hash and the canonical record (`payload`) the hash is computed from. |

The content hash is `sha256` of `payload` serialised as JSON with sorted keys, separators `,`
and `:` and no spaces, and non-ASCII characters escaped (Python:
`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`).

## 1. Adobe Acrobat Reader

1. Open the PDF and open the **Signature Panel**. The signature is by "Key Regulatory" and
   carries a timestamp.
2. Until you trust our certificate, Adobe shows "signature is valid, but the identity of the
   signer is unknown". To trust it once: in the Signature Panel, right-click the signature,
   choose **Show Signature Properties**, then **Show Signer's Certificate**, open the **Trust**
   tab and choose **Add to Trusted Certificates**. Tick **Use this certificate as a trusted
   root** and confirm. Before you do, compare the certificate's SHA-256 public key fingerprint
   with the one you obtained above.
3. Close and reopen the PDF. The panel should show "Signed and all signatures are valid" and
   "The document has not been modified since this signature was applied".

## 2. `kr-verify.py` (one file, needs only `cryptography`)

```sh
pip install cryptography
python3 kr-verify.py report.pdf --key key-regulatory-evidence.pem
```

It checks that the PDF signature covers the whole file and verifies under your key, that the
RFC 3161 timestamp is over that signature, that the verification code in `record.json`
verifies under your key, and that `record.json` recomputes the content hash the code signs. To
check a code copied from a printout on its own:

```sh
python3 kr-verify.py --code 'kr5.....' --key key-regulatory-evidence.pem
```

## 3. `openssl`

Extract the parts with `kr-verify.py --extract parts report.pdf` (it writes the files named
below), or extract the PDF signature with standard tools:

```sh
F=report.pdf
set -- $(grep -a -o '/ByteRange \[[0-9 ]*\]' "$F" | tr -d '/ByteRange[]')
B=$2; C=$3; D=$4
head -c "$B" "$F" > parts/signed-bytes.bin
tail -c "$D" "$F" >> parts/signed-bytes.bin
dd if="$F" bs=1 skip=$((B + 1)) count=$((C - B - 2)) status=none | xxd -r -p > parts/signature.raw
openssl cms -cmsout -inform DER -in parts/signature.raw -outform DER -out parts/signature.p7s
```

**The PDF signature** (the file is unaltered and signed by the key):

```sh
openssl cms -verify -binary -inform DER -in parts/signature.p7s \
  -content parts/signed-bytes.bin -CAfile key-regulatory-evidence.pem -purpose any -out /dev/null
```

Expected output: `CMS Verification successful`.

**The timestamp** (the signature existed at the stated time). The authority's root certificate
must be in your trust store (DigiCert and Sectigo roots ship with most systems):

```sh
openssl ts -reply -token_in -in parts/timestamp.tst -token_out -text | grep 'Time stamp'
openssl ts -verify -token_in -in parts/timestamp.tst -data parts/signature-value.bin \
  -CApath /etc/ssl/certs
```

Expected output: `Verification: OK`.

**The verification code** (the facts printed on the page):

```sh
openssl dgst -sha256 -verify key-regulatory-evidence.pem \
  -signature parts/code-signature.der parts/code-payload.txt
```

Expected output: `Verified OK`. `code-payload.txt` holds the signed facts:
`kr5|<kid>|<kind>|<id>|<generated at, ms since 1970>|<scope>|<content hash>|<hash version>`.

## The verification code

The code printed on the report (and in its QR code) is
`kr5.<base64url(payload)>.<base64url(signature)>`. The signature is ECDSA P-256 with SHA-256
(ES256) over the payload bytes exactly as embedded, 64 bytes (r then s). The short reference
printed as `XXXX-XXXX` is the first 8 hex digits of the SHA-256 of the signature; it is only a
lookup key for our verify page and proves nothing by itself.

Codes signed with a key id beginning `dev-` come from a development system and are never valid
for a real report.

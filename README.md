# Key Regulatory evidence keys

The public keys that Key Regulatory evidence files are signed with, and the tools to verify those files offline.

| File | Purpose |
|---|---|
| `VERIFY.md` | How to verify an evidence file offline, with the Adobe Reader trust steps and the exact `openssl` commands. It is byte-identical to the copy embedded in every signed PDF. |
| `kr-verify.py` | A single-file verifier whose only dependency is `cryptography`. It checks the PDF signature, the RFC 3161 timestamp, the `kr5` code and `record.json` against the content hash. |
| `issue-certificate.py` | How the self-issued certificate for a signing key was built. The private key never leaves AWS KMS. |
| `keys/` | One `<kid>.pem` per production key (the self-issued certificate carrying the public key), with its SHA-256 fingerprint. |
| `succession/` | Present only after a key is replaced. Holds the signed, timestamped succession statements. |

## Keys

| kid | Fingerprint (SHA-256 of the DER SubjectPublicKeyInfo) | Status |
|---|---|---|
| `kr-evidence-2026-1` | `57bfadc6 516b0bb5 9430c4b2 53752a4f 1830be92 1b061790 5a539c68 2fd67ac4` | current |

Before trusting a key, check its fingerprint against at least one independent source:

- the DNS TXT record `_evidence-key.keyregulatory.com`, which reads `kid=<kid>; sha256=<fingerprint, no spaces>`
- the Key Regulatory trust page
- the fingerprint printed in the report's verification section

```
dig +short TXT _evidence-key.keyregulatory.com
openssl x509 -in keys/kr-evidence-2026-1.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
python3 kr-verify.py report.pdf --key keys/kr-evidence-2026-1.pem
```

This repository holds no private key, secret or customer data. Development keys (`kid` beginning `dev-`) are never published.

A valid signature means Key Regulatory issued the file and it is unaltered since the timestamped time. It is not a statement about compliance. It does not approve publication, and it is not legal advice.

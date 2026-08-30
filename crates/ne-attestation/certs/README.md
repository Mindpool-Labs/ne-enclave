# AMD Milan SEV-SNP trust material (baked for verification)

These are the **public** AMD Key Distribution Service (KDS) certificates for the
Milan SEV-SNP product line. They are *trust material*, not secrets: anyone may
fetch them from `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`. They are
baked into the crate so the verifier has a known-good default ARK and so the
Mac test suite can exercise the **real** RSA-4096 RSASSA-PSS-SHA384 signature
path without network access.

Nothing here is a private key. Verifying the ARK self-signature or the ASK's
signature under the ARK is a purely public-key operation.

## Files

| File | Role | Algorithm | Subject CN | Issuer CN |
| --- | --- | --- | --- | --- |
| `amd-milan-ark.der` | Product root (ARK) | RSA-4096, self-signed RSASSA-PSS-SHA384 | `ARK-Milan` | `ARK-Milan` (self) |
| `amd-milan-ask.der` | Intermediate (ASK) | RSA-4096, signed by ARK (RSASSA-PSS-SHA384) | `SEV-Milan` | `ARK-Milan` |

The VCEK leaf (P-384 ECDSA, signed by the ASK) is **not** baked here: it is
unique per chip + TCB and fetched at runtime by the supervisor.

## Provenance / SHA-256

Fetched from the AMD KDS `cert_chain` endpoint (PEM, ASK-then-ARK) and
converted to DER with `openssl x509 -outform DER`. The ARK from that chain is
byte-identical to the separately-fetched ARK pinned below.

```
amd-milan-ark.der  SHA-256  69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd
amd-milan-ask.der  SHA-256  67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b
```

The ARK SHA-256 is pinned in `vcek::tests::milan_default_ark_parses_and_matches_pinned_hash`.
Validity (ARK): 2020-10-22 → 2045-10-22 (serial `010000`).

## Refresh

```sh
curl -s https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o /tmp/milan_chain.pem
awk 'BEGIN{c=0} /BEGIN CERT/{c++} {if(c==1)print > "/tmp/ask.pem"; else if(c==2)print > "/tmp/ark.pem"}' /tmp/milan_chain.pem
openssl x509 -in /tmp/ask.pem -outform DER -out crates/ne-attestation/certs/amd-milan-ask.der
openssl x509 -in /tmp/ark.pem -outform DER -out crates/ne-attestation/certs/amd-milan-ark.der
shasum -a 256 crates/ne-attestation/certs/amd-milan-{ark,ask}.der
```

If a refresh changes the ARK SHA-256, that is a trust-anchor rotation: update
the pinned hash in `vcek::tests` and treat it as a breaking change (callers
embedding the old ARK must update).

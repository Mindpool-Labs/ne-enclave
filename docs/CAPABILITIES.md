# Capability ledger

This ledger is the public source of truth for what NeuronEdge Enclave supports.
“Implemented” means code exists. “Verified” means a defined test has exercised
the primitive. “Supported” additionally requires an installable release
artifact, a public API path, and independently checkable evidence.

| Capability | Profile | Maturity | Artifact | Verification | Limits |
|---|---|---|---|---|---|
| Firecracker workspace execution | `standard` | Supported | `nee-x86_64-unknown-linux-musl` plus operator-provided Firecracker and jailer | Required `standard-artifact-gate`: signed-bundle install, capabilities check, REST create → execute → write → read → destroy on KVM | Linux x86_64; host operator remains trusted; workspace snapshot/network limits remain documented in the threat model |
| Public gRPC/REST API, CLI, Python SDK, and TypeScript SDK | All | Supported | `nee`, Python wheel/sdist, npm tarball | Unit/integration suites plus release artifact gates | Operations vary by profile; callers must inspect `GET /v1/runtime/capabilities`, `GetRuntimeCapabilities`, or `nee runtime capabilities` |
| Azure confidential execution | `confidential-azure` | Preview | Signed `nee`, pinned `openshell-sandbox`, and signed OpenShell policies | Required `azure-confidential-artifact-gate` is defined for Azure `Standard_DC4as_v5`; promotion requires a successful signed v0.2.0 run | One workspace per CVM; shared-kernel OpenShell isolation inside the outer SEV-SNP CVM; create/destroy/execute/file I/O/attestation only; no confidential snapshot/restore/fork |
| Azure vTPM SEV-SNP evidence primitive | `confidential-azure` | Verified | Public evidence schema version 1 (`sev_snp_azure` typed proof) | Previously exercised on Azure DCasv5 silicon; release gate checks REST, CLI offline verification, Python, and TypeScript transports | Attests the host CVM/OpenHCL launch and a fresh TPM quote, not workspace guest code; product lane remains Preview until signed release evidence exists |
| Signed release bundle, SBOM, and provenance | All | Implemented for v0.2.0 candidate | Cosign bundles for ordinary components, SPDX JSON SBOM, GitHub/Sigstore provenance, `SHA256SUMS`, resolved release manifest | Candidate job verifies signer identity, issuer, signatures, checksums, and staged provenance before producing the immutable tar transport | No v0.2.0 release evidence exists until the required environment gates pass and the release is published |
| Runtime package supply-chain enforcement (OSV/OPA/CVSS during standard workspace execution) | `standard` | Not implemented | None | None | OpenShell contains related functionality, but it is not wired into the standard runtime profile |
| Confidential snapshot / restore / fork | `confidential-azure` | Not implemented | None | Profile contract rejects these operations | Firecracker vmstate is not applicable to the OpenShell execution backend |
| Direct `/dev/sev-guest` product profile | None | Not implemented | None | Domain/provider code is synthetic-tested only | v0.2.0 product routing selects Azure vTPM explicitly; no public profile opens `/dev/sev-guest` |
| External OpenBao Transit key release | All | Verified | Runtime mTLS key-release client and opaque Transit envelope | A local Docker integration stack exercised one key-release service, one PostgreSQL service, and one OpenBao development-mode service | This verifies only that local topology. HashiCorp Vault, cloud KMS, HSM, fleet operation, certificate enrollment and lifecycle, audit export, high availability, multi-region operation, and GA are not verified. |

## Promotion rule

Azure confidential execution stays **Preview** until the exact signed v0.2.0
candidate passes the required Azure artifact gate and is published without a
rebuild. Promotion to **Supported** is a separate documentation-only commit
that records:

- release tag;
- SHA-256 of `nee`;
- SHA-256 of `openshell-sandbox`;
- Azure VM size and image URN;
- workflow run URL;
- attestation evidence schema version.

No product code, package, checksum, signature, or provenance may change during
that promotion.

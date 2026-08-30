# Breaking changes

## Next release

The SEV-SNP policy pins `min_tcb` and `guest_policy` are now JSON strings, in
both `SealingTrustAnchor::SevSnp` and the `nee attestation verify` policy file.
They serialize as `"min_tcb": "792633534417207304"` instead of
`"min_tcb": 792633534417207304`. The string must be canonical: no leading `+`
and no leading zeros. A JSON number is rejected rather than coerced, because a
producer still emitting numbers is the lossy path this change removes.

The reason is precision. `min_tcb` is compared against the raw 64-bit AMD
`REPORTED_TCB` word, whose high byte is the microcode SVN, so production values
exceed 2^53. Any consumer that parses JSON numbers as IEEE-754 doubles — every
JavaScript and TypeScript client, and `jq` — silently rounds them. Two distinct
pins 56 apart, `792633534417207304` and `792633534417207360`, both become
`792633534417207300`. At that magnitude one unit in the last place spans 128,
which covers the whole low byte of the packed word, so adjacent representable
doubles are different security levels.

That had two consequences, and this change closes both. A `SevSnp` snapshot
sealed by a Rust producer could not be unsealed by a JavaScript one, because the
two computed different policy hashes and therefore different DEK-wrap associated
data. Worse, wherever the rounded hash serves as the policy identity — as it does
in a KMS encryption context — a caller could present a TCB floor rolled back by
up to one double-ULP bucket, still satisfy the binding, and have the gate then
enforce the weaker floor. The `nee attestation verify` path had the same defect
in the opposite direction: a rounded policy file moved the enforced floor *down*
and failed open with no error.

`guest_policy` was never at risk. It is enforced as a required-bits mask and real
values sit around 2^18. It changes form only so that one pin has one wire
encoding rather than two.

## Do not hand-edit an existing seal

**Re-encoding the pins in an existing `seal.json` destroys the wrapped DEK.**
The policy hash is inside the AES-GCM associated data and inside the signed
envelope, both fixed at seal time and not recomputable. Quoting the values by
hand changes that hash, and the snapshot then fails with
`seal signature does not verify` and `ciphertext failed authentication` — errors
that read as tampering or disk corruption, not as a schema migration.

There is no in-place migration. To move an existing SevSnp snapshot: unseal it
with the prior release first, then re-seal it with this one. If the plaintext is
gone and only the edited file remains, the data is unrecoverable.

The practical blast radius is nil: `docs/CAPABILITIES.md` and
`docs/THREAT-MODEL.md` both mark the SEV-SNP path synthetic-only and unclaimed
on real silicon, so no production snapshot exists in the old format. That is
what makes shipping without a migration defensible.

## What must move in the same release

Rust callers are unaffected at the type level — both fields remain `u64` and only
the serialized form changes. Everything that crosses the JSON boundary must be
updated together:

- Any non-Rust client that emits or parses a `SealingPolicy`, including an
  optional external-client schema and its independent `policy_canonical_bytes`
  port. A JS fix must carry the value as a string end
  to end; `Number`-based coercion re-introduces the rounding this change removes,
  and no current test would go red.
- Any vendored `ne-enclave-wasm` artifact, which must be rebuilt — a stale
  prebuilt still demands numbers.
- Any tooling that authors a policy file with `jq`, which represents JSON numbers
  as doubles.

Cross-implementation parity fixtures currently cover the `Software` anchor only.
A `SevSnp` fixture is what would have caught this divergence, and it is still
missing on both sides.

Workspace creation now identifies managed images by content digest. The request fields
`kernel_image_path` and `rootfs_image_path` (and the TypeScript spellings
`kernelImagePath` and `rootfsImagePath`) have been removed. Use `kernel_sha256` and
`rootfs_sha256` in protobuf, REST, and Python, or `kernelSha256` and `rootfsSha256` in
TypeScript. LangChain and Mastra environment configuration now uses
`NE_KERNEL_SHA256` and `NE_ROOTFS_SHA256`; legacy path variables are ignored.

Import images with `sudo /opt/ne-enclave/bin/nee image import` and pass the same lowercase
64-character SHA-256 values when creating a cold Firecracker workspace. The supervisor
resolves and verifies those artifacts beneath `NE_IMAGE_STORE` (default
`/var/lib/ne-enclave/images`) and stages independent copies for each workspace.

Snapshot manifests are now schema version 5 and sign the managed kernel/rootfs digest
pair. Restore and fork reject manifests older than version 5; there is no migration path.
Snapshots also require a read-only rootfs, so create a snapshot source with
`rootfs_read_only=true`.

The implicit confidential-mode switch `NE_CONFIDENTIAL_MODE` has been removed.
Select an explicit execution profile with `NE_EXECUTION_PROFILE=standard` or
`NE_EXECUTION_PROFILE=confidential-azure`. Installations should use
`nee install --execution-profile <profile>` and discover the active contract
through `GetRuntimeCapabilities`, `GET /v1/runtime/capabilities`, or
`nee runtime capabilities`.

Complete attestation evidence is now a versioned typed envelope. The public
provider is an enum (`software`, `sev_snp_direct`, or `sev_snp_azure`) and the
proof is a provider-specific oneof instead of an untyped proof-property bag.
Consumers that parsed legacy `provider_type` strings or arbitrary proof
properties must migrate to the typed fields. Legacy summary evidence remains
available for software and direct SEV-SNP compatibility. Azure callers must use
the complete typed envelope because the two-layer proof cannot be represented
safely in the legacy summary.

Confidential workspace creation now has profile-specific semantics: provide the
workspace ID and leave Firecracker image digests, VM sizing, networking, and
snapshot fields unset. Python callers can use
`create_confidential_workspace`; TypeScript callers can use
`createConfidentialWorkspace`.

Release asset names now use the `nee-` prefix. The Linux runtime artifact is
`nee-x86_64-unknown-linux-musl`, and the v0.2.0 installer requires Cosign to
verify the signed manifest, checksums, resolved component digests, and
profile-specific components before installation.

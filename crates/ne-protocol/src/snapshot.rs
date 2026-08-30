// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Snapshot manifest: the signed, verifiable descriptor of a microVM
//! snapshot artifact.
//!
//! Layout on disk (written by the supervisor):
//! ```text
//! <state_dir>/snapshots/<snapshot_id>/
//!   mem            full memory file
//!   vmstate        device + vCPU state
//!   manifest.json  this struct, Ed25519-signed
//! ```
//! The signature covers the canonical bytes of every field except
//! `signature_b64`. `signer_pubkey_b64` IS inside the signed bytes, so a
//! key-swap forgery changes the canonical bytes and fails verification
//! (same discipline as the audit chain).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Manifest schema version (bump on incompatible field changes).
///
/// v2 (audit `S5-F4`): the signed canonical form embeds a `ctx` domain tag
/// ([`SNAPSHOT_DOMAIN_TAG`]).
/// v3 (Obex rename): the [`SNAPSHOT_DOMAIN_TAG`] changed to `obex-snapshot-v1`.
/// v4 (NeuronEdge Enclave rename): the tag rotated to `ne-enclave-snapshot-v1`,
/// a signing-format break folded into the rename. Pre-v4 manifests are rejected
/// with [`VerifyError::UnsupportedVersion`]; there is no migration.
/// v5 (managed images): host image paths were removed and the signed form now
/// carries the kernel and rootfs SHA-256 content identities. Pre-v5 manifests
/// are rejected with [`VerifyError::UnsupportedVersion`]; there is no migration.
pub const MANIFEST_VERSION: u32 = 5;

/// Domain-separation tag embedded in every snapshot manifest signature.
///
/// Audit `S5-F4`: mirrors the attestation `ctx` convention so snapshot
/// signatures are explicitly non-interchangeable with audit/attestation ones.
/// Changing this string is a signing-format break.
pub const SNAPSHOT_DOMAIN_TAG: &str = "ne-enclave-snapshot-v1";

/// Guest identity captured at snapshot time and reapplied on restore.
///
/// NOTE: field declaration order is part of the signed canonical bytes
/// (nested objects are not key-sorted). Reordering fields breaks
/// verification of existing signatures — bump `MANIFEST_VERSION` if you must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIdentity {
    /// Hostname assigned to the guest.
    pub hostname: String,
    /// MAC address of the guest's TAP interface.
    pub mac: String,
    /// vsock CID assigned to the guest.
    pub guest_vsock_cid: u32,
    /// Number of vCPUs allocated.
    pub vcpu_count: u8,
    /// Guest memory size in MiB.
    pub mem_size_mib: u32,
}

/// The signed snapshot descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    /// Manifest schema version; must equal [`MANIFEST_VERSION`].
    pub manifest_version: u32,
    /// Stable, globally unique snapshot identifier (ULID).
    pub snapshot_id: String,
    /// Workspace ID from which this snapshot was taken.
    pub created_from_workspace_id: String,
    /// Firecracker binary version string recorded at snapshot time.
    pub firecracker_version: String,
    /// Hex-encoded SHA-256 of the `mem` artifact file.
    pub mem_sha256: String,
    /// Hex-encoded SHA-256 of the `vmstate` artifact file.
    pub vmstate_sha256: String,
    /// Canonical lowercase SHA-256 of the managed kernel image.
    pub kernel_sha256: String,
    /// Hex-encoded SHA-256 of the rootfs image.
    pub rootfs_sha256: String,
    /// Guest identity metadata captured at snapshot time.
    pub guest_identity: GuestIdentity,
    /// Kernel boot arguments string.
    pub kernel_boot_args: String,
    /// Base64-encoded Ed25519 public key that signed this manifest.
    /// Carried inside the signed bytes so key-swap forgery is detectable.
    pub signer_pubkey_b64: String,
    /// Base64-encoded Ed25519 signature over the canonical bytes of this
    /// manifest (all fields except `signature_b64` itself, BTreeMap-sorted).
    pub signature_b64: String,
}

/// Errors building canonical bytes.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// JSON serialization failed.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Errors verifying a manifest.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Manifest schema version is not supported by this build.
    #[error("manifest version {got} unsupported (this build supports {supported})")]
    UnsupportedVersion {
        /// Version found in the manifest.
        got: u32,
        /// Version this build supports.
        supported: u32,
    },
    /// Base64 decoding failed for the named field.
    #[error("base64 decode of {field}: {source}")]
    Base64 {
        /// Field name that failed to decode.
        field: &'static str,
        /// Underlying decode error.
        source: base64::DecodeError,
    },
    /// The signer public key bytes are malformed.
    #[error("malformed public key")]
    BadPublicKey,
    /// The manifest was signed by a key other than the caller-pinned trust
    /// anchor (the embedded `signer_pubkey_b64` did not match the expected
    /// host signing key). A self-signed manifest cannot vouch for itself.
    #[error("manifest signed by an untrusted key")]
    UntrustedSigner,
    /// The signature bytes are malformed.
    #[error("malformed signature")]
    BadSignature,
    /// Ed25519 verification rejected the signature.
    #[error("signature does not verify")]
    SignatureMismatch,
    /// Failed to produce canonical bytes for signing.
    #[error("canonical bytes: {0}")]
    Canonical(#[from] ManifestError),
    /// A recorded snapshot artifact hash does not match the supplied actual hash.
    #[error("{field} hash mismatch: manifest {expected}, actual {actual}")]
    HashMismatch {
        /// Artifact field name (`mem` or `vmstate`).
        field: &'static str,
        /// Hash recorded in the manifest.
        expected: String,
        /// Hash computed from the artifact file.
        actual: String,
    },
}

impl SnapshotManifest {
    /// Deterministic bytes signed/verified: this struct as a JSON object
    /// with `signature_b64` removed and keys sorted (`BTreeMap`).
    ///
    /// Top-level keys are sorted; nested objects keep serde field order, so
    /// nested field order is load-bearing for signatures.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("signature_b64");
            let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            // Domain tag. `ctx` sorts deterministically with the
            // rest of the top-level keys.
            sorted.insert(
                "ctx".to_string(),
                serde_json::Value::String(SNAPSHOT_DOMAIN_TAG.to_string()),
            );
            return Ok(serde_json::to_vec(&sorted)?);
        }
        Ok(serde_json::to_vec(&value)?)
    }
}

/// **Integrity-only** check: verify the manifest's Ed25519 signature against
/// the public key *embedded in the manifest itself*.
///
/// This proves the manifest is internally self-consistent (not corrupted
/// relative to whatever key signed it) but does **NOT** authenticate the
/// signer: a manifest signed by an attacker's own key, embedding that key,
/// passes. For any **trust decision** (restore / fork) use
/// [`verify_manifest_signature_pinned`], which pins to the host's signing
/// key. This function remains for offline diagnostics where no trust anchor
/// is available.
///
/// Does NOT touch the filesystem; pair with [`manifest_matches_hashes`].
pub fn verify_manifest_signature(m: &SnapshotManifest) -> Result<(), VerifyError> {
    let (vk, sig) = decode_signer_and_sig(m)?;
    let bytes = m.canonical_bytes()?;
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| VerifyError::SignatureMismatch)
}

/// Verify the manifest's signature against a **caller-pinned trust anchor**.
///
/// `expected_signer` is the host's signing key, obtained out-of-band (e.g. the
/// supervisor's own `AuditLog` verifying key). The key embedded in the
/// (untrusted) manifest is only a consistency hint: it MUST equal
/// `expected_signer` or verification fails with [`VerifyError::UntrustedSigner`]
/// before any signature check. This is the authenticity-bearing verifier — it
/// proves the artifact was produced by the holder of `expected_signer`, closing
/// the self-signed forgery class (mirrors the attestation `verify()`
/// trust-anchor discipline). Does NOT touch the filesystem.
pub fn verify_manifest_signature_pinned(
    m: &SnapshotManifest,
    expected_signer: &VerifyingKey,
) -> Result<(), VerifyError> {
    let (embedded_vk, sig) = decode_signer_and_sig(m)?;
    if embedded_vk.as_bytes() != expected_signer.as_bytes() {
        return Err(VerifyError::UntrustedSigner);
    }
    let bytes = m.canonical_bytes()?;
    expected_signer
        .verify_strict(&bytes, &sig)
        .map_err(|_| VerifyError::SignatureMismatch)
}

/// Shared decode of the version, embedded verifying key, and signature.
fn decode_signer_and_sig(m: &SnapshotManifest) -> Result<(VerifyingKey, Signature), VerifyError> {
    if m.manifest_version != MANIFEST_VERSION {
        return Err(VerifyError::UnsupportedVersion {
            got: m.manifest_version,
            supported: MANIFEST_VERSION,
        });
    }
    let pk_bytes = B64
        .decode(&m.signer_pubkey_b64)
        .map_err(|source| VerifyError::Base64 {
            field: "signer_pubkey_b64",
            source,
        })?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| VerifyError::BadPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| VerifyError::BadPublicKey)?;
    let sig_bytes = B64
        .decode(&m.signature_b64)
        .map_err(|source| VerifyError::Base64 {
            field: "signature_b64",
            source,
        })?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::BadSignature)?;
    Ok((vk, Signature::from_bytes(&sig_arr)))
}

/// Compare the manifest's recorded hashes against freshly computed ones.
///
/// Caller computes the actual SHA-256 hex of each artifact file.
pub fn manifest_matches_hashes(
    m: &SnapshotManifest,
    mem_sha256: &str,
    vmstate_sha256: &str,
) -> Result<(), VerifyError> {
    check("mem", &m.mem_sha256, mem_sha256)?;
    check("vmstate", &m.vmstate_sha256, vmstate_sha256)?;
    Ok(())
}

fn check(field: &'static str, expected: &str, actual: &str) -> Result<(), VerifyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(VerifyError::HashMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample(signer: &SigningKey) -> SnapshotManifest {
        let mut m = SnapshotManifest {
            manifest_version: 5,
            snapshot_id: "01J0SNAP".into(),
            created_from_workspace_id: "ws-a".into(),
            firecracker_version: "1.7.0".into(),
            mem_sha256: "aa".into(),
            vmstate_sha256: "bb".into(),
            kernel_sha256: "33".repeat(32),
            rootfs_sha256: "44".repeat(32),
            guest_identity: GuestIdentity {
                hostname: "ne-enclave".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            kernel_boot_args: "console=ttyS0".into(),
            signer_pubkey_b64: B64.encode(signer.verifying_key().as_bytes()),
            signature_b64: String::new(),
        };
        let sig = signer.sign(&m.canonical_bytes().unwrap());
        m.signature_b64 = B64.encode(sig.to_bytes());
        m
    }

    #[test]
    fn valid_signature_verifies() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        assert!(verify_manifest_signature(&sample(&signer)).is_ok());
    }

    #[test]
    fn tampered_field_fails() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = sample(&signer);
        m.mem_sha256 = "deadbeef".into();
        assert!(matches!(
            verify_manifest_signature(&m),
            Err(VerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn pubkey_swap_fails() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = sample(&signer);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        m.signer_pubkey_b64 = B64.encode(other.verifying_key().as_bytes());
        assert!(verify_manifest_signature(&m).is_err());
    }

    #[test]
    fn pinned_accepts_manifest_signed_by_the_host_key() {
        let host = SigningKey::from_bytes(&[7u8; 32]);
        let m = sample(&host);
        assert!(verify_manifest_signature_pinned(&m, &host.verifying_key()).is_ok());
    }

    #[test]
    fn pinned_rejects_attacker_signed_manifest() {
        // The forgery the unpinned check MISSES: an attacker signs a fully
        // self-consistent manifest with their OWN key and embeds their own
        // pubkey. `verify_manifest_signature` (integrity-only) accepts it;
        // the pinned verifier rejects it as UntrustedSigner against the host.
        let attacker = SigningKey::from_bytes(&[0xAB; 32]);
        let host = SigningKey::from_bytes(&[7u8; 32]);
        let forged = sample(&attacker);
        assert!(
            verify_manifest_signature(&forged).is_ok(),
            "integrity-only check accepts the self-signed forgery (the gap)"
        );
        assert!(matches!(
            verify_manifest_signature_pinned(&forged, &host.verifying_key()),
            Err(VerifyError::UntrustedSigner)
        ));
    }

    #[test]
    fn hash_mismatch_detected() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let m = sample(&signer);
        assert!(manifest_matches_hashes(&m, "aa", "bb").is_ok());
        assert!(matches!(
            manifest_matches_hashes(&m, "aa", "WRONG"),
            Err(VerifyError::HashMismatch {
                field: "vmstate",
                ..
            })
        ));
    }

    #[test]
    fn unsupported_version_rejected() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = sample(&signer);
        m.manifest_version = 999;
        m.signature_b64 = String::new();
        let sig = signer.sign(&m.canonical_bytes().unwrap());
        m.signature_b64 = B64.encode(sig.to_bytes());
        assert!(matches!(
            verify_manifest_signature(&m),
            Err(VerifyError::UnsupportedVersion { got: 999, .. })
        ));
    }

    #[test]
    fn canonical_bytes_carries_snapshot_domain_tag() {
        // S5-F4: the signed manifest form must embed an explicit domain tag.
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = sample(&signer).canonical_bytes().expect("canonical");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            text.contains("\"ctx\":\"ne-enclave-snapshot-v1\""),
            "snapshot canonical must carry the domain tag, got: {text}"
        );
    }

    #[test]
    fn pre_v5_manifest_is_rejected() {
        // Clean break (S5-F4 + NeuronEdge Enclave rename): manifests written under any prior
        // schema version are rejected with UnsupportedVersion — no migration.
        assert_eq!(
            MANIFEST_VERSION, 5,
            "managed image digests replace host paths in manifest v5"
        );
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = sample(&signer);
        m.manifest_version = 4;
        m.signature_b64 = String::new();
        let sig = signer.sign(&m.canonical_bytes().unwrap());
        m.signature_b64 = B64.encode(sig.to_bytes());
        assert!(matches!(
            verify_manifest_signature(&m),
            Err(VerifyError::UnsupportedVersion {
                got: 4,
                supported: 5
            })
        ));
    }

    #[test]
    fn serialized_v5_manifest_contains_only_image_digests() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let json = serde_json::to_string(&sample(&signer)).expect("serialize manifest");
        assert!(json.contains("\"kernel_sha256\""));
        assert!(json.contains("\"rootfs_sha256\""));
        assert!(!json.contains(&["kernel", "path"].join("_")));
        assert!(!json.contains(&["rootfs", "path"].join("_")));
    }

    #[test]
    fn v5_manifest_rejects_unknown_fields() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut value = serde_json::to_value(sample(&signer)).expect("manifest value");
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("kernel_path".into(), serde_json::json!("/host/vmlinux"));
        let error = serde_json::from_value::<SnapshotManifest>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}

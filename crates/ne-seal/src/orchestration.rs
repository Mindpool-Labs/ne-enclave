// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Seal/unseal orchestration: the full restore trust path.
//!
//! Unseal order: verify manifest (pinned) → verify seal (pinned to the SAME
//! host key) → manifest↔seal binding → build gate params → fetch evidence →
//! `ne_attestation::verify()` must be `Verified` → resolve DEK → stream-decrypt
//! → zeroize. Fail-closed at every gate.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ne_attestation::{Evidence, Measurement, Nonce};
use ne_protocol::snapshot::{MANIFEST_VERSION, SnapshotManifest};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SealError;
use crate::crypto::{decrypt_stream, encrypt_stream};
use crate::gate::verify_against_policy;
use crate::key_release::{ControlPlaneKeyRelease, KeyRelease};
use crate::key_release_cp::{ControlPlaneError, CpWrapClient};
use crate::types::{DekEnvelope, KekProvider, SEAL_VERSION, SealEnvelope, SealingPolicy};

const SEALED_MEM: &str = "mem.sealed";
const SEALED_VMSTATE: &str = "vmstate.sealed";
const SEAL_JSON: &str = "seal.json";
const MANIFEST_JSON: &str = "manifest.json";

#[derive(Deserialize)]
struct ManifestVersionEnvelope {
    manifest_version: u32,
}

fn parse_snapshot_manifest(bytes: &[u8]) -> Result<SnapshotManifest, SealError> {
    let envelope: ManifestVersionEnvelope = serde_json::from_slice(bytes)?;
    if envelope.manifest_version != MANIFEST_VERSION {
        return Err(SealError::UnsupportedVersion {
            got: envelope.manifest_version,
            supported: MANIFEST_VERSION,
        });
    }
    Ok(serde_json::from_slice(bytes)?)
}

/// SHA-256 hex of a manifest's canonical bytes (the seal↔manifest binding value).
pub fn manifest_canonical_sha256(m: &SnapshotManifest) -> Result<String, SealError> {
    let bytes = m
        .canonical_bytes()
        .map_err(|e| SealError::BadCrypto(format!("manifest canonical bytes: {e}")))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Sign `seal` in place with the host Ed25519 key.
pub fn sign_seal(seal: &mut SealEnvelope, signer: &SigningKey) -> Result<(), SealError> {
    seal.signer_pubkey_b64 = B64.encode(signer.verifying_key().as_bytes());
    let bytes = seal.canonical_bytes()?;
    let sig = signer.sign(&bytes);
    seal.signature_b64 = B64.encode(sig.to_bytes());
    Ok(())
}

/// Verify the seal's signature pinned to the host verifying key.
///
/// F1: caller-pinned, never taken from the seal. The embedded
/// `signer_pubkey_b64` must equal `host_vk`.
pub fn verify_seal_pinned(seal: &SealEnvelope, host_vk: &VerifyingKey) -> Result<(), SealError> {
    if seal.seal_version != SEAL_VERSION {
        return Err(SealError::UnsupportedVersion {
            got: seal.seal_version,
            supported: SEAL_VERSION,
        });
    }
    let pk_bytes = B64
        .decode(&seal.signer_pubkey_b64)
        .map_err(|e| SealError::BadCrypto(format!("seal signer pubkey: {e}")))?;
    let arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| SealError::BadCrypto("seal signer pubkey not 32 bytes".into()))?;
    let embedded =
        VerifyingKey::from_bytes(&arr).map_err(|e| SealError::BadCrypto(e.to_string()))?;
    if embedded.as_bytes() != host_vk.as_bytes() {
        return Err(SealError::UntrustedSigner);
    }
    let sig_bytes = B64
        .decode(&seal.signature_b64)
        .map_err(|e| SealError::BadCrypto(format!("seal signature: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SealError::BadCrypto("seal signature not 64 bytes".into()))?;
    let bytes = seal.canonical_bytes()?;
    host_vk
        .verify_strict(&bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|_| SealError::SignatureMismatch)
}

/// Evaluate the attestation gate.
///
/// `verify()` must be `Verified` else `AttestationGateDenied`. Pure; no
/// network. Delegates to `gate::verify_against_policy` (anchor material lives
/// on that stack frame — no leak).
pub fn evaluate_gate(
    seal: &SealEnvelope,
    evidence: &Evidence,
    expected_nonce: &Nonce,
    now: i64,
) -> Result<(), SealError> {
    verify_against_policy(&seal.policy, evidence, expected_nonce, now)
}

/// Check the seal↔manifest binding (`snapshot_id` + `manifest_canonical_sha256`).
pub fn check_binding(seal: &SealEnvelope, manifest: &SnapshotManifest) -> Result<(), SealError> {
    if seal.snapshot_id != manifest.snapshot_id {
        return Err(SealError::BindingMismatch);
    }
    if seal.manifest_canonical_sha256 != manifest_canonical_sha256(manifest)? {
        return Err(SealError::BindingMismatch);
    }
    Ok(())
}

/// Seal the plaintext `mem` and `vmstate` files in `snapshot_dir`.
///
/// `snapshot_dir` already holds the unsealed snapshot path's plaintext
/// artifacts; this produces ciphertext siblings + `seal.json`. The caller
/// should ensure the manifest on disk describes the ciphertext hashes (re-run
/// `write_manifest` after this, or pass the manifest that already reflects
/// ciphertext). Returns the written `SealEnvelope`.
pub async fn seal_artifacts(
    snapshot_dir: &Path,
    manifest: &SnapshotManifest,
    signing_key: &SigningKey,
    policy: SealingPolicy,
    kek_provider: KekProvider,
    cp: Option<&dyn CpWrapClient>,
) -> Result<SealEnvelope, SealError> {
    let snapshot_id = manifest.snapshot_id.clone();
    let mh = manifest_canonical_sha256(manifest)?;
    // Generate DEK.
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(dek.as_mut_slice());
    // Encrypt mem + vmstate (provider-agnostic).
    let sealed_mem = snapshot_dir.join(SEALED_MEM);
    let sealed_vm = snapshot_dir.join(SEALED_VMSTATE);
    seal_one_file(
        &snapshot_dir.join("mem"),
        &sealed_mem,
        &dek,
        &snapshot_id,
        &mh,
    )
    .await?;
    seal_one_file(
        &snapshot_dir.join("vmstate"),
        &sealed_vm,
        &dek,
        &snapshot_id,
        &mh,
    )
    .await?;
    // Wrap the DEK under the selected KEK provider.
    let env = match kek_provider {
        KekProvider::ControlPlane => {
            let cp = cp.ok_or(SealError::ControlPlaneRelease(
                ControlPlaneError::Unconfigured,
            ))?;
            let (wrapped, nonce) = cp
                .wrap_dek(
                    &dek,
                    &manifest.created_from_workspace_id,
                    &snapshot_id,
                    &mh,
                    &policy,
                )
                .await?;
            DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: wrapped,
                wrap_nonce: nonce,
            }
        }
        KekProvider::SoftwareFallback => {
            let kek = crate::kek::derive_kek(signing_key);
            crate::kek::wrap_dek(
                &dek,
                &kek,
                KekProvider::SoftwareFallback,
                &snapshot_id,
                &mh,
                &policy,
            )?
        }
    };
    let mut seal = SealEnvelope {
        seal_version: SEAL_VERSION,
        snapshot_id,
        attestation_policy_id: None,
        policy,
        dek_envelope: env,
        manifest_canonical_sha256: mh,
        signer_pubkey_b64: String::new(),
        signature_b64: String::new(),
    };
    sign_seal(&mut seal, signing_key)?;
    let json = serde_json::to_vec_pretty(&seal)?;
    tokio::fs::write(snapshot_dir.join(SEAL_JSON), json).await?;
    Ok(seal)
}

async fn seal_one_file(
    src: &Path,
    dst: &Path,
    dek: &[u8; 32],
    snapshot_id: &str,
    manifest_hash: &str,
) -> Result<(), SealError> {
    let pt = tokio::fs::read(src).await?;
    let mut ct: Vec<u8> = Vec::with_capacity(pt.len() + 64);
    let mut reader = pt.as_slice();
    encrypt_stream(&mut reader, &mut ct, dek, snapshot_id, manifest_hash)?;
    tokio::fs::write(dst, &ct).await?;
    Ok(())
}

/// Full unseal + restore trust path.
///
/// `sw_release` serves the `SoftwareFallback` KEK path (local unwrap); `cp`
/// serves the `ControlPlane` KEK path (CP-side release, attested by
/// `evidence`). `evidence_provider` supplies current attestation evidence.
/// Branches on `seal.dek_envelope.kek_provider`. Writes plaintext to
/// `out_mem` / `out_vmstate`.
///
/// The local attestation gate on the `ControlPlane` path is
/// **fail-fast defense-in-depth, NOT a security boundary** — a compromised host
/// cannot be trusted to gate itself, so the authoritative gate runs server-side
/// inside `cp.release_dek`. The local check merely avoids a network round-trip
/// when the host already knows its own evidence fails. On the `SoftwareFallback`
/// path the local gate IS authoritative (there is no server-side gate).
#[allow(clippy::too_many_arguments)]
pub async fn unseal_artifacts(
    snapshot_dir: &Path,
    host_vk: &VerifyingKey,
    sw_release: Option<&dyn KeyRelease>,
    cp: Option<&dyn ControlPlaneKeyRelease>,
    evidence_provider: &dyn ne_attestation::AttestationProvider,
    workspace_id: &str,
    measurement: Measurement,
    now: i64,
    out_mem: &Path,
    out_vmstate: &Path,
) -> Result<(), SealError> {
    // 1. Manifest (pinned to the host key).
    let manifest_bytes = tokio::fs::read(snapshot_dir.join(MANIFEST_JSON)).await?;
    let manifest = parse_snapshot_manifest(&manifest_bytes)?;
    ne_protocol::snapshot::verify_manifest_signature_pinned(&manifest, host_vk)
        .map_err(|_| SealError::SignatureMismatch)?;
    // 2. Seal (pinned to the SAME host key).
    let seal_bytes = tokio::fs::read(snapshot_dir.join(SEAL_JSON)).await?;
    let seal: SealEnvelope = serde_json::from_slice(&seal_bytes).map_err(SealError::Serde)?;
    verify_seal_pinned(&seal, host_vk)?;
    // 3. Manifest↔seal binding.
    check_binding(&seal, &manifest)?;
    // 4. Mint the attestation challenge nonce + fetch fresh evidence. The same
    //    evidence/nonce feeds both the local fail-fast gate and the CP release
    //    so the CP re-derives the same expected nonce.
    let nonce = Nonce::new({
        let mut n = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut n);
        n.to_vec()
    })
    .ok_or_else(|| SealError::BadCrypto("nonce gen".into()))?;
    let req = ne_attestation::EvidenceRequest {
        workspace_id: workspace_id.to_string(),
        measurement,
        nonce: nonce.clone(),
    };
    let evidence = evidence_provider
        .generate(&req, now)
        .map_err(|_| SealError::AttestationGateDenied(ne_attestation::FailReason::BadSignature))?;
    // 5. Resolve the DEK under the provider the seal pinned. Each arm fails
    //    closed before any DEK reaches memory.
    let dek: Zeroizing<[u8; 32]> = match seal.dek_envelope.kek_provider {
        KekProvider::SoftwareFallback => {
            let sw = sw_release.ok_or(SealError::ControlPlaneRelease(
                ControlPlaneError::Unconfigured,
            ))?;
            // Authoritative gate for the SW path — there is no server-side gate.
            evaluate_gate(&seal, &evidence, &nonce, now)?;
            sw.resolve_dek(&seal).await?
        }
        KekProvider::ControlPlane => {
            // FAIL-FAST defense-in-depth: a compromised host cannot
            // be trusted to gate itself, so this is NOT the security boundary.
            // It only avoids a round-trip when the host already knows its own
            // evidence fails; the authoritative gate runs server-side inside
            // `release_dek`. If this passes, fall through to the CP so the
            // server-side gate makes the real decision.
            evaluate_gate(&seal, &evidence, &nonce, now)?;
            let cp = cp.ok_or(SealError::ControlPlaneRelease(
                ControlPlaneError::Unconfigured,
            ))?;
            cp.release_dek(&seal, &evidence).await?
        }
    };
    // 6. Stream-decrypt mem + vmstate (DEK now in memory).
    let mh = seal.manifest_canonical_sha256.clone();
    let sid = seal.snapshot_id.clone();
    let ct_mem = tokio::fs::read(snapshot_dir.join(SEALED_MEM)).await?;
    let mut pt_mem: Vec<u8> = Vec::with_capacity(ct_mem.len());
    let mut reader = ct_mem.as_slice();
    decrypt_stream(&mut reader, &mut pt_mem, &dek, &sid, &mh)?;
    tokio::fs::write(out_mem, &pt_mem).await?;
    let ct_vm = tokio::fs::read(snapshot_dir.join(SEALED_VMSTATE)).await?;
    let mut pt_vm: Vec<u8> = Vec::with_capacity(ct_vm.len());
    let mut reader = ct_vm.as_slice();
    decrypt_stream(&mut reader, &mut pt_vm, &dek, &sid, &mh)?;
    tokio::fs::write(out_vmstate, &pt_vm).await?;
    // 7. DEK zeroized on drop (Zeroizing).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kek::wrap_dek;
    use crate::key_release::ControlPlaneKeyRelease;
    use crate::types::{DekEnvelope, SealingTrustAnchor};
    use ed25519_dalek::SigningKey;
    use ne_attestation::{AttestationProvider, EvidenceRequest, ProviderType, SoftwareProvider};
    use std::future::Future;
    use std::pin::Pin;

    fn host() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn policy_with_signer(vk: VerifyingKey) -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ProviderType::Software],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::Software {
                expected_signer: vk.to_bytes(),
            },
            expected_measurement: None,
        }
    }

    fn make_seal(host_sk: &SigningKey) -> (SealEnvelope, Nonce) {
        let vk = host_sk.verifying_key();
        let policy = policy_with_signer(vk);
        let dek = [9u8; 32];
        let env = wrap_dek(
            &dek,
            &crate::kek::derive_kek(host_sk),
            KekProvider::SoftwareFallback,
            "01S",
            "mh",
            &policy,
        )
        .expect("wrap_dek");
        let mut seal = SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy,
            dek_envelope: env,
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        sign_seal(&mut seal, host_sk).expect("sign_seal");
        let nonce = Nonce::new(vec![1u8; 16]).expect("16-byte nonce");
        (seal, nonce)
    }

    fn evidence(workspace_id: &str, issued_at: i64, sk: &SigningKey) -> Evidence {
        let provider = SoftwareProvider::new(sk.clone());
        let req = EvidenceRequest {
            workspace_id: workspace_id.into(),
            measurement: Measurement([3u8; 32]),
            nonce: Nonce::new(vec![1u8; 16]).expect("16-byte nonce"),
        };
        provider
            .generate(&req, issued_at)
            .expect("generate evidence")
    }

    #[test]
    fn seal_sign_verify_roundtrip() {
        let sk = host();
        let (seal, _) = make_seal(&sk);
        verify_seal_pinned(&seal, &sk.verifying_key()).expect("verify");
    }

    #[test]
    fn seal_rejects_untrusted_signer() {
        let attacker = SigningKey::from_bytes(&[0xAB; 32]);
        let host_sk = host();
        let (seal, _) = make_seal(&attacker);
        let err = verify_seal_pinned(&seal, &host_sk.verifying_key()).unwrap_err();
        assert!(matches!(err, SealError::UntrustedSigner), "{err:?}");
    }

    #[test]
    fn seal_rejects_tampered_policy() {
        let sk = host();
        let (mut seal, _) = make_seal(&sk);
        seal.policy.freshness_seconds = 99999; // breaks signature
        let err = verify_seal_pinned(&seal, &sk.verifying_key()).unwrap_err();
        assert!(matches!(err, SealError::SignatureMismatch), "{err:?}");
    }

    #[test]
    fn gate_opens_for_fresh_valid_evidence() {
        let sk = host();
        let (seal, nonce) = make_seal(&sk);
        let ev = evidence("ws", 1_700_000_010, &sk);
        evaluate_gate(&seal, &ev, &nonce, 1_700_000_015).expect("gate open");
    }

    #[test]
    fn gate_closes_on_stale_evidence() {
        let sk = host();
        let (seal, nonce) = make_seal(&sk);
        let ev = evidence("ws", 1_700_000_000, &sk);
        let err = evaluate_gate(&seal, &ev, &nonce, 1_700_000_999).unwrap_err();
        assert!(
            matches!(err, SealError::AttestationGateDenied(_)),
            "{err:?}"
        );
    }

    #[test]
    fn gate_closes_on_wrong_nonce() {
        let sk = host();
        let (seal, _nonce) = make_seal(&sk);
        let other = Nonce::new(vec![99u8; 16]).expect("16-byte nonce");
        let ev = evidence("ws", 1_700_000_010, &sk);
        let err = evaluate_gate(&seal, &ev, &other, 1_700_000_015).unwrap_err();
        assert!(
            matches!(err, SealError::AttestationGateDenied(_)),
            "{err:?}"
        );
    }

    #[test]
    fn gate_closes_on_untrusted_attestation_key() {
        let different = SigningKey::from_bytes(&[0xFE; 32]);
        let sk = host();
        let (seal, nonce) = make_seal(&sk); // policy pins host vk
        let ev = evidence("ws", 1_700_000_010, &different); // signed by a different key
        let err = evaluate_gate(&seal, &ev, &nonce, 1_700_000_015).unwrap_err();
        assert!(
            matches!(
                err,
                SealError::AttestationGateDenied(ne_attestation::FailReason::UntrustedSigner)
            ),
            "{err:?}"
        );
    }

    #[test]
    fn gate_sev_snp_synthetic_open_and_deny() {
        // HONEST: synthetic AMD-rooted material only. This
        // proves the gate's SevSnp arm opens on a chain-valid synthetic report
        // and closes on a reference-value (min_tcb) pin — NOT a real-silicon
        // or real-AMD-ARK claim.
        use ne_attestation::vcek::test_support::{self, SyntheticChain};
        use sha2::Sha512;

        let SyntheticChain {
            vcek_signing_key,
            vcek_leaf_der,
            ask_der,
            root: _root,
            ark_der,
        } = test_support::synthetic_chain();
        let canonical = ne_attestation::canonical_report_data(
            ProviderType::SevSnp,
            &EvidenceRequest {
                workspace_id: "ws".into(),
                measurement: Measurement([0u8; 32]),
                nonce: Nonce::new(vec![1u8; 16]).expect("16-byte nonce"),
            },
            1_700_000_000,
        );
        let mut h = Sha512::new();
        h.update(&canonical);
        let rd64: [u8; 64] = h.finalize().into();
        let mut report = vec![0u8; ne_attestation::snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&rd64);
        test_support::sign_report(&mut report, &vcek_signing_key);
        // Leaf-first `[VCEK, ASK]` — the real chain shape `verify_report` walks
        // (VCEK → ASK → ARK). Mirrors `KdsVcekFetcher::fetch`'s production output.
        let vcek_cert_chain = [vcek_leaf_der.as_slice(), ask_der.as_slice()].concat();
        let ev = Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws".into(),
            measurement: Measurement([0u8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_000,
            report_data: canonical,
            proof: ne_attestation::Proof::SevSnp {
                report,
                vcek_cert_chain,
            },
        };
        let nonce = Nonce::new(vec![1u8; 16]).expect("16-byte nonce");

        let open_policy = SealingPolicy {
            accept_provider_types: vec![ProviderType::SevSnp],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::SevSnp {
                amd_product_root_der: ark_der.clone(),
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
            expected_measurement: None,
        };
        let open_seal = SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: open_policy,
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::SoftwareFallback,
                wrapped_dek: vec![0u8; 48],
                wrap_nonce: vec![0u8; 12],
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        evaluate_gate(&open_seal, &ev, &nonce, 1_700_000_010).expect("synthetic sev-snp gate open");

        // Deny: min_tcb = 1 while the report's reported_tcb = 0.
        let mut deny_policy = open_seal.policy.clone();
        deny_policy.trust_anchor = SealingTrustAnchor::SevSnp {
            amd_product_root_der: ark_der,
            expected_host_cvm_meas: None,
            min_tcb: 1,
            guest_policy: 0,
        };
        let deny_seal = SealEnvelope {
            policy: deny_policy,
            ..open_seal
        };
        let err = evaluate_gate(&deny_seal, &ev, &nonce, 1_700_000_010).unwrap_err();
        assert!(
            matches!(
                err,
                SealError::AttestationGateDenied(ne_attestation::FailReason::PolicyMismatch)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn end_to_end_round_trip_software() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snap");
        tokio::fs::create_dir_all(&snap)
            .await
            .expect("create_dir_all");
        let plaintext_mem = b"MEM-CONTENTS".to_vec();
        let plaintext_vm = b"VM-CONTENTS".to_vec();
        tokio::fs::write(snap.join("mem"), &plaintext_mem)
            .await
            .expect("write mem");
        tokio::fs::write(snap.join("vmstate"), &plaintext_vm)
            .await
            .expect("write vmstate");

        let host_sk = host();
        let manifest = build_and_write_manifest(&snap, &host_sk).await;
        let vk = host_sk.verifying_key();

        // THE binding seal: encrypts the plaintext artifacts and writes
        // `seal.json` bound to the final manifest's canonical hash.
        let policy = policy_with_signer(vk);
        let _seal = seal_artifacts(
            &snap,
            &manifest,
            &host_sk,
            policy,
            KekProvider::SoftwareFallback,
            None,
        )
        .await
        .expect("seal_artifacts");

        let out_mem = dir.path().join("out_mem");
        let out_vm = dir.path().join("out_vm");
        let release = crate::key_release::SoftwareFallbackKeyRelease::new(&host_sk);
        unseal_artifacts(
            &snap,
            &vk,
            Some(&release),
            None,
            &SoftwareProvider::new(host_sk),
            "ws",
            Measurement([3u8; 32]),
            1_700_000_020,
            &out_mem,
            &out_vm,
        )
        .await
        .expect("unseal_artifacts");
        assert_eq!(
            tokio::fs::read(&out_mem).await.expect("read out_mem"),
            plaintext_mem
        );
        assert_eq!(
            tokio::fs::read(&out_vm).await.expect("read out_vm"),
            plaintext_vm
        );
    }

    /// Build the on-disk `manifest.json`. The manifest's `mem_sha256` /
    /// `vmstate_sha256` are computed over the FIRST seal pass's ciphertext; the
    /// test's subsequent `seal_artifacts` re-encrypts (new DEK + nonces), so
    /// those recorded hashes no longer match the on-disk ciphertext.
    ///
    /// This is HONEST about a limitation: `unseal_artifacts` does NOT re-verify
    /// manifest artifact hashes against the ciphertext files (it verifies
    /// manifest-sig → seal-sig → seal↔manifest binding → gate → DEK → decrypt).
    /// The load-bearing binding is `seal.manifest_canonical_sha256 ↔
    /// SHA256(manifest.canonical_bytes())`, which holds because the SAME final
    /// manifest is passed to `seal_artifacts` (by the caller) and written here.
    /// Re-verifying artifact hashes vs files is future hardening (tracked
    /// separately); this test proves the trust path that IS enforced.
    async fn build_and_write_manifest(snap: &Path, signer: &SigningKey) -> SnapshotManifest {
        use ne_protocol::snapshot::{GuestIdentity, MANIFEST_VERSION};

        // (i) Throwaway seal: produces `mem.sealed` / `vmstate.sealed` so we can
        // hash the ciphertext for the manifest. Its `seal.json` is overwritten
        // by the caller's binding `seal_artifacts` call.
        let throwaway = SnapshotManifest {
            manifest_version: MANIFEST_VERSION,
            snapshot_id: "01S".into(),
            created_from_workspace_id: "ws".into(),
            firecracker_version: "1.7.0".into(),
            mem_sha256: String::new(),
            vmstate_sha256: String::new(),
            kernel_sha256: "bb".repeat(32),
            rootfs_sha256: "cc".repeat(32),
            guest_identity: GuestIdentity {
                hostname: "h".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            kernel_boot_args: "console=ttyS0".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        let throwaway_policy = policy_with_signer(signer.verifying_key());
        let _ = seal_artifacts(
            snap,
            &throwaway,
            signer,
            throwaway_policy,
            KekProvider::SoftwareFallback,
            None,
        )
        .await
        .expect("throwaway seal");

        // (ii) SHA-256 the sealed ciphertext siblings.
        let mem_ct = tokio::fs::read(snap.join(SEALED_MEM))
            .await
            .expect("read mem.sealed");
        let vm_ct = tokio::fs::read(snap.join(SEALED_VMSTATE))
            .await
            .expect("read vmstate.sealed");
        let mem_hash = hex_digest(&mem_ct);
        let vm_hash = hex_digest(&vm_ct);

        // (iii) Build + sign the final manifest over those ciphertext hashes.
        let mut manifest = SnapshotManifest {
            manifest_version: MANIFEST_VERSION,
            snapshot_id: "01S".into(),
            created_from_workspace_id: "ws".into(),
            firecracker_version: "1.7.0".into(),
            mem_sha256: mem_hash,
            vmstate_sha256: vm_hash,
            kernel_sha256: "bb".repeat(32),
            rootfs_sha256: "cc".repeat(32),
            guest_identity: GuestIdentity {
                hostname: "h".into(),
                mac: "06:00:00:00:00:01".into(),
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 128,
            },
            kernel_boot_args: "console=ttyS0".into(),
            signer_pubkey_b64: B64.encode(signer.verifying_key().as_bytes()),
            signature_b64: String::new(),
        };
        let sig = signer.sign(
            &manifest
                .canonical_bytes()
                .expect("manifest canonical_bytes"),
        );
        manifest.signature_b64 = B64.encode(sig.to_bytes());

        // (iv) Persist the final manifest.
        tokio::fs::write(
            snap.join(MANIFEST_JSON),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .await
        .expect("write manifest.json");
        manifest
    }

    fn hex_digest(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// In-process mock CP implementing BOTH `CpWrapClient` (seal-time wrap) and
    /// `ControlPlaneKeyRelease` (restore-time release). Mirrors what the real
    /// The software backend does: wrap stores the DEK keyed by the returned blob
    /// (transparent wrap — the blob IS the DEK); release looks up the stored DEK
    /// by the seal's `wrapped_dek`. Reused by unseal round-trip tests.
    ///
    /// `release_count` lets the fail-fast test prove the CP's `release_dek` is
    /// NEVER called when the local gate denies (defense-in-depth).
    #[derive(Debug, Default, Clone)]
    #[allow(clippy::type_complexity)]
    struct MockCp {
        wraps: std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, [u8; 32])>>>,
        workspace_ids: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        release_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MockCp {
        /// Number of times `release_dek` has been invoked.
        fn release_count(&self) -> u64 {
            self.release_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl CpWrapClient for MockCp {
        #[allow(clippy::type_complexity)]
        fn wrap_dek<'a>(
            &'a self,
            dek: &'a [u8; 32],
            workspace_id: &'a str,
            _snapshot_id: &'a str,
            _manifest_hash: &'a str,
            _policy: &'a SealingPolicy,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), SealError>> + Send + 'a>>
        {
            Box::pin(async move {
                // The blob tag is the stored DEK index; the returned wrapped
                // blob is the DEK itself (transparent wrap, like the SW CP
                // backend). The nonce is a fixed marker.
                let blob = dek.to_vec();
                self.wraps
                    .lock()
                    .expect("mock wraps lock")
                    .push((blob.clone(), *dek));
                self.workspace_ids
                    .lock()
                    .expect("mock workspace IDs lock")
                    .push(workspace_id.to_string());
                Ok((blob, vec![9u8; 12]))
            })
        }
    }

    impl ControlPlaneKeyRelease for MockCp {
        #[allow(clippy::type_complexity)]
        fn release_dek<'a>(
            &'a self,
            seal: &'a SealEnvelope,
            _evidence: &'a Evidence,
        ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.release_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Store-and-return: find the DEK the wrap path stored under the
                // seal's `wrapped_dek` blob. If none matches, the seal predates
                // any wrap against this mock — `Unconfigured` is the honest
                // framing (the mock has no record for this blob), not
                // `BadResponse` (the CP DID respond, we just never stored it).
                let wraps = self.wraps.lock().expect("mock wraps lock");
                for (blob, dek) in wraps.iter() {
                    if blob == &seal.dek_envelope.wrapped_dek {
                        return Ok(Zeroizing::new(*dek));
                    }
                }
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Unconfigured,
                ))
            })
        }
    }

    /// Seal-time CP branch: when `kek_provider == ControlPlane`, `seal_artifacts`
    /// delegates the DEK wrap to the CP instead of the local HKDF path. Full
    /// The end-to-end seal→unseal test asserts the envelope reflects the
    /// CP wrap result.
    #[tokio::test]
    async fn seal_cp_path_uses_cp_wrap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snap");
        tokio::fs::create_dir_all(&snap)
            .await
            .expect("create_dir_all");
        tokio::fs::write(snap.join("mem"), b"MEM")
            .await
            .expect("write mem");
        tokio::fs::write(snap.join("vmstate"), b"VM")
            .await
            .expect("write vmstate");

        let host_sk = host();
        let manifest = build_and_write_manifest(&snap, &host_sk).await;
        let vk = host_sk.verifying_key();
        let policy = policy_with_signer(vk);

        let cp = MockCp::default();
        let seal = seal_artifacts(
            &snap,
            &manifest,
            &host_sk,
            policy,
            KekProvider::ControlPlane,
            Some(&cp),
        )
        .await
        .expect("seal_artifacts CP");

        assert_eq!(seal.dek_envelope.kek_provider, KekProvider::ControlPlane);
        // The mock's wrap returns the DEK itself as the wrapped blob.
        assert_eq!(seal.dek_envelope.wrapped_dek.len(), 32);
        assert_eq!(seal.dek_envelope.wrap_nonce, vec![9u8; 12]);
        assert_eq!(
            seal.dek_envelope.wrapped_dek,
            cp.wraps.lock().unwrap().last().unwrap().0
        );
        assert_eq!(
            *cp.workspace_ids.lock().expect("mock workspace IDs lock"),
            vec![manifest.created_from_workspace_id.clone()]
        );
    }

    /// `ControlPlane` provider without a CP client is a misconfiguration that
    /// must `fail-closed`.
    #[tokio::test]
    async fn seal_cp_path_without_client_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snap");
        tokio::fs::create_dir_all(&snap)
            .await
            .expect("create_dir_all");
        tokio::fs::write(snap.join("mem"), b"MEM")
            .await
            .expect("write mem");
        tokio::fs::write(snap.join("vmstate"), b"VM")
            .await
            .expect("write vmstate");

        let host_sk = host();
        let manifest = build_and_write_manifest(&snap, &host_sk).await;
        let policy = policy_with_signer(host_sk.verifying_key());

        let err = seal_artifacts(
            &snap,
            &manifest,
            &host_sk,
            policy,
            KekProvider::ControlPlane,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Unconfigured)
            ),
            "{err:?}"
        );
    }

    /// Proves the `MockCp` double's wrap→release round-trip: the DEK handed to
    /// `CpWrapClient::wrap_dek` is recovered verbatim from
    /// `ControlPlaneKeyRelease::release_dek`. This is the seam that unseal
    /// round-trip builds on — a self-contained proof that the double, in
    /// isolation, faithfully returns what it stored.
    #[tokio::test]
    async fn mockcp_release_returns_wrapped_dek() {
        let cp = MockCp::default();
        let dek = [0x42u8; 32];
        let policy = policy_with_signer(host().verifying_key());
        let (wrapped, nonce) = cp
            .wrap_dek(&dek, "source-workspace", "01S", "mh", &policy)
            .await
            .expect("wrap_dek");

        // Build a control-plane seal envelope the way `seal_artifacts` does:
        // verbatim storage of the wrap result.
        let seal = SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: policy_with_signer(host().verifying_key()),
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: wrapped,
                wrap_nonce: nonce,
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        // Evidence content is irrelevant to the mock's release (it does not
        // re-gate); any well-formed Evidence exercises the trait path.
        let ev = evidence("ws", 1_700_000_010, &host());
        let released = cp.release_dek(&seal, &ev).await.expect("release_dek");
        assert_eq!(*released, dek);
    }

    // ---- Control-plane unseal matrix -----------------------------------------

    /// Evidence provider that stamps evidence `STALE_OFFSET` seconds in the past
    /// relative to the `now` the caller passes — forces the freshness gate to
    /// deny. Test-only; used to exercise the fail-fast local gate on the CP
    /// unseal path without tampering with the (signature-checked) evidence.
    #[derive(Debug)]
    struct StaleEvidenceProvider {
        inner: SoftwareProvider,
    }

    const STALE_OFFSET: i64 = 10_000;

    impl StaleEvidenceProvider {
        fn new(sk: SigningKey) -> Self {
            Self {
                inner: SoftwareProvider::new(sk),
            }
        }
    }

    impl AttestationProvider for StaleEvidenceProvider {
        fn provider_type(&self) -> ProviderType {
            self.inner.provider_type()
        }

        fn generate(
            &self,
            req: &EvidenceRequest,
            issued_at: i64,
        ) -> Result<Evidence, ne_attestation::AttestationError> {
            self.inner.generate(req, issued_at - STALE_OFFSET)
        }
    }

    /// CP client that always denies release. Mirrors the real CP's authoritative
    /// 403 path: the runtime's local fail-fast gate PASSED, but the server-side
    /// gate denies (the authoritative decision).
    #[derive(Debug, Default)]
    struct DenyingMockCp;

    impl ControlPlaneKeyRelease for DenyingMockCp {
        #[allow(clippy::type_complexity)]
        fn release_dek<'a>(
            &'a self,
            _seal: &'a SealEnvelope,
            _evidence: &'a Evidence,
        ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>>
        {
            Box::pin(async {
                Err(SealError::ControlPlaneRelease(ControlPlaneError::Denied(
                    "test deny".into(),
                )))
            })
        }
    }

    /// Build a CP-sealed snapshot in a tempdir: plaintext `mem`/`vmstate`,
    /// manifest, and a `ControlPlane` envelope sealed under `cp`. Returns the
    /// tempdir (kept alive for the test) and the snapshot dir path.
    async fn cp_sealed_snapshot(
        sk: &SigningKey,
        cp: &MockCp,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = dir.path().join("snap");
        tokio::fs::create_dir_all(&snap)
            .await
            .expect("create_dir_all");
        tokio::fs::write(snap.join("mem"), b"MEM")
            .await
            .expect("write mem");
        tokio::fs::write(snap.join("vmstate"), b"VM")
            .await
            .expect("write vmstate");
        let manifest = build_and_write_manifest(&snap, sk).await;
        let policy = policy_with_signer(sk.verifying_key());
        let _seal = seal_artifacts(
            &snap,
            &manifest,
            sk,
            policy,
            KekProvider::ControlPlane,
            Some(cp),
        )
        .await
        .expect("seal_artifacts CP");
        (dir, snap)
    }

    /// CP unseal happy path: seal under the CP, unseal restores byte-identical
    /// plaintext. The fail-fast local gate opens (fresh, valid evidence), then
    /// the CP releases the DEK, then decrypt.
    #[tokio::test]
    async fn unseal_cp_happy_path() {
        let host_sk = host();
        let cp = MockCp::default();
        let (_dir, snap) = cp_sealed_snapshot(&host_sk, &cp).await;
        let vk = host_sk.verifying_key();

        let out_mem = snap.parent().unwrap().join("om");
        let out_vm = snap.parent().unwrap().join("ov");
        unseal_artifacts(
            &snap,
            &vk,
            None,
            Some(&cp),
            &SoftwareProvider::new(host_sk.clone()),
            "ws",
            Measurement([3u8; 32]),
            1_700_000_020,
            &out_mem,
            &out_vm,
        )
        .await
        .expect("unseal_artifacts CP happy path");
        assert_eq!(tokio::fs::read(&out_mem).await.expect("read om"), b"MEM");
        assert_eq!(tokio::fs::read(&out_vm).await.expect("read ov"), b"VM");
        assert_eq!(cp.release_count(), 1, "CP release_dek called exactly once");
    }

    /// FAIL-FAST defense-in-depth: when the local gate denies (stale evidence),
    /// the CP's `release_dek` is NEVER invoked — fail-closed without the
    /// round-trip. This local gate is NOT the security
    /// boundary; if the CP WERE called it would also deny. The point is early,
    /// cheap fail-closed.
    #[tokio::test]
    async fn unseal_cp_fail_fast_local_gate_denies() {
        let host_sk = host();
        let cp = MockCp::default();
        let (_dir, snap) = cp_sealed_snapshot(&host_sk, &cp).await;
        let vk = host_sk.verifying_key();

        let out_mem = snap.parent().unwrap().join("om");
        let out_vm = snap.parent().unwrap().join("ov");
        // StaleEvidenceProvider stamps evidence STALE_OFFSET in the past, so the
        // local freshness gate denies before the CP is contacted.
        let err = unseal_artifacts(
            &snap,
            &vk,
            None,
            Some(&cp),
            &StaleEvidenceProvider::new(host_sk.clone()),
            "ws",
            Measurement([3u8; 32]),
            1_700_000_020,
            &out_mem,
            &out_vm,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::AttestationGateDenied(ne_attestation::FailReason::Stale)
            ),
            "{err:?}"
        );
        assert_eq!(
            cp.release_count(),
            0,
            "CP release_dek must NOT be called on fail-fast"
        );
    }

    /// AUTHORITATIVE CP gate: the local fail-fast gate opens, but the CP denies
    /// (server-side decision). The DEK never reaches memory.
    #[tokio::test]
    async fn unseal_cp_cp_gate_denies() {
        let host_sk = host();
        // Seal under a transparent MockCp so the envelope is well-formed, then
        // unseal against the denying client (the seal envelope is
        // provider-agnostic — only `kek_provider` matters).
        let cp_seal = MockCp::default();
        let (_dir, snap) = cp_sealed_snapshot(&host_sk, &cp_seal).await;
        let vk = host_sk.verifying_key();

        let deny = DenyingMockCp;
        let out_mem = snap.parent().unwrap().join("om");
        let out_vm = snap.parent().unwrap().join("ov");
        let err = unseal_artifacts(
            &snap,
            &vk,
            None,
            Some(&deny),
            &SoftwareProvider::new(host_sk.clone()),
            "ws",
            Measurement([3u8; 32]),
            1_700_000_020,
            &out_mem,
            &out_vm,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Denied(_))
            ),
            "{err:?}"
        );
    }

    /// A `ControlPlane` envelope with no CP client configured is a
    /// misconfiguration that must fail-closed with `Unconfigured`.
    #[tokio::test]
    async fn unseal_cp_unconfigured_no_client() {
        let host_sk = host();
        let cp = MockCp::default();
        let (_dir, snap) = cp_sealed_snapshot(&host_sk, &cp).await;
        let vk = host_sk.verifying_key();

        let out_mem = snap.parent().unwrap().join("om");
        let out_vm = snap.parent().unwrap().join("ov");
        let err = unseal_artifacts(
            &snap,
            &vk,
            None,
            None,
            &SoftwareProvider::new(host_sk.clone()),
            "ws",
            Measurement([3u8; 32]),
            1_700_000_020,
            &out_mem,
            &out_vm,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Unconfigured)
            ),
            "{err:?}"
        );
        // The local fail-fast gate ran (fresh evidence) but the CP arm never
        // reached release_dek because no client was supplied — so the shared
        // MockCp here is irrelevant; the deny is structural.
        assert_eq!(cp.release_count(), 0);
    }
}

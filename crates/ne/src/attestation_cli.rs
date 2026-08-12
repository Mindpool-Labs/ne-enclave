// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! CLI-side export and offline verification for public attestation evidence.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;
use ne_attestation::vcek::AmdRootCert;
use ne_attestation::{
    CvmMeasurement, Measurement, Nonce, TrustAnchor, VerifyOutcome, VerifyParams,
};
use ne_protocol::attestation::{PublicAttestationEvidence, PublicAttestationProvider};
use serde::Deserialize;

/// Offline attestation verification policy loaded from JSON.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyPolicy {
    /// Public evidence providers the verifier accepts.
    pub accepted_providers: Vec<PublicAttestationProvider>,
    /// Workspace identifier the evidence must bind.
    pub expected_workspace_id: String,
    /// Caller challenge nonce as hex.
    pub expected_nonce_hex: String,
    /// Maximum evidence age in seconds.
    pub freshness_seconds: u64,
    /// Optional expected 32-byte workspace measurement as hex.
    pub expected_workspace_measurement_hex: Option<String>,
    /// Optional expected 48-byte host-CVM launch measurement as hex.
    pub expected_host_cvm_measurement_hex: Option<String>,
    /// Required out-of-band Ed25519 public key for software evidence, as base64.
    pub expected_signer_b64: Option<String>,
    /// Minimum accepted SNP reported TCB, as a canonical decimal string.
    ///
    /// A string rather than a JSON number for the same reason as
    /// `SealingTrustAnchor::SevSnp` — see [`ne_attestation::u64_str`]. This
    /// file is authored by hand and by tooling: `jq` represents JSON numbers
    /// as IEEE-754 doubles, so a production TCB floor written as a number is
    /// rounded, and the rounding moves the floor **down**. That failure is
    /// silent and it fails open.
    #[serde(with = "ne_attestation::u64_str")]
    pub min_tcb: u64,
    /// Required SNP guest-policy bits, as a canonical decimal string.
    ///
    /// Real guest-policy values sit far below 2^53 and were never at risk of
    /// rounding. Encoded as a string only so one pin has one wire form across
    /// every file the verifier reads.
    #[serde(with = "ne_attestation::u64_str")]
    pub guest_policy: u64,
}

/// Verify one public evidence JSON file against one policy JSON file.
///
/// Verification is fully offline: software evidence uses the caller-pinned
/// Ed25519 signer, while SNP evidence uses the built-in AMD Milan root and the
/// VCEK chain embedded in the evidence.
pub fn verify_files(evidence_path: &Path, policy_path: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    verify_files_at(
        evidence_path,
        policy_path,
        i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
    )
}

fn verify_files_at(evidence_path: &Path, policy_path: &Path, now: i64) -> Result<()> {
    let evidence_json = std::fs::read(evidence_path)
        .with_context(|| format!("reading evidence {}", evidence_path.display()))?;
    let evidence: PublicAttestationEvidence = serde_json::from_slice(&evidence_json)
        .with_context(|| format!("parsing evidence {}", evidence_path.display()))?;
    let policy_json = std::fs::read(policy_path)
        .with_context(|| format!("reading policy {}", policy_path.display()))?;
    let policy: VerifyPolicy = serde_json::from_slice(&policy_json)
        .with_context(|| format!("parsing policy {}", policy_path.display()))?;

    verify_evidence_at(evidence, policy, now)
}

fn verify_evidence_at(
    evidence: PublicAttestationEvidence,
    policy: VerifyPolicy,
    now: i64,
) -> Result<()> {
    if evidence.workspace_id != policy.expected_workspace_id {
        anyhow::bail!(
            "workspace id mismatch: expected {:?}, got {:?}",
            policy.expected_workspace_id,
            evidence.workspace_id
        );
    }
    if !policy.accepted_providers.contains(&evidence.provider) {
        anyhow::bail!(
            "attestation provider {:?} is not accepted by policy",
            evidence.provider
        );
    }

    let expected_nonce_bytes =
        hex::decode(&policy.expected_nonce_hex).context("expected_nonce_hex must be valid hex")?;
    let expected_nonce = Nonce::new(expected_nonce_bytes)
        .ok_or_else(|| anyhow::anyhow!("expected_nonce_hex must decode to 16..=64 bytes"))?;
    let expected_measurement = policy
        .expected_workspace_measurement_hex
        .as_deref()
        .map(|value| parse_hex_array::<32>("expected_workspace_measurement_hex", value))
        .transpose()?
        .map(Measurement);
    let expected_host_cvm_measurement = policy
        .expected_host_cvm_measurement_hex
        .as_deref()
        .map(|value| parse_hex_array::<48>("expected_host_cvm_measurement_hex", value))
        .transpose()?
        .map(CvmMeasurement);
    let expected_signer = policy
        .expected_signer_b64
        .as_deref()
        .map(parse_software_signer)
        .transpose()?;

    let public_provider = evidence.provider;
    let domain = ne_attestation::Evidence::try_from(evidence)
        .context("public evidence contract validation failed")?;
    let accepted_provider_types = [domain.provider_type];
    let freshness = Duration::from_secs(policy.freshness_seconds);

    let outcome = match public_provider {
        PublicAttestationProvider::Software => {
            let expected_signer = expected_signer.as_ref().ok_or_else(|| {
                anyhow::anyhow!("expected_signer_b64 is required for software evidence")
            })?;
            ne_attestation::verify(
                &domain,
                &VerifyParams {
                    expected_nonce: &expected_nonce,
                    expected_measurement: expected_measurement.as_ref(),
                    accept_provider_types: &accepted_provider_types,
                    freshness,
                    now,
                    trust_anchor: TrustAnchor::Software { expected_signer },
                },
            )
        }
        PublicAttestationProvider::SevSnpDirect | PublicAttestationProvider::SevSnpAzure => {
            let amd_product_root =
                AmdRootCert::milan_default().context("loading built-in AMD Milan root")?;
            ne_attestation::verify(
                &domain,
                &VerifyParams {
                    expected_nonce: &expected_nonce,
                    expected_measurement: expected_measurement.as_ref(),
                    accept_provider_types: &accepted_provider_types,
                    freshness,
                    now,
                    trust_anchor: TrustAnchor::SevSnp {
                        amd_product_root: &amd_product_root,
                        expected_host_cvm_meas: expected_host_cvm_measurement.as_ref(),
                        min_tcb: policy.min_tcb,
                        guest_policy: policy.guest_policy,
                    },
                },
            )
        }
    };

    match outcome {
        VerifyOutcome::Verified => Ok(()),
        VerifyOutcome::Failed(reason) => {
            anyhow::bail!("attestation verification failed: {reason:?}")
        }
    }
}

fn parse_hex_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{field} must be valid hex"))?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must decode to {N} bytes, got {actual}"))
}

fn parse_software_signer(value: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(value.as_bytes())
        .context("expected_signer_b64 must be valid base64")?;
    let actual = bytes.len();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("expected_signer_b64 must decode to 32 bytes, got {actual}")
    })?;
    VerifyingKey::from_bytes(&bytes).context("expected_signer_b64 is not a valid Ed25519 key")
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::SigningKey;
    use ne_attestation::{
        AttestationProvider as _, EvidenceRequest, Measurement, Nonce, SoftwareProvider,
    };
    use ne_protocol::attestation::PublicAttestationEvidence;

    fn signed_public_evidence(
        issued_at: i64,
    ) -> (PublicAttestationEvidence, ed25519_dalek::VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let provider = SoftwareProvider::new(signing_key);
        let evidence = provider
            .generate(
                &EvidenceRequest {
                    workspace_id: "secret-1".to_string(),
                    measurement: Measurement([0x11; 32]),
                    nonce: Nonce::new(vec![0xaa; 16]).expect("valid nonce"),
                },
                issued_at,
            )
            .expect("generate software evidence");
        (
            PublicAttestationEvidence::try_from(evidence).expect("domain -> public"),
            verifying_key,
        )
    }

    fn policy_json(signer: &ed25519_dalek::VerifyingKey) -> serde_json::Value {
        serde_json::json!({
            "accepted_providers": ["software"],
            "expected_workspace_id": "secret-1",
            "expected_nonce_hex": "aa".repeat(16),
            "freshness_seconds": 300,
            "expected_workspace_measurement_hex": null,
            "expected_host_cvm_measurement_hex": null,
            "expected_signer_b64": B64.encode(signer.as_bytes()),
            "min_tcb": "0",
            "guest_policy": "0"
        })
    }

    fn write_case(
        evidence: &PublicAttestationEvidence,
        policy: &serde_json::Value,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let evidence_path = dir.path().join("evidence.json");
        let policy_path = dir.path().join("policy.json");
        std::fs::write(
            &evidence_path,
            serde_json::to_vec_pretty(evidence).expect("evidence JSON"),
        )
        .expect("write evidence");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(policy).expect("policy JSON"),
        )
        .expect("write policy");
        (dir, evidence_path, policy_path)
    }

    fn verify_at(evidence_path: &Path, policy_path: &Path, now: i64) -> anyhow::Result<()> {
        super::verify_files_at(evidence_path, policy_path, now)
    }

    #[test]
    fn verified_software_evidence_passes() {
        let (evidence, signer) = signed_public_evidence(1_700_000_000);
        let policy = policy_json(&signer);
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        verify_at(&evidence_path, &policy_path, 1_700_000_010).expect("valid signed evidence");
    }

    #[test]
    fn public_verify_files_uses_current_time() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time")
            .as_secs();
        let now = i64::try_from(now).expect("timestamp fits i64");
        let (evidence, signer) = signed_public_evidence(now);
        let policy = policy_json(&signer);
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        super::verify_files(&evidence_path, &policy_path).expect("public verifier");
    }

    #[test]
    fn malformed_expected_nonce_is_rejected() {
        let (evidence, signer) = signed_public_evidence(1_700_000_000);
        let mut policy = policy_json(&signer);
        policy["expected_nonce_hex"] = serde_json::json!("aa");
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        let error =
            verify_at(&evidence_path, &policy_path, 1_700_000_010).expect_err("short policy nonce");
        assert!(error.to_string().contains("16..=64"));
    }

    #[test]
    fn unaccepted_public_provider_is_rejected() {
        let (evidence, signer) = signed_public_evidence(1_700_000_000);
        let mut policy = policy_json(&signer);
        policy["accepted_providers"] = serde_json::json!(["sev_snp_azure"]);
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        let error = verify_at(&evidence_path, &policy_path, 1_700_000_010)
            .expect_err("software provider is not accepted");
        assert!(error.to_string().contains("not accepted"));
    }

    #[test]
    fn stale_evidence_is_rejected() {
        let (evidence, signer) = signed_public_evidence(1_700_000_000);
        let policy = policy_json(&signer);
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        let error = verify_at(&evidence_path, &policy_path, 1_700_000_301)
            .expect_err("evidence outside freshness window");
        assert!(error.to_string().contains("Stale"));
    }

    #[test]
    fn untrusted_software_signer_is_rejected() {
        let (evidence, _signer) = signed_public_evidence(1_700_000_000);
        let other = SigningKey::from_bytes(&[0x24; 32]).verifying_key();
        let policy = policy_json(&other);
        let (_dir, evidence_path, policy_path) = write_case(&evidence, &policy);

        let error = verify_at(&evidence_path, &policy_path, 1_700_000_010)
            .expect_err("wrong out-of-band signer");
        assert!(error.to_string().contains("UntrustedSigner"));
    }
}

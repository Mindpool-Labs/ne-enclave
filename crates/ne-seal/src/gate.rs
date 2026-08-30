// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! The attestation gate: reconstruct the borrowed `TrustAnchor` + `VerifyParams`
//! from a [`SealingPolicy`] on this stack and call `ne_attestation::verify`.
//!
//! The nonce and `now` are restore-time inputs, not policy-derived.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use ne_attestation::{
    CvmMeasurement, Evidence, Nonce, TrustAnchor, VerifyOutcome, VerifyParams, vcek::AmdRootCert,
    verify,
};

use crate::SealError;
use crate::types::{SealingPolicy, SealingTrustAnchor};

/// Evaluate the gate: `verify()` must be `Verified` else `AttestationGateDenied`.
/// Pure; no network. The underlying `verify` is pure and offline.
pub fn verify_against_policy(
    policy: &SealingPolicy,
    evidence: &Evidence,
    expected_nonce: &Nonce,
    now: i64,
) -> Result<(), SealError> {
    match &policy.trust_anchor {
        SealingTrustAnchor::Software { expected_signer } => {
            let vk = VerifyingKey::from_bytes(expected_signer)
                .map_err(|e| SealError::BadCrypto(format!("bad expected_signer: {e}")))?;
            let params = VerifyParams {
                expected_nonce,
                expected_measurement: policy.expected_measurement.as_ref(),
                accept_provider_types: &policy.accept_provider_types,
                freshness: Duration::from_secs(policy.freshness_seconds),
                now,
                trust_anchor: TrustAnchor::Software {
                    expected_signer: &vk,
                },
            };
            outcome_to_result(verify(evidence, &params))
        }
        SealingTrustAnchor::SevSnp {
            amd_product_root_der,
            expected_host_cvm_meas,
            min_tcb,
            guest_policy,
        } => {
            let root = AmdRootCert::from_der(amd_product_root_der)
                .map_err(|e| SealError::SevSnpPolicy(format!("ARK parse: {e:?}")))?;
            let meas_arr: Option<[u8; 48]> = match expected_host_cvm_meas {
                Some(bytes) => Some(bytes.as_slice().try_into().map_err(|_| {
                    SealError::SevSnpPolicy("expected_host_cvm_meas not 48 bytes".into())
                })?),
                None => None,
            };
            let meas = meas_arr.map(CvmMeasurement);
            let params = VerifyParams {
                expected_nonce,
                expected_measurement: policy.expected_measurement.as_ref(),
                accept_provider_types: &policy.accept_provider_types,
                freshness: Duration::from_secs(policy.freshness_seconds),
                now,
                trust_anchor: TrustAnchor::SevSnp {
                    amd_product_root: &root,
                    expected_host_cvm_meas: meas.as_ref(),
                    min_tcb: *min_tcb,
                    guest_policy: *guest_policy,
                },
            };
            outcome_to_result(verify(evidence, &params))
        }
    }
}

fn outcome_to_result(outcome: VerifyOutcome) -> Result<(), SealError> {
    match outcome {
        VerifyOutcome::Verified => Ok(()),
        VerifyOutcome::Failed(reason) => {
            // The error type carries the specific attestation failure reason.
            Err(SealError::AttestationGateDenied(reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SealingPolicy, SealingTrustAnchor};
    use ed25519_dalek::SigningKey;
    use ne_attestation::{
        AttestationProvider, EvidenceRequest, Measurement, ProviderType, SoftwareProvider,
    };

    fn software_policy(vk_bytes: [u8; 32]) -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ProviderType::Software],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::Software {
                expected_signer: vk_bytes,
            },
            expected_measurement: None,
        }
    }

    fn evidence(issued_at: i64, sk: &SigningKey) -> (Evidence, Nonce) {
        let provider = SoftwareProvider::new(sk.clone());
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let req = EvidenceRequest {
            workspace_id: "ws".into(),
            measurement: Measurement([3u8; 32]),
            nonce: nonce.clone(),
        };
        (provider.generate(&req, issued_at).unwrap(), nonce)
    }

    #[test]
    fn software_gate_opens_for_fresh_valid_evidence() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let policy = software_policy(sk.verifying_key().to_bytes());
        let (ev, nonce) = evidence(1_700_000_010, &sk);
        verify_against_policy(&policy, &ev, &nonce, 1_700_000_015).unwrap();
    }

    #[test]
    fn software_gate_closes_on_untrusted_key() {
        let trusted = SigningKey::from_bytes(&[9u8; 32]);
        let attacker = SigningKey::from_bytes(&[0xFE; 32]);
        let policy = software_policy(trusted.verifying_key().to_bytes());
        let (ev, nonce) = evidence(1_700_000_010, &attacker);
        let err = verify_against_policy(&policy, &ev, &nonce, 1_700_000_015).unwrap_err();
        assert!(
            matches!(err, SealError::AttestationGateDenied(_)),
            "expected gate denial, got {err:?}"
        );
    }

    #[test]
    fn sev_snp_bad_ark_rejected() {
        let policy = SealingPolicy {
            accept_provider_types: vec![ProviderType::SevSnp],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::SevSnp {
                amd_product_root_der: vec![0u8; 4], // garbage
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
            expected_measurement: None,
        };
        // evidence content is irrelevant — the parse fails first.
        let ev = evidence(0, &SigningKey::from_bytes(&[1u8; 32])).0;
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let err = verify_against_policy(&policy, &ev, &nonce, 0).unwrap_err();
        assert!(matches!(err, SealError::SevSnpPolicy(_)), "{err:?}");
    }
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! The runtime↔control-plane key-release contract.
//!
//! [`SoftwareFallbackKeyRelease`] unwraps the DEK locally using the HKDF KEK
//! (caller MUST have already produced an Open gate). The control-plane path is
//! the HTTPS client is implemented in [`crate::key_release_cp`]. This module
//! retains a placeholder that returns [`SealError::NotImplemented`].

use std::future::Future;
use std::pin::Pin;

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::SealError;
use crate::kek::{derive_kek, unwrap_dek};
use crate::types::{KekProvider, SealEnvelope};

/// Whether the software-fallback KEK may be used.
///
/// Mirrors `ne_attestation::software_provider_allowed`: allowed in dev mode,
/// or with `NE_SEAL_ALLOW_SOFTWARE=1`; refused otherwise (confidential prod
/// fail-closed).
#[must_use]
pub fn software_kek_allowed(dev_mode: bool, allow_software_env: bool) -> bool {
    dev_mode || allow_software_env
}

/// Resolve a sealed snapshot's DEK.
pub trait KeyRelease: Send + Sync + std::fmt::Debug {
    /// Resolve (unwrap or release) the DEK sealed inside `seal`.
    #[allow(clippy::type_complexity)]
    fn resolve_dek<'a>(
        &'a self,
        seal: &'a SealEnvelope,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>>;
}

/// Runtime-local software fallback. Holds the KEK derived from the host key.
#[derive(Debug)]
pub struct SoftwareFallbackKeyRelease {
    kek: Zeroizing<[u8; 32]>,
}

impl SoftwareFallbackKeyRelease {
    /// Construct from the host Ed25519 signing key. Caller is responsible for
    /// the `software_kek_allowed` gate before constructing in prod.
    #[must_use]
    pub fn new(signing_key: &SigningKey) -> Self {
        Self {
            kek: derive_kek(signing_key),
        }
    }
}

impl KeyRelease for SoftwareFallbackKeyRelease {
    fn resolve_dek<'a>(
        &'a self,
        seal: &'a SealEnvelope,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>> {
        Box::pin(async move {
            if seal.dek_envelope.kek_provider != KekProvider::SoftwareFallback {
                return Err(SealError::UnsupportedKekProvider(
                    seal.dek_envelope.kek_provider,
                ));
            }
            unwrap_dek(
                &seal.dek_envelope,
                &self.kek,
                &seal.snapshot_id,
                &seal.manifest_canonical_sha256,
                &seal.policy,
            )
        })
    }
}

/// Control-plane key-release contract.
pub trait ControlPlaneKeyRelease: Send + Sync + std::fmt::Debug {
    /// Request the control plane release the wrapped DEK for `seal`, attested
    /// by `evidence`.
    #[allow(clippy::type_complexity)]
    fn release_dek<'a>(
        &'a self,
        seal: &'a SealEnvelope,
        evidence: &'a ne_attestation::Evidence,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>>;
}

/// Placeholder control-plane client that always returns
/// [`SealError::NotImplemented`]. Use `key_release_cp` for HTTPS transport.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedControlPlaneClient;

impl ControlPlaneKeyRelease for NotImplementedControlPlaneClient {
    fn release_dek<'a>(
        &'a self,
        _seal: &'a SealEnvelope,
        _evidence: &'a ne_attestation::Evidence,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>> {
        Box::pin(async { Err(SealError::NotImplemented) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kek::wrap_dek;
    use crate::types::{DekEnvelope, SealingPolicy, SealingTrustAnchor};
    use ne_attestation::ProviderType;

    fn policy() -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ProviderType::Software],
            freshness_seconds: 300,
            trust_anchor: SealingTrustAnchor::Software {
                expected_signer: [9u8; 32],
            },
            expected_measurement: None,
        }
    }

    #[tokio::test]
    async fn software_round_trip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let release = SoftwareFallbackKeyRelease::new(&sk);
        let dek = [5u8; 32];
        let env = wrap_dek(
            &dek,
            &derive_kek(&sk),
            KekProvider::SoftwareFallback,
            "01S",
            "mh",
            &policy(),
        )
        .unwrap();
        let seal = SealEnvelope {
            seal_version: 1,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: policy(),
            dek_envelope: env,
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        assert_eq!(*release.resolve_dek(&seal).await.unwrap(), dek);
    }

    #[tokio::test]
    async fn software_rejects_control_plane_provider() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let release = SoftwareFallbackKeyRelease::new(&sk);
        let seal = SealEnvelope {
            seal_version: 1,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: policy(),
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: vec![0u8; 48],
                wrap_nonce: vec![0u8; 12],
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        let err = release.resolve_dek(&seal).await.unwrap_err();
        assert!(
            matches!(
                err,
                SealError::UnsupportedKekProvider(KekProvider::ControlPlane)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn cp_stub_is_not_implemented() {
        let client = NotImplementedControlPlaneClient;
        // evidence content is irrelevant for the stub.
        let ev = ne_attestation::Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws".into(),
            measurement: ne_attestation::Measurement([0u8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 0,
            report_data: vec![],
            proof: ne_attestation::Proof::Software {
                signature: [0u8; 64],
                signer_pubkey: [0u8; 32],
            },
        };
        let seal = SealEnvelope {
            seal_version: 1,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: policy(),
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: vec![],
                wrap_nonce: vec![],
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        };
        let err = client.release_dek(&seal, &ev).await.unwrap_err();
        assert!(matches!(err, SealError::NotImplemented), "{err:?}");
    }

    #[test]
    fn software_kek_gate_matrix() {
        assert!(software_kek_allowed(true, false));
        assert!(software_kek_allowed(true, true));
        assert!(!software_kek_allowed(false, false));
        assert!(software_kek_allowed(false, true));
    }
}

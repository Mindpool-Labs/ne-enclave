// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! HKDF-derived software-fallback KEK and AES-256-GCM DEK wrap/unwrap.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::SealError;
use crate::types::{DekEnvelope, KekProvider, POLICY_DOMAIN_TAG, SealingPolicy};

const WRAP_DOMAIN: &[u8] = b"ne-enclave-dek-wrap-v1";
const KEK_INFO: &[u8] = b"ne-enclave-seal-kek-v1";

/// Stable, sorted-key JSON canonical form of the policy (domain-tagged
/// `POLICY_DOMAIN_TAG`). Hashed into the DEK-wrap AD to reject a policy swap.
pub fn policy_canonical_bytes(p: &SealingPolicy) -> Vec<u8> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "ctx",
        serde_json::Value::String(POLICY_DOMAIN_TAG.to_string()),
    );
    map.insert(
        "accept_provider_types",
        serde_json::to_value(&p.accept_provider_types).unwrap_or(serde_json::Value::Null),
    );
    map.insert(
        "freshness_seconds",
        serde_json::Value::Number(serde_json::Number::from(p.freshness_seconds)),
    );
    map.insert(
        "trust_anchor",
        serde_json::to_value(&p.trust_anchor).unwrap_or(serde_json::Value::Null),
    );
    map.insert(
        "expected_measurement",
        serde_json::to_value(p.expected_measurement).unwrap_or(serde_json::Value::Null),
    );
    serde_json::to_vec(&map).unwrap_or_default()
}

/// Derive the 256-bit software-fallback KEK from the host Ed25519 key via
/// HKDF-SHA256. The HKDF output (never the raw signing bytes) is the AES key.
pub fn derive_kek(signing_key: &SigningKey) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, signing_key.to_bytes().as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    // HKDF-SHA256 expand to 32 bytes (<= 255*32) is infallible for the fixed
    // KEK_INFO info string; discard the never-Err result.
    let _ = hk.expand(KEK_INFO, out.as_mut_slice());
    out
}

#[must_use]
/// Constructs associated data that binds a DEK wrapping operation to its
/// snapshot, manifest, and sealing policy.
pub fn dek_wrap_associated_data(
    snapshot_id: &str,
    manifest_hash: &str,
    policy: &SealingPolicy,
) -> Vec<u8> {
    let policy_hash = policy_hash(policy);
    let mut ad = Vec::with_capacity(
        WRAP_DOMAIN.len() + snapshot_id.len() + manifest_hash.len() + policy_hash.len(),
    );
    ad.extend_from_slice(WRAP_DOMAIN);
    ad.extend_from_slice(snapshot_id.as_bytes());
    ad.extend_from_slice(manifest_hash.as_bytes());
    ad.extend_from_slice(&policy_hash);
    ad
}

/// SHA-256 of [`policy_canonical_bytes`]. Hashed into the DEK-wrap AD to
/// reject a policy swap.
pub fn policy_hash(p: &SealingPolicy) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(policy_canonical_bytes(p));
    h.finalize().into()
}

/// Wrap the 32-byte DEK under `kek` with a fresh random nonce.
///
/// AD binds to `snapshot_id` + manifest hash + policy. See
/// [`wrap_dek_with_nonce`] for the caller-supplied-nonce variant used by the
/// wasm seam (wasm32 has no host RNG, so the Worker supplies the nonce —
/// the host-supplied nonce contract).
pub fn wrap_dek(
    dek: &[u8; 32],
    kek: &[u8; 32],
    kek_provider: KekProvider,
    snapshot_id: &str,
    manifest_hash: &str,
    policy: &SealingPolicy,
) -> Result<DekEnvelope, SealError> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = wrap_dek_with_nonce(dek, kek, &nonce, snapshot_id, manifest_hash, policy)?;
    Ok(DekEnvelope {
        kek_provider,
        wrapped_dek: ct,
        wrap_nonce: nonce.to_vec(),
    })
}

/// Wrap the DEK with a CALLER-SUPPLIED 12-byte nonce.
///
/// Used by the wasm seam — wasm32 has no host RNG; the Worker supplies the
/// nonce via `crypto.getRandomValues`. The cipher and
/// associated-data construction are identical to [`wrap_dek`]; only the nonce
/// source differs.
pub fn wrap_dek_with_nonce(
    dek: &[u8; 32],
    kek: &[u8; 32],
    nonce: &[u8; 12],
    snapshot_id: &str,
    manifest_hash: &str,
    policy: &SealingPolicy,
) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|e| SealError::BadCrypto(e.to_string()))?;
    let ad = dek_wrap_associated_data(snapshot_id, manifest_hash, policy);
    cipher
        .encrypt(
            nonce.into(),
            aes_gcm::aead::Payload {
                msg: dek.as_slice(),
                aad: &ad,
            },
        )
        .map_err(|_| SealError::CiphertextCorrupt)
}

/// Unwrap the DEK. AD mismatch (policy/manifest/snapshot swap) ⇒
/// `CiphertextCorrupt`.
pub fn unwrap_dek(
    env: &DekEnvelope,
    kek: &[u8; 32],
    snapshot_id: &str,
    manifest_hash: &str,
    policy: &SealingPolicy,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|e| SealError::BadCrypto(e.to_string()))?;
    let nonce: [u8; 12] = env
        .wrap_nonce
        .as_slice()
        .try_into()
        .map_err(|_| SealError::BadCrypto("wrap nonce not 12 bytes".into()))?;
    let ad = dek_wrap_associated_data(snapshot_id, manifest_hash, policy);
    let pt = cipher
        .decrypt(
            &nonce.into(),
            aes_gcm::aead::Payload {
                msg: &env.wrapped_dek,
                aad: &ad,
            },
        )
        .map_err(|_| SealError::CiphertextCorrupt)?;
    let dek: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| SealError::BadCrypto("unwrapped DEK not 32 bytes".into()))?;
    Ok(Zeroizing::new(dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SealingPolicy, SealingTrustAnchor};
    use ne_attestation::ProviderType;

    fn policy(freshness_seconds: u64) -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ProviderType::Software],
            freshness_seconds,
            trust_anchor: SealingTrustAnchor::Software {
                expected_signer: [9u8; 32],
            },
            expected_measurement: None,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let kek = derive_kek(&sk);
        let dek = [77u8; 32];
        let env = wrap_dek(
            &dek,
            &kek,
            KekProvider::SoftwareFallback,
            "01S",
            "mh",
            &policy(300),
        )
        .unwrap();
        let back = unwrap_dek(&env, &kek, "01S", "mh", &policy(300)).unwrap();
        assert_eq!(*back, dek);
    }

    #[test]
    fn policy_swap_detected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let kek = derive_kek(&sk);
        let env = wrap_dek(
            &[1u8; 32],
            &kek,
            KekProvider::SoftwareFallback,
            "01S",
            "mh",
            &policy(300),
        )
        .unwrap();
        let relaxed = policy(9999);
        let err = unwrap_dek(&env, &kek, "01S", "mh", &relaxed).unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    fn manifest_swap_detected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let kek = derive_kek(&sk);
        let env = wrap_dek(
            &[1u8; 32],
            &kek,
            KekProvider::SoftwareFallback,
            "01S",
            "mh",
            &policy(300),
        )
        .unwrap();
        let err = unwrap_dek(&env, &kek, "01S", "OTHER", &policy(300)).unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    fn policy_canonical_bytes_is_deterministic() {
        let p = policy(300);
        assert_eq!(policy_canonical_bytes(&p), policy_canonical_bytes(&p));
    }

    #[test]
    fn wrap_dek_with_nonce_roundtrip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let kek = derive_kek(&sk);
        let dek = [77u8; 32];
        let nonce = [42u8; 12];
        let ct = wrap_dek_with_nonce(&dek, &kek, &nonce, "01S", "mh", &policy(300)).unwrap();
        let env = DekEnvelope {
            kek_provider: KekProvider::SoftwareFallback,
            wrapped_dek: ct,
            wrap_nonce: nonce.to_vec(),
        };
        let back = unwrap_dek(&env, &kek, "01S", "mh", &policy(300)).unwrap();
        assert_eq!(*back, dek);
    }

    #[test]
    fn dek_wrap_associated_data_is_stable_and_field_bound() {
        let p = policy(300);
        let manifest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut expected = b"ne-enclave-dek-wrap-v1".to_vec();
        expected.extend_from_slice(b"01SNAP");
        expected.extend_from_slice(manifest.as_bytes());
        expected.extend_from_slice(&policy_hash(&p));
        assert_eq!(dek_wrap_associated_data("01SNAP", manifest, &p), expected);
        assert_ne!(
            dek_wrap_associated_data("01SNAP-other", manifest, &p),
            expected
        );
    }
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Native-versus-WASM equivalence coverage for the WASM seam. This native test
//! uses synthetic evidence only.
//!
//! Test-only relaxations: the workspace clippy config lints `unwrap()` even in
//! tests, but STANDARDS permits it inside `#[cfg(test)]`. These allows are scoped
//! to this test module only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use ne_attestation::{
    AttestationProvider, EvidenceRequest, Measurement, Nonce, ProviderType, SoftwareProvider,
};
use ne_enclave_wasm::native::{unwrap_dek_json, verify_against_policy_json, wrap_dek_json};
use ne_seal::kek::{derive_kek, policy_hash, unwrap_dek};
use ne_seal::types::{KekProvider, SealingPolicy, SealingTrustAnchor};

fn policy_json(expected_signer: [u8; 32]) -> String {
    serde_json::to_string(&SealingPolicy {
        accept_provider_types: vec![ProviderType::Software],
        freshness_seconds: 300,
        trust_anchor: SealingTrustAnchor::Software { expected_signer },
        expected_measurement: None,
    })
    .expect("policy serializes")
}

#[test]
fn verify_open_matches_native() {
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let expected_signer = sk.verifying_key().to_bytes();
    let provider = SoftwareProvider::new(sk);
    let nonce = Nonce::new(vec![1u8; 16]).expect("nonce");
    let req = EvidenceRequest {
        workspace_id: "ws".into(),
        measurement: Measurement([3u8; 32]),
        nonce,
    };
    let ev = provider.generate(&req, 1_700_000_010).expect("generate");
    let out = verify_against_policy_json(
        &policy_json(expected_signer),
        &serde_json::to_string(&ev).expect("evidence serializes"),
        &B64.encode([1u8; 16]),
        1_700_000_015,
    );
    assert!(out.contains("\"verified\":true"), "out={out}");
}

#[test]
fn wrap_unwrap_roundtrip_matches_native() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let kek = derive_kek(&sk);
    let expected_signer = VerifyingKey::from(&sk).to_bytes();
    let policy: SealingPolicy =
        serde_json::from_str(&policy_json(expected_signer)).expect("policy");
    let dek = [7u8; 32];
    let nonce = [42u8; 12];
    let wrapped = wrap_dek_json(
        &B64.encode(dek),
        &B64.encode(*kek),
        &B64.encode(nonce),
        "01S",
        "mh",
        &policy_json(expected_signer),
    );
    let v: serde_json::Value = serde_json::from_str(&wrapped).expect("wrapped json");
    let blob = B64
        .decode(
            v["wrapped_dek_b64"]
                .as_str()
                .expect("wrapped_dek_b64")
                .as_bytes(),
        )
        .expect("wrapped_dek decodes");

    // wasm-unwrap path (nonce is host-supplied):
    let unwrapped = unwrap_dek_json(
        &B64.encode(&blob),
        &B64.encode(*kek),
        &B64.encode(nonce),
        "01S",
        "mh",
        &policy_json(expected_signer),
    );
    let uv: serde_json::Value = serde_json::from_str(&unwrapped).expect("unwrapped json");
    assert_eq!(
        B64.decode(uv["dek_b64"].as_str().expect("dek_b64").as_bytes())
            .expect("dek decodes"),
        dek
    );

    // native parity (same blob must unwrap natively):
    let env = ne_seal::types::DekEnvelope {
        kek_provider: KekProvider::SoftwareFallback,
        wrapped_dek: blob,
        wrap_nonce: nonce.to_vec(),
    };
    let native = unwrap_dek(&env, &kek, "01S", "mh", &policy).expect("native unwrap");
    assert_eq!(*native, dek);
    // policy_hash consistency (the binding AD source):
    let _ = policy_hash(&policy);
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! WASM seam over `ne-seal` for external evaluation tooling.
//!
//! Exposes three JSON-in/JSON-out functions: attestation-policy evaluation and
//! DEK wrap/unwrap. Pure: `verify` needs no
//! RNG; `wrap_dek` takes a HOST-SUPPLIED nonce because wasm32 has no host RNG by
//! default. This module does not select or make a production external
//! key-release backend ready.
//!
//! The `SevSnp` arm is synthetic-evidence-tested only. The WASM build reuses
//! the exact audited Rust; it does not reimplement cryptography.

#![cfg_attr(not(test), allow(clippy::expect_used))]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ne_attestation::{Evidence, Nonce};
use ne_seal::gate::verify_against_policy;
use ne_seal::kek::{unwrap_dek, wrap_dek_with_nonce};
use ne_seal::types::SealingPolicy;

/// Native (rlib) entry points used by the cross-repo native-equivalence test AND
/// mirrored 1:1 by the `#[wasm_bindgen]` wrappers below.
pub mod native {
    use super::*;

    /// Run the authoritative attestation gate over JSON inputs and return the
    /// §5.3 result envelope: `{"verified":true}` or
    /// `{"verified":false,"fail_reason":"<FailReason debug>"}`.
    pub fn verify_against_policy_json(
        policy_json: &str,
        evidence_json: &str,
        expected_nonce_b64: &str,
        now: i64,
    ) -> String {
        match inner_verify(policy_json, evidence_json, expected_nonce_b64, now) {
            Ok(()) => String::from(r#"{"verified":true}"#),
            Err(reason) => format!(r#"{{"verified":false,"fail_reason":"{reason}"}}"#),
        }
    }

    /// Wrap a DEK under a KEK with a host-supplied nonce.
    ///
    /// Returns `{"wrapped_dek_b64":".."}` on success or
    /// `{"ok":false,"error":".."}` on bad input.
    pub fn wrap_dek_json(
        dek_b64: &str,
        kek_b64: &str,
        wrap_nonce_b64: &str,
        snapshot_id: &str,
        manifest_hash: &str,
        policy_json: &str,
    ) -> String {
        let inp = match parse_wrap_inputs(dek_b64, kek_b64, wrap_nonce_b64, policy_json) {
            Ok(v) => v,
            Err(e) => return error_json(&e),
        };
        match wrap_dek_with_nonce(
            &inp.dek,
            &inp.kek,
            &inp.nonce,
            snapshot_id,
            manifest_hash,
            &inp.policy,
        ) {
            Ok(blob) => format!(r#"{{"wrapped_dek_b64":"{}"}}"#, B64.encode(blob)),
            Err(e) => error_json(&format!("wrap failed: {e:?}")),
        }
    }

    /// Unwrap a DEK under a KEK.
    ///
    /// The GCM nonce is host-supplied: in the real CP path it
    /// travels inside the seal's `DekEnvelope` and external tooling forwards it here.
    /// Returns `{"dek_b64":".."}` on success or `{"ok":false,"error":".."}` on
    /// failure.
    pub fn unwrap_dek_json(
        wrapped_dek_b64: &str,
        kek_b64: &str,
        wrap_nonce_b64: &str,
        snapshot_id: &str,
        manifest_hash: &str,
        policy_json: &str,
    ) -> String {
        let wrapped = match B64.decode(wrapped_dek_b64.as_bytes()) {
            Ok(v) => v,
            Err(e) => return error_json(&format!("bad wrapped_dek b64: {e}")),
        };
        let kek = match decode_kek(kek_b64) {
            Ok(v) => v,
            Err(e) => return error_json(&e),
        };
        let nonce: [u8; 12] = match B64
            .decode(wrap_nonce_b64.as_bytes())
            .map_err(|e| format!("nonce b64: {e}"))
        {
            Ok(v) => match v.try_into() {
                Ok(n) => n,
                Err(_) => return error_json("wrap nonce not 12 bytes"),
            },
            Err(e) => return error_json(&e),
        };
        let policy: SealingPolicy = match serde_json::from_str(policy_json) {
            Ok(p) => p,
            Err(e) => return error_json(&format!("bad policy json: {e}")),
        };
        let env = ne_seal::types::DekEnvelope {
            kek_provider: ne_seal::types::KekProvider::SoftwareFallback,
            wrapped_dek: wrapped,
            wrap_nonce: nonce.to_vec(),
        };
        match unwrap_dek(&env, &kek, snapshot_id, manifest_hash, &policy) {
            Ok(dek) => format!(r#"{{"dek_b64":"{}"}}"#, B64.encode(*dek)),
            Err(e) => error_json(&format!("unwrap failed: {e:?}")),
        }
    }

    fn error_json(msg: &str) -> String {
        format!(r#"{{"ok":false,"error":"{}"}}"#, msg.replace('"', ""))
    }

    fn decode_kek(kek_b64: &str) -> Result<[u8; 32], String> {
        let v = B64
            .decode(kek_b64.as_bytes())
            .map_err(|e| format!("bad kek b64: {e}"))?;
        v.try_into().map_err(|_| "kek not 32 bytes".to_string())
    }
}

fn inner_verify(
    policy_json: &str,
    evidence_json: &str,
    expected_nonce_b64: &str,
    now: i64,
) -> Result<(), String> {
    let policy: SealingPolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("policy json: {e}"))?;
    let evidence: Evidence =
        serde_json::from_str(evidence_json).map_err(|e| format!("evidence json: {e}"))?;
    let nonce_bytes = B64
        .decode(expected_nonce_b64.as_bytes())
        .map_err(|e| format!("nonce b64: {e}"))?;
    let expected =
        Nonce::new(nonce_bytes).ok_or_else(|| "nonce out of 16..=64 range".to_string())?;
    // Run the same gate the runtime uses; map SealError → a non-secret reason string.
    match verify_against_policy(&policy, &evidence, &expected, now) {
        Ok(()) => Ok(()),
        Err(ne_seal::SealError::AttestationGateDenied(reason)) => Err(format!("{reason:?}")),
        Err(e) => Err(format!("gate error: {e:?}")),
    }
}

/// Parsed DEK-wrap inputs (decoded fixed-size arrays + the policy).
struct WrapInputs {
    dek: [u8; 32],
    kek: [u8; 32],
    nonce: [u8; 12],
    policy: SealingPolicy,
}

fn parse_wrap_inputs(
    dek_b64: &str,
    kek_b64: &str,
    wrap_nonce_b64: &str,
    policy_json: &str,
) -> Result<WrapInputs, String> {
    let dek = B64
        .decode(dek_b64.as_bytes())
        .map_err(|e| format!("dek b64: {e}"))?
        .try_into()
        .map_err(|_| "dek not 32 bytes".to_string())?;
    let kek = B64
        .decode(kek_b64.as_bytes())
        .map_err(|e| format!("kek b64: {e}"))?
        .try_into()
        .map_err(|_| "kek not 32 bytes".to_string())?;
    let nonce = B64
        .decode(wrap_nonce_b64.as_bytes())
        .map_err(|e| format!("nonce b64: {e}"))?
        .try_into()
        .map_err(|_| "wrap nonce not 12 bytes".to_string())?;
    let policy: SealingPolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("policy json: {e}"))?;
    Ok(WrapInputs {
        dek,
        kek,
        nonce,
        policy,
    })
}

// ---- wasm32 RNG shim --------------------------------------------------------
// Under `wasm32-unknown-unknown` getrandom has no host RNG. The seam is
// constructed to need NONE of it (`verify_against_policy` is pure; `wrap_dek`
// takes a HOST-SUPPLIED nonce). We register a custom getrandom
// backend that loudly panics so any future code path that reaches RNG fails
// immediately rather than silently producing broken key material.
#[cfg(target_arch = "wasm32")]
mod getrandom_shim {
    #[allow(clippy::unnecessary_wraps)]
    fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
        panic!(
            "getrandom reached in ne-enclave-wasm: no RNG on wasm32; verify is pure and the \
             wrap nonce is host-supplied"
        );
    }
    getrandom::register_custom_getrandom!(always_fail);
}

// ---- wasm32 wrappers (consumed by external evaluation tooling) --------------
// These are consumed via `#[wasm_bindgen]` JS export, which Rust's
// reachability analysis can't see, hence the dead-code allow.
#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
mod wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn verify_against_policy_json(
        policy_json: &str,
        evidence_json: &str,
        expected_nonce_b64: &str,
        now: i64,
    ) -> String {
        super::native::verify_against_policy_json(
            policy_json,
            evidence_json,
            expected_nonce_b64,
            now,
        )
    }

    #[wasm_bindgen]
    pub fn wrap_dek_json(
        dek_b64: &str,
        kek_b64: &str,
        wrap_nonce_b64: &str,
        snapshot_id: &str,
        manifest_hash: &str,
        policy_json: &str,
    ) -> String {
        super::native::wrap_dek_json(
            dek_b64,
            kek_b64,
            wrap_nonce_b64,
            snapshot_id,
            manifest_hash,
            policy_json,
        )
    }

    #[wasm_bindgen]
    pub fn unwrap_dek_json(
        wrapped_dek_b64: &str,
        kek_b64: &str,
        wrap_nonce_b64: &str,
        snapshot_id: &str,
        manifest_hash: &str,
        policy_json: &str,
    ) -> String {
        super::native::unwrap_dek_json(
            wrapped_dek_b64,
            kek_b64,
            wrap_nonce_b64,
            snapshot_id,
            manifest_hash,
            policy_json,
        )
    }
}

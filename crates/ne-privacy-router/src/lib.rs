// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave workspace-egress privacy router.
//!
//! Privacy-router substrate. Wraps the NVIDIA OpenShell PII detection engine
//! (consumed as a SHA-pinned git dep from our OpenShell fork) and
//! exposes:
//!
//! - **Re-exports** of the engine surface — downstream NeuronEdge Enclave crates
//!   import `EntityType`, `PiiEngine`, `PiiPolicy`, `PiiAction`, etc.
//!   from `ne_privacy_router`, never from `openshell_pii` directly.
//!   This keeps the fork bump a single-`Cargo.toml` change.
//! - **A reusable HTTP reverse proxy** (`proxy` module) that scans
//!   request bodies via the engine and forwards / redacts / blocks
//!   per the active policy. The supervisor spawns one
//!   instance per workspace inside the workspace netns.
//! - **A YAML policy loader** (`policy_loader` module) for the binary.
//!
//! ## Current scope
//!
//! Current scope: HTTP/1.1 cleartext only — destinations are
//! taken from the inbound `Host:` header, so the proxy sits behind an
//! iptables DNAT without needing `SO_ORIGINAL_DST`
//! recovery. Tier-1 (regex) detection only; NER and HTTPS interception
//! are deferred to later releases. Request-direction scanning only;
//! response-direction scanning is outside the current cleartext scope.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod policy_loader;
pub mod proxy;

pub use openshell_pii::{
    CustomPattern, EntityType, PiiAction, PiiApplyResult, PiiDetection, PiiEngine, PiiPolicy,
    merge_detections, redact,
};

use anyhow::Context as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolved privacy-router configuration, ready for `run()`.
///
/// The binary's `main()` maps `Cli` fields onto this struct so that a
/// future fused `nee` binary (or integration tests) can drive the
/// same startup path without going through `clap`.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Address the HTTP listener binds on.
    pub listen: SocketAddr,
    /// Path to the PII policy YAML file.
    pub policy: PathBuf,
    /// Hard cap on bodies the proxy will buffer for scanning.
    pub max_body_bytes: usize,
    /// Emit one JSON audit line per scan decision on stdout.
    pub emit_audit_stdout: bool,
}

/// Load the PII policy, build the engine + proxy state, bind the
/// listener, and drive the serve loop.
///
/// The caller is responsible for initialising tracing before calling
/// `run()`.  This design keeps tracing initialisation in `main()` (or
/// the fused binary's startup) where global subscriber registration
/// belongs, while allowing integration tests and future callers to
/// substitute their own subscriber.
pub async fn run(cfg: RouterConfig) -> anyhow::Result<()> {
    let policy = policy_loader::load_from_path(&cfg.policy)
        .with_context(|| format!("load privacy policy from {}", cfg.policy.display()))?;
    let engine = Arc::new(PiiEngine::new(&policy));
    let state = Arc::new(
        proxy::ProxyState::new(engine, cfg.max_body_bytes).with_audit_stdout(cfg.emit_audit_stdout),
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding privacy-router listener on {}", cfg.listen))?;
    tracing::info!(
        listen = %cfg.listen,
        policy = %cfg.policy.display(),
        max_body_bytes = cfg.max_body_bytes,
        emit_audit_stdout = cfg.emit_audit_stdout,
        "ne-privacy-router listening",
    );
    proxy::serve(listener, state)
        .await
        .map_err(|e| anyhow::anyhow!("privacy-router serve loop terminated: {e}"))
}

#[cfg(test)]
mod tests {
    use super::{EntityType, PiiAction, PiiEngine, PiiPolicy};
    use std::collections::HashMap;

    #[test]
    fn engine_detects_ssn_through_reexport() {
        let mut entities = HashMap::new();
        entities.insert(EntityType::Ssn, PiiAction::Redact);
        let policy = PiiPolicy {
            enforcement: "audit".to_string(),
            entities,
            ..PiiPolicy::default()
        };

        let engine = PiiEngine::new(&policy);
        let body = b"my ssn is 123-45-6789";
        let detections = engine.detect(body);

        assert!(
            detections.iter().any(|d| d.entity_type == EntityType::Ssn),
            "expected SSN detection through re-export, got {detections:?}",
        );
    }

    #[test]
    fn policy_action_for_block_enforcement_through_reexport() {
        let policy = PiiPolicy {
            enforcement: "block".to_string(),
            ..PiiPolicy::default()
        };
        assert_eq!(policy.action_for(EntityType::Email), PiiAction::Block);
    }
}

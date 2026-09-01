// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-side sealed-snapshot wiring.
//!
//! Holds the host Ed25519 key (via `AuditLog::signing_key`) + the active
//! attestation provider + the software-fallback key release, and exposes
//! seal/unseal entrypoints that delegate to `ne_seal`.
//!
//! **Claim discipline:** the software-fallback path is at-rest /
//! confidentiality-vs-the-operator only (NOT hardware-protected). Confidential
//! prod must refuse the software KEK via `software_kek_allowed` unless
//! `NE_SEAL_ALLOW_SOFTWARE` is set.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ne_attestation::{AttestationProvider, Measurement};
use ne_seal::SealError;
use ne_seal::key_release::{SoftwareFallbackKeyRelease, software_kek_allowed};
use ne_seal::key_release_cp::{ControlPlaneKeyReleaseClient, ControlPlaneTlsFiles};
use ne_seal::orchestration::{seal_artifacts, unseal_artifacts};
use ne_seal::types::SealingPolicy;

use crate::audit::AuditLog;

/// Wall-clock seconds-since-epoch closure for the CP client's freshness clock.
/// Uses `std::time` (no chrono dep); falls back to 0 if the system clock is
/// before `UNIX_EPOCH` (which would itself be a catastrophic environment).
fn wall_clock_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Supervisor-side sealed-snapshot facade.
pub struct SupervisorSealer {
    audit: AuditLog,
    provider: Arc<dyn AttestationProvider>,
    allow_software_kek: bool,
    cp: Option<ControlPlaneKeyReleaseClient>,
}

impl SupervisorSealer {
    /// Construct. `dev_mode` + the `NE_SEAL_ALLOW_SOFTWARE` env decide whether
    /// the software KEK may be used; `software_kek_allowed(false, _)` => the
    /// unseal path will refuse to build a `SoftwareFallbackKeyRelease`.
    ///
    /// The key-release transport accepts either a complete mTLS configuration
    /// or a loopback development endpoint with bearer credentials. Any partial
    /// configuration is an error.
    pub fn new(
        audit: AuditLog,
        provider: Arc<dyn AttestationProvider>,
        dev_mode: bool,
    ) -> Result<Self, SealError> {
        let allow_env = std::env::var("NE_SEAL_ALLOW_SOFTWARE").is_ok();
        let cp = Self::cp_client_from_values(
            std::env::var("NE_CP_KEY_RELEASE_ENDPOINT").ok(),
            std::env::var("NE_CP_TLS_CA_CERT").ok(),
            std::env::var("NE_CP_TLS_CLIENT_CERT").ok(),
            std::env::var("NE_CP_TLS_CLIENT_KEY").ok(),
            std::env::var("NE_CP_API_KEY").ok(),
            dev_mode,
        )?;
        Ok(Self {
            audit,
            provider,
            allow_software_kek: software_kek_allowed(dev_mode, allow_env),
            cp,
        })
    }

    fn cp_client_from_values(
        endpoint: Option<String>,
        ca_cert: Option<String>,
        client_cert: Option<String>,
        client_key: Option<String>,
        api_key: Option<String>,
        dev_mode: bool,
    ) -> Result<Option<ControlPlaneKeyReleaseClient>, SealError> {
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        match (ca_cert, client_cert, client_key, api_key) {
            (Some(ca_cert), Some(client_cert), Some(client_key), api_key) => {
                ControlPlaneKeyReleaseClient::new_mtls(
                    endpoint,
                    api_key,
                    ControlPlaneTlsFiles {
                        ca_cert: ca_cert.into(),
                        client_cert: client_cert.into(),
                        client_key: client_key.into(),
                    },
                    Arc::new(wall_clock_now),
                )
                .map(Some)
                .map_err(SealError::from)
            }
            (None, None, None, Some(api_key)) if dev_mode => {
                ControlPlaneKeyReleaseClient::new_development(
                    endpoint,
                    api_key,
                    Arc::new(wall_clock_now),
                )
                .map(Some)
                .map_err(SealError::from)
            }
            _ => Err(SealError::from(
                ne_seal::key_release_cp::ControlPlaneError::Configuration(
                    "invalid key-release transport configuration".into(),
                ),
            )),
        }
    }

    /// Test/construction seam: build a sealer from explicit parts, bypassing
    /// the env read in [`new`](Self::new). Used by the wiring tests to inject a
    /// CP client (or `None`) without mutating process env (which is
    /// `unsafe` in edition 2024 and forbidden at this workspace's
    /// `unsafe_code = "deny"` floor).
    #[cfg(test)]
    fn from_parts(
        audit: AuditLog,
        provider: Arc<dyn AttestationProvider>,
        dev_mode: bool,
        allow_software_env: bool,
        cp: Option<ControlPlaneKeyReleaseClient>,
    ) -> Self {
        Self {
            audit,
            provider,
            allow_software_kek: software_kek_allowed(dev_mode, allow_software_env),
            cp,
        }
    }

    /// Seal `snapshot_dir`. The manifest must already be written over the
    /// plaintext files; `seal_artifacts` writes ciphertext siblings + seal.json.
    ///
    /// `kek_provider` selects the DEK-wrap backend: `SoftwareFallback` (local
    /// HKDF) or `ControlPlane` (CP-held KEK via the wired CP client). When
    /// `ControlPlane` is selected but no client was constructed (env unset), the
    /// delegation fails closed with `ControlPlaneRelease(Unconfigured)`.
    ///
    /// # Errors
    /// [`SealError`] on any failure.
    pub async fn seal(
        &self,
        snapshot_dir: &Path,
        manifest: &ne_protocol::snapshot::SnapshotManifest,
        policy: SealingPolicy,
        kek_provider: ne_seal::types::KekProvider,
    ) -> Result<ne_seal::types::SealEnvelope, SealError> {
        let cp: Option<&dyn ne_seal::key_release_cp::CpWrapClient> = self
            .cp
            .as_ref()
            .map(|c| -> &dyn ne_seal::key_release_cp::CpWrapClient { c });
        seal_artifacts(
            snapshot_dir,
            manifest,
            &self.audit.signing_key(),
            policy,
            kek_provider,
            cp,
        )
        .await
    }

    /// Unseal + restore trust path.
    ///
    /// The software-fallback release is built (gated by `allow_software_kek`)
    /// and the wired CP client is passed for the `ControlPlane` KEK arm. Each
    /// arm fails closed before any DEK reaches memory.
    ///
    /// # Errors
    /// [`SealError::AttestationGateDenied`] if the gate closes;
    /// [`SealError`] otherwise.
    pub async fn unseal(
        &self,
        snapshot_dir: &Path,
        workspace_id: &str,
        measurement: Measurement,
        now: i64,
        out_mem: &Path,
        out_vmstate: &Path,
    ) -> Result<(), SealError> {
        let vk = self.audit.verifying_key();
        // SW release is built only when the software KEK is permitted; the CP
        // arm does not need it. `unseal_artifacts` branches on the envelope's
        // pinned provider and fails closed if the matching release is absent.
        let release: Option<Box<dyn ne_seal::key_release::KeyRelease>> = if self.allow_software_kek
        {
            Some(Box::new(SoftwareFallbackKeyRelease::new(
                &self.audit.signing_key(),
            )))
        } else {
            None
        };
        let cp: Option<&dyn ne_seal::key_release::ControlPlaneKeyRelease> = self
            .cp
            .as_ref()
            .map(|c| -> &dyn ne_seal::key_release::ControlPlaneKeyRelease { c });
        unseal_artifacts(
            snapshot_dir,
            &vk,
            release.as_deref(),
            cp,
            self.provider.as_ref(),
            workspace_id,
            measurement,
            now,
            out_mem,
            out_vmstate,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_attestation::SoftwareProvider;
    use ne_protocol::snapshot::{GuestIdentity, MANIFEST_VERSION};

    /// Build a minimal unsigned `SnapshotManifest` (signature fields empty).
    /// `seal_artifacts` only reads `snapshot_id` + the canonical hash, so an
    /// unsigned manifest is sufficient to exercise the seal wiring.
    fn unsigned_manifest() -> ne_protocol::snapshot::SnapshotManifest {
        ne_protocol::snapshot::SnapshotManifest {
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
        }
    }

    /// Write plaintext `mem`/`vmstate` into a fresh snapshot dir under `dir`.
    async fn write_plaintext(dir: &Path) -> std::path::PathBuf {
        let snap = dir.join("snap");
        tokio::fs::create_dir_all(&snap)
            .await
            .expect("create_dir_all");
        tokio::fs::write(snap.join("mem"), b"MEM")
            .await
            .expect("write mem");
        tokio::fs::write(snap.join("vmstate"), b"VM")
            .await
            .expect("write vmstate");
        snap
    }

    fn policy() -> SealingPolicy {
        SealingPolicy {
            accept_provider_types: vec![ne_attestation::ProviderType::Software],
            freshness_seconds: 300,
            trust_anchor: ne_seal::types::SealingTrustAnchor::Software {
                expected_signer: [0u8; 32],
            },
            expected_measurement: None,
        }
    }

    async fn make_sealer(
        dev_mode: bool,
        cp: Option<ControlPlaneKeyReleaseClient>,
    ) -> (tempfile::TempDir, SupervisorSealer) {
        let state_dir = tempfile::tempdir().expect("tempdir");
        let audit = AuditLog::open(state_dir.path()).await.expect("audit open");
        let provider: Arc<dyn AttestationProvider> =
            Arc::new(SoftwareProvider::new(audit.signing_key()));
        let sealer = SupervisorSealer::from_parts(audit, provider, dev_mode, true, cp);
        (state_dir, sealer)
    }

    #[test]
    fn control_plane_configuration_matrix_fails_closed() {
        let tls_path = || Some("/tmp/test.pem".into());
        assert!(
            SupervisorSealer::cp_client_from_values(None, None, None, None, None, false)
                .expect("no configuration is allowed")
                .is_none()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                None,
                tls_path(),
                tls_path(),
                tls_path(),
                None,
                false,
            )
            .expect("shared TLS without a key-release endpoint disables only key release")
            .is_none()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                Some("https://127.0.0.1:8443/v1".into()),
                tls_path(),
                None,
                tls_path(),
                None,
                false,
            )
            .is_err()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                Some("http://127.0.0.1:8443/v1".into()),
                None,
                None,
                None,
                Some("development-key".into()),
                false,
            )
            .is_err()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                Some("http://192.0.2.1:8443/v1".into()),
                None,
                None,
                None,
                Some("development-key".into()),
                true,
            )
            .is_err()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                Some("http://127.0.0.1:8443/v1".into()),
                None,
                None,
                None,
                Some("development-key".into()),
                true,
            )
            .expect("development configuration")
            .is_some()
        );
        assert!(
            SupervisorSealer::cp_client_from_values(
                Some("http://127.0.0.1:8443/v1".into()),
                tls_path(),
                tls_path(),
                tls_path(),
                None,
                true,
            )
            .is_err()
        );
    }

    /// CP-client wiring matrix, exercised via the `from_parts` seam so no
    /// process-env mutation is required (edition 2024 marks `set_var`/
    /// `remove_var` `unsafe`, which this workspace forbids at the floor).
    ///
    /// (a) `cp = None`  → `ControlPlane` seal fails closed with `Unconfigured`
    ///     (the CP field is absent; ne-seal enforces fail-closed).
    /// (b) `cp = Some` against a dead endpoint → the same seal reaches the
    ///     network and fails with `Transport`, proving the client was
    ///     constructed AND wired into the seal delegation.
    ///
    /// Both halves live in one test so the CP client (which captures the
    /// endpoint/api-key at construction) is built deterministically inline.
    #[tokio::test]
    async fn cp_client_wiring_matrix() {
        // (a) No CP client: the ControlPlane arm is unconfigured.
        let (_state_a, sealer_a) = make_sealer(true, None).await;
        let dir_a = tempfile::tempdir().expect("tempdir");
        let snap_a = write_plaintext(dir_a.path()).await;
        let manifest_a = unsigned_manifest();
        let err = sealer_a
            .seal(
                &snap_a,
                &manifest_a,
                policy(),
                ne_seal::types::KekProvider::ControlPlane,
            )
            .await
            .expect_err("must fail closed when unconfigured");
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(
                    ne_seal::key_release_cp::ControlPlaneError::Unconfigured
                )
            ),
            "(a) unconfigured: {err:?}"
        );

        // (b) CP client wired against a dead endpoint: the seal delegation
        // reaches the network and fails with Transport. Bind+drop a TCP socket
        // to obtain a reliably-dead address (ECONNREFUSED) with no live server.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = dead.local_addr().expect("local_addr");
        drop(dead);
        let cp = ControlPlaneKeyReleaseClient::new_development(
            format!("http://{addr}/v1"),
            "test-key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");

        let (_state_b, sealer_b) = make_sealer(true, Some(cp)).await;
        let dir_b = tempfile::tempdir().expect("tempdir");
        let snap_b = write_plaintext(dir_b.path()).await;
        let manifest_b = unsigned_manifest();
        let err = sealer_b
            .seal(
                &snap_b,
                &manifest_b,
                policy(),
                ne_seal::types::KekProvider::ControlPlane,
            )
            .await
            .expect_err("transport must fail against dead endpoint");
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(
                    ne_seal::key_release_cp::ControlPlaneError::Transport(_)
                )
            ),
            "(b) transport: {err:?}"
        );
    }

    /// The env-driven constructor (`new`) yields no CP client when the env is
    /// unset. Asserted behaviorally: a `ControlPlane` seal returns
    /// `Unconfigured`. This is the light env-presence check — in a clean
    /// harness `NE_CP_*` are unset; if a developer shell happens to set them,
    /// the assertion is skipped (env is global and we cannot soundly mutate it
    /// under this workspace's `unsafe_code = "deny"` floor).
    #[tokio::test]
    async fn new_without_env_yields_no_cp_client() {
        let env_set = [
            "NE_CP_KEY_RELEASE_ENDPOINT",
            "NE_CP_TLS_CA_CERT",
            "NE_CP_TLS_CLIENT_CERT",
            "NE_CP_TLS_CLIENT_KEY",
            "NE_CP_API_KEY",
        ]
        .iter()
        .any(|name| std::env::var(name).is_ok());
        if env_set {
            // NE_CP_* env present in this environment; skipping the env-absence
            // assertion (process env cannot be soundly mutated under
            // `unsafe_code = "deny"`; no print per the workspace's no-println bar).
            return;
        }
        let state_dir = tempfile::tempdir().expect("tempdir");
        let audit = AuditLog::open(state_dir.path()).await.expect("audit open");
        let provider: Arc<dyn AttestationProvider> =
            Arc::new(SoftwareProvider::new(audit.signing_key()));
        let sealer = SupervisorSealer::new(audit, provider, true).expect("sealer configuration");
        let dir = tempfile::tempdir().expect("tempdir");
        let snap = write_plaintext(dir.path()).await;
        let manifest = unsigned_manifest();
        let err = sealer
            .seal(
                &snap,
                &manifest,
                policy(),
                ne_seal::types::KekProvider::ControlPlane,
            )
            .await
            .expect_err("must fail closed when env absent");
        assert!(
            matches!(
                err,
                SealError::ControlPlaneRelease(
                    ne_seal::key_release_cp::ControlPlaneError::Unconfigured
                )
            ),
            "{err:?}"
        );
    }
}

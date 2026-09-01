// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Request dispatcher.
//!
//! Maps a typed [`SupervisorRequest`] to a typed [`SupervisorResponse`].
//! This is the only path from public API to privileged
//! operation; no free-form strings reach the supervisor through here.

use std::sync::Arc;
use std::time::Instant;

use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
use tracing::error;

use crate::audit::AuditLog;
use crate::workspace::WorkspaceManager;

/// Stateful dispatcher. Owned by [`crate::ipc::IpcServer`] and shared
/// across connections behind an [`std::sync::Arc`].
#[derive(Debug)]
pub struct Dispatcher {
    started_at: Instant,
    version: &'static str,
    workspaces: Arc<WorkspaceManager>,
    audit: AuditLog,
}

impl Dispatcher {
    /// Construct a dispatcher. Records the supervisor's start time so
    /// [`SupervisorRequest::Ping`] can report uptime.
    #[must_use]
    pub fn new(workspaces: Arc<WorkspaceManager>, audit: AuditLog) -> Self {
        Self {
            started_at: Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            workspaces,
            audit,
        }
    }

    /// Dispatch one request. Always returns a response — error paths
    /// surface as [`SupervisorResponse::Error`] rather than panicking,
    /// because the IPC loop must remain alive after a bad call.
    pub async fn dispatch(&self, req: SupervisorRequest) -> SupervisorResponse {
        if let Some(operation) = req.workspace_operation()
            && !self.workspaces.execution_profile().supports(operation)
        {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::UnsupportedForProfile,
                message: format!(
                    "operation {operation:?} is not supported by execution profile {}",
                    self.workspaces.execution_profile()
                ),
            };
        }

        match req {
            SupervisorRequest::Ping => SupervisorResponse::Pong {
                version: self.version.to_string(),
                uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            },
            SupervisorRequest::GetCapabilities => {
                SupervisorResponse::Capabilities(self.workspaces.execution_profile().capabilities(
                    self.version,
                    ne_protocol::attestation::PUBLIC_EVIDENCE_SCHEMA_VERSION,
                ))
            }
            SupervisorRequest::CreateWorkspace(req) => Box::pin(self.workspaces.create(req)).await,
            SupervisorRequest::Terminate(req) => self.workspaces.terminate(req).await,
            SupervisorRequest::RunCommand(req) => self.workspaces.run_command(req).await,
            SupervisorRequest::WriteFile(req) => self.workspaces.write_file(req).await,
            SupervisorRequest::ReadFile(req) => self.workspaces.read_file(req).await,
            SupervisorRequest::ListEvents(req) => match self.audit.list(&req).await {
                Ok(resp) => SupervisorResponse::Events(resp),
                Err(e) => {
                    error!(error = %e, "audit list failed");
                    SupervisorResponse::Error {
                        kind: SupervisorErrorKind::Internal,
                        message: format!("audit list failed: {e}"),
                    }
                }
            },
            SupervisorRequest::PauseWorkspace(r) => self.workspaces.pause(r).await,
            SupervisorRequest::ResumeWorkspace(r) => self.workspaces.resume(r).await,
            SupervisorRequest::SnapshotWorkspace(r) => self.workspaces.snapshot(r).await,
            SupervisorRequest::RestoreWorkspace(r) => self.workspaces.restore(r).await,
            SupervisorRequest::ForkWorkspace(r) => Box::pin(self.workspaces.fork(r)).await,
            SupervisorRequest::PoolStatus(r) => self.workspaces.pool_status(r).await,
            SupervisorRequest::CapacitySnapshot(_) => self.workspaces.capacity_snapshot(),
            SupervisorRequest::ExposePort(r) => self.workspaces.expose_port(r).await,
            SupervisorRequest::UnexposePort(r) => self.workspaces.unexpose_port(r).await,
            SupervisorRequest::GetAttestationEvidence(r) => {
                self.workspaces.get_attestation_evidence(r).await
            }
            // `SupervisorRequest` is `#[non_exhaustive]`; a new variant
            // landing in the protocol crate before the supervisor has
            // implemented it must return Unsupported rather than panic.
            _ => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Unsupported,
                message: "operation not implemented in this supervisor build".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::WorkspaceManagerConfig;

    async fn test_dispatcher_for(
        execution_profile: ne_protocol::profile::ExecutionProfile,
    ) -> Dispatcher {
        let tmp = tempfile::tempdir().expect("tmpdir");
        // Leak the tempdir so the audit log file stays alive for
        // the test's duration; tests don't share the dispatcher so
        // this leak is bounded per-test.
        let state_dir = Box::leak(Box::new(tmp)).path().to_path_buf();
        let audit = AuditLog::open(&state_dir).await.expect("audit open");
        let attestation = crate::attestation_factory::build_provider(
            ne_protocol::profile::AttestationBackend::Software,
            audit.signing_key(),
        )
        .expect("software provider");
        // Generous test ceilings: these dispatcher tests aren't exercising
        // admission control and must not spuriously hit it.
        let mut cfg = WorkspaceManagerConfig::dev_defaults();
        cfg.execution_profile = execution_profile;
        let mgr = WorkspaceManager::new(cfg, audit.clone(), attestation, 1024, 32768)
            .expect("workspace manager");
        Dispatcher::new(Arc::new(mgr), audit)
    }

    async fn test_dispatcher() -> Dispatcher {
        test_dispatcher_for(ne_protocol::profile::ExecutionProfile::Standard).await
    }

    #[tokio::test]
    async fn ping_returns_pong_with_crate_version() {
        let d = test_dispatcher().await;
        let resp = d.dispatch(SupervisorRequest::Ping).await;
        match resp {
            SupervisorResponse::Pong { version, .. } => {
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn uptime_is_monotonic_across_two_pings() {
        let d = test_dispatcher().await;
        let first = match d.dispatch(SupervisorRequest::Ping).await {
            SupervisorResponse::Pong { uptime_ms, .. } => uptime_ms,
            other => panic!("unexpected: {other:?}"),
        };
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let second = match d.dispatch(SupervisorRequest::Ping).await {
            SupervisorResponse::Pong { uptime_ms, .. } => uptime_ms,
            other => panic!("unexpected: {other:?}"),
        };
        assert!(second >= first, "uptime must not move backwards");
    }

    #[tokio::test]
    async fn confidential_profile_rejects_snapshot_before_dispatch() {
        use ne_protocol::supervisor::SnapshotRequest;

        let d =
            test_dispatcher_for(ne_protocol::profile::ExecutionProfile::ConfidentialAzure).await;
        let req = SupervisorRequest::SnapshotWorkspace(SnapshotRequest {
            workspace_id: "w".into(),
            live: false,
        });
        match d.dispatch(req).await {
            SupervisorResponse::Error { kind, .. } => {
                assert_eq!(kind, SupervisorErrorKind::UnsupportedForProfile);
            }
            other => panic!("expected UnsupportedForProfile, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn capabilities_are_derived_from_the_selected_profile() {
        let d =
            test_dispatcher_for(ne_protocol::profile::ExecutionProfile::ConfidentialAzure).await;
        match d.dispatch(SupervisorRequest::GetCapabilities).await {
            SupervisorResponse::Capabilities(capabilities) => {
                assert_eq!(
                    capabilities.execution_profile,
                    ne_protocol::profile::ExecutionProfile::ConfidentialAzure
                );
                assert_eq!(capabilities.hard_workspace_capacity, Some(1));
                assert_eq!(
                    capabilities.evidence_schema_version,
                    ne_protocol::attestation::PUBLIC_EVIDENCE_SCHEMA_VERSION
                );
            }
            other => panic!("expected capabilities, got {other:?}"),
        }
    }

    // Break caught: omitting the dispatcher route would return Unsupported
    // instead of the supervisor's atomic capacity inventory.
    #[tokio::test]
    async fn capacity_snapshot_comes_from_the_workspace_manager() {
        let d = test_dispatcher().await;
        let response = d
            .dispatch(SupervisorRequest::CapacitySnapshot(
                ne_protocol::supervisor::CapacitySnapshotRequest {},
            ))
            .await;
        match response {
            SupervisorResponse::CapacitySnapshot(capacity) => {
                assert_eq!(capacity.configured_workspace_ceiling, 1024);
                assert_eq!(capacity.registered_workspaces, 0);
                assert_eq!(capacity.revision, 0);
            }
            other => panic!("expected capacity snapshot, got {other:?}"),
        }
    }

    // Break caught: an accepted IPC connection could start a new mutating
    // request after shutdown had begun.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closed_lifecycle_rejects_new_mutating_dispatch() {
        use ne_protocol::supervisor::CreateWorkspaceRequest;

        let dispatcher = test_dispatcher().await;
        dispatcher.workspaces.close_lifecycle();
        let response = dispatcher
            .dispatch(SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
                workspace_id: "closed".to_string(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 128,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: None,
                tier: None,
            }))
            .await;
        assert!(matches!(
            response,
            SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                ref message,
            } if message == "supervisor is shutting down"
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn fork_workspace_returns_unsupported_on_non_linux() {
        use ne_protocol::supervisor::ForkRequest;
        let d = test_dispatcher().await;
        let req = SupervisorRequest::ForkWorkspace(ForkRequest {
            snapshot_id: "s".into(),
            new_workspace_id: "fork-x".into(),
            hostname: None,
        });
        match d.dispatch(req).await {
            SupervisorResponse::Error { kind, .. } => {
                assert_eq!(kind, SupervisorErrorKind::Unsupported);
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn create_workspace_returns_unsupported_on_non_linux() {
        use ne_protocol::supervisor::CreateWorkspaceRequest;
        let d = test_dispatcher().await;
        let req = SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
            workspace_id: "wks_test".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 256,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        });
        match d.dispatch(req).await {
            SupervisorResponse::Error { kind, .. } => {
                assert_eq!(kind, SupervisorErrorKind::Unsupported);
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}

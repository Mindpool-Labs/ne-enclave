// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Transport-agnostic runtime core.
//!
//! Both the gRPC server (`crate::server`) and the REST gateway
//! (`crate::rest`) call this layer, so request validation and error
//! classification have exactly one home and cannot drift between the
//! two surfaces.

use std::time::Instant;

use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
use tracing::error;

use crate::supervisor_client::{SupervisorClient, SupervisorClientError};

/// Guest vsock port the `ne-guest-agent` listens on by convention.
/// A `0` from the caller is rewritten to this.
const DEFAULT_GUEST_PORT: u32 = 52;

/// Transport-agnostic runtime operations shared by the gRPC and REST
/// front doors. Cheap to wrap in an `Arc`; holds no per-request state.
#[derive(Debug)]
pub struct RuntimeCore {
    started_at: Instant,
    supervisor: SupervisorClient,
}

/// A failed core operation. Front doors map this onto their own
/// transport error type (`tonic::Status` / HTTP status + body).
#[derive(Debug)]
pub enum CoreError {
    /// Request failed validation at the API boundary (bad shape, out
    /// of range, oversized body). Maps to 400 / `InvalidArgument`.
    Validation(String),
    /// The supervisor returned a typed error response.
    Supervisor {
        /// Stable supervisor error classifier.
        kind: SupervisorErrorKind,
        /// Human-readable detail; never load-bearing for control flow.
        message: String,
    },
    /// Transport-level failure talking to the supervisor (IPC / decode).
    Transport(SupervisorClientError),
}

impl CoreError {
    /// Stable, machine-readable `SCREAMING_SNAKE_CASE` code clients can
    /// branch on without parsing the human message.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "VALIDATION",
            Self::Supervisor { kind, .. } => supervisor_kind_code(*kind),
            Self::Transport(SupervisorClientError::Io(_)) => "SUPERVISOR_UNAVAILABLE",
            Self::Transport(SupervisorClientError::Supervisor { kind, .. }) => {
                supervisor_kind_code(*kind)
            }
            Self::Transport(_) => "INTERNAL",
        }
    }

    /// Human-readable message for the error body / status detail.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Validation(m) => m.clone(),
            Self::Supervisor { message, .. } => message.clone(),
            Self::Transport(e) => e.to_string(),
        }
    }
}

/// Maps a [`SupervisorErrorKind`] to its stable code string. Shared by
/// the gRPC and REST status mappers so the two stay in lockstep.
#[must_use]
pub fn supervisor_kind_code(kind: SupervisorErrorKind) -> &'static str {
    use SupervisorErrorKind as K;
    match kind {
        K::Unauthorized => "UNAUTHORIZED",
        K::InvalidRequest => "INVALID_REQUEST",
        K::InvalidImageDigest => "INVALID_IMAGE_DIGEST",
        K::ImageNotFound => "IMAGE_NOT_FOUND",
        K::ImageRejected => "IMAGE_REJECTED",
        K::ImageDigestMismatch => "IMAGE_DIGEST_MISMATCH",
        K::ImageStageFailed => "IMAGE_STAGE_FAILED",
        K::Unsupported => "UNSUPPORTED",
        K::UnsupportedForProfile => "UNSUPPORTED_FOR_PROFILE",
        K::WorkspaceAlreadyExists => "WORKSPACE_ALREADY_EXISTS",
        K::WorkspaceNotFound => "WORKSPACE_NOT_FOUND",
        K::TierNotFound => "TIER_NOT_FOUND",
        K::ConfidentialCapacityExceeded => "CONFIDENTIAL_CAPACITY_EXCEEDED",
        K::GuestUnreachable => "GUEST_UNREACHABLE",
        K::Timeout => "TIMEOUT",
        K::PathRejected => "PATH_REJECTED",
        K::FileTooLarge => "FILE_TOO_LARGE",
        K::FileNotFound => "FILE_NOT_FOUND",
        K::SnapshotFailed => "SNAPSHOT_FAILED",
        K::RestoreFailed => "RESTORE_FAILED",
        K::InvalidSnapshot => "INVALID_SNAPSHOT",
        K::WorkspaceNotPaused => "WORKSPACE_NOT_PAUSED",
        K::WorkspaceAlreadyPaused => "WORKSPACE_ALREADY_PAUSED",
        K::ForkFailed => "FORK_FAILED",
        K::WorkspaceNotNetworked => "WORKSPACE_NOT_NETWORKED",
        K::IngressPortNotFound => "INGRESS_PORT_NOT_FOUND",
        K::AttestationReplay => "ATTESTATION_REPLAY",
        // LaunchFailed / GuestProtocolError / IoError / Internal / any
        // future variant collapse to the generic internal code.
        _ => "INTERNAL",
    }
}

/// Successful [`RuntimeCore::ping`] result.
#[derive(Debug)]
pub struct PingOutcome {
    /// `ne-api` crate version.
    pub api_version: String,
    /// Milliseconds since this `RuntimeCore` was constructed.
    pub api_uptime_ms: u64,
    /// Supervisor crate version (echoed from its `Pong`).
    pub supervisor_version: String,
    /// Supervisor uptime in milliseconds (echoed from its `Pong`).
    pub supervisor_uptime_ms: u64,
}

/// Per-workspace network policy in transport-neutral form. `privacy_router`
/// is a plain opt-in bool here; the core maps it to the supervisor's
/// `Option<PrivacyRouterConfig>`.
#[derive(Debug)]
pub struct NetworkInput {
    /// Install a MASQUERADE rule so the workspace egresses via the host.
    pub enable_egress: bool,
    /// Destination CIDR allowlist (empty + egress = allow-all).
    pub allow_cidrs: Vec<String>,
    /// Hostname allowlist enforced by the per-workspace DNS filter.
    pub allow_hostnames: Vec<String>,
    /// Opt into the per-workspace privacy router (PII body scanning).
    pub privacy_router: bool,
    /// Guest TCP ports exposed to host-based ingress routing at workspace
    /// creation time. Dynamic changes use `expose_port` / `unexpose_port`.
    pub exposed_ports: Vec<ne_protocol::supervisor::ExposedPort>,
}

/// Validated input for [`RuntimeCore::create_workspace`]. `vcpu_count`
/// is a `u32` here so the core (not the caller) owns the `1..=255`
/// range check before the `u8` narrowing the supervisor wants.
#[derive(Debug)]
pub struct CreateWorkspaceInput {
    /// Caller-chosen workspace id.
    pub workspace_id: String,
    /// Canonical lowercase SHA-256 digest of the managed guest kernel image.
    pub kernel_sha256: String,
    /// Canonical lowercase SHA-256 digest of the managed guest rootfs image.
    pub rootfs_sha256: String,
    /// Mount the rootfs read-only inside the guest.
    pub rootfs_read_only: bool,
    /// Guest vCPU count; validated to `1..=255`.
    pub vcpu_count: u32,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
    /// Guest vsock CID.
    pub guest_vsock_cid: u32,
    /// Optional kernel boot args.
    pub kernel_boot_args: Option<String>,
    /// Optional network configuration (`None` = no network device).
    pub network: Option<NetworkInput>,
    /// Optional warm-pool tier tag. When set, the pool manager may satisfy
    /// this request from a pre-warmed VM keyed by this tier string.
    pub tier: Option<String>,
}

/// Validated input for [`RuntimeCore::execute_command`].
#[derive(Debug)]
pub struct ExecuteCommandInput {
    /// Target workspace.
    pub workspace_id: String,
    /// Command binary path (resolved against guest `$PATH`).
    pub command: String,
    /// Arguments passed verbatim (no shell parsing).
    pub args: Vec<String>,
    /// Per-call timeout in ms; `0` disables.
    pub timeout_ms: u32,
    /// Guest vsock port; `0` defaults to 52.
    pub guest_port: u32,
}

/// Validated input for [`RuntimeCore::write_file`].
#[derive(Debug)]
pub struct WriteFileInput {
    /// Target workspace.
    pub workspace_id: String,
    /// Relative path inside the workspace jail root.
    pub path: String,
    /// File bytes; length validated against `MAX_INLINE_FILE_BYTES`.
    pub content: Vec<u8>,
    /// Guest vsock port; `0` defaults to 52.
    pub guest_port: u32,
}

/// Validated input for [`RuntimeCore::read_file`].
#[derive(Debug)]
pub struct ReadFileInput {
    /// Target workspace.
    pub workspace_id: String,
    /// Relative path inside the workspace jail root.
    pub path: String,
    /// Max bytes to return; `0` = server default, else capped at
    /// `MAX_INLINE_FILE_BYTES`.
    pub max_bytes: u64,
    /// Guest vsock port; `0` defaults to 52.
    pub guest_port: u32,
}

/// Validated input for [`RuntimeCore::expose_port`].
#[derive(Debug)]
pub struct ExposePortInput {
    /// Target workspace.
    pub workspace_id: String,
    /// Guest TCP port to route; must be `1..=65535`.
    pub port: u16,
    /// HTTP header name/value pairs the ingress proxy injects into every
    /// proxied request for this port.
    pub inject_headers: Vec<(String, String)>,
}

impl RuntimeCore {
    /// Construct a core backed by `supervisor`.
    #[must_use]
    pub fn new(supervisor: SupervisorClient) -> Self {
        Self {
            started_at: Instant::now(),
            supervisor,
        }
    }

    fn api_uptime_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Send one request to the supervisor, surfacing transport failures
    /// and typed `Error` responses as [`CoreError`]. Success variants
    /// flow back for op-specific unpacking.
    async fn call(&self, req: SupervisorRequest) -> Result<SupervisorResponse, CoreError> {
        let resp = self
            .supervisor
            .call(&req)
            .await
            .map_err(CoreError::Transport)?;
        if let SupervisorResponse::Error { kind, message } = resp {
            error!(?kind, %message, "supervisor returned typed error");
            return Err(CoreError::Supervisor { kind, message });
        }
        Ok(resp)
    }

    fn unexpected(op: &str, resp: &SupervisorResponse) -> CoreError {
        error!(op, ?resp, "supervisor returned unexpected variant");
        CoreError::Transport(SupervisorClientError::Unexpected(format!(
            "supervisor returned unexpected variant for {op}"
        )))
    }

    /// Liveness + supervisor round-trip.
    pub async fn ping(&self) -> Result<PingOutcome, CoreError> {
        match self.call(SupervisorRequest::Ping).await? {
            SupervisorResponse::Pong { version, uptime_ms } => Ok(PingOutcome {
                api_version: env!("CARGO_PKG_VERSION").to_string(),
                api_uptime_ms: self.api_uptime_ms(),
                supervisor_version: version,
                supervisor_uptime_ms: uptime_ms,
            }),
            other => Err(Self::unexpected("Ping", &other)),
        }
    }

    /// Return the supervisor's resolved runtime capabilities.
    pub async fn runtime_capabilities(
        &self,
    ) -> Result<ne_protocol::profile::RuntimeCapabilitiesInfo, CoreError> {
        match self.call(SupervisorRequest::GetCapabilities).await? {
            SupervisorResponse::Capabilities(capabilities) => Ok(capabilities),
            other => Err(Self::unexpected("GetCapabilities", &other)),
        }
    }

    /// Launch a workspace. Validates `vcpu_count` before narrowing to
    /// the supervisor's `u8`.
    pub async fn create_workspace(
        &self,
        input: CreateWorkspaceInput,
    ) -> Result<ne_protocol::supervisor::WorkspaceCreated, CoreError> {
        use ne_protocol::supervisor as sup;

        let vcpu_count = u8::try_from(input.vcpu_count).map_err(|_| {
            CoreError::Validation(format!(
                "vcpu_count must fit in u8, got {}",
                input.vcpu_count
            ))
        })?;
        let req = SupervisorRequest::CreateWorkspace(sup::CreateWorkspaceRequest {
            workspace_id: input.workspace_id,
            kernel_sha256: input.kernel_sha256,
            rootfs_sha256: input.rootfs_sha256,
            rootfs_read_only: input.rootfs_read_only,
            vcpu_count,
            mem_size_mib: input.mem_size_mib,
            guest_vsock_cid: input.guest_vsock_cid,
            kernel_boot_args: input.kernel_boot_args,
            network: input.network.map(|n| sup::NetworkConfig {
                enable_egress: n.enable_egress,
                allow_cidrs: n.allow_cidrs,
                allow_hostnames: n.allow_hostnames,
                privacy_router: n.privacy_router.then_some(sup::PrivacyRouterConfig {}),
                exposed_ports: n.exposed_ports,
            }),
            tier: input.tier,
        });

        match self.call(req).await? {
            SupervisorResponse::WorkspaceCreated(c) => Ok(c),
            other => Err(Self::unexpected("CreateWorkspace", &other)),
        }
    }

    /// Terminate a workspace and reclaim host resources.
    pub async fn destroy_workspace(
        &self,
        workspace_id: String,
        grace_period_ms: u32,
    ) -> Result<String, CoreError> {
        use ne_protocol::supervisor as sup;
        let req = SupervisorRequest::Terminate(sup::TerminateRequest {
            workspace_id,
            grace_period_ms,
        });
        match self.call(req).await? {
            SupervisorResponse::WorkspaceTerminated { workspace_id } => Ok(workspace_id),
            other => Err(Self::unexpected("DestroyWorkspace", &other)),
        }
    }

    /// Run one command inside a workspace (unary; full output buffered).
    pub async fn execute_command(
        &self,
        input: ExecuteCommandInput,
    ) -> Result<ne_protocol::supervisor::CommandCompleted, CoreError> {
        use ne_protocol::supervisor as sup;
        let guest_port = if input.guest_port == 0 {
            DEFAULT_GUEST_PORT
        } else {
            input.guest_port
        };
        let req = SupervisorRequest::RunCommand(sup::RunCommandRequest {
            workspace_id: input.workspace_id,
            guest_port,
            command: input.command,
            args: input.args,
            timeout_ms: input.timeout_ms,
        });
        match self.call(req).await? {
            SupervisorResponse::CommandCompleted(c) => Ok(c),
            other => Err(Self::unexpected("ExecuteCommand", &other)),
        }
    }

    /// Atomically write a file inside a workspace.
    pub async fn write_file(
        &self,
        input: WriteFileInput,
    ) -> Result<ne_protocol::supervisor::FileWritten, CoreError> {
        use ne_protocol::supervisor::{self as sup, MAX_INLINE_FILE_BYTES};
        if input.content.len() > MAX_INLINE_FILE_BYTES {
            return Err(CoreError::Validation(format!(
                "content length {} exceeds inline cap of {} bytes",
                input.content.len(),
                MAX_INLINE_FILE_BYTES,
            )));
        }
        let guest_port = if input.guest_port == 0 {
            DEFAULT_GUEST_PORT
        } else {
            input.guest_port
        };
        let req = SupervisorRequest::WriteFile(sup::WriteFileRequest {
            workspace_id: input.workspace_id,
            guest_port,
            path: input.path,
            content: input.content,
        });
        match self.call(req).await? {
            SupervisorResponse::FileWritten(w) => Ok(w),
            other => Err(Self::unexpected("WriteFile", &other)),
        }
    }

    /// Read a file from inside a workspace. Caps an explicit `max_bytes`
    /// at the inline limit (`0` passes through as server default).
    pub async fn read_file(
        &self,
        input: ReadFileInput,
    ) -> Result<ne_protocol::supervisor::FileRead, CoreError> {
        use ne_protocol::supervisor::{self as sup, MAX_INLINE_FILE_BYTES};
        let max_bytes = if input.max_bytes == 0 {
            0
        } else {
            std::cmp::min(input.max_bytes, MAX_INLINE_FILE_BYTES as u64)
        };
        let guest_port = if input.guest_port == 0 {
            DEFAULT_GUEST_PORT
        } else {
            input.guest_port
        };
        let req = SupervisorRequest::ReadFile(sup::ReadFileRequest {
            workspace_id: input.workspace_id,
            guest_port,
            path: input.path,
            max_bytes,
        });
        match self.call(req).await? {
            SupervisorResponse::FileRead(r) => Ok(r),
            other => Err(Self::unexpected("ReadFile", &other)),
        }
    }

    /// Pause a running workspace.
    ///
    /// DEFERRED: in-place pause/resume is unsupported on current
    /// Firecracker (the guest vsock control channel does not survive an
    /// in-place resume). The supervisor returns `Unsupported`; this surfaces as
    /// a `CoreError`. Use snapshot/restore instead. Retained so the API
    /// re-activates once a Firecracker fix lands.
    pub async fn pause_workspace(&self, workspace_id: String) -> Result<String, CoreError> {
        let req = SupervisorRequest::PauseWorkspace(ne_protocol::supervisor::WorkspaceRef {
            workspace_id,
        });
        match self.call(req).await? {
            SupervisorResponse::WorkspacePaused { workspace_id } => Ok(workspace_id),
            other => Err(Self::unexpected("PauseWorkspace", &other)),
        }
    }

    /// Resume a paused workspace.
    ///
    /// DEFERRED: see [`Self::pause_workspace`]. The supervisor
    /// returns `Unsupported`; use snapshot/restore instead.
    pub async fn resume_workspace(&self, workspace_id: String) -> Result<String, CoreError> {
        let req = SupervisorRequest::ResumeWorkspace(ne_protocol::supervisor::WorkspaceRef {
            workspace_id,
        });
        match self.call(req).await? {
            SupervisorResponse::WorkspaceResumed { workspace_id } => Ok(workspace_id),
            other => Err(Self::unexpected("ResumeWorkspace", &other)),
        }
    }

    /// Snapshot a workspace into a reusable artifact.
    ///
    /// When `live` is `true` the source VM keeps running (hot-swap snapshot);
    /// the returned [`SnapshotInfo`] carries the source's new `firecracker_pid`.
    pub async fn snapshot_workspace(
        &self,
        workspace_id: String,
        live: bool,
    ) -> Result<ne_protocol::supervisor::SnapshotInfo, CoreError> {
        let req = SupervisorRequest::SnapshotWorkspace(ne_protocol::supervisor::SnapshotRequest {
            workspace_id,
            live,
        });
        match self.call(req).await? {
            SupervisorResponse::SnapshotCreated(i) => Ok(i),
            other => Err(Self::unexpected("SnapshotWorkspace", &other)),
        }
    }

    /// Fork a fresh workspace from a snapshot artifact, resetting the new
    /// guest's identity. Returns the applied identity in the [`ForkInfo`].
    pub async fn fork_workspace(
        &self,
        snapshot_id: String,
        new_workspace_id: String,
        hostname: Option<String>,
    ) -> Result<ne_protocol::supervisor::ForkInfo, CoreError> {
        let req = SupervisorRequest::ForkWorkspace(ne_protocol::supervisor::ForkRequest {
            snapshot_id,
            new_workspace_id,
            hostname,
        });
        match self.call(req).await? {
            SupervisorResponse::WorkspaceForked(i) => Ok(i),
            other => Err(Self::unexpected("ForkWorkspace", &other)),
        }
    }

    /// Restore a fresh workspace from a snapshot artifact.
    pub async fn restore_workspace(
        &self,
        snapshot_id: String,
        new_workspace_id: String,
    ) -> Result<ne_protocol::supervisor::WorkspaceCreated, CoreError> {
        let req = SupervisorRequest::RestoreWorkspace(ne_protocol::supervisor::RestoreRequest {
            snapshot_id,
            new_workspace_id,
        });
        match self.call(req).await? {
            SupervisorResponse::WorkspaceRestored(c) => Ok(c),
            other => Err(Self::unexpected("RestoreWorkspace", &other)),
        }
    }

    /// Query the supervisor's signed audit event log.
    pub async fn list_events(
        &self,
        workspace_id: Option<String>,
        since_chain_index: u64,
        limit: u32,
    ) -> Result<ne_protocol::audit::ListEventsResponse, CoreError> {
        use ne_protocol::audit;
        let req = SupervisorRequest::ListEvents(audit::ListEventsRequest {
            workspace_id,
            since_chain_index,
            limit,
        });
        match self.call(req).await? {
            SupervisorResponse::Events(e) => Ok(e),
            other => Err(Self::unexpected("ListEvents", &other)),
        }
    }

    /// Query the warm pool manager's current status for the configured tier.
    pub async fn pool_status(&self) -> Result<ne_protocol::supervisor::PoolStatusInfo, CoreError> {
        let req = SupervisorRequest::PoolStatus(ne_protocol::supervisor::PoolStatusRequest {});
        match self.call(req).await? {
            SupervisorResponse::PoolStatus(info) => Ok(info),
            other => Err(Self::unexpected("PoolStatus", &other)),
        }
    }

    /// Start routing an ingress TCP port for a workspace.
    ///
    /// `port` must be in `1..=65535`; `inject_headers` are name/value pairs
    /// that the ingress proxy injects into every proxied HTTP request.
    /// Returns `(workspace_id, port)` on success.
    pub async fn expose_port(&self, input: ExposePortInput) -> Result<(String, u16), CoreError> {
        use ne_protocol::supervisor as sup;
        if input.port == 0 {
            return Err(CoreError::Validation("port must be 1..=65535".into()));
        }
        let req = SupervisorRequest::ExposePort(sup::ExposePortRequest {
            workspace_id: input.workspace_id,
            port: sup::ExposedPort {
                port: input.port,
                inject_headers: input
                    .inject_headers
                    .into_iter()
                    .map(|(name, value)| sup::HeaderInjection { name, value })
                    .collect(),
            },
        });
        match self.call(req).await? {
            SupervisorResponse::PortExposed { workspace_id, port } => Ok((workspace_id, port)),
            other => Err(Self::unexpected("ExposePort", &other)),
        }
    }

    /// Stop routing an ingress TCP port for a workspace.
    ///
    /// Returns `(workspace_id, port)` on success.
    pub async fn unexpose_port(
        &self,
        workspace_id: String,
        port: u16,
    ) -> Result<(String, u16), CoreError> {
        use ne_protocol::supervisor as sup;
        if port == 0 {
            return Err(CoreError::Validation("port must be 1..=65535".into()));
        }
        let req = SupervisorRequest::UnexposePort(sup::UnexposePortRequest { workspace_id, port });
        match self.call(req).await? {
            SupervisorResponse::PortUnexposed { workspace_id, port } => Ok((workspace_id, port)),
            other => Err(Self::unexpected("UnexposePort", &other)),
        }
    }

    /// Generate attestation evidence for a workspace. `nonce` must be
    /// 16..=64 bytes (validated here). Returns the signed envelope.
    pub async fn get_attestation_evidence(
        &self,
        workspace_id: String,
        nonce: Vec<u8>,
    ) -> Result<ne_attestation::Evidence, CoreError> {
        use ne_protocol::supervisor as sup;
        if !(16..=64).contains(&nonce.len()) {
            return Err(CoreError::Validation("nonce must be 16..=64 bytes".into()));
        }
        let req = SupervisorRequest::GetAttestationEvidence(sup::GetAttestationEvidenceRequest {
            workspace_id,
            nonce,
        });
        match self.call(req).await? {
            SupervisorResponse::AttestationEvidenceIssued { evidence } => Ok(evidence),
            other => Err(Self::unexpected("GetAttestationEvidence", &other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    /// Spawns an in-process NDJSON supervisor that answers every
    /// request via `responder`. Mirrors the harness in `server.rs`.
    fn spawn_fake_supervisor<F>(responder: F) -> (tempfile::TempDir, PathBuf)
    where
        F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
    {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("super.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let responder = Arc::clone(&responder);
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut reader = BufReader::new(rd);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let Ok(req) = serde_json::from_str::<SupervisorRequest>(line.trim_end()) else {
                        return;
                    };
                    let resp = responder(req);
                    let mut body = serde_json::to_vec(&resp).expect("ser");
                    body.push(b'\n');
                    let _ = wr.write_all(&body).await;
                });
            }
        });
        (tmp, path)
    }

    fn make_core<F>(responder: F) -> (RuntimeCore, tempfile::TempDir)
    where
        F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
    {
        let (tmp, path) = spawn_fake_supervisor(responder);
        (RuntimeCore::new(SupervisorClient::new(path)), tmp)
    }

    #[tokio::test]
    async fn ping_relays_supervisor_pong() {
        let (core, _tmp) = make_core(|_| SupervisorResponse::Pong {
            version: "0.0.0-fake".into(),
            uptime_ms: 7,
        });
        let out = core.ping().await.expect("ping");
        assert_eq!(out.supervisor_version, "0.0.0-fake");
        assert_eq!(out.supervisor_uptime_ms, 7);
        assert_eq!(out.api_version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn runtime_capabilities_relay_profile_contract() {
        let expected =
            ne_protocol::profile::ExecutionProfile::ConfidentialAzure.capabilities("0.2.0", 1);
        let response = expected.clone();
        let (core, _tmp) = make_core(move |_| SupervisorResponse::Capabilities(response.clone()));
        assert_eq!(
            core.runtime_capabilities().await.expect("capabilities"),
            expected
        );
    }

    #[tokio::test]
    async fn typed_error_becomes_core_error_with_code() {
        let (core, _tmp) = make_core(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message: "ghost".into(),
        });
        let err = core.ping().await.expect_err("must surface error");
        assert_eq!(err.code(), "WORKSPACE_NOT_FOUND");
    }

    #[test]
    fn image_error_codes_are_stable() {
        for (kind, code) in [
            (
                SupervisorErrorKind::InvalidImageDigest,
                "INVALID_IMAGE_DIGEST",
            ),
            (SupervisorErrorKind::ImageNotFound, "IMAGE_NOT_FOUND"),
            (SupervisorErrorKind::ImageRejected, "IMAGE_REJECTED"),
            (
                SupervisorErrorKind::ImageDigestMismatch,
                "IMAGE_DIGEST_MISMATCH",
            ),
            (SupervisorErrorKind::ImageStageFailed, "IMAGE_STAGE_FAILED"),
        ] {
            assert_eq!(supervisor_kind_code(kind), code);
        }
    }

    #[test]
    fn profile_error_codes_are_stable() {
        assert_eq!(
            supervisor_kind_code(SupervisorErrorKind::UnsupportedForProfile),
            "UNSUPPORTED_FOR_PROFILE"
        );
        assert_eq!(
            supervisor_kind_code(SupervisorErrorKind::ConfidentialCapacityExceeded),
            "CONFIDENTIAL_CAPACITY_EXCEEDED"
        );
    }

    #[tokio::test]
    async fn create_workspace_relays_and_maps_network() {
        use ne_protocol::supervisor as sup;
        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::CreateWorkspace(c) => {
                let net = c.network.expect("network must reach supervisor");
                assert!(net.enable_egress);
                assert!(net.privacy_router.is_some(), "bool true -> Some(cfg)");
                SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                    workspace_id: c.workspace_id,
                    firecracker_pid: 4242,
                    vsock_host_socket: "/x/vsock.sock".into(),
                    jailer_chroot: "/x".into(),
                    network: None,
                    exec_backend: None,
                    control_socket: None,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected: {other:?}"),
            },
        });
        let out = core
            .create_workspace(CreateWorkspaceInput {
                workspace_id: "wks-1".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 2,
                mem_size_mib: 256,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: Some(NetworkInput {
                    enable_egress: true,
                    allow_cidrs: vec!["10.0.0.0/8".into()],
                    allow_hostnames: vec!["*.github.com".into()],
                    privacy_router: true,
                    exposed_ports: vec![],
                }),
                tier: None,
            })
            .await
            .expect("create");
        assert_eq!(out.workspace_id, "wks-1");
        assert_eq!(out.firecracker_pid, 4242);
    }

    #[tokio::test]
    async fn create_workspace_relays_zero_and_rejects_oversized_vcpu() {
        use ne_protocol::supervisor as sup;

        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::CreateWorkspace(c) => {
                assert_eq!(c.vcpu_count, 0);
                SupervisorResponse::WorkspaceCreated(sup::WorkspaceCreated {
                    workspace_id: c.workspace_id,
                    firecracker_pid: 0,
                    vsock_host_socket: String::new(),
                    jailer_chroot: String::new(),
                    network: None,
                    exec_backend: Some("openshell".into()),
                    control_socket: Some("127.0.0.1:2222".into()),
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected: {other:?}"),
            },
        });
        let base = || CreateWorkspaceInput {
            workspace_id: "w".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 0,
            mem_size_mib: 256,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        };
        core.create_workspace(base())
            .await
            .expect("zero vcpu must reach profile-aware supervisor");
        let mut big = base();
        big.vcpu_count = 300;
        let over = core.create_workspace(big).await.expect_err("vcpu > 255");
        assert_eq!(over.code(), "VALIDATION");
    }

    #[tokio::test]
    async fn destroy_maps_not_found() {
        let (core, _tmp) = make_core(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message: "gone".into(),
        });
        let err = core
            .destroy_workspace("ghost".into(), 1000)
            .await
            .expect_err("nf");
        assert_eq!(err.code(), "WORKSPACE_NOT_FOUND");
    }

    #[tokio::test]
    async fn execute_command_defaults_guest_port_and_relays() {
        use ne_protocol::supervisor as sup;
        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::RunCommand(r) => {
                assert_eq!(r.guest_port, 52, "0 must default to 52");
                SupervisorResponse::CommandCompleted(sup::CommandCompleted {
                    workspace_id: r.workspace_id,
                    stdout: "hi\n".into(),
                    stderr: String::new(),
                    exit_code: 0,
                    elapsed_ms: 1,
                    truncated: false,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("{other:?}"),
            },
        });
        let out = core
            .execute_command(ExecuteCommandInput {
                workspace_id: "w".into(),
                command: "/bin/echo".into(),
                args: vec!["hi".into()],
                timeout_ms: 1000,
                guest_port: 0,
            })
            .await
            .expect("exec");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("hi"));
    }

    #[tokio::test]
    async fn write_file_rejects_oversized_content() {
        use ne_protocol::supervisor::MAX_INLINE_FILE_BYTES;
        let (core, _tmp) = make_core(|_| SupervisorResponse::Pong {
            version: "x".into(),
            uptime_ms: 0,
        });
        let err = core
            .write_file(WriteFileInput {
                workspace_id: "w".into(),
                path: "big.bin".into(),
                content: vec![0u8; MAX_INLINE_FILE_BYTES + 1],
                guest_port: 0,
            })
            .await
            .expect_err("oversized");
        assert_eq!(err.code(), "VALIDATION");
    }

    #[tokio::test]
    async fn read_file_caps_max_bytes() {
        use ne_protocol::supervisor::{self as sup, MAX_INLINE_FILE_BYTES};
        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::ReadFile(c) => {
                assert_eq!(c.max_bytes, MAX_INLINE_FILE_BYTES as u64, "must cap");
                SupervisorResponse::FileRead(sup::FileRead {
                    workspace_id: c.workspace_id,
                    content: b"ok".to_vec(),
                    size_bytes: 2,
                    truncated: false,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("{other:?}"),
            },
        });
        let out = core
            .read_file(ReadFileInput {
                workspace_id: "w".into(),
                path: "f".into(),
                max_bytes: 100_000_000,
                guest_port: 0,
            })
            .await
            .expect("read");
        assert_eq!(out.content, b"ok");
    }

    #[tokio::test]
    async fn list_events_relays() {
        use ne_protocol::audit;
        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::ListEvents(r) => {
                assert_eq!(r.workspace_id.as_deref(), Some("w"));
                SupervisorResponse::Events(audit::ListEventsResponse { events: vec![] })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("{other:?}"),
            },
        });
        let out = core
            .list_events(Some("w".into()), 0, 0)
            .await
            .expect("events");
        assert!(out.events.is_empty());
    }

    #[tokio::test]
    async fn fork_relays_and_returns_identity() {
        use ne_protocol::supervisor as sup;
        let (core, _tmp) = make_core(|req| match req {
            SupervisorRequest::ForkWorkspace(f) => {
                assert_eq!(f.snapshot_id, "01J0SNAP");
                SupervisorResponse::WorkspaceForked(sup::ForkInfo {
                    workspace_id: f.new_workspace_id,
                    firecracker_pid: 99,
                    vsock_host_socket: "/x/vsock.sock".into(),
                    jailer_chroot: "/x".into(),
                    source_snapshot_id: f.snapshot_id,
                    hostname: f.hostname.unwrap_or_else(|| "default".into()),
                    machine_id: "0123456789abcdef0123456789abcdef".into(),
                    guest_vsock_cid: 3,
                })
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("{other:?}"),
            },
        });
        let out = core
            .fork_workspace("01J0SNAP".into(), "fork-a".into(), Some("fork-a".into()))
            .await
            .expect("fork");
        assert_eq!(out.workspace_id, "fork-a");
        assert_eq!(out.hostname, "fork-a");
        assert_eq!(out.guest_vsock_cid, 3);
    }

    #[tokio::test]
    async fn fork_maps_fork_failed_code() {
        let (core, _tmp) = make_core(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::ForkFailed,
            message: "reset failed".into(),
        });
        let err = core
            .fork_workspace("s".into(), "w".into(), None)
            .await
            .expect_err("must fail");
        assert_eq!(err.code(), "FORK_FAILED");
    }

    #[tokio::test]
    async fn get_attestation_evidence_rejects_short_nonce() {
        let (core, _tmp) = make_core(|_| panic!("supervisor must not be called"));
        let err = core
            .get_attestation_evidence("ws-attest-1".into(), vec![0u8; 8])
            .await
            .expect_err("short nonce must fail");
        assert_eq!(err.code(), "VALIDATION");
    }

    #[tokio::test]
    async fn get_attestation_evidence_maps_workspace_not_found() {
        let (core, _tmp) = make_core(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message: "ghost workspace".into(),
        });
        let err = core
            .get_attestation_evidence("ghost".into(), vec![0u8; 16])
            .await
            .expect_err("must fail");
        assert_eq!(err.code(), "WORKSPACE_NOT_FOUND");
    }
}

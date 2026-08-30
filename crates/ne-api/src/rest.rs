// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! REST/JSON gateway over [`crate::core::RuntimeCore`].
//!
//! Maps the runtime RPCs to HTTP paths. Shares
//! the supervisor IPC path with the gRPC server via `RuntimeCore`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use ne_protocol::supervisor as sup;

use crate::auth::ApiKeyStore;

use crate::core::{CoreError, NetworkInput, RuntimeCore};
use crate::supervisor_client::SupervisorClientError;

/// Max REST request body. File content travels base64 in JSON, which
/// inflates the 10 MiB raw inline cap by 4/3 (~13.98 MiB); 15 MiB leaves
/// headroom for JSON field overhead. The raw 10 MiB cap is still
/// enforced in `RuntimeCore::write_file` after base64 decode.
const REST_MAX_BODY_BYTES: usize = 15 * 1024 * 1024;

/// Build the REST router backed by `core`.
pub fn router(core: Arc<RuntimeCore>) -> Router {
    Router::new()
        .route("/v1/host/health", get(health))
        .route("/v1/runtime/capabilities", get(runtime_capabilities))
        .route("/v1/workspaces", post(create_workspace))
        .route("/v1/workspaces/:workspace_id", delete(destroy_workspace))
        .route("/v1/workspaces/:workspace_id/exec", post(execute_command))
        .route(
            "/v1/workspaces/:workspace_id/files",
            put(write_file).get(read_file),
        )
        .route("/v1/workspaces/:workspace_id/pause", post(pause_workspace))
        .route(
            "/v1/workspaces/:workspace_id/resume",
            post(resume_workspace),
        )
        .route(
            "/v1/workspaces/:workspace_id/snapshot",
            post(snapshot_workspace),
        )
        .route(
            "/v1/snapshots/:snapshot_id/restore",
            post(restore_workspace),
        )
        .route("/v1/snapshots/:snapshot_id/fork", post(fork_workspace))
        .route("/v1/events", get(list_events))
        .route("/v1/pool/status", get(pool_status))
        .route(
            "/v1/workspaces/:workspace_id/ingress/:port",
            post(expose_port).delete(unexpose_port),
        )
        .route(
            "/v1/workspaces/:workspace_id/attestation",
            post(get_attestation),
        )
        .layer(DefaultBodyLimit::max(REST_MAX_BODY_BYTES))
        .with_state(core)
}

/// Router with the API-key middleware applied. Used by `run()` in
/// production posture. `router()` (no auth) is used only in dev mode.
pub fn authed_router(core: Arc<RuntimeCore>, store: Arc<ApiKeyStore>) -> Router {
    router(core).layer(middleware::from_fn_with_state(store, api_key_guard))
}

async fn api_key_guard(
    State(store): State<Arc<ApiKeyStore>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let ok = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(ApiKeyStore::bearer_from_str)
        .is_some_and(|t| store.verify(t).is_some());
    if ok {
        next.run(req).await
    } else {
        let body = ErrorBody {
            error: ErrorDetail {
                code: "UNAUTHENTICATED",
                message: "missing or invalid API key".into(),
            },
        };
        (StatusCode::UNAUTHORIZED, Json(body)).into_response()
    }
}

/// JSON error envelope: `{ "error": { "code": ..., "message": ... } }`.
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

/// Wraps [`CoreError`] so it can be returned from handlers as `?` and
/// rendered into an HTTP response.
struct ApiError(CoreError);

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = core_error_to_status(&self.0);
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.0.code(),
                message: self.0.message(),
            },
        };
        (status, Json(body)).into_response()
    }
}

/// Map a [`CoreError`] to its HTTP status. Mirrors the gRPC status map
/// and the code strings in `crate::core::supervisor_kind_code`.
fn core_error_to_status(e: &CoreError) -> StatusCode {
    use ne_protocol::supervisor::SupervisorErrorKind as K;
    let kind = match e {
        CoreError::Validation(_) => return StatusCode::BAD_REQUEST,
        CoreError::Transport(SupervisorClientError::Io(_)) => {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        CoreError::Transport(SupervisorClientError::Supervisor { kind, .. })
        | CoreError::Supervisor { kind, .. } => *kind,
        CoreError::Transport(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    match kind {
        K::Unauthorized => StatusCode::FORBIDDEN,
        K::InvalidRequest | K::InvalidImageDigest | K::PathRejected | K::FileTooLarge => {
            StatusCode::BAD_REQUEST
        }
        K::Unsupported => StatusCode::NOT_IMPLEMENTED,
        // WorkspaceAlreadyExists + the failed_precondition group all map to
        // 409 CONFLICT (team convention: gRPC failed_precondition ↔ HTTP 409).
        K::WorkspaceAlreadyExists
        | K::ImageRejected
        | K::ImageDigestMismatch
        | K::InvalidSnapshot
        | K::WorkspaceNotPaused
        | K::WorkspaceAlreadyPaused
        | K::WorkspaceNotNetworked
        | K::AttestationReplay
        | K::UnsupportedForProfile
        | K::ConfidentialCapacityExceeded => StatusCode::CONFLICT,
        K::WorkspaceNotFound
        | K::FileNotFound
        | K::ImageNotFound
        | K::TierNotFound
        | K::IngressPortNotFound => StatusCode::NOT_FOUND,
        K::Timeout => StatusCode::GATEWAY_TIMEOUT,
        K::GuestUnreachable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod image_error_mapping_tests {
    use super::*;
    use ne_protocol::supervisor::SupervisorErrorKind as K;

    #[test]
    fn image_errors_map_to_http_statuses() {
        for (kind, status) in [
            (K::InvalidImageDigest, StatusCode::BAD_REQUEST),
            (K::ImageNotFound, StatusCode::NOT_FOUND),
            (K::ImageRejected, StatusCode::CONFLICT),
            (K::ImageDigestMismatch, StatusCode::CONFLICT),
            (K::ImageStageFailed, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let error = CoreError::Supervisor {
                kind,
                message: "image error".into(),
            };
            assert_eq!(core_error_to_status(&error), status);
        }
    }

    #[test]
    fn profile_errors_map_to_conflict() {
        for kind in [K::UnsupportedForProfile, K::ConfidentialCapacityExceeded] {
            let error = CoreError::Supervisor {
                kind,
                message: "profile error".into(),
            };
            assert_eq!(core_error_to_status(&error), StatusCode::CONFLICT);
        }
    }
}

/// Liveness + supervisor round-trip. `GET /v1/host/health`.
#[derive(Serialize)]
struct HealthResponse {
    api_version: String,
    api_uptime_ms: u64,
    supervisor_version: String,
    supervisor_uptime_ms: u64,
}

async fn health(State(core): State<Arc<RuntimeCore>>) -> Result<Json<HealthResponse>, ApiError> {
    let out = core.ping().await?;
    Ok(Json(HealthResponse {
        api_version: out.api_version,
        api_uptime_ms: out.api_uptime_ms,
        supervisor_version: out.supervisor_version,
        supervisor_uptime_ms: out.supervisor_uptime_ms,
    }))
}

async fn runtime_capabilities(
    State(core): State<Arc<RuntimeCore>>,
) -> Result<Json<ne_protocol::profile::RuntimeCapabilitiesInfo>, ApiError> {
    Ok(Json(core.runtime_capabilities().await?))
}

/// `POST /v1/workspaces` request body. `network.privacy_router` present
/// (even `{}`) means opt-in.
#[derive(Deserialize)]
struct CreateWorkspaceBody {
    workspace_id: String,
    kernel_sha256: String,
    rootfs_sha256: String,
    rootfs_read_only: bool,
    vcpu_count: u32,
    mem_size_mib: u32,
    guest_vsock_cid: u32,
    #[serde(default)]
    kernel_boot_args: Option<String>,
    #[serde(default)]
    network: Option<NetworkBody>,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Deserialize)]
struct NetworkBody {
    enable_egress: bool,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    allow_hostnames: Vec<String>,
    #[serde(default)]
    privacy_router: Option<serde_json::Value>,
    /// Guest TCP ports to expose via ingress routing at creation time.
    #[serde(default)]
    exposed_ports: Vec<ExposedPortBody>,
}

/// One guest TCP port exposed in a REST `NetworkBody`.
#[derive(Deserialize)]
struct ExposedPortBody {
    /// Guest TCP port (1..=65535). Invalid ports are silently dropped.
    port: u32,
    /// HTTP headers the ingress proxy injects for this port.
    #[serde(default)]
    inject_headers: Vec<HeaderInjectionBody>,
}

/// A single injected header in a REST `ExposedPortBody`.
#[derive(Deserialize)]
struct HeaderInjectionBody {
    name: String,
    value: String,
}

/// `POST /v1/workspaces` success body (mirrors the supervisor's
/// `WorkspaceCreated`).
#[derive(Serialize)]
struct CreateWorkspaceResponse {
    workspace_id: String,
    firecracker_pid: u32,
    vsock_host_socket: String,
    jailer_chroot: String,
    network: Option<WorkspaceNetworkResponse>,
}

#[derive(Serialize)]
struct WorkspaceNetworkResponse {
    netns_path: String,
    tap_device: String,
    host_ip: String,
    guest_ip: String,
    prefix: u8,
}

async fn create_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Json(body): Json<CreateWorkspaceBody>,
) -> Result<(StatusCode, Json<CreateWorkspaceResponse>), ApiError> {
    use crate::core::CreateWorkspaceInput;
    let c = core
        .create_workspace(CreateWorkspaceInput {
            workspace_id: body.workspace_id,
            kernel_sha256: body.kernel_sha256,
            rootfs_sha256: body.rootfs_sha256,
            rootfs_read_only: body.rootfs_read_only,
            vcpu_count: body.vcpu_count,
            mem_size_mib: body.mem_size_mib,
            guest_vsock_cid: body.guest_vsock_cid,
            kernel_boot_args: body.kernel_boot_args,
            tier: body.tier,
            network: body.network.map(|n| NetworkInput {
                enable_egress: n.enable_egress,
                allow_cidrs: n.allow_cidrs,
                allow_hostnames: n.allow_hostnames,
                privacy_router: n.privacy_router.is_some(),
                exposed_ports: n
                    .exposed_ports
                    .into_iter()
                    .filter_map(|p| {
                        u16::try_from(p.port)
                            .ok()
                            .filter(|&port| port != 0)
                            .map(|port| sup::ExposedPort {
                                port,
                                inject_headers: p
                                    .inject_headers
                                    .into_iter()
                                    .map(|h| sup::HeaderInjection {
                                        name: h.name,
                                        value: h.value,
                                    })
                                    .collect(),
                            })
                    })
                    .collect(),
            }),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateWorkspaceResponse {
            workspace_id: c.workspace_id,
            firecracker_pid: c.firecracker_pid,
            vsock_host_socket: c.vsock_host_socket,
            jailer_chroot: c.jailer_chroot,
            network: c.network.map(|n| WorkspaceNetworkResponse {
                netns_path: n.netns_path,
                tap_device: n.tap_device,
                host_ip: n.host_ip,
                guest_ip: n.guest_ip,
                prefix: n.prefix,
            }),
        }),
    ))
}

/// `DELETE /v1/workspaces/{id}` query string.
#[derive(Deserialize)]
struct DestroyQuery {
    #[serde(default)]
    grace_period_ms: u32,
}

#[derive(Serialize)]
struct DestroyResponse {
    workspace_id: String,
}

async fn destroy_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    Query(q): Query<DestroyQuery>,
) -> Result<Json<DestroyResponse>, ApiError> {
    let workspace_id = core
        .destroy_workspace(workspace_id, q.grace_period_ms)
        .await?;
    Ok(Json(DestroyResponse { workspace_id }))
}

/// `POST /v1/workspaces/{id}/exec` request body.
#[derive(Deserialize)]
struct ExecBody {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    timeout_ms: u32,
    #[serde(default)]
    guest_port: u32,
}

#[derive(Serialize)]
struct ExecResponse {
    workspace_id: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
    elapsed_ms: u64,
    truncated: bool,
}

async fn execute_command(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    Json(body): Json<ExecBody>,
) -> Result<Json<ExecResponse>, ApiError> {
    use crate::core::ExecuteCommandInput;
    let c = core
        .execute_command(ExecuteCommandInput {
            workspace_id,
            command: body.command,
            args: body.args,
            timeout_ms: body.timeout_ms,
            guest_port: body.guest_port,
        })
        .await?;
    Ok(Json(ExecResponse {
        workspace_id: c.workspace_id,
        stdout: c.stdout,
        stderr: c.stderr,
        exit_code: c.exit_code,
        elapsed_ms: c.elapsed_ms,
        truncated: c.truncated,
    }))
}

/// `PUT /v1/workspaces/{id}/files` request body. `content` is base64.
#[derive(Deserialize)]
struct WriteFileBody {
    path: String,
    content: String,
    #[serde(default)]
    guest_port: u32,
}

#[derive(Serialize)]
struct WriteFileResponse {
    workspace_id: String,
    bytes_written: u64,
    absolute_path: String,
}

async fn write_file(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    Json(body): Json<WriteFileBody>,
) -> Result<Json<WriteFileResponse>, ApiError> {
    use crate::core::WriteFileInput;
    let content = BASE64.decode(body.content.as_bytes()).map_err(|e| {
        ApiError(CoreError::Validation(format!(
            "content is not valid base64: {e}"
        )))
    })?;
    let w = core
        .write_file(WriteFileInput {
            workspace_id,
            path: body.path,
            content,
            guest_port: body.guest_port,
        })
        .await?;
    Ok(Json(WriteFileResponse {
        workspace_id: w.workspace_id,
        bytes_written: w.bytes_written,
        absolute_path: w.absolute_path,
    }))
}

/// `GET /v1/workspaces/{id}/files` query string.
#[derive(Deserialize)]
struct ReadFileQuery {
    path: String,
    #[serde(default)]
    max_bytes: u64,
    #[serde(default)]
    guest_port: u32,
}

/// Read response; `content` is base64-encoded.
#[derive(Serialize)]
struct ReadFileResponse {
    workspace_id: String,
    content: String,
    size_bytes: u64,
    truncated: bool,
}

async fn read_file(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    Query(q): Query<ReadFileQuery>,
) -> Result<Json<ReadFileResponse>, ApiError> {
    use crate::core::ReadFileInput;
    let r = core
        .read_file(ReadFileInput {
            workspace_id,
            path: q.path,
            max_bytes: q.max_bytes,
            guest_port: q.guest_port,
        })
        .await?;
    Ok(Json(ReadFileResponse {
        workspace_id: r.workspace_id,
        content: BASE64.encode(&r.content),
        size_bytes: r.size_bytes,
        truncated: r.truncated,
    }))
}

/// `GET /v1/events` query string. All fields optional.
#[derive(Deserialize)]
struct ListEventsQuery {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    since_chain_index: u64,
    #[serde(default)]
    limit: u32,
}

async fn list_events(
    State(core): State<Arc<RuntimeCore>>,
    Query(q): Query<ListEventsQuery>,
) -> Result<Json<ne_protocol::audit::ListEventsResponse>, ApiError> {
    let events = core
        .list_events(q.workspace_id, q.since_chain_index, q.limit)
        .await?;
    Ok(Json(events))
}

/// `POST /v1/workspaces/{id}/pause` and `resume` response body. NOTE: pause/
/// resume are DEFERRED and currently always return an error, so
/// this success shape is unused for now; retained for when the API re-activates.
#[derive(Serialize)]
struct WorkspaceIdResponse {
    workspace_id: String,
}

/// `POST /v1/workspaces/{id}/snapshot` request body (optional).
#[derive(Deserialize, Default)]
#[serde(default)]
struct SnapshotBody {
    live: bool,
}

/// `POST /v1/workspaces/{id}/snapshot` success body.
#[derive(Serialize)]
struct SnapshotResponse {
    snapshot_id: String,
    created_from_workspace_id: String,
    mem_sha256: String,
    vmstate_sha256: String,
    size_bytes: u64,
    firecracker_pid: Option<u32>,
}

/// `POST /v1/snapshots/{id}/restore` request body.
#[derive(Deserialize)]
struct RestoreBody {
    new_workspace_id: String,
}

/// `POST /v1/snapshots/{id}/fork` request body.
#[derive(Deserialize)]
struct ForkBody {
    new_workspace_id: String,
    #[serde(default)]
    hostname: Option<String>,
}

/// `POST /v1/snapshots/{id}/fork` response body.
#[derive(Serialize)]
struct ForkResponse {
    workspace_id: String,
    firecracker_pid: u32,
    vsock_host_socket: String,
    jailer_chroot: String,
    source_snapshot_id: String,
    hostname: String,
    machine_id: String,
    guest_vsock_cid: u32,
}

async fn pause_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
) -> Result<Json<WorkspaceIdResponse>, ApiError> {
    let id = core.pause_workspace(workspace_id).await?;
    Ok(Json(WorkspaceIdResponse { workspace_id: id }))
}

async fn resume_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
) -> Result<Json<WorkspaceIdResponse>, ApiError> {
    let id = core.resume_workspace(workspace_id).await?;
    Ok(Json(WorkspaceIdResponse { workspace_id: id }))
}

async fn snapshot_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    body: Option<Json<SnapshotBody>>,
) -> Result<(StatusCode, Json<SnapshotResponse>), ApiError> {
    let live = body.is_some_and(|Json(b)| b.live);
    let i = core.snapshot_workspace(workspace_id, live).await?;
    Ok((
        StatusCode::CREATED,
        Json(SnapshotResponse {
            snapshot_id: i.snapshot_id,
            created_from_workspace_id: i.created_from_workspace_id,
            mem_sha256: i.mem_sha256,
            vmstate_sha256: i.vmstate_sha256,
            size_bytes: i.size_bytes,
            firecracker_pid: i.firecracker_pid,
        }),
    ))
}

async fn restore_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(snapshot_id): Path<String>,
    Json(body): Json<RestoreBody>,
) -> Result<(StatusCode, Json<CreateWorkspaceResponse>), ApiError> {
    let c = core
        .restore_workspace(snapshot_id, body.new_workspace_id)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateWorkspaceResponse {
            workspace_id: c.workspace_id,
            firecracker_pid: c.firecracker_pid,
            vsock_host_socket: c.vsock_host_socket,
            jailer_chroot: c.jailer_chroot,
            network: None,
        }),
    ))
}

async fn fork_workspace(
    State(core): State<Arc<RuntimeCore>>,
    Path(snapshot_id): Path<String>,
    Json(body): Json<ForkBody>,
) -> Result<(StatusCode, Json<ForkResponse>), ApiError> {
    let i = core
        .fork_workspace(snapshot_id, body.new_workspace_id, body.hostname)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ForkResponse {
            workspace_id: i.workspace_id,
            firecracker_pid: i.firecracker_pid,
            vsock_host_socket: i.vsock_host_socket,
            jailer_chroot: i.jailer_chroot,
            source_snapshot_id: i.source_snapshot_id,
            hostname: i.hostname,
            machine_id: i.machine_id,
            guest_vsock_cid: i.guest_vsock_cid,
        }),
    ))
}

/// `GET /v1/pool/status` response body.
#[derive(Serialize)]
struct PoolStatusResponse {
    configured: bool,
    tier: Option<String>,
    target_size: u32,
    available: u32,
    in_flight: u32,
}

async fn pool_status(
    State(core): State<Arc<RuntimeCore>>,
) -> Result<Json<PoolStatusResponse>, ApiError> {
    let s = core.pool_status().await?;
    Ok(Json(PoolStatusResponse {
        configured: s.configured,
        tier: s.tier,
        target_size: s.target_size,
        available: s.available,
        in_flight: s.in_flight,
    }))
}

/// `POST /v1/workspaces/{id}/ingress/{port}` request body.
/// `inject_headers` is optional; omitting it means no header injection.
#[derive(Deserialize)]
struct ExposeBody {
    #[serde(default)]
    inject_headers: Vec<HeaderInjectionBody>,
}

/// `POST` and `DELETE /v1/workspaces/{id}/ingress/{port}` response body.
#[derive(Serialize)]
struct ExposeResponse {
    workspace_id: String,
    port: u16,
}

/// `POST /v1/workspaces/:workspace_id/ingress/:port` — expose a guest TCP port
/// via the host ingress proxy.
async fn expose_port(
    State(core): State<Arc<RuntimeCore>>,
    Path((workspace_id, port)): Path<(String, u16)>,
    Json(body): Json<ExposeBody>,
) -> Result<Json<ExposeResponse>, ApiError> {
    use crate::core::ExposePortInput;
    let (workspace_id, port) = core
        .expose_port(ExposePortInput {
            workspace_id,
            port,
            inject_headers: body
                .inject_headers
                .into_iter()
                .map(|h| (h.name, h.value))
                .collect(),
        })
        .await?;
    Ok(Json(ExposeResponse { workspace_id, port }))
}

/// `DELETE /v1/workspaces/:workspace_id/ingress/:port` — remove an ingress
/// mapping for the given guest TCP port.
async fn unexpose_port(
    State(core): State<Arc<RuntimeCore>>,
    Path((workspace_id, port)): Path<(String, u16)>,
) -> Result<Json<ExposeResponse>, ApiError> {
    let (workspace_id, port) = core.unexpose_port(workspace_id, port).await?;
    Ok(Json(ExposeResponse { workspace_id, port }))
}

/// `POST /v1/workspaces/{id}/attestation` request body.
#[derive(Deserialize)]
struct AttestationBody {
    /// Base64-encoded caller nonce (16..=64 bytes decoded).
    nonce: String,
}

/// `POST /v1/workspaces/:workspace_id/attestation` — generate attestation
/// evidence for the workspace. The caller must supply a base64-encoded
/// nonce (16..=64 bytes after decoding). Returns the versioned public
/// evidence envelope as JSON.
async fn get_attestation(
    State(core): State<Arc<RuntimeCore>>,
    Path(workspace_id): Path<String>,
    Json(body): Json<AttestationBody>,
) -> Result<Json<ne_protocol::attestation::PublicAttestationEvidence>, ApiError> {
    let nonce = BASE64
        .decode(body.nonce.as_bytes())
        .map_err(|_| CoreError::Validation("nonce must be valid base64".into()))?;
    let evidence = core.get_attestation_evidence(workspace_id, nonce).await?;
    let public = ne_protocol::attestation::PublicAttestationEvidence::try_from(evidence).map_err(
        |error| {
            ApiError(CoreError::Supervisor {
                kind: sup::SupervisorErrorKind::Internal,
                message: format!("encode public attestation evidence: {error}"),
            })
        },
    )?;
    Ok(Json(public))
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    use crate::auth::ApiKeyStore;
    use crate::core::RuntimeCore;
    use crate::supervisor_client::SupervisorClient;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn store_with(token: &str) -> Arc<ApiKeyStore> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(
            &path,
            format!("sha256:{}\n", hex::encode(Sha256::digest(token.as_bytes()))),
        )
        .unwrap();
        // keep tempdir alive for the test process lifetime
        std::mem::forget(dir);
        Arc::new(ApiKeyStore::load(&path).unwrap())
    }

    fn app(store: Arc<ApiKeyStore>) -> Router {
        // RuntimeCore pointing at a non-existent socket is fine: auth
        // rejects before any supervisor call on the unauthorized paths.
        let core = Arc::new(RuntimeCore::new(SupervisorClient::new(
            "/nonexistent.sock".into(),
        )));
        authed_router(core, store)
    }

    #[tokio::test]
    async fn rest_rejects_missing_authorization() {
        let app = app(store_with("nee_good"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/host/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rest_rejects_wrong_token() {
        let app = app(store_with("nee_good"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/host/health")
                    .header("authorization", "Bearer nee_bad")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rest_accepts_valid_token_passes_auth() {
        let app = app(store_with("nee_good"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/host/health")
                    .header("authorization", "Bearer nee_good")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Valid token passes the auth layer; the request then fails at the
        // (absent) supervisor — NOT a 401. This proves the positive path.
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::*;
    use crate::core::RuntimeCore;
    use crate::supervisor_client::SupervisorClient;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app() -> Router {
        // RuntimeCore pointing at a non-existent socket; the ingress routes
        // will fail at the supervisor IPC level (EPERM / connection refused on
        // macOS), but routing + deserialization are exercised.  On the dev VM
        // with a live supervisor this returns 200.
        let core = Arc::new(RuntimeCore::new(SupervisorClient::new(
            "/nonexistent.sock".into(),
        )));
        router(core)
    }

    /// POST to the ingress route is routed correctly (not 404/405) and the
    /// request body deserialises without error.  The response will be a
    /// transport error on macOS (no supervisor), not a 200 — that is
    /// expected.  On the dev VM with a live supervisor returning
    /// `PortExposed`, this will be 200 + echoed body.
    #[tokio::test]
    async fn expose_port_route_exists_and_body_parses() {
        let body = serde_json::json!({
            "inject_headers": [
                { "name": "X-Workspace-Id", "value": "ws-a" }
            ]
        })
        .to_string();
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workspaces/ws-a/ingress/8080")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Must NOT be 404 (route missing) or 405 (method not allowed) or 422
        // (body parse error).  A 503 (supervisor unreachable) is fine here.
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_ne!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// DELETE to the ingress route is also routed correctly.
    #[tokio::test]
    async fn unexpose_port_route_exists() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/workspaces/ws-a/ingress/8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// A non-numeric port in the URL yields a 400 from axum's path extractor.
    #[tokio::test]
    async fn expose_port_rejects_non_numeric_port() {
        let body = serde_json::json!({ "inject_headers": [] }).to_string();
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workspaces/ws-a/ingress/not-a-port")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod attestation_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ne_attestation::{Evidence, Measurement, Proof, ProviderType};
    use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tower::ServiceExt;

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
                    let req: SupervisorRequest = match serde_json::from_str(line.trim_end()) {
                        Ok(r) => r,
                        Err(_) => return,
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

    fn app_with<F>(responder: F) -> (Router, tempfile::TempDir)
    where
        F: Fn(SupervisorRequest) -> SupervisorResponse + Send + Sync + 'static,
    {
        let (tmp, path) = spawn_fake_supervisor(responder);
        let core = Arc::new(RuntimeCore::new(
            crate::supervisor_client::SupervisorClient::new(path),
        ));
        (router(core), tmp)
    }

    fn attest_request(workspace_id: &str, nonce_b64: &str) -> Request<Body> {
        let body = serde_json::json!({ "nonce": nonce_b64 }).to_string();
        Request::builder()
            .method("POST")
            .uri(format!("/v1/workspaces/{workspace_id}/attestation"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    /// Happy path: REST returns the versioned public software envelope.
    #[tokio::test]
    async fn attestation_happy_path_200_with_evidence() {
        let nonce_bytes = vec![0xaau8; 16];
        let nonce_b64 = BASE64.encode(&nonce_bytes);
        let fake_evidence = Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws-1".into(),
            measurement: Measurement([0xbbu8; 32]),
            nonce: nonce_bytes.clone(),
            issued_at: 1_700_000_042,
            report_data: b"test-report".to_vec(),
            proof: Proof::Software {
                signature: [0u8; 64],
                signer_pubkey: [1u8; 32],
            },
        };
        let expected = fake_evidence.clone();
        let (app, _tmp) = app_with(move |req| match req {
            SupervisorRequest::GetAttestationEvidence(r) => {
                assert_eq!(r.workspace_id, "ws-1");
                assert_eq!(r.nonce, nonce_bytes);
                SupervisorResponse::AttestationEvidenceIssued {
                    evidence: expected.clone(),
                }
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("unexpected req: {other:?}"),
            },
        });
        let resp = app
            .oneshot(attest_request("ws-1", &nonce_b64))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["provider"], serde_json::json!("software"));
        assert_eq!(json["workspace_id"], "ws-1");
        assert_eq!(json["workspace_measurement"], BASE64.encode([0xbbu8; 32]));
        assert_eq!(json["nonce"], nonce_b64);
        assert_eq!(json["proof"]["proof_type"], "software");
        assert!(json["proof"]["signature"].is_string());
    }

    #[tokio::test]
    async fn attestation_azure_response_preserves_all_typed_proof_fields() {
        let nonce_bytes = vec![0xaau8; 16];
        let nonce_b64 = BASE64.encode(&nonce_bytes);
        let fake_evidence = Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws-azure".into(),
            measurement: Measurement([0xbbu8; 32]),
            nonce: nonce_bytes.clone(),
            issued_at: 1_700_000_043,
            report_data: vec![0xcc],
            proof: Proof::SevSnpAzure {
                report: vec![1],
                vcek_cert_chain: vec![2],
                var_data: vec![3],
                ak_pub_tpm2b: vec![4],
                quote_msg: vec![5],
                quote_sig: vec![6],
            },
        };
        let expected = fake_evidence.clone();
        let (app, _tmp) = app_with(move |_| SupervisorResponse::AttestationEvidenceIssued {
            evidence: expected.clone(),
        });

        let resp = app
            .oneshot(attest_request("ws-azure", &nonce_b64))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["provider"], "sev_snp_azure");
        assert_eq!(json["proof"]["proof_type"], "sev_snp_azure");
        assert_eq!(json["proof"]["report"], BASE64.encode([1]));
        assert_eq!(json["proof"]["vcek_cert_chain"], BASE64.encode([2]));
        assert_eq!(json["proof"]["var_data"], BASE64.encode([3]));
        assert_eq!(json["proof"]["ak_pub_tpm2b"], BASE64.encode([4]));
        assert_eq!(json["proof"]["quote_msg"], BASE64.encode([5]));
        assert_eq!(json["proof"]["quote_sig"], BASE64.encode([6]));
    }

    #[tokio::test]
    async fn attestation_rejects_malformed_supervisor_evidence() {
        let request_nonce = BASE64.encode([0xaau8; 16]);
        let malformed = Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws-malformed".into(),
            measurement: Measurement([0xbbu8; 32]),
            nonce: vec![0xcc; 15],
            issued_at: 1_700_000_044,
            report_data: vec![0xdd],
            proof: Proof::Software {
                signature: [0xee; 64],
                signer_pubkey: [0xff; 32],
            },
        };
        let (app, _tmp) = app_with(move |_| SupervisorResponse::AttestationEvidenceIssued {
            evidence: malformed.clone(),
        });

        let resp = app
            .oneshot(attest_request("ws-malformed", &request_nonce))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Unknown workspace → supervisor returns `WorkspaceNotFound` → 404.
    #[tokio::test]
    async fn attestation_unknown_workspace_returns_404() {
        let nonce_b64 = BASE64.encode([0xaau8; 16]);
        let (app, _tmp) = app_with(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message: "workspace not found".into(),
        });
        let resp = app
            .oneshot(attest_request("ghost", &nonce_b64))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Replay (supervisor returns `AttestationReplay`) → 409 CONFLICT.
    #[tokio::test]
    async fn attestation_replay_returns_409() {
        let nonce_b64 = BASE64.encode([0xaau8; 16]);
        let (app, _tmp) = app_with(|_| SupervisorResponse::Error {
            kind: SupervisorErrorKind::AttestationReplay,
            message: "nonce already used".into(),
        });
        let resp = app
            .oneshot(attest_request("ws-1", &nonce_b64))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// Invalid base64 nonce → 400.
    #[tokio::test]
    async fn attestation_invalid_base64_nonce_returns_400() {
        let (app, _tmp) = app_with(|_| panic!("supervisor must not be called"));
        let resp = app
            .oneshot(attest_request("ws-1", "not-valid-base64!!!"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

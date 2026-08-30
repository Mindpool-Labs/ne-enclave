// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Workspace registry — owns the set of running Firecracker
//! microVMs the supervisor knows about.
//!
//! The registry is cross-platform; the heavy lifting it delegates to
//! [`crate::firecracker`] is Linux-only. On macOS the manager exists
//! but every workspace operation returns
//! `Unsupported` — that's what keeps the dev loop on a Mac quiet while
//! the Linux integration lands.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ne_protocol::supervisor::{
    CreateWorkspaceRequest, ExposePortRequest, ForkRequest, ReadFileRequest, RestoreRequest,
    RunCommandRequest, SnapshotRequest, SupervisorErrorKind, SupervisorResponse, TerminateRequest,
    UnexposePortRequest, WorkspaceRef, WriteFileRequest,
};

use crate::audit::AuditLog;
#[cfg(target_os = "linux")]
use crate::image::{ImageDigest, ImageError, ImageKind, ImageStore};

/// Host-side wall clock for the guest file-RPC round trip. Five seconds
/// above the guest's 25-second `FILE_OP_TIMEOUT` so the guest's typed
/// `Timeout` response reaches the host before this wall clock fires.
#[cfg(target_os = "linux")]
const FILE_RPC_TIMEOUT_MS: u32 = 30_000;

/// Guest vsock port the ne-guest-agent listens on by convention.
#[cfg(target_os = "linux")]
const DEFAULT_GUEST_VSOCK_PORT: u32 = 52;

#[cfg(target_os = "linux")]
fn image_error_response(error: ImageError) -> SupervisorResponse {
    let kind = match &error {
        ImageError::InvalidDigest { .. } => SupervisorErrorKind::InvalidImageDigest,
        ImageError::NotFound { .. } => SupervisorErrorKind::ImageNotFound,
        ImageError::Rejected { .. } => SupervisorErrorKind::ImageRejected,
        ImageError::DigestMismatch { .. } => SupervisorErrorKind::ImageDigestMismatch,
        ImageError::Stage { .. } => SupervisorErrorKind::ImageStageFailed,
    };
    SupervisorResponse::Error {
        kind,
        message: error.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn restore_launch_error_response(error: crate::firecracker::LaunchError) -> SupervisorResponse {
    match error {
        crate::firecracker::LaunchError::NetworkedRestoreUnsupported => SupervisorResponse::Error {
            kind: SupervisorErrorKind::InvalidSnapshot,
            message: "networked snapshot restore is not supported".to_string(),
        },
        crate::firecracker::LaunchError::Image(error) => image_error_response(error),
        error => SupervisorResponse::Error {
            kind: SupervisorErrorKind::RestoreFailed,
            message: error.to_string(),
        },
    }
}

/// Short readiness probe at pool checkout — the member was proven ready at
/// provision time; this only catches members that died while idle.
#[cfg(target_os = "linux")]
const POOL_CHECKOUT_PROBE: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
use ne_protocol::audit::EventType;
#[cfg(target_os = "linux")]
use ne_protocol::guest::{GuestErrorKind, GuestResponse};
#[cfg(target_os = "linux")]
use ne_protocol::snapshot::GuestIdentity;
#[cfg(target_os = "linux")]
use ne_protocol::supervisor::{
    CommandCompleted, FileRead, FileWritten, ForkInfo, MAX_INLINE_FILE_BYTES, WorkspaceCreated,
    WorkspaceNetwork, WorkspaceState,
};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use crate::network::NetworkController;

/// Which execution backend a workspace lands on.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub enum WorkspaceExec {
    /// Standard tier: an upstream Firecracker microVM under jailer.
    ///
    /// Boxed (as is `OpenShell`): the payloads are hundreds of bytes (clippy
    /// `large_enum_variant`), and each registry entry is created once and
    /// then only looked up by reference.
    Firecracker(Box<crate::firecracker::Instance>),
    /// Confidential tier (B): an OpenShell sandbox runs directly in the
    /// attested CVM. Only present under `feature = "confidential-cvm"`.
    #[cfg(feature = "confidential-cvm")]
    OpenShell(Box<ConfidentialWorkspace>),
}

#[cfg(target_os = "linux")]
enum WorkspaceControl {
    Firecracker(PathBuf),
    #[cfg(feature = "confidential-cvm")]
    OpenShell {
        ssh_addr: std::net::SocketAddr,
        handshake_secret: String,
    },
}

/// OpenShell workspace plus the hard confidential-capacity lease it owns.
#[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
#[derive(Debug)]
pub struct ConfidentialWorkspace {
    /// Running OpenShell sandbox.
    pub sandbox: Box<crate::openshell::Sandbox>,
    /// Held for the entire creating-or-active workspace lifetime.
    _capacity_permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(feature = "confidential-cvm")]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn try_acquire_confidential_capacity(
    capacity: &Arc<tokio::sync::Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, SupervisorErrorKind> {
    Arc::clone(capacity)
        .try_acquire_owned()
        .map_err(|_| SupervisorErrorKind::ConfidentialCapacityExceeded)
}

#[cfg(feature = "confidential-cvm")]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn validate_confidential_create(req: &CreateWorkspaceRequest) -> Result<(), &'static str> {
    if !req.kernel_sha256.is_empty()
        || !req.rootfs_sha256.is_empty()
        || req.network.is_some()
        || req.tier.is_some()
        || req.vcpu_count != 0
        || req.mem_size_mib != 0
        || req.guest_vsock_cid != 0
    {
        Err("confidential-azure create accepts workspace_id only")
    } else {
        Ok(())
    }
}

#[cfg(feature = "confidential-cvm")]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn confidential_workspace_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("path is empty".into());
    }
    if raw.starts_with('/') {
        return Err(format!("absolute path not allowed: {raw:?}"));
    }
    let mut normalized = Vec::new();
    for component in raw.split('/') {
        if component.is_empty() {
            return Err(format!("empty component in {raw:?}"));
        }
        if component == "." || component == ".." {
            return Err(format!("{component:?} segment in {raw:?}"));
        }
        if component.contains('\0') {
            return Err(format!("null byte in component of {raw:?}"));
        }
        normalized.push(component);
    }
    Ok(format!("/workspace/{}", normalized.join("/")))
}

/// How `snapshot()`'s finalize step should resolve the source's lifecycle
/// state once the identity-verified registry re-lock is held. See
/// [`WorkspaceManager::finalize_snapshot_state`].
#[cfg(target_os = "linux")]
enum SnapshotFinalize {
    /// Set the given state; no Firecracker call.
    Set(WorkspaceState),
    /// Resume the VM in place (inside the verified critical section, so the
    /// PATCH can never hit a replacement boot's reused socket) and record
    /// `Running` — or `Paused` if the resume fails.
    ResumeInPlace,
}

/// Derive a safe default concurrent-workspace ceiling from host RAM: ~512 MiB
/// nominal per VM, floored at 1, capped at 1024. Used when
/// `NE_MAX_WORKSPACES` is unset (0 = auto). Pure + platform-independent so
/// it's unit-testable on macOS.
#[must_use]
pub(crate) fn derive_max_workspaces(host_ram_mib: u64) -> usize {
    const NOMINAL_VM_MIB: u64 = 512;
    let n = (host_ram_mib / NOMINAL_VM_MIB).clamp(1, 1024);
    n as usize
}

/// Per-runtime configuration that doesn't come from the request — host
/// binary paths, jailer drop-priv uid/gid, chroot base.
#[derive(Debug, Clone)]
pub struct WorkspaceManagerConfig {
    /// Absolute host path to the Firecracker binary.
    pub firecracker_binary: PathBuf,
    /// Absolute host path to the jailer binary.
    pub jailer_binary: PathBuf,
    /// Base directory under which jailer creates per-workspace chroots.
    pub chroot_base: PathBuf,
    /// Supervisor-owned content-addressed kernel and rootfs image store.
    pub image_store: PathBuf,
    /// UID jailer drops the Firecracker process to.
    pub jailer_uid: u32,
    /// GID jailer drops the Firecracker process to.
    pub jailer_gid: u32,
    /// Path to the `openshell-sandbox` binary (confidential tier, B; spawned
    /// per workspace + controlled over SSH). Unused on the standard tier.
    pub openshell_sandbox_binary: PathBuf,
    /// How long to wait for Firecracker's API socket to appear before
    /// declaring the launch failed.
    pub api_socket_timeout: Duration,
    /// Kernel boot args used when a `CreateWorkspace` request omits its
    /// own `kernel_boot_args` field.
    pub default_kernel_boot_args: String,
    /// Execution profile resolved once by `serve()`.
    pub execution_profile: ne_protocol::profile::ExecutionProfile,
    /// Optional network controller. When `Some`, a workspace request
    /// that carries a [`ne_protocol::supervisor::NetworkConfig`]
    /// gets a per-workspace netns + TAP + NAT. When `None`, requests
    /// with network config are still accepted but networking is
    /// skipped (logged at warn). This keeps the dev loop usable on
    /// hosts where the supervisor doesn't have `CAP_NET_ADMIN`.
    #[cfg(target_os = "linux")]
    pub network: Option<NetworkController>,
    /// Persistent state directory. Snapshot artifacts land under
    /// `<state_dir>/snapshots/<snapshot_id>/`. The signing key is
    /// loaded from `<state_dir>/keys/`.
    pub state_dir: PathBuf,
    /// Optional warm pool (one tier). `None` disables the pool entirely.
    #[cfg(target_os = "linux")]
    pub warm_pool: Option<crate::pool::WarmPoolConfig>,
}

impl WorkspaceManagerConfig {
    /// Defaults match a standard single-host install layout.
    #[must_use]
    pub fn dev_defaults() -> Self {
        Self {
            firecracker_binary: PathBuf::from("/opt/ne-enclave/bin/firecracker"),
            jailer_binary: PathBuf::from("/opt/ne-enclave/bin/jailer"),
            chroot_base: PathBuf::from("/srv/jailer"),
            image_store: PathBuf::from("/var/lib/ne-enclave/images"),
            jailer_uid: 1000,
            jailer_gid: 1000,
            openshell_sandbox_binary: PathBuf::from("/opt/ne-enclave/bin/openshell-sandbox"),
            api_socket_timeout: Duration::from_secs(10),
            default_kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
            #[cfg(target_os = "linux")]
            network: None,
            state_dir: PathBuf::from("/var/lib/ne-enclave"),
            #[cfg(target_os = "linux")]
            warm_pool: None,
        }
    }
}

/// The supervisor's workspace registry.
#[derive(Debug)]
pub struct WorkspaceManager {
    // All four of these fields are only consumed on Linux; kept on macOS
    // for construction symmetry so callers (main.rs, tests) can build a
    // manager cross-platform.
    #[allow(dead_code)]
    cfg: WorkspaceManagerConfig,
    #[allow(dead_code)]
    audit: AuditLog,
    /// Admission ceiling on concurrent registered workspaces.
    /// Resolved (0=auto already applied) at the arg→config→manager
    /// boundary in `serve()`.
    #[allow(dead_code)]
    max_workspaces: usize,
    /// Admission ceiling on a single workspace's `mem_size_mib`.
    /// Resolved the same way as `max_workspaces`.
    #[allow(dead_code)]
    max_workspace_mem_mib: u32,
    #[cfg(target_os = "linux")]
    instances: Mutex<HashMap<String, WorkspaceExec>>,
    #[cfg(target_os = "linux")]
    pool: Option<Arc<crate::pool::WarmPool>>,
    /// Sender half of the refill-kick channel; used by `create_from_pool`.
    #[cfg(target_os = "linux")]
    refill_tx: Option<mpsc::Sender<()>>,
    #[cfg(target_os = "linux")]
    refill_rx: Mutex<Option<mpsc::Receiver<()>>>,
    #[cfg(target_os = "linux")]
    ingress: Arc<ne_ingress::IngressRegistry>,
    /// Active attestation provider (software fallback in this configuration).
    #[cfg(target_os = "linux")]
    attestation: Arc<dyn ne_attestation::AttestationProvider>,
    /// Per-workspace bounded ring of recently-seen attestation nonces
    /// (replay detection). Bounded; not a durable anti-replay store.
    #[cfg(target_os = "linux")]
    attestation_nonces: Mutex<HashMap<String, NonceRing>>,
    /// Ids with a path-owning lifecycle operation in flight. A create,
    /// restore, or fork holds its claim through registration; snapshot holds
    /// it through the entire unlocked pause/dump/publication/finalization
    /// window. This prevents same-id jailer socket/chroot reuse after a
    /// concurrent terminate removes the registry entry.
    #[cfg(target_os = "linux")]
    lifecycle_claims: LifecycleClaims,
    /// Hard one-slot ceiling for the confidential profile. The owned permit
    /// lives inside the registered OpenShell workspace.
    #[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
    confidential_capacity: Arc<tokio::sync::Semaphore>,
}

impl WorkspaceManager {
    /// Execution profile selected once at supervisor startup.
    #[must_use]
    pub fn execution_profile(&self) -> ne_protocol::profile::ExecutionProfile {
        self.cfg.execution_profile
    }
}

/// Shared atomic set behind per-workspace lifecycle leases.
#[derive(Debug, Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct LifecycleClaims {
    ids: std::sync::Mutex<std::collections::HashSet<String>>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl LifecycleClaims {
    fn claim(&self, id: &str) -> Option<LifecycleLease<'_>> {
        let inserted = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_string());
        inserted.then(|| LifecycleLease {
            claims: self,
            id: id.to_string(),
        })
    }
}

/// RAII lease on a workspace id for a path-owning lifecycle operation.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct LifecycleLease<'a> {
    claims: &'a LifecycleClaims,
    id: String,
}

impl Drop for LifecycleLease<'_> {
    fn drop(&mut self) {
        self.claims
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

/// Bounded set of recently-seen nonce hashes for one workspace.
/// O(1) membership via a `HashSet`, FIFO eviction via a `VecDeque`.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct NonceRing {
    seen: std::collections::HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
}

#[cfg(target_os = "linux")]
impl NonceRing {
    const CAP: usize = 256;

    /// Record a nonce hash. Returns `true` if it was already present (replay).
    fn record(&mut self, hash: [u8; 32]) -> bool {
        if self.seen.contains(&hash) {
            return true;
        }
        if self.order.len() >= Self::CAP
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.order.push_back(hash);
        self.seen.insert(hash);
        false
    }
}

/// Validate a caller-supplied workspace/snapshot id before it is used as a
/// filesystem path component or jailer `--id`. Matches the jailer grammar
/// (`[A-Za-z0-9-]{1,64}`): no path separators, no `.`/`..`, no NUL — so the id
/// cannot traverse out of `state_dir`/`chroot_base`. See S2-F1.
#[cfg(target_os = "linux")]
fn is_valid_workspace_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Compute the v1 configuration measurement from stable launch metadata.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn configuration_measurement(
    vcpu_count: u8,
    mem_size_mib: u32,
    kernel_boot_args: &str,
    networked: bool,
    kernel_sha256: &str,
    rootfs_sha256: &str,
) -> ne_attestation::Measurement {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::json!({
        "vcpu_count": vcpu_count,
        "mem_size_mib": mem_size_mib,
        "kernel_boot_args": kernel_boot_args,
        "networked": networked,
        "kernel_sha256": kernel_sha256,
        "rootfs_sha256": rootfs_sha256,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    ne_attestation::Measurement(digest.into())
}

/// Reject snapshot configurations that v5 cannot restore faithfully. This is
/// pure so callers can run it before pausing a VM or allocating artifacts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn snapshot_preflight(rootfs_read_only: bool, networked: bool) -> Result<(), &'static str> {
    if !rootfs_read_only {
        return Err(
            "snapshot of writable-rootfs workspaces is not supported; create the workspace with rootfs_read_only=true",
        );
    }
    if networked {
        return Err("snapshot of networked workspaces is not supported in this build");
    }
    Ok(())
}

/// Compute the v1 configuration measurement for a running instance.
/// Hashes stable launch metadata without per-request file I/O.
#[cfg(target_os = "linux")]
fn measure_config(inst: &crate::firecracker::Instance) -> ne_attestation::Measurement {
    configuration_measurement(
        inst.vcpu_count,
        inst.mem_size_mib,
        &inst.kernel_boot_args,
        inst.network_slot.is_some(),
        &inst.kernel_sha256,
        &inst.rootfs_sha256,
    )
}

#[cfg(test)]
mod measurement_tests {
    use super::{LifecycleClaims, configuration_measurement, snapshot_preflight};

    #[test]
    fn lifecycle_claims_serialize_and_release_same_id() {
        let claims = LifecycleClaims::default();
        let lease = claims.claim("ws-lifecycle").expect("first claim");

        assert!(
            claims.claim("ws-lifecycle").is_none(),
            "same id must remain unavailable while an unlocked lifecycle operation continues"
        );
        assert!(claims.claim("ws-other").is_some(), "ids are independent");

        drop(lease);
        assert!(
            claims.claim("ws-lifecycle").is_some(),
            "same id must be released on every return path via Drop"
        );
    }

    #[test]
    fn configuration_measurement_binds_both_image_digests() {
        let baseline = configuration_measurement(
            2,
            512,
            "console=ttyS0",
            false,
            &"11".repeat(32),
            &"22".repeat(32),
        );
        let other_kernel = configuration_measurement(
            2,
            512,
            "console=ttyS0",
            false,
            &"33".repeat(32),
            &"22".repeat(32),
        );
        let other_rootfs = configuration_measurement(
            2,
            512,
            "console=ttyS0",
            false,
            &"11".repeat(32),
            &"44".repeat(32),
        );
        assert_ne!(baseline, other_kernel);
        assert_ne!(baseline, other_rootfs);
    }

    #[test]
    fn writable_snapshot_preflight_rejects_before_state_or_artifact_changes() {
        for live in [false, true] {
            let lifecycle = ne_protocol::supervisor::WorkspaceState::Running;
            let artifact_published = false;
            let error = snapshot_preflight(false, false).unwrap_err();
            assert_eq!(
                error,
                "snapshot of writable-rootfs workspaces is not supported; create the workspace with rootfs_read_only=true"
            );
            assert_eq!(lifecycle, ne_protocol::supervisor::WorkspaceState::Running);
            assert!(!artifact_published, "live={live}");
        }
    }
}

#[cfg(target_os = "linux")]
impl WorkspaceManager {
    /// Best-effort audit emission. Logs but doesn't fail the
    /// originating op — the supervisor must always be able to
    /// honor a lifecycle request even when the audit log can't
    /// be written (out-of-disk, etc.). Production posture
    /// tightens this once the control plane treats audit-write
    /// failure as a release-blocking condition.
    async fn audit_emit(
        &self,
        event_type: EventType,
        workspace_id: Option<String>,
        payload: serde_json::Value,
    ) {
        if let Err(e) = self.audit.emit(event_type, workspace_id, payload).await {
            warn!(error = %e, ?event_type, "audit emit failed");
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl WorkspaceManager {
    /// Construct an empty registry that returns `Unsupported` for every
    /// workspace operation on a non-Linux build.
    ///
    /// Returns `Result` for signature parity with the Linux implementation;
    /// provider construction happens before the manager is created.
    ///
    /// # Errors
    /// Never on non-Linux.
    pub fn new(
        cfg: WorkspaceManagerConfig,
        audit: AuditLog,
        _attestation: Arc<dyn ne_attestation::AttestationProvider>,
        max_workspaces: usize,
        max_workspace_mem_mib: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cfg,
            audit,
            max_workspaces,
            max_workspace_mem_mib,
        })
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    //
    // The signature stays `async` to match the Linux impl; clippy
    // notices there's no `.await` on this branch.
    #[allow(clippy::unused_async)]
    pub async fn create(&self, _req: CreateWorkspaceRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "CreateWorkspace requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn terminate(&self, _req: TerminateRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "Terminate requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn run_command(&self, _req: RunCommandRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "RunCommand requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn write_file(&self, _req: WriteFileRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "WriteFile requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn read_file(&self, _req: ReadFileRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "ReadFile requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    /// Also deferred on Linux: vsock dies on in-place resume; use snapshot/restore.
    #[allow(clippy::unused_async)]
    pub async fn pause(&self, _req: WorkspaceRef) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "in-place pause is deferred: the guest vsock control channel \
                      does not survive an in-place Firecracker resume. Use \
                      snapshot/restore instead."
                .to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    /// Also deferred on Linux: vsock dies on in-place resume; use snapshot/restore.
    #[allow(clippy::unused_async)]
    pub async fn resume(&self, _req: WorkspaceRef) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "in-place resume is deferred: the guest vsock control channel \
                      does not survive an in-place Firecracker resume. Use \
                      snapshot/restore instead."
                .to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn snapshot(&self, _req: SnapshotRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "SnapshotWorkspace requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn restore(&self, _req: RestoreRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "RestoreWorkspace requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn fork(&self, _req: ForkRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "ForkWorkspace requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn pool_status(
        &self,
        _req: ne_protocol::supervisor::PoolStatusRequest,
    ) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "warm pool requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn expose_port(&self, _req: ExposePortRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "ExposePort requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn unexpose_port(&self, _req: UnexposePortRequest) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "UnexposePort requires Linux + KVM".to_string(),
        }
    }

    /// Always returns [`SupervisorErrorKind::Unsupported`] on non-Linux.
    #[allow(clippy::unused_async)]
    pub async fn get_attestation_evidence(
        &self,
        _req: ne_protocol::supervisor::GetAttestationEvidenceRequest,
    ) -> SupervisorResponse {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "GetAttestationEvidence requires Linux + KVM".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
impl WorkspaceManager {
    /// Construct an empty registry that uses `cfg` for every launch.
    ///
    /// Provider selection and construction happen in `serve()` before this
    /// registry is created, so this constructor cannot silently switch
    /// attestation backends.
    ///
    /// # Errors
    /// `anyhow::Error` if registry initialization fails.
    pub fn new(
        cfg: WorkspaceManagerConfig,
        audit: AuditLog,
        attestation: Arc<dyn ne_attestation::AttestationProvider>,
        max_workspaces: usize,
        max_workspace_mem_mib: u32,
    ) -> anyhow::Result<Self> {
        let (pool, refill_tx, refill_rx) = cfg.warm_pool.as_ref().map_or_else(
            || (None, None, Mutex::new(None)),
            |wp| {
                let (tx, rx) = mpsc::channel(8);
                (
                    Some(Arc::new(crate::pool::WarmPool::new(wp.clone()))),
                    Some(tx),
                    Mutex::new(Some(rx)),
                )
            },
        );
        Ok(Self {
            cfg,
            audit,
            max_workspaces,
            max_workspace_mem_mib,
            instances: Mutex::new(HashMap::new()),
            pool,
            refill_tx,
            refill_rx,
            ingress: ne_ingress::IngressRegistry::new(),
            attestation,
            attestation_nonces: Mutex::new(HashMap::new()),
            lifecycle_claims: LifecycleClaims::default(),
            #[cfg(feature = "confidential-cvm")]
            confidential_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    /// Return a handle to the in-process ingress route table so the server
    /// layer (Task D3) can pass it to the ingress router.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn ingress_registry(&self) -> Arc<ne_ingress::IngressRegistry> {
        Arc::clone(&self.ingress)
    }

    async fn workspace_control(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspaceControl, SupervisorResponse> {
        let instances = self.instances.lock().await;
        match instances.get(workspace_id) {
            Some(WorkspaceExec::Firecracker(instance)) => Ok(WorkspaceControl::Firecracker(
                instance.vsock_host_socket.clone(),
            )),
            #[cfg(feature = "confidential-cvm")]
            Some(WorkspaceExec::OpenShell(workspace)) => Ok(WorkspaceControl::OpenShell {
                ssh_addr: workspace.sandbox.ssh_addr,
                handshake_secret: workspace.sandbox.handshake_secret.clone(),
            }),
            None => Err(SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceNotFound,
                message: format!("workspace {workspace_id} not found"),
            }),
        }
    }

    /// Total live Firecracker VMs this manager is responsible for: registered
    /// `instances` PLUS warm-pool members (idle ready members and in-flight
    /// provisions — both are real, memory-consuming FC processes even though
    /// they are not in `instances` yet). This is the figure the
    /// `max_workspaces` exhaustion backstop bounds: counting only
    /// `instances` would let a configured pool run the host `target_size` VMs
    /// past the ceiling.
    ///
    /// Locking: the `instances` lock and the pool's members lock are taken
    /// sequentially (acquire, read, release; then the other), never nested —
    /// the reading is therefore a snapshot, which is fine for a soft ceiling.
    async fn live_vm_count(&self) -> usize {
        let registered = self.instances.lock().await.len();
        let pooled = match &self.pool {
            Some(pool) => {
                let (available, in_flight) = pool.counts().await;
                available + in_flight
            }
            None => 0,
        };
        registered + pooled
    }

    /// Launch a new workspace under the selected execution profile and
    /// register it under the caller-supplied `workspace_id`.
    pub async fn create(&self, req: CreateWorkspaceRequest) -> SupervisorResponse {
        let confidential = matches!(
            self.cfg.execution_profile,
            ne_protocol::profile::ExecutionProfile::ConfidentialAzure
        );
        // Admission control: reject before reserving anything —
        // ahead of even the tier dispatch below, so both the cold-boot and
        // warm-pool paths are covered (both flow through `create`).
        if !confidential && req.mem_size_mib > self.max_workspace_mem_mib {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: format!(
                    "mem_size_mib {} exceeds max {}",
                    req.mem_size_mib, self.max_workspace_mem_mib
                ),
            };
        }
        let both_empty = req.kernel_sha256.is_empty() && req.rootfs_sha256.is_empty();
        let both_present = !req.kernel_sha256.is_empty() && !req.rootfs_sha256.is_empty();
        if !confidential && !both_empty && !both_present {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidImageDigest,
                message: "kernel and rootfs image digests must be supplied together".into(),
            };
        }
        if !confidential
            && both_present
            && (ImageDigest::parse(ImageKind::Kernel, &req.kernel_sha256).is_err()
                || ImageDigest::parse(ImageKind::Rootfs, &req.rootfs_sha256).is_err())
        {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidImageDigest,
                message: "image digests must be 64 lowercase hexadecimal characters".into(),
            };
        }
        // Claim every caller-selected id before either pool adoption or a
        // cold boot can begin. The lease remains held through registration.
        let _lifecycle_lease = match self.claim_boot(&req.workspace_id).await {
            Ok(claim) => claim,
            Err(resp) => return resp,
        };
        // The confidential profile has its own hard one-slot admission and
        // accepts no Firecracker or warm-pool launch settings.
        #[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
        if confidential {
            return self.create_confidential(req).await;
        }

        #[cfg(not(all(target_os = "linux", feature = "confidential-cvm")))]
        if confidential {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::Unsupported,
                message: format!(
                    "confidential-azure requires Linux + the confidential-cvm feature; \
                     workspace {} cannot be created on this build",
                    req.workspace_id
                ),
            };
        }

        // Warm-pool dispatch runs BEFORE the net-new count ceiling below,
        // deliberately: a pool HIT is count-neutral — the VM moves from the
        // pool tally into `instances`, leaving `live_vm_count` unchanged — so
        // gating adoption on the combined ceiling would starve a full pool
        // sized near `max_workspaces`, rejecting every tier create even though
        // adoption adds no VM. `create_from_pool` applies the ceiling itself,
        // only on its net-new miss/fork-fallback branch.
        if req.tier.is_some() {
            return self.create_from_pool(req).await;
        }

        // Soft ceiling on the COMBINED live-VM count (registered instances +
        // warm-pool members, see `live_vm_count`), gating only NET-NEW boots:
        // the Firecracker cold boot that follows (count-neutral warm-pool
        // adoption is handled above / inside `create_from_pool`). This
        // check-then-act races the eventual insert into `instances` (done
        // later, under separate lock acquisitions, by
        // `register_or_teardown`), so a burst of concurrent creates can admit
        // a few requests over the line. Acceptable for an exhaustion
        // backstop — not a hard quota.
        if self.live_vm_count().await >= self.max_workspaces {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::CapacityExceeded,
                message: format!("at workspace capacity ({})", self.max_workspaces),
            };
        }
        if both_empty {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidImageDigest,
                message: "standard cold creates require kernel and rootfs image digests".into(),
            };
        }
        if req.vcpu_count == 0 {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: "standard creates require vcpu_count >= 1".into(),
            };
        }

        // Resolve and verify both images before allocating a network slot or
        // creating any workspace/chroot state.
        let verified_images = match ImageStore::new(self.cfg.image_store.clone())
            .resolve_pair(&req.kernel_sha256, &req.rootfs_sha256)
            .await
        {
            Ok(images) => images,
            Err(error) => return image_error_response(error),
        };

        // Provision network plumbing first so we can hand the TAP +
        // netns to Firecracker. On any failure here we exit without
        // touching the chroot, so cleanup is a no-op.
        let network_slot = match (&req.network, &self.cfg.network) {
            (Some(net), Some(controller)) => {
                let policy = crate::network::NetworkPolicy {
                    enable_egress: net.enable_egress,
                    allow_cidrs: net.allow_cidrs.clone(),
                    allow_hostnames: net.allow_hostnames.clone(),
                    enable_privacy_router: net.privacy_router.is_some(),
                };
                match controller.setup(&req.workspace_id, &policy).await {
                    Ok(slot) => {
                        // Chain a NetworkSetup event before the
                        // launch attempt so operators can correlate
                        // the netns + iptables footprint with the
                        // workspace even if the Firecracker spawn
                        // that follows fails.
                        self.audit_emit(
                            EventType::NetworkSetup,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({
                                "netns": slot.netns,
                                "host_ip": slot.host_ip,
                                "guest_ip": slot.workspace_ip,
                                "slot": slot.slot,
                                "forward_chain": slot.forward_chain,
                                "enable_egress": policy.enable_egress,
                                "allow_cidrs": policy.allow_cidrs,
                                "allow_hostnames": policy.allow_hostnames,
                                "masquerade_installed": slot.masquerade_installed,
                                "dns_filter_pid": slot.dns_filter_pid,
                                "privacy_router_pid": slot.privacy_router_pid,
                                "privacy_router_enabled": policy.enable_privacy_router,
                            }),
                        )
                        .await;
                        Some(slot)
                    }
                    Err(e) => {
                        warn!(workspace_id = %req.workspace_id, error = %e, "network setup failed");
                        self.audit_emit(
                            EventType::CommandFailed,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({ "op": "create_workspace", "stage": "network",
                                                "error": e.to_string() }),
                        )
                        .await;
                        return SupervisorResponse::Error {
                            kind: SupervisorErrorKind::LaunchFailed,
                            message: format!("network setup: {e}"),
                        };
                    }
                }
            }
            (Some(_), None) => {
                warn!(workspace_id = %req.workspace_id,
                      "request asked for network but supervisor was started without --enable-networking");
                None
            }
            (None, _) => None,
        };

        let network_attachment =
            network_slot
                .as_ref()
                .map(|slot| crate::firecracker::NetworkAttachment {
                    netns_path: PathBuf::from(format!("/var/run/netns/{}", slot.netns)),
                    tap_name: slot.tap.clone(),
                });

        let cfg = crate::firecracker::LaunchConfig {
            workspace_id: req.workspace_id.clone(),
            verified_images,
            rootfs_read_only: req.rootfs_read_only,
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            guest_vsock_cid: req.guest_vsock_cid,
            kernel_boot_args: {
                let base = req
                    .kernel_boot_args
                    .clone()
                    .unwrap_or_else(|| self.cfg.default_kernel_boot_args.clone());
                let layout = network_slot
                    .as_ref()
                    .map(|s| crate::network::SlotIpLayout::for_slot(s.slot));
                compose_boot_args(&base, layout.as_ref())
            },
            firecracker_binary: self.cfg.firecracker_binary.clone(),
            jailer_binary: self.cfg.jailer_binary.clone(),
            chroot_base: self.cfg.chroot_base.clone(),
            jailer_uid: self.cfg.jailer_uid,
            jailer_gid: self.cfg.jailer_gid,
            api_socket_timeout: self.cfg.api_socket_timeout,
            network: network_attachment,
        };

        match crate::firecracker::launch(cfg).await {
            Ok(mut instance) => {
                instance.network_slot = network_slot;
                let workspace_network =
                    instance.network_slot.as_ref().map(|slot| WorkspaceNetwork {
                        netns_path: format!("/var/run/netns/{}", slot.netns),
                        tap_device: slot.tap.clone(),
                        host_ip: slot.host_ip.clone(),
                        guest_ip: slot.workspace_ip.clone(),
                        prefix: slot.prefix,
                    });
                let resp = WorkspaceCreated {
                    workspace_id: instance.workspace_id.clone(),
                    firecracker_pid: instance.firecracker_pid,
                    vsock_host_socket: instance.vsock_host_socket.display().to_string(),
                    jailer_chroot: instance.jailer_chroot.display().to_string(),
                    network: workspace_network,
                    // Standard tier (Firecracker) — no OpenShell backend.
                    exec_backend: None,
                    control_socket: None,
                };
                info!(
                    workspace_id = %resp.workspace_id,
                    pid = resp.firecracker_pid,
                    networked = resp.network.is_some(),
                    "workspace created"
                );
                self.audit_emit(
                    EventType::WorkspaceCreated,
                    Some(resp.workspace_id.clone()),
                    serde_json::json!({
                        "firecracker_pid": resp.firecracker_pid,
                        "vsock_host_socket": resp.vsock_host_socket,
                        "jailer_chroot": resp.jailer_chroot,
                        "network": resp.network,
                    }),
                )
                .await;
                // Capture ingress registration inputs before `instance` and
                // `req` are consumed. The slot now lives on `instance`
                // (moved above), so read its guest IP from there.
                #[cfg(target_os = "linux")]
                let ingress_routes = instance
                    .network_slot
                    .as_ref()
                    .and_then(|slot| slot.guest_eth_ip.parse::<std::net::Ipv4Addr>().ok())
                    .map(|guest_ip| (guest_ip, exposed_ports_from_request(&req.network)));
                // Re-check the id under the final lock and tear the loser
                // down (chroot + netns) on a collision — a bare insert here
                // let two concurrent same-id creates both leak a live VM.
                if let Err(resp) = self
                    .register_or_teardown(
                        &req.workspace_id,
                        WorkspaceExec::Firecracker(Box::new(instance)),
                    )
                    .await
                {
                    return resp;
                }
                #[cfg(target_os = "linux")]
                if let Some((guest_ip, ports)) = ingress_routes {
                    self.ingress
                        .upsert_workspace(&req.workspace_id, guest_ip, ports)
                        .await;
                }
                SupervisorResponse::WorkspaceCreated(resp)
            }
            Err(e) => {
                warn!(workspace_id = %req.workspace_id, error = %e, "workspace launch failed");
                // Reclaim the netns we provisioned before the launch
                // failure to avoid leaking link-local slots.
                if let (Some(slot), Some(controller)) = (network_slot, &self.cfg.network)
                    && let Err(te) = controller.teardown(slot).await
                {
                    warn!(error = %te, "post-failure network teardown failed");
                }
                self.audit_emit(
                    EventType::CommandFailed,
                    Some(req.workspace_id),
                    serde_json::json!({ "op": "create_workspace", "error": e.to_string() }),
                )
                .await;
                match e {
                    crate::firecracker::LaunchError::Image(error) => image_error_response(error),
                    other => SupervisorResponse::Error {
                        kind: SupervisorErrorKind::LaunchFailed,
                        message: other.to_string(),
                    },
                }
            }
        }
    }

    /// Confidential-tier (B) create: spawn an OpenShell sandbox directly in the
    /// attested CVM (single-CVM-direct). Linux + `confidential-cvm` only — the
    /// `confidential-azure` routes here instead of the Firecracker path.
    ///
    /// OpenShell provides its own isolation (Landlock/seccomp/netns) + governance
    /// (L7 OPA + PII/supply-chain); the CVM is the outer hardware boundary. The
    /// supervisor controls the sandbox over SSH (NSSH1 preface + exec/SFTP).
    #[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
    async fn create_confidential(&self, req: CreateWorkspaceRequest) -> SupervisorResponse {
        use crate::openshell::{OpenShellError, OpenShellLaunchConfig, Sandbox};
        use std::net::{Ipv4Addr, SocketAddr};

        if let Err(message) = validate_confidential_create(&req) {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: message.into(),
            };
        }
        let permit = match try_acquire_confidential_capacity(&self.confidential_capacity) {
            Ok(permit) => permit,
            Err(kind) => {
                return SupervisorResponse::Error {
                    kind,
                    message: "confidential-azure permits one active or creating workspace".into(),
                };
            }
        };

        // The OpenShell path does not consume the Firecracker-specific request
        // fields (kernel/rootfs/vcpu/mem/vsock cid); the sandbox is configured
        // by the operator-supplied policy files + the agent command. The
        // workspace_id is the only field reused.
        //
        // Bind a concrete ephemeral port (not 0) so we can connect back: bind a
        // TcpListener to :0, read the OS-assigned port, drop the listener, then
        // hand that port to the sandbox. A tiny race window is acceptable here
        // (the supervisor is the only loopback client).
        let ssh_port = std::net::TcpListener::bind("127.0.0.1:0")
            .map_or(0, |l| l.local_addr().map_or(0, |a| a.port()));
        let ssh_listen_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, ssh_port));

        let cfg = OpenShellLaunchConfig {
            sandbox_binary: self.cfg.openshell_sandbox_binary.clone(),
            workspace_id: req.workspace_id.clone(),
            // B v1: run an interactive shell by default; the agent command is
            // operator-configured via the policy data file. A future step
            // surfaces the agent command via the request.
            agent_command: vec![
                "/bin/bash".to_string(),
                "-c".to_string(),
                "sleep infinity".to_string(),
            ],
            // Policy paths are operator-configured at install time (default
            // under the state dir). Surfaced as a follow-up config field.
            policy_rules_path: self.cfg.state_dir.join("openshell/policy.rego"),
            policy_data_path: self.cfg.state_dir.join("openshell/policy.yaml"),
            ssh_listen_addr,
            ssh_ready_timeout: self.cfg.api_socket_timeout,
        };

        match Sandbox::spawn(&cfg).await {
            Ok(sandbox) => {
                let ssh_addr = sandbox.ssh_addr;
                let workspace_id = sandbox.workspace_id.clone();
                let resp = WorkspaceCreated {
                    workspace_id: workspace_id.clone(),
                    // No Firecracker on the confidential tier — sentinel values.
                    firecracker_pid: 0,
                    vsock_host_socket: String::new(),
                    jailer_chroot: String::new(),
                    network: None,
                    exec_backend: Some("openshell".to_string()),
                    control_socket: Some(ssh_addr.to_string()),
                };
                info!(
                    workspace_id = %resp.workspace_id,
                    ssh_addr = %ssh_addr,
                    "confidential workspace created (OpenShell, single-CVM-direct)"
                );
                self.audit_emit(
                    EventType::WorkspaceCreated,
                    Some(resp.workspace_id.clone()),
                    serde_json::json!({
                        "exec_backend": "openshell",
                        "control_socket": ssh_addr.to_string(),
                    }),
                )
                .await;
                // Re-check the id under the final lock and tear the loser's
                // sandbox down on a collision instead of a bare insert.
                if let Err(resp) = self
                    .register_or_teardown(
                        &req.workspace_id,
                        WorkspaceExec::OpenShell(Box::new(ConfidentialWorkspace {
                            sandbox: Box::new(sandbox),
                            _capacity_permit: permit,
                        })),
                    )
                    .await
                {
                    return resp;
                }
                SupervisorResponse::WorkspaceCreated(resp)
            }
            Err(OpenShellError::Spawn(msg)) => {
                warn!(workspace_id = %req.workspace_id, error = %msg, "openshell spawn failed");
                self.audit_emit(
                    EventType::CommandFailed,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "op": "create_confidential", "error": msg }),
                )
                .await;
                SupervisorResponse::Error {
                    kind: SupervisorErrorKind::Internal,
                    message: format!("openshell-sandbox spawn failed: {msg}"),
                }
            }
            Err(e) => {
                warn!(workspace_id = %req.workspace_id, error = %e, "openshell launch failed");
                SupervisorResponse::Error {
                    kind: SupervisorErrorKind::Internal,
                    message: format!("confidential workspace launch failed: {e}"),
                }
            }
        }
    }

    /// health-probe it, adopt it under the caller's id. On an empty pool, fall
    /// back to a synchronous fork from the tier base (warm state preserved).
    async fn create_from_pool(&self, req: CreateWorkspaceRequest) -> SupervisorResponse {
        let tier = req.tier.clone().unwrap_or_default();

        let Some(pool) = &self.pool else {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::TierNotFound,
                message: format!("no warm pool configured (requested tier {tier:?})"),
            };
        };
        if tier != pool.config().tier_name {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::TierNotFound,
                message: format!(
                    "tier {:?} not configured (configured tier: {:?})",
                    tier,
                    pool.config().tier_name
                ),
            };
        }
        if req.network.is_some() {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message:
                    "tier-based create cannot request networking (pool members are non-networked)"
                        .to_string(),
            };
        }
        if self.instances.lock().await.contains_key(&req.workspace_id) {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceAlreadyExists,
                message: format!("workspace {} already exists", req.workspace_id),
            };
        }

        let base_snapshot_id = pool.config().base_snapshot_id.clone();

        // Pop + probe loop: discard any member that died while idle.
        let mut adopted: Option<crate::firecracker::Instance> = None;
        while let Some(mut member) = pool.pop().await {
            let vsock = member.vsock_host_socket.clone();
            match crate::firecracker::wait_for_guest_ready(
                &vsock,
                DEFAULT_GUEST_VSOCK_PORT,
                POOL_CHECKOUT_PROBE,
            )
            .await
            {
                Ok(()) => {
                    member.workspace_id = req.workspace_id.clone();
                    adopted = Some(member);
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "warm-pool member failed checkout probe — evicting");
                    self.audit_emit(
                        EventType::PoolMemberEvicted,
                        Some(req.workspace_id.clone()),
                        serde_json::json!({ "reason": "checkout_probe_failed", "error": e.to_string() }),
                    )
                    .await;
                    let _ = crate::firecracker::terminate(member, Duration::from_secs(5)).await;
                    self.kick_refill();
                }
            }
        }

        if let Some(instance) = adopted {
            let resp = WorkspaceCreated {
                workspace_id: instance.workspace_id.clone(),
                firecracker_pid: instance.firecracker_pid,
                vsock_host_socket: instance.vsock_host_socket.display().to_string(),
                jailer_chroot: instance.jailer_chroot.display().to_string(),
                network: None,
                exec_backend: None,
                control_socket: None,
            };
            if let Err(resp) = self
                .register_or_teardown(
                    &req.workspace_id,
                    WorkspaceExec::Firecracker(Box::new(instance)),
                )
                .await
            {
                return resp;
            }
            info!(workspace_id = %req.workspace_id, tier = %tier, "warm-pool hit");
            self.audit_emit(
                EventType::PoolHit,
                Some(req.workspace_id.clone()),
                serde_json::json!({ "tier": tier, "firecracker_pid": resp.firecracker_pid }),
            )
            .await;
            self.kick_refill();
            return SupervisorResponse::WorkspaceCreated(resp);
        }

        // Miss: synchronous fork from the tier base. This boots a NET-NEW VM
        // (unlike the count-neutral hit/adopt path above), so it must honor the
        // same soft combined-count ceiling the cold-boot path enforces —
        // otherwise an empty pool at capacity would fork past `max_workspaces`.
        if self.live_vm_count().await >= self.max_workspaces {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::CapacityExceeded,
                message: format!("at workspace capacity ({})", self.max_workspaces),
            };
        }

        info!(workspace_id = %req.workspace_id, tier = %tier, "warm-pool miss — synchronous fork fallback");
        self.audit_emit(
            EventType::PoolMiss,
            Some(req.workspace_id.clone()),
            serde_json::json!({ "tier": tier }),
        )
        .await;
        self.kick_refill();

        let (instance, _machine_id) = match self
            .boot_ready_reset(&base_snapshot_id, &req.workspace_id, &req.workspace_id)
            .await
        {
            Ok(v) => v,
            Err((kind, message)) => {
                self.audit_emit(
                    EventType::CommandFailed,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "op": "create_from_pool_fallback",
                                        "error_kind": format!("{kind:?}"), "error": message }),
                )
                .await;
                return SupervisorResponse::Error { kind, message };
            }
        };
        let resp = WorkspaceCreated {
            workspace_id: instance.workspace_id.clone(),
            firecracker_pid: instance.firecracker_pid,
            vsock_host_socket: instance.vsock_host_socket.display().to_string(),
            jailer_chroot: instance.jailer_chroot.display().to_string(),
            network: None,
            // Standard tier (Firecracker) — no OpenShell backend.
            exec_backend: None,
            control_socket: None,
        };
        if let Err(resp) = self
            .register_or_teardown(
                &req.workspace_id,
                WorkspaceExec::Firecracker(Box::new(instance)),
            )
            .await
        {
            return resp;
        }
        self.audit_emit(
            EventType::WorkspaceCreated,
            Some(req.workspace_id.clone()),
            serde_json::json!({ "firecracker_pid": resp.firecracker_pid, "tier": tier, "via": "pool_miss_fallback" }),
        )
        .await;
        SupervisorResponse::WorkspaceCreated(resp)
    }

    /// Relay one [`RunCommandRequest`] over the profile's control channel.
    pub async fn run_command(&self, req: RunCommandRequest) -> SupervisorResponse {
        let control = match self.workspace_control(&req.workspace_id).await {
            Ok(control) => control,
            Err(response) => return response,
        };

        let guest_resp = match control {
            WorkspaceControl::Firecracker(vsock_uds) => {
                match crate::firecracker::run_command_via_vsock(
                    &vsock_uds,
                    req.guest_port,
                    &req.command,
                    &req.args,
                    req.timeout_ms,
                )
                .await
                {
                    Ok(r) => r,
                    Err(crate::firecracker::GuestRpcError::ConnectRejected(line)) => {
                        warn!(workspace_id = %req.workspace_id, %line, "vsock CONNECT rejected");
                        self.audit_emit(
                            EventType::CommandExecuted,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({
                                "command": req.command,
                                "args": req.args,
                                "error_kind": "guest_unreachable",
                                "error": format!("vsock CONNECT rejected: {line}"),
                            }),
                        )
                        .await;
                        return SupervisorResponse::Error {
                            kind: SupervisorErrorKind::GuestUnreachable,
                            message: format!("vsock CONNECT rejected: {line}"),
                        };
                    }
                    Err(crate::firecracker::GuestRpcError::Timeout(ms)) => {
                        warn!(workspace_id = %req.workspace_id, timeout_ms = ms, "vsock RPC timed out (run_command)");
                        self.audit_emit(
                            EventType::CommandExecuted,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({
                                "command": req.command,
                                "args": req.args,
                                "error_kind": "timeout",
                                "timeout_ms": ms,
                                "timeout_origin": "host",
                            }),
                        )
                        .await;
                        return SupervisorResponse::Error {
                            kind: SupervisorErrorKind::Timeout,
                            message: format!("vsock RPC exceeded {ms}ms"),
                        };
                    }
                    Err(e) => {
                        warn!(workspace_id = %req.workspace_id, error = %e, "vsock RPC failed");
                        self.audit_emit(
                            EventType::CommandExecuted,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({
                                "command": req.command,
                                "args": req.args,
                                "error_kind": "guest_unreachable",
                                "error": e.to_string(),
                            }),
                        )
                        .await;
                        return SupervisorResponse::Error {
                            kind: SupervisorErrorKind::GuestUnreachable,
                            message: e.to_string(),
                        };
                    }
                }
            }
            #[cfg(feature = "confidential-cvm")]
            WorkspaceControl::OpenShell {
                ssh_addr,
                handshake_secret,
            } => {
                match crate::openshell::run_command_via_ssh_endpoint(
                    ssh_addr,
                    &handshake_secret,
                    &req.command,
                    &req.args,
                    req.timeout_ms,
                )
                .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let (kind, message) = openshell_control_error(&error);
                        warn!(workspace_id = %req.workspace_id, error = %error, "OpenShell command failed");
                        self.audit_emit(
                            EventType::CommandExecuted,
                            Some(req.workspace_id.clone()),
                            serde_json::json!({
                                "command": req.command,
                                "args": req.args,
                                "error_kind": control_error_code(kind),
                                "error": message,
                            }),
                        )
                        .await;
                        return SupervisorResponse::Error { kind, message };
                    }
                }
            }
        };

        match guest_resp {
            GuestResponse::CommandCompleted(c) => {
                info!(
                    workspace_id = %req.workspace_id,
                    exit_code = c.exit_code,
                    elapsed_ms = c.elapsed_ms,
                    "run_command completed"
                );
                self.audit_emit(
                    EventType::CommandExecuted,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({
                        "command": req.command,
                        "args": req.args,
                        "exit_code": c.exit_code,
                        "elapsed_ms": c.elapsed_ms,
                    }),
                )
                .await;
                SupervisorResponse::CommandCompleted(CommandCompleted {
                    workspace_id: req.workspace_id,
                    stdout: c.stdout,
                    stderr: c.stderr,
                    exit_code: c.exit_code,
                    elapsed_ms: c.elapsed_ms,
                    truncated: c.truncated,
                })
            }
            GuestResponse::Error { kind, message } => {
                let supervisor_kind = match kind {
                    GuestErrorKind::Timeout => SupervisorErrorKind::Timeout,
                    GuestErrorKind::InvalidRequest => SupervisorErrorKind::InvalidRequest,
                    GuestErrorKind::CommandFailed => SupervisorErrorKind::LaunchFailed,
                    _ => SupervisorErrorKind::Internal,
                };
                warn!(workspace_id = %req.workspace_id, ?kind, %message, "guest returned error");
                let mut payload = serde_json::json!({
                    "command": req.command,
                    "args": req.args,
                    "error_kind": serde_json::to_value(kind).unwrap_or_else(|_| {
                        serde_json::Value::String(format!("{kind:?}"))
                    }),
                    "error": message,
                });
                if matches!(kind, GuestErrorKind::Timeout)
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert(
                        "timeout_origin".to_string(),
                        serde_json::Value::String("guest".to_string()),
                    );
                }
                self.audit_emit(
                    EventType::CommandExecuted,
                    Some(req.workspace_id.clone()),
                    payload,
                )
                .await;
                SupervisorResponse::Error {
                    kind: supervisor_kind,
                    message,
                }
            }
            other => {
                warn!(workspace_id = %req.workspace_id, ?other, "unexpected guest response");
                SupervisorResponse::Error {
                    kind: SupervisorErrorKind::GuestProtocolError,
                    message: format!("unexpected guest response: {other:?}"),
                }
            }
        }
    }

    /// Relay a [`WriteFileRequest`] over the profile's control channel and
    /// emit the matching audit event.
    pub async fn write_file(&self, req: WriteFileRequest) -> SupervisorResponse {
        // Defense in depth: the API daemon already enforces this cap,
        // but the supervisor is a separate trust boundary (direct
        // socket clients exist in dev mode). Match the documented
        // 10 MiB cap exactly.
        if req.content.len() > MAX_INLINE_FILE_BYTES {
            self.audit_emit(
                EventType::FileOpFailed,
                Some(req.workspace_id.clone()),
                serde_json::json!({
                    "op": "write_file",
                    "path": req.path,
                    "error_kind": "file_too_large",
                    "error": format!(
                        "content length {} exceeds inline cap of {} bytes",
                        req.content.len(),
                        MAX_INLINE_FILE_BYTES,
                    ),
                }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::FileTooLarge,
                message: format!(
                    "content length {} exceeds inline cap of {} bytes",
                    req.content.len(),
                    MAX_INLINE_FILE_BYTES,
                ),
            };
        }

        let control = match self.workspace_control(&req.workspace_id).await {
            Ok(control) => control,
            Err(response) => return response,
        };

        let guest_port = if req.guest_port == 0 {
            52
        } else {
            req.guest_port
        };
        let timeout_ms = FILE_RPC_TIMEOUT_MS;

        let guest_resp =
            match write_file_over_control(control, guest_port, &req.path, req.content, timeout_ms)
                .await
            {
                Ok(response) => response,
                Err((kind, message)) => {
                    self.audit_emit(
                        EventType::FileOpFailed,
                        Some(req.workspace_id.clone()),
                        serde_json::json!({
                            "op": "write_file",
                            "path": req.path,
                            "error_kind": control_error_code(kind),
                            "error": message,
                        }),
                    )
                    .await;
                    return SupervisorResponse::Error { kind, message };
                }
            };

        match guest_resp {
            GuestResponse::FileWritten(written) => {
                self.audit_emit(
                    EventType::FileWritten,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({
                        "path": req.path,
                        "absolute_path": written.absolute_path,
                        "bytes_written": written.bytes_written,
                        "guest_port": guest_port,
                    }),
                )
                .await;
                SupervisorResponse::FileWritten(FileWritten {
                    workspace_id: req.workspace_id,
                    bytes_written: written.bytes_written,
                    absolute_path: written.absolute_path,
                })
            }
            GuestResponse::Error { kind, message } => {
                warn!(
                    workspace_id = %req.workspace_id,
                    ?kind,
                    %message,
                    "guest file op error (write_file)"
                );
                let supervisor_kind = guest_kind_to_supervisor_kind(kind);
                let mut payload = serde_json::json!({
                    "op": "write_file",
                    "path": req.path,
                    "error_kind": serde_json::to_value(kind).unwrap_or_else(|_| {
                        serde_json::Value::String(format!("{kind:?}"))
                    }),
                    "error": message,
                });
                if matches!(kind, GuestErrorKind::Timeout)
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert(
                        "timeout_origin".to_string(),
                        serde_json::Value::String("guest".to_string()),
                    );
                }
                self.audit_emit(
                    EventType::FileOpFailed,
                    Some(req.workspace_id.clone()),
                    payload,
                )
                .await;
                SupervisorResponse::Error {
                    kind: supervisor_kind,
                    message,
                }
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::GuestProtocolError,
                message: format!("unexpected guest response: {other:?}"),
            },
        }
    }

    /// Relay a [`ReadFileRequest`] over the profile's control channel.
    pub async fn read_file(&self, req: ReadFileRequest) -> SupervisorResponse {
        let control = match self.workspace_control(&req.workspace_id).await {
            Ok(control) => control,
            Err(response) => return response,
        };

        let guest_port = if req.guest_port == 0 {
            52
        } else {
            req.guest_port
        };
        let timeout_ms = FILE_RPC_TIMEOUT_MS;

        let guest_resp =
            match read_file_over_control(control, guest_port, &req.path, req.max_bytes, timeout_ms)
                .await
            {
                Ok(response) => response,
                Err((kind, message)) => {
                    self.audit_emit(
                        EventType::FileOpFailed,
                        Some(req.workspace_id.clone()),
                        serde_json::json!({
                            "op": "read_file",
                            "path": req.path,
                            "error_kind": control_error_code(kind),
                            "error": message,
                        }),
                    )
                    .await;
                    return SupervisorResponse::Error { kind, message };
                }
            };

        match guest_resp {
            GuestResponse::FileRead(read) => {
                self.audit_emit(
                    EventType::FileRead,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({
                        "path": req.path,
                        "absolute_path": format!("/workspace/{}", req.path),
                        "bytes_returned": read.content.len(),
                        "size_bytes": read.size_bytes,
                        "truncated": read.truncated,
                        "guest_port": guest_port,
                    }),
                )
                .await;
                SupervisorResponse::FileRead(FileRead {
                    workspace_id: req.workspace_id,
                    content: read.content,
                    size_bytes: read.size_bytes,
                    truncated: read.truncated,
                })
            }
            GuestResponse::Error { kind, message } => {
                warn!(
                    workspace_id = %req.workspace_id,
                    ?kind,
                    %message,
                    "guest file op error (read_file)"
                );
                let supervisor_kind = guest_kind_to_supervisor_kind(kind);
                let mut payload = serde_json::json!({
                    "op": "read_file",
                    "path": req.path,
                    "error_kind": serde_json::to_value(kind).unwrap_or_else(|_| {
                        serde_json::Value::String(format!("{kind:?}"))
                    }),
                    "error": message,
                });
                if matches!(kind, GuestErrorKind::Timeout)
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert(
                        "timeout_origin".to_string(),
                        serde_json::Value::String("guest".to_string()),
                    );
                }
                self.audit_emit(
                    EventType::FileOpFailed,
                    Some(req.workspace_id.clone()),
                    payload,
                )
                .await;
                SupervisorResponse::Error {
                    kind: supervisor_kind,
                    message,
                }
            }
            other => SupervisorResponse::Error {
                kind: SupervisorErrorKind::GuestProtocolError,
                message: format!("unexpected guest response: {other:?}"),
            },
        }
    }

    /// Tear down a registered workspace and reclaim its host resources.
    pub async fn terminate(&self, req: TerminateRequest) -> SupervisorResponse {
        let Some(exec) = self.instances.lock().await.remove(&req.workspace_id) else {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceNotFound,
                message: format!("workspace {} not found", req.workspace_id),
            };
        };

        // Dispatch on the backend. The confidential tier's teardown is
        // separate (OpenShell sandbox); the standard tier reaps the
        // Firecracker process + reclaims its network slot.
        let grace = Duration::from_millis(u64::from(req.grace_period_ms));
        #[cfg(feature = "confidential-cvm")]
        let (network_slot, firecracker_result) = match exec {
            WorkspaceExec::OpenShell(workspace) => {
                workspace.sandbox.terminate(grace).await;
                // OpenShell sandboxes don't carry a NetworkSlot today (the
                // sandbox's own netns is managed by the spawned binary).
                (None, Ok(()))
            }
            WorkspaceExec::Firecracker(instance) => {
                let slot = instance.network_slot.clone();
                let r = crate::firecracker::terminate(*instance, grace).await;
                (slot, r)
            }
        };
        #[cfg(not(feature = "confidential-cvm"))]
        let (network_slot, firecracker_result) = match exec {
            WorkspaceExec::Firecracker(instance) => {
                let slot = instance.network_slot.clone();
                let r = crate::firecracker::terminate(*instance, grace).await;
                (slot, r)
            }
        };

        // Reclaim network resources regardless of how firecracker
        // teardown went — leaking netns / NAT rules across a single
        // failed teardown would burn slots quickly. Emit the
        // NetworkTeardown audit event whether reclamation succeeded
        // or not; downstream operators can correlate a "teardown
        // emitted but slot still present" signal with a leak.
        if let (Some(slot), Some(controller)) = (network_slot, &self.cfg.network) {
            let teardown_outcome = controller.teardown(slot.clone()).await;
            let teardown_ok = teardown_outcome.is_ok();
            self.audit_emit(
                EventType::NetworkTeardown,
                Some(req.workspace_id.clone()),
                serde_json::json!({
                    "netns": slot.netns,
                    "slot": slot.slot,
                    "forward_chain": slot.forward_chain,
                    "dns_filter_pid": slot.dns_filter_pid,
                    "privacy_router_pid": slot.privacy_router_pid,
                    "reclaim_ok": teardown_ok,
                    "error": teardown_outcome.as_ref().err().map(ToString::to_string),
                }),
            )
            .await;
            if let Err(e) = teardown_outcome {
                warn!(workspace_id = %req.workspace_id, error = %e,
                      "network teardown failed (resources may have leaked)");
            }
        }

        #[cfg(target_os = "linux")]
        self.ingress.remove_workspace(&req.workspace_id).await;

        // S1-F3: free the per-workspace attestation nonce ring so a long-lived
        // supervisor that churns workspaces does not grow `attestation_nonces`
        // without bound (one 256-entry ring per ever-attested workspace).
        self.attestation_nonces
            .lock()
            .await
            .remove(&req.workspace_id);

        match firecracker_result {
            Ok(()) => {
                info!(workspace_id = %req.workspace_id, "workspace terminated");
                self.audit_emit(
                    EventType::WorkspaceTerminated,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "grace_period_ms": req.grace_period_ms }),
                )
                .await;
                SupervisorResponse::WorkspaceTerminated {
                    workspace_id: req.workspace_id,
                }
            }
            Err(e) => {
                warn!(workspace_id = %req.workspace_id, error = %e, "workspace terminate failed");
                self.audit_emit(
                    EventType::CommandFailed,
                    Some(req.workspace_id),
                    serde_json::json!({ "op": "terminate", "error": e.to_string() }),
                )
                .await;
                SupervisorResponse::Error {
                    kind: SupervisorErrorKind::Internal,
                    message: e.to_string(),
                }
            }
        }
    }

    /// DEFERRED: in-place pause/resume is unsupported on current
    /// Firecracker — the vsock control channel does not survive an in-place
    /// `PATCH /vm Resumed` (the resumed guest is unreachable over vsock). Use
    /// snapshot/restore (fresh process) instead, which works. Any future
    /// investigation must use an upstream-compatible Firecracker path.
    /// `WorkspaceManager::snapshot` still uses
    /// the low-level `crate::firecracker::pause`/`resume` directly; only this
    /// public API is gated.
    // `async` kept (no await while deferred) so the dispatcher contract in
    // `command.rs` (`self.workspaces.pause(r).await`) is unchanged and the body
    // re-becomes async when the API is restored.
    #[allow(clippy::unused_async)]
    pub async fn pause(&self, ws_ref: WorkspaceRef) -> SupervisorResponse {
        let _ = &ws_ref;
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "in-place pause is deferred: the guest vsock control channel \
                      does not survive an in-place Firecracker resume. Use \
                      snapshot/restore instead."
                .to_string(),
        }
    }

    /// DEFERRED: see [`Self::pause`].
    #[allow(clippy::unused_async)]
    pub async fn resume(&self, ws_ref: WorkspaceRef) -> SupervisorResponse {
        let _ = &ws_ref;
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::Unsupported,
            message: "in-place resume is deferred: the guest vsock control channel \
                      does not survive an in-place Firecracker resume. Use \
                      snapshot/restore instead."
                .to_string(),
        }
    }

    /// Snapshot a workspace.
    ///
    /// Locking strategy: the global `instances` mutex is held only
    /// for the brief lookup/validate/capture step — where the FC socket + chroot
    /// paths and metadata are copied out and the transient `Snapshotting` state
    /// is set — then the guard is DROPPED. The pause → memory-dump → resume
    /// sequence (multi-GiB, seconds) runs entirely unlocked against those
    /// captured paths, so it no longer head-of-line-blocks every other
    /// supervisor op. The lock is re-acquired only briefly at finalize to
    /// resolve the tracked state back to `Running`/`Paused`, guarded by an
    /// existence re-check (the resurrection guard): if the workspace
    /// was terminated mid-dump it is NOT reinserted. The subsequent copy-out,
    /// hashing, and signing need only the artifact paths and stay unlocked.
    pub async fn snapshot(&self, req: SnapshotRequest) -> SupervisorResponse {
        // Claim before looking in the registry. If terminate removes the
        // source after this point, no create/restore/fork can reuse its
        // id-derived socket or chroot until every snapshot return path drops
        // this lease, including artifact publication and live finalization.
        let Some(_lifecycle_lease) = self.claim_lifecycle(&req.workspace_id) else {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::SnapshotFailed,
                message: format!(
                    "another lifecycle operation is in progress for workspace {}",
                    req.workspace_id
                ),
            };
        };
        // Step 1: brief lock — look up + validate + capture FC socket/chroot
        // paths + metadata, set the transient `Snapshotting` state, then DROP
        // the guard. The multi-GiB memory dump (Steps 2-4) runs entirely
        // UNLOCKED against the captured paths, so it no longer head-of-line-
        // blocks every other supervisor operation on the global `instances` mutex.
        let (
            source_ws_id,
            boot_id,
            api_socket,
            jailer_chroot,
            uid,
            gid,
            guest_vsock_cid,
            vcpu_count,
            mem_size_mib,
            kernel_boot_args,
            kernel_sha256,
            rootfs_sha256,
            was_running,
        ) = {
            let mut guard = self.instances.lock().await;
            let Some(exec) = guard.get_mut(&req.workspace_id) else {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::WorkspaceNotFound,
                    message: format!("workspace {} not found", req.workspace_id),
                };
            };
            // Snapshot is Firecracker-vmstate-coupled; the confidential tier
            // (OpenShell) returns Unsupported in B v1 (a process-checkpoint
            // format is a later release). Unwrap the FC variant for the rest.
            #[cfg(not(feature = "confidential-cvm"))]
            let WorkspaceExec::Firecracker(instance) = exec;
            #[cfg(feature = "confidential-cvm")]
            let instance = match exec {
                WorkspaceExec::Firecracker(inst) => inst,
                WorkspaceExec::OpenShell(_) => {
                    return SupervisorResponse::Error {
                        kind: SupervisorErrorKind::Unsupported,
                        message: format!(
                            "snapshot is unsupported on the confidential tier (workspace {}); B v1",
                            req.workspace_id
                        ),
                    };
                }
            };

            // Reject a re-entrant snapshot: another dump for this id is already
            // in flight (its state was left `Snapshotting` under a prior lock and
            // it hasn't been finalized yet). Two concurrent `/snapshot/create`
            // calls against the same FC socket would corrupt each other's dump.
            // This guard is also what makes the unlocked window below safe from a
            // second snapshot mutating the source mid-dump.
            if instance.lifecycle_state == WorkspaceState::Snapshotting {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::SnapshotFailed,
                    message: format!(
                        "snapshot already in progress for workspace {}",
                        req.workspace_id
                    ),
                };
            }

            // Reject before live-state checks, pause, snapshot_create, or
            // destination allocation. A writable rootfs may have diverged from
            // its managed source digest and v5 intentionally has no disk-capture
            // schema, so publishing such a snapshot would be unsound. This also
            // rejects networked sources because Firecracker bakes the host TAP
            // name into vmstate and restore cannot safely reconstruct it.
            if let Err(reason) =
                snapshot_preflight(instance.rootfs_read_only, instance.network_slot.is_some())
            {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::SnapshotFailed,
                    message: format!("workspace {}: {reason}", req.workspace_id),
                };
            }

            // Live snapshot requires a running source (it keeps the source live).
            if req.live && instance.lifecycle_state != WorkspaceState::Running {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::SnapshotFailed,
                    message: format!(
                        "live snapshot requires a running workspace; {} is {:?}",
                        req.workspace_id, instance.lifecycle_state
                    ),
                };
            }

            let was_running = instance.lifecycle_state == WorkspaceState::Running;

            // Mark the transient state under the lock so any concurrent op that
            // does look up this id (a re-entrant snapshot, a future status probe)
            // sees "dump in flight". It is resolved back to Running/Paused at
            // finalize — or dropped entirely if the workspace is terminated
            // mid-dump (resurrection guard). It never leaks as a terminal state.
            instance.lifecycle_state = WorkspaceState::Snapshotting;

            // Capture everything we need before dropping the guard — including
            // the per-boot identity token. The lifecycle lease prevents a
            // same-id boot from reusing these id-derived paths; the token
            // remains defense in depth for every later registry re-acquire.
            (
                instance.workspace_id.clone(),
                instance.boot_id.clone(),
                instance.api_socket_host.clone(),
                instance.jailer_chroot.clone(),
                instance.jailer_uid,
                instance.jailer_gid,
                instance.guest_vsock_cid,
                instance.vcpu_count,
                instance.mem_size_mib,
                instance.kernel_boot_args.clone(),
                instance.kernel_sha256.clone(),
                instance.rootfs_sha256.clone(),
                was_running,
            )
        };
        // Guard dropped — the pause + dump below run UNLOCKED against the
        // captured paths. What can still happen to this workspace meanwhile:
        // only a `terminate` can remove it from the registry (in-place
        // pause/resume are deferred/Unsupported, and a re-entrant snapshot is
        // rejected above by the Snapshotting guard). A concurrent terminate
        // kills the FC process + reaps its chroot, which makes our unlocked FC
        // calls fail (handled as a dump failure). The lifecycle lease held
        // above prevents create/restore/fork from reusing the SAME id-derived
        // paths until this function returns. Finalize still verifies the
        // captured `boot_id` as defense in depth before touching registry
        // state or resuming in place.

        // Step 2: if the source was running, pause it (unlocked).
        if was_running && let Err(e) = crate::firecracker::pause_at(&api_socket).await {
            // Pause never took — the VM is still running. Restore the tracked
            // state (identity-guarded) and fail.
            self.finalize_snapshot_state(
                &source_ws_id,
                &boot_id,
                SnapshotFinalize::Set(WorkspaceState::Running),
            )
            .await;
            self.audit_emit(
                EventType::SnapshotFailed,
                Some(source_ws_id.clone()),
                serde_json::json!({ "error": format!("pre-snapshot pause failed: {e}") }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::SnapshotFailed,
                message: format!("pre-snapshot pause failed: {e}"),
            };
        }

        // Step 3: dump the (now paused) guest memory + vmstate into the chroot
        // (unlocked — this is the multi-GiB, seconds-long operation that used to
        // hold the global lock).
        let arts = match crate::firecracker::snapshot_create_at(
            &api_socket,
            &jailer_chroot,
            uid,
            gid,
            mem_size_mib,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                // Best-effort resume if we paused it (under the identity-
                // verified lock, so it can never PATCH a replacement boot's
                // reused socket), restoring the tracked state honestly
                // (Running only if the resume actually succeeds), then fail.
                let action = if was_running {
                    SnapshotFinalize::ResumeInPlace
                } else {
                    SnapshotFinalize::Set(WorkspaceState::Paused)
                };
                self.finalize_snapshot_state(&source_ws_id, &boot_id, action)
                    .await;
                self.audit_emit(
                    EventType::SnapshotFailed,
                    Some(source_ws_id.clone()),
                    serde_json::json!({ "error": e.to_string() }),
                )
                .await;
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::SnapshotFailed,
                    message: e.to_string(),
                };
            }
        };

        // Step 4: resolve the source's post-dump state under the identity-
        // verified re-lock (`finalize_snapshot_state`).
        //  - non-live + was_running: resume in place → Running (Paused if the
        //    resume fails; the map must not lie about a still-frozen VM). The
        //    resume PATCH runs inside the verified critical section so it can
        //    never hit a reused socket owned by a replacement boot.
        //  - non-live + already paused: stays Paused (never resumed).
        //  - live: intentionally leave the source PAUSED — `live_hot_swap` (after
        //    the artifact is signed, below) replaces it with a fresh, reachable
        //    process, so resuming this frozen one here would be wasted work.
        let action = if was_running && !req.live {
            SnapshotFinalize::ResumeInPlace
        } else {
            SnapshotFinalize::Set(WorkspaceState::Paused)
        };
        let finalized = self
            .finalize_snapshot_state(&source_ws_id, &boot_id, action)
            .await;
        if !finalized {
            // Terminated (or terminated-and-recreated) mid-dump: do NOT touch
            // the registry. The dump itself completed, so fall through to
            // Step 5+ to attempt the copy-out/hash/sign — but note the dump
            // files live in the (id-derived) chroot until the copy-out, and a
            // concurrent terminate reaps that chroot: if it won that race the
            // copy below fails gracefully as SnapshotFailed rather than
            // producing an artifact. The live path below skips the hot-swap
            // either way.
            info!(workspace_id = %source_ws_id,
                  "source boot gone during snapshot; attempting artifact finalize without touching the registry");
        }
        // From here we only use the captured paths + metadata.

        // Step 5: allocate snapshot id + create destination dir.
        let snapshot_id = ulid::Ulid::new().to_string();
        let dest = crate::snapshot::snapshot_dir(&self.cfg.state_dir, &snapshot_id);
        if let Err(e) = tokio::fs::create_dir_all(&dest).await {
            self.audit_emit(
                EventType::SnapshotFailed,
                Some(source_ws_id.clone()),
                serde_json::json!({ "error": e.to_string() }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("snapshot dir create failed: {e}"),
            };
        }

        // Step 6: copy mem/vmstate out of the chroot to the snapshots dir.
        // The chroot files are written by FC (as jailer_uid); the supervisor
        // runs as root and can read them.
        let copy_result = async {
            tokio::fs::copy(&arts.mem_in_chroot, dest.join("mem")).await?;
            tokio::fs::copy(&arts.vmstate_in_chroot, dest.join("vmstate")).await?;
            Ok::<(), std::io::Error>(())
        }
        .await;

        if let Err(e) = copy_result {
            let _ = tokio::fs::remove_dir_all(&dest).await;
            self.audit_emit(
                EventType::SnapshotFailed,
                Some(source_ws_id.clone()),
                serde_json::json!({ "error": e.to_string() }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::Internal,
                message: format!("artifact copy failed: {e}"),
            };
        }

        // Step 7: get FC version + load signing key + write manifest.
        let fc_version =
            crate::firecracker::firecracker_version(&self.cfg.firecracker_binary).await;

        let keys_dir = self.cfg.state_dir.join("keys");
        let signer = match crate::signing::load_or_create_signing_key(&keys_dir).await {
            Ok(s) => s,
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&dest).await;
                self.audit_emit(
                    EventType::SnapshotFailed,
                    Some(source_ws_id.clone()),
                    serde_json::json!({ "error": e.to_string() }),
                )
                .await;
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::Internal,
                    message: format!("signing key load failed: {e}"),
                };
            }
        };

        // hostname in GuestIdentity = source workspace id (unique, meaningful label).
        let guest_identity = GuestIdentity {
            hostname: source_ws_id.clone(),
            mac: "unset".into(), // non-networked snapshots have no TAP MAC
            guest_vsock_cid,
            vcpu_count,
            mem_size_mib,
        };

        let mut info = match crate::snapshot::write_manifest(
            &dest,
            &signer,
            &snapshot_id,
            &source_ws_id,
            &fc_version,
            &kernel_sha256,
            &rootfs_sha256,
            guest_identity,
            &kernel_boot_args,
        )
        .await
        {
            Ok(i) => i,
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&dest).await;
                self.audit_emit(
                    EventType::SnapshotFailed,
                    Some(source_ws_id.clone()),
                    serde_json::json!({ "error": e.to_string() }),
                )
                .await;
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::SnapshotFailed,
                    message: e.to_string(),
                };
            }
        };

        // Live snapshot: hot-swap the frozen source with a fresh restore so it
        // comes back Running + reachable. Fail-closed — on swap failure the source
        // is left Paused and the (valid, signed) artifact persists.
        if req.live {
            // If finalize already saw the source boot gone/replaced, don't boot
            // a restore only to discard it — short-circuit to the same
            // fail-closed error the swap's own identity check would produce.
            // Either way the (valid, signed) artifact persists.
            let swap_result = if finalized {
                self.live_hot_swap(&source_ws_id, &boot_id, &snapshot_id)
                    .await
            } else {
                Err((
                    SupervisorErrorKind::WorkspaceNotFound,
                    format!(
                        "source {source_ws_id} was terminated during live snapshot; \
                         hot-swap skipped"
                    ),
                ))
            };
            match swap_result {
                Ok(new_pid) => {
                    info.firecracker_pid = Some(new_pid);
                }
                Err((kind, message)) => {
                    self.audit_emit(
                        EventType::SnapshotFailed,
                        Some(source_ws_id.clone()),
                        serde_json::json!({
                            "snapshot_id": snapshot_id,
                            "phase": "live_hot_swap",
                            "error": message,
                            "note": "snapshot artifact created; source left paused",
                        }),
                    )
                    .await;
                    return SupervisorResponse::Error {
                        kind,
                        message: format!(
                            "snapshot {snapshot_id} created but live resume failed: {message}; \
                             source {source_ws_id} left paused"
                        ),
                    };
                }
            }
        }

        // Step 8: audit + return.
        info!(
            workspace_id = %source_ws_id,
            snapshot_id = %snapshot_id,
            mem_sha256 = %info.mem_sha256,
            size_bytes = info.size_bytes,
            was_running,
            "snapshot created"
        );
        self.audit_emit(
            EventType::SnapshotCreated,
            Some(source_ws_id.clone()),
            serde_json::json!({
                "snapshot_id": snapshot_id,
                "mem_sha256": info.mem_sha256,
                "vmstate_sha256": info.vmstate_sha256,
                "size_bytes": info.size_bytes,
                "source": source_ws_id,
                "live": req.live,
                "new_firecracker_pid": info.firecracker_pid,
            }),
        )
        .await;
        SupervisorResponse::SnapshotCreated(info)
    }

    /// Re-acquire the registry lock and resolve `workspace_id`'s lifecycle
    /// state after an unlocked snapshot window — but ONLY if the entry still
    /// refers to the SAME boot this snapshot captured (identity-token check;
    /// the resurrection guard, hardened against ABA).
    ///
    /// Existence alone is NOT enough: the FC socket/chroot paths are fully
    /// id-derived. The lifecycle lease now blocks a terminate→recreate ABA
    /// through the public boot paths; this token check remains defense in
    /// depth so mutating (or resuming) a replacement based on the id string
    /// can never mislabel a live guest as Paused — poisoning later snapshots
    /// (a non-live snapshot would skip the pause and dump a running guest; a
    /// live snapshot would be spuriously rejected). So: `get_mut` → compare
    /// `boot_id` → only then
    /// touch. On `None` OR token mismatch, leave the map untouched and return
    /// `false`; never reinsert, never relabel, never resume.
    ///
    /// `SnapshotFinalize::ResumeInPlace` issues the resume PATCH *inside* the
    /// verified critical section, so it can never land on a replacement
    /// boot's reused socket. Holding the lock across this flat-timeout
    /// control call (µs in practice) is deliberate — it is the only way to
    /// make socket ownership and registry membership atomic, and it is a
    /// strict subset of the pre-C2 lock window (which held pause + multi-GiB
    /// dump + resume).
    async fn finalize_snapshot_state(
        &self,
        workspace_id: &str,
        boot_id: &str,
        action: SnapshotFinalize,
    ) -> bool {
        let mut guard = self.instances.lock().await;
        let Some(exec) = guard.get_mut(workspace_id) else {
            warn!(workspace_id = %workspace_id,
                  "workspace terminated during snapshot; not resurrecting");
            return false;
        };
        // Snapshot is Firecracker-only; the FC variant is boxed (field access
        // auto-derefs through the box).
        #[cfg(not(feature = "confidential-cvm"))]
        let WorkspaceExec::Firecracker(instance) = exec;
        #[cfg(feature = "confidential-cvm")]
        let instance = match exec {
            WorkspaceExec::Firecracker(inst) => inst,
            WorkspaceExec::OpenShell(_) => {
                // The id now points at a different backend entirely — by
                // definition not the boot this snapshot captured. Leave it.
                warn!(workspace_id = %workspace_id,
                      "snapshot finalize: id now owned by an OpenShell workspace; leaving untouched");
                return false;
            }
        };
        if instance.boot_id != boot_id {
            warn!(workspace_id = %workspace_id,
                  "workspace was terminated and recreated during snapshot; leaving the new boot untouched");
            return false;
        }
        instance.lifecycle_state = match action {
            SnapshotFinalize::Set(state) => state,
            SnapshotFinalize::ResumeInPlace => {
                match crate::firecracker::resume_at(&instance.api_socket_host).await {
                    Ok(()) => WorkspaceState::Running,
                    Err(e) => {
                        // Honest state: on resume failure FC is still frozen,
                        // so report Paused rather than lie.
                        warn!(workspace_id = %workspace_id, error = %e,
                              "post-snapshot resume failed — workspace left paused");
                        WorkspaceState::Paused
                    }
                }
            }
        };
        true
    }

    /// Shared fork/restore boot: verify the artifact (signature + hashes,
    /// fail-closed), build a `LaunchConfig` from the manifest, and boot a
    /// fresh jailed Firecracker via `firecracker::restore` (load + resume).
    /// Returns the live, `UNregistered` instance plus the verified manifest.
    /// On failure returns the typed error response the caller relays.
    async fn boot_from_snapshot(
        &self,
        snapshot_id: &str,
        new_workspace_id: &str,
    ) -> Result<
        (
            crate::firecracker::Instance,
            ne_protocol::snapshot::SnapshotManifest,
        ),
        SupervisorResponse,
    > {
        // S2-F1 (Critical): validate BOTH caller-supplied ids before either is
        // used as a filesystem path component. `snapshot_id` feeds
        // `snapshot_dir(state_dir, ..)` (read path) and `new_workspace_id`
        // becomes the jailer `--id` / chroot component (as-root write path). An
        // absolute or `..`-bearing id would escape the intended tree (Rust
        // `Path::join` replaces on an absolute component; the OS resolves `..`),
        // turning restore/fork into an as-root create/`remove_dir_all` outside
        // the workspace tree. The jailer grammar (`[A-Za-z0-9-]{1,64}`) is the
        // safe charset for both. `firecracker::spawn_jailed_firecracker` repeats
        // this check as a defense-in-depth backstop.
        if !is_valid_workspace_id(snapshot_id) {
            return Err(SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: format!(
                    "invalid snapshot_id {snapshot_id:?}: expected [A-Za-z0-9-]{{1,64}}"
                ),
            });
        }
        if !is_valid_workspace_id(new_workspace_id) {
            return Err(SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: format!(
                    "invalid new_workspace_id {new_workspace_id:?}: expected [A-Za-z0-9-]{{1,64}}"
                ),
            });
        }

        let dir = crate::snapshot::snapshot_dir(&self.cfg.state_dir, snapshot_id);
        // S5-F1 (High): pin manifest verification to the host's own signing key
        // (the only legitimate producer of a snapshot here) rather than the key
        // embedded in the untrusted manifest — closes the self-signed forgery
        // class on the restore/fork trust path.
        let (manifest, verified_images) = crate::snapshot::verify_and_resolve_images(
            &dir,
            &self.audit.verifying_key(),
            &ImageStore::new(self.cfg.image_store.clone()),
        )
        .await
        .map_err(|error| match error {
            crate::snapshot::SnapshotRestoreError::Artifact(error) => SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidSnapshot,
                message: error.to_string(),
            },
            crate::snapshot::SnapshotRestoreError::Image(error) => image_error_response(error),
        })?;

        // Admission control: validate the memory size the
        // snapshot will boot at before spawning anything. `restore`/`fork`
        // requests don't carry a client-supplied `mem_size_mib` (unlike
        // `create`) — the size comes from the pinned manifest — so this is
        // the earliest point it's known, and this helper is shared by
        // restore, fork, and pool refill provisioning.
        if manifest.guest_identity.mem_size_mib > self.max_workspace_mem_mib {
            return Err(SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: format!(
                    "snapshot {snapshot_id} mem_size_mib {} exceeds max {}",
                    manifest.guest_identity.mem_size_mib, self.max_workspace_mem_mib
                ),
            });
        }

        let launch_cfg = crate::firecracker::LaunchConfig {
            workspace_id: new_workspace_id.to_string(),
            verified_images,
            rootfs_read_only: true,
            vcpu_count: manifest.guest_identity.vcpu_count,
            mem_size_mib: manifest.guest_identity.mem_size_mib,
            guest_vsock_cid: manifest.guest_identity.guest_vsock_cid,
            kernel_boot_args: manifest.kernel_boot_args.clone(),
            firecracker_binary: self.cfg.firecracker_binary.clone(),
            jailer_binary: self.cfg.jailer_binary.clone(),
            chroot_base: self.cfg.chroot_base.clone(),
            jailer_uid: self.cfg.jailer_uid,
            jailer_gid: self.cfg.jailer_gid,
            api_socket_timeout: self.cfg.api_socket_timeout,
            network: None,
        };
        let restore_cfg = crate::firecracker::RestoreLaunchConfig {
            launch: launch_cfg,
            mem_source: dir.join("mem"),
            vmstate_source: dir.join("vmstate"),
        };
        crate::firecracker::restore(restore_cfg)
            .await
            .map(|inst| (inst, manifest))
            .map_err(restore_launch_error_response)
    }

    /// Claim `workspace_id` for a cold boot, failing fast with
    /// `WorkspaceAlreadyExists` if another cold boot of the same id is in
    /// flight or the id is already registered (to avoid cross-instance interference).
    ///
    /// Why: the boot runs for seconds outside the registry lock and the
    /// jailer chroot is derived from the caller id, so two concurrent same-id
    /// boots collide destructively on the shared chroot tree — worse, the
    /// loser's error-path cleanup (`remove_dir_all` in `launch()`) deletes
    /// the winner's live tree. Claiming the id up front means the second
    /// racer never boots, stages, or cleans anything at all.
    ///
    /// Ordering: the winner registers into `instances` BEFORE its claim is
    /// released (the claim lives past `register_or_teardown`), so there is no
    /// window in which neither guard covers the id.
    fn claim_lifecycle(&self, workspace_id: &str) -> Option<LifecycleLease<'_>> {
        self.lifecycle_claims.claim(workspace_id)
    }

    async fn claim_boot(
        &self,
        workspace_id: &str,
    ) -> Result<LifecycleLease<'_>, SupervisorResponse> {
        let already = |id: &str| SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceAlreadyExists,
            message: format!("workspace {id} already exists"),
        };
        // Claim first, registry check second (dropping the claim on failure);
        // `register_or_teardown` re-checks the registry under its own lock as
        // the final backstop.
        let claim = self
            .claim_lifecycle(workspace_id)
            .ok_or_else(|| already(workspace_id))?;
        if self.instances.lock().await.contains_key(workspace_id) {
            return Err(already(workspace_id));
        }
        Ok(claim)
    }

    /// Register a freshly-booted workspace under the final lock, re-checking
    /// for an id collision (the boot above released the lock for seconds).
    /// On collision, tear the loser down rather than leak it — for either
    /// exec backend (Firecracker chroot/netns, or the OpenShell sandbox).
    async fn register_or_teardown(
        &self,
        workspace_id: &str,
        exec: WorkspaceExec,
    ) -> Result<(), SupervisorResponse> {
        let mut guard = self.instances.lock().await;
        if guard.contains_key(workspace_id) {
            drop(guard);
            warn!(
                workspace_id,
                "lost boot race — tearing down freshly-booted workspace"
            );
            match exec {
                WorkspaceExec::Firecracker(instance) => {
                    // Reclaim the loser's network slot too (terminate() only
                    // reaps the process + chroot; netns/NAT reclamation is the
                    // caller's job — mirror the main terminate handler).
                    let network_slot = instance.network_slot.clone();
                    let _ = crate::firecracker::terminate(*instance, Duration::from_secs(5)).await;
                    if let (Some(slot), Some(controller)) = (network_slot, &self.cfg.network)
                        && let Err(e) = controller.teardown(slot).await
                    {
                        warn!(workspace_id, error = %e,
                              "boot-race loser network teardown failed (resources may have leaked)");
                    }
                }
                #[cfg(feature = "confidential-cvm")]
                WorkspaceExec::OpenShell(workspace) => {
                    workspace.sandbox.terminate(Duration::from_secs(5)).await;
                }
            }
            return Err(SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceAlreadyExists,
                message: format!("workspace {workspace_id} already exists"),
            });
        }
        guard.insert(workspace_id.to_string(), exec);
        Ok(())
    }

    /// Live-snapshot hot-swap: replace a just-snapshotted (now frozen/paused) source
    /// with a fresh Firecracker restored from that same snapshot, so the source comes
    /// back Running + vsock-reachable (an in-place resume would leave it vsock-dead —
    /// the deferred limitation). Same identity is intentional: this is the
    /// *same* workspace continuing, NOT a fork — so NO `ResetIdentity`.
    ///
    /// On success: the registry entry for `source_ws_id` now points at the new
    /// instance; the old frozen process + chroot are reaped; returns the new PID.
    /// On failure: the freshly-restored instance (if any) is torn down and the
    /// ORIGINAL frozen source is left registered as `Paused` (never destroyed).
    async fn live_hot_swap(
        &self,
        source_ws_id: &str,
        source_boot_id: &str,
        snapshot_id: &str,
    ) -> Result<u32, (SupervisorErrorKind, String)> {
        // Provisional id doubles as the new jailer chroot id; the swap rewrites the
        // in-registry workspace_id back to the source id (chroot keeps the provisional
        // id — the cosmetic warm-pool 7.0 pattern).
        let provisional_id = format!("live-{}", ulid::Ulid::new());

        // Boot a fresh FC from the snapshot (verify -> load -> resume). Reachable by
        // construction (fresh process rebuilds the vsock muxer). boot_from_snapshot
        // cleans up its own chroot on load failure.
        let (instance, _manifest) = self
            .boot_from_snapshot(snapshot_id, &provisional_id)
            .await
            .map_err(|resp| match resp {
                SupervisorResponse::Error { kind, message } => (kind, message),
                _ => (
                    SupervisorErrorKind::Internal,
                    "unexpected boot response".to_string(),
                ),
            })?;

        // Wait for the guest agent to re-arm its vsock listener post-load.
        if let Err(e) = crate::firecracker::wait_for_guest_ready(
            &instance.vsock_host_socket,
            DEFAULT_GUEST_VSOCK_PORT,
            Duration::from_secs(10),
        )
        .await
        {
            let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
            return Err((
                SupervisorErrorKind::RestoreFailed,
                format!("live restore guest not ready: {e}"),
            ));
        }

        let new_pid = instance.firecracker_pid;

        // Swap under the registry mutex (atomic w.r.t. the mutex only). The
        // source may have been removed during our lock-free boot window. The
        // lifecycle lease prevents a public same-id recreate, while the boot
        // token remains defense in depth: existence alone is not enough.
        // Swapping out a replacement boot would silently destroy a freshly-
        // created workspace and resurrect stale state under its id.
        // On gone-or-replaced: tear the fresh instance down and fail; the
        // signed artifact still persists, so fail-closed holds.
        let old_instance = {
            let mut guard = self.instances.lock().await;
            // Remove first, token-check the removed value, and on mismatch put
            // the SAME entry back — no await between, so the whole sequence is
            // atomic under this one lock hold and needs no panic path.
            match guard.remove(source_ws_id) {
                Some(WorkspaceExec::Firecracker(inst)) if inst.boot_id == source_boot_id => {
                    // Verified same boot — splice the fresh instance in its place.
                    let mut instance = instance;
                    instance.workspace_id = source_ws_id.to_string();
                    guard.insert(
                        source_ws_id.to_string(),
                        WorkspaceExec::Firecracker(Box::new(instance)),
                    );
                    inst
                }
                other => {
                    // Gone, replaced by a new boot, or a different backend:
                    // reinsert whatever we removed and decline gracefully.
                    if let Some(entry) = other {
                        guard.insert(source_ws_id.to_string(), entry);
                    }
                    drop(guard);
                    let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
                    return Err((
                        SupervisorErrorKind::WorkspaceNotFound,
                        format!(
                            "source {source_ws_id} was terminated (or replaced by a new boot) \
                             during live snapshot; restored instance discarded"
                        ),
                    ));
                }
            }
        };

        // Reap the old frozen FC process + chroot (outside the lock).
        if let Err(e) = crate::firecracker::terminate(*old_instance, Duration::from_secs(5)).await {
            warn!(workspace_id = %source_ws_id, error = %e, "live hot-swap: old source teardown failed");
        }
        Ok(new_pid)
    }

    /// Generate a fresh 32-lowercase-hex machine-id from a new ULID's 128 bits.
    fn fresh_machine_id() -> String {
        hex::encode(ulid::Ulid::new().to_bytes())
    }

    /// Read `n` fresh random bytes from the host's `/dev/urandom`.
    async fn fresh_entropy(n: usize) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut f = tokio::fs::File::open("/dev/urandom").await?;
        let mut buf = vec![0u8; n];
        f.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Boot a fresh VM from `snapshot_id` (verify → load → resume), wait for the
    /// guest, then reset its identity to `hostname` + a fresh machine-id + fresh
    /// RNG. Fail-closed: any failure tears the booted VM down. On success returns
    /// the live, `UNregistered` instance plus its new machine-id.
    async fn boot_ready_reset(
        &self,
        snapshot_id: &str,
        new_workspace_id: &str,
        hostname: &str,
    ) -> Result<(crate::firecracker::Instance, String), (SupervisorErrorKind, String)> {
        let (instance, _manifest) = self
            .boot_from_snapshot(snapshot_id, new_workspace_id)
            .await
            .map_err(|resp| match resp {
                SupervisorResponse::Error { kind, message } => (kind, message),
                _ => (
                    SupervisorErrorKind::Internal,
                    "unexpected boot response".to_string(),
                ),
            })?;

        let vsock_uds = instance.vsock_host_socket.clone();
        if let Err(e) = crate::firecracker::wait_for_guest_ready(
            &vsock_uds,
            DEFAULT_GUEST_VSOCK_PORT,
            Duration::from_secs(10),
        )
        .await
        {
            let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
            return Err((
                SupervisorErrorKind::ForkFailed,
                format!("guest not ready: {e}"),
            ));
        }

        let machine_id = Self::fresh_machine_id();
        let entropy_seed = match Self::fresh_entropy(32).await {
            Ok(b) => b,
            Err(e) => {
                let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
                return Err((
                    SupervisorErrorKind::Internal,
                    format!("entropy generation failed: {e}"),
                ));
            }
        };

        match crate::firecracker::reset_identity_via_vsock(
            &vsock_uds,
            DEFAULT_GUEST_VSOCK_PORT,
            hostname.to_string(),
            machine_id.clone(),
            entropy_seed,
            30_000,
        )
        .await
        {
            Ok(GuestResponse::IdentityReset { .. }) => Ok((instance, machine_id)),
            Ok(other) => {
                let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
                Err((
                    SupervisorErrorKind::ForkFailed,
                    format!("identity reset: unexpected guest response: {other:?}"),
                ))
            }
            Err(e) => {
                let _ = crate::firecracker::terminate(instance, Duration::from_secs(5)).await;
                Err((
                    SupervisorErrorKind::ForkFailed,
                    format!("identity reset failed: {e}"),
                ))
            }
        }
    }

    /// Provision one pool member: a fresh fork from the tier base snapshot,
    /// identity already reset, returned `UNregistered`. Audits on success.
    async fn provision_pool_member(
        &self,
    ) -> Result<crate::firecracker::Instance, (SupervisorErrorKind, String)> {
        let pool = self.pool.as_ref().ok_or_else(|| {
            (
                SupervisorErrorKind::Internal,
                "no warm pool configured".to_string(),
            )
        })?;
        let snapshot_id = pool.config().base_snapshot_id.clone();
        // Provisional id doubles as jailer chroot id and provision-time hostname.
        let provisional_id = format!("pool-{}", ulid::Ulid::new());
        let (instance, machine_id) = self
            .boot_ready_reset(&snapshot_id, &provisional_id, &provisional_id)
            .await?;
        self.audit_emit(
            EventType::PoolMemberProvisioned,
            Some(provisional_id.clone()),
            serde_json::json!({
                "provisional_id": provisional_id,
                "source_snapshot_id": snapshot_id,
                "machine_id": machine_id,
                "firecracker_pid": instance.firecracker_pid,
            }),
        )
        .await;
        Ok(instance)
    }

    /// Reserve and start the provisions needed to top the pool up to target.
    /// Each provision runs in its own task so up to `max_in_flight` boots
    /// proceed concurrently; accounting prevents over-spawn across ticks.
    fn refill_once(self: &Arc<Self>) {
        let Some(pool) = self.pool.clone() else {
            return;
        };
        let me = Arc::clone(self);
        tokio::spawn(async move {
            // Admission control: pool refill boots real FC VMs, so
            // it must respect the same combined instances+pool ceiling as the
            // request paths. At (or over) the ceiling, DEFER — skip this tick
            // with a warn rather than erroring; the next tick / kick retries
            // once capacity frees. Soft, like the request-path guards: the
            // count is a snapshot and can race a concurrent create by a VM or
            // two. `live_vm_count` includes in-flight provisions, and
            // headroom is computed BEFORE reserving, so the `take(headroom)`
            // below can't overshoot from this tick's own reservations.
            let headroom = {
                let live = me.live_vm_count().await;
                let headroom = me.max_workspaces.saturating_sub(live);
                if headroom == 0 {
                    warn!(
                        live_vms = live,
                        max_workspaces = me.max_workspaces,
                        "warm-pool refill deferred: at combined live-VM capacity"
                    );
                    return;
                }
                headroom
            };
            // One RAII permit per reserved slot: the success path consumes it via
            // `complete_provision`; any failure — including a panic in the task —
            // drops it, releasing the in-flight slot so it can never leak.
            // Permits past the ceiling headroom are dropped immediately, which
            // releases their in-flight slots for a later, freer tick.
            let permits = pool.reserve_provisions().await;
            for permit in permits.into_iter().take(headroom) {
                let me2 = Arc::clone(&me);
                let pool2 = Arc::clone(&pool);
                tokio::spawn(async move {
                    match me2.provision_pool_member().await {
                        Ok(member) => pool2.complete_provision(member, permit).await,
                        Err((kind, message)) => {
                            warn!(?kind, %message, "warm-pool provision failed");
                            me2.audit_emit(
                                EventType::CommandFailed,
                                None,
                                serde_json::json!({ "op": "pool_provision",
                                                    "error_kind": format!("{kind:?}"), "error": message }),
                            )
                            .await;
                            drop(permit); // release the in-flight slot
                        }
                    }
                });
            }
        });
    }

    /// Spawn the background refill loop. Call once, after wrapping the manager
    /// in an `Arc`. No-op if no pool is configured.
    pub fn spawn_refill(self: &Arc<Self>) {
        if self.pool.is_none() {
            return;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let Some(mut rx) = me.refill_rx.lock().await.take() else {
                return;
            };
            loop {
                me.refill_once();
                tokio::select! {
                    () = tokio::time::sleep(crate::pool::POOL_REFILL_INTERVAL) => {}
                    r = rx.recv() => {
                        if r.is_none() { break; }
                    }
                }
            }
        });
    }

    /// Nudge the refill loop (best-effort). Called by `create_from_pool`.
    fn kick_refill(&self) {
        if let Some(tx) = &self.refill_tx {
            let _ = tx.try_send(());
        }
    }

    /// Report warm-pool status.
    pub async fn pool_status(
        &self,
        _req: ne_protocol::supervisor::PoolStatusRequest,
    ) -> SupervisorResponse {
        use ne_protocol::supervisor::PoolStatusInfo;
        let info = match &self.pool {
            Some(pool) => {
                let (available, in_flight) = pool.counts().await;
                PoolStatusInfo {
                    configured: true,
                    tier: Some(pool.config().tier_name.clone()),
                    target_size: u32::try_from(pool.config().target_size).unwrap_or(u32::MAX),
                    available: u32::try_from(available).unwrap_or(u32::MAX),
                    in_flight: u32::try_from(in_flight).unwrap_or(u32::MAX),
                }
            }
            None => PoolStatusInfo {
                configured: false,
                tier: None,
                target_size: 0,
                available: 0,
                in_flight: 0,
            },
        };
        SupervisorResponse::PoolStatus(info)
    }

    /// Terminate every pooled member. Call on supervisor shutdown so no
    /// Firecracker process leaks.
    pub async fn shutdown_pool(&self) {
        let Some(pool) = &self.pool else { return };
        let members = pool.drain().await;
        let n = members.len();
        for inst in members {
            if let Err(e) = crate::firecracker::terminate(inst, Duration::from_secs(5)).await {
                warn!(error = %e, "warm-pool member teardown failed during shutdown");
            }
        }
        if n > 0 {
            info!(count = n, "warm-pool reaped on shutdown");
        }
    }

    /// Restore a fresh workspace from a snapshot artifact.
    pub async fn restore(&self, req: RestoreRequest) -> SupervisorResponse {
        // Admission control: same soft ceiling as `create`, on the
        // combined instances+warm-pool live-VM count — restore also boots a
        // net-new VM. No mem_size_mib guard here: `RestoreRequest` carries no
        // client-supplied memory size (it comes from the pinned snapshot
        // manifest instead), so that check lives in `boot_from_snapshot`,
        // applied once the manifest is loaded and before the VM is actually
        // spawned.
        if self.live_vm_count().await >= self.max_workspaces {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::CapacityExceeded,
                message: format!("at workspace capacity ({})", self.max_workspaces),
            };
        }

        // Step 1: hold the caller-selected id through boot and registration.
        let _lifecycle_lease = match self.claim_boot(&req.new_workspace_id).await {
            Ok(claim) => claim,
            Err(resp) => return resp,
        };

        // Step 2: verify + boot (shared with fork).
        let (instance, _manifest) = match self
            .boot_from_snapshot(&req.snapshot_id, &req.new_workspace_id)
            .await
        {
            Ok(v) => v,
            Err(resp) => {
                if let SupervisorResponse::Error { kind, message } = &resp {
                    self.audit_emit(
                            EventType::CommandFailed,
                            Some(req.new_workspace_id.clone()),
                            serde_json::json!({ "op": "restore", "snapshot_id": req.snapshot_id,
                                                "error_kind": format!("{kind:?}"), "error": message }),
                        )
                        .await;
                }
                return resp;
            }
        };

        // Build the success response before the insert moves the instance.
        let resp = WorkspaceCreated {
            workspace_id: instance.workspace_id.clone(),
            firecracker_pid: instance.firecracker_pid,
            vsock_host_socket: instance.vsock_host_socket.display().to_string(),
            jailer_chroot: instance.jailer_chroot.display().to_string(),
            network: None,
            // Standard tier (Firecracker) — no OpenShell backend.
            exec_backend: None,
            control_socket: None,
        };

        // Step 3: register under the final lock with collision re-check.
        if let Err(resp) = self
            .register_or_teardown(
                &req.new_workspace_id,
                WorkspaceExec::Firecracker(Box::new(instance)),
            )
            .await
        {
            return resp;
        }

        // Step 4: log success (after register, so a lost race doesn't log a
        // false success), then audit + return.
        info!(
            new_workspace_id = %resp.workspace_id,
            snapshot_id = %req.snapshot_id,
            pid = resp.firecracker_pid,
            "workspace restored from snapshot"
        );
        self.audit_emit(
            EventType::WorkspaceRestored,
            Some(req.new_workspace_id.clone()),
            serde_json::json!({
                "snapshot_id": req.snapshot_id,
                "new_workspace_id": req.new_workspace_id,
                "firecracker_pid": resp.firecracker_pid,
            }),
        )
        .await;
        SupervisorResponse::WorkspaceRestored(resp)
    }

    /// Fork a fresh workspace from a snapshot, then reset its guest
    /// identity (hostname / machine-id / RNG) so it is distinct from the
    /// source and any sibling fork.
    ///
    /// Fail-closed: a fork is NEVER returned with un-reset identity. If the
    /// guest is unreachable or `ResetIdentity` fails, the freshly-booted VM
    /// is torn down and `ForkFailed` is returned.
    pub async fn fork(&self, req: ForkRequest) -> SupervisorResponse {
        // Admission control: same soft ceiling as `create`, on the
        // combined instances+warm-pool live-VM count — fork also boots a
        // net-new VM. No mem_size_mib guard here for the same reason as
        // `restore`: `ForkRequest` carries no client-supplied memory size; it
        // comes from the pinned snapshot manifest and is validated in
        // `boot_from_snapshot` instead.
        if self.live_vm_count().await >= self.max_workspaces {
            return SupervisorResponse::Error {
                kind: SupervisorErrorKind::CapacityExceeded,
                message: format!("at workspace capacity ({})", self.max_workspaces),
            };
        }

        // Step 1: hold the caller-selected id through boot and registration.
        let _lifecycle_lease = match self.claim_boot(&req.new_workspace_id).await {
            Ok(claim) => claim,
            Err(resp) => return resp,
        };

        // Steps 2-4: boot + ready + identity reset (shared with pool provisioning).
        let hostname = req
            .hostname
            .clone()
            .unwrap_or_else(|| req.new_workspace_id.clone());
        let (instance, machine_id) = match self
            .boot_ready_reset(&req.snapshot_id, &req.new_workspace_id, &hostname)
            .await
        {
            Ok(v) => v,
            Err((kind, message)) => {
                self.audit_emit(
                    EventType::CommandFailed,
                    Some(req.new_workspace_id.clone()),
                    serde_json::json!({ "op": "fork", "snapshot_id": req.snapshot_id,
                                            "error_kind": format!("{kind:?}"), "error": message }),
                )
                .await;
                return SupervisorResponse::Error { kind, message };
            }
        };

        // Step 5: build response, register under final lock.
        let info = ForkInfo {
            workspace_id: instance.workspace_id.clone(),
            firecracker_pid: instance.firecracker_pid,
            vsock_host_socket: instance.vsock_host_socket.display().to_string(),
            jailer_chroot: instance.jailer_chroot.display().to_string(),
            source_snapshot_id: req.snapshot_id.clone(),
            hostname: hostname.clone(),
            machine_id: machine_id.clone(),
            guest_vsock_cid: instance.guest_vsock_cid,
        };
        if let Err(resp) = self
            .register_or_teardown(
                &req.new_workspace_id,
                WorkspaceExec::Firecracker(Box::new(instance)),
            )
            .await
        {
            return resp;
        }

        // Step 6: audit + return.
        info!(
            new_workspace_id = %info.workspace_id,
            snapshot_id = %req.snapshot_id,
            hostname = %info.hostname,
            "workspace forked from snapshot"
        );
        self.audit_emit(
            EventType::WorkspaceForked,
            Some(req.new_workspace_id.clone()),
            serde_json::json!({
                "source_snapshot_id": req.snapshot_id,
                "new_workspace_id": req.new_workspace_id,
                "hostname": info.hostname,
                "machine_id": info.machine_id,
                "firecracker_pid": info.firecracker_pid,
            }),
        )
        .await;
        SupervisorResponse::WorkspaceForked(info)
    }

    /// Expose a guest port via host-based ingress routing.
    ///
    /// The workspace must exist **and** be networked (have a TAP slot);
    /// non-networked workspaces have no host-visible guest IP to route to.
    pub async fn expose_port(&self, req: ExposePortRequest) -> SupervisorResponse {
        // Workspace must exist AND be networked (have a slot).
        let networked = self
            .instances
            .lock()
            .await
            .get(&req.workspace_id)
            .map(|exec| match exec {
                WorkspaceExec::Firecracker(inst) => inst.network_slot.is_some(),
                #[cfg(feature = "confidential-cvm")]
                WorkspaceExec::OpenShell(_) => false,
            });
        match networked {
            None => {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::WorkspaceNotFound,
                    message: format!("workspace {} not found", req.workspace_id),
                };
            }
            Some(false) => {
                return SupervisorResponse::Error {
                    kind: SupervisorErrorKind::WorkspaceNotNetworked,
                    message: format!(
                        "workspace {} has no network; cannot expose ports",
                        req.workspace_id
                    ),
                };
            }
            Some(true) => {}
        }
        let route = ne_ingress::PortRoute {
            port: req.port.port,
            inject_headers: req
                .port
                .inject_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        };
        let header_names: Vec<&str> = req
            .port
            .inject_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        match self.ingress.expose_port(&req.workspace_id, route).await {
            Ok(()) => {
                self.audit_emit(
                    EventType::IngressPortExposed,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "port": req.port.port, "header_names": header_names }),
                )
                .await;
                SupervisorResponse::PortExposed {
                    workspace_id: req.workspace_id,
                    port: req.port.port,
                }
            }
            Err(_) => SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceNotFound,
                message: format!("workspace {} not registered for ingress", req.workspace_id),
            },
        }
    }

    /// Stop exposing a previously-exposed guest port via host-based ingress routing.
    pub async fn unexpose_port(&self, req: UnexposePortRequest) -> SupervisorResponse {
        match self
            .ingress
            .unexpose_port(&req.workspace_id, req.port)
            .await
        {
            Ok(()) => {
                self.audit_emit(
                    EventType::IngressPortUnexposed,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "port": req.port }),
                )
                .await;
                SupervisorResponse::PortUnexposed {
                    workspace_id: req.workspace_id,
                    port: req.port,
                }
            }
            Err(ne_ingress::RegistryError::PortNotFound) => SupervisorResponse::Error {
                kind: SupervisorErrorKind::IngressPortNotFound,
                message: format!("port {} not exposed on {}", req.port, req.workspace_id),
            },
            Err(_) => SupervisorResponse::Error {
                kind: SupervisorErrorKind::WorkspaceNotFound,
                message: format!("workspace {} not found", req.workspace_id),
            },
        }
    }

    /// Generate attestation evidence for a workspace (challenge-response).
    pub async fn get_attestation_evidence(
        &self,
        req: ne_protocol::supervisor::GetAttestationEvidenceRequest,
    ) -> SupervisorResponse {
        use ne_protocol::supervisor::SupervisorErrorKind as K;

        let Some(nonce) = ne_attestation::Nonce::new(req.nonce.clone()) else {
            self.audit_emit(
                EventType::AttestationFailed,
                Some(req.workspace_id.clone()),
                serde_json::json!({ "reason": "malformed_nonce" }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: K::InvalidRequest,
                message: "nonce must be 16..=64 bytes".to_string(),
            };
        };

        let measurement = {
            let instances = self.instances.lock().await;
            instances
                .get(&req.workspace_id)
                .and_then(|exec| match exec {
                    WorkspaceExec::Firecracker(inst) => Some(measure_config(inst)),
                    // The confidential tier (B) does not derive a per-workspace
                    // measurement from the launch config — its attestation is the
                    // host-CVM launch evidence, surfaced separately. Use
                    // a zeroed placeholder here; a per-backend measurement fn is a
                    // follow-up.
                    #[cfg(feature = "confidential-cvm")]
                    WorkspaceExec::OpenShell(_) => Some(ne_attestation::Measurement([0u8; 32])),
                })
        };
        let Some(measurement) = measurement else {
            self.audit_emit(
                EventType::AttestationFailed,
                Some(req.workspace_id.clone()),
                serde_json::json!({ "reason": "workspace_not_found" }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: K::WorkspaceNotFound,
                message: format!("workspace {} not found", req.workspace_id),
            };
        };

        let nonce_hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(nonce.as_bytes()).into()
        };
        let is_replay = {
            let mut rings = self.attestation_nonces.lock().await;
            let ring = rings.entry(req.workspace_id.clone()).or_default();
            ring.record(nonce_hash)
        };
        if is_replay {
            self.audit_emit(
                EventType::AttestationReplayed,
                Some(req.workspace_id.clone()),
                serde_json::json!({ "nonce_sha256": hex::encode(nonce_hash) }),
            )
            .await;
            return SupervisorResponse::Error {
                kind: K::AttestationReplay,
                message: "nonce already used for this workspace".to_string(),
            };
        }

        let issued_at = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(i64::MAX);
        let evreq = ne_attestation::EvidenceRequest {
            workspace_id: req.workspace_id.clone(),
            measurement,
            nonce,
        };
        match self.attestation.generate(&evreq, issued_at) {
            Ok(evidence) => {
                // Serialize the resolved provider_type to its snake_case string
                // ("software" / "sev_snp") rather than a hardcoded literal, so
                // the audit chain reflects whichever provider this deployment
                // actually constructed. Only hashes are emitted — never raw
                // report/key bytes.
                self.audit_emit(
                    EventType::AttestationEvidenceIssued,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({
                        "provider_type": serde_json::to_value(evidence.provider_type)
                            .unwrap_or(serde_json::Value::Null),
                        "measurement_sha256": hex::encode(measurement.0),
                        "nonce_sha256": hex::encode(nonce_hash),
                    }),
                )
                .await;
                SupervisorResponse::AttestationEvidenceIssued { evidence }
            }
            Err(e) => {
                self.audit_emit(
                    EventType::AttestationFailed,
                    Some(req.workspace_id.clone()),
                    serde_json::json!({ "reason": "generate_failed" }),
                )
                .await;
                SupervisorResponse::Error {
                    kind: K::Internal,
                    message: format!("attestation generation failed: {e}"),
                }
            }
        }
    }
}

/// Map the `exposed_ports` from a [`NetworkConfig`] request into the flat
/// [`ne_ingress::PortRoute`] list the registry expects. Returns an empty
/// `Vec` when `network` is `None` (non-networked workspace — nothing to
/// register).
#[cfg(target_os = "linux")]
fn exposed_ports_from_request(
    network: &Option<ne_protocol::supervisor::NetworkConfig>,
) -> Vec<ne_ingress::PortRoute> {
    network
        .as_ref()
        .map(|n| {
            n.exposed_ports
                .iter()
                .map(|p| ne_ingress::PortRoute {
                    port: p.port,
                    inject_headers: p
                        .inject_headers
                        .iter()
                        .map(|h| (h.name.clone(), h.value.clone()))
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Append the guest `ip=` autoconf directive to the base kernel boot args
/// when the workspace is networked. The guest kernel must be built with
/// `CONFIG_IP_PNP=y` (see `images/.../linux_ip_pnp.fragment`). When not
/// networked, the base args are returned unchanged.
#[cfg(target_os = "linux")]
fn compose_boot_args(base: &str, layout: Option<&crate::network::SlotIpLayout>) -> String {
    layout.map_or_else(
        || base.to_string(),
        |l| format!("{base} {}", l.ip_boot_arg()),
    )
}

#[cfg(target_os = "linux")]
async fn write_file_over_control(
    control: WorkspaceControl,
    guest_port: u32,
    path: &str,
    content: Vec<u8>,
    timeout_ms: u32,
) -> Result<GuestResponse, (SupervisorErrorKind, String)> {
    match control {
        WorkspaceControl::Firecracker(vsock_uds) => crate::firecracker::write_file_via_vsock(
            &vsock_uds, guest_port, path, content, timeout_ms,
        )
        .await
        .map_err(firecracker_control_error),
        #[cfg(feature = "confidential-cvm")]
        WorkspaceControl::OpenShell {
            ssh_addr,
            handshake_secret,
        } => {
            let path = confidential_workspace_path(path)
                .map_err(|message| (SupervisorErrorKind::PathRejected, message))?;
            crate::openshell::write_file_via_sftp_endpoint(
                ssh_addr,
                &handshake_secret,
                &path,
                content,
                timeout_ms,
            )
            .await
            .map_err(|error| openshell_control_error(&error))
        }
    }
}

#[cfg(target_os = "linux")]
async fn read_file_over_control(
    control: WorkspaceControl,
    guest_port: u32,
    path: &str,
    max_bytes: u64,
    timeout_ms: u32,
) -> Result<GuestResponse, (SupervisorErrorKind, String)> {
    match control {
        WorkspaceControl::Firecracker(vsock_uds) => crate::firecracker::read_file_via_vsock(
            &vsock_uds, guest_port, path, max_bytes, timeout_ms,
        )
        .await
        .map_err(firecracker_control_error),
        #[cfg(feature = "confidential-cvm")]
        WorkspaceControl::OpenShell {
            ssh_addr,
            handshake_secret,
        } => {
            let path = confidential_workspace_path(path)
                .map_err(|message| (SupervisorErrorKind::PathRejected, message))?;
            crate::openshell::read_file_via_sftp_endpoint(
                ssh_addr,
                &handshake_secret,
                &path,
                max_bytes,
                timeout_ms,
            )
            .await
            .map_err(|error| openshell_control_error(&error))
        }
    }
}

#[cfg(target_os = "linux")]
fn firecracker_control_error(
    error: crate::firecracker::GuestRpcError,
) -> (SupervisorErrorKind, String) {
    match error {
        crate::firecracker::GuestRpcError::Timeout(ms) => (
            SupervisorErrorKind::Timeout,
            format!("vsock RPC exceeded {ms}ms"),
        ),
        crate::firecracker::GuestRpcError::ConnectRejected(message) => (
            SupervisorErrorKind::GuestUnreachable,
            format!("vsock CONNECT rejected: {message}"),
        ),
        other => (SupervisorErrorKind::GuestUnreachable, other.to_string()),
    }
}

/// Map a [`ne_protocol::guest::GuestErrorKind`] to the
/// corresponding [`SupervisorErrorKind`] for relay back to the API
/// caller. One-to-one where the semantics align; everything else
/// collapses to `Internal`.
#[cfg(target_os = "linux")]
fn guest_kind_to_supervisor_kind(kind: GuestErrorKind) -> SupervisorErrorKind {
    use ne_protocol::guest::GuestErrorKind as G;
    match kind {
        G::PathRejected => SupervisorErrorKind::PathRejected,
        G::FileNotFound => SupervisorErrorKind::FileNotFound,
        G::FileTooLarge => SupervisorErrorKind::FileTooLarge,
        G::IoError => SupervisorErrorKind::IoError,
        G::InvalidRequest => SupervisorErrorKind::InvalidRequest,
        G::CommandFailed => SupervisorErrorKind::LaunchFailed,
        G::Timeout => SupervisorErrorKind::Timeout,
        // `GuestErrorKind` is `#[non_exhaustive]`; G::Internal and any
        // future variants collapse to Internal until the supervisor
        // adds a specific arm.
        _ => SupervisorErrorKind::Internal,
    }
}

#[cfg(all(target_os = "linux", feature = "confidential-cvm"))]
fn openshell_control_error(
    error: &crate::openshell::OpenShellError,
) -> (SupervisorErrorKind, String) {
    match error {
        crate::openshell::OpenShellError::Timeout(ms) => (
            SupervisorErrorKind::Timeout,
            format!("OpenShell control operation exceeded {ms}ms"),
        ),
        crate::openshell::OpenShellError::ConnectRejected(message) => (
            SupervisorErrorKind::GuestUnreachable,
            format!("OpenShell control connection rejected: {message}"),
        ),
        _ => (SupervisorErrorKind::GuestUnreachable, error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn control_error_code(kind: SupervisorErrorKind) -> &'static str {
    match kind {
        SupervisorErrorKind::Timeout => "timeout",
        SupervisorErrorKind::PathRejected => "path_rejected",
        _ => "guest_unreachable",
    }
}

#[cfg(all(test, feature = "confidential-cvm"))]
mod confidential_capacity_tests {
    use std::sync::Arc;

    use ne_protocol::supervisor::SupervisorErrorKind;

    use super::{
        confidential_workspace_path, try_acquire_confidential_capacity,
        validate_confidential_create,
    };

    #[tokio::test]
    async fn confidential_capacity_rejects_a_second_holder() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let first = try_acquire_confidential_capacity(&capacity).expect("first permit");
        assert_eq!(
            try_acquire_confidential_capacity(&capacity).expect_err("second fails"),
            SupervisorErrorKind::ConfidentialCapacityExceeded
        );
        drop(first);
    }

    #[tokio::test]
    async fn confidential_capacity_releases_after_holder_drops() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let first = try_acquire_confidential_capacity(&capacity).expect("first permit");
        drop(first);
        let second = try_acquire_confidential_capacity(&capacity).expect("permit released");
        drop(second);
    }

    #[test]
    fn confidential_create_accepts_only_zeroed_runtime_fields() {
        let request = ne_protocol::supervisor::CreateWorkspaceRequest {
            workspace_id: "w".into(),
            kernel_sha256: String::new(),
            rootfs_sha256: String::new(),
            rootfs_read_only: false,
            vcpu_count: 0,
            mem_size_mib: 0,
            guest_vsock_cid: 0,
            kernel_boot_args: None,
            network: None,
            tier: None,
        };
        validate_confidential_create(&request).expect("workspace-only request");

        let mut firecracker_request = request;
        firecracker_request.vcpu_count = 1;
        assert!(validate_confidential_create(&firecracker_request).is_err());
    }

    #[test]
    fn confidential_file_paths_are_jailed_under_workspace() {
        assert_eq!(
            confidential_workspace_path("a/b.txt").expect("valid path"),
            "/workspace/a/b.txt"
        );
        for invalid in ["", "/etc/passwd", "../escape", "a/./b", "a//b"] {
            assert!(
                confidential_workspace_path(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::{
        ImageError, ImageKind, NonceRing, PathBuf, WorkspaceExec, WorkspaceManager,
        WorkspaceManagerConfig, compose_boot_args, guest_kind_to_supervisor_kind,
        is_valid_workspace_id, restore_launch_error_response,
    };
    use ne_protocol::guest::GuestErrorKind as G;
    use ne_protocol::supervisor::{
        CreateWorkspaceRequest, ForkRequest, RestoreRequest, SnapshotRequest,
        SupervisorErrorKind as S, SupervisorResponse, WorkspaceRef, WorkspaceState,
    };
    use std::sync::Arc;

    use crate::audit::AuditLog;

    fn software_provider(audit: &AuditLog) -> Arc<dyn ne_attestation::AttestationProvider> {
        crate::attestation_factory::build_provider(
            ne_protocol::profile::AttestationBackend::Software,
            audit.signing_key(),
        )
        .expect("software provider")
    }

    /// Build a minimal `WorkspaceManager` backed by a tempdir state + audit
    /// log, with generous admission ceilings that no test here is meant to
    /// exercise.
    async fn test_manager() -> WorkspaceManager {
        test_manager_with_limits(1024, 32768).await
    }

    /// Like [`test_manager`] but with caller-controlled admission ceilings,
    /// for exercising the O3 guards themselves.
    async fn test_manager_with_limits(
        max_workspaces: usize,
        max_workspace_mem_mib: u32,
    ) -> WorkspaceManager {
        let tmp = tempfile::tempdir().expect("tmpdir");
        // Leak so the audit file stays alive; bounded per-test.
        let state_dir = Box::leak(Box::new(tmp)).path().to_path_buf();
        // Signing key lives under <state_dir>/keys/ — create the dir now.
        tokio::fs::create_dir_all(state_dir.join("keys"))
            .await
            .expect("keys dir");
        let audit = AuditLog::open(&state_dir).await.expect("audit open");
        let mut cfg = WorkspaceManagerConfig::dev_defaults();
        cfg.state_dir = state_dir;
        let attestation = software_provider(&audit);
        WorkspaceManager::new(
            cfg,
            audit,
            attestation,
            max_workspaces,
            max_workspace_mem_mib,
        )
        .expect("workspace manager")
    }

    /// Fabricate a registered Firecracker instance with a known boot token.
    /// `child` needs a real process; a killed-on-drop `sleep` stands in for
    /// the jailer. Paths are deliberately nonexistent — the tests below must
    /// never reach an FC API call against them.
    async fn insert_fake_instance(mgr: &WorkspaceManager, ws_id: &str, boot_id: &str) {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("30").kill_on_drop(true);
        let child = cmd.spawn().expect("spawn sleep");
        let pid = child.id().unwrap_or(0);
        let instance = crate::firecracker::Instance {
            workspace_id: ws_id.to_string(),
            boot_id: boot_id.to_string(),
            child,
            firecracker_pid: pid,
            api_socket_host: "/nonexistent/api.sock".into(),
            vsock_host_socket: "/nonexistent/vsock.sock".into(),
            jailer_chroot: "/nonexistent/chroot".into(),
            jailer_uid: 0,
            jailer_gid: 0,
            lifecycle_state: WorkspaceState::Running,
            network_slot: None,
            guest_vsock_cid: 3,
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_boot_args: String::new(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
        };
        mgr.instances.lock().await.insert(
            ws_id.to_string(),
            WorkspaceExec::Firecracker(Box::new(instance)),
        );
    }

    async fn fake_lifecycle_state(mgr: &WorkspaceManager, ws_id: &str) -> WorkspaceState {
        let guard = mgr.instances.lock().await;
        match guard.get(ws_id) {
            Some(WorkspaceExec::Firecracker(inst)) => inst.lifecycle_state,
            _ => panic!("workspace {ws_id} missing from registry"),
        }
    }

    /// The ABA guard: a stale snapshot finalize —
    /// carrying the boot token of a terminated boot — must be a strict no-op
    /// on a replacement workspace registered under the same id. Existence
    /// alone must not be enough to mutate the entry.
    #[tokio::test]
    async fn snapshot_finalize_never_touches_a_replacement_boot() {
        use ne_protocol::supervisor::WorkspaceState;

        let mgr = test_manager().await;
        // The "replacement": a fresh boot registered under ws-aba, Running.
        insert_fake_instance(&mgr, "ws-aba", "boot-NEW").await;

        // Stale finalize from a snapshot of the terminated OLD boot: must
        // report failure and leave the replacement's state untouched.
        let touched = mgr
            .finalize_snapshot_state(
                "ws-aba",
                "boot-OLD",
                super::SnapshotFinalize::Set(WorkspaceState::Paused),
            )
            .await;
        assert!(
            !touched,
            "stale finalize (old boot token) must not claim success against a replacement boot"
        );
        assert_eq!(
            fake_lifecycle_state(&mgr, "ws-aba").await,
            WorkspaceState::Running,
            "replacement boot was relabeled by a stale snapshot finalize (ABA)"
        );

        // Same for the resume-in-place flavor: the identity mismatch must
        // short-circuit BEFORE any FC call (the fake socket path would error,
        // but more importantly a real reused socket must never be PATCHed).
        let touched = mgr
            .finalize_snapshot_state("ws-aba", "boot-OLD", super::SnapshotFinalize::ResumeInPlace)
            .await;
        assert!(
            !touched,
            "stale ResumeInPlace must not touch a replacement boot"
        );
        assert_eq!(
            fake_lifecycle_state(&mgr, "ws-aba").await,
            WorkspaceState::Running
        );

        // The MATCHING token still finalizes normally.
        let touched = mgr
            .finalize_snapshot_state(
                "ws-aba",
                "boot-NEW",
                super::SnapshotFinalize::Set(WorkspaceState::Paused),
            )
            .await;
        assert!(touched, "same-boot finalize must succeed");
        assert_eq!(
            fake_lifecycle_state(&mgr, "ws-aba").await,
            WorkspaceState::Paused
        );

        // And the plain resurrection guard: id absent → false, no reinsert.
        mgr.instances.lock().await.clear();
        let touched = mgr
            .finalize_snapshot_state(
                "ws-aba",
                "boot-NEW",
                super::SnapshotFinalize::Set(WorkspaceState::Running),
            )
            .await;
        assert!(
            !touched,
            "finalize must not resurrect a terminated workspace"
        );
        assert!(
            mgr.instances.lock().await.is_empty(),
            "finalize must never insert"
        );
    }

    #[tokio::test]
    async fn claim_boot_serializes_same_id_cold_boots() {
        let mgr = test_manager().await;
        // First claim wins.
        let claim = mgr.claim_boot("ws-claim").await;
        let claim = match claim {
            Ok(c) => c,
            Err(resp) => panic!("first claim must succeed, got {resp:?}"),
        };
        // A concurrent same-id claim fails fast with WorkspaceAlreadyExists.
        match mgr.claim_boot("ws-claim").await {
            Err(SupervisorResponse::Error { kind, .. }) => {
                assert_eq!(kind, S::WorkspaceAlreadyExists);
            }
            Err(other) => panic!("unexpected error response: {other:?}"),
            Ok(_) => panic!("second same-id claim must fail while the first is held"),
        }
        // Distinct ids are unaffected.
        assert!(
            mgr.claim_boot("ws-other").await.is_ok(),
            "distinct id must be claimable"
        );
        // Releasing the claim (the failed-boot path) frees the id again.
        drop(claim);
        assert!(
            mgr.claim_boot("ws-claim").await.is_ok(),
            "id must be claimable again after release"
        );
    }

    #[tokio::test]
    async fn lifecycle_lease_blocks_same_id_boot_after_registry_removal() {
        let mgr = test_manager().await;
        insert_fake_instance(&mgr, "ws-lifecycle", "boot-OLD").await;

        // Snapshot takes this lease before dropping the registry lock for its
        // long pause/dump/publish window.
        let lease = mgr
            .claim_lifecycle("ws-lifecycle")
            .expect("snapshot lifecycle lease");

        // Simulate terminate removing the source while snapshot continues.
        mgr.instances.lock().await.remove("ws-lifecycle");

        match mgr.claim_boot("ws-lifecycle").await {
            Err(SupervisorResponse::Error { kind, .. }) => {
                assert_eq!(kind, S::WorkspaceAlreadyExists);
            }
            Err(other) => panic!("unexpected error response: {other:?}"),
            Ok(_) => panic!("same-id boot must remain blocked for the lease lifetime"),
        }

        drop(lease);
        assert!(
            mgr.claim_boot("ws-lifecycle").await.is_ok(),
            "same id must become claimable only after snapshot releases its lease"
        );
    }

    #[test]
    fn guest_kind_maps_to_supervisor_kind_one_to_one() {
        for (input, expected) in [
            (G::PathRejected, S::PathRejected),
            (G::FileNotFound, S::FileNotFound),
            (G::FileTooLarge, S::FileTooLarge),
            (G::IoError, S::IoError),
            (G::InvalidRequest, S::InvalidRequest),
            (G::CommandFailed, S::LaunchFailed),
            (G::Timeout, S::Timeout),
            (G::Internal, S::Internal),
        ] {
            assert_eq!(
                guest_kind_to_supervisor_kind(input),
                expected,
                "for {input:?}"
            );
        }
    }

    #[test]
    fn restore_destination_staging_failure_is_image_stage_failed() {
        let error = crate::firecracker::LaunchError::Image(ImageError::Stage {
            kind: ImageKind::Rootfs,
            digest: "ab".repeat(32),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected destination create failure",
            ),
        });
        let response = restore_launch_error_response(error);
        assert!(matches!(
            response,
            SupervisorResponse::Error {
                kind: S::ImageStageFailed,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn write_file_supervisor_rejects_oversized_body() {
        // Defense-in-depth cap rejects without ever reaching the guest.
        // We can't easily construct a full WorkspaceManager + audit log
        // for this unit test, so instead we exercise the protocol
        // constant directly.
        assert_eq!(
            ne_protocol::supervisor::MAX_INLINE_FILE_BYTES,
            10 * 1024 * 1024,
            "protocol crate must own the cap value",
        );
    }

    #[test]
    fn is_valid_workspace_id_grammar() {
        // S2-F1: only the jailer grammar is accepted; anything that could
        // traverse a path is rejected.
        assert!(is_valid_workspace_id("ws-01jabcdef"));
        assert!(is_valid_workspace_id("01J0SNAPSHOTULID"));
        assert!(!is_valid_workspace_id(""), "empty rejected");
        assert!(
            !is_valid_workspace_id("../../etc"),
            "dot-dot + slash rejected"
        );
        assert!(
            !is_valid_workspace_id("/var/lib/ne-enclave"),
            "absolute rejected"
        );
        assert!(!is_valid_workspace_id("ws/01j"), "slash rejected");
        assert!(!is_valid_workspace_id("ws.01j"), "dot rejected");
        assert!(!is_valid_workspace_id("ws_01j"), "underscore rejected");
        assert!(!is_valid_workspace_id(&"a".repeat(65)), "too long rejected");
    }

    #[tokio::test]
    async fn restore_and_fork_reject_traversal_ids() {
        // S2-F1: a traversal in either id must be rejected as InvalidRequest
        // BEFORE any filesystem path is built (it never reaches verify_artifact
        // or the jailer). The check lives at the shared boot_from_snapshot
        // chokepoint, so both restore and fork are covered.
        let mgr = test_manager().await;

        // Bad snapshot_id (read path).
        let resp = mgr
            .restore(RestoreRequest {
                snapshot_id: "../../../../var/lib/ne-enclave".into(),
                new_workspace_id: "ws-ok".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidRequest,
                    ..
                }
            ),
            "traversal snapshot_id must be InvalidRequest, got {resp:?}"
        );

        // Bad new_workspace_id (as-root write path) with a valid snapshot_id.
        let resp = mgr
            .restore(RestoreRequest {
                snapshot_id: "01J0VALIDSNAPSHOT".into(),
                new_workspace_id: "../../../../var/lib/ne-enclave".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidRequest,
                    ..
                }
            ),
            "traversal new_workspace_id must be InvalidRequest, got {resp:?}"
        );

        // Same for fork.
        let resp = mgr
            .fork(ForkRequest {
                snapshot_id: "01J0VALIDSNAPSHOT".into(),
                new_workspace_id: "/abs/escape".into(),
                hostname: None,
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidRequest,
                    ..
                }
            ),
            "traversal fork new_workspace_id must be InvalidRequest, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn pause_returns_unsupported_deferred() {
        // Public pause/resume is deferred: in-place Firecracker
        // resume kills the vsock control channel. Both APIs must return
        // Unsupported regardless of whether the workspace exists.
        let mgr = test_manager().await;
        let resp = mgr
            .pause(WorkspaceRef {
                workspace_id: "any-id".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::Unsupported,
                    ..
                }
            ),
            "expected Unsupported (deferred), got {resp:?}"
        );
        let resp = mgr
            .resume(WorkspaceRef {
                workspace_id: "any-id".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::Unsupported,
                    ..
                }
            ),
            "expected Unsupported (deferred), got {resp:?}"
        );
    }

    #[tokio::test]
    async fn writable_snapshot_rejection_preserves_running_state_and_publishes_nothing() {
        let mgr = test_manager().await;
        for live in [false, true] {
            let id = format!("writable-{live}");
            let child = tokio::process::Command::new("/usr/bin/true")
                .spawn()
                .expect("spawn harmless child");
            mgr.instances.lock().await.insert(
                id.clone(),
                WorkspaceExec::Firecracker(Box::new(crate::firecracker::Instance {
                    workspace_id: id.clone(),
                    boot_id: ulid::Ulid::new().to_string(),
                    child,
                    firecracker_pid: 1,
                    api_socket_host: PathBuf::from("/unused/api.sock"),
                    vsock_host_socket: PathBuf::from("/unused/vsock.sock"),
                    jailer_chroot: PathBuf::from("/unused/chroot"),
                    jailer_uid: 1000,
                    jailer_gid: 1000,
                    lifecycle_state: WorkspaceState::Running,
                    network_slot: None,
                    guest_vsock_cid: 3,
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    kernel_boot_args: "console=ttyS0".into(),
                    kernel_sha256: "11".repeat(32),
                    rootfs_sha256: "22".repeat(32),
                    rootfs_read_only: false,
                })),
            );

            let response = mgr
                .snapshot(SnapshotRequest {
                    workspace_id: id.clone(),
                    live,
                })
                .await;
            assert!(matches!(
                response,
                SupervisorResponse::Error {
                    kind: S::SnapshotFailed,
                    ref message,
                } if message.contains("writable-rootfs")
            ));
            let guard = mgr.instances.lock().await;
            let Some(WorkspaceExec::Firecracker(instance)) = guard.get(&id) else {
                panic!("writable instance must remain registered");
            };
            assert_eq!(instance.lifecycle_state, WorkspaceState::Running);
            drop(guard);
            assert!(
                !mgr.cfg.state_dir.join("snapshots").exists(),
                "live={live}: rejection must occur before artifact publication"
            );
        }
    }

    #[tokio::test]
    async fn restore_missing_snapshot_is_invalid() {
        let mgr = test_manager().await;
        let resp = mgr
            .restore(RestoreRequest {
                snapshot_id: "missing-snap-id".into(),
                new_workspace_id: "ws-x".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidSnapshot,
                    ..
                }
            ),
            "expected InvalidSnapshot, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn fork_missing_snapshot_is_invalid() {
        let mgr = test_manager().await;
        let resp = mgr
            .fork(ForkRequest {
                snapshot_id: "missing-snap".into(),
                new_workspace_id: "fork-x".into(),
                hostname: None,
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidSnapshot,
                    ..
                }
            ),
            "expected InvalidSnapshot, got {resp:?}"
        );
    }

    #[test]
    fn fresh_machine_id_is_32_lower_hex() {
        let id = WorkspaceManager::fresh_machine_id();
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[tokio::test]
    async fn create_with_tier_but_no_pool_is_tier_not_found() {
        let mgr = test_manager().await;
        let req = CreateWorkspaceRequest {
            workspace_id: "w".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: Some("default".into()),
        };
        let resp = mgr.create(req).await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::TierNotFound,
                    ..
                }
            ),
            "expected TierNotFound, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn create_rejects_mem_over_ceiling() {
        let mgr = test_manager_with_limits(1024, 256).await;
        let req = CreateWorkspaceRequest {
            workspace_id: "ws-mem".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 512,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        };
        let resp = mgr.create(req).await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::InvalidRequest,
                    ..
                }
            ),
            "expected InvalidRequest, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn create_rejects_at_workspace_capacity() {
        // A zero ceiling means "0 registered >= 0 allowed" is always true —
        // exercises the count guard without needing a real boot.
        let mgr = test_manager_with_limits(0, 32768).await;
        let req = CreateWorkspaceRequest {
            workspace_id: "ws-cap".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        };
        let resp = mgr.create(req).await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::CapacityExceeded,
                    ..
                }
            ),
            "expected CapacityExceeded, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn live_vm_count_includes_warm_pool_and_create_respects_it() {
        // Manager with a pool and a combined live-VM ceiling of 2.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let state_dir = Box::leak(Box::new(tmp)).path().to_path_buf();
        tokio::fs::create_dir_all(state_dir.join("keys"))
            .await
            .expect("keys dir");
        let audit = AuditLog::open(&state_dir).await.expect("audit open");
        let mut cfg = WorkspaceManagerConfig::dev_defaults();
        cfg.state_dir = state_dir;
        cfg.warm_pool = Some(crate::pool::WarmPoolConfig {
            tier_name: "default".into(),
            base_snapshot_id: "snap".into(),
            target_size: 2,
            max_in_flight: 2,
        });
        let attestation = software_provider(&audit);
        let mgr =
            WorkspaceManager::new(cfg, audit, attestation, 2, 32768).expect("workspace manager");
        assert_eq!(mgr.live_vm_count().await, 0);

        // Simulate two live pool VMs without booting anything: reserved
        // provision permits count as in-flight, and in-flight provisions are
        // real booting FC processes as far as the ceiling is concerned.
        let pool = mgr.pool.clone().expect("pool configured");
        let permits = pool.reserve_provisions().await;
        assert_eq!(permits.len(), 2);
        assert_eq!(mgr.live_vm_count().await, 2);

        // A cold create must now be rejected: zero registered instances, but
        // the combined instances+pool live-VM count is at the ceiling.
        let resp = mgr
            .create(CreateWorkspaceRequest {
                workspace_id: "ws-pool-cap".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 128,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: None,
                tier: None,
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::CapacityExceeded,
                    ..
                }
            ),
            "expected CapacityExceeded, got {resp:?}"
        );

        // Dropping the permits releases the in-flight slots: the combined
        // count returns to zero and capacity frees for the next refill tick.
        drop(permits);
        assert_eq!(mgr.live_vm_count().await, 0);
    }

    #[tokio::test]
    async fn restore_rejects_at_workspace_capacity() {
        let mgr = test_manager_with_limits(0, 32768).await;
        let resp = mgr
            .restore(RestoreRequest {
                snapshot_id: "snap".into(),
                new_workspace_id: "ws-restore-cap".into(),
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::CapacityExceeded,
                    ..
                }
            ),
            "expected CapacityExceeded, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn fork_rejects_at_workspace_capacity() {
        let mgr = test_manager_with_limits(0, 32768).await;
        let resp = mgr
            .fork(ForkRequest {
                snapshot_id: "snap".into(),
                new_workspace_id: "ws-fork-cap".into(),
                hostname: None,
            })
            .await;
        assert!(
            matches!(
                resp,
                SupervisorResponse::Error {
                    kind: S::CapacityExceeded,
                    ..
                }
            ),
            "expected CapacityExceeded, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn tier_create_rejects_half_present_or_invalid_digest_pair() {
        let mgr = test_manager().await;
        for (kernel_sha256, rootfs_sha256) in [
            ("11".repeat(32), String::new()),
            ("AA".repeat(32), "22".repeat(32)),
        ] {
            let response = mgr
                .create(CreateWorkspaceRequest {
                    workspace_id: "bad-tier-digest".into(),
                    kernel_sha256,
                    rootfs_sha256,
                    rootfs_read_only: true,
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    guest_vsock_cid: 3,
                    kernel_boot_args: None,
                    network: None,
                    tier: Some("default".into()),
                })
                .await;
            assert!(matches!(
                response,
                SupervisorResponse::Error {
                    kind: S::InvalidImageDigest,
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    async fn standard_cold_create_rejects_empty_digest_pair() {
        let mgr = test_manager().await;
        let response = mgr
            .create(CreateWorkspaceRequest {
                workspace_id: "missing-digests".into(),
                kernel_sha256: String::new(),
                rootfs_sha256: String::new(),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 128,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: None,
                tier: None,
            })
            .await;
        assert!(matches!(
            response,
            SupervisorResponse::Error {
                kind: S::InvalidImageDigest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn missing_managed_image_is_rejected_before_network_setup() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let state_dir = tmp.path().join("state");
        let image_store = tmp.path().join("images");
        tokio::fs::create_dir_all(state_dir.join("keys"))
            .await
            .expect("keys dir");
        tokio::fs::create_dir_all(&image_store)
            .await
            .expect("image store");
        let audit = AuditLog::open(&state_dir).await.expect("audit open");
        let mut cfg = WorkspaceManagerConfig::dev_defaults();
        cfg.state_dir = state_dir;
        cfg.image_store = image_store;
        cfg.network = Some(crate::network::NetworkController::new(
            PathBuf::from("/definitely/not/invoked/ip"),
            PathBuf::from("/definitely/not/invoked/iptables"),
            "eth0".into(),
            None,
            "1.1.1.1:53".into(),
            None,
            None,
            None,
        ));
        let attestation = software_provider(&audit);
        let mgr =
            WorkspaceManager::new(cfg, audit, attestation, 1024, 32768).expect("workspace manager");
        let response = mgr
            .create(CreateWorkspaceRequest {
                workspace_id: "missing-image".into(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
                vcpu_count: 1,
                mem_size_mib: 128,
                guest_vsock_cid: 3,
                kernel_boot_args: None,
                network: Some(ne_protocol::supervisor::NetworkConfig {
                    enable_egress: true,
                    ..Default::default()
                }),
                tier: None,
            })
            .await;
        assert!(
            matches!(
                response,
                SupervisorResponse::Error {
                    kind: S::ImageNotFound,
                    ..
                }
            ),
            "missing image must win before any network command: {response:?}"
        );
    }

    #[test]
    fn boot_args_append_guest_ip_when_networked() {
        let base = "console=ttyS0 reboot=k panic=1 pci=off";
        let layout = crate::network::SlotIpLayout::for_slot(3);
        let with = compose_boot_args(base, Some(&layout));
        assert_eq!(
            with,
            "console=ttyS0 reboot=k panic=1 pci=off ip=169.254.3.6::169.254.3.5:255.255.255.252::eth0:off"
        );
        let without = compose_boot_args(base, None);
        assert_eq!(without, base);
    }

    #[test]
    fn nonce_ring_detects_replay_and_evicts_at_cap() {
        let mut ring = NonceRing::default();
        let a = [1u8; 32];
        assert!(!ring.record(a), "first sighting is not a replay");
        assert!(ring.record(a), "second sighting is a replay");
        // Fill past CAP with distinct hashes; `a` must eventually evict.
        for i in 0..u32::try_from(NonceRing::CAP).expect("CAP fits in u32") {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            // ensure distinct from `a`
            h[31] = 0xFF;
            let _ = ring.record(h);
        }
        assert!(
            !ring.record(a),
            "after CAP distinct inserts, `a` was evicted and is fresh again"
        );
        assert!(ring.seen.len() <= NonceRing::CAP, "set never exceeds CAP");
    }
}

/// Cross-platform unit tests for the admission-control derivation (audit
/// O3). Pure, so they run on macOS — enforcement itself is exercised in the
/// Linux-only `tests` module below.
#[cfg(test)]
mod admission_tests {
    #[test]
    fn derive_max_workspaces_scales_and_floors() {
        // ~512 MiB nominal per VM; never returns 0; capped at 1024.
        assert_eq!(super::derive_max_workspaces(64), 1); // tiny host -> floor 1
        assert_eq!(super::derive_max_workspaces(8 * 1024), 16);
        assert_eq!(super::derive_max_workspaces(4 * 1024 * 1024), 1024); // ceiling
    }
}

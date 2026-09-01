// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Typed IPC schema between `ne-api` and `ne-supervisor`.
//!
//! The supervisor's command surface is small, typed, and
//! explicit; no free-form strings reach the privileged side.
//!
//! Wire format on the unix domain socket is newline-delimited JSON: one
//! request per line, one response per line, in lockstep on a single
//! connection.
//!
//! # Example
//!
//! ```
//! use ne_protocol::supervisor::SupervisorRequest;
//!
//! let req = SupervisorRequest::Ping;
//! let encoded = serde_json::to_string(&req).unwrap();
//! assert_eq!(encoded, r#"{"op":"ping"}"#);
//! ```

use serde::{Deserialize, Serialize};

use crate::fleet::RunnerCapacity;

/// Wire protocol version. Bumped on incompatible request/response
/// schema changes; clients refuse to talk to a mismatched supervisor.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard cap on inline file content for `WriteFile` / `ReadFile` RPCs.
/// Enforced at both the API daemon and the supervisor (defense in
/// depth). Bumps require coordinated SDK release.
pub const MAX_INLINE_FILE_BYTES: usize = 10 * 1024 * 1024;

/// Operations the supervisor accepts.
///
/// `#[non_exhaustive]` ensures consumers handle future variants safely.
/// New operations require an RFC and the service-inventory lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SupervisorRequest {
    /// Liveness probe. Always replies with [`SupervisorResponse::Pong`].
    Ping,
    /// Return the runtime's resolved execution and evidence capabilities.
    GetCapabilities,
    /// Launch a workspace using the selected execution profile. Linux-only;
    /// macOS builds reply with [`SupervisorErrorKind::Unsupported`].
    CreateWorkspace(CreateWorkspaceRequest),
    /// Terminate a running workspace and reclaim host resources.
    Terminate(TerminateRequest),
    /// Run one command inside a workspace using the profile's control channel.
    /// Linux-only.
    RunCommand(RunCommandRequest),
    /// Write a file inside a workspace using the profile's control channel.
    /// Linux-only.
    WriteFile(WriteFileRequest),
    /// Read a file inside a workspace using the profile's control channel.
    /// Linux-only.
    ReadFile(ReadFileRequest),
    /// Read entries from the supervisor's signed audit event log.
    /// Cross-platform — useful in dev for inspecting emitted events
    /// even without a live workspace.
    ListEvents(crate::audit::ListEventsRequest),
    /// Pause a running workspace (freeze vCPUs in place).
    PauseWorkspace(WorkspaceRef),
    /// Resume a previously paused workspace.
    ResumeWorkspace(WorkspaceRef),
    /// Snapshot a paused workspace into a reusable artifact.
    SnapshotWorkspace(SnapshotRequest),
    /// Restore a fresh workspace from an existing snapshot artifact.
    RestoreWorkspace(RestoreRequest),
    /// Fork a fresh workspace from a snapshot artifact, then reset the
    /// new guest's identity (hostname / machine-id / RNG) so it is
    /// distinct from the source and any sibling fork.
    ForkWorkspace(ForkRequest),
    /// Query the current warm-pool status.
    PoolStatus(PoolStatusRequest),
    /// Query the supervisor-owned atomic runtime capacity inventory.
    CapacitySnapshot(CapacitySnapshotRequest),
    /// Start exposing a guest port via host-based ingress routing.
    /// The supervisor registers the port in the workspace's
    /// `NetworkConfig::exposed_ports` and signals the ingress router.
    ExposePort(ExposePortRequest),
    /// Stop exposing a previously-exposed guest port. The ingress
    /// router stops routing `{port}-{workspace_id}.{domain}` traffic.
    UnexposePort(UnexposePortRequest),
    /// Generate attestation evidence for a workspace, binding the
    /// caller-supplied nonce. Challenge–response: a fresh nonce per call.
    GetAttestationEvidence(GetAttestationEvidenceRequest),
}

impl SupervisorRequest {
    /// Return the profile-gated workspace operation represented by this
    /// request. Host liveness and audit-log reads are profile-independent.
    #[must_use]
    pub fn workspace_operation(&self) -> Option<crate::profile::WorkspaceOperation> {
        use crate::profile::WorkspaceOperation as Op;

        match self {
            Self::CreateWorkspace(_) => Some(Op::Create),
            Self::Terminate(_) => Some(Op::Destroy),
            Self::RunCommand(_) => Some(Op::Execute),
            Self::WriteFile(_) => Some(Op::WriteFile),
            Self::ReadFile(_) => Some(Op::ReadFile),
            Self::PauseWorkspace(_) => Some(Op::Pause),
            Self::ResumeWorkspace(_) => Some(Op::Resume),
            Self::SnapshotWorkspace(_) => Some(Op::Snapshot),
            Self::RestoreWorkspace(_) => Some(Op::Restore),
            Self::ForkWorkspace(_) => Some(Op::Fork),
            Self::PoolStatus(_) => Some(Op::WarmPool),
            Self::ExposePort(_) | Self::UnexposePort(_) => Some(Op::Ingress),
            Self::GetAttestationEvidence(_) => Some(Op::Attest),
            Self::Ping
            | Self::GetCapabilities
            | Self::ListEvents(_)
            | Self::CapacitySnapshot(_) => None,
        }
    }
}

/// Workspace launch specification.
///
/// Sealed snapshots and attestation policy are outside the current request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateWorkspaceRequest {
    /// Opaque workspace identifier. The caller (API daemon) picks this;
    /// the supervisor does not generate IDs.
    pub workspace_id: String,
    /// Canonical lowercase SHA-256 digest of the managed guest kernel image.
    pub kernel_sha256: String,
    /// Canonical lowercase SHA-256 digest of the managed guest rootfs image.
    pub rootfs_sha256: String,
    /// Whether the rootfs should be mounted read-only inside the guest.
    /// Required `true` for squashfs; ext4 may be either.
    pub rootfs_read_only: bool,
    /// Guest vCPU count.
    pub vcpu_count: u8,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
    /// Guest vsock CID. The supervisor exposes a host-side unix socket
    /// at `vsock_host_socket` in the response; the guest connects to
    /// it using this CID.
    pub guest_vsock_cid: u32,
    /// Optional kernel boot args; defaults to a quiet console=ttyS0
    /// setup when `None`.
    pub kernel_boot_args: Option<String>,
    /// Optional network configuration. `None` preserves the existing
    /// behavior — workspace boots with no network device at all and
    /// only the vsock guest-agent channel is reachable. `Some(_)`
    /// asks the supervisor to provision a per-workspace netns + TAP
    /// + veth + NAT before launching Firecracker.
    ///
    /// `default` keeps older clients deserializing cleanly against
    /// newer supervisors.
    #[serde(default)]
    pub network: Option<NetworkConfig>,
    /// Optional warm-pool tier. When `Some`, the supervisor draws the new
    /// workspace from that tier's pool (its launch params come from the
    /// tier's base snapshot, not from this request). When `None`, the
    /// existing blank cold-boot path is used unchanged.
    #[serde(default)]
    pub tier: Option<String>,
}

/// Per-workspace network policy.
///
/// The current implementation ships a single toggle — later versions can add
/// allow CIDRs / ports / hostname allowlists / DNS overrides without
/// breaking the wire shape (`#[serde(default)]` on every new field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    /// When `true`, the supervisor installs a MASQUERADE rule so the
    /// workspace egresses through the host's default route. When
    /// `false`, the netns + interfaces still exist (so the guest's
    /// `eth0` is configured) but no NAT rule lands — useful for
    /// confidential / air-gapped workloads.
    pub enable_egress: bool,
    /// Allowlist of destination CIDRs the workspace is permitted to
    /// reach. Independent of [`Self::enable_egress`]; controls the
    /// per-workspace FORWARD chain. An empty list combined with
    /// `enable_egress = true` allows all destinations (the current
    /// open-egress shape). An empty list with `enable_egress = false`
    /// blocks every outbound destination — workspace can still talk
    /// to its own netns and to the host veth, but no further.
    /// Conntrack-tracked return traffic for accepted flows is always
    /// allowed regardless of this list.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    /// Hostname allowlist enforced by the per-workspace DNS filter.
    /// Matches by suffix — `openai.com` allows `api.openai.com`,
    /// `chat.openai.com`, etc. A leading `*.` prefix is permitted
    /// and equivalent to the bare form. An empty list disables the
    /// DNS filter entirely (E4.b will then leave the workspace's
    /// resolver pointing at whatever the operator's CNI provides).
    /// A non-empty list switches the workspace into deny-by-default
    /// DNS: only listed names resolve to real IPs; everything else
    /// returns NXDOMAIN.
    #[serde(default)]
    pub allow_hostnames: Vec<String>,
    /// When `Some`, the workspace opts into the host-side privacy
    /// router (HTTP body PII scanning). The supervisor spawns one
    /// `ne-privacy-router` per workspace inside the netns and
    /// installs iptables DNAT to redirect TCP/80 egress to it. The
    /// PII policy itself is host-global (operator-set
    /// via supervisor CLI) — this struct stays empty for now and will
    /// grow per-workspace overrides (`policy: Option<PiiPolicy>`) in
    /// a later compatible extension without breaking existing clients.
    #[serde(default)]
    pub privacy_router: Option<PrivacyRouterConfig>,
    /// Guest ports exposed to host-based ingress routing
    /// (`{port}-{workspace_id}.{domain}`). Empty = no ingress; only
    /// listed ports are routable. `#[serde(default)]` keeps older
    /// clients deserializing cleanly against newer supervisors.
    #[serde(default)]
    pub exposed_ports: Vec<ExposedPort>,
}

/// Per-workspace privacy-router opt-in marker.
///
/// Empty today: the operator-set global YAML policy applies
/// to every workspace that opts in. Kept as a struct (rather than a
/// bool) so later API versions can add fields (`policy`, `redirect_ports`, etc.)
/// without an SDK migration — all future fields will be
/// `#[serde(default)]` so older clients sending `{}` stay compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivacyRouterConfig {}

/// A single HTTP header injected at the ingress edge before forwarding
/// to the guest port. Used to carry auth tokens, workspace identity, or
/// operator-defined context without requiring guest-side changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderInjection {
    /// Header name (e.g. `"x-enclave-auth"`).
    pub name: String,
    /// Header value. Treated as an opaque string; no encoding applied.
    pub value: String,
}

/// One guest port exposed to host-based ingress routing.
///
/// When a `CreateWorkspaceRequest` lists this port in
/// `NetworkConfig::exposed_ports`, the ingress router maps
/// `{port}-{workspace_id}.{domain}` → the workspace TAP address at
/// this port, optionally injecting auth headers before forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedPort {
    /// Guest TCP port to expose. `u16` in these hand-written types;
    /// converted to `uint32` at the gRPC boundary.
    pub port: u16,
    /// Headers the ingress proxy injects on every forwarded request.
    /// Empty = no injection. `#[serde(default)]` keeps old clients
    /// deserializing cleanly against newer supervisors.
    #[serde(default)]
    pub inject_headers: Vec<HeaderInjection>,
}

/// Request to start exposing a guest port via host ingress routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposePortRequest {
    /// Target workspace id.
    pub workspace_id: String,
    /// Port specification (number + optional header injections).
    pub port: ExposedPort,
}

/// Request to stop exposing a previously-exposed guest port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnexposePortRequest {
    /// Target workspace id.
    pub workspace_id: String,
    /// Guest TCP port to stop exposing.
    pub port: u16,
}

/// Request to generate attestation evidence for a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetAttestationEvidenceRequest {
    /// Target workspace id.
    pub workspace_id: String,
    /// Caller challenge nonce (16..=64 bytes; validated at the boundary).
    pub nonce: Vec<u8>,
}

/// Returned on successful workspace creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceCreated {
    /// Echoes the caller's [`CreateWorkspaceRequest::workspace_id`].
    pub workspace_id: String,
    /// Process id of the Firecracker process under jailer.
    ///
    /// On the **confidential tier** (single-CVM-direct, B; `exec_backend ==
    /// "openshell"`) this is `0` — there is no Firecracker process; the
    /// OpenShell sandbox PID is not surfaced here. Read `exec_backend` to
    /// discriminate the tier.
    pub firecracker_pid: u32,
    /// Host-side unix socket the guest agent will connect back on via
    /// vsock. Absolute path on the host (outside the jailer chroot).
    ///
    /// On the **confidential tier** this is the empty string — the
    /// OpenShell control channel is surfaced via `control_socket` instead.
    pub vsock_host_socket: String,
    /// Absolute path to the jailer chroot root for this workspace.
    ///
    /// On the **confidential tier** this is the empty string.
    pub jailer_chroot: String,
    /// Network resources the supervisor provisioned for this
    /// workspace, when the request asked for networking. `None`
    /// when the request omitted [`CreateWorkspaceRequest::network`].
    #[serde(default)]
    pub network: Option<WorkspaceNetwork>,
    /// Which execution backend the workspace landed on. `"firecracker"`
    /// (the standard tier, default when omitted for back-compat) or
    /// `"openshell"` (the confidential tier, single-CVM-direct, B). It was
    /// added additively so existing clients deserialize unchanged.
    #[serde(default)]
    pub exec_backend: Option<String>,
    /// On the **confidential tier** (`exec_backend == "openshell"`): the
    /// `host:port` SSH address the supervisor uses to control the OpenShell
    /// sandbox. `None` on the standard tier (Firecracker uses
    /// `vsock_host_socket` instead). This optional field preserves
    /// compatibility with existing clients.
    #[serde(default)]
    pub control_socket: Option<String>,
}

/// Network details for a created workspace.
///
/// Surfaced back to the caller after a successful
/// [`SupervisorRequest::CreateWorkspace`] so the caller can recognize
/// where the workspace lives on the link-local pool without having
/// to query the supervisor again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceNetwork {
    /// Netns the supervisor placed the workspace into (full path on
    /// the host, e.g. `/var/run/netns/ne-<short_id>`).
    pub netns_path: String,
    /// TAP device the guest's `eth0` is wired to.
    pub tap_device: String,
    /// Host-side veth IP. The workspace reaches the outside world by
    /// using this as its default gateway.
    pub host_ip: String,
    /// Guest-side IP assigned to `eth0`.
    pub guest_ip: String,
    /// Prefix length of the /30 pair (always 30 in this iteration).
    pub prefix: u8,
}

/// A bare workspace reference (pause/resume).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRef {
    /// Target workspace id.
    pub workspace_id: String,
}

/// Request to snapshot a workspace into a reusable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Workspace to snapshot.
    pub workspace_id: String,
    /// When true, perform a *live-state* snapshot: capture the artifact AND keep the
    /// source running + vsock-reachable via an internal hot-swap restore. Requires the
    /// source to be `Running`. Defaults false (a plain paused-state snapshot).
    #[serde(default)]
    pub live: bool,
}

/// Request to restore a fresh workspace from a snapshot artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// Snapshot artifact id to restore from.
    pub snapshot_id: String,
    /// New workspace id to register the restored VM under.
    pub new_workspace_id: String,
}

/// Request to fork a fresh workspace from a snapshot artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkRequest {
    /// Snapshot artifact id to fork from.
    pub snapshot_id: String,
    /// New workspace id to register the fork under (jailer grammar
    /// `[a-zA-Z0-9-]{1,64}`; must not already exist).
    pub new_workspace_id: String,
    /// Optional hostname for the fork. Defaults to `new_workspace_id`
    /// when absent. `#[serde(default)]` keeps older clients compatible.
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Result of a successful [`SupervisorRequest::ForkWorkspace`]. Surfaces
/// the applied identity so callers can confirm distinctness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkInfo {
    /// The new fork's workspace id.
    pub workspace_id: String,
    /// PID of the forked Firecracker process under jailer.
    pub firecracker_pid: u32,
    /// Host-side absolute path to the fork's vsock UDS.
    pub vsock_host_socket: String,
    /// Host-side absolute path to the fork's jailer chroot.
    pub jailer_chroot: String,
    /// Snapshot this fork was created from.
    pub source_snapshot_id: String,
    /// Hostname applied to the fork.
    pub hostname: String,
    /// machine-id applied to the fork (32 lowercase hex).
    pub machine_id: String,
    /// Guest vsock CID (inherited from the snapshot vmstate — FC has no
    /// load-time override; surfaced for transparency, not a per-fork knob).
    pub guest_vsock_cid: u32,
}

/// Request the current warm-pool status. Single-tier in v1, so no fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolStatusRequest {}

/// Request the current atomic runtime capacity inventory. No fields are
/// needed because the snapshot belongs to the supervisor process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapacitySnapshotRequest {}

/// Snapshot of the warm pool's state for operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatusInfo {
    /// Whether a warm-pool tier is configured at all.
    pub configured: bool,
    /// Configured tier name (`None` when not configured).
    pub tier: Option<String>,
    /// Target number of ready members.
    pub target_size: u32,
    /// Members currently ready and held in the pool.
    pub available: u32,
    /// Provisions currently in flight (booting + resetting).
    pub in_flight: u32,
}

/// Result of a successful snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Allocated snapshot id (ULID).
    pub snapshot_id: String,
    /// Source workspace this snapshot was taken from.
    pub created_from_workspace_id: String,
    /// SHA-256 (hex) of the memory file.
    pub mem_sha256: String,
    /// SHA-256 (hex) of the vmstate file.
    pub vmstate_sha256: String,
    /// Combined size of mem + vmstate in bytes.
    pub size_bytes: u64,
    /// Source workspace's NEW Firecracker PID after a successful live hot-swap.
    /// `None` for non-live snapshots. `#[serde(default)]` keeps old clients compatible.
    #[serde(default)]
    pub firecracker_pid: Option<u32>,
}

/// Lifecycle state of a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceState {
    /// Running normally.
    Running,
    /// Paused (vCPUs stopped).
    Paused,
    /// Transient: a snapshot memory dump is in flight. The vCPUs are frozen
    /// (the VM is paused for the duration of the dump), so for any external
    /// status report this is treated as equivalent to [`Paused`]. This is
    /// never a terminal state — `snapshot()` sets it under the registry lock
    /// before dropping the guard to run the dump unlocked, then re-acquires to
    /// resolve it back to `Running`/`Paused` (or, if the workspace was
    /// terminated mid-dump, drops it without resurrecting).
    Snapshotting,
}

/// Termination request. The supervisor first sends `SIGTERM` to the
/// Firecracker process, waits up to `grace_period_ms`, then escalates
/// to `SIGKILL` and cleans up host resources unconditionally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateRequest {
    /// The workspace to tear down.
    pub workspace_id: String,
    /// Milliseconds to wait between `SIGTERM` and `SIGKILL`.
    pub grace_period_ms: u32,
}

/// Run-one-command request.
///
/// The supervisor connects to the workspace's vsock UDS, performs
/// Firecracker's host→guest `CONNECT <port>` handshake, relays a
/// [`crate::guest::GuestRequest::RunCommand`] to the
/// `ne-guest-agent` listening inside the microVM, and returns the
/// guest's reply as a [`SupervisorResponse::CommandCompleted`].
///
/// This operation is unary (full stdout/stderr buffer returned in one
/// shot). A later API version can add streaming with backpressure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCommandRequest {
    /// The workspace the guest agent runs inside.
    pub workspace_id: String,
    /// Guest vsock port the agent listens on. Defaults to 52 by
    /// convention but explicit so test harnesses can stand up
    /// alternates.
    pub guest_port: u32,
    /// Path to the command binary, resolved against guest `$PATH`.
    pub command: String,
    /// Arguments passed verbatim to the command. No shell parsing.
    pub args: Vec<String>,
    /// Per-call timeout in milliseconds. `0` disables the timeout.
    pub timeout_ms: u32,
}

/// Successful result of a [`SupervisorRequest::RunCommand`]. Mirrors
/// [`crate::guest::CommandCompleted`] plus a `workspace_id` echo so
/// callers can correlate without holding extra state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandCompleted {
    /// Echoes the [`RunCommandRequest::workspace_id`].
    pub workspace_id: String,
    /// Captured stdout (lossy UTF-8; the current buffer is full).
    pub stdout: String,
    /// Captured stderr (same conversion as `stdout`).
    pub stderr: String,
    /// Process exit code (`-1` if terminated by signal today).
    pub exit_code: i32,
    /// Wall-clock duration the command ran for, milliseconds.
    pub elapsed_ms: u64,
    /// True if the guest truncated stdout or stderr at its per-stream cap
    /// Relayed verbatim from the guest response.
    /// `#[serde(default)]` for additive wire-compat across version skew.
    #[serde(default)]
    pub truncated: bool,
}

/// Atomic file write request (`SupervisorRequest::WriteFile`).
///
/// The supervisor relays this to the workspace's guest agent over
/// vsock, then emits a chain-signed `FileWritten` (success) or
/// `FileOpFailed` (failure) event. The [`MAX_INLINE_FILE_BYTES`] cap
/// is enforced at the API daemon, the supervisor (defense in depth),
/// and the guest agent — the protocol type does not validate
/// `content.len()` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileRequest {
    /// Workspace the guest agent runs inside.
    pub workspace_id: String,
    /// Guest vsock port. `0` → API defaults to 52 by convention.
    pub guest_port: u32,
    /// Relative path inside the workspace jail root (`/workspace`).
    pub path: String,
    /// File contents. The guest agent writes these atomically via
    /// temp file + rename.
    pub content: Vec<u8>,
}

/// Successful result of [`SupervisorRequest::WriteFile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWritten {
    /// Echoes the [`WriteFileRequest::workspace_id`].
    pub workspace_id: String,
    /// Bytes the guest agent reported writing.
    pub bytes_written: u64,
    /// Canonical absolute path the file landed at (`/workspace/<relative>`).
    pub absolute_path: String,
}

/// File read request (`SupervisorRequest::ReadFile`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFileRequest {
    /// Workspace the guest agent runs inside.
    pub workspace_id: String,
    /// Guest vsock port. `0` → API defaults to 52 by convention.
    pub guest_port: u32,
    /// Relative path inside the workspace jail root.
    pub path: String,
    /// Maximum bytes to return. `0` is replaced with the 10 MiB
    /// default by the guest agent.
    pub max_bytes: u64,
}

/// Successful result of [`SupervisorRequest::ReadFile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRead {
    /// Echoes the [`ReadFileRequest::workspace_id`].
    pub workspace_id: String,
    /// File contents. May be shorter than `size_bytes` when truncated.
    pub content: Vec<u8>,
    /// Size of the underlying file on disk.
    pub size_bytes: u64,
    /// True if `content.len() < size_bytes` because the file exceeded
    /// `max_bytes`.
    pub truncated: bool,
}

/// Responses the supervisor emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SupervisorResponse {
    /// Reply to a successful [`SupervisorRequest::Ping`].
    Pong {
        /// Crate version string of the running supervisor.
        version: String,
        /// Milliseconds since the supervisor started accepting connections.
        uptime_ms: u64,
    },
    /// Reply to a successful [`SupervisorRequest::GetCapabilities`].
    Capabilities(crate::profile::RuntimeCapabilitiesInfo),
    /// Reply to a successful [`SupervisorRequest::CreateWorkspace`].
    WorkspaceCreated(WorkspaceCreated),
    /// Reply to a successful [`SupervisorRequest::Terminate`].
    WorkspaceTerminated {
        /// Echoes the [`TerminateRequest::workspace_id`].
        workspace_id: String,
    },
    /// Reply to a successful [`SupervisorRequest::RunCommand`].
    CommandCompleted(CommandCompleted),
    /// Reply to a successful [`SupervisorRequest::WriteFile`].
    FileWritten(FileWritten),
    /// Reply to a successful [`SupervisorRequest::ReadFile`].
    FileRead(FileRead),
    /// Reply to a successful [`SupervisorRequest::ListEvents`].
    Events(crate::audit::ListEventsResponse),
    /// Reply to a successful [`SupervisorRequest::PauseWorkspace`].
    WorkspacePaused {
        /// Echoes the [`WorkspaceRef::workspace_id`].
        workspace_id: String,
    },
    /// Reply to a successful [`SupervisorRequest::ResumeWorkspace`].
    WorkspaceResumed {
        /// Echoes the [`WorkspaceRef::workspace_id`].
        workspace_id: String,
    },
    /// Reply to a successful [`SupervisorRequest::SnapshotWorkspace`].
    SnapshotCreated(SnapshotInfo),
    /// Reply to a successful [`SupervisorRequest::RestoreWorkspace`].
    WorkspaceRestored(WorkspaceCreated),
    /// Reply to a successful [`SupervisorRequest::ForkWorkspace`].
    WorkspaceForked(ForkInfo),
    /// Reply to a successful [`SupervisorRequest::PoolStatus`].
    PoolStatus(PoolStatusInfo),
    /// Reply to a successful [`SupervisorRequest::CapacitySnapshot`].
    CapacitySnapshot(RunnerCapacity),
    /// Reply to a successful [`SupervisorRequest::ExposePort`].
    PortExposed {
        /// Echoes the [`ExposePortRequest::workspace_id`].
        workspace_id: String,
        /// The guest TCP port now being routed.
        port: u16,
    },
    /// Reply to a successful [`SupervisorRequest::UnexposePort`].
    PortUnexposed {
        /// Echoes the [`UnexposePortRequest::workspace_id`].
        workspace_id: String,
        /// The guest TCP port that is no longer routed.
        port: u16,
    },
    /// Reply to a successful [`SupervisorRequest::GetAttestationEvidence`].
    AttestationEvidenceIssued {
        /// The signed evidence envelope.
        evidence: ne_attestation::Evidence,
    },
    /// Any failure path. Callers branch on `kind`, not on `message`.
    Error {
        /// Stable, machine-readable error classifier.
        kind: SupervisorErrorKind,
        /// Human-readable message; never load-bearing for control flow.
        message: String,
    },
}

/// Stable error classifier for [`SupervisorResponse::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SupervisorErrorKind {
    /// Peer credentials did not match the supervisor's expected UID.
    Unauthorized,
    /// Request could not be parsed or was malformed.
    InvalidRequest,
    /// A required image digest was missing or not canonical lowercase SHA-256.
    InvalidImageDigest,
    /// The expected managed image artifact does not exist.
    ImageNotFound,
    /// The managed image artifact was unsafe (for example a symlink).
    ImageRejected,
    /// The managed artifact bytes did not match the requested digest.
    ImageDigestMismatch,
    /// A verified image could not be staged into the workspace chroot.
    ImageStageFailed,
    /// Operation is not implemented on this platform or build.
    Unsupported,
    /// Operation is implemented, but not by the selected execution profile.
    UnsupportedForProfile,
    /// A workspace with this `workspace_id` already exists.
    WorkspaceAlreadyExists,
    /// No workspace with this `workspace_id` is registered with the
    /// supervisor.
    WorkspaceNotFound,
    /// Jailer / Firecracker launch failed at the host layer.
    LaunchFailed,
    /// The supervisor could not reach the guest agent over vsock
    /// (no UDS, CONNECT rejected, guest not listening yet, etc.).
    GuestUnreachable,
    /// The guest agent returned a malformed or unexpected response.
    GuestProtocolError,
    /// A guest call exceeded its `timeout_ms`. Distinct from
    /// `Internal` so callers can surface it as a retryable signal.
    Timeout,
    /// Catch-all for unexpected supervisor-side failures.
    Internal,
    /// Path violated the jail policy (absolute, `..`, null byte, or
    /// resolved outside `/workspace`).
    PathRejected,
    /// Request body or read result exceeded the 10 MiB cap.
    FileTooLarge,
    /// File read targeted a path that does not exist.
    FileNotFound,
    /// Guest-side filesystem I/O failed (disk full, permission, etc.).
    IoError,
    /// Firecracker snapshot creation failed at the host layer.
    SnapshotFailed,
    /// Firecracker snapshot restore failed at the host layer.
    RestoreFailed,
    /// The requested snapshot artifact is missing, corrupt, or tampered.
    InvalidSnapshot,
    /// Operation requires the workspace to be paused but it is running.
    WorkspaceNotPaused,
    /// The workspace is already paused.
    WorkspaceAlreadyPaused,
    /// Fork booted the VM but post-boot identity reset (or guest
    /// readiness) failed; the freshly-booted VM was torn down. Distinct
    /// from `RestoreFailed` (load failure) and `InvalidSnapshot`.
    ForkFailed,
    /// `Create` named a warm-pool tier that this supervisor was not
    /// configured with.
    TierNotFound,
    /// The supervisor is at its configured workspace-count ceiling and cannot
    /// admit another workspace (host-exhaustion backstop).
    CapacityExceeded,
    /// The confidential profile already has its single active or creating
    /// workspace slot held.
    ConfidentialCapacityExceeded,
    /// The target workspace has no network configuration and therefore
    /// cannot participate in ingress routing.
    WorkspaceNotNetworked,
    /// The requested ingress port is not listed in the workspace's
    /// `exposed_ports` (raised by `UnexposePort`).
    IngressPortNotFound,
    /// A nonce was reused for a workspace (replay).
    AttestationReplay,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Break caught: removing the host capacity IPC tag would make callers
    // unable to obtain the atomic inventory snapshot.
    #[test]
    fn capacity_snapshot_request_and_response_roundtrip() {
        let request = SupervisorRequest::CapacitySnapshot(CapacitySnapshotRequest {});
        let request_json = serde_json::to_string(&request).expect("serialize request");
        assert_eq!(request_json, r#"{"op":"capacity_snapshot"}"#);
        let request_back: SupervisorRequest =
            serde_json::from_str(&request_json).expect("deserialize request");
        assert_eq!(request_back, request);

        let response = SupervisorResponse::CapacitySnapshot(ne_protocol_capacity());
        let response_json = serde_json::to_string(&response).expect("serialize response");
        let response_back: SupervisorResponse =
            serde_json::from_str(&response_json).expect("deserialize response");
        assert_eq!(response_back, response);
    }

    fn ne_protocol_capacity() -> RunnerCapacity {
        RunnerCapacity {
            revision: 7,
            configured_workspace_ceiling: 3,
            registered_workspaces: 1,
            resident_workspaces: 1,
            runnable_workspaces: 1,
            allocated_cpu_millicores: 1_000,
            allocated_memory_bytes: 1_024,
            warm_pool_reserved_slots: 0,
            profiles: vec![crate::profile::ExecutionProfile::Standard],
            operations: vec![crate::profile::WorkspaceOperation::Create],
        }
    }

    #[test]
    fn ping_request_roundtrips() {
        let req = SupervisorRequest::Ping;
        let json = serde_json::to_string(&req).expect("serialize Ping");
        assert_eq!(json, r#"{"op":"ping"}"#);
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize Ping");
        assert_eq!(back, req);
    }

    #[test]
    fn pong_response_roundtrips() {
        let resp = SupervisorResponse::Pong {
            version: "0.0.0".into(),
            uptime_ms: 42,
        };
        let json = serde_json::to_string(&resp).expect("serialize Pong");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize Pong");
        assert_eq!(back, resp);
    }

    #[test]
    fn error_response_roundtrips_with_classified_kind() {
        for kind in [
            SupervisorErrorKind::Unauthorized,
            SupervisorErrorKind::InvalidRequest,
            SupervisorErrorKind::Unsupported,
            SupervisorErrorKind::Internal,
        ] {
            let resp = SupervisorResponse::Error {
                kind,
                message: "explanation".into(),
            };
            let json = serde_json::to_string(&resp).expect("serialize Error");
            let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize Error");
            assert_eq!(back, resp);
        }
    }

    #[test]
    fn unknown_op_is_rejected() {
        let raw = r#"{"op":"does_not_exist"}"#;
        let result: Result<SupervisorRequest, _> = serde_json::from_str(raw);
        assert!(result.is_err(), "deserialization of unknown op must fail");
    }

    #[test]
    fn create_workspace_request_roundtrips() {
        let req = SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
            workspace_id: "wks_01jABCDEF".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 256,
            guest_vsock_cid: 3,
            kernel_boot_args: Some("console=ttyS0 reboot=k panic=1 pci=off".into()),
            network: None,
            tier: None,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn create_workspace_request_with_network_roundtrips() {
        let req = SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
            workspace_id: "wks-net-1".into(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 256,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: Some(NetworkConfig {
                enable_egress: true,
                allow_cidrs: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
                allow_hostnames: vec!["openai.com".into(), "*.github.com".into()],
                privacy_router: Some(PrivacyRouterConfig {}),
                exposed_ports: vec![],
            }),
            tier: None,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn create_workspace_request_back_compat_without_network_field() {
        // Older clients sending the pre-E2 schema (no `network`
        // field) must still deserialize cleanly. `#[serde(default)]`
        // does the work; this test pins the contract.
        let legacy = r#"{
            "op":"create_workspace",
            "workspace_id":"wks-legacy",
            "kernel_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "rootfs_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "rootfs_read_only":true,
            "vcpu_count":1,
            "mem_size_mib":256,
            "guest_vsock_cid":3,
            "kernel_boot_args":null
        }"#;
        let parsed: SupervisorRequest = serde_json::from_str(legacy).expect("legacy");
        if let SupervisorRequest::CreateWorkspace(c) = parsed {
            assert!(c.network.is_none());
        } else {
            panic!("expected CreateWorkspace variant");
        }
    }

    #[test]
    fn workspace_created_response_roundtrips() {
        let resp = SupervisorResponse::WorkspaceCreated(WorkspaceCreated {
            workspace_id: "wks_01jABCDEF".into(),
            firecracker_pid: 12345,
            vsock_host_socket: "/opt/ne-enclave/run/wks_01jABCDEF/vsock.sock".into(),
            jailer_chroot: "/srv/jailer/firecracker/wks_01jABCDEF/root".into(),
            network: None,
            exec_backend: None,
            control_socket: None,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn workspace_created_response_with_network_roundtrips() {
        let resp = SupervisorResponse::WorkspaceCreated(WorkspaceCreated {
            workspace_id: "wks-net-1".into(),
            firecracker_pid: 4242,
            vsock_host_socket: "/srv/jailer/firecracker/wks-net-1/root/vsock.sock".into(),
            jailer_chroot: "/srv/jailer/firecracker/wks-net-1/root".into(),
            network: Some(WorkspaceNetwork {
                netns_path: "/var/run/netns/ne-abcd".into(),
                tap_device: "tap-abcd".into(),
                host_ip: "169.254.7.1".into(),
                guest_ip: "169.254.7.2".into(),
                prefix: 30,
            }),
            exec_backend: None,
            control_socket: None,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn terminate_request_roundtrips() {
        let req = SupervisorRequest::Terminate(TerminateRequest {
            workspace_id: "wks_01jABCDEF".into(),
            grace_period_ms: 5_000,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn workspace_error_kinds_roundtrip() {
        for kind in [
            SupervisorErrorKind::WorkspaceAlreadyExists,
            SupervisorErrorKind::WorkspaceNotFound,
            SupervisorErrorKind::LaunchFailed,
            SupervisorErrorKind::GuestUnreachable,
            SupervisorErrorKind::GuestProtocolError,
            SupervisorErrorKind::Timeout,
        ] {
            let resp = SupervisorResponse::Error {
                kind,
                message: "x".into(),
            };
            let json = serde_json::to_string(&resp).expect("serialize");
            let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, resp);
        }
    }

    #[test]
    fn run_command_request_roundtrips() {
        let req = SupervisorRequest::RunCommand(RunCommandRequest {
            workspace_id: "wks-rc-1".into(),
            guest_port: 52,
            command: "/bin/echo".into(),
            args: vec!["hello".into(), "world".into()],
            timeout_ms: 5_000,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn command_completed_response_roundtrips() {
        let resp = SupervisorResponse::CommandCompleted(CommandCompleted {
            workspace_id: "wks-rc-1".into(),
            stdout: "hello world\n".into(),
            stderr: String::new(),
            exit_code: 0,
            elapsed_ms: 17,
            truncated: false,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn write_file_request_roundtrips() {
        let req = SupervisorRequest::WriteFile(WriteFileRequest {
            workspace_id: "wks-w-1".into(),
            guest_port: 52,
            path: "src/main.rs".into(),
            content: b"fn main() {}".to_vec(),
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn read_file_request_roundtrips() {
        let req = SupervisorRequest::ReadFile(ReadFileRequest {
            workspace_id: "wks-r-1".into(),
            guest_port: 52,
            path: "out/log.txt".into(),
            max_bytes: 0,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SupervisorRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn file_written_response_roundtrips() {
        let resp = SupervisorResponse::FileWritten(FileWritten {
            workspace_id: "wks-w-1".into(),
            bytes_written: 12,
            absolute_path: "/workspace/src/main.rs".into(),
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn file_read_response_roundtrips() {
        let resp = SupervisorResponse::FileRead(FileRead {
            workspace_id: "wks-r-1".into(),
            content: b"hello".to_vec(),
            size_bytes: 5,
            truncated: false,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SupervisorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn new_supervisor_error_kinds_roundtrip() {
        for (variant, expected) in [
            (
                SupervisorErrorKind::InvalidImageDigest,
                "invalid_image_digest",
            ),
            (SupervisorErrorKind::ImageNotFound, "image_not_found"),
            (SupervisorErrorKind::ImageRejected, "image_rejected"),
            (
                SupervisorErrorKind::ImageDigestMismatch,
                "image_digest_mismatch",
            ),
            (SupervisorErrorKind::ImageStageFailed, "image_stage_failed"),
            (
                SupervisorErrorKind::UnsupportedForProfile,
                "unsupported_for_profile",
            ),
            (
                SupervisorErrorKind::ConfidentialCapacityExceeded,
                "confidential_capacity_exceeded",
            ),
            (SupervisorErrorKind::PathRejected, "path_rejected"),
            (SupervisorErrorKind::FileTooLarge, "file_too_large"),
            (SupervisorErrorKind::FileNotFound, "file_not_found"),
            (SupervisorErrorKind::IoError, "io_error"),
        ] {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(s, format!("\"{expected}\""));
            let back: SupervisorErrorKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn pause_request_roundtrips() {
        let r = SupervisorRequest::PauseWorkspace(WorkspaceRef {
            workspace_id: "ws-a".into(),
        });
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"op\":\"pause_workspace\""));
        assert_eq!(serde_json::from_str::<SupervisorRequest>(&line).unwrap(), r);
    }

    #[test]
    fn snapshot_request_roundtrips() {
        let r = SupervisorRequest::SnapshotWorkspace(SnapshotRequest {
            workspace_id: "ws-a".into(),
            live: false,
        });
        let line = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<SupervisorRequest>(&line).unwrap(), r);
    }

    #[test]
    fn snapshot_maps_to_snapshot_operation() {
        let req = SupervisorRequest::SnapshotWorkspace(SnapshotRequest {
            workspace_id: "w".into(),
            live: false,
        });
        assert_eq!(
            req.workspace_operation(),
            Some(crate::profile::WorkspaceOperation::Snapshot)
        );
    }

    #[test]
    fn capabilities_request_and_response_roundtrip() {
        let request = SupervisorRequest::GetCapabilities;
        let request_json = serde_json::to_string(&request).expect("serialize request");
        assert_eq!(request_json, r#"{"op":"get_capabilities"}"#);
        assert_eq!(
            serde_json::from_str::<SupervisorRequest>(&request_json).expect("request"),
            request
        );

        let response = SupervisorResponse::Capabilities(
            crate::profile::ExecutionProfile::ConfidentialAzure.capabilities("0.2.0", 1),
        );
        let response_json = serde_json::to_string(&response).expect("serialize response");
        assert_eq!(
            serde_json::from_str::<SupervisorResponse>(&response_json).expect("response"),
            response
        );
    }

    #[test]
    fn restore_request_roundtrips() {
        let r = SupervisorRequest::RestoreWorkspace(RestoreRequest {
            snapshot_id: "01J0SNAP".into(),
            new_workspace_id: "ws-b".into(),
        });
        let line = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<SupervisorRequest>(&line).unwrap(), r);
    }

    #[test]
    fn snapshot_created_response_roundtrips() {
        let r = SupervisorResponse::SnapshotCreated(SnapshotInfo {
            snapshot_id: "01J0SNAP".into(),
            created_from_workspace_id: "ws-a".into(),
            mem_sha256: "aa".into(),
            vmstate_sha256: "bb".into(),
            size_bytes: 4096,
            firecracker_pid: None,
        });
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"status\":\"snapshot_created\""));
        assert_eq!(
            serde_json::from_str::<SupervisorResponse>(&line).unwrap(),
            r
        );
    }

    #[test]
    fn snapshot_request_live_defaults_false_for_old_clients() {
        let r: SnapshotRequest = serde_json::from_str(r#"{"workspace_id":"ws-a"}"#).unwrap();
        assert!(!r.live);
        let r2: SnapshotRequest =
            serde_json::from_str(r#"{"workspace_id":"ws-a","live":true}"#).unwrap();
        assert!(r2.live);
    }

    #[test]
    fn snapshot_info_firecracker_pid_defaults_none() {
        let i: SnapshotInfo = serde_json::from_str(
            r#"{"snapshot_id":"s","created_from_workspace_id":"w","mem_sha256":"a","vmstate_sha256":"b","size_bytes":1}"#,
        )
        .unwrap();
        assert_eq!(i.firecracker_pid, None);
    }

    #[test]
    fn new_error_kinds_roundtrip() {
        for k in [
            SupervisorErrorKind::SnapshotFailed,
            SupervisorErrorKind::RestoreFailed,
            SupervisorErrorKind::InvalidSnapshot,
            SupervisorErrorKind::WorkspaceNotPaused,
            SupervisorErrorKind::WorkspaceAlreadyPaused,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            assert_eq!(serde_json::from_str::<SupervisorErrorKind>(&s).unwrap(), k);
        }
    }

    #[test]
    fn workspace_state_roundtrips() {
        for st in [
            WorkspaceState::Running,
            WorkspaceState::Paused,
            WorkspaceState::Snapshotting,
        ] {
            let s = serde_json::to_string(&st).unwrap();
            assert_eq!(serde_json::from_str::<WorkspaceState>(&s).unwrap(), st);
        }
        // The transient state serializes in snake_case like its siblings.
        assert_eq!(
            serde_json::to_string(&WorkspaceState::Snapshotting).unwrap(),
            "\"snapshotting\""
        );
    }

    #[test]
    fn fork_request_roundtrips() {
        let r = SupervisorRequest::ForkWorkspace(ForkRequest {
            snapshot_id: "01J0SNAP".into(),
            new_workspace_id: "fork-a".into(),
            hostname: Some("fork-a".into()),
        });
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"op\":\"fork_workspace\""), "got {line}");
        assert_eq!(serde_json::from_str::<SupervisorRequest>(&line).unwrap(), r);
    }

    #[test]
    fn fork_request_back_compat_without_hostname() {
        let legacy = r#"{"op":"fork_workspace","snapshot_id":"s","new_workspace_id":"w"}"#;
        let parsed: SupervisorRequest = serde_json::from_str(legacy).expect("legacy");
        if let SupervisorRequest::ForkWorkspace(f) = parsed {
            assert!(f.hostname.is_none());
        } else {
            panic!("expected ForkWorkspace");
        }
    }

    #[test]
    fn workspace_forked_response_roundtrips() {
        let r = SupervisorResponse::WorkspaceForked(ForkInfo {
            workspace_id: "fork-a".into(),
            firecracker_pid: 4242,
            vsock_host_socket: "/srv/jailer/firecracker/fork-a/root/vsock.sock".into(),
            jailer_chroot: "/srv/jailer/firecracker/fork-a/root".into(),
            source_snapshot_id: "01J0SNAP".into(),
            hostname: "fork-a".into(),
            machine_id: "0123456789abcdef0123456789abcdef".into(),
            guest_vsock_cid: 3,
        });
        let line = serde_json::to_string(&r).unwrap();
        assert!(
            line.contains("\"status\":\"workspace_forked\""),
            "got {line}"
        );
        assert_eq!(
            serde_json::from_str::<SupervisorResponse>(&line).unwrap(),
            r
        );
    }

    #[test]
    fn fork_failed_error_kind_roundtrips() {
        let s = serde_json::to_string(&SupervisorErrorKind::ForkFailed).unwrap();
        assert_eq!(s, "\"fork_failed\"");
        assert_eq!(
            serde_json::from_str::<SupervisorErrorKind>(&s).unwrap(),
            SupervisorErrorKind::ForkFailed
        );
    }

    #[test]
    fn create_request_tier_is_optional_and_snake_tagged() {
        let json = r#"{"op":"create_workspace","workspace_id":"w","kernel_sha256":"1111111111111111111111111111111111111111111111111111111111111111","rootfs_sha256":"2222222222222222222222222222222222222222222222222222222222222222","rootfs_read_only":true,"vcpu_count":1,"mem_size_mib":128,"guest_vsock_cid":3}"#;
        let req: SupervisorRequest = serde_json::from_str(json).expect("parse");
        match req {
            SupervisorRequest::CreateWorkspace(c) => assert_eq!(c.tier, None),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn exposed_port_serde_roundtrip() {
        let p = ExposedPort {
            port: 8080,
            inject_headers: vec![HeaderInjection {
                name: "x-enclave-auth".into(),
                value: "t".into(),
            }],
        };
        let s = serde_json::to_string(&p).expect("ser");
        let back: ExposedPort = serde_json::from_str(&s).expect("de");
        assert_eq!(p, back);
    }

    #[test]
    fn network_config_defaults_exposed_ports_empty() {
        let nc: NetworkConfig = serde_json::from_str(r#"{"enable_egress":true}"#).expect("de");
        assert!(nc.exposed_ports.is_empty());
    }

    #[test]
    fn expose_unexpose_request_roundtrip() {
        let e = ExposePortRequest {
            workspace_id: "ws-a".into(),
            port: ExposedPort {
                port: 9090,
                inject_headers: vec![],
            },
        };
        let s = serde_json::to_string(&e).expect("ser");
        let back: ExposePortRequest = serde_json::from_str(&s).expect("de");
        assert_eq!(e, back);

        let u = UnexposePortRequest {
            workspace_id: "ws-a".into(),
            port: 9090,
        };
        let s2 = serde_json::to_string(&u).expect("ser");
        let back2: UnexposePortRequest = serde_json::from_str(&s2).expect("de");
        assert_eq!(u, back2);
    }

    #[test]
    fn get_attestation_evidence_request_round_trips() {
        let req = SupervisorRequest::GetAttestationEvidence(GetAttestationEvidenceRequest {
            workspace_id: "ws-1".to_string(),
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"op\":\"get_attestation_evidence\""),
            "got {json}"
        );
        let back: SupervisorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn pool_status_response_round_trips() {
        let info = PoolStatusInfo {
            configured: true,
            tier: Some("default".into()),
            target_size: 4,
            available: 3,
            in_flight: 1,
        };
        let resp = SupervisorResponse::PoolStatus(info.clone());
        let s = serde_json::to_string(&resp).expect("ser");
        assert!(s.contains(r#""status":"pool_status""#), "tag = {s}");
        let back: SupervisorResponse = serde_json::from_str(&s).expect("de");
        assert_eq!(back, SupervisorResponse::PoolStatus(info));
    }

    #[test]
    fn capacity_exceeded_serializes_snake_case() {
        let json = serde_json::to_string(&SupervisorErrorKind::CapacityExceeded).unwrap();
        assert_eq!(json, "\"capacity_exceeded\"");
        let back: SupervisorErrorKind = serde_json::from_str("\"capacity_exceeded\"").unwrap();
        assert_eq!(back, SupervisorErrorKind::CapacityExceeded);
    }
}

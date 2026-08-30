// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Firecracker process supervisor — Linux-only.
//!
//! Each workspace gets its own Firecracker process,
//! launched under `jailer` with a per-workspace chroot. The host
//! supervisor (this code) coordinates lifecycle:
//!
//! 1. Stage kernel + rootfs into the jailer chroot.
//! 2. Spawn the jailer (which spawns Firecracker after dropping privs
//!    into `{jailer_uid}:{jailer_gid}` and chrooting).
//! 3. Wait for Firecracker's HTTP API socket to appear inside the
//!    chroot.
//! 4. POST `/boot-source`, `/drives/rootfs`, `/machine-config`,
//!    `/vsock`, `/actions {InstanceStart}` over HTTP/1.0 on the API
//!    socket. Hand-rolled — we don't pull in hyper for five PUTs.
//! 5. Track the `tokio::process::Child` until termination.
//!
//! Current scope: no network namespace, no nftables, no cgroup
//! enforcement beyond what jailer applies. Later releases add networking and
//! attestation.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Host-side cap on a single guest vsock reply frame. Matches the guest
/// agent's own `MAX_GUEST_FRAME_BYTES` (32 MiB); the host does NOT trust the
/// guest to honor its own cap (audit: host-OOM `DoS`). Override via
/// `NE_MAX_GUEST_FRAME_BYTES`; a 0/garbage override is rejected (falls back to
/// the default) — a 0-byte cap would reject every frame and brick all vsock RPC.
static MAX_GUEST_FRAME_BYTES: LazyLock<u64> = LazyLock::new(|| {
    crate::util::parse_positive_or(
        std::env::var("NE_MAX_GUEST_FRAME_BYTES").ok(),
        32 * 1024 * 1024,
    )
});

/// Per-MiB timeout budget added on top of [`FC_API_TIMEOUT_MS`] for
/// `/snapshot/create` and `/snapshot/load`, which serialize/deserialize
/// `mem_size_mib` MiB of guest memory to/from disk — the flat control-call
/// deadline alone would false-positive on a large VM. ~10ms/MiB → +~40s for
/// a 4 GiB VM.
const PER_MIB_MS: u64 = 10;

/// Parse the `NE_FC_API_TIMEOUT_MS` override. A missing, unparseable, or
/// zero value falls back to the 30s default — 0 is rejected because a zero
/// deadline would make `tokio::time::timeout` fire on every API call
/// instantly (same class of bug fixed for `NE_MAX_EXEC_TIMEOUT_MS`; see
/// `util::parse_ceiling`).
fn parse_api_timeout_ms(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(30_000)
}

/// Default deadline for a single Firecracker control-API call
/// (machine-config, boot-source, drives, vsock, actions, pause/resume).
/// Snapshot/restore use [`scaled_api_timeout`] instead. Override via
/// `NE_FC_API_TIMEOUT_MS`; a 0 or unparseable value falls back to 30s — see
/// [`parse_api_timeout_ms`].
static FC_API_TIMEOUT_MS: LazyLock<u64> =
    LazyLock::new(|| parse_api_timeout_ms(std::env::var("NE_FC_API_TIMEOUT_MS").ok()));

/// Memory-scaled deadline for `/snapshot/create` and `/snapshot/load`.
fn scaled_api_timeout(mem_size_mib: u32) -> Duration {
    Duration::from_millis(*FC_API_TIMEOUT_MS + u64::from(mem_size_mib) * PER_MIB_MS)
}

use crate::image::{ImageError, VerifiedImagePair, WorkspaceClaim, stage_verified_pair};

/// Inputs to a single workspace launch. The supervisor builds this
/// from a [`ne_protocol::supervisor::CreateWorkspaceRequest`]
/// plus its own configuration (binary paths, jailer uid/gid, etc.).
pub struct LaunchConfig {
    /// Opaque identifier for the workspace; jailer uses this as the
    /// chroot subdirectory name.
    pub workspace_id: String,
    /// Retained, verified source handles. All launch and restore paths must
    /// resolve these before any workspace tree is claimed.
    pub verified_images: VerifiedImagePair,
    /// Whether to mount the rootfs read-only inside the guest.
    pub rootfs_read_only: bool,
    /// Number of vCPUs to give the guest.
    pub vcpu_count: u8,
    /// Memory size in MiB.
    pub mem_size_mib: u32,
    /// Vsock guest CID. 0 disables the vsock device.
    pub guest_vsock_cid: u32,
    /// Kernel command-line arguments.
    pub kernel_boot_args: String,
    /// Path to the Firecracker binary on the host (jailer will execve it).
    pub firecracker_binary: PathBuf,
    /// Path to the jailer binary on the host.
    pub jailer_binary: PathBuf,
    /// Base directory under which jailer creates the chroot tree.
    pub chroot_base: PathBuf,
    /// UID jailer drops Firecracker to.
    pub jailer_uid: u32,
    /// GID jailer drops Firecracker to.
    pub jailer_gid: u32,
    /// Timeout for the post-spawn wait on Firecracker's API socket.
    pub api_socket_timeout: Duration,
    /// Optional networking attachment. When `Some`, the supervisor
    /// has already provisioned the netns + TAP via
    /// [`crate::network::NetworkController::setup`]; we just need to
    /// point jailer at the netns and tell Firecracker to wire its
    /// `eth0` to the TAP.
    pub network: Option<NetworkAttachment>,
}

/// Per-launch network attachment passed by [`crate::workspace::WorkspaceManager`].
#[derive(Debug, Clone)]
pub struct NetworkAttachment {
    /// Absolute path to the netns the workspace lives in
    /// (`/var/run/netns/ne-<short_id>`). jailer's `--netns` flag
    /// gets this verbatim.
    pub netns_path: PathBuf,
    /// Name of the TAP device inside the netns. Firecracker's
    /// `/network-interfaces` API call wires its `eth0` to this.
    pub tap_name: String,
}

/// A running Firecracker microVM under jailer. Dropping the instance
/// does NOT terminate the VM; use [`terminate`] for clean shutdown.
#[derive(Debug)]
pub struct Instance {
    /// Echoes [`LaunchConfig::workspace_id`].
    pub workspace_id: String,
    /// Unique per-boot identity token (fresh ULID stamped at spawn, in both
    /// `launch` and `restore`). Distinguishes THIS boot of a workspace id
    /// from any later boot registered under the same id: the jailer chroot
    /// and API-socket paths are fully id-derived, so after a
    /// terminate→recreate the paths collide while the process behind them
    /// is a different VM. Lock-free flows that capture paths and later
    /// re-acquire the registry lock (e.g. `snapshot()`'s finalize) must
    /// compare this token before mutating the entry — the workspace-id
    /// string alone is ABA-prone. NOT the PID (PIDs recycle).
    pub boot_id: String,
    /// Handle to the jailer process (the actual Firecracker is a
    /// child of jailer, but jailer execs into it, so this PID is
    /// effectively Firecracker's).
    pub child: Child,
    /// PID of the jailer process (effectively Firecracker's PID).
    pub firecracker_pid: u32,
    /// Host-side absolute path to Firecracker's HTTP API socket.
    pub api_socket_host: PathBuf,
    /// Host-side absolute path to the guest-agent vsock socket.
    pub vsock_host_socket: PathBuf,
    /// Host-side absolute path to the jailer chroot root.
    pub jailer_chroot: PathBuf,
    /// UID Firecracker runs as inside the jailer. Needed so
    /// `snapshot_create` can chown the snapshot dir before telling FC
    /// to write there.
    pub jailer_uid: u32,
    /// GID Firecracker runs as inside the jailer.
    pub jailer_gid: u32,
    /// Current lifecycle state (Running or Paused).
    pub lifecycle_state: ne_protocol::supervisor::WorkspaceState,
    /// Network resources owned by this workspace, if any. The
    /// supervisor populates this after a successful launch so
    /// `terminate` knows to reclaim the netns + NAT rule.
    pub network_slot: Option<crate::network::NetworkSlot>,
    // --- Snapshot manifest metadata ---
    // These fields are captured at launch/restore time and written into
    // the snapshot manifest so `restore()` can reconstruct a full launch.
    /// vsock CID assigned to the guest (from `LaunchConfig::guest_vsock_cid`).
    pub guest_vsock_cid: u32,
    /// vCPU count (from `LaunchConfig::vcpu_count`).
    pub vcpu_count: u8,
    /// Memory size in MiB (from `LaunchConfig::mem_size_mib`).
    pub mem_size_mib: u32,
    /// Kernel command-line arguments (from `LaunchConfig::kernel_boot_args`).
    pub kernel_boot_args: String,
    /// Canonical managed kernel content identity.
    pub kernel_sha256: String,
    /// Canonical managed rootfs content identity.
    pub rootfs_sha256: String,
    /// Whether the rootfs was launched read-only. Writable-rootfs instances
    /// cannot be snapshotted because v5 does not capture disk mutations.
    pub rootfs_read_only: bool,
}

/// Errors returned by [`launch`].
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// IO error during chroot setup, jailer spawn, or API call.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Verified image staging failed.
    #[error(transparent)]
    Image(#[from] ImageError),
    /// Child termination or reaping failed. The owned workspace tree is left
    /// intact because deleting it while the child may still run is unsafe.
    #[error("{0}")]
    TerminationFailed(String),
    /// `workspace_id` contained a character not in `[a-zA-Z0-9-]` (the
    /// jailer ID grammar).
    #[error("workspace_id {0:?} is not a valid jailer id ([a-zA-Z0-9-]{{1,64}})")]
    InvalidWorkspaceId(String),
    /// jailer process exited before Firecracker's API socket appeared.
    #[error("jailer exited before Firecracker came up")]
    JailerExited,
    /// Either `api_socket_timeout` elapsed without the API socket
    /// appearing, or an API request to an already-present
    /// socket did not complete within its deadline (`NE_FC_API_TIMEOUT_MS`,
    /// memory-scaled for snapshot/restore) — from the caller's POV both are
    /// "the Firecracker API is unreachable within budget."
    #[error("timed out waiting for Firecracker API socket at {0}")]
    ApiSocketTimeout(PathBuf),
    /// Restore was requested for a networked workspace, which this build
    /// does not support (Firecracker stores the host TAP name in vmstate).
    #[error("networked snapshot restore is not supported in this build")]
    NetworkedRestoreUnsupported,
    /// Firecracker rejected a configuration call.
    #[error("Firecracker API call to {path} failed: status {status}: {body}")]
    ApiRequest {
        /// The API path that was requested (e.g. `/boot-source`).
        path: String,
        /// HTTP status code returned by Firecracker.
        status: u16,
        /// Response body as text (typically JSON `{fault_message: ...}`).
        body: String,
    },
}

/// Errors returned by [`terminate`].
#[derive(Debug, thiserror::Error)]
pub enum TerminateError {
    /// IO error reading process status or removing chroot.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// nix-crate error from a `kill(2)` call.
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
}

/// Output of [`spawn_jailed_firecracker`]: the live process handle plus the
/// host paths `launch` and `restore` need. `kernel_in_chroot`/`rootfs_in_chroot`
/// are launch-only.
struct JailedFirecracker {
    child: Child,
    firecracker_pid: u32,
    api_socket_host: PathBuf,
    vsock_host_socket: PathBuf,
    jailer_chroot: PathBuf,
    /// Exact workspace directory atomically claimed by this launch.
    workspace_root: PathBuf,
    /// Host path of the staged kernel inside the chroot (used by launch
    /// to derive the chroot-relative boot-source path).
    kernel_in_chroot: PathBuf,
    /// Host path of the staged rootfs inside the chroot (used by launch
    /// to derive the chroot-relative drive path).
    rootfs_in_chroot: PathBuf,
}

/// Spawns a jailed Firecracker, stages kernel+rootfs into the chroot, and
/// waits for the API socket. Shared by `launch` (cold boot) and `restore`
/// (snapshot load). Returns the live child + resolved host paths.
async fn spawn_jailed_firecracker(
    cfg: &mut LaunchConfig,
) -> Result<JailedFirecracker, LaunchError> {
    // S2-F1 (Critical) backstop: validate the id BEFORE it is joined into any
    // host path or passed to the jailer. `launch()` also checks this, but
    // `restore()`/`fork()` reach this function directly with a caller-supplied
    // `new_workspace_id`; gating here covers every caller by construction so an
    // absolute or `..`-bearing id can never reach workspace claiming/image
    // staging/cleanup (which run as root) outside the per-workspace tree.
    if !is_valid_jailer_id(&cfg.workspace_id) {
        return Err(LaunchError::InvalidWorkspaceId(cfg.workspace_id.clone()));
    }
    // Claim the workspace id atomically. A collision returns before this
    // invocation owns anything and therefore never cleans the existing tree.
    let claim = WorkspaceClaim::claim(&cfg.chroot_base, &cfg.workspace_id).await?;
    let jailer_chroot = claim.jailer_chroot().to_path_buf();
    let workspace_root = claim.workspace_root().to_path_buf();

    let outcome: Result<JailedFirecracker, LaunchError> = async {
        let kernel_in_chroot = jailer_chroot.join("vmlinux");
        let rootfs_in_chroot = jailer_chroot.join("rootfs.img");
        stage_verified_pair(
            &mut cfg.verified_images,
            &kernel_in_chroot,
            &rootfs_in_chroot,
            cfg.rootfs_read_only,
            cfg.jailer_uid,
            cfg.jailer_gid,
        )
        .await?;

        // Host-side path to the vsock UDS. Firecracker (running inside
        // the jailer chroot) creates this file at the `uds_path` we pass
        // in the /vsock API call — relative to its OWN root, which from
        // the host's POV is the jailer chroot. So the host path is
        // `{jailer_chroot}/vsock.sock`, NOT `{chroot_base}/firecracker/
        // {id}/vsock.sock` (that wrong path was one level too shallow
        // and would never have a socket on it).
        //
        // Firecracker vsock UDS convention (for our caller's reference):
        //   - Host → guest connection: connect to this base UDS and
        //     send "CONNECT <guest_port>\n". Firecracker replies
        //     "OK <fc_port>\n" then bridges the byte stream.
        //   - Guest → host connection: Firecracker forwards to
        //     `{vsock_host_socket}_<host_port>` (host must listen there).
        let vsock_host_socket = jailer_chroot.join("vsock.sock");

        // The API socket lives at /run/firecracker.socket inside the
        // chroot per jailer convention; host path is chroot + that.
        let api_socket_in_chroot = "/run/firecracker.socket";
        let api_socket_host = jailer_chroot.join("run").join("firecracker.socket");

        // Spawn jailer. Args after `--` go to Firecracker itself.
        let mut jailer_cmd = Command::new(&cfg.jailer_binary);
        jailer_cmd
            .arg("--id")
            .arg(&cfg.workspace_id)
            .arg("--exec-file")
            .arg(&cfg.firecracker_binary)
            .arg("--uid")
            .arg(cfg.jailer_uid.to_string())
            .arg("--gid")
            .arg(cfg.jailer_gid.to_string())
            .arg("--chroot-base-dir")
            .arg(&cfg.chroot_base);
        if let Some(net) = &cfg.network {
            // jailer's --netns drops Firecracker into the workspace's
            // network namespace before chrooting + exec'ing, so the TAP
            // we provisioned in the netns is visible from inside.
            jailer_cmd.arg("--netns").arg(&net.netns_path);
        }
        // After `--`, args go to Firecracker. Jailer already passes
        // `--id` to Firecracker itself, so we only add `--api-sock`.
        jailer_cmd
            .arg("--")
            .arg("--api-sock")
            .arg(api_socket_in_chroot);
        let mut child = jailer_cmd.kill_on_drop(true).spawn()?;

        let firecracker_pid = child.id().ok_or_else(|| {
            LaunchError::Io(io::Error::other(
                "jailer child has no pid (already exited?)",
            ))
        })?;
        info!(
            workspace_id = %cfg.workspace_id,
            pid = firecracker_pid,
            chroot = %jailer_chroot.display(),
            "jailer spawned"
        );

        // Wait for the API socket. While waiting, watch for early jailer
        // death so we don't burn the full timeout on a launch failure.
        if let Err(e) = wait_for_socket(&api_socket_host, &mut child, cfg.api_socket_timeout).await
        {
            confirm_child_exit(&mut child, "jailer startup", &e).await?;
            return Err(e);
        }
        debug!(socket = %api_socket_host.display(), "Firecracker API socket ready");

        Ok(JailedFirecracker {
            child,
            firecracker_pid,
            api_socket_host,
            vsock_host_socket,
            jailer_chroot,
            workspace_root,
            kernel_in_chroot,
            rootfs_in_chroot,
        })
    }
    .await;

    match outcome {
        Ok(jailed) => Ok(jailed),
        Err(LaunchError::Image(image_error)) => Err(LaunchError::Image(
            claim.cleanup_image_failure(image_error).await,
        )),
        Err(error @ LaunchError::TerminationFailed(_)) => Err(error),
        Err(other) => match claim.cleanup().await {
            Ok(()) => Err(other),
            Err(cleanup_error) => Err(LaunchError::Io(io::Error::other(format!(
                "launch failed after claiming workspace: {other}; removing owned workspace tree: \
                 {cleanup_error}"
            )))),
        },
    }
}

/// Launch one workspace. On error all partial host state is cleaned
/// up (chroot directory, jailer process if it spawned).
pub async fn launch(mut cfg: LaunchConfig) -> Result<Instance, LaunchError> {
    if !is_valid_jailer_id(&cfg.workspace_id) {
        return Err(LaunchError::InvalidWorkspaceId(cfg.workspace_id));
    }
    let (kernel_sha256, rootfs_sha256) = cfg.verified_images.digests();
    let kernel_sha256 = kernel_sha256.to_owned();
    let rootfs_sha256 = rootfs_sha256.to_owned();
    let mut jailed = spawn_jailed_firecracker(&mut cfg).await?;

    // Configure the microVM. The order here matters: machine-config
    // sets vCPU/memory budgets, boot-source loads the kernel, drives
    // attach storage, vsock adds the guest-host channel, actions
    // boots. Configure in an inner block so any failure after the jailer
    // has spawned flows through the owned-tree cleanup below.
    let configured: Result<(), LaunchError> = async {
        // Flat control-call deadline — none of these PUTs touch guest memory
        // (unlike snapshot/restore, which use `scaled_api_timeout`).
        let api_timeout = Duration::from_millis(*FC_API_TIMEOUT_MS);
        api_put(
            &jailed.api_socket_host,
            "/machine-config",
            &MachineConfig {
                vcpu_count: cfg.vcpu_count,
                mem_size_mib: cfg.mem_size_mib,
            },
            api_timeout,
        )
        .await?;
        api_put(
            &jailed.api_socket_host,
            "/boot-source",
            &BootSource {
                kernel_image_path: format!("/{}", chroot_relative(&jailed.kernel_in_chroot)?),
                boot_args: cfg.kernel_boot_args.clone(),
            },
            api_timeout,
        )
        .await?;
        api_put(
            &jailed.api_socket_host,
            "/drives/rootfs",
            &Drive {
                drive_id: "rootfs".into(),
                path_on_host: format!("/{}", chroot_relative(&jailed.rootfs_in_chroot)?),
                is_root_device: true,
                is_read_only: cfg.rootfs_read_only,
            },
            api_timeout,
        )
        .await?;
        if cfg.guest_vsock_cid != 0 {
            api_put(
                &jailed.api_socket_host,
                "/vsock",
                &Vsock {
                    guest_cid: cfg.guest_vsock_cid,
                    // `uds_path` is relative to Firecracker's chroot. From
                    // the host's POV the same file is `vsock_host_socket`
                    // (= `{jailer_chroot}/vsock.sock`).
                    uds_path: "/vsock.sock".to_string(),
                },
                api_timeout,
            )
            .await?;
        }
        if let Some(net) = &cfg.network {
            // Wire the guest's eth0 to the TAP we provisioned in the
            // workspace netns. iface_id is the kernel-side name the
            // guest sees (eth0 by convention); host_dev_name is the
            // host-visible TAP, which Firecracker (now inside the
            // netns) sees by its raw name.
            api_put(
                &jailed.api_socket_host,
                "/network-interfaces/eth0",
                &NetworkInterface {
                    iface_id: "eth0".to_string(),
                    host_dev_name: net.tap_name.clone(),
                },
                api_timeout,
            )
            .await?;
        }
        api_put(
            &jailed.api_socket_host,
            "/actions",
            &Action {
                action_type: "InstanceStart".into(),
            },
            api_timeout,
        )
        .await?;
        info!(workspace_id = %cfg.workspace_id, "InstanceStart sent");
        Ok(())
    }
    .await;
    if let Err(primary) = configured {
        return Err(cleanup_failed_child(
            &mut jailed.child,
            &jailed.workspace_root,
            "Firecracker configuration",
            primary,
        )
        .await);
    }

    Ok(Instance {
        workspace_id: cfg.workspace_id,
        boot_id: ulid::Ulid::new().to_string(),
        child: jailed.child,
        firecracker_pid: jailed.firecracker_pid,
        api_socket_host: jailed.api_socket_host,
        vsock_host_socket: jailed.vsock_host_socket,
        jailer_chroot: jailed.jailer_chroot,
        jailer_uid: cfg.jailer_uid,
        jailer_gid: cfg.jailer_gid,
        lifecycle_state: ne_protocol::supervisor::WorkspaceState::Running,
        // Caller (WorkspaceManager) attaches the NetworkSlot after
        // launch returns; firecracker module never sees the slot
        // directly — it only knows about the NetworkAttachment in
        // LaunchConfig.
        network_slot: None,
        // Snapshot manifest metadata — captured at launch time.
        guest_vsock_cid: cfg.guest_vsock_cid,
        vcpu_count: cfg.vcpu_count,
        mem_size_mib: cfg.mem_size_mib,
        kernel_boot_args: cfg.kernel_boot_args,
        kernel_sha256,
        rootfs_sha256,
        rootfs_read_only: cfg.rootfs_read_only,
    })
}

/// Errors returned by [`run_command_via_vsock`].
#[derive(Debug, thiserror::Error)]
pub enum GuestRpcError {
    /// IO failure on the vsock UDS (connect / read / write).
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Firecracker's host→guest `CONNECT` handshake returned a non-OK
    /// status line. Usually means the guest isn't listening on the
    /// requested port (yet).
    #[error("vsock CONNECT rejected: {0}")]
    ConnectRejected(String),
    /// JSON encode/decode failure on request or response.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Host-side wall clock elapsed before the guest replied. The
    /// `u32` is the timeout in milliseconds that fired.
    #[error("vsock RPC exceeded timeout {0}ms")]
    Timeout(u32),
}

/// Core vsock request–response helper.
///
/// Opens the vsock UDS, performs Firecracker's host→guest
/// `CONNECT <port>` handshake, sends `req` as a single NDJSON line,
/// reads one NDJSON response line, and returns the parsed
/// [`ne_protocol::guest::GuestResponse`].
///
/// Every public vsock helper (`run_command_via_vsock`,
/// `write_file_via_vsock`, `read_file_via_vsock`) delegates here so
/// the wire framing is defined in exactly one place.
async fn vsock_request_response(
    uds: &Path,
    guest_port: u32,
    req: &ne_protocol::guest::GuestRequest,
    timeout_ms: u32,
) -> Result<ne_protocol::guest::GuestResponse, GuestRpcError> {
    use ne_protocol::guest::GuestResponse;

    let timeout_ms = crate::util::clamp_timeout_ms(timeout_ms, *crate::util::MAX_EXEC_TIMEOUT_MS);

    let work = async {
        let stream = UnixStream::connect(uds).await?;
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);

        // Firecracker host→guest CONNECT handshake.
        wr.write_all(format!("CONNECT {guest_port}\n").as_bytes())
            .await?;
        let mut handshake = String::new();
        crate::util::read_capped_line(&mut reader, &mut handshake, *MAX_GUEST_FRAME_BYTES).await?;
        if !handshake.starts_with("OK ") {
            return Err(GuestRpcError::ConnectRejected(
                handshake.trim_end().to_string(),
            ));
        }

        let mut body = serde_json::to_vec(req)?;
        body.push(b'\n');
        wr.write_all(&body).await?;

        let mut line = String::new();
        crate::util::read_capped_line(&mut reader, &mut line, *MAX_GUEST_FRAME_BYTES).await?;
        let resp: GuestResponse = serde_json::from_str(line.trim_end())?;
        Ok::<GuestResponse, GuestRpcError>(resp)
    };

    // `timeout_ms` was clamped above against `MAX_EXEC_TIMEOUT_MS` (which is
    // guaranteed > 0), so a client-supplied 0 becomes the ceiling and the value
    // here is always non-zero — always enforce a wall-clock deadline.
    match tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), work).await {
        Ok(result) => result,
        Err(_elapsed) => Err(GuestRpcError::Timeout(timeout_ms)),
    }
}

/// Relay one `RunCommand` to the guest agent over vsock.
///
/// Opens the vsock UDS for a workspace, performs Firecracker's
/// host→guest `CONNECT <port>` handshake, sends one
/// [`ne_protocol::guest::GuestRequest::RunCommand`] as NDJSON,
/// and returns the parsed [`ne_protocol::guest::GuestResponse`].
///
/// The current command API is unary — no streaming or connection reuse. Streaming
/// can be added once the supervisor and guest agent grow chunked
/// stdout/stderr framing.
pub async fn run_command_via_vsock(
    uds: &Path,
    guest_port: u32,
    command: &str,
    args: &[String],
    timeout_ms: u32,
) -> Result<ne_protocol::guest::GuestResponse, GuestRpcError> {
    use ne_protocol::guest::{GuestRequest, RunCommandRequest};

    let req = GuestRequest::RunCommand(RunCommandRequest {
        command: command.to_string(),
        args: args.to_vec(),
        timeout_ms,
    });
    vsock_request_response(uds, guest_port, &req, timeout_ms).await
}

/// Relay a `WriteFile` request to the workspace's guest agent over vsock.
///
/// Returns the typed [`ne_protocol::guest::GuestResponse`]. Same
/// wire framing as [`run_command_via_vsock`]; only the payload differs.
pub async fn write_file_via_vsock(
    vsock_uds: &Path,
    guest_port: u32,
    path: &str,
    content: Vec<u8>,
    timeout_ms: u32,
) -> Result<ne_protocol::guest::GuestResponse, GuestRpcError> {
    let req = ne_protocol::guest::GuestRequest::WriteFile(ne_protocol::guest::WriteFileRequest {
        path: path.to_string(),
        content,
    });
    vsock_request_response(vsock_uds, guest_port, &req, timeout_ms).await
}

/// Relay a [`ne_protocol::guest::GuestRequest::ReadFile`] to the
/// workspace's guest agent over vsock and return the typed response.
pub async fn read_file_via_vsock(
    vsock_uds: &Path,
    guest_port: u32,
    path: &str,
    max_bytes: u64,
    timeout_ms: u32,
) -> Result<ne_protocol::guest::GuestResponse, GuestRpcError> {
    let req = ne_protocol::guest::GuestRequest::ReadFile(ne_protocol::guest::ReadFileRequest {
        path: path.to_string(),
        max_bytes,
    });
    vsock_request_response(vsock_uds, guest_port, &req, timeout_ms).await
}

/// Poll the guest agent with `Ping` until it answers `Pong` or `timeout` elapses.
///
/// Used after a fork/restore resume before sending the first real RPC
/// (e.g. `ResetIdentity`), since the guest needs a moment to re-arm its
/// vsock listener after `/snapshot/load`.
pub async fn wait_for_guest_ready(
    uds: &Path,
    guest_port: u32,
    timeout: Duration,
) -> Result<(), GuestRpcError> {
    use ne_protocol::guest::{GuestRequest, GuestResponse};
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(GuestResponse::Pong { .. }) =
            vsock_request_response(uds, guest_port, &GuestRequest::Ping, 2_000).await
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(GuestRpcError::Timeout(
                u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Relay a [`ne_protocol::guest::GuestRequest::ResetIdentity`] to the
/// workspace's guest agent over vsock and return the typed response.
pub async fn reset_identity_via_vsock(
    uds: &Path,
    guest_port: u32,
    hostname: String,
    machine_id: String,
    entropy_seed: Vec<u8>,
    timeout_ms: u32,
) -> Result<ne_protocol::guest::GuestResponse, GuestRpcError> {
    let req =
        ne_protocol::guest::GuestRequest::ResetIdentity(ne_protocol::guest::ResetIdentityRequest {
            hostname,
            machine_id,
            entropy_seed,
        });
    vsock_request_response(uds, guest_port, &req, timeout_ms).await
}

/// Terminate one workspace cleanly. `SIGTERM` → wait `grace` → `SIGKILL`
/// → reap → remove chroot. Cleanup is best-effort: filesystem errors
/// surface but the registry entry is still removed by the caller.
pub async fn terminate(mut instance: Instance, grace: Duration) -> Result<(), TerminateError> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let pid = Pid::from_raw(i32::try_from(instance.firecracker_pid).unwrap_or(i32::MAX));
    debug!(workspace_id = %instance.workspace_id, pid = %pid, "sending SIGTERM");
    let _ = kill(pid, Signal::SIGTERM);

    let deadline = Instant::now() + grace;
    loop {
        match instance.child.try_wait() {
            Ok(Some(status)) => {
                debug!(workspace_id = %instance.workspace_id, ?status, "jailer exited");
                break;
            }
            Ok(None) => {}
            Err(e) => return Err(e.into()),
        }
        if Instant::now() >= deadline {
            warn!(workspace_id = %instance.workspace_id, "grace expired, escalating to SIGKILL");
            let primary = LaunchError::Io(io::Error::other("graceful termination timed out"));
            confirm_child_exit(&mut instance.child, "workspace termination", &primary)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            break;
        }
        sleep(Duration::from_millis(25)).await;
    }

    // Cleanup: remove the per-workspace chroot tree. We strip the
    // trailing `/root` to also reap the jailer's parent directory
    // (e.g. /srv/jailer/firecracker/{id}/).
    let workspace_root = instance
        .jailer_chroot
        .parent()
        .unwrap_or(&instance.jailer_chroot)
        .to_path_buf();
    if let Err(e) = tokio::fs::remove_dir_all(&workspace_root).await {
        warn!(workspace_id = %instance.workspace_id, error = %e, "chroot cleanup failed");
    }
    Ok(())
}

#[allow(async_fn_in_trait)]
trait ChildControl {
    fn try_wait_control(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
    fn start_kill_control(&mut self) -> io::Result<()>;
    async fn wait_control(&mut self) -> io::Result<std::process::ExitStatus>;
}

impl ChildControl for Child {
    fn try_wait_control(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }

    fn start_kill_control(&mut self) -> io::Result<()> {
        self.start_kill()
    }

    async fn wait_control(&mut self) -> io::Result<std::process::ExitStatus> {
        self.wait().await
    }
}

/// Confirm that a child has exited and has been reaped. Failure deliberately
/// carries the primary operation context so callers can leave the owned tree
/// intact without losing the original cause.
async fn confirm_child_exit<C: ChildControl>(
    child: &mut C,
    context: &str,
    primary: &LaunchError,
) -> Result<(), LaunchError> {
    match child.try_wait_control() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => {
            return Err(LaunchError::TerminationFailed(format!(
                "{context} failed: {primary}; checking child exit before cleanup failed: {error}; \
                 owned workspace tree retained"
            )));
        }
    }
    child.start_kill_control().map_err(|error| {
        LaunchError::TerminationFailed(format!(
            "{context} failed: {primary}; terminating child before cleanup failed: {error}; owned \
             workspace tree retained"
        ))
    })?;
    child.wait_control().await.map_err(|error| {
        LaunchError::TerminationFailed(format!(
            "{context} failed: {primary}; reaping child before cleanup failed: {error}; owned \
             workspace tree retained"
        ))
    })?;
    Ok(())
}

async fn cleanup_failed_child<C: ChildControl>(
    child: &mut C,
    workspace_root: &Path,
    context: &str,
    primary: LaunchError,
) -> LaunchError {
    if let Err(termination) = confirm_child_exit(child, context, &primary).await {
        return termination;
    }
    match tokio::fs::remove_dir_all(workspace_root).await {
        Ok(()) => primary,
        Err(cleanup) => LaunchError::Io(io::Error::other(format!(
            "{context} failed: {primary}; removing owned workspace tree: {cleanup}"
        ))),
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// jailer's `--id` flag accepts only `[a-zA-Z0-9-]{1,64}`. Validate
/// before spawn so we fail with a typed error instead of relying on
/// jailer's exit code.
fn is_valid_jailer_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// chown via the nix crate (no unsafe in this crate).
fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use nix::unistd::{Gid, Uid, chown as nix_chown};
    nix_chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|e| io::Error::other(format!("chown {}: {e}", path.display())))
}

/// Make a path relative to the jailer chroot (strip the leading
/// chroot prefix). Returns the suffix without a leading `/`.
fn chroot_relative(p: &Path) -> Result<String, LaunchError> {
    let s = p.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        LaunchError::Io(io::Error::other(format!("non-utf8 path: {}", p.display())))
    })?;
    Ok(s.to_string())
}

/// Poll for the API socket to appear. Also fails fast if jailer dies.
async fn wait_for_socket(
    path: &Path,
    child: &mut Child,
    timeout: Duration,
) -> Result<(), LaunchError> {
    let deadline = Instant::now() + timeout;
    loop {
        // Check jailer liveness BEFORE trusting the socket path. On a same-id
        // cold-create race the API socket path is shared (it is derived from
        // the id-derived chroot), so a loser whose jailer already died at
        // mkdir/mknod would otherwise observe the WINNER's socket here,
        // believe it booted, and replay its config PUTs against the winner's
        // live instance (to prevent cross-instance interference).
        //
        // Residual window (accepted): the child can die right after
        // try_wait() returns None and before the exists() check; the API
        // replay that follows still fails gracefully at InstanceStart
        // ("not supported after starting the microVM"). The full fix is
        // unique per-boot chroot ids — filed as a follow-up.
        if let Some(_status) = child.try_wait()? {
            return Err(LaunchError::JailerExited);
        }
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::ApiSocketTimeout(path.to_path_buf()));
        }
        sleep(Duration::from_millis(20)).await;
    }
}

/// Issue a single HTTP/1.0 request (PUT or PATCH) to the Firecracker API
/// socket. Returns `Ok` on any 2xx status; otherwise [`LaunchError::ApiRequest`].
///
/// We serialize the body up front and pass `&[u8]` across the await
/// boundary; that keeps the future `Send`, so the dispatcher can spawn
/// the whole chain onto tokio's multi-threaded runtime.
async fn api_request<T: Serialize + Sync>(
    method: &str,
    socket: &Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> Result<(), LaunchError> {
    let work = async {
        let body_bytes = serde_json::to_vec(body).map_err(io::Error::other)?;
        let request = format!(
            "{method} {path} HTTP/1.0\r\nHost: localhost\r\n\
             Accept: application/json\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\n\r\n",
            len = body_bytes.len(),
        );
        let mut stream = UnixStream::connect(socket).await?;
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&body_bytes).await?;
        stream.flush().await?;

        // Read the response using the Content-Length header. We can't rely
        // on connection-close to signal EOF: Firecracker's HTTP impl keeps
        // the connection open even with HTTP/1.0, and half-closing the
        // write side prompts it to RST. Parsing Content-Length is the only
        // path that consistently terminates.
        let mut reader = BufReader::new(stream);
        let (status, content_length) = read_http_head(&mut reader).await?;
        let mut body_buf = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body_buf).await?;
        }
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(LaunchError::ApiRequest {
                path: path.to_string(),
                status,
                body: String::from_utf8_lossy(&body_buf).into_owned(),
            })
        }
    };
    // A wedged Firecracker (hung syscall, deadlocked API thread) would
    // otherwise stall connect/write/read forever, hanging create/snapshot/
    // restore indefinitely. Reuses `ApiSocketTimeout` — from the
    // caller's POV both "socket never appeared" and "socket appeared but
    // never answered" are the same failure: the API is unreachable within
    // budget.
    tokio::time::timeout(timeout, work)
        .await
        .unwrap_or_else(|_| Err(LaunchError::ApiSocketTimeout(socket.to_path_buf())))
}

#[inline]
async fn api_put<T: Serialize + Sync>(
    socket: &Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> Result<(), LaunchError> {
    api_request("PUT", socket, path, body, timeout).await
}

/// Test-only surface onto [`api_put`]. Integration tests under `tests/`
/// link this crate as an external dependency, so they can't see
/// `pub(crate)`/`#[cfg(test)]` items directly — this thin `pub` wrapper,
/// gated behind the `test-support` feature (see `Cargo.toml`), lets
/// `tests/fc_api_timeout.rs` drive `api_put`'s deadline without widening
/// `api_put` itself to `pub` in ordinary builds.
#[cfg(any(test, feature = "test-support"))]
pub async fn api_put_for_test<T: Serialize + Sync>(
    socket: &Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> Result<(), LaunchError> {
    api_put(socket, path, body, timeout).await
}

#[inline]
async fn api_patch<T: Serialize + Sync>(
    socket: &Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> Result<(), LaunchError> {
    api_request("PATCH", socket, path, body, timeout).await
}

/// Pause a running microVM by API-socket path (`PATCH /vm {state:Paused}`).
///
/// Path-based sibling of [`pause`]: takes only the raw FC API socket so the
/// caller can drive pause/dump/resume against captured paths without holding
/// a borrow on (or the registry lock over) the `Instance`.
pub async fn pause_at(api_socket: &Path) -> Result<(), LaunchError> {
    api_patch(
        api_socket,
        "/vm",
        &VmStatePatch { state: "Paused" },
        Duration::from_millis(*FC_API_TIMEOUT_MS),
    )
    .await
}

/// Pause a running microVM (`PATCH /vm {state:Paused}`).
pub async fn pause(instance: &Instance) -> Result<(), LaunchError> {
    pause_at(&instance.api_socket_host).await
}

/// Resume a paused microVM by API-socket path (`PATCH /vm {state:Resumed}`).
///
/// Path-based sibling of [`resume`]; see [`pause_at`].
pub async fn resume_at(api_socket: &Path) -> Result<(), LaunchError> {
    api_patch(
        api_socket,
        "/vm",
        &VmStatePatch { state: "Resumed" },
        Duration::from_millis(*FC_API_TIMEOUT_MS),
    )
    .await
}

/// Resume a paused microVM (`PATCH /vm {state:Resumed}`).
pub async fn resume(instance: &Instance) -> Result<(), LaunchError> {
    resume_at(&instance.api_socket_host).await
}

/// Artifacts produced inside the chroot by `PUT /snapshot/create`.
pub struct SnapshotArtifacts {
    /// `{chroot}/snapshot/mem`
    pub mem_in_chroot: PathBuf,
    /// `{chroot}/snapshot/vmstate`
    pub vmstate_in_chroot: PathBuf,
}

/// Create a Full snapshot of a PAUSED microVM. Caller MUST pause first.
///
/// Writes mem + vmstate inside the jail chroot (FC can only write there);
/// the caller copies them out to the snapshots dir via the returned paths.
pub async fn snapshot_create(instance: &Instance) -> Result<SnapshotArtifacts, LaunchError> {
    snapshot_create_at(
        &instance.api_socket_host,
        &instance.jailer_chroot,
        instance.jailer_uid,
        instance.jailer_gid,
        instance.mem_size_mib,
    )
    .await
}

/// Create a Full snapshot of a PAUSED microVM given raw paths. Caller MUST
/// pause first.
///
/// Path-based sibling of [`snapshot_create`]: takes the FC API socket, the
/// jailer chroot, the jailer uid/gid (to chown the snapshot dir so FC can
/// write into it), and `mem_size_mib` (so the memory-scaled API deadline is
/// preserved — a multi-GiB dump needs headroom beyond the flat control-call
/// timeout). Lets the caller run the dump against captured paths without
/// borrowing the `Instance` or holding the registry lock across the dump.
pub async fn snapshot_create_at(
    api_socket: &Path,
    jailer_chroot: &Path,
    uid: u32,
    gid: u32,
    mem_size_mib: u32,
) -> Result<SnapshotArtifacts, LaunchError> {
    let snap_dir_in_chroot = jailer_chroot.join("snapshot");
    tokio::fs::create_dir_all(&snap_dir_in_chroot).await?;
    // Chown the snapshot dir to uid:gid so that Firecracker (which runs as
    // that uid/gid inside the jail) can write mem + vmstate into it. Mirrors
    // the same chown applied to the staged kernel/rootfs in
    // spawn_jailed_firecracker.
    chown(&snap_dir_in_chroot, uid, gid)?;
    api_put(
        api_socket,
        "/snapshot/create",
        &SnapshotCreateBody {
            snapshot_type: "Full",
            snapshot_path: "/snapshot/vmstate".into(),
            mem_file_path: "/snapshot/mem".into(),
        },
        scaled_api_timeout(mem_size_mib),
    )
    .await?;
    Ok(SnapshotArtifacts {
        mem_in_chroot: snap_dir_in_chroot.join("mem"),
        vmstate_in_chroot: snap_dir_in_chroot.join("vmstate"),
    })
}

/// Best-effort Firecracker version string, captured into the manifest.
///
/// Runs `{firecracker_binary} --version`, returns the first output line.
/// Returns `"unknown"` if the binary cannot be executed, exits non-zero,
/// or produces no output. Because this value lands in the signed manifest,
/// a failed invocation must not smuggle stderr/garbage in as a version.
pub async fn firecracker_version(firecracker_binary: &Path) -> String {
    match Command::new(firecracker_binary)
        .arg("--version")
        .output()
        .await
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string(),
        _ => "unknown".to_string(),
    }
}

/// Read the HTTP status line + headers from `reader`, returning the
/// status code and the value of the `Content-Length` header (0 if
/// absent). Leaves `reader` positioned at the start of the body.
async fn read_http_head<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<(u16, usize), LaunchError> {
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| LaunchError::Io(io::Error::other("malformed HTTP status line")))?;

    let mut content_length: usize = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::to_string)
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    Ok((status, content_length))
}

// ----------------------------------------------------------------------
// Firecracker API request bodies. We hand-roll the small subset we
// actually use; the full spec is in firecracker_spec-v1.13.1.yaml.
// ----------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
}

#[derive(Debug, Serialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

// Firecracker's API spec names the field `drive_id`; we match it to
// keep the serialized JSON byte-identical.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Serialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Serialize)]
struct Vsock {
    guest_cid: u32,
    uds_path: String,
}

#[derive(Debug, Serialize)]
struct Action {
    action_type: String,
}

// Firecracker /network-interfaces request body.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Serialize)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
}

#[derive(Debug, Serialize)]
struct VmStatePatch {
    state: &'static str, // "Paused" | "Resumed"
}

#[derive(Debug, Serialize)]
struct SnapshotCreateBody {
    snapshot_type: &'static str, // "Full"
    snapshot_path: String,       // chroot-relative, e.g. "/snapshot/vmstate"
    mem_file_path: String,       // chroot-relative, e.g. "/snapshot/mem"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tokio::net::UnixListener;

    struct FakeChild {
        start_kill_error: bool,
        wait_error: bool,
    }

    impl ChildControl for FakeChild {
        fn try_wait_control(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
            Ok(None)
        }

        fn start_kill_control(&mut self) -> io::Result<()> {
            if self.start_kill_error {
                Err(io::Error::other("injected start_kill failure"))
            } else {
                Ok(())
            }
        }

        async fn wait_control(&mut self) -> io::Result<std::process::ExitStatus> {
            if self.wait_error {
                Err(io::Error::other("injected wait failure"))
            } else {
                Ok(std::process::ExitStatus::from_raw(0))
            }
        }
    }

    fn injected_primary() -> LaunchError {
        LaunchError::Io(io::Error::other("injected primary failure"))
    }

    #[tokio::test]
    async fn cold_cleanup_keeps_tree_when_start_kill_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("owned");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(root.join("sentinel"), b"live")
            .await
            .unwrap();
        let mut child = FakeChild {
            start_kill_error: true,
            wait_error: false,
        };

        let error = cleanup_failed_child(
            &mut child,
            &root,
            "Firecracker configuration",
            injected_primary(),
        )
        .await;

        assert!(matches!(error, LaunchError::TerminationFailed(_)));
        assert!(error.to_string().contains("injected primary failure"));
        assert!(
            root.join("sentinel").exists(),
            "live child's tree was removed"
        );
    }

    #[tokio::test]
    async fn restore_cleanup_keeps_tree_when_reap_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("owned");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(root.join("sentinel"), b"live")
            .await
            .unwrap();
        let mut child = FakeChild {
            start_kill_error: false,
            wait_error: true,
        };

        let error =
            cleanup_failed_child(&mut child, &root, "snapshot restore", injected_primary()).await;

        assert!(matches!(error, LaunchError::TerminationFailed(_)));
        assert!(error.to_string().contains("injected wait failure"));
        assert!(
            root.join("sentinel").exists(),
            "unreaped child's tree was removed"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_tree_only_after_confirmed_reap() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("owned");
        tokio::fs::create_dir(&root).await.unwrap();
        let mut child = FakeChild {
            start_kill_error: false,
            wait_error: false,
        };

        let error = cleanup_failed_child(&mut child, &root, "restore", injected_primary()).await;

        assert!(matches!(error, LaunchError::Io(_)));
        assert!(!root.exists());
    }

    /// Spawn a fake vsock-style UDS server that accepts one connection,
    /// completes the `CONNECT` handshake by writing `"OK 0\n"`, then
    /// hangs forever without sending the response payload. Returns the
    /// path the server is listening on (caller owns the tempdir).
    fn spawn_wedged_uds_server(dir: &Path) -> PathBuf {
        let sock = dir.join("fake.sock");
        let listener = UnixListener::bind(&sock).expect("bind fake uds");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (rd, mut wr) = stream.split();
                let mut reader = BufReader::new(rd);
                let mut line = String::new();
                let _ = reader.read_line(&mut line).await;
                let _ = wr.write_all(b"OK 0\n").await;
                // Now hang forever — never write the response.
                std::future::pending::<()>().await;
            }
        });
        sock
    }

    #[tokio::test]
    async fn vsock_request_response_honors_timeout() {
        use ne_protocol::guest::{GuestRequest, RunCommandRequest};
        let tmp = tempfile::tempdir().expect("tmp");
        let sock = spawn_wedged_uds_server(tmp.path());
        let req = GuestRequest::RunCommand(RunCommandRequest {
            command: "/bin/true".into(),
            args: vec![],
            timeout_ms: 1_000,
        });
        let start = Instant::now();
        let result = vsock_request_response(&sock, 52, &req, 100).await;
        let elapsed = start.elapsed();
        match result {
            Err(GuestRpcError::Timeout(ms)) => assert_eq!(ms, 100),
            other => panic!("expected Timeout(100), got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_millis(500),
            "timeout enforcement should be tight; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn vsock_request_response_returns_ok_within_budget() {
        use ne_protocol::guest::{GuestRequest, GuestResponse};
        let tmp = tempfile::tempdir().expect("tmp");
        let sock = tmp.path().join("ok.sock");
        let listener = UnixListener::bind(&sock).expect("bind ok uds");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (rd, mut wr) = stream.split();
                let mut reader = BufReader::new(rd);
                let mut handshake = String::new();
                let _ = reader.read_line(&mut handshake).await;
                let _ = wr.write_all(b"OK 0\n").await;
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                // Reply with a Pong.
                let pong = serde_json::json!({
                    "status": "pong",
                    "agent_version": "test",
                    "uptime_ms": 0,
                });
                let mut payload = serde_json::to_vec(&pong).unwrap();
                payload.push(b'\n');
                let _ = wr.write_all(&payload).await;
            }
        });
        let result = vsock_request_response(&sock, 52, &GuestRequest::Ping, 5_000).await;
        match result {
            Ok(GuestResponse::Pong { .. }) => {}
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vsock_request_response_with_zero_timeout_completes() {
        use ne_protocol::guest::{GuestRequest, GuestResponse};

        let tmp = tempfile::tempdir().expect("tmp");
        let sock = tmp.path().join("zero.sock");
        let listener = UnixListener::bind(&sock).expect("bind zero uds");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (rd, mut wr) = stream.split();
                let mut reader = BufReader::new(rd);
                let mut handshake = String::new();
                let _ = reader.read_line(&mut handshake).await;
                let _ = wr.write_all(b"OK 0\n").await;
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;
                let pong = serde_json::json!({
                    "status": "pong",
                    "agent_version": "test",
                    "uptime_ms": 0,
                });
                let mut payload = serde_json::to_vec(&pong).unwrap();
                payload.push(b'\n');
                let _ = wr.write_all(&payload).await;
            }
        });

        // timeout_ms = 0 is clamped up to MAX_EXEC_TIMEOUT_MS (the ceiling,
        // ~1h default), so the call still completes promptly against a
        // responsive server. Wrap the whole call in an outer 2-second guard so
        // a regression that accidentally hangs doesn't hang the test runner.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            vsock_request_response(&sock, 52, &GuestRequest::Ping, 0),
        )
        .await
        .expect("outer guard should not fire — server replies promptly");
        match result {
            Ok(GuestResponse::Pong { .. }) => {}
            other => panic!("expected Pong on zero-timeout path, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_state_default_is_running() {
        // Compile-time check: WorkspaceState::Running is accessible from this module.
        let state = ne_protocol::supervisor::WorkspaceState::Running;
        let s = serde_json::to_string(&state).unwrap();
        // WorkspaceState is #[serde(rename_all = "snake_case")].
        assert_eq!(s, r#""running""#);
    }

    #[test]
    fn jailer_id_validator_accepts_dashes_and_alnum() {
        assert!(is_valid_jailer_id("wks-01jabcdef"));
        assert!(is_valid_jailer_id("wks-it-12345"));
        assert!(
            !is_valid_jailer_id("wks_01j"),
            "underscore should be rejected"
        );
        assert!(!is_valid_jailer_id(""), "empty should be rejected");
        assert!(
            !is_valid_jailer_id(&"a".repeat(65)),
            "too long should be rejected"
        );
        assert!(!is_valid_jailer_id("wks/01j"), "slash should be rejected");
    }

    #[tokio::test]
    async fn read_http_head_parses_204_no_content() {
        let raw = b"HTTP/1.0 204 No Content\r\nServer: Firecracker\r\nContent-Length: 0\r\n\r\n";
        let mut reader = BufReader::new(&raw[..]);
        let (status, len) = read_http_head(&mut reader).await.expect("parse 204");
        assert_eq!(status, 204);
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn read_http_head_parses_400_with_body_length() {
        let body = br#"{"fault_message":"bad request"}"#;
        let mut raw = Vec::new();
        raw.extend_from_slice(b"HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        raw.extend_from_slice(body);
        let mut reader = BufReader::new(&raw[..]);
        let (status, len) = read_http_head(&mut reader).await.expect("parse 400");
        assert_eq!(status, 400);
        assert_eq!(len, body.len());
    }

    #[tokio::test]
    async fn wait_for_guest_ready_times_out_on_dead_socket() {
        // No listener at this path → readiness never succeeds → Timeout.
        let tmp = tempfile::tempdir().expect("tmp");
        let sock = tmp.path().join("nope.sock");
        let start = Instant::now();
        let res = wait_for_guest_ready(&sock, 52, Duration::from_millis(300)).await;
        assert!(matches!(res, Err(GuestRpcError::Timeout(_))), "got {res:?}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "should give up promptly"
        );
    }

    #[tokio::test]
    async fn reset_identity_via_vsock_relays_pong_style_reply() {
        use ne_protocol::guest::GuestResponse;
        let tmp = tempfile::tempdir().expect("tmp");
        let sock = tmp.path().join("reset.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let (rd, mut wr) = stream.split();
                let mut reader = BufReader::new(rd);
                let mut hs = String::new();
                let _ = reader.read_line(&mut hs).await;
                let _ = wr.write_all(b"OK 0\n").await;
                let mut req = String::new();
                let _ = reader.read_line(&mut req).await;
                let reply = serde_json::json!({
                    "status": "identity_reset",
                    "hostname": "fork-a",
                    "machine_id": "0123456789abcdef0123456789abcdef",
                });
                let mut payload = serde_json::to_vec(&reply).unwrap();
                payload.push(b'\n');
                let _ = wr.write_all(&payload).await;
            }
        });
        let resp = reset_identity_via_vsock(
            &sock,
            52,
            "fork-a".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
            vec![1u8; 32],
            5_000,
        )
        .await
        .expect("reset");
        match resp {
            GuestResponse::IdentityReset { hostname, .. } => assert_eq!(hostname, "fork-a"),
            other => panic!("expected IdentityReset, got {other:?}"),
        }
    }

    /// Regression test for the golden-image corruption bug: two concurrent
    /// managed-image stages racing on the SAME `dst` path (the exact shape of
    /// the `create_race` concurrency test, where two same-id creates derive
    /// the identical chroot path). Pre-fix, `stage_file` staged in place —
    /// `if dst.exists() { remove_file }` → `hard_link` → fallback `copy` —
    /// which has a TOCTOU window: both racers can observe `!dst.exists()`,
    /// one wins the hardlink, the other's `hard_link` then fails EEXIST and
    /// falls to `copy(src, dst)`. Since `dst` is now a hardlink to `src`
    /// (the winner's link), `copy`'s truncate-on-open zeroes the shared
    /// inode — i.e. it destroys `src` too. This was observed for real as a
    /// 0-byte `vmlinux` / "Unable to read elf header" during the image-staging
    /// KVM gauntlet.
    ///
    /// Managed staging retains independently verified source handles and
    /// creates the destination exclusively. Exactly one racer owns the
    /// destination; the loser fails closed without opening either existing
    /// inode for writing.
    #[tokio::test]
    async fn managed_stage_concurrent_same_dst_never_corrupts_source() {
        use crate::image::{ImageKind, ImageStore};
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt as _;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let golden = b"GOLDEN-KERNEL-IMAGE-DO-NOT-TRUNCATE-ME".to_vec();
        let digest = hex::encode(sha2::Sha256::digest(&golden));
        let src = tmp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(src.parent().expect("managed kernel parent"))
            .await
            .expect("create managed kernel parent");
        tokio::fs::write(&src, &golden).await.expect("write src");
        let metadata = std::fs::metadata(&src).expect("source metadata");
        let store = ImageStore::new(tmp.path().to_path_buf());
        let dst = tmp.path().join("staged.img");

        for iter in 0..200 {
            let _ = tokio::fs::remove_file(&dst).await;
            let mut first = store
                .resolve(ImageKind::Kernel, &digest)
                .await
                .expect("resolve first retained handle");
            let mut second = store
                .resolve(ImageKind::Kernel, &digest)
                .await
                .expect("resolve second retained handle");

            // Exactly two racers on the identical dst path — the literal
            // shape of the reported race (two concurrent same-id creates
            // sharing one chroot dst path).
            let (r1, r2) = tokio::join!(
                first.stage(&dst, 0o400, metadata.uid(), metadata.gid()),
                second.stage(&dst, 0o400, metadata.uid(), metadata.gid())
            );
            assert_ne!(
                r1.is_ok(),
                r2.is_ok(),
                "iter {iter}: exclusive destination creation must select exactly one owner"
            );

            let src_now = tokio::fs::read(&src).await.expect("read src");
            assert_eq!(
                src_now, golden,
                "iter {iter}: golden source image was corrupted by a concurrent \
                 managed-stage race"
            );
            assert_eq!(
                tokio::fs::read(&dst).await.expect("read staged image"),
                golden,
                "iter {iter}: winning stage must publish the verified image"
            );
        }
    }

    /// Defense-in-depth: even a single managed-image stage that happens to
    /// find `dst` already hardlinked to `src` (e.g. left behind by a prior
    /// staging attempt) must never truncate through that shared inode.
    /// Managed staging never opens a pre-existing destination for writing.
    #[tokio::test]
    async fn managed_stage_preexisting_hardlink_dst_leaves_source_intact() {
        use crate::image::{ImageError, ImageKind, ImageStore};
        use sha2::Digest as _;
        use std::os::unix::fs::MetadataExt as _;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let golden = b"ANOTHER-GOLDEN-IMAGE-PAYLOAD".to_vec();
        let digest = hex::encode(sha2::Sha256::digest(&golden));
        let src = tmp.path().join("kernels").join(&digest).join("vmlinux");
        tokio::fs::create_dir_all(src.parent().expect("managed kernel parent"))
            .await
            .expect("create managed kernel parent");
        tokio::fs::write(&src, &golden).await.expect("write src");
        let metadata = std::fs::metadata(&src).expect("source metadata");
        let mut verified = ImageStore::new(tmp.path().to_path_buf())
            .resolve(ImageKind::Kernel, &digest)
            .await
            .expect("resolve retained image handle");

        let dst = tmp.path().join("staged.img");
        tokio::fs::hard_link(&src, &dst)
            .await
            .expect("pre-link dst to src (simulate a prior racer's win)");

        let error = verified
            .stage(&dst, 0o400, metadata.uid(), metadata.gid())
            .await
            .expect_err("exclusive staging must reject a pre-existing destination");
        assert!(matches!(error, ImageError::Stage { .. }));

        let src_now = tokio::fs::read(&src).await.expect("read src");
        assert_eq!(
            src_now, golden,
            "source must survive staging onto a pre-linked dst"
        );
        let dst_now = tokio::fs::read(&dst).await.expect("read dst");
        assert_eq!(
            dst_now, golden,
            "dst must contain the golden content after staging"
        );
    }

    // NE_FC_API_TIMEOUT_MS itself is env-dependent + process-global
    // (LazyLock), so its parsing is tested via the pure `parse_api_timeout_ms`
    // helper instead of racy `std::env::set_var` manipulation — mirrors
    // `util::parse_ceiling`'s test strategy for `NE_MAX_EXEC_TIMEOUT_MS`.
    #[test]
    fn parse_api_timeout_ms_rejects_zero_and_garbage() {
        assert_eq!(parse_api_timeout_ms(None), 30_000);
        assert_eq!(parse_api_timeout_ms(Some("0".into())), 30_000);
        assert_eq!(parse_api_timeout_ms(Some("not-a-number".into())), 30_000);
        assert_eq!(parse_api_timeout_ms(Some("5000".into())), 5_000);
    }

    #[test]
    fn scaled_api_timeout_adds_per_mib_budget() {
        let base = *FC_API_TIMEOUT_MS;
        assert_eq!(
            scaled_api_timeout(0),
            Duration::from_millis(base),
            "zero-MiB VM should see exactly the flat control-call deadline"
        );
        assert_eq!(
            scaled_api_timeout(4096),
            Duration::from_millis(base + 4096 * PER_MIB_MS),
            "a 4 GiB VM should get the flat deadline plus its memory-scaled budget"
        );
    }
}

/// Memory backend descriptor for `PUT /snapshot/load`.
#[derive(Debug, Serialize)]
struct MemBackend {
    backend_type: &'static str, // "File"
    backend_path: String,       // chroot-relative "/snapshot/mem"
}

/// Request body for `PUT /snapshot/load`.
#[derive(Debug, Serialize)]
struct SnapshotLoadBody {
    snapshot_path: String, // chroot-relative "/snapshot/vmstate"
    mem_backend: MemBackend,
    enable_diff_snapshots: bool,
    resume_vm: bool,
}

/// Inputs to restore a workspace from a snapshot artifact.
pub struct RestoreLaunchConfig {
    /// Reuses the cold-boot [`LaunchConfig`] fields (binaries, `chroot_base`,
    /// jailer uid/gid, verified managed images, and timeouts). `network` MUST
    /// be `None` for this implementation — networked restore is not supported (FC
    /// records the host TAP name in vmstate; restoring into a different
    /// `workspace_id` would reference a non-existent TAP).
    /// `workspace_id` is the NEW id (ws-B, the restored workspace).
    pub launch: LaunchConfig,
    /// Host path to the memory snapshot artifact file (in the snapshots dir).
    pub mem_source: PathBuf,
    /// Host path to the vmstate snapshot artifact file (in the snapshots dir).
    pub vmstate_source: PathBuf,
}

/// Restore a fresh, running microVM from a snapshot artifact.
///
/// Boots a jailed Firecracker (via [`spawn_jailed_firecracker`]), stages the
/// snapshot mem/vmstate files into the new chroot, then issues a single
/// `PUT /snapshot/load` with `resume_vm: true`. No machine-config/boot-source/
/// drives/vsock/actions are sent — FC restores those from vmstate.
///
/// # Errors
///
/// Returns [`LaunchError::ApiRequest`] immediately if `cfg.launch.network` is
/// `Some` — networked snapshot restore is not supported in this build.
///
// VM-VALIDATION NOTES (resolved empirically in the T13 e2e on a KVM host):
// 1. vsock on load: confirm FC re-creates the host vsock listener at the
//    chroot-relative uds_path recorded in vmstate; if FC needs the host UDS
//    parent pre-created, ensure {chroot}/ exists (it does after spawn).
// 2. rootfs drive path: vmstate records drive path_on_host as the chroot-
//    relative path used at snapshot time (/rootfs.img); spawn_jailed_firecracker
//    stages rootfs there — confirm the path matches exactly.
// 3. FC version skew: if /snapshot/load returns a version-incompat error, the
//    caller surfaces it as RestoreFailed (manifest records firecracker_version).
pub async fn restore(mut cfg: RestoreLaunchConfig) -> Result<Instance, LaunchError> {
    if cfg.launch.network.is_some() {
        return Err(LaunchError::NetworkedRestoreUnsupported);
    }
    let (kernel_sha256, rootfs_sha256) = cfg.launch.verified_images.digests();
    let kernel_sha256 = kernel_sha256.to_owned();
    let rootfs_sha256 = rootfs_sha256.to_owned();
    // Boot the jailed FC (stages rootfs+kernel, waits for api socket).
    let jailed = spawn_jailed_firecracker(&mut cfg.launch).await?;

    // Stage the snapshot mem/vmstate into the chroot and issue the load.
    // Capture the first error rather than `?`-ing out: restore copies a
    // potentially GB-scale mem image into the chroot, so on a failed load
    // (FC version skew, corrupt vmstate, etc.) we must reap that tree
    // instead of stranding it. (`launch` has the same latent chroot-on-error
    // leak; restore cleans up here because it stages a full mem image.)
    let staged: Result<(), LaunchError> = async {
        // Stage snapshot files into the chroot where FC (jailed) can read them.
        let snap_in_chroot = jailed.jailer_chroot.join("snapshot");
        tokio::fs::create_dir_all(&snap_in_chroot).await?;
        tokio::fs::copy(&cfg.mem_source, snap_in_chroot.join("mem")).await?;
        tokio::fs::copy(&cfg.vmstate_source, snap_in_chroot.join("vmstate")).await?;
        // chown the snapshot dir + staged files to jailer_uid:jailer_gid so the
        // jailed FC can read them. Mirrors the same chown pattern applied in
        // snapshot_create (snap_dir_in_chroot) and spawn_jailed_firecracker
        // (kernel + rootfs) — FC runs inside the jail as this uid/gid and cannot
        // read files owned by root.
        chown(
            &snap_in_chroot,
            cfg.launch.jailer_uid,
            cfg.launch.jailer_gid,
        )?;
        chown(
            &snap_in_chroot.join("mem"),
            cfg.launch.jailer_uid,
            cfg.launch.jailer_gid,
        )?;
        chown(
            &snap_in_chroot.join("vmstate"),
            cfg.launch.jailer_uid,
            cfg.launch.jailer_gid,
        )?;

        api_put(
            &jailed.api_socket_host,
            "/snapshot/load",
            &SnapshotLoadBody {
                snapshot_path: "/snapshot/vmstate".into(),
                mem_backend: MemBackend {
                    backend_type: "File",
                    backend_path: "/snapshot/mem".into(),
                },
                enable_diff_snapshots: false,
                resume_vm: true,
            },
            scaled_api_timeout(cfg.launch.mem_size_mib),
        )
        .await?;
        Ok(())
    }
    .await;

    match staged {
        Ok(()) => {
            info!(workspace_id = %cfg.launch.workspace_id, "snapshot load sent — VM resumed");
            Ok(Instance {
                workspace_id: cfg.launch.workspace_id,
                boot_id: ulid::Ulid::new().to_string(),
                child: jailed.child,
                firecracker_pid: jailed.firecracker_pid,
                api_socket_host: jailed.api_socket_host,
                vsock_host_socket: jailed.vsock_host_socket,
                jailer_chroot: jailed.jailer_chroot,
                jailer_uid: cfg.launch.jailer_uid,
                jailer_gid: cfg.launch.jailer_gid,
                lifecycle_state: ne_protocol::supervisor::WorkspaceState::Running,
                // Networked restore is rejected above; restored VMs are always
                // non-networked in this implementation.
                network_slot: None,
                // Snapshot manifest metadata — captured from the restore config.
                guest_vsock_cid: cfg.launch.guest_vsock_cid,
                vcpu_count: cfg.launch.vcpu_count,
                mem_size_mib: cfg.launch.mem_size_mib,
                kernel_boot_args: cfg.launch.kernel_boot_args,
                kernel_sha256,
                rootfs_sha256,
                rootfs_read_only: cfg.launch.rootfs_read_only,
            })
        }
        Err(e) => {
            // Kill the jailer child FIRST (ordering matters — never remove a
            // chroot still in use by a live jailer), then reap the chroot tree
            // including the GB-scale mem copy we staged.
            let mut jailed = jailed;
            Err(cleanup_failed_child(
                &mut jailed.child,
                &jailed.workspace_root,
                "snapshot restore",
                e,
            )
            .await)
        }
    }
}

#[cfg(test)]
mod snapshot_body_tests {
    use super::*;

    #[test]
    fn vm_state_patch_serializes() {
        let body = VmStatePatch { state: "Paused" };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"state":"Paused"}"#
        );
    }

    #[test]
    fn snapshot_create_body_serializes() {
        let body = SnapshotCreateBody {
            snapshot_type: "Full",
            snapshot_path: "/snapshot/vmstate".into(),
            mem_file_path: "/snapshot/mem".into(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        assert_eq!(v["snapshot_type"], "Full");
        assert_eq!(v["mem_file_path"], "/snapshot/mem");
    }

    #[test]
    fn snapshot_load_body_serializes() {
        let body = SnapshotLoadBody {
            snapshot_path: "/snapshot/vmstate".into(),
            mem_backend: MemBackend {
                backend_type: "File",
                backend_path: "/snapshot/mem".into(),
            },
            enable_diff_snapshots: false,
            resume_vm: true,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        assert_eq!(v["mem_backend"]["backend_type"], "File");
        assert_eq!(v["resume_vm"], true);
    }
}

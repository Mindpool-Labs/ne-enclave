// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Baseline command-execution integration test:
//! "Boot, run one command, destroy. Verify cleanup."
//!
//! Builds on `firecracker_lifecycle.rs` (boot + destroy + cleanup)
//! by also reaching into the guest over vsock and asking the
//! `ne-guest-agent` to run `/bin/echo hello, enclave`. Expects
//! `GuestResponse::CommandCompleted { stdout: "hello, enclave\n", ... }`.
//!
//! Skipped by default — annotated `#[ignore]` because it requires:
//!   - the Buildroot-produced vmlinux + rootfs at
//!     `target/images/standard/images/{vmlinux,rootfs.ext2}`
//!     (run `cargo run -p ne-image -- build` first);
//!   - `/dev/kvm` + nested virt (only a KVM-capable host);
//!   - `sudo -n` (NOPASSWD `sudo` for the `ne` service user — either broad
//!     or a focused fragment in `/etc/sudoers.d/`);
//!   - write access to `/srv/jailer/firecracker/{wks_id}/`.
//!
//! Run with: `cargo test --test run_command_e2e -- --ignored`.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ne_protocol::guest::{
    GuestRequest, GuestResponse, RunCommandRequest as GuestRunCommandRequest,
};
use ne_protocol::supervisor::{
    CreateWorkspaceRequest, RunCommandRequest as SupervisorRunCommandRequest, SupervisorRequest,
    SupervisorResponse, TerminateRequest,
};
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::time::sleep;

const FIRECRACKER: &str = "/opt/ne-enclave/bin/firecracker";
const JAILER: &str = "/opt/ne-enclave/bin/jailer";
const CHROOT_BASE: &str = "/srv/jailer";

#[tokio::test]
#[ignore = "boots the test image and round-trips a command via vsock; \
           needs ne-image build + sudo NOPASSWD on a KVM-capable host"]
async fn run_command_round_trips_through_vsock() {
    let (kernel, rootfs) = locate_runtime_artifacts();

    let socket = format!("/tmp/ne-rc-{}.sock", std::process::id());
    let workspace_id = format!("wks-rc-{}", std::process::id());
    let supervisor_bin = ne_binary();
    let (image_store, kernel_sha256, rootfs_sha256) =
        prepare_managed_images(&kernel, &rootfs, "direct");

    let mut supervisor = Command::new("sudo")
        .arg("-n")
        .arg(supervisor_bin)
        .arg("serve-supervisor")
        .arg("--dev-mode")
        .arg("--socket")
        .arg(&socket)
        .arg("--firecracker-binary")
        .arg(FIRECRACKER)
        .arg("--jailer-binary")
        .arg(JAILER)
        .arg("--jailer-chroot-base")
        .arg(CHROOT_BASE)
        .arg("--image-store")
        .arg(&image_store)
        .arg("--jailer-uid")
        .arg("1000")
        .arg("--jailer-gid")
        .arg("1000")
        .kill_on_drop(true)
        .spawn()
        .expect("spawn supervisor under sudo");

    wait_for_socket(&socket, Duration::from_secs(5)).await;

    // Boot the test image.
    let create = SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
        workspace_id: workspace_id.clone(),
        kernel_sha256,
        rootfs_sha256,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 256,
        guest_vsock_cid: 3,
        kernel_boot_args: None,
        network: None,
        tier: None,
    });
    let (chroot, vsock_uds) = match send_one(&socket, &create).await {
        SupervisorResponse::WorkspaceCreated(created) => (
            PathBuf::from(created.jailer_chroot),
            PathBuf::from(created.vsock_host_socket),
        ),
        other => panic!("CreateWorkspace → {other:?}"),
    };

    // Talk to the guest agent over vsock. The agent listens on port
    // 52 (default). Firecracker's host-to-guest UDS contract: connect
    // to the base UDS, send `CONNECT <guest_port>\n`, read `OK <fc_port>\n`
    // back. The guest agent isn't listening the instant Firecracker
    // boots, so we retry until userspace + agent are up (bounded ≤15s).
    let agent_response = connect_and_run_command(&vsock_uds, 52, Duration::from_secs(15))
        .await
        .expect("vsock round-trip to guest agent");

    match agent_response {
        GuestResponse::CommandCompleted(c) => {
            assert_eq!(c.exit_code, 0, "agent: {c:?}");
            assert!(
                c.stdout.contains("hello, enclave"),
                "stdout was {:?}",
                c.stdout
            );
        }
        other => panic!("agent returned {other:?}"),
    }

    // Tear down and verify cleanup.
    let term = SupervisorRequest::Terminate(TerminateRequest {
        workspace_id: workspace_id.clone(),
        grace_period_ms: 2_000,
    });
    match send_one(&socket, &term).await {
        SupervisorResponse::WorkspaceTerminated { workspace_id: id } => {
            assert_eq!(id, workspace_id);
        }
        other => panic!("Terminate → {other:?}"),
    }
    let workspace_root = format!("{CHROOT_BASE}/firecracker/{workspace_id}");
    assert!(
        !Path::new(&workspace_root).exists(),
        "{workspace_root} must be cleaned up"
    );
    let _ = chroot;

    let _ = supervisor.kill().await;
}

/// Same lifecycle as the test above, but routes the `RunCommand`
/// through the supervisor's IPC (`SupervisorRequest::RunCommand`)
/// instead of having the test client open the vsock UDS directly.
/// Exercises the path an SDK takes via `ne-api` → supervisor →
/// guest agent, without the gRPC hop on top.
#[tokio::test]
#[ignore = "boots a real Firecracker microVM via jailer + relays RunCommand \
           through the supervisor's IPC; needs /opt/ne-enclave/* + sudo NOPASSWD"]
async fn run_command_via_supervisor_ipc_round_trip() {
    let (kernel, rootfs) = locate_runtime_artifacts();

    let socket = format!("/tmp/ne-rc2-{}.sock", std::process::id());
    let workspace_id = format!("wks-rc2-{}", std::process::id());
    let supervisor_bin = ne_binary();
    let (image_store, kernel_sha256, rootfs_sha256) =
        prepare_managed_images(&kernel, &rootfs, "ipc");

    let mut supervisor = Command::new("sudo")
        .arg("-n")
        .arg(supervisor_bin)
        .arg("serve-supervisor")
        .arg("--dev-mode")
        .arg("--socket")
        .arg(&socket)
        .arg("--firecracker-binary")
        .arg(FIRECRACKER)
        .arg("--jailer-binary")
        .arg(JAILER)
        .arg("--jailer-chroot-base")
        .arg(CHROOT_BASE)
        .arg("--image-store")
        .arg(&image_store)
        .arg("--jailer-uid")
        .arg("1000")
        .arg("--jailer-gid")
        .arg("1000")
        .kill_on_drop(true)
        .spawn()
        .expect("spawn supervisor under sudo");

    wait_for_socket(&socket, Duration::from_secs(5)).await;

    // CreateWorkspace.
    let create = SupervisorRequest::CreateWorkspace(CreateWorkspaceRequest {
        workspace_id: workspace_id.clone(),
        kernel_sha256,
        rootfs_sha256,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 256,
        guest_vsock_cid: 3,
        kernel_boot_args: None,
        network: None,
        tier: None,
    });
    match send_one(&socket, &create).await {
        SupervisorResponse::WorkspaceCreated(_) => {}
        other => panic!("CreateWorkspace → {other:?}"),
    }

    // Poll RunCommand until the guest agent is up. Same ~15s bound
    // as the direct-vsock test; on this VM the agent is reachable in
    // ~150ms post-boot.
    let deadline = Instant::now() + Duration::from_secs(15);
    let completed = loop {
        let req = SupervisorRequest::RunCommand(SupervisorRunCommandRequest {
            workspace_id: workspace_id.clone(),
            guest_port: 52,
            command: "/bin/echo".to_string(),
            args: vec!["hello via supervisor".to_string()],
            timeout_ms: 5_000,
        });
        match send_one(&socket, &req).await {
            SupervisorResponse::CommandCompleted(c) => break c,
            SupervisorResponse::Error {
                kind: ne_protocol::supervisor::SupervisorErrorKind::GuestUnreachable,
                message,
            } => {
                assert!(
                    Instant::now() < deadline,
                    "guest agent never reachable: {message}"
                );
                sleep(Duration::from_millis(200)).await;
            }
            other => panic!("RunCommand → {other:?}"),
        }
    };
    assert_eq!(completed.workspace_id, workspace_id);
    assert_eq!(completed.exit_code, 0);
    assert!(
        completed.stdout.contains("hello via supervisor"),
        "stdout was {:?}",
        completed.stdout
    );

    // Tear down.
    let term = SupervisorRequest::Terminate(TerminateRequest {
        workspace_id: workspace_id.clone(),
        grace_period_ms: 2_000,
    });
    match send_one(&socket, &term).await {
        SupervisorResponse::WorkspaceTerminated { workspace_id: id } => {
            assert_eq!(id, workspace_id);
        }
        other => panic!("Terminate → {other:?}"),
    }
    let workspace_root = format!("{CHROOT_BASE}/firecracker/{workspace_id}");
    assert!(
        !Path::new(&workspace_root).exists(),
        "{workspace_root} must be cleaned up"
    );

    let _ = supervisor.kill().await;
}

/// Resolve the fused `nee` binary. `CARGO_BIN_EXE_nee` isn't set
/// for bin-only dev-deps, so: honor `NE_BIN` first, then build
/// `<CARGO_TARGET_DIR | <workspace>/target>/<profile>/nee`. Defaults
/// to the `debug` profile; release/CI runs set `NE_BIN` explicitly.
fn ne_binary() -> PathBuf {
    if let Ok(path) = std::env::var("NE_BIN") {
        return PathBuf::from(path);
    }
    let target_base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("workspace root above CARGO_MANIFEST_DIR")
                .join("target")
        },
        PathBuf::from,
    );
    target_base.join("debug").join("nee")
}

fn locate_runtime_artifacts() -> (PathBuf, PathBuf) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = PathBuf::from(manifest_dir)
        .parent()
        .expect("repo root")
        .parent()
        .unwrap()
        .to_path_buf();
    let images = repo_root.join("target/images/standard/images");
    let kernel = images.join("vmlinux");
    let rootfs = images.join("rootfs.ext2");
    assert!(
        kernel.is_file(),
        "missing {} — run `cargo run -p ne-image -- build` first",
        kernel.display()
    );
    assert!(rootfs.is_file(), "missing {}", rootfs.display());
    (kernel, rootfs)
}

fn prepare_managed_images(kernel: &Path, rootfs: &Path, suffix: &str) -> (PathBuf, String, String) {
    let store = PathBuf::from(format!("/tmp/ne-rc-images-{}-{suffix}", std::process::id()));
    let kernel_bytes = std::fs::read(kernel).expect("read kernel");
    let rootfs_bytes = std::fs::read(rootfs).expect("read rootfs");
    let kernel_sha256 = hex::encode(sha2::Sha256::digest(&kernel_bytes));
    let rootfs_sha256 = hex::encode(sha2::Sha256::digest(&rootfs_bytes));
    let kernel_dst = store.join("kernels").join(&kernel_sha256).join("vmlinux");
    let rootfs_dst = store.join("rootfs").join(&rootfs_sha256).join("rootfs.img");
    std::fs::create_dir_all(kernel_dst.parent().unwrap()).expect("kernel store dir");
    std::fs::create_dir_all(rootfs_dst.parent().unwrap()).expect("rootfs store dir");
    std::fs::write(kernel_dst, kernel_bytes).expect("managed kernel");
    std::fs::write(rootfs_dst, rootfs_bytes).expect("managed rootfs");
    (store, kernel_sha256, rootfs_sha256)
}

async fn connect_and_run_command(
    uds: &Path,
    guest_port: u32,
    timeout: Duration,
) -> std::io::Result<GuestResponse> {
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<std::io::Error> = None;
    while Instant::now() < deadline {
        match try_connect_and_send(uds, guest_port).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("vsock connect timed out")))
}

async fn try_connect_and_send(uds: &Path, guest_port: u32) -> std::io::Result<GuestResponse> {
    let stream = UnixStream::connect(uds).await?;
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // Firecracker host→guest CONNECT handshake.
    wr.write_all(format!("CONNECT {guest_port}\n").as_bytes())
        .await?;
    let mut handshake = String::new();
    reader.read_line(&mut handshake).await?;
    if !handshake.starts_with("OK ") {
        return Err(std::io::Error::other(format!(
            "vsock CONNECT rejected: {}",
            handshake.trim_end()
        )));
    }

    // We are now byte-piped to the guest agent on its listening port.
    let req = GuestRequest::RunCommand(GuestRunCommandRequest {
        command: "/bin/echo".to_string(),
        args: vec!["hello, enclave".to_string()],
        timeout_ms: 5_000,
    });
    let mut body = serde_json::to_vec(&req).map_err(std::io::Error::other)?;
    body.push(b'\n');
    wr.write_all(&body).await?;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    serde_json::from_str::<GuestResponse>(line.trim_end()).map_err(std::io::Error::other)
}

async fn wait_for_socket(socket: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !Path::new(socket).exists() {
        assert!(
            Instant::now() <= deadline,
            "supervisor socket {socket} never appeared within {timeout:?}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn send_one(socket: &str, req: &SupervisorRequest) -> SupervisorResponse {
    let stream = UnixStream::connect(socket).await.expect("client connect");
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut body = serde_json::to_vec(req).expect("serialize");
    body.push(b'\n');
    wr.write_all(&body).await.expect("write request");
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    serde_json::from_str(line.trim_end()).expect("parse response")
}

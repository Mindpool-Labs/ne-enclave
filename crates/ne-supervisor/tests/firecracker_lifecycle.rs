// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage: boot one Firecracker microVM through
//! the supervisor and tear it down, asserting host resource cleanup.
//!
//! Skipped by default — annotated `#[ignore]` because it:
//!   - spawns a real Firecracker via jailer (needs `/dev/kvm` + nested
//!     virt — only a KVM-capable host is set up for this);
//!   - re-execs the supervisor under `sudo -n` (needs NOPASSWD `sudo`
//!     configured for the `ne` service user on the host);
//!   - writes to `/srv/jailer/firecracker/{wks_id}/`.
//!
//! Run with: `cargo test --test firecracker_lifecycle -- --ignored`.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ne_protocol::supervisor::{
    CreateWorkspaceRequest, SupervisorRequest, SupervisorResponse, TerminateRequest,
};
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::time::sleep;

const KERNEL: &str = "/opt/ne-enclave/kernel/vmlinux";
const ROOTFS: &str = "/opt/ne-enclave/rootfs/ubuntu-24.04.squashfs";
const FIRECRACKER: &str = "/opt/ne-enclave/bin/firecracker";
const JAILER: &str = "/opt/ne-enclave/bin/jailer";
const CHROOT_BASE: &str = "/srv/jailer";

#[tokio::test]
#[ignore = "boots a real Firecracker microVM via jailer; needs /opt/ne-enclave/* + sudo NOPASSWD"]
async fn firecracker_lifecycle_end_to_end() {
    let socket = format!("/tmp/ne-it-{}.sock", std::process::id());
    // jailer's --id accepts only [a-zA-Z0-9-]; dashes only.
    let workspace_id = format!("wks-it-{}", std::process::id());
    let supervisor_bin = ne_binary();
    let (image_store, kernel_sha256, rootfs_sha256) =
        prepare_managed_images(Path::new(KERNEL), Path::new(ROOTFS));

    // Spawn the supervisor as root via sudo. The cargo target binary
    // is NOT on the sudoers production allowlist (/opt/ne-enclave/bin/*),
    // so this test relies on the Azure default broad NOPASSWD rule.
    // In production the supervisor runs under a systemd unit with
    // CAP_* capabilities and no sudo.
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

    // Sanity: Ping should round-trip on dev-mode socket.
    match send_one(&socket, &SupervisorRequest::Ping).await {
        SupervisorResponse::Pong { .. } => {}
        other => panic!("Ping → {other:?}"),
    }

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
    let chroot = match send_one(&socket, &create).await {
        SupervisorResponse::WorkspaceCreated(created) => {
            assert_eq!(created.workspace_id, workspace_id);
            assert!(created.firecracker_pid > 0, "pid must be set");
            created.jailer_chroot
        }
        other => panic!("CreateWorkspace → {other:?}"),
    };
    assert!(
        Path::new(&chroot).exists(),
        "chroot {chroot} must exist after create"
    );

    // Let the guest finish early boot before terminating. The
    // Firecracker test kernel reaches userspace within ~200ms on
    // the D8as_v5, so 500ms gives generous slack.
    sleep(Duration::from_millis(500)).await;

    // Terminate.
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

    // Cleanup invariant: the workspace's chroot tree (one level above
    // `root/`) is removed.
    let workspace_root = format!("{CHROOT_BASE}/firecracker/{workspace_id}");
    assert!(
        !Path::new(&workspace_root).exists(),
        "{workspace_root} must be cleaned up"
    );

    let _ = supervisor.kill().await;
}

fn prepare_managed_images(kernel: &Path, rootfs: &Path) -> (PathBuf, String, String) {
    let store = PathBuf::from(format!("/tmp/ne-it-images-{}", std::process::id()));
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

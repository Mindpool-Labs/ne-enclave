// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Live-state snapshot of a running VM (KVM-gated).
//!
//! Proves: a `live` snapshot of a RUNNING workspace leaves the source live +
//! vsock-reachable (a command runs on it AFTER the snapshot, via its NEW
//! hot-swapped process), and the artifact is a consistent point-in-time
//! (a file written AFTER the snapshot is absent in a restore of it).
//!
//! `#[ignore]` by default. On a KVM host:
//! ```sh
//! cargo test -p ne-e2e --test live_snapshot -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;

use ne_protocol::supervisor::{
    CreateWorkspaceRequest, ReadFileRequest, RestoreRequest, RunCommandRequest, SnapshotInfo,
    SnapshotRequest, SupervisorErrorKind, SupervisorResponse, TerminateRequest, WriteFileRequest,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

const PORT: u32 = 52;

struct HostEnv {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
    jailer: PathBuf,
}

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

/// Returns the host paths if KVM + all required files are present, else None.
fn load_host_env() -> Option<HostEnv> {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return None;
    }
    let env = HostEnv {
        kernel: env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux"),
        rootfs: env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img"),
        firecracker: env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker"),
        jailer: env_path("NE_E2E_JAILER", "/usr/local/bin/jailer"),
    };
    for p in [&env.kernel, &env.rootfs, &env.firecracker, &env.jailer] {
        assert!(p.is_file(), "missing required file: {}", p.display());
    }
    Some(env)
}

fn expect_snapshot_created(resp: SupervisorResponse) -> SnapshotInfo {
    match resp {
        SupervisorResponse::SnapshotCreated(info) => info,
        other => panic!("expected SnapshotCreated, got {other:?}"),
    }
}

/// Live snapshot: source survives + vsock-reachable; restore is a consistent
/// point-in-time (bar is absent in restore because it was written after the
/// snapshot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker"]
async fn live_snapshot_source_survives_and_is_consistent() {
    let Some(env) = load_host_env() else { return };

    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &env.kernel, &env.rootfs);
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    // --- Build WorkspaceManager (no warm pool) ---
    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = image_store;
    let audit = AuditLog::open(&state_dir).await.expect("audit");
    let attestation = ne_supervisor::attestation_factory::build_provider(
        ne_protocol::profile::AttestationBackend::Software,
        audit.signing_key(),
    )
    .expect("software provider");
    let mgr = Arc::new(
        WorkspaceManager::new(cfg, audit, attestation, 1024, 32768).expect("workspace manager"),
    );

    // --- Step 1: Create ws-a (cold boot) ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-a".to_string(),
            kernel_sha256,
            rootfs_sha256,
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        })
        .await;
    let wc = match create_resp {
        SupervisorResponse::WorkspaceCreated(w) => w,
        other => panic!("expected WorkspaceCreated, got {other:?}"),
    };
    let pre_pid = wc.firecracker_pid;
    eprintln!("ws-a created: pid={pre_pid}");

    // The cold `create()` returns once the Firecracker API socket is up, NOT
    // once the guest agent is listening. Wait for guest-ready before the first
    // vsock op so the write below can't race guest boot on a loaded KVM host.
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc.vsock_host_socket),
        PORT,
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("ws-a guest agent did not become ready within 10s");

    // --- Step 2: Write /workspace/foo ---
    let write_resp = mgr
        .write_file(WriteFileRequest {
            workspace_id: "ws-a".to_string(),
            guest_port: PORT,
            path: "foo".to_string(),
            content: b"hi".to_vec(),
        })
        .await;
    match write_resp {
        SupervisorResponse::FileWritten(w) => {
            assert_eq!(
                w.absolute_path, "/workspace/foo",
                "unexpected absolute_path"
            );
        }
        other => panic!("expected FileWritten, got {other:?}"),
    }
    eprintln!("wrote /workspace/foo to ws-a");

    // --- Step 3: Live snapshot ---
    let snap_resp = mgr
        .snapshot(SnapshotRequest {
            workspace_id: "ws-a".to_string(),
            live: true,
        })
        .await;
    let info = expect_snapshot_created(snap_resp);
    let new_pid = info
        .firecracker_pid
        .expect("live snapshot must return a new firecracker_pid");
    assert_ne!(
        new_pid, pre_pid,
        "new_pid {new_pid} must differ from pre_pid {pre_pid} (hot-swap happened)"
    );
    let snapshot_id = info.snapshot_id.clone();
    eprintln!("live snapshot created: id={snapshot_id}, new_pid={new_pid}");

    // --- Step 4: Source survives — run a command on ws-a AFTER the snapshot ---
    let run_resp = mgr
        .run_command(RunCommandRequest {
            workspace_id: "ws-a".to_string(),
            guest_port: PORT,
            command: "cat".to_string(),
            args: vec!["/workspace/foo".to_string()],
            timeout_ms: 5_000,
        })
        .await;
    match run_resp {
        SupervisorResponse::CommandCompleted(c) => {
            assert_eq!(
                c.exit_code, 0,
                "cat /workspace/foo exited non-zero on hot-swapped source"
            );
            assert!(
                c.stdout.contains("hi"),
                "expected stdout to contain 'hi', got {:?}",
                c.stdout
            );
        }
        other => panic!("expected CommandCompleted from ws-a post-snapshot, got {other:?}"),
    }
    eprintln!("ws-a is still reachable post-snapshot (hot-swap confirmed)");

    // --- Step 5: Write /workspace/bar AFTER the snapshot (must not appear in restore) ---
    let write_bar = mgr
        .write_file(WriteFileRequest {
            workspace_id: "ws-a".to_string(),
            guest_port: PORT,
            path: "bar".to_string(),
            content: b"after".to_vec(),
        })
        .await;
    match write_bar {
        SupervisorResponse::FileWritten(_) => {}
        other => panic!("expected FileWritten for bar, got {other:?}"),
    }
    eprintln!("wrote /workspace/bar to ws-a after snapshot");

    // --- Step 6: Restore into ws-b ---
    let restore_resp = mgr
        .restore(RestoreRequest {
            snapshot_id: snapshot_id.clone(),
            new_workspace_id: "ws-b".to_string(),
        })
        .await;
    match restore_resp {
        SupervisorResponse::WorkspaceRestored(_) => {}
        other => panic!("expected WorkspaceRestored, got {other:?}"),
    }
    eprintln!("ws-b restored from snapshot {snapshot_id}");

    // --- Step 7: ws-b must see /workspace/foo (it was written before the snapshot) ---
    let read_foo = mgr
        .read_file(ReadFileRequest {
            workspace_id: "ws-b".to_string(),
            guest_port: PORT,
            path: "foo".to_string(),
            max_bytes: 64,
        })
        .await;
    match read_foo {
        SupervisorResponse::FileRead(r) => {
            assert_eq!(
                r.content, b"hi",
                "ws-b must contain the pre-snapshot file content"
            );
        }
        other => panic!("expected FileRead for foo on ws-b, got {other:?}"),
    }
    eprintln!("ws-b has /workspace/foo with correct content");

    // --- Step 8: ws-b must NOT see /workspace/bar (written after the snapshot) ---
    // The supervisor maps GuestErrorKind::FileNotFound -> SupervisorErrorKind::FileNotFound
    // and returns SupervisorResponse::Error. Assert that.
    let read_bar = mgr
        .read_file(ReadFileRequest {
            workspace_id: "ws-b".to_string(),
            guest_port: PORT,
            path: "bar".to_string(),
            max_bytes: 64,
        })
        .await;
    match read_bar {
        SupervisorResponse::Error { kind, .. } => {
            assert_eq!(
                kind,
                SupervisorErrorKind::FileNotFound,
                "expected FileNotFound for bar on ws-b (post-snapshot write must be absent), got {kind:?}"
            );
        }
        SupervisorResponse::FileRead(r) if r.content.is_empty() => {
            // Permissive: some guest agents may return an empty read for a
            // missing file. Either FileNotFound error OR empty FileRead is
            // acceptable evidence that the post-snapshot write is absent.
        }
        other => {
            panic!("expected FileNotFound error (or empty FileRead) for bar on ws-b, got {other:?}")
        }
    }
    eprintln!("ws-b correctly does not have /workspace/bar (point-in-time consistency verified)");

    // --- Cleanup (best-effort) ---
    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-a".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-b".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    eprintln!("live_snapshot_source_survives_and_is_consistent: PASSED");
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! The snapshot memory dump must NOT head-of-line-block the supervisor
//! and is KVM-gated.
//!
//! Proves: while a large-memory `snapshot()` is mid-dump (multi-GiB, seconds),
//! a concurrent supervisor op that only needs the global `instances` mutex
//! returns *well before* the snapshot completes. Before the fix, `snapshot()`
//! held that mutex across pause → dump → resume, so every other op serialized
//! behind the whole dump.
//!
//! Probe: a `terminate` of a non-existent id. Its first act is
//! `self.instances.lock().await.remove(id)` → `None` → `WorkspaceNotFound`. It
//! touches nothing but the lock, so its latency is a direct measurement of how
//! long the `instances` mutex is unavailable. We also fire a real `create` of a
//! *different* id concurrently to show a genuine op makes progress, not just a
//! no-op probe.
//!
//! `#[ignore]` by default. On a KVM host:
//! ```sh
//! cargo test -p ne-e2e --test snapshot_no_hol -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ne_protocol::supervisor::{
    CreateWorkspaceRequest, ReadFileRequest, SnapshotInfo, SnapshotRequest, SupervisorErrorKind,
    SupervisorResponse, TerminateRequest, WriteFileRequest,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

const PORT: u32 = 52;

/// Memory size (MiB) for the snapshot source. Large enough that the Full
/// memory dump takes multiple seconds — that gap is what the concurrent probe
/// slots into. Bump via NE_E2E_HOL_MEM_MIB if the host dumps too fast to make
/// the timing unambiguous.
fn source_mem_mib() -> u32 {
    std::env::var("NE_E2E_HOL_MEM_MIB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2048)
}

struct HostEnv {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
    jailer: PathBuf,
}

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

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

/// A large-mem `snapshot()` must not head-of-line-block the `instances` mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker"]
async fn snapshot_does_not_head_of_line_block() {
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

    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = image_store;
    let audit = AuditLog::open(&state_dir).await.expect("audit");
    // Generous admission: source VM + a concurrent small create.
    let mem_mib = source_mem_mib();
    let attestation = ne_supervisor::attestation_factory::build_provider(
        ne_protocol::profile::AttestationBackend::Software,
        audit.signing_key(),
    )
    .expect("software provider");
    let mgr = Arc::new(
        WorkspaceManager::new(cfg, audit, attestation, 64, 65536).expect("workspace manager"),
    );

    // --- Create the large-mem source (cold boot) ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-src".to_string(),
            kernel_sha256: kernel_sha256.clone(),
            rootfs_sha256: rootfs_sha256.clone(),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: mem_mib,
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
    eprintln!(
        "ws-src created: pid={}, mem={mem_mib}MiB",
        wc.firecracker_pid
    );

    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc.vsock_host_socket),
        PORT,
        Duration::from_secs(15),
    )
    .await
    .expect("ws-src guest agent did not become ready");

    // --- Kick off the snapshot (non-live) in the background ---
    let snap_mgr = Arc::clone(&mgr);
    let snap_start = Instant::now();
    let snap_handle = tokio::spawn(async move {
        snap_mgr
            .snapshot(SnapshotRequest {
                workspace_id: "ws-src".to_string(),
                live: false,
            })
            .await
    });

    // Let the snapshot get past its brief capture lock and into the UNLOCKED
    // memory dump. If the fix is absent, the mutex is held for the whole dump
    // and the probe below blocks the full duration.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !snap_handle.is_finished(),
        "snapshot finished in <500ms — mem too small to make the timing meaningful; \
         raise NE_E2E_HOL_MEM_MIB"
    );

    // --- Probe 1: pure instances-lock op (terminate of a bogus id) ---
    let probe_start = Instant::now();
    let probe_resp = mgr
        .terminate(TerminateRequest {
            workspace_id: "does-not-exist".to_string(),
            grace_period_ms: 0,
        })
        .await;
    let probe_latency = probe_start.elapsed();
    let snap_still_running = !snap_handle.is_finished();

    match probe_resp {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            ..
        } => {}
        other => panic!("expected WorkspaceNotFound from bogus terminate, got {other:?}"),
    }

    // --- Probe 2: a genuine op on a DIFFERENT id proceeds concurrently ---
    let create2_start = Instant::now();
    let create2 = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-other".to_string(),
            kernel_sha256,
            rootfs_sha256,
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 4,
            kernel_boot_args: None,
            network: None,
            tier: None,
        })
        .await;
    let create2_latency = create2_start.elapsed();
    let create2_before_snap = !snap_handle.is_finished();
    match create2 {
        SupervisorResponse::WorkspaceCreated(_) => {}
        other => panic!("expected WorkspaceCreated for ws-other, got {other:?}"),
    }

    // --- Join the snapshot ---
    let snap_resp = snap_handle.await.expect("snapshot task panicked");
    let snap_elapsed = snap_start.elapsed();
    let info = expect_snapshot_created(snap_resp);

    eprintln!("---- HOL measurements ----");
    eprintln!("snapshot total:        {snap_elapsed:?}");
    eprintln!(
        "bogus-terminate probe: {probe_latency:?} (snapshot still running: {snap_still_running})"
    );
    eprintln!(
        "concurrent create:     {create2_latency:?} (before snapshot done: {create2_before_snap})"
    );
    eprintln!(
        "snapshot_id: {}, mem_sha256: {}",
        info.snapshot_id, info.mem_sha256
    );

    // The probe touched only the instances mutex; if the dump held it, this
    // would be ~snap_elapsed. Assert it returned promptly AND while the dump
    // was still in flight — the direct proof the HOL block is gone.
    assert!(
        snap_still_running,
        "probe returned only after the snapshot completed — instances mutex was held across the dump (HOL block present)"
    );
    assert!(
        probe_latency < Duration::from_millis(500),
        "instances-lock probe took {probe_latency:?} (>=500ms) — likely blocked behind the dump"
    );
    // The dump must dominate: it should be many times the probe latency.
    assert!(
        snap_elapsed > probe_latency * 4,
        "snapshot ({snap_elapsed:?}) not dominated by the unlocked dump vs probe ({probe_latency:?})"
    );

    // --- Cleanup (best-effort) ---
    for id in ["ws-src", "ws-other"] {
        let _ = mgr
            .terminate(TerminateRequest {
                workspace_id: id.to_string(),
                grace_period_ms: 2_000,
            })
            .await;
    }
    eprintln!("snapshot_does_not_head_of_line_block: PASSED");
}

/// A `terminate` that races an in-flight snapshot must NOT be undone by the
/// snapshot's finalize step: once the workspace is removed, `snapshot()` must
/// never reinsert it (the resurrection guard). The on-disk artifact
/// may still complete, but the workspace stays gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker"]
async fn terminate_during_snapshot_does_not_resurrect() {
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

    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = image_store;
    let audit = AuditLog::open(&state_dir).await.expect("audit");
    let mem_mib = source_mem_mib();
    let attestation = ne_supervisor::attestation_factory::build_provider(
        ne_protocol::profile::AttestationBackend::Software,
        audit.signing_key(),
    )
    .expect("software provider");
    let mgr = Arc::new(
        WorkspaceManager::new(cfg, audit, attestation, 64, 65536).expect("workspace manager"),
    );

    // --- Create the large-mem source so the dump is long enough to terminate
    //     mid-flight ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-doomed".to_string(),
            kernel_sha256: kernel_sha256.clone(),
            rootfs_sha256: rootfs_sha256.clone(),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: mem_mib,
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
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc.vsock_host_socket),
        PORT,
        Duration::from_secs(15),
    )
    .await
    .expect("ws-doomed guest agent did not become ready");

    // --- Kick off the snapshot, then terminate the source mid-dump ---
    let snap_mgr = Arc::clone(&mgr);
    let snap_handle = tokio::spawn(async move {
        snap_mgr
            .snapshot(SnapshotRequest {
                workspace_id: "ws-doomed".to_string(),
                live: false,
            })
            .await
    });

    // Wait until we are safely inside the unlocked dump, then terminate.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !snap_handle.is_finished(),
        "snapshot completed before we could terminate mid-dump; raise NE_E2E_HOL_MEM_MIB"
    );
    let term_resp = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-doomed".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    match term_resp {
        SupervisorResponse::WorkspaceTerminated { .. } => {}
        other => {
            panic!("expected WorkspaceTerminated for the mid-snapshot terminate, got {other:?}")
        }
    }
    eprintln!("ws-doomed terminated while its snapshot dump was in flight");

    // --- The snapshot resolves to either outcome; neither may resurrect it ---
    let snap_resp = snap_handle.await.expect("snapshot task panicked");
    match &snap_resp {
        SupervisorResponse::SnapshotCreated(info) => {
            eprintln!(
                "snapshot completed despite terminate: id={} (artifact valid, source stays gone)",
                info.snapshot_id
            );
        }
        SupervisorResponse::Error { kind, .. } => {
            eprintln!(
                "snapshot failed after terminate killed FC: {kind:?} (expected, source stays gone)"
            );
        }
        other => panic!("unexpected snapshot outcome: {other:?}"),
    }

    // --- The invariant: ws-doomed was NOT reinserted by finalize ---
    let recheck = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-doomed".to_string(),
            grace_period_ms: 0,
        })
        .await;
    match recheck {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            ..
        } => {}
        other => panic!(
            "ws-doomed was RESURRECTED by snapshot finalize — expected WorkspaceNotFound, got {other:?}"
        ),
    }

    // --- ABA leg: recreate the SAME id and prove the (possibly still
    //     settling) stale snapshot machinery cannot mislabel the new boot.
    //     The recreated workspace must stay Running: a live snapshot of it —
    //     which is rejected outright unless the registry says Running — must
    //     succeed, and the guest must be reachable. ---
    let recreate = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-doomed".to_string(),
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
    let wc2 = match recreate {
        SupervisorResponse::WorkspaceCreated(w) => w,
        other => panic!("expected WorkspaceCreated for the recreate, got {other:?}"),
    };
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc2.vsock_host_socket),
        PORT,
        Duration::from_secs(15),
    )
    .await
    .expect("recreated ws-doomed guest agent did not become ready");
    let live_probe = mgr
        .snapshot(SnapshotRequest {
            workspace_id: "ws-doomed".to_string(),
            live: true,
        })
        .await;
    match live_probe {
        SupervisorResponse::SnapshotCreated(_) => {}
        other => panic!(
            "live snapshot of the RECREATED ws-doomed failed — its registry state was \
             clobbered by the stale snapshot (expected SnapshotCreated, got {other:?})"
        ),
    }
    eprintln!("recreated ws-doomed is Running and live-snapshottable (not mislabeled)");

    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-doomed".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    eprintln!("terminate_during_snapshot_does_not_resurrect: PASSED");
}

/// A live snapshot holds the source id's lifecycle lease through artifact
/// publication and hot-swap finalization. If the source is terminated during
/// that window, a same-id create must fail fast until the snapshot finishes;
/// once the lease is released, the id is reusable and the replacement must be
/// reachable without inheriting the old boot's state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/kvm + firecracker"]
async fn same_id_recreate_waits_for_live_snapshot_lease() {
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
        WorkspaceManager::new(cfg, audit, attestation, 64, 65536).expect("workspace manager"),
    );

    // --- Original boot (small mem: the window here is the hot-swap's restore
    //     boot, not the dump) with a marker file only the OLD boot has ---
    let create_resp = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-aba".to_string(),
            kernel_sha256: kernel_sha256.clone(),
            rootfs_sha256: rootfs_sha256.clone(),
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
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc.vsock_host_socket),
        PORT,
        Duration::from_secs(15),
    )
    .await
    .expect("ws-aba guest agent did not become ready");
    match mgr
        .write_file(WriteFileRequest {
            workspace_id: "ws-aba".to_string(),
            guest_port: PORT,
            path: "old-boot-marker".to_string(),
            content: b"orig".to_vec(),
        })
        .await
    {
        SupervisorResponse::FileWritten(_) => {}
        other => panic!("expected FileWritten, got {other:?}"),
    }

    // --- Kick off a LIVE snapshot in the background ---
    let snap_mgr = Arc::clone(&mgr);
    let snap_handle = tokio::spawn(async move {
        snap_mgr
            .snapshot(SnapshotRequest {
                workspace_id: "ws-aba".to_string(),
                live: true,
            })
            .await
    });

    // --- Wait for the manifest to land: it is written immediately before
    //     live_hot_swap starts booting its restore, i.e. the beginning of
    //     the seconds-wide lock-free swap window ---
    let snapshots_dir = state_dir.join("snapshots");
    let manifest_deadline = Instant::now() + Duration::from_secs(60);
    'poll: loop {
        assert!(
            Instant::now() < manifest_deadline,
            "manifest never appeared under {}",
            snapshots_dir.display()
        );
        if let Ok(mut rd) = tokio::fs::read_dir(&snapshots_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if entry.path().join("manifest.json").is_file() {
                    break 'poll;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !snap_handle.is_finished(),
        "live snapshot finished the instant its manifest appeared — hot-swap window too \
         small to race; investigate before trusting this test"
    );
    eprintln!("manifest written; inside the hot-swap window — terminating ws-aba");

    // --- Terminate, then prove the lifecycle lease blocks same-id reuse ---
    match mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-aba".to_string(),
            grace_period_ms: 0,
        })
        .await
    {
        SupervisorResponse::WorkspaceTerminated { .. } => {}
        other => panic!("expected WorkspaceTerminated, got {other:?}"),
    }
    let blocked_recreate = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-aba".to_string(),
            kernel_sha256: kernel_sha256.clone(),
            rootfs_sha256: rootfs_sha256.clone(),
            rootfs_read_only: true,
            vcpu_count: 1,
            mem_size_mib: 128,
            guest_vsock_cid: 3,
            kernel_boot_args: None,
            network: None,
            tier: None,
        })
        .await;
    match blocked_recreate {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceAlreadyExists,
            ..
        } => {}
        other => panic!(
            "same-id create must be rejected while the live snapshot holds its lifecycle lease; \
             expected WorkspaceAlreadyExists, got {other:?}"
        ),
    }

    // --- The live snapshot must notice that its source was terminated ---
    let snap_resp = snap_handle.await.expect("snapshot task panicked");
    match &snap_resp {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::WorkspaceNotFound,
            message,
        } => {
            eprintln!("live snapshot declined the swap as expected: {message}");
        }
        other => panic!(
            "expected the live snapshot to decline its hot-swap (WorkspaceNotFound) after the \
             source was terminated mid-swap; got {other:?}"
        ),
    }

    // --- Snapshot completion releases the lease; same-id reuse now succeeds ---
    let recreate = mgr
        .create(CreateWorkspaceRequest {
            workspace_id: "ws-aba".to_string(),
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
    let wc2 = match recreate {
        SupervisorResponse::WorkspaceCreated(w) => w,
        other => panic!("expected WorkspaceCreated after snapshot completion, got {other:?}"),
    };
    eprintln!(
        "ws-aba recreated after snapshot completion (new pid={})",
        wc2.firecracker_pid
    );

    // --- The replacement is reachable, WITHOUT the old boot's marker ---
    ne_supervisor::firecracker::wait_for_guest_ready(
        std::path::Path::new(&wc2.vsock_host_socket),
        PORT,
        Duration::from_secs(15),
    )
    .await
    .expect("recreated ws-aba guest agent did not become ready");
    let read_marker = mgr
        .read_file(ReadFileRequest {
            workspace_id: "ws-aba".to_string(),
            guest_port: PORT,
            path: "old-boot-marker".to_string(),
            max_bytes: 64,
        })
        .await;
    match read_marker {
        SupervisorResponse::Error {
            kind: SupervisorErrorKind::FileNotFound,
            ..
        } => {}
        SupervisorResponse::FileRead(r) if r.content.is_empty() => {}
        other => panic!(
            "recreated ws-aba has the OLD boot's marker — the stale live snapshot resurrected \
             old state over the replacement (got {other:?})"
        ),
    }

    // --- And still Running per the registry: a live snapshot of it succeeds ---
    match mgr
        .snapshot(SnapshotRequest {
            workspace_id: "ws-aba".to_string(),
            live: true,
        })
        .await
    {
        SupervisorResponse::SnapshotCreated(_) => {}
        other => panic!(
            "live snapshot of the recreated ws-aba failed — registry state clobbered \
             (expected SnapshotCreated, got {other:?})"
        ),
    }

    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "ws-aba".to_string(),
            grace_period_ms: 2_000,
        })
        .await;
    eprintln!("same_id_recreate_waits_for_live_snapshot_lease: PASSED");
}

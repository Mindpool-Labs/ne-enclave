// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Concurrent `CreateWorkspace` calls with the SAME
//! caller-supplied id must never produce two live workspaces and must never
//! leak a second chroot/netns for the loser.
//!
//! Before the fix, the cold `create` path did a courtesy `contains_key` then a
//! bare `insert` seconds later; the loser's freshly-booted `Instance` was
//! silently dropped (leaking its chroot/netns) instead of terminated. The
//! lifecycle claim now rejects a same-id loser before either a cold boot or a
//! warm-pool checkout can allocate resources; `register_or_teardown` remains a
//! final registry-lock backstop.
//!
//! REAL-HARDWARE NOTE (empirical): on the blank cold path the jailer chroot is
//! derived directly from the caller-supplied id
//! (`{chroot_base}/firecracker/{id}/root`), so two *simultaneous* same-id boots
//! collide on that shared tree: the loser's jailer dies at mkdir/mknod
//! (`File exists`). Two hazards were found and fixed running this test:
//!
//! 1. `stage_file` could TRUNCATE THE SHARED SOURCE IMAGE (copy-fallback wrote
//!    through the winner's hardlinked inode) — fixed by atomic temp+rename
//!    staging; this test pins it by asserting the staged sources stay
//!    non-empty after the race.
//! 2. `wait_for_socket` trusted `path.exists()` at the SHARED socket path
//!    before checking its own child's liveness, so the loser adopted the
//!    winner's API socket and replayed config PUTs against the winner's live
//!    instance — fixed by polling jailer liveness first (fail-fast
//!    `JailerExited`).
//! 3. Even failing fast, the loser's error-path cleanup (`remove_dir_all` of
//!    the shared id-derived tree in `launch()`) deleted the WINNER's chroot
//!    mid-boot, killing both racers — fixed by `claim_boot` in the manager:
//!    same-id cold boots are serialized up front, so the second racer fails
//!    with `WorkspaceAlreadyExists` before ever booting, staging, or cleaning.
//!
//! Post-fix the outcome is deterministic: exactly one winner; the loser fails
//! in microseconds with `WorkspaceAlreadyExists` (the boot claim) — the
//! assertion also tolerates `LaunchFailed` ("jailer exited...", the fail-fast
//! backstop) — with no leaked chroot and no cross-instance interference. The
//! `concurrent_pool_checkout_single_winner` below pins the same ordering for
//! warm-pool creates: the loser must not pop or tear down the second ready
//! member. Unique per-boot chroot ids stay a filed follow-up defense in depth.
//!
//! `#[ignore]` by default — needs `/dev/kvm`. Run on a KVM host:
//! ```sh
//! cargo test -p ne-e2e --test create_race -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Required env (same as the other KVM gauntlet tests):
//! - `NE_E2E_KERNEL`      — host path to vmlinux
//! - `NE_E2E_ROOTFS`      — host path to rootfs image
//! - `NE_E2E_FIRECRACKER` — defaults to `/usr/local/bin/firecracker`
//! - `NE_E2E_JAILER`      — defaults to `/usr/local/bin/jailer`

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ne_protocol::snapshot::GuestIdentity;
use ne_protocol::supervisor::{
    CreateWorkspaceRequest, PoolStatusRequest, SupervisorErrorKind, SupervisorResponse,
    TerminateRequest,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::firecracker::{
    LaunchConfig, firecracker_version, launch, pause, snapshot_create, terminate,
    wait_for_guest_ready,
};
use ne_supervisor::pool::WarmPoolConfig;
use ne_supervisor::signing::load_or_create_signing_key;
use ne_supervisor::snapshot::{snapshot_dir, write_manifest};
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

const WS_ID: &str = "ws-race";
const POOL_WS_ID: &str = "ws-pool-race";
const TIER: &str = "default";
const PORT: u32 = 52;

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

fn cold_create_req(kernel_sha256: &str, rootfs_sha256: &str) -> CreateWorkspaceRequest {
    CreateWorkspaceRequest {
        workspace_id: WS_ID.to_string(),
        kernel_sha256: kernel_sha256.to_string(),
        rootfs_sha256: rootfs_sha256.to_string(),
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: None,
        network: None,
        // tier: None => the plain cold Firecracker create path (the one under test).
        tier: None,
    }
}

/// Count the chroot subdirectories named `WS_ID` under `{chroot_base}/firecracker`.
/// Both racers derive the identical jailer chroot from the shared id, so a
/// correct run leaves at most one such directory — never a second, distinctly
/// leaked tree.
fn chroot_dirs_for_id(chroot_base: &std::path::Path) -> usize {
    let fc = chroot_base.join("firecracker");
    let Ok(entries) = std::fs::read_dir(&fc) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy() == WS_ID && e.path().is_dir())
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_same_id_create_has_one_winner() {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return;
    }
    let kernel = env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux");
    let rootfs = env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img");
    let firecracker = env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker");
    let jailer = env_path("NE_E2E_JAILER", "/usr/local/bin/jailer");
    for p in [&kernel, &rootfs, &firecracker, &jailer] {
        assert!(p.is_file(), "missing required file: {}", p.display());
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    // Fixture integrity: stage this test's kernel/rootfs as COPIES in the
    // tempdir. Pre-5b, the same-id staging collision could truncate the SOURCE
    // image through a hardlinked inode; stage_file is atomic now, and the
    // race-survives-intact assertion below pins that end-to-end. The copies
    // keep any regression's blast radius inside the tempdir.
    let kernel_copy = tmp.path().join("vmlinux");
    let rootfs_copy = tmp.path().join("rootfs.img");
    tokio::fs::copy(&kernel, &kernel_copy)
        .await
        .expect("copy kernel fixture");
    tokio::fs::copy(&rootfs, &rootfs_copy)
        .await
        .expect("copy rootfs fixture");
    let image_store = state_dir.join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &kernel_copy, &rootfs_copy);
    let managed_kernel = image_store
        .join("kernels")
        .join(&kernel_sha256)
        .join("vmlinux");
    let managed_rootfs = image_store
        .join("rootfs")
        .join(&rootfs_sha256)
        .join("rootfs.img");

    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = firecracker.clone();
    cfg.jailer_binary = jailer.clone();
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

    // Fire two identical cold creates concurrently. The winner claims the id
    // up front (`claim_boot`) and boots alone; the loser fails fast without
    // ever spawning a jailer. `register_or_teardown` remains the final
    // registry-lock backstop.
    let a = {
        let mgr = Arc::clone(&mgr);
        let (kernel_sha256, rootfs_sha256) = (kernel_sha256.clone(), rootfs_sha256.clone());
        async move {
            mgr.create(cold_create_req(&kernel_sha256, &rootfs_sha256))
                .await
        }
    };
    let b = {
        let mgr = Arc::clone(&mgr);
        let (kernel_sha256, rootfs_sha256) = (kernel_sha256.clone(), rootfs_sha256.clone());
        async move {
            mgr.create(cold_create_req(&kernel_sha256, &rootfs_sha256))
                .await
        }
    };
    let (resp_a, resp_b) = tokio::join!(a, b);

    eprintln!("resp_a = {resp_a:?}");
    eprintln!("resp_b = {resp_b:?}");

    // Classify the two responses.
    let mut created = Vec::new();
    let mut errors = Vec::new();
    for resp in [resp_a, resp_b] {
        match resp {
            SupervisorResponse::WorkspaceCreated(w) => created.push(w),
            SupervisorResponse::Error { kind, message } => errors.push((kind, message)),
            other => panic!("unexpected response variant: {other:?}"),
        }
    }

    // Deterministic post-fix outcome (boot claim + atomic stage_file +
    // fail-fast wait_for_socket): the loser is rejected at the claim and never
    // touches the shared chroot or the winner's API socket; the winner boots
    // normally.
    assert_eq!(
        created.len(),
        1,
        "expected exactly one WorkspaceCreated, got {created:?} (errors: {errors:?})"
    );
    assert_eq!(
        errors.len(),
        1,
        "expected exactly one Error, got {errors:?}"
    );
    let (err_kind, err_msg) = &errors[0];
    assert!(
        matches!(
            err_kind,
            SupervisorErrorKind::LaunchFailed | SupervisorErrorKind::WorkspaceAlreadyExists
        ),
        "loser must fail fast (LaunchFailed: jailer exited before Firecracker came up) \
         or lose the courtesy gate (WorkspaceAlreadyExists), got {err_kind:?}: {err_msg}"
    );

    // --- No leaked second chroot tree for the loser. ---
    // Both racers share the id-derived chroot path, so at most one `ws-race`
    // tree may exist; a leaked *distinct* tree would show up as a second entry.
    let dirs = chroot_dirs_for_id(&chroot_base);
    assert!(
        dirs <= 1,
        "expected at most one chroot dir for {WS_ID}, found {dirs}"
    );

    // --- 5b end-to-end pin: the managed source images survive the race. ---
    // Pre-fix, the loser's copy-fallback zeroed the managed source image
    // through the winner's hardlinked inode; atomic staging must keep it intact.
    for p in [&managed_kernel, &managed_rootfs] {
        let len = std::fs::metadata(p)
            .expect("managed source image exists")
            .len();
        assert!(
            len > 0,
            "managed source image {} was truncated by the race (stage_file regression)",
            p.display()
        );
    }

    // The winner is live and cleanly terminable; no orphaned Firecracker/chroot.
    let winner = &created[0];
    assert_eq!(winner.workspace_id, WS_ID);
    let term = mgr
        .terminate(TerminateRequest {
            workspace_id: WS_ID.to_string(),
            grace_period_ms: 5_000,
        })
        .await;
    eprintln!("terminate winner = {term:?}");
    assert!(
        matches!(term, SupervisorResponse::WorkspaceTerminated { .. }),
        "winner terminate should succeed, got {term:?}"
    );

    // claim must not outlive the workspace: id is reusable after terminate
    let recreate = mgr
        .create(cold_create_req(&kernel_sha256, &rootfs_sha256))
        .await;
    eprintln!("re-create after terminate = {recreate:?}");
    assert!(
        matches!(recreate, SupervisorResponse::WorkspaceCreated(_)),
        "fresh cold create of the same id must succeed after terminate, got {recreate:?}"
    );
    let term = mgr
        .terminate(TerminateRequest {
            workspace_id: WS_ID.to_string(),
            grace_period_ms: 5_000,
        })
        .await;
    assert!(
        matches!(term, SupervisorResponse::WorkspaceTerminated { .. }),
        "re-created workspace terminate should succeed, got {term:?}"
    );
}

// ---------------------------------------------------------------------------
// Pool-checkout race: pins lifecycle-claim ordering before pool adoption.
// ---------------------------------------------------------------------------

/// Build a signed base snapshot from a throwaway workspace (mirrors the
/// warm-pool e2e's setup).
#[allow(clippy::too_many_arguments)]
async fn build_base_snapshot(
    kernel: &Path,
    rootfs: &Path,
    firecracker: &Path,
    jailer: &Path,
    chroot_base: &Path,
    state_dir: &Path,
    snap_id: &str,
    src_id: &str,
) {
    let image_store = state_dir.join("images");
    let (_, _, verified_images) =
        ne_e2e::resolve_managed_images(&image_store, kernel, rootfs).await;
    let src = launch(LaunchConfig {
        workspace_id: src_id.to_string(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: firecracker.to_path_buf(),
        jailer_binary: jailer.to_path_buf(),
        chroot_base: chroot_base.to_path_buf(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    })
    .await
    .expect("launch src");
    wait_for_guest_ready(
        &src.vsock_host_socket.clone(),
        PORT,
        Duration::from_secs(10),
    )
    .await
    .expect("src ready");
    pause(&src).await.expect("pause src");
    let arts = snapshot_create(&src).await.expect("snapshot_create");
    let snap_dir = snapshot_dir(state_dir, snap_id);
    tokio::fs::create_dir_all(&snap_dir)
        .await
        .expect("snap dir");
    tokio::fs::copy(&arts.mem_in_chroot, snap_dir.join("mem"))
        .await
        .expect("copy mem");
    tokio::fs::copy(&arts.vmstate_in_chroot, snap_dir.join("vmstate"))
        .await
        .expect("copy vmstate");
    let signer = load_or_create_signing_key(&state_dir.join("keys"))
        .await
        .expect("signer");
    let fc_version = firecracker_version(firecracker).await;
    write_manifest(
        &snap_dir,
        &signer,
        snap_id,
        &src.workspace_id,
        &fc_version,
        &src.kernel_sha256,
        &src.rootfs_sha256,
        GuestIdentity {
            hostname: src.workspace_id.clone(),
            mac: "unset".into(),
            guest_vsock_cid: src.guest_vsock_cid,
            vcpu_count: src.vcpu_count,
            mem_size_mib: src.mem_size_mib,
        },
        &src.kernel_boot_args.clone(),
    )
    .await
    .expect("write_manifest");
    terminate(src, Duration::from_secs(5))
        .await
        .expect("terminate src");
}

async fn pool_counts(mgr: &WorkspaceManager) -> (u32, u32) {
    match mgr.pool_status(PoolStatusRequest {}).await {
        SupervisorResponse::PoolStatus(s) => (s.available, s.in_flight),
        other => panic!("expected PoolStatus, got {other:?}"),
    }
}

/// Wait until the pool holds at least `n` ready members with no provisions
/// still in flight, so the set of `pool-*` chroot dirs on disk is stable.
async fn wait_pool_settled(mgr: &WorkspaceManager, n: u32, deadline: Duration) {
    let start = Instant::now();
    loop {
        let (available, in_flight) = pool_counts(mgr).await;
        if available >= n && in_flight == 0 {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "pool did not settle at >= {n} ready / 0 in-flight within {deadline:?} \
             (available={available}, in_flight={in_flight})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Names of the `pool-*` member chroot dirs under `{chroot_base}/firecracker`.
fn pool_member_dirs(chroot_base: &Path) -> BTreeSet<String> {
    let fc = chroot_base.join("firecracker");
    let Ok(entries) = std::fs::read_dir(&fc) else {
        return BTreeSet::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("pool-"))
        .collect()
}

fn tier_create_req(workspace_id: &str) -> CreateWorkspaceRequest {
    CreateWorkspaceRequest {
        workspace_id: workspace_id.to_string(),
        kernel_sha256: String::new(),
        rootfs_sha256: String::new(),
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: None,
        network: None,
        tier: Some(TIER.to_string()),
    }
}

/// Pins the lifecycle claim ahead of warm-pool checkout. Two same-id callers
/// race for the claim; exactly one may pop and adopt a member. The loser must
/// fail before touching the pool, leaving the other ready member intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn concurrent_pool_checkout_single_winner() {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return;
    }
    let kernel = env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux");
    let rootfs = env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img");
    let firecracker = env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker");
    let jailer = env_path("NE_E2E_JAILER", "/usr/local/bin/jailer");
    for p in [&kernel, &rootfs, &firecracker, &jailer] {
        assert!(p.is_file(), "missing required file: {}", p.display());
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    build_base_snapshot(
        &kernel,
        &rootfs,
        &firecracker,
        &jailer,
        &chroot_base,
        &state_dir,
        "01J0RACEPOOLSNAP",
        "race-pool-src",
    )
    .await;

    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = firecracker.clone();
    cfg.jailer_binary = jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = state_dir.join("images");
    cfg.warm_pool = Some(WarmPoolConfig {
        tier_name: TIER.into(),
        base_snapshot_id: "01J0RACEPOOLSNAP".into(),
        target_size: 2,
        max_in_flight: 2,
    });
    let audit = AuditLog::open(&state_dir).await.expect("audit");
    let attestation = ne_supervisor::attestation_factory::build_provider(
        ne_protocol::profile::AttestationBackend::Software,
        audit.signing_key(),
    )
    .expect("software provider");
    let mgr = Arc::new(
        WorkspaceManager::new(cfg, audit, attestation, 1024, 32768).expect("workspace manager"),
    );
    mgr.spawn_refill();

    // Two ready members, no boots in flight: the on-disk `pool-*` dir set is
    // exactly the two members whose preservation the race will check.
    wait_pool_settled(&mgr, 2, Duration::from_secs(120)).await;
    let pre_dirs = pool_member_dirs(&chroot_base);
    eprintln!("pre-race pool member dirs: {pre_dirs:?}");
    assert_eq!(pre_dirs.len(), 2, "expected exactly 2 settled pool members");

    // Race: two concurrent creates of the SAME caller id. The lifecycle claim
    // admits one caller to checkout and rejects the other before pool.pop().
    let a = {
        let mgr = Arc::clone(&mgr);
        async move { mgr.create(tier_create_req(POOL_WS_ID)).await }
    };
    let b = {
        let mgr = Arc::clone(&mgr);
        async move { mgr.create(tier_create_req(POOL_WS_ID)).await }
    };
    let (resp_a, resp_b) = tokio::join!(a, b);
    eprintln!("resp_a = {resp_a:?}");
    eprintln!("resp_b = {resp_b:?}");

    let mut created = Vec::new();
    let mut errors = Vec::new();
    for resp in [resp_a, resp_b] {
        match resp {
            SupervisorResponse::WorkspaceCreated(w) => created.push(w),
            SupervisorResponse::Error { kind, message } => errors.push((kind, message)),
            other => panic!("unexpected response variant: {other:?}"),
        }
    }

    // Exactly one winner + one WorkspaceAlreadyExists.
    assert_eq!(
        created.len(),
        1,
        "expected exactly one WorkspaceCreated, got {created:?} (errors: {errors:?})"
    );
    assert_eq!(
        errors.len(),
        1,
        "expected exactly one Error, got {errors:?}"
    );
    let (err_kind, err_msg) = &errors[0];
    assert_eq!(
        *err_kind,
        SupervisorErrorKind::WorkspaceAlreadyExists,
        "loser must be WorkspaceAlreadyExists, got {err_kind:?}: {err_msg}"
    );

    // The winner keeps its member's pool chroot (registry id rewritten, chroot
    // name kept). The loser never pops the other member, so BOTH pre-race dirs
    // remain: one registered to the winner and one still pooled. Refill may
    // add a new member, but cannot change this intersection.
    let winner = &created[0];
    assert_eq!(winner.workspace_id, POOL_WS_ID);
    let winner_dir = PathBuf::from(&winner.jailer_chroot)
        .parent()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .expect("winner jailer_chroot has a member dir");
    assert!(
        pre_dirs.contains(&winner_dir),
        "winner chroot {winner_dir:?} not among pre-race members {pre_dirs:?}"
    );
    let surviving: BTreeSet<String> = pool_member_dirs(&chroot_base)
        .intersection(&pre_dirs)
        .cloned()
        .collect();
    eprintln!("surviving pre-race member dirs: {surviving:?}");
    assert_eq!(
        surviving, pre_dirs,
        "the loser must be rejected before checkout, leaving both pre-race member dirs intact"
    );

    // Winner is live and terminable; its chroot goes away with it.
    let term = mgr
        .terminate(TerminateRequest {
            workspace_id: POOL_WS_ID.to_string(),
            grace_period_ms: 5_000,
        })
        .await;
    eprintln!("terminate winner = {term:?}");
    assert!(
        matches!(term, SupervisorResponse::WorkspaceTerminated { .. }),
        "winner terminate should succeed, got {term:?}"
    );
    assert!(
        !pool_member_dirs(&chroot_base).contains(&winner_dir),
        "winner chroot should be reaped by terminate"
    );
    let untouched_member = pre_dirs
        .iter()
        .find(|dir| *dir != &winner_dir)
        .expect("two distinct pre-race pool members");
    assert!(
        pool_member_dirs(&chroot_base).contains(untouched_member),
        "the member untouched by the losing create must remain pooled"
    );

    // Reap the refilled pool so no Firecracker process outlives the test.
    mgr.shutdown_pool().await;
}

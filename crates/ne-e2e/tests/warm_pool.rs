// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! KVM-gated e2e for the one-tier warm pool.
//!
//! Asserts: a `create(tier)` HIT returns a ready, identity-distinct workspace
//! far faster than cold-start P50 (1404 ms); the pool refills after
//! checkout; members are reaped (no leaked FC procs) on `shutdown_pool`; and an
//! empty pool falls back to a working synchronous fork.
//!
//! `#[ignore]` by default. On a KVM host:
//! ```sh
//! cargo test -p ne-e2e --test warm_pool -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ne_protocol::snapshot::GuestIdentity;
use ne_protocol::supervisor::{
    CreateWorkspaceRequest, PoolStatusRequest, SupervisorResponse, TerminateRequest,
    WorkspaceCreated,
};
use ne_supervisor::audit::AuditLog;
use ne_supervisor::firecracker::{
    LaunchConfig, firecracker_version, launch, pause, run_command_via_vsock, snapshot_create,
    terminate, wait_for_guest_ready,
};
use ne_supervisor::pool::WarmPoolConfig;
use ne_supervisor::signing::load_or_create_signing_key;
use ne_supervisor::snapshot::{snapshot_dir, write_manifest};
use ne_supervisor::workspace::{WorkspaceManager, WorkspaceManagerConfig};

const PORT: u32 = 52;
const TIER: &str = "default";

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

/// Build a signed base snapshot from a throwaway workspace.
async fn build_base_snapshot(
    env: &HostEnv,
    chroot_base: &Path,
    state_dir: &Path,
    snap_id: &str,
    src_id: &str,
) {
    let image_store = state_dir.join("images");
    let (_, _, verified_images) =
        ne_e2e::resolve_managed_images(&image_store, &env.kernel, &env.rootfs).await;
    let src = launch(LaunchConfig {
        workspace_id: src_id.to_string(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: env.firecracker.clone(),
        jailer_binary: env.jailer.clone(),
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
    let fc_version = firecracker_version(&env.firecracker).await;
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

/// Read a file from a workspace over its vsock socket.
async fn read_via_vsock(vsock_host_socket: &str, path: &str) -> String {
    let uds = PathBuf::from(vsock_host_socket);
    match run_command_via_vsock(&uds, PORT, "/bin/cat", &[path.to_string()], 5_000)
        .await
        .expect("cat")
    {
        ne_protocol::guest::GuestResponse::CommandCompleted(c) => c.stdout.trim().to_string(),
        other => panic!("unexpected guest response: {other:?}"),
    }
}

fn expect_created(resp: SupervisorResponse) -> WorkspaceCreated {
    match resp {
        SupervisorResponse::WorkspaceCreated(w) => w,
        other => panic!("expected WorkspaceCreated, got {other:?}"),
    }
}

async fn pool_available(mgr: &WorkspaceManager) -> u32 {
    match mgr.pool_status(PoolStatusRequest {}).await {
        SupervisorResponse::PoolStatus(s) => s.available,
        other => panic!("expected PoolStatus, got {other:?}"),
    }
}

async fn wait_pool_at_least(mgr: &WorkspaceManager, n: u32, deadline: Duration) {
    let start = Instant::now();
    loop {
        if pool_available(mgr).await >= n {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "pool did not reach {n} ready within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

const ZERO_MACHINE_ID: &str = "00000000000000000000000000000000";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn warm_pool_hit_is_fast_distinct_and_refills() {
    let Some(env) = load_host_env() else { return };

    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().join("chroot");
    let state_dir = tmp.path().join("state");
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");
    tokio::fs::create_dir_all(&chroot_base)
        .await
        .expect("chroot dir");

    build_base_snapshot(&env, &chroot_base, &state_dir, "01J0WARMPOOLSNAP", "wp-src").await;

    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = state_dir.join("images");
    cfg.warm_pool = Some(WarmPoolConfig {
        tier_name: TIER.into(),
        base_snapshot_id: "01J0WARMPOOLSNAP".into(),
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

    // Pool fills to target.
    wait_pool_at_least(&mgr, 2, Duration::from_secs(60)).await;

    // HIT 1 — time the checkout; assert it's a small fraction of 1404 ms.
    let t = Instant::now();
    let wc_a = expect_created(mgr.create(tier_create_req("wp-a")).await);
    let hit_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!("pool-hit checkout latency: {hit_ms:.1} ms");
    assert!(
        hit_ms < 500.0,
        "pool-hit checkout took {hit_ms:.1} ms — not a small fraction of 1404 ms"
    );

    // HIT 2.
    let wc_b = expect_created(mgr.create(tier_create_req("wp-b")).await);

    // Identity distinct + actually reset (not the zero placeholder).
    let ma = read_via_vsock(&wc_a.vsock_host_socket, "/etc/machine-id").await;
    let mb = read_via_vsock(&wc_b.vsock_host_socket, "/etc/machine-id").await;
    assert_ne!(ma, mb, "pooled members must have distinct machine-ids");
    assert_ne!(
        ma, ZERO_MACHINE_ID,
        "machine-id must be reset (not the placeholder)"
    );
    assert_ne!(
        mb, ZERO_MACHINE_ID,
        "machine-id must be reset (not the placeholder)"
    );

    // Pool refills back to target after the two checkouts.
    wait_pool_at_least(&mgr, 2, Duration::from_secs(60)).await;

    // Reap: terminate the two adopted workspaces + drain the pool.
    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "wp-a".into(),
            grace_period_ms: 2000,
        })
        .await;
    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "wp-b".into(),
            grace_period_ms: 2000,
        })
        .await;
    mgr.shutdown_pool().await;
    assert_eq!(
        pool_available(&mgr).await,
        0,
        "pool must be empty after shutdown_pool"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn warm_pool_miss_falls_back_to_fork() {
    let Some(env) = load_host_env() else { return };

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
        &env,
        &chroot_base,
        &state_dir,
        "01J0WARMPOOLMISS",
        "wp-miss-src",
    )
    .await;

    // target_size 0 → pool is always empty → every create(tier) takes the
    // synchronous-fork fallback path.
    let mut cfg = WorkspaceManagerConfig::dev_defaults();
    cfg.firecracker_binary = env.firecracker.clone();
    cfg.jailer_binary = env.jailer.clone();
    cfg.chroot_base = chroot_base.clone();
    cfg.state_dir = state_dir.clone();
    cfg.image_store = state_dir.join("images");
    cfg.warm_pool = Some(WarmPoolConfig {
        tier_name: TIER.into(),
        base_snapshot_id: "01J0WARMPOOLMISS".into(),
        target_size: 0,
        max_in_flight: 1,
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

    // Empty pool: create(tier) must still return a ready, identity-reset workspace.
    let wc = expect_created(mgr.create(tier_create_req("wp-miss")).await);
    let mid = read_via_vsock(&wc.vsock_host_socket, "/etc/machine-id").await;
    assert_ne!(
        mid, ZERO_MACHINE_ID,
        "fallback fork must reset the machine-id"
    );

    let _ = mgr
        .terminate(TerminateRequest {
            workspace_id: "wp-miss".into(),
            grace_period_ms: 2000,
        })
        .await;
    mgr.shutdown_pool().await;
}

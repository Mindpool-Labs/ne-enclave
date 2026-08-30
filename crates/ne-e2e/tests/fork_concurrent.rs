// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! KVM-gated concurrent-fork coverage with distinct-identity checks.
//!
//! This test is the gate: prove that two VMs restored
//! concurrently from ONE snapshot (same guest CID baked into vmstate) are each
//! reachable over their own vsock UDS and do not interfere. Firecracker vsock
//! is UDS-based and per-process, so same-CID forks should be independent; this
//! test confirms it empirically before we build identity reset on top.
//!
//! `#[ignore]` by default. Run on a KVM host:
//! ```sh
//! cargo test -p ne-e2e fork_concurrent -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use ne_protocol::snapshot::GuestIdentity;
use ne_supervisor::firecracker::{
    LaunchConfig, RestoreLaunchConfig, launch, pause, reset_identity_via_vsock, restore,
    run_command_via_vsock, snapshot_create, terminate, wait_for_guest_ready, write_file_via_vsock,
};
use ne_supervisor::signing::load_or_create_signing_key;
use ne_supervisor::snapshot::{snapshot_dir, verify_artifact, write_manifest};

const PORT: u32 = 52;
const SNAPSHOT_ID: &str = "01J0FORKSNAP";

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

async fn wait_for_guest(vsock_uds: &Path) {
    let mut ready = false;
    for _ in 0..100 {
        if run_command_via_vsock(vsock_uds, PORT, "/bin/echo", &["r".to_string()], 2_000)
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "guest agent did not become reachable within 10 s");
}

/// Build a non-networked LaunchConfig for the given id (CID is always 3 — the
/// inherited snapshot CID; that is the behavior this test covers).
async fn cfg_for(
    id: &str,
    image_store: &Path,
    kernel_sha256: &str,
    rootfs_sha256: &str,
    firecracker: &Path,
    jailer: &Path,
    chroot_base: &Path,
) -> LaunchConfig {
    let verified_images = ne_supervisor::image::ImageStore::new(image_store.to_path_buf())
        .resolve_pair(kernel_sha256, rootfs_sha256)
        .await
        .expect("resolve managed fork images");
    LaunchConfig {
        workspace_id: id.to_string(),
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
    }
}

#[tokio::test]
#[ignore]
async fn fork_two_concurrent_reachable() {
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
    let chroot_base = tmp.path().to_path_buf();
    let state_dir = tmp.path().to_path_buf();
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &kernel, &rootfs);
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");

    // --- Build a source snapshot from a throwaway ws ---
    let inst = launch(
        cfg_for(
            "fork-src",
            &image_store,
            &kernel_sha256,
            &rootfs_sha256,
            &firecracker,
            &jailer,
            &chroot_base,
        )
        .await,
    )
    .await
    .expect("launch src");
    wait_for_guest(&inst.vsock_host_socket.clone()).await;
    pause(&inst).await.expect("pause src");
    let arts = snapshot_create(&inst).await.expect("snapshot_create");

    let snap_dir = snapshot_dir(&state_dir, SNAPSHOT_ID);
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
    let fc_version = ne_supervisor::firecracker::firecracker_version(&firecracker).await;
    write_manifest(
        &snap_dir,
        &signer,
        SNAPSHOT_ID,
        &inst.workspace_id,
        &fc_version,
        &inst.kernel_sha256,
        &inst.rootfs_sha256,
        GuestIdentity {
            hostname: inst.workspace_id.clone(),
            mac: "unset".into(),
            guest_vsock_cid: inst.guest_vsock_cid,
            vcpu_count: inst.vcpu_count,
            mem_size_mib: inst.mem_size_mib,
        },
        &inst.kernel_boot_args.clone(),
    )
    .await
    .expect("write_manifest");
    terminate(inst, Duration::from_secs(5))
        .await
        .expect("terminate src");
    verify_artifact(&snap_dir).await.expect("verify");

    // --- Restore TWO forks concurrently from the one snapshot ---
    let restore_one = |id: &str| {
        let id = id.to_string();
        let image_store = image_store.clone();
        let kernel_sha256 = kernel_sha256.clone();
        let rootfs_sha256 = rootfs_sha256.clone();
        let firecracker = firecracker.clone();
        let jailer = jailer.clone();
        let chroot_base = chroot_base.clone();
        let mem = snap_dir.join("mem");
        let vmstate = snap_dir.join("vmstate");
        async move {
            let cfg = cfg_for(
                &id,
                &image_store,
                &kernel_sha256,
                &rootfs_sha256,
                &firecracker,
                &jailer,
                &chroot_base,
            )
            .await;
            restore(RestoreLaunchConfig {
                launch: cfg,
                mem_source: mem,
                vmstate_source: vmstate,
            })
            .await
            .expect("restore fork")
        }
    };
    let (fork_a, fork_b) = tokio::join!(restore_one("fork-a"), restore_one("fork-b"));

    // --- Both reachable over their OWN UDS (same inherited CID) ---
    wait_for_guest(&fork_a.vsock_host_socket.clone()).await;
    wait_for_guest(&fork_b.vsock_host_socket.clone()).await;

    // --- No cross-talk: distinct writes in each /workspace, read back ---
    write_file_via_vsock(
        &fork_a.vsock_host_socket.clone(),
        PORT,
        "tag",
        b"A".to_vec(),
        5_000,
    )
    .await
    .expect("write A");
    write_file_via_vsock(
        &fork_b.vsock_host_socket.clone(),
        PORT,
        "tag",
        b"B".to_vec(),
        5_000,
    )
    .await
    .expect("write B");
    let read = |uds: PathBuf| async move {
        match run_command_via_vsock(
            &uds,
            PORT,
            "/bin/cat",
            &["/workspace/tag".to_string()],
            5_000,
        )
        .await
        .expect("cat")
        {
            ne_protocol::guest::GuestResponse::CommandCompleted(c) => c.stdout,
            other => panic!("unexpected: {other:?}"),
        }
    };
    let a = read(fork_a.vsock_host_socket.clone()).await;
    let b = read(fork_b.vsock_host_socket.clone()).await;
    assert_eq!(a.trim(), "A", "fork-a saw wrong content (cross-talk!)");
    assert_eq!(b.trim(), "B", "fork-b saw wrong content (cross-talk!)");

    terminate(fork_a, Duration::from_secs(5)).await.ok();
    terminate(fork_b, Duration::from_secs(5)).await.ok();
}

/// Read a command's stdout from a fork over vsock.
async fn run_stdout(uds: &Path, cmd: &str, args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match run_command_via_vsock(uds, PORT, cmd, &args, 5_000)
        .await
        .expect("run")
    {
        ne_protocol::guest::GuestResponse::CommandCompleted(c) => c.stdout,
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn fork_two_concurrent_distinct_identity() {
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
    let chroot_base = tmp.path().to_path_buf();
    let state_dir = tmp.path().to_path_buf();
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &kernel, &rootfs);
    tokio::fs::create_dir_all(state_dir.join("keys"))
        .await
        .expect("keys dir");

    // Build the source snapshot.
    let inst = launch(
        cfg_for(
            "fork2-src",
            &image_store,
            &kernel_sha256,
            &rootfs_sha256,
            &firecracker,
            &jailer,
            &chroot_base,
        )
        .await,
    )
    .await
    .expect("launch src");
    wait_for_guest(&inst.vsock_host_socket.clone()).await;
    pause(&inst).await.expect("pause src");
    let arts = snapshot_create(&inst).await.expect("snapshot_create");
    let snap_id = "01J0FORK2SNAP";
    let snap_dir = snapshot_dir(&state_dir, snap_id);
    tokio::fs::create_dir_all(&snap_dir)
        .await
        .expect("snap dir");
    tokio::fs::copy(&arts.mem_in_chroot, snap_dir.join("mem"))
        .await
        .expect("mem");
    tokio::fs::copy(&arts.vmstate_in_chroot, snap_dir.join("vmstate"))
        .await
        .expect("vmstate");
    let signer = load_or_create_signing_key(&state_dir.join("keys"))
        .await
        .expect("signer");
    let fc_version = ne_supervisor::firecracker::firecracker_version(&firecracker).await;
    write_manifest(
        &snap_dir,
        &signer,
        snap_id,
        &inst.workspace_id,
        &fc_version,
        &inst.kernel_sha256,
        &inst.rootfs_sha256,
        GuestIdentity {
            hostname: inst.workspace_id.clone(),
            mac: "unset".into(),
            guest_vsock_cid: inst.guest_vsock_cid,
            vcpu_count: inst.vcpu_count,
            mem_size_mib: inst.mem_size_mib,
        },
        &inst.kernel_boot_args.clone(),
    )
    .await
    .expect("write_manifest");
    terminate(inst, Duration::from_secs(5))
        .await
        .expect("terminate src");
    verify_artifact(&snap_dir).await.expect("verify");

    // Fork twice concurrently: restore + reset identity, mirroring fork().
    let fork_one = |id: &str, host: &str, mid: &str| {
        let id = id.to_string();
        let image_store = image_store.clone();
        let kernel_sha256 = kernel_sha256.clone();
        let rootfs_sha256 = rootfs_sha256.clone();
        let firecracker = firecracker.clone();
        let jailer = jailer.clone();
        let chroot_base = chroot_base.clone();
        let mem = snap_dir.join("mem");
        let vmstate = snap_dir.join("vmstate");
        let host = host.to_string();
        let mid = mid.to_string();
        async move {
            let cfg = cfg_for(
                &id,
                &image_store,
                &kernel_sha256,
                &rootfs_sha256,
                &firecracker,
                &jailer,
                &chroot_base,
            )
            .await;
            let f = restore(RestoreLaunchConfig {
                launch: cfg,
                mem_source: mem,
                vmstate_source: vmstate,
            })
            .await
            .expect("restore");
            wait_for_guest_ready(&f.vsock_host_socket.clone(), PORT, Duration::from_secs(10))
                .await
                .expect("ready");
            let r = reset_identity_via_vsock(
                &f.vsock_host_socket.clone(),
                PORT,
                host,
                mid,
                vec![0xABu8; 32],
                30_000,
            )
            .await
            .expect("reset");
            assert!(
                matches!(r, ne_protocol::guest::GuestResponse::IdentityReset { .. }),
                "expected IdentityReset, got {r:?}"
            );
            f
        }
    };
    let (fa, fb) = tokio::join!(
        fork_one("fork2-a", "fork2-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        fork_one("fork2-b", "fork2-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );

    // Distinct hostnames.
    let ha = run_stdout(&fa.vsock_host_socket.clone(), "/bin/hostname", &[]).await;
    let hb = run_stdout(&fb.vsock_host_socket.clone(), "/bin/hostname", &[]).await;
    assert_eq!(ha.trim(), "fork2-a", "fork-a hostname");
    assert_eq!(hb.trim(), "fork2-b", "fork-b hostname");
    assert_ne!(ha.trim(), hb.trim(), "hostnames must differ");

    // Distinct machine-ids.
    let ma = run_stdout(
        &fa.vsock_host_socket.clone(),
        "/bin/cat",
        &["/etc/machine-id"],
    )
    .await;
    let mb = run_stdout(
        &fb.vsock_host_socket.clone(),
        "/bin/cat",
        &["/etc/machine-id"],
    )
    .await;
    assert_eq!(
        ma.trim(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "fork-a machine-id"
    );
    assert_eq!(
        mb.trim(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "fork-b machine-id"
    );
    assert_ne!(ma.trim(), mb.trim(), "machine-ids must differ");

    // No cross-talk in /workspace.
    write_file_via_vsock(
        &fa.vsock_host_socket.clone(),
        PORT,
        "who",
        b"A".to_vec(),
        5_000,
    )
    .await
    .expect("write A");
    write_file_via_vsock(
        &fb.vsock_host_socket.clone(),
        PORT,
        "who",
        b"B".to_vec(),
        5_000,
    )
    .await
    .expect("write B");
    let ra = run_stdout(
        &fa.vsock_host_socket.clone(),
        "/bin/cat",
        &["/workspace/who"],
    )
    .await;
    let rb = run_stdout(
        &fb.vsock_host_socket.clone(),
        "/bin/cat",
        &["/workspace/who"],
    )
    .await;
    assert_eq!(ra.trim(), "A");
    assert_eq!(rb.trim(), "B");

    terminate(fa, Duration::from_secs(5)).await.ok();
    terminate(fb, Duration::from_secs(5)).await.ok();
}

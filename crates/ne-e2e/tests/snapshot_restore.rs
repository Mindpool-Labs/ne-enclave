// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! KVM-gated snapshot/restore round-trip + pause/resume e2e.
//!
//! **Headline test:** writes `/workspace/foo` (in guest tmpfs) → pauses ws-A →
//! takes a Full snapshot → terminates ws-A → verifies the artifact → restores
//! into ws-B → reads `/workspace/foo` back and asserts the content survived.
//!
//! **Secondary test (sentinel):** launches a workspace, pauses, resumes
//! in-place, and asserts the guest is NOT reachable over vsock afterward —
//! documenting the confirmed Firecracker limitation that motivated deferring
//! the public Pause/Resume API. It flips (fails) if a future FC ever fixes
//! in-place resume, prompting us to re-enable the API.
//!
//! Both tests are `#[ignore]` by default. Run on a KVM host with:
//!
//! ```sh
//! cargo test -p ne-e2e -- --ignored
//! ```
//!
//! Required env (defaults chosen for a standard KVM-capable dev host):
//!
//! - `NE_E2E_KERNEL`      — host path to vmlinux
//! - `NE_E2E_ROOTFS`      — host path to rootfs.img
//! - `NE_E2E_FIRECRACKER` — defaults to `/usr/local/bin/firecracker`
//! - `NE_E2E_JAILER`      — defaults to `/usr/local/bin/jailer`

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::Duration;

use ne_protocol::snapshot::GuestIdentity;
use ne_supervisor::firecracker::{
    LaunchConfig, RestoreLaunchConfig, launch, pause, restore, resume, run_command_via_vsock,
    snapshot_create, terminate, write_file_via_vsock,
};
use ne_supervisor::signing::load_or_create_signing_key;
use ne_supervisor::snapshot::{snapshot_dir, verify_artifact, write_manifest};

/// Guest vsock port the guest agent binds on — must match `firecracker_roundtrip.rs`.
const PORT: u32 = 52;

/// Fixed snapshot identifier for the round-trip test.
const SNAPSHOT_ID: &str = "01J0E2ESNAP";

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

/// Wait for the guest agent to become reachable (up to 10 s, probed every 100 ms).
async fn wait_for_guest(vsock_uds: &std::path::Path) {
    let mut ready = false;
    for _ in 0..100 {
        match run_command_via_vsock(vsock_uds, PORT, "/bin/echo", &["ready".to_string()], 2_000)
            .await
        {
            Ok(_) => {
                ready = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(ready, "guest agent did not become reachable within 10 s");
}

#[tokio::test]
#[ignore]
async fn snapshot_restore_roundtrip() {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return;
    }

    let kernel = env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux");
    let rootfs = env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img");
    let firecracker = env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker");
    let jailer = env_path("NE_E2E_JAILER", "/usr/local/bin/jailer");
    assert!(kernel.is_file(), "kernel not found at {}", kernel.display());
    assert!(rootfs.is_file(), "rootfs not found at {}", rootfs.display());
    assert!(
        firecracker.is_file(),
        "firecracker not found at {}",
        firecracker.display()
    );
    assert!(jailer.is_file(), "jailer not found at {}", jailer.display());

    let tmp = tempfile::tempdir().expect("tempdir");
    let chroot_base = tmp.path().to_path_buf();
    let state_dir = tmp.path().to_path_buf();
    let image_store = tmp.path().join("images");
    let (kernel_sha256, rootfs_sha256) =
        ne_e2e::prepare_managed_images(&image_store, &kernel, &rootfs);

    // Create the keys subdir for the signing key.
    let keys_dir = state_dir.join("keys");
    tokio::fs::create_dir_all(&keys_dir)
        .await
        .expect("create keys dir");

    // --- Step 1: Launch ws-A ---
    let verified_images = ne_supervisor::image::ImageStore::new(image_store.clone())
        .resolve_pair(&kernel_sha256, &rootfs_sha256)
        .await
        .expect("resolve source images");
    let cfg_a = LaunchConfig {
        workspace_id: "snap-src".to_string(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: firecracker.clone(),
        jailer_binary: jailer.clone(),
        chroot_base: chroot_base.clone(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    };

    let inst_a = launch(cfg_a).await.expect("launch ws-A");
    let vsock_a = inst_a.vsock_host_socket.clone();

    wait_for_guest(&vsock_a).await;

    // --- Step 2: Write a marker file into ws-A's tmpfs ---
    let resp = write_file_via_vsock(&vsock_a, PORT, "foo", b"hi".to_vec(), 5_000)
        .await
        .expect("write_file_via_vsock");
    match resp {
        ne_protocol::guest::GuestResponse::FileWritten(w) => {
            assert_eq!(w.absolute_path, "/workspace/foo");
        }
        other => panic!("expected FileWritten, got {other:?}"),
    }

    // --- Step 3: Pause ws-A ---
    pause(&inst_a).await.expect("pause ws-A");

    // --- Step 4: snapshot_create — artifacts land inside the jail chroot ---
    let arts = snapshot_create(&inst_a).await.expect("snapshot_create");

    // --- Step 5: Copy artifacts to the managed snapshot dir and write manifest ---
    let snap_dir = snapshot_dir(&state_dir, SNAPSHOT_ID);
    tokio::fs::create_dir_all(&snap_dir)
        .await
        .expect("create snap dir");
    tokio::fs::copy(&arts.mem_in_chroot, snap_dir.join("mem"))
        .await
        .expect("copy mem");
    tokio::fs::copy(&arts.vmstate_in_chroot, snap_dir.join("vmstate"))
        .await
        .expect("copy vmstate");

    let signer = load_or_create_signing_key(&keys_dir)
        .await
        .expect("load signing key");

    let fc_version = ne_supervisor::firecracker::firecracker_version(&firecracker).await;

    let guest_identity = GuestIdentity {
        hostname: inst_a.workspace_id.clone(),
        mac: "06:00:00:00:00:01".to_string(),
        guest_vsock_cid: inst_a.guest_vsock_cid,
        vcpu_count: inst_a.vcpu_count,
        mem_size_mib: inst_a.mem_size_mib,
    };

    write_manifest(
        &snap_dir,
        &signer,
        SNAPSHOT_ID,
        &inst_a.workspace_id,
        &fc_version,
        &inst_a.kernel_sha256,
        &inst_a.rootfs_sha256,
        guest_identity,
        &inst_a.kernel_boot_args.clone(),
    )
    .await
    .expect("write_manifest");

    // --- Step 6: Terminate ws-A entirely ---
    terminate(inst_a, Duration::from_secs(5))
        .await
        .expect("terminate ws-A");

    // --- Step 7: Verify the snapshot artifact (signature + hashes) ---
    verify_artifact(&snap_dir).await.expect("verify_artifact");

    // --- Step 8: Restore into ws-B ---
    let verified_images = ne_supervisor::image::ImageStore::new(image_store)
        .resolve_pair(&kernel_sha256, &rootfs_sha256)
        .await
        .expect("resolve restore images");
    let cfg_b = LaunchConfig {
        workspace_id: "snap-dst".to_string(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: firecracker.clone(),
        jailer_binary: jailer.clone(),
        chroot_base: chroot_base.clone(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    };

    let inst_b = restore(RestoreLaunchConfig {
        launch: cfg_b,
        mem_source: snap_dir.join("mem"),
        vmstate_source: snap_dir.join("vmstate"),
    })
    .await
    .expect("restore into ws-B");

    let vsock_b = inst_b.vsock_host_socket.clone();

    // Firecracker resumes the VM on load (resume_vm: true) — wait for guest agent.
    wait_for_guest(&vsock_b).await;

    // --- Step 9: Read the marker back from ws-B ---
    let resp = run_command_via_vsock(
        &vsock_b,
        PORT,
        "cat",
        &["/workspace/foo".to_string()],
        5_000,
    )
    .await
    .expect("run cat on ws-B");
    match resp {
        ne_protocol::guest::GuestResponse::CommandCompleted(c) => {
            assert_eq!(c.exit_code, 0, "cat /workspace/foo exited non-zero");
            assert!(
                c.stdout.contains("hi"),
                "expected stdout to contain 'hi', got {:?}",
                c.stdout,
            );
        }
        other => panic!("expected CommandCompleted from ws-B cat, got {other:?}"),
    }

    // --- Step 10: Terminate ws-B (best-effort) ---
    terminate(inst_b, Duration::from_secs(5)).await.ok();
}

/// Documents the confirmed Firecracker limitation: after an
/// in-place pause→resume, host→guest vsock is dead (FC stops servicing
/// CONNECTs), so the guest is unreachable. The public Pause/Resume API is
/// deferred for this reason; snapshot/restore (fresh process) is the
/// supported path. This test is a SENTINEL: if a future Firecracker fixes
/// in-place resume, the command will succeed and this test will fail,
/// prompting us to re-enable the public API.
#[tokio::test]
#[ignore]
async fn in_place_resume_breaks_vsock_known_limitation() {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing — run on a KVM host");
        return;
    }
    let kernel = env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux");
    let rootfs = env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img");
    let firecracker = env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker");
    let jailer = env_path("NE_E2E_JAILER", "/usr/local/bin/jailer");
    assert!(kernel.is_file(), "kernel not found at {}", kernel.display());
    assert!(rootfs.is_file(), "rootfs not found at {}", rootfs.display());
    assert!(
        firecracker.is_file(),
        "firecracker not found at {}",
        firecracker.display()
    );
    assert!(jailer.is_file(), "jailer not found at {}", jailer.display());

    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, _, verified_images) =
        ne_e2e::resolve_managed_images(&tmp.path().join("images"), &kernel, &rootfs).await;
    let cfg = LaunchConfig {
        workspace_id: "in-place-resume-limitation".to_string(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 5,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: firecracker.clone(),
        jailer_binary: jailer.clone(),
        chroot_base: tmp.path().to_path_buf(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    };

    let inst = launch(cfg).await.expect("launch");
    let vsock = inst.vsock_host_socket.clone();

    // Guest reachable before pause.
    wait_for_guest(&vsock).await;

    // In-place pause then resume.
    pause(&inst).await.expect("pause");
    resume(&inst).await.expect("resume");

    // KNOWN LIMITATION: after in-place resume the guest is NOT reachable over
    // vsock. A single short-timeout probe must FAIL (no successful command).
    // We give it a small grace + a couple attempts so this isn't flaky on a
    // transient, but it must not succeed.
    let mut reachable = false;
    for _ in 0..3 {
        if run_command_via_vsock(&vsock, PORT, "/bin/echo", &["x".to_string()], 2_000)
            .await
            .is_ok()
        {
            reachable = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !reachable,
        "UNEXPECTED: in-place resume made the guest reachable over vsock — \
         Firecracker may have fixed the limitation; re-enable the public \
         Pause/Resume API and restore a positive pause_resume_e2e test."
    );

    terminate(inst, Duration::from_secs(5)).await.ok();
}

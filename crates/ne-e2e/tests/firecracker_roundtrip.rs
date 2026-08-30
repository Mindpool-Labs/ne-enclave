// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Real Firecracker round-trip. Boots a microVM via
//! [`ne_supervisor::firecracker::launch`], hits Ping, RunCommand,
//! WriteFile, ReadFile across the vsock, then terminates and asserts
//! chroot cleanup.
//!
//! `#[ignore]` by default. Run with:
//!
//! ```sh
//! cargo test -p ne-e2e -- --ignored
//! ```
//!
//! Required env (defaults chosen for a standard KVM-capable dev host):
//!
//! - `NE_E2E_KERNEL`     — host path to vmlinux
//! - `NE_E2E_ROOTFS`     — host path to rootfs.img
//! - `NE_E2E_FIRECRACKER` — defaults to `/usr/local/bin/firecracker`
//! - `NE_E2E_JAILER`     — defaults to `/usr/local/bin/jailer`

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::Duration;

use ne_supervisor::firecracker::{
    LaunchConfig, launch, read_file_via_vsock, run_command_via_vsock, terminate,
    write_file_via_vsock,
};

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test]
#[ignore]
async fn firecracker_roundtrip() {
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
    let workspace_id = format!("e2e-rt-{}", std::process::id());
    let (_, _, verified_images) =
        ne_e2e::resolve_managed_images(&tmp.path().join("images"), &kernel, &rootfs).await;

    let cfg = LaunchConfig {
        workspace_id: workspace_id.clone(),
        verified_images,
        rootfs_read_only: true,
        vcpu_count: 1,
        mem_size_mib: 128,
        guest_vsock_cid: 3,
        kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".into(),
        firecracker_binary: firecracker,
        jailer_binary: jailer,
        chroot_base: chroot_base.clone(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    };

    let instance = launch(cfg).await.expect("launch");
    let vsock_uds = instance.vsock_host_socket.clone();
    let jailer_chroot_parent = instance.jailer_chroot.parent().unwrap().to_path_buf();

    // Wait briefly for the guest agent to bind. Probe with a Ping every
    // 100 ms for up to 10 s.
    let mut ready = false;
    for _ in 0..100 {
        match run_command_via_vsock(&vsock_uds, 52, "/bin/echo", &["ready".to_string()], 2_000)
            .await
        {
            Ok(_) => {
                ready = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(ready, "guest agent did not become reachable within 10s");

    // RunCommand: echo "hi"
    let resp = run_command_via_vsock(&vsock_uds, 52, "/bin/echo", &["hi".to_string()], 5_000)
        .await
        .expect("run_command");
    match resp {
        ne_protocol::guest::GuestResponse::CommandCompleted(c) => {
            assert_eq!(c.exit_code, 0);
            assert!(c.stdout.contains("hi"), "got stdout={:?}", c.stdout);
        }
        other => panic!("expected CommandCompleted, got {other:?}"),
    }

    // WriteFile
    let resp = write_file_via_vsock(&vsock_uds, 52, "rt.txt", b"hello".to_vec(), 5_000)
        .await
        .expect("write_file");
    match resp {
        ne_protocol::guest::GuestResponse::FileWritten(w) => {
            assert_eq!(w.bytes_written, 5);
            assert_eq!(w.absolute_path, "/workspace/rt.txt");
        }
        other => panic!("expected FileWritten, got {other:?}"),
    }

    // ReadFile
    let resp = read_file_via_vsock(&vsock_uds, 52, "rt.txt", 0, 5_000)
        .await
        .expect("read_file");
    match resp {
        ne_protocol::guest::GuestResponse::FileRead(r) => {
            assert_eq!(r.content, b"hello");
            assert!(!r.truncated);
        }
        other => panic!("expected FileRead, got {other:?}"),
    }

    terminate(instance, Duration::from_secs(2))
        .await
        .expect("terminate");

    // Cleanup assertion: terminate() removes the workspace chroot tree.
    assert!(
        !jailer_chroot_parent.exists(),
        "chroot parent {} still exists after terminate",
        jailer_chroot_parent.display(),
    );
}

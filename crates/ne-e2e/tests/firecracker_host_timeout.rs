// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Confirms that the host's 30-second cap fires when a guest
//! command outruns the supplied `timeout_ms`. Run with:
//!
//! ```sh
//! cargo test -p ne-e2e -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ne_protocol::guest::{GuestErrorKind, GuestResponse};
use ne_supervisor::firecracker::{
    GuestRpcError, LaunchConfig, launch, run_command_via_vsock, terminate,
};

fn env_path(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test]
#[ignore]
async fn firecracker_host_timeout() {
    if !ne_e2e::host_can_launch_firecracker() {
        eprintln!("skip: /dev/kvm missing");
        return;
    }
    let kernel = env_path("NE_E2E_KERNEL", "/var/lib/ne-enclave/vmlinux");
    let rootfs = env_path("NE_E2E_ROOTFS", "/var/lib/ne-enclave/rootfs.img");
    let firecracker = env_path("NE_E2E_FIRECRACKER", "/usr/local/bin/firecracker");
    let jailer = env_path("NE_E2E_JAILER", "/usr/local/bin/jailer");
    let tmp = tempfile::tempdir().expect("tempdir");
    let workspace_id = format!("e2e-to-{}", std::process::id());
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
        chroot_base: tmp.path().to_path_buf(),
        jailer_uid: 1000,
        jailer_gid: 1000,
        api_socket_timeout: Duration::from_secs(5),
        network: None,
    };

    let instance = launch(cfg).await.expect("launch");
    let vsock_uds = instance.vsock_host_socket.clone();

    // Wait for guest agent.
    let mut ready = false;
    for _ in 0..100 {
        match run_command_via_vsock(&vsock_uds, 52, "/bin/true", &[], 2_000).await {
            Ok(_) => {
                ready = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(ready, "guest not ready");

    // Sleep 5 s under a 100 ms host wall clock.
    let start = Instant::now();
    let result = run_command_via_vsock(&vsock_uds, 52, "/bin/sleep", &["5".to_string()], 100).await;
    let elapsed = start.elapsed();
    match result {
        Err(GuestRpcError::Timeout(100)) => {}
        Ok(GuestResponse::Error {
            kind: GuestErrorKind::Timeout,
            ..
        }) => {}
        other => panic!("expected host or guest timeout, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_millis(800),
        "host timeout not tight: {elapsed:?}"
    );

    terminate(instance, Duration::from_secs(2))
        .await
        .expect("terminate");
}

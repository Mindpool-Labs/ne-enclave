// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Host-side timeout propagation through the three vsock
//! RPC helpers. Uses a fake `UnixListener` server that completes the
//! CONNECT handshake and then hangs, forcing the host's
//! `tokio::time::timeout` to fire.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::Instant;

use ne_supervisor::firecracker::{
    GuestRpcError, read_file_via_vsock, run_command_via_vsock, write_file_via_vsock,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

fn spawn_wedged_uds_server(dir: &Path) -> PathBuf {
    let sock = dir.join("wedged.sock");
    let listener = UnixListener::bind(&sock).expect("bind");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (rd, mut wr) = stream.split();
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let _ = wr.write_all(b"OK 0\n").await;
            // Hang.
            std::future::pending::<()>().await;
        }
    });
    sock
}

#[tokio::test]
async fn run_command_via_vsock_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = spawn_wedged_uds_server(tmp.path());
    let start = Instant::now();
    let result = run_command_via_vsock(&sock, 52, "/bin/true", &[], 100).await;
    assert!(start.elapsed() < Duration::from_millis(500));
    match result {
        Err(GuestRpcError::Timeout(100)) => {}
        other => panic!("expected Timeout(100), got {other:?}"),
    }
}

#[tokio::test]
async fn write_file_via_vsock_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = spawn_wedged_uds_server(tmp.path());
    let start = Instant::now();
    let result = write_file_via_vsock(&sock, 52, "rt.txt", b"hi".to_vec(), 100).await;
    assert!(start.elapsed() < Duration::from_millis(500));
    match result {
        Err(GuestRpcError::Timeout(100)) => {}
        other => panic!("expected Timeout(100), got {other:?}"),
    }
}

#[tokio::test]
async fn read_file_via_vsock_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = spawn_wedged_uds_server(tmp.path());
    let start = Instant::now();
    let result = read_file_via_vsock(&sock, 52, "rt.txt", 0, 100).await;
    assert!(start.elapsed() < Duration::from_millis(500));
    match result {
        Err(GuestRpcError::Timeout(100)) => {}
        other => panic!("expected Timeout(100), got {other:?}"),
    }
}

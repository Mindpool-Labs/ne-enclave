// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! `api_request`/`api_put` must not hang forever against a wedged
//! Firecracker API socket. Uses a fake `UnixListener` server that accepts
//! the connection and then stalls, forcing the host's
//! `tokio::time::timeout` to fire. Mirrors `tests/timeout_propagation.rs`'s
//! wedged-server pattern.
//!
//! `api_put` itself is private; this drives it through the `test-support`
//! -gated `api_put_for_test` hook (see `Cargo.toml`'s `test-support`
//! feature and `firecracker.rs`'s `api_put_for_test`) rather than widening
//! `api_put` to `pub` in ordinary builds.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ne_supervisor::firecracker::{LaunchError, api_put_for_test};
use serde_json::json;
use tokio::net::UnixListener;

/// Bind a UDS that accepts a connection and then hangs — never reads or
/// writes anything back, so any HTTP response parsing on the client side
/// blocks forever without a deadline.
fn spawn_wedged_uds_server(dir: &Path) -> PathBuf {
    let sock = dir.join("fc-wedged.sock");
    let listener = UnixListener::bind(&sock).expect("bind fake fc api socket");
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            // Accept and hang — the client's write may succeed (it just
            // fills a kernel buffer), but nothing ever replies.
            std::future::pending::<()>().await;
        }
    });
    sock
}

#[tokio::test]
async fn api_put_times_out_on_wedged_socket() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let sock = spawn_wedged_uds_server(tmp.path());

    let start = Instant::now();
    let result = api_put_for_test(
        &sock,
        "/machine-config",
        &json!({"vcpu_count": 1, "mem_size_mib": 128}),
        Duration::from_millis(200),
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "api_put must respect its deadline instead of hanging; took {elapsed:?}"
    );
    match result {
        Err(LaunchError::ApiSocketTimeout(path)) => assert_eq!(path, sock),
        other => panic!("expected ApiSocketTimeout, got {other:?}"),
    }
}

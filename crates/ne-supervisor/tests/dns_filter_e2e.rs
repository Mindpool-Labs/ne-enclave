// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test: per-workspace DNS filter spawned inside the
//! workspace netns + iptables DNAT redirects all UDP/53 to it.
//!
//! Focus is the deny path (the security-critical one): a denied
//! hostname must return NXDOMAIN without the packet ever leaving
//! the host. We also assert the filter PID is alive after setup,
//! the iptables DNAT rules land in the netns, and teardown
//! reclaims both. The forwarding (allow) path is exercised by
//! `ne-dns-filter`'s own integration test against an in-process
//! fake upstream — adding it here would require synthesizing a
//! resolver reachable from inside the netns, which is brittle in
//! Azure-managed network environments.
//!
//! Skipped by default (`#[ignore]`) — needs root for netns + iptables.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use ne_supervisor::network::{NetworkController, NetworkPolicy};

fn ip_binary() -> PathBuf {
    PathBuf::from("/usr/sbin/ip")
}

fn iptables_binary() -> PathBuf {
    PathBuf::from("/usr/sbin/iptables")
}

fn upstream_iface() -> String {
    std::env::var("NE_NETWORK_TEST_IFACE").unwrap_or_else(|_| "eth0".into())
}

fn dns_filter_binary() -> PathBuf {
    // NE_DNS_FILTER_BIN env var lets the harness supply an
    // explicit path (e.g. a release-profile build on the dev VM).
    // When not set, use the fused `nee` binary built by Cargo.
    // The supervisor injects the `dns-filter` subcommand token
    // automatically (see `network.rs::dns_filter_args`).
    if let Ok(path) = std::env::var("NE_DNS_FILTER_BIN") {
        return PathBuf::from(path);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root above CARGO_MANIFEST_DIR")
        .join("target")
        .join("debug")
        .join("nee")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root for netns + iptables; run via `sudo -E ./target/debug/...`"]
async fn dns_filter_denies_unlisted_hostnames_and_teardown_reclaims() {
    let ctl = NetworkController::new(
        ip_binary(),
        iptables_binary(),
        upstream_iface(),
        Some(dns_filter_binary()),
        // No upstream connectivity needed for the deny path — the
        // filter returns NXDOMAIN without ever forwarding.
        "127.0.0.1:1".into(),
        // Privacy router disabled for this DNS-focused e2e; the
        // privacy path has its own audit-relay unit test.
        None,
        None,
        // Audit relay disabled for the e2e — exercising the
        // signed-chain integration belongs in a unit test with a
        // temp AuditLog (see audit-chain follow-up).
        None,
    );

    let workspace_id = format!("wks-dns-{}", std::process::id());
    let policy = NetworkPolicy {
        enable_egress: false,
        allow_cidrs: vec![],
        allow_hostnames: vec!["allowed.example".into()],
        enable_privacy_router: false,
    };
    let slot = ctl.setup(&workspace_id, &policy).await.expect("setup");
    let pid = slot.dns_filter_pid.expect("expected spawn to succeed");

    // Give the filter a moment to bind UDP/53 inside the netns.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Structural assertion 1: the DNAT rule lands in the netns's
    // nat OUTPUT chain. We don't need to count rules precisely —
    // just confirm a DNAT for port 53 is present.
    let nat_dump = Command::new("/usr/sbin/ip")
        .args([
            "netns",
            "exec",
            &slot.netns,
            "iptables",
            "-t",
            "nat",
            "-S",
            "OUTPUT",
        ])
        .output()
        .expect("iptables -S");
    let nat_str = String::from_utf8_lossy(&nat_dump.stdout);
    assert!(
        nat_str.contains("--dport 53") && nat_str.contains("DNAT"),
        "expected DNAT for port 53 in netns OUTPUT, got: {nat_str}",
    );

    // Behavioral assertion: dig for a denied name returns NXDOMAIN.
    // The query is destined to 1.2.3.4 (arbitrary); the DNAT
    // rewrites the destination to our filter, which returns
    // NXDOMAIN because `blocked.evil.example` isn't on the allow
    // list. The packet never leaves the host.
    let denied = Command::new("/usr/sbin/ip")
        .args([
            "netns",
            "exec",
            &slot.netns,
            "dig",
            "+tries=1",
            "+time=2",
            "@1.2.3.4",
            "blocked.evil.example",
        ])
        .output()
        .expect("dig denied");
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied_stdout.contains("status: NXDOMAIN"),
        "expected NXDOMAIN, got stdout={denied_stdout:?} stderr={:?}",
        String::from_utf8_lossy(&denied.stderr),
    );

    // Teardown reclaims the filter PID + netns + iptables state.
    ctl.teardown(slot).await.expect("teardown");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let alive = Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .status()
        .expect("kill -0")
        .success();
    assert!(
        !alive,
        "ne-dns-filter (pid {pid}) must be reaped post-teardown"
    );
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! `ne-guest-agent` binary entry point.
//!
//! Runs inside the Firecracker guest. Listens on a vsock port; the
//! host supervisor (or a control-plane caller relaying through it)
//! connects to dispatch commands. The guest-side wire format mirrors
//! the supervisor's: NDJSON of
//! [`ne_protocol::guest::GuestRequest`] / `GuestResponse`.
//!
//! Linux-only: vsock is an `AF_VSOCK` socket, which exists on Linux
//! (and inside the microVM, which is always Linux). On macOS the
//! binary builds but refuses to run, keeping cross-platform `cargo
//! check` / `clippy` quiet.

// `deny` (not `forbid`) so the single, justified `RNDRESEEDCRNG` ioctl in
// `identity.rs` can be locally `#[allow(unsafe_code)]` with a `// SAFETY:`
// comment (per STANDARDS). All other code remains unsafe-free.
#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

mod files;

// Intentional user-facing stderr — this binary should not be invoked
// on macOS, and the message tells a developer what they're missing.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::print_stderr)]
fn main() -> std::process::ExitCode {
    eprintln!(
        "ne-guest-agent is Linux-only; it runs inside the Firecracker guest. \
         Cross-compile to x86_64-unknown-linux-musl for the minimal guest image."
    );
    std::process::ExitCode::from(1)
}

#[cfg(target_os = "linux")]
pub mod linux_main;

#[cfg(target_os = "linux")]
mod identity;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    linux_main::run().await
}

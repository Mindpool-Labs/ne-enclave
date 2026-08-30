// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Linux implementation of the guest agent. Compiled only on
//! `cfg(target_os = "linux")` — vsock is an `AF_VSOCK` socket.

use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(test)]
use ne_protocol::guest::ResetIdentityRequest;
use ne_protocol::guest::{
    CommandCompleted, FileRead, FileWritten, GuestErrorKind, GuestRequest, GuestResponse,
    ReadFileRequest, RunCommandRequest, WriteFileRequest,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

/// Per-stream cap on captured command output (audit `S3-F2`). Output beyond
/// this is discarded (drained so the child does not block) and `truncated` is
/// set.
const MAX_CMD_OUTPUT_BYTES: usize = 1024 * 1024;

/// Captured stdout/stderr (each with a truncation flag) plus the child exit
/// status from [`run_command`]'s bounded capture future.
type CaptureResult = (
    std::io::Result<(Vec<u8>, bool)>,
    std::io::Result<(Vec<u8>, bool)>,
    std::io::Result<std::process::ExitStatus>,
);

/// Max guest vsock request frame. Host requests (incl. `WriteFile` content) are
/// bounded well under this; rejects a runaway frame instead of growing without
/// limit (audit `S3-F3`).
///
/// The host-side [`ne_protocol::supervisor::MAX_INLINE_FILE_BYTES`] cap is
/// 10 MiB; 32 MiB is comfortably above that plus NDJSON framing overhead,
/// leaving room for future protocol additions without requiring a bump.
const MAX_GUEST_FRAME_BYTES: u64 = 32 * 1024 * 1024;

/// Read `r` fully, retaining at most `cap` bytes; drains and discards the
/// remainder so a child writing more than `cap` does not block on a full pipe.
/// Returns the retained bytes and whether any were dropped.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    // Heap-allocated so the read buffer does not bloat this future's stack size
    // (kept small to satisfy `clippy::large_futures` across the call chain).
    let mut chunk = vec![0u8; 8192];
    let mut truncated = false;
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() < cap {
            let take = (cap - buf.len()).min(n);
            buf.extend_from_slice(&chunk[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((buf, truncated))
}

/// NeuronEdge Enclave guest agent.
#[derive(Debug, Parser)]
#[command(name = "ne-guest-agent", version, about)]
struct Cli {
    /// Vsock port to listen on for host supervisor connections.
    #[arg(long, env = "NE_GUEST_VSOCK_PORT", default_value_t = 52)]
    vsock_port: u32,
}

/// Initialize tracing, bind the vsock listener, and serve forever.
/// Entry point for the binary's `main` on Linux.
pub async fn run() -> Result<()> {
    init_tracing().context("tracing initialization failed")?;
    let cli = Cli::parse();
    let started_at = Instant::now();

    let mut listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, cli.vsock_port))
        .with_context(|| format!("bind vsock port {}", cli.vsock_port))?;
    info!(port = cli.vsock_port, "ne-guest-agent listening");

    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept")?;
        debug!(
            cid = peer.cid(),
            port = peer.port(),
            "guest agent peer connected"
        );
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, started_at).await {
                warn!(error = %e, "guest agent connection ended with error");
            }
        });
    }
}

async fn handle_connection(stream: VsockStream, started_at: Instant) -> std::io::Result<()> {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        // Cap each incoming request frame at MAX_GUEST_FRAME_BYTES so a
        // runaway host (or a misbehaving sender) cannot grow this buffer
        // without bound. Mirrors read_capped_line in
        // crates/ne-supervisor/src/ipc.rs — kept local; the guest-agent
        // is a separate cfg(linux) crate with no shared dep on supervisor.
        let n = {
            // Borrow the reader via &mut so Take wraps `&mut BufReader<_>`
            // rather than consuming the BufReader itself — the underlying
            // reader is still usable after this block for subsequent frames.
            let mut limited = (&mut reader).take(MAX_GUEST_FRAME_BYTES + 1);
            limited.read_line(&mut line).await?
        };
        if n == 0 {
            break;
        }
        if n as u64 > MAX_GUEST_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guest vsock request frame exceeds maximum size",
            ));
        }
        let resp = match serde_json::from_str::<GuestRequest>(line.trim_end()) {
            Ok(req) => dispatch(req, started_at).await,
            Err(e) => GuestResponse::Error {
                kind: GuestErrorKind::InvalidRequest,
                message: e.to_string(),
            },
        };
        let mut bytes = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        wr.write_all(&bytes).await?;
    }
    Ok(())
}

async fn dispatch(req: GuestRequest, started_at: Instant) -> GuestResponse {
    match req {
        GuestRequest::Ping => GuestResponse::Pong {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_ms: u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        GuestRequest::RunCommand(req) => run_command(req).await,
        GuestRequest::WriteFile(req) => write_file(req).await,
        GuestRequest::ReadFile(req) => read_file(req).await,
        GuestRequest::ResetIdentity(req) => crate::identity::reset_identity(&req),
        // Future variants require an RFC.
        _ => GuestResponse::Error {
            kind: GuestErrorKind::Internal,
            message: "operation not implemented in this guest-agent build".to_string(),
        },
    }
}

async fn run_command(req: RunCommandRequest) -> GuestResponse {
    let started = Instant::now();
    let _wallclock = SystemTime::now(); // reserved for future audit-event timestamping

    // Spawn with piped stdout/stderr so we can cap each stream independently
    // kill_on_drop(true) ensures the child is reaped when the
    // capture future is dropped on timeout.
    let mut cmd = Command::new(&req.command);
    cmd.args(&req.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return GuestResponse::Error {
                kind: GuestErrorKind::CommandFailed,
                message: e.to_string(),
            };
        }
    };

    // Take the piped handles before the capture future is constructed. They are
    // `Some` because stdout/stderr were just set to `piped()`; handle `None`
    // gracefully rather than panic (no unwrap/expect in production).
    let (Some(mut stdout_pipe), Some(mut stderr_pipe)) = (child.stdout.take(), child.stderr.take())
    else {
        return GuestResponse::Error {
            kind: GuestErrorKind::Internal,
            message: "failed to capture command stdio pipes".to_string(),
        };
    };

    // Capture both streams concurrently, then wait for the child.
    // The async block borrows child + pipes so we pin it as a named future to
    // allow wrapping in timeout() without a move closure.
    let capture_fut = async {
        let (out_res, err_res) = tokio::join!(
            read_capped(&mut stdout_pipe, MAX_CMD_OUTPUT_BYTES),
            read_capped(&mut stderr_pipe, MAX_CMD_OUTPUT_BYTES),
        );
        let status = child.wait().await;
        (out_res, err_res, status)
    };

    // Run capture_fut directly or wrapped in a timeout. On timeout the future
    // is dropped, and kill_on_drop(true) reaps the child automatically.
    let triple: CaptureResult = if req.timeout_ms == 0 {
        capture_fut.await
    } else {
        match timeout(
            Duration::from_millis(u64::from(req.timeout_ms)),
            capture_fut,
        )
        .await
        {
            Ok(t) => t,
            Err(_elapsed) => {
                return GuestResponse::Error {
                    kind: GuestErrorKind::Timeout,
                    message: format!("command exceeded timeout {}ms", req.timeout_ms),
                };
            }
        }
    };

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (out_res, err_res, status_res) = triple;

    match (out_res, err_res, status_res) {
        (Ok((stdout_bytes, out_truncated)), Ok((stderr_bytes, err_truncated)), Ok(status)) => {
            GuestResponse::CommandCompleted(CommandCompleted {
                stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
                stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
                exit_code: status.code().unwrap_or(-1),
                elapsed_ms,
                truncated: out_truncated || err_truncated,
            })
        }
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => GuestResponse::Error {
            kind: GuestErrorKind::CommandFailed,
            message: e.to_string(),
        },
    }
}

const JAIL_ROOT: &str = "/workspace";
/// Hard cap on a single file-I/O syscall sequence inside the guest.
/// Five seconds under the host's 30 s vsock timeout so the typed
/// `Timeout` response reaches the host before the wall clock fires.
const FILE_OP_TIMEOUT: Duration = Duration::from_secs(25);

async fn write_file(req: WriteFileRequest) -> GuestResponse {
    write_file_with_timeout(req, FILE_OP_TIMEOUT).await
}

async fn write_file_with_timeout(req: WriteFileRequest, op_timeout: Duration) -> GuestResponse {
    let jail = std::path::Path::new(JAIL_ROOT).to_path_buf();
    // NOTE: create_dir_all runs on the async thread BEFORE spawn_blocking,
    // so a wedged filesystem could hang here outside the FILE_OP_TIMEOUT
    // budget. Acceptable for the current guest image — /workspace is tmpfs in the guest
    // image — but tighten in a future release if a real filesystem replaces
    // tmpfs.
    let _ = std::fs::create_dir_all(&jail);
    let bytes_written = req.content.len() as u64;
    let path = req.path.clone();
    let content = req.content;
    let join = tokio::task::spawn_blocking(move || {
        crate::files::write_file_atomic(&jail, &path, &content)
    });
    match timeout(op_timeout, join).await {
        Ok(Ok(Ok(absolute_path))) => GuestResponse::FileWritten(FileWritten {
            bytes_written,
            absolute_path: absolute_path.display().to_string(),
        }),
        Ok(Ok(Err(e))) => GuestResponse::Error {
            kind: e.kind(),
            message: e.to_string(),
        },
        Ok(Err(join_err)) => GuestResponse::Error {
            kind: GuestErrorKind::Internal,
            message: format!("write_file task panicked: {join_err}"),
        },
        Err(_elapsed) => GuestResponse::Error {
            kind: GuestErrorKind::Timeout,
            message: format!("write_file exceeded {}ms", op_timeout.as_millis()),
        },
    }
}

async fn read_file(req: ReadFileRequest) -> GuestResponse {
    read_file_with_timeout(req, FILE_OP_TIMEOUT).await
}

async fn read_file_with_timeout(req: ReadFileRequest, op_timeout: Duration) -> GuestResponse {
    let jail = std::path::Path::new(JAIL_ROOT).to_path_buf();
    let path = req.path.clone();
    let max_bytes = req.max_bytes;
    let join = tokio::task::spawn_blocking(move || {
        crate::files::read_file_capped(&jail, &path, max_bytes)
    });
    match timeout(op_timeout, join).await {
        Ok(Ok(Ok((content, size_bytes, truncated)))) => GuestResponse::FileRead(FileRead {
            content,
            size_bytes,
            truncated,
        }),
        Ok(Ok(Err(e))) => GuestResponse::Error {
            kind: e.kind(),
            message: e.to_string(),
        },
        Ok(Err(join_err)) => GuestResponse::Error {
            kind: GuestErrorKind::Internal,
            message: format!("read_file task panicked: {join_err}"),
        },
        Err(_elapsed) => GuestResponse::Error {
            kind: GuestErrorKind::Timeout,
            message: format!("read_file exceeded {}ms", op_timeout.as_millis()),
        },
    }
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatch_ping_returns_pong_with_agent_version() {
        let started = Instant::now();
        let resp = dispatch(GuestRequest::Ping, started).await;
        match resp {
            GuestResponse::Pong { agent_version, .. } => {
                assert_eq!(agent_version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_command_echo_returns_completed() {
        // `/bin/echo` is universally present on Linux distros that
        // would run the guest agent. On the CI macOS shadow build
        // this test would be cfg'd out (the whole module is Linux-only).
        let resp = run_command(RunCommandRequest {
            command: "/bin/echo".into(),
            args: vec!["hello".into()],
            timeout_ms: 1_000,
        })
        .await;
        match resp {
            GuestResponse::CommandCompleted(c) => {
                assert_eq!(c.exit_code, 0);
                assert!(c.stdout.contains("hello"), "got stdout={:?}", c.stdout);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_command_times_out() {
        let resp = run_command(RunCommandRequest {
            command: "/bin/sleep".into(),
            args: vec!["5".into()],
            timeout_ms: 100,
        })
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::Timeout,
                ..
            } => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_command_nonexistent_binary_returns_command_failed() {
        let resp = run_command(RunCommandRequest {
            command: "/this/does/not/exist".into(),
            args: vec![],
            timeout_ms: 1_000,
        })
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::CommandFailed,
                ..
            } => {}
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_write_file_then_read_round_trips() {
        // Skip if /workspace isn't writable on the host running these
        // (macOS / CI sandboxes vary). The same logic is unit-tested
        // under a tempdir in the `files` module.
        if std::fs::write("/workspace/.dispatch_probe", b"x").is_err() {
            // /workspace not writable in this environment — skip silently
            return;
        }
        let _ = std::fs::remove_file("/workspace/.dispatch_probe");

        let started = Instant::now();
        let resp = dispatch(
            GuestRequest::WriteFile(WriteFileRequest {
                path: "dispatch-rt.txt".into(),
                content: b"hi".to_vec(),
            }),
            started,
        )
        .await;
        match resp {
            GuestResponse::FileWritten(w) => {
                assert_eq!(w.bytes_written, 2);
                assert_eq!(w.absolute_path, "/workspace/dispatch-rt.txt");
            }
            other => panic!("expected FileWritten, got {other:?}"),
        }

        let resp = dispatch(
            GuestRequest::ReadFile(ReadFileRequest {
                path: "dispatch-rt.txt".into(),
                max_bytes: 0,
            }),
            started,
        )
        .await;
        match resp {
            GuestResponse::FileRead(r) => assert_eq!(r.content, b"hi"),
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_write_rejects_absolute_path() {
        let resp = dispatch(
            GuestRequest::WriteFile(WriteFileRequest {
                path: "/etc/passwd".into(),
                content: b"x".to_vec(),
            }),
            Instant::now(),
        )
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::PathRejected,
                ..
            } => {}
            other => panic!("expected PathRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_file_times_out() {
        // Skip if /workspace isn't writable on the host running these
        // (macOS / CI sandboxes / non-root users vary). Without the guard,
        // a host where the spawn_blocking write wins the Duration::ZERO race
        // returns the underlying fs error (e.g. EACCES) instead of Timeout.
        // The same logic is unit-tested under a tempdir in the `files` module.
        if std::fs::write("/workspace/.timeout_probe", b"x").is_err() {
            // /workspace not writable in this environment — skip silently
            return;
        }
        let _ = std::fs::remove_file("/workspace/.timeout_probe");

        // Structural smoke test: with Duration::ZERO, tokio's scheduling
        // fairness fires the timer before the spawn_blocking future makes
        // progress. This exercises the Timeout match arm deterministically
        // but does not test real blocking-thread interruption. Genuine
        // wedged-disk behaviour is exercised by the Firecracker e2e test
        // covered by the Firecracker end-to-end test.
        let resp = write_file_with_timeout(
            WriteFileRequest {
                path: "timeout-probe.txt".into(),
                content: b"x".to_vec(),
            },
            Duration::from_millis(0),
        )
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::Timeout,
                message,
            } => {
                assert!(
                    message.contains("write_file exceeded"),
                    "got message={message:?}"
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_reset_identity_rejects_bad_machine_id() {
        let resp = dispatch(
            GuestRequest::ResetIdentity(ResetIdentityRequest {
                hostname: "fork-a".into(),
                machine_id: "bad".into(),
                entropy_seed: vec![],
            }),
            Instant::now(),
        )
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::InvalidRequest,
                ..
            } => {}
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_file_times_out() {
        // Skip if /workspace isn't writable on the host running these
        // (macOS / CI sandboxes / non-root users vary). Without the guard,
        // a host where the spawn_blocking read wins the Duration::ZERO race
        // returns the underlying fs error (e.g. ENOENT) instead of Timeout.
        // The same logic is unit-tested under a tempdir in the `files` module.
        if std::fs::write("/workspace/.timeout_probe", b"x").is_err() {
            // /workspace not writable in this environment — skip silently
            return;
        }
        let _ = std::fs::remove_file("/workspace/.timeout_probe");

        // Structural smoke test: with Duration::ZERO, tokio's scheduling
        // fairness fires the timer before the spawn_blocking future makes
        // progress. This exercises the Timeout match arm deterministically
        // but does not test real blocking-thread interruption. Genuine
        // wedged-disk behaviour is exercised by the Firecracker e2e test
        // covered by the Firecracker end-to-end test.
        let resp = read_file_with_timeout(
            ReadFileRequest {
                path: "timeout-probe.txt".into(),
                max_bytes: 0,
            },
            Duration::from_millis(0),
        )
        .await;
        match resp {
            GuestResponse::Error {
                kind: GuestErrorKind::Timeout,
                message,
            } => {
                assert!(
                    message.contains("read_file exceeded"),
                    "got message={message:?}"
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    /// Verify that `run_command` caps stdout at `MAX_CMD_OUTPUT_BYTES` and sets
    /// `truncated = true` when a child produces more output than the cap
    /// `head -c <2×cap> /dev/zero` emits 2 MiB of NUL bytes to
    /// stdout; the guest rootfs ships coreutils at `/usr/bin/head`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_command_caps_large_output() {
        // `head -c <2*cap> /dev/zero` emits 2 MiB of NULs to stdout.
        let resp = run_command(RunCommandRequest {
            command: "/usr/bin/head".into(),
            args: vec![
                "-c".into(),
                (MAX_CMD_OUTPUT_BYTES * 2).to_string(),
                "/dev/zero".into(),
            ],
            timeout_ms: 5_000,
        })
        .await;
        match resp {
            GuestResponse::CommandCompleted(c) => {
                assert!(c.truncated, "output past the cap must set truncated");
                assert!(
                    c.stdout.len() <= MAX_CMD_OUTPUT_BYTES,
                    "stdout must be capped"
                );
            }
            other => panic!("expected CommandCompleted, got {other:?}"),
        }
    }
}

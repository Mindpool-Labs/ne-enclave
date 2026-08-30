// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Typed IPC schema between the host supervisor and the
//! `ne-guest-agent` running inside a Firecracker microVM.
//!
//! Wire format on the vsock channel is the same NDJSON we use for the
//! supervisor's host-side IPC (see [`crate::supervisor`]): one
//! request per line, one response per line, in lockstep on a single
//! connection. The shared format makes it trivial for the supervisor
//! to relay between an SDK caller and the guest.
//!
//! # Example
//!
//! ```
//! use ne_protocol::guest::GuestRequest;
//!
//! let req = GuestRequest::Ping;
//! let encoded = serde_json::to_string(&req).unwrap();
//! assert_eq!(encoded, r#"{"op":"ping"}"#);
//! ```

use serde::{Deserialize, Serialize};

/// Wire protocol version for the guest channel. Bumped on
/// incompatible request/response schema changes.
pub const GUEST_PROTOCOL_VERSION: u32 = 1;

/// Operations the guest agent accepts.
///
/// `#[non_exhaustive]` so adding a new operation in the protocol crate
/// does not break older guest builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuestRequest {
    /// Liveness probe. Replies with [`GuestResponse::Pong`].
    Ping,
    /// Execute one command inside the guest and return its output.
    RunCommand(RunCommandRequest),
    /// Atomically write a file under the guest's `/workspace` jail.
    WriteFile(WriteFileRequest),
    /// Read a file from under the guest's `/workspace` jail.
    ReadFile(ReadFileRequest),
    /// Reset the guest's identity after a fork: set a fresh hostname,
    /// rewrite `/etc/machine-id`, and mix fresh host-supplied entropy
    /// into the kernel RNG so a forked clone diverges from its source.
    ResetIdentity(ResetIdentityRequest),
}

/// One-shot command execution. The guest waits up to `timeout_ms`,
/// then sends the process `SIGKILL` and replies with
/// [`GuestResponse::Error`] of kind [`GuestErrorKind::Timeout`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCommandRequest {
    /// Path to the command binary (resolved via guest `$PATH`).
    pub command: String,
    /// Arguments passed verbatim to the command. No shell interpretation.
    pub args: Vec<String>,
    /// Per-call timeout in milliseconds. 0 disables the timeout.
    pub timeout_ms: u32,
}

/// Responses the guest agent emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuestResponse {
    /// Reply to [`GuestRequest::Ping`].
    Pong {
        /// Crate version string of the running guest agent.
        agent_version: String,
        /// Milliseconds since the guest agent began accepting connections.
        uptime_ms: u64,
    },
    /// Successful completion of [`GuestRequest::RunCommand`].
    CommandCompleted(CommandCompleted),
    /// Reply to a successful [`GuestRequest::WriteFile`].
    FileWritten(FileWritten),
    /// Reply to a successful [`GuestRequest::ReadFile`].
    FileRead(FileRead),
    /// Reply to a successful [`GuestRequest::ResetIdentity`]. Echoes the
    /// applied hostname + machine-id for the host's audit record.
    IdentityReset {
        /// Hostname now set in the guest.
        hostname: String,
        /// machine-id now written in the guest (32 lowercase hex).
        machine_id: String,
    },
    /// Any failure path. Callers branch on `kind`, not on `message`.
    Error {
        /// Stable, machine-readable error classifier.
        kind: GuestErrorKind,
        /// Human-readable message; never load-bearing for control flow.
        message: String,
    },
}

/// Result of one successful command run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandCompleted {
    /// Captured stdout as UTF-8, lossily converted (invalid bytes
    /// become `U+FFFD`). This response returns the full buffer in one shot;
    /// a later API version can add streaming.
    pub stdout: String,
    /// Captured stderr; same conversion as `stdout`.
    pub stderr: String,
    /// Process exit code. `-1` if the process was terminated by a
    /// signal and produced no code (the protocol surfaces the signal
    /// separately).
    pub exit_code: i32,
    /// Wall-clock duration the command ran for.
    pub elapsed_ms: u64,
    /// True if stdout or stderr was truncated at the guest agent's per-stream
    /// output cap. The captured bytes are still valid; only the
    /// tail was dropped. `#[serde(default)]` so a host running this build can
    /// still parse a response from a guest agent that predates the field
    /// (additive wire-compat; the guest image is upgraded independently).
    #[serde(default)]
    pub truncated: bool,
}

/// Atomic file write inside the guest's jail root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileRequest {
    /// Relative path inside `/workspace`.
    pub path: String,
    /// Content to write.
    pub content: Vec<u8>,
}

/// Fork identity reset (`GuestRequest::ResetIdentity`).
///
/// All values are generated by the host (a forked guest is a byte-clone
/// with identical RNG state, so it cannot self-generate distinct values).
/// The guest only *applies* them. See the fork design spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetIdentityRequest {
    /// New hostname (applied via `sethostname(2)`; valid host label).
    pub hostname: String,
    /// New machine-id: exactly 32 lowercase hex chars. Written to
    /// `/etc/machine-id` (a symlink to writable `/run/machine-id`).
    pub machine_id: String,
    /// Fresh entropy bytes mixed into `/dev/urandom`. 32 bytes by
    /// convention; the guest writes them verbatim into the RNG pool.
    pub entropy_seed: Vec<u8>,
}

/// File read from inside the guest's jail root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFileRequest {
    /// Relative path inside `/workspace`.
    pub path: String,
    /// Maximum bytes to return. `0` means use the guest's default cap.
    pub max_bytes: u64,
}

/// Result of a successful [`GuestRequest::WriteFile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWritten {
    /// Bytes written to disk.
    pub bytes_written: u64,
    /// Absolute path inside the guest (`/workspace/<relative>`).
    pub absolute_path: String,
}

/// Result of a successful [`GuestRequest::ReadFile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRead {
    /// File contents; may be shorter than `size_bytes` when truncated.
    pub content: Vec<u8>,
    /// Size of the file on disk.
    pub size_bytes: u64,
    /// True if the read was truncated.
    pub truncated: bool,
}

/// Stable error classifier for [`GuestResponse::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuestErrorKind {
    /// Request could not be parsed or was malformed.
    InvalidRequest,
    /// Command could not be spawned (binary not found, exec failed).
    CommandFailed,
    /// Command ran longer than the request's `timeout_ms`.
    Timeout,
    /// Catch-all for unexpected guest-agent-side failures.
    Internal,
    /// Path violated the jail policy (absolute, `..`, null byte, or
    /// resolved outside `/workspace`).
    PathRejected,
    /// File read targeted a path that does not exist.
    FileNotFound,
    /// Request payload exceeded the guest's body cap.
    FileTooLarge,
    /// Guest-side filesystem I/O failed (disk full, permission, fsync,
    /// rename, etc.). Distinct from `Internal` so the supervisor can
    /// map it cleanly to `SupervisorErrorKind::IoError`.
    IoError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrips() {
        let req = GuestRequest::Ping;
        let json = serde_json::to_string(&req).expect("serialize Ping");
        assert_eq!(json, r#"{"op":"ping"}"#);
        let back: GuestRequest = serde_json::from_str(&json).expect("deserialize Ping");
        assert_eq!(back, req);
    }

    #[test]
    fn run_command_request_roundtrips() {
        let req = GuestRequest::RunCommand(RunCommandRequest {
            command: "/bin/echo".into(),
            args: vec!["hello".into(), "world".into()],
            timeout_ms: 5_000,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn command_completed_response_roundtrips() {
        let resp = GuestResponse::CommandCompleted(CommandCompleted {
            stdout: "hello world\n".into(),
            stderr: String::new(),
            exit_code: 0,
            elapsed_ms: 12,
            truncated: false,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn pong_and_error_roundtrip() {
        let pong = GuestResponse::Pong {
            agent_version: "0.0.0".into(),
            uptime_ms: 42,
        };
        assert_eq!(
            serde_json::from_str::<GuestResponse>(
                &serde_json::to_string(&pong).expect("serialize")
            )
            .expect("deserialize"),
            pong
        );

        for kind in [
            GuestErrorKind::InvalidRequest,
            GuestErrorKind::CommandFailed,
            GuestErrorKind::Timeout,
            GuestErrorKind::Internal,
        ] {
            let err = GuestResponse::Error {
                kind,
                message: "boom".into(),
            };
            assert_eq!(
                serde_json::from_str::<GuestResponse>(
                    &serde_json::to_string(&err).expect("serialize")
                )
                .expect("deserialize"),
                err
            );
        }
    }

    #[test]
    fn guest_write_file_roundtrips() {
        let req = GuestRequest::WriteFile(WriteFileRequest {
            path: "a/b.txt".into(),
            content: b"hi".to_vec(),
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn guest_read_file_roundtrips() {
        let req = GuestRequest::ReadFile(ReadFileRequest {
            path: "a/b.txt".into(),
            max_bytes: 1024,
        });
        let json = serde_json::to_string(&req).expect("serialize");
        let back: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn guest_file_written_response_roundtrips() {
        let resp = GuestResponse::FileWritten(FileWritten {
            bytes_written: 2,
            absolute_path: "/workspace/a/b.txt".into(),
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn guest_file_read_response_roundtrips() {
        let resp = GuestResponse::FileRead(FileRead {
            content: b"hi".to_vec(),
            size_bytes: 2,
            truncated: false,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn reset_identity_request_roundtrips() {
        let req = GuestRequest::ResetIdentity(ResetIdentityRequest {
            hostname: "fork-a".into(),
            machine_id: "0123456789abcdef0123456789abcdef".into(),
            entropy_seed: vec![1, 2, 3, 4],
        });
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains("\"op\":\"reset_identity\""), "got {json}");
        let back: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn identity_reset_response_roundtrips() {
        let resp = GuestResponse::IdentityReset {
            hostname: "fork-a".into(),
            machine_id: "0123456789abcdef0123456789abcdef".into(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"status\":\"identity_reset\""), "got {json}");
        let back: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn new_guest_error_kinds_roundtrip() {
        for (variant, expected) in [
            (GuestErrorKind::PathRejected, "path_rejected"),
            (GuestErrorKind::FileNotFound, "file_not_found"),
            (GuestErrorKind::FileTooLarge, "file_too_large"),
            (GuestErrorKind::IoError, "io_error"),
        ] {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(s, format!("\"{expected}\""));
            let back: GuestErrorKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, variant);
        }
    }
}

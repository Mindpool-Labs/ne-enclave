// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Thin client for the privileged supervisor's NDJSON IPC.
//!
//! The current implementation uses one connection per request. A connection
//! pool + reconnect-with-backoff lands once we have more than a
//! handful of ops in flight per second.

use std::path::PathBuf;

use ne_protocol::supervisor::{SupervisorRequest, SupervisorResponse};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Errors a supervisor call can produce on the API side.
#[derive(Debug, Error)]
pub enum SupervisorClientError {
    /// IO failure on the unix socket (connect / read / write).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encode/decode failure on the request or response.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Supervisor returned a typed error response (not an IO failure).
    #[error("supervisor error: {message}")]
    Supervisor {
        /// Stable error classifier echoed from the supervisor.
        kind: ne_protocol::supervisor::SupervisorErrorKind,
        /// Human-readable message; for control-flow use `kind`.
        message: String,
    },
    /// Supervisor returned an unexpected variant for this request.
    #[error("unexpected supervisor response: {0}")]
    Unexpected(String),
}

/// Handle to a supervisor IPC endpoint. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SupervisorClient {
    socket_path: PathBuf,
}

impl SupervisorClient {
    /// Construct a client pointing at the supervisor's unix socket.
    /// The socket isn't opened until the first call.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send one request, read one response.
    pub async fn call(
        &self,
        req: &SupervisorRequest,
    ) -> Result<SupervisorResponse, SupervisorClientError> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);

        let mut body = serde_json::to_vec(req)?;
        body.push(b'\n');
        wr.write_all(&body).await?;
        wr.flush().await?;

        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let resp: SupervisorResponse = serde_json::from_str(line.trim_end())?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ne_protocol::supervisor::SupervisorErrorKind;
    use tokio::net::UnixListener;

    /// Spawns a tiny in-process NDJSON echo-server that replies with
    /// a fixed `Pong`. Returns the socket path; the server lives for
    /// the lifetime of the returned `tokio::task::JoinHandle`.
    fn fake_supervisor() -> (tempfile::TempDir, PathBuf, tokio::task::JoinHandle<()>) {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("super.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut reader = BufReader::new(rd);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let resp = SupervisorResponse::Pong {
                        version: "0.0.0-fake".into(),
                        uptime_ms: 42,
                    };
                    let mut body = serde_json::to_vec(&resp).expect("ser");
                    body.push(b'\n');
                    let _ = wr.write_all(&body).await;
                });
            }
        });
        (tmp, path, handle)
    }

    #[tokio::test]
    async fn ping_round_trip_against_fake_supervisor() {
        let (_tmp, path, server) = fake_supervisor();
        let client = SupervisorClient::new(path);
        let resp = client.call(&SupervisorRequest::Ping).await.expect("call");
        match resp {
            SupervisorResponse::Pong { version, uptime_ms } => {
                assert_eq!(version, "0.0.0-fake");
                assert_eq!(uptime_ms, 42);
            }
            other => panic!("expected Pong, got {other:?}"),
        }
        server.abort();
    }

    #[test]
    fn error_kind_preserves_classification() {
        let err = SupervisorClientError::Supervisor {
            kind: SupervisorErrorKind::Unauthorized,
            message: "no".into(),
        };
        match err {
            SupervisorClientError::Supervisor { kind, .. } => {
                assert_eq!(kind, SupervisorErrorKind::Unauthorized);
            }
            _ => panic!("wrong variant"),
        }
    }
}

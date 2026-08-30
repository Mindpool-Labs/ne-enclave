// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket IPC server for the supervisor.
//!
//! The supervisor's IPC surface is a unix domain socket
//! with peer-credential authentication. Wire format: newline-delimited
//! JSON of [`SupervisorRequest`] / [`SupervisorResponse`].
//!
//! # Peer authentication
//!
//! In production the supervisor runs as `root` and accepts only an
//! [`ne-api`](crate) caller whose UID matches [`PeerAuth::RequireUid`].
//! In `NE_DEV_MODE=1`, [`PeerAuth::DevDisabled`]
//! turns the UID check off; the server still binds the socket but logs
//! a warning on each connection.

use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ne_protocol::supervisor::{SupervisorErrorKind, SupervisorRequest, SupervisorResponse};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::command::Dispatcher;
use crate::util::read_capped_line;

/// Maximum size of a single newline-delimited IPC request frame.
///
/// Control-plane requests are small JSON; this bounds a misbehaving or
/// malicious (authenticated/dev-mode) peer from growing the read buffer without
/// limit (memory-exhaustion denial of service, audit `S2-F4`).
const MAX_IPC_FRAME_BYTES: u64 = 1024 * 1024;

/// Authentication policy for incoming connections.
#[derive(Debug, Clone, Copy)]
pub enum PeerAuth {
    /// Accept connections only from this UID. Production default.
    RequireUid(u32),
    /// Accept all connections; log a warning. For `NE_DEV_MODE=1`.
    DevDisabled,
}

/// A bound unix-socket server. Construct with [`IpcServer::bind`] then
/// drive with [`IpcServer::serve`].
#[derive(Debug)]
pub struct IpcServer {
    listener: UnixListener,
    auth: PeerAuth,
    path: PathBuf,
}

impl IpcServer {
    /// Bind the socket at `path`. Any pre-existing file at `path` is
    /// removed first; a later revision hardens this against TOCTOU. ENOENT on
    /// removal is expected (and ignored).
    pub async fn bind(path: impl AsRef<Path>, auth: PeerAuth) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        match tokio::fs::remove_file(&path).await {
            Ok(()) => debug!(socket = %path.display(), "removed stale socket"),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        // Socket permissions. The supervisor runs as root while
        // the API daemon runs as the unprivileged `ne` user, so the socket
        // must be reachable across uids. SO_PEERCRED is the authentication gate;
        // the file mode is a coarse reachability control layered under the
        // 0750 root:ne socket directory.
        //
        // * Dev mode: peer auth is OFF and the client may be an arbitrary uid
        //   (tests connect cross-uid with no shared group) → stay 0666.
        // * Production: restrict to owner + the socket directory's group
        //   (root:ne in the packaged deploy) and drop world access → 0660.
        let mode = if matches!(auth, PeerAuth::DevDisabled) {
            0o666
        } else {
            // Inherit the parent directory's group so a group-member client
            // (the `ne`-group API daemon) can still connect. Best-effort:
            // a non-root supervisor may lack permission to chgrp, in which case
            // the socket keeps the process's own group and 0660 still applies.
            use std::os::unix::fs::MetadataExt;
            if let Some(parent) = path.parent()
                && let Ok(meta) = std::fs::metadata(parent)
                && let Err(e) = std::os::unix::fs::chown(&path, None, Some(meta.gid()))
            {
                debug!(socket = %path.display(), error = %e, "socket chgrp skipped");
            }
            0o660
        };
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).await?;
        info!(socket = %path.display(), ?auth, mode = format!("{mode:o}"), "supervisor IPC server bound");
        Ok(Self {
            listener,
            auth,
            path,
        })
    }

    /// The bound socket path. Useful for tests and the reconciler.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept connections forever. Each connection runs on its own
    /// tokio task. Returns only on a fatal `accept(2)` error.
    pub async fn serve(self, dispatcher: Arc<Dispatcher>) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let dispatcher = Arc::clone(&dispatcher);
            let auth = self.auth;
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, auth, dispatcher).await {
                    if matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe) {
                        debug!(error = %e, "supervisor IPC peer disconnected");
                    } else {
                        warn!(error = %e, "supervisor IPC connection ended with error");
                    }
                }
            });
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    auth: PeerAuth,
    dispatcher: Arc<Dispatcher>,
) -> io::Result<()> {
    let cred = stream.peer_cred()?;
    let uid = cred.uid();
    match auth {
        PeerAuth::RequireUid(expected) if uid != expected => {
            warn!(
                peer_uid = uid,
                expected, "rejecting peer with mismatched uid"
            );
            let resp = SupervisorResponse::Error {
                kind: SupervisorErrorKind::Unauthorized,
                message: format!("unauthorized peer uid {uid}"),
            };
            write_one(stream, &resp).await?;
            return Ok(());
        }
        PeerAuth::RequireUid(_) => {
            debug!(peer_uid = uid, peer_pid = ?cred.pid(), "peer authorized");
        }
        PeerAuth::DevDisabled => {
            warn!(peer_uid = uid, peer_pid = ?cred.pid(), "NE_DEV_MODE=1: peer auth disabled");
        }
    }

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        let n = read_capped_line(&mut reader, &mut line, MAX_IPC_FRAME_BYTES).await?;
        if n == 0 {
            break;
        }
        let resp = match serde_json::from_str::<SupervisorRequest>(line.trim_end()) {
            Ok(req) => dispatcher.dispatch(req).await,
            Err(e) => SupervisorResponse::Error {
                kind: SupervisorErrorKind::InvalidRequest,
                message: e.to_string(),
            },
        };
        let mut bytes = serde_json::to_vec(&resp).map_err(io::Error::other)?;
        bytes.push(b'\n');
        wr.write_all(&bytes).await?;
    }
    Ok(())
}

async fn write_one(stream: UnixStream, resp: &SupervisorResponse) -> io::Result<()> {
    let (_, mut wr) = stream.into_split();
    let mut bytes = serde_json::to_vec(resp).map_err(io::Error::other)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn dev_mode_socket_is_group_and_world_connectable() {
        // Dev mode disables peer auth and tests connect cross-uid with no
        // shared group, so the socket stays broadly connectable.
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("dev.sock");
        let _srv = IpcServer::bind(&sock, PeerAuth::DevDisabled).await.unwrap();
        let mode = std::fs::metadata(&sock).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o666, "dev-mode socket should be 0o666, got {mode:o}");
    }

    #[tokio::test]
    async fn production_socket_is_group_restricted() {
        // Production restricts to owner + the socket directory's group; world
        // access is removed (SO_PEERCRED remains the real gate).
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("prod.sock");
        let _srv = IpcServer::bind(&sock, PeerAuth::RequireUid(4242))
            .await
            .unwrap();
        let meta = std::fs::metadata(&sock).unwrap();
        let mode = meta.mode() & 0o777;
        assert_eq!(mode, 0o660, "prod socket should be 0o660, got {mode:o}");
        // Group should follow the parent directory (root:ne in the deploy;
        // the tempdir's own gid here).
        let dir_gid = std::fs::metadata(tmp.path()).unwrap().gid();
        assert_eq!(
            meta.gid(),
            dir_gid,
            "socket group should inherit the directory"
        );
    }

    #[tokio::test]
    async fn capped_line_reads_normal_frame() {
        let data = b"hello world\n".to_vec();
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let n = read_capped_line(&mut reader, &mut line, 1024)
            .await
            .unwrap();
        assert_eq!(n, 12);
        assert_eq!(line, "hello world\n");
    }

    #[tokio::test]
    async fn capped_line_accepts_frame_at_exact_cap() {
        let data = b"1234\n".to_vec(); // 5 bytes incl newline
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let n = read_capped_line(&mut reader, &mut line, 5).await.unwrap();
        assert_eq!(n, 5);
    }
}

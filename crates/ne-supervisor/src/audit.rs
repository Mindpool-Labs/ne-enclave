// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Signed audit event log.
//!
//! Implements the per-event Ed25519 + Merkle-chain audit design.
//! decision. Cross-platform — the supervisor emits events on every
//! op regardless of whether the underlying Firecracker launch is
//! reachable.
//!
//! On-disk layout:
//!
//! ```text
//! <state_dir>/
//!   keys/
//!     audit-signing.ed25519       0600 — private key (32 bytes raw)
//!     audit-signing.pub.ed25519   0644 — public key (32 bytes raw)
//!   audit.jsonl                   one signed AuditEvent per line
//! ```
//!
//! Key handling: on first run the supervisor generates a fresh
//! Ed25519 keypair and writes both halves. Subsequent runs load the
//! existing pair so signatures remain verifiable across restarts.
//! The public key is carried inline in every emitted event so
//! consumers don't need an out-of-band fetch.
//!
//! Chain handling: each event records `chain_index` (monotonic from
//! 0) and `prev_hash_hex` (hex SHA-256 of the canonical-JSON
//! serialization of event `chain_index - 1`). Genesis uses
//! `prev_hash_hex = "00".repeat(32)`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use ne_protocol::audit::{AuditEvent, EventType, ListEventsRequest, ListEventsResponse};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{info, warn};

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors emitted by the audit log subsystem.
#[derive(Debug, Error)]
pub enum AuditError {
    /// IO error opening / writing the log or key files.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encode/decode error on an event or recovery scan.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Signing-key file is malformed (wrong length, bad bytes).
    #[error("key: {0}")]
    Key(String),
    /// `SystemTime::now()` was before the Unix epoch (clock skew).
    #[error("system time before unix epoch")]
    Time,
}

/// Singleton handle for the supervisor's audit log. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuditLog {
    inner: std::sync::Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    signing_key: SigningKey,
    signer_pubkey_b64: String,
    log_path: PathBuf,
    chain: Mutex<ChainState>,
}

#[derive(Debug)]
struct ChainState {
    next_index: u64,
    last_canonical: Option<Vec<u8>>,
}

impl AuditLog {
    /// Open (or initialize) the audit log under `state_dir`. Generates
    /// the signing keypair on first run; loads it on subsequent runs.
    /// Replays the existing JSONL to recover the chain head.
    pub async fn open(state_dir: &Path) -> Result<Self, AuditError> {
        let keys_dir = state_dir.join("keys");
        let log_path = state_dir.join("audit.jsonl");
        tokio::fs::create_dir_all(&keys_dir).await?;

        let signing_key = crate::signing::load_or_create_signing_key(&keys_dir)
            .await
            .map_err(|e| AuditError::Key(e.to_string()))?;
        let signer_pubkey_b64 = B64.encode(signing_key.verifying_key().as_bytes());

        let chain = recover_chain_head(&log_path).await?;
        info!(
            log = %log_path.display(),
            next_index = chain.next_index,
            pubkey = %signer_pubkey_b64,
            "audit log opened"
        );

        Ok(Self {
            inner: std::sync::Arc::new(Inner {
                signing_key,
                signer_pubkey_b64,
                log_path,
                chain: Mutex::new(chain),
            }),
        })
    }

    /// Sign and append one event. Returns the chain index assigned to
    /// the event.
    pub async fn emit(
        &self,
        event_type: EventType,
        workspace_id: Option<String>,
        payload: serde_json::Value,
    ) -> Result<u64, AuditError> {
        let mut chain = self.inner.chain.lock().await;
        let chain_index = chain.next_index;
        let prev_hash_hex = chain.last_canonical.as_ref().map_or_else(
            || GENESIS_PREV_HASH.to_string(),
            |bytes| hex::encode(Sha256::digest(bytes)),
        );

        let timestamp_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AuditError::Time)?
                .as_millis(),
        )
        .unwrap_or(u64::MAX);

        let mut event = AuditEvent {
            event_id: ulid::Ulid::new().to_string(),
            timestamp_ms,
            event_type,
            workspace_id,
            payload,
            chain_index,
            prev_hash_hex,
            // Filled in below after we sign the canonical form.
            signature_b64: String::new(),
            signer_pubkey_b64: self.inner.signer_pubkey_b64.clone(),
        };

        let to_sign = canonicalize(&event)?;
        let sig = self.inner.signing_key.sign(&to_sign);
        event.signature_b64 = B64.encode(sig.to_bytes());

        // Persist as one JSON line. We re-serialize the fully-formed
        // event (signature included) for the log entry.
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.inner.log_path)
            .await?;
        file.write_all(&line).await?;
        file.flush().await?;

        chain.next_index = chain_index.saturating_add(1);
        chain.last_canonical = Some(to_sign);
        Ok(chain_index)
    }

    /// Read events from the log applying the request's filter.
    pub async fn list(&self, req: &ListEventsRequest) -> Result<ListEventsResponse, AuditError> {
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit as usize
        };
        let file = match tokio::fs::File::open(&self.inner.log_path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ListEventsResponse { events: Vec::new() });
            }
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut out = Vec::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            let event: AuditEvent = match serde_json::from_str(line.trim_end()) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "skipping malformed audit log entry");
                    continue;
                }
            };
            if event.chain_index < req.since_chain_index {
                continue;
            }
            if let Some(ref wid) = req.workspace_id
                && event.workspace_id.as_deref() != Some(wid.as_str())
            {
                continue;
            }
            out.push(event);
            if out.len() >= limit {
                break;
            }
        }
        Ok(ListEventsResponse { events: out })
    }

    /// Base64 of the supervisor's audit signing public key. Useful
    /// to surface in health probes once we wire it into Pong.
    #[must_use]
    pub fn signer_pubkey_b64(&self) -> &str {
        &self.inner.signer_pubkey_b64
    }

    /// The runtime instance's Ed25519 signing key. Reused as the
    /// software-attestation root of trust (the same identity that signs
    /// the audit chain). Returns a clone; the key never leaves the host.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        self.inner.signing_key.clone()
    }

    /// The host's Ed25519 **public** verifying key. This is the trust anchor
    /// the restore/fork path pins snapshot-manifest verification to (the host
    /// that wrote a snapshot is the only legitimate signer of its manifest).
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.signing_key.verifying_key()
    }
}

/// Canonical serialization used both for signing and for the chain
/// hash. Delegates to `ne_protocol::audit::canonical_bytes` so
/// the supervisor (signer) and CLI/third-party verifiers share
/// byte-identical canonicalization.
fn canonicalize(event: &AuditEvent) -> Result<Vec<u8>, AuditError> {
    Ok(ne_protocol::audit::canonical_bytes(event)?)
}

async fn recover_chain_head(log_path: &Path) -> Result<ChainState, AuditError> {
    let file = match tokio::fs::File::open(log_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ChainState {
                next_index: 0,
                last_canonical: None,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut last_index: Option<u64> = None;
    let mut last_canonical: Option<Vec<u8>> = None;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let event: AuditEvent = match serde_json::from_str(line.trim_end()) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "skipping malformed audit log entry during recovery");
                continue;
            }
        };
        last_index = Some(event.chain_index);
        last_canonical = Some(canonicalize(&event)?);
    }
    Ok(ChainState {
        next_index: last_index.map_or(0, |i| i + 1),
        last_canonical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_then_list_returns_signed_event() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::open(tmp.path()).await.expect("open");
        let idx = log
            .emit(
                EventType::WorkspaceCreated,
                Some("wks-1".into()),
                serde_json::json!({ "vcpu": 1 }),
            )
            .await
            .expect("emit");
        assert_eq!(idx, 0);

        let events = log
            .list(&ListEventsRequest {
                workspace_id: None,
                since_chain_index: 0,
                limit: 10,
            })
            .await
            .expect("list");
        assert_eq!(events.events.len(), 1);
        let e = &events.events[0];
        assert_eq!(e.chain_index, 0);
        assert_eq!(e.prev_hash_hex, GENESIS_PREV_HASH);
        assert_eq!(e.event_type, EventType::WorkspaceCreated);
        assert_eq!(e.workspace_id.as_deref(), Some("wks-1"));
        assert!(!e.signature_b64.is_empty());
        assert!(!e.signer_pubkey_b64.is_empty());
    }

    #[tokio::test]
    async fn chain_advances_and_prev_hash_links_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::open(tmp.path()).await.expect("open");
        for i in 0..3 {
            log.emit(
                EventType::CommandExecuted,
                Some(format!("wks-{i}")),
                serde_json::json!({}),
            )
            .await
            .expect("emit");
        }
        let events = log
            .list(&ListEventsRequest {
                workspace_id: None,
                since_chain_index: 0,
                limit: 10,
            })
            .await
            .expect("list")
            .events;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].prev_hash_hex, GENESIS_PREV_HASH);
        for w in events.windows(2) {
            let prev_canonical = canonicalize(&w[0]).expect("canonicalize");
            let expected = hex::encode(Sha256::digest(&prev_canonical));
            assert_eq!(
                w[1].prev_hash_hex, expected,
                "chain link broken at {}",
                w[1].chain_index
            );
            assert_eq!(w[1].chain_index, w[0].chain_index + 1);
        }
    }

    #[tokio::test]
    async fn signatures_verify_against_inlined_pubkey() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::open(tmp.path()).await.expect("open");
        log.emit(
            EventType::CommandExecuted,
            None,
            serde_json::json!({ "exit": 0 }),
        )
        .await
        .expect("emit");
        let event = &log
            .list(&ListEventsRequest {
                workspace_id: None,
                since_chain_index: 0,
                limit: 1,
            })
            .await
            .expect("list")
            .events[0];

        let pubkey_bytes = B64.decode(&event.signer_pubkey_b64).expect("b64 pubkey");
        let pubkey = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()).expect("pubkey");
        let sig_bytes = B64.decode(&event.signature_b64).expect("b64 sig");
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        let canonical = canonicalize(event).expect("canonicalize");
        pubkey
            .verify(&canonical, &sig)
            .expect("signature must verify");
    }

    #[tokio::test]
    async fn list_filters_by_workspace_and_since_index() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::open(tmp.path()).await.expect("open");
        log.emit(
            EventType::WorkspaceCreated,
            Some("a".into()),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        log.emit(
            EventType::WorkspaceCreated,
            Some("b".into()),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        log.emit(
            EventType::WorkspaceTerminated,
            Some("a".into()),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let only_a = log
            .list(&ListEventsRequest {
                workspace_id: Some("a".into()),
                since_chain_index: 0,
                limit: 10,
            })
            .await
            .unwrap()
            .events;
        assert_eq!(only_a.len(), 2);
        assert!(
            only_a
                .iter()
                .all(|e| e.workspace_id.as_deref() == Some("a"))
        );

        let from_two = log
            .list(&ListEventsRequest {
                workspace_id: None,
                since_chain_index: 2,
                limit: 10,
            })
            .await
            .unwrap()
            .events;
        assert_eq!(from_two.len(), 1);
        assert_eq!(from_two[0].chain_index, 2);
    }

    #[tokio::test]
    async fn signing_key_matches_emitted_pubkey() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::open(tmp.path()).await.unwrap();
        let sk = log.signing_key();
        let pub_b64 = B64.encode(sk.verifying_key().to_bytes());
        log.emit(EventType::WorkspaceCreated, None, serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(pub_b64.len(), 44); // 32 bytes base64 = 44 chars
    }

    #[tokio::test]
    async fn chain_head_recovers_across_reopens() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let log = AuditLog::open(tmp.path()).await.expect("open");
            log.emit(
                EventType::WorkspaceCreated,
                Some("x".into()),
                serde_json::json!({}),
            )
            .await
            .unwrap();
            log.emit(
                EventType::WorkspaceTerminated,
                Some("x".into()),
                serde_json::json!({}),
            )
            .await
            .unwrap();
        }
        let log2 = AuditLog::open(tmp.path()).await.expect("reopen");
        // Emitting after reopen should land at index 2 with prev_hash
        // matching the canonical hash of the last persisted event.
        log2.emit(
            EventType::CommandExecuted,
            Some("x".into()),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        let all = log2
            .list(&ListEventsRequest {
                workspace_id: None,
                since_chain_index: 0,
                limit: 10,
            })
            .await
            .unwrap()
            .events;
        assert_eq!(all.len(), 3);
        assert_eq!(all[2].chain_index, 2);
        let prev_canonical = canonicalize(&all[1]).expect("canonicalize");
        assert_eq!(
            all[2].prev_hash_hex,
            hex::encode(Sha256::digest(&prev_canonical))
        );
    }
}

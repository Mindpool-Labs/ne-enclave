// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Signed audit event chain types.
//!
//! The supervisor emits per-event Ed25519
//! signatures + maintains a Merkle chain over the log. Each
//! [`AuditEvent`] carries:
//!
//!   * a stable `event_id` (ULID),
//!   * the event's `payload` (typed via `event_type` + free-form
//!     `payload`),
//!   * `chain_index` + `prev_hash_hex` (the Merkle link to event
//!     `chain_index - 1`),
//!   * `signature_b64` over the canonical-JSON serialization of every
//!     field EXCEPT `signature_b64` itself (the `signer_pubkey_b64` is
//!     deliberately INSIDE the signed bytes — see below),
//!   * `signer_pubkey_b64` so consumers can verify without external
//!     key distribution (and so the supervisor can rotate keys later
//!     without invalidating prior entries). Because the public key is
//!     part of the signed bytes, an attacker cannot swap in their own
//!     key to forge an event: doing so changes the canonical bytes and
//!     invalidates the signature.
//!
//! Wire format is the same NDJSON we use throughout — one event per
//! line in the log file, and `ListEvents` responses ship them as a
//! JSON array of [`AuditEvent`].

use serde::{Deserialize, Serialize};

// ── Chain verification constants ─────────────────────────────────────────────

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Chain error types ─────────────────────────────────────────────────────────

/// Why a chain failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainErrorReason {
    /// The Ed25519 signature did not verify against the event's canonical bytes.
    BadSignature,
    /// The `prev_hash_hex` of an event does not match the SHA-256 of the
    /// canonical bytes of the preceding event.
    BrokenLink,
    /// `chain_index` of an event is not exactly `prev.chain_index + 1`.
    NonSequentialIndex,
    /// The `signer_pubkey_b64` field could not be decoded as a valid Ed25519
    /// public key (bad base64, wrong length, or rejected by the library).
    MalformedPubkey,
    /// The `signature_b64` field could not be decoded as a valid 64-byte
    /// Ed25519 signature (bad base64 or wrong length).
    MalformedSignature,
}

/// The first detected break in a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainError {
    /// `chain_index` of the event at which verification stopped.
    pub index: u64,
    /// Precise reason the event failed.
    pub reason: ChainErrorReason,
}

/// Outcome of verifying a complete or partial chain of audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// `true` iff every signature and every chain link verified without error.
    pub ok: bool,
    /// Number of events in the slice that was passed to `verify_chain`.
    pub count: u64,
    /// `chain_index` of the first event in the slice, or `None` if the slice
    /// was empty.
    pub first_index: Option<u64>,
    /// `chain_index` of the last event in the slice, or `None` if the slice
    /// was empty.
    pub last_index: Option<u64>,
    /// Hex-encoded SHA-256 of the canonical bytes of the last successfully
    /// verified event ("pinnable root"). `None` if the slice was empty.
    pub root_hex: Option<String>,
    /// The first error encountered, or `None` on a clean run.
    pub first_error: Option<ChainError>,
}

// ── verify_chain ─────────────────────────────────────────────────────────────

/// Verify every Ed25519 signature and every chain link in `events` in order.
///
/// Stops at the first error and records it in `ChainVerification::first_error`.
///
/// ## Partial-export semantics
///
/// For a full chain the first event has `chain_index == 0` and
/// `prev_hash_hex` must equal the all-zero genesis value.
///
/// For a *partial* export (e.g. events 50–99 of a 100-event log) the first
/// element has `chain_index != 0`; its `prev_hash_hex` link cannot be
/// checked because its predecessor is absent.  In that case the link is
/// **accepted** (unverifiable) but the signature is still fully verified,
/// and forward linking from that point is strictly enforced.
#[must_use]
pub fn verify_chain(events: &[AuditEvent]) -> ChainVerification {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let mut result = ChainVerification {
        ok: true,
        count: events.len() as u64,
        first_index: events.first().map(|e| e.chain_index),
        last_index: events.last().map(|e| e.chain_index),
        root_hex: None,
        first_error: None,
    };

    if events.is_empty() {
        return result;
    }

    let mut prev: Option<&AuditEvent> = None;

    for (pos, e) in events.iter().enumerate() {
        // 1. Compute canonical bytes (serialization error treated as BadSignature —
        //    the event cannot be verified if it cannot be canonicalized).
        let Ok(canon) = canonical_bytes(e) else {
            result.ok = false;
            result.first_error = Some(ChainError {
                index: e.chain_index,
                reason: ChainErrorReason::BadSignature,
            });
            return result;
        };

        // 2. Decode the signer public key.
        let pk_opt = B64
            .decode(&e.signer_pubkey_b64)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let Some(pk_bytes) = pk_opt else {
            result.ok = false;
            result.first_error = Some(ChainError {
                index: e.chain_index,
                reason: ChainErrorReason::MalformedPubkey,
            });
            return result;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            result.ok = false;
            result.first_error = Some(ChainError {
                index: e.chain_index,
                reason: ChainErrorReason::MalformedPubkey,
            });
            return result;
        };

        // 3. Decode the signature.
        let sig_opt = B64
            .decode(&e.signature_b64)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok());
        let Some(sig_bytes) = sig_opt else {
            result.ok = false;
            result.first_error = Some(ChainError {
                index: e.chain_index,
                reason: ChainErrorReason::MalformedSignature,
            });
            return result;
        };

        // 4. Verify the signature.
        // S5-F3: verify_strict rejects non-canonical/small-order signature
        // encodings (uniform with the attestation verifier). The host signer
        // always produces canonical signatures, so existing chains still verify.
        if vk
            .verify_strict(&canon, &Signature::from_bytes(&sig_bytes))
            .is_err()
        {
            result.ok = false;
            result.first_error = Some(ChainError {
                index: e.chain_index,
                reason: ChainErrorReason::BadSignature,
            });
            return result;
        }

        // 5. Check the chain link.
        match prev {
            None => {
                // First element: check genesis only when chain_index == 0.
                // For a partial export starting at index > 0, the predecessor
                // is absent and the link is unverifiable — accept it.
                if e.chain_index == 0 && e.prev_hash_hex != GENESIS_PREV_HASH {
                    result.ok = false;
                    result.first_error = Some(ChainError {
                        index: e.chain_index,
                        reason: ChainErrorReason::BrokenLink,
                    });
                    return result;
                }
            }
            Some(p) => {
                // Subsequent elements: must be sequential in index …
                // `checked_add` guards against u64 overflow at the chain tail
                // (panic in debug / wrap in release) for a hostile index.
                match p.chain_index.checked_add(1) {
                    Some(expected) if expected == e.chain_index => {}
                    _ => {
                        result.ok = false;
                        result.first_error = Some(ChainError {
                            index: e.chain_index,
                            reason: ChainErrorReason::NonSequentialIndex,
                        });
                        return result;
                    }
                }
                // … and the prev-hash must match.
                // p already passed verification above; canonical_bytes(p) cannot
                // fail here. Treat it as a broken link if it somehow does.
                let Ok(prev_canon) = canonical_bytes(p) else {
                    result.ok = false;
                    result.first_error = Some(ChainError {
                        index: e.chain_index,
                        reason: ChainErrorReason::BrokenLink,
                    });
                    return result;
                };
                let expected = hex::encode(Sha256::digest(prev_canon));
                if e.prev_hash_hex != expected {
                    result.ok = false;
                    result.first_error = Some(ChainError {
                        index: e.chain_index,
                        reason: ChainErrorReason::BrokenLink,
                    });
                    return result;
                }
            }
        }

        // 6. Update the pinnable root after the last event.
        if pos == events.len() - 1 {
            result.root_hex = Some(hex::encode(Sha256::digest(&canon)));
        }

        prev = Some(e);
    }

    result
}

// ── Export manifest ───────────────────────────────────────────────────────────

/// Manifest written alongside an exported chain for off-host / WORM retention.
///
/// Consumers can pin `root_hex` and later re-verify by running `verify_chain`
/// against the exported `audit.jsonl`; a mismatch detects truncation or
/// replacement even without a retained signature key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportManifest {
    /// Number of events in the export.
    pub count: u64,
    /// `chain_index` of the first exported event.
    pub first_index: Option<u64>,
    /// `chain_index` of the last exported event.
    pub last_index: Option<u64>,
    /// Hex-encoded SHA-256 of the canonical bytes of the last event (the
    /// pinnable root). Matches `ChainVerification::root_hex`.
    pub root_hex: Option<String>,
    /// Base64-encoded Ed25519 public key of the signing key (taken from the
    /// last event's `signer_pubkey_b64`).
    pub signer_pubkey_b64: Option<String>,
    /// Milliseconds since Unix epoch when the export was produced.
    pub exported_at_ms: u64,
    /// `CARGO_PKG_VERSION` of the `nee` binary that produced this export.
    pub runtime_version: String,
    /// Whether `verify_chain` passed at export time.
    pub verified: bool,
}

/// Domain-separation tag embedded in every audit signature's canonical bytes.
///
/// Audit `S5-F4`: mirrors the attestation crate's `ctx` convention; makes audit
/// signatures explicitly non-interchangeable with snapshot/attestation ones
/// rather than relying on incidental schema disjointness. Changing this string
/// is a signing-format break.
pub const AUDIT_DOMAIN_TAG: &str = "ne-enclave-audit-v1";

/// Canonical serialization used for signing and chaining.
///
/// Strips `signature_b64`, injects the `ctx` domain tag ([`AUDIT_DOMAIN_TAG`]),
/// sorts top-level keys, serializes to JSON bytes. MUST stay byte-identical to
/// what the supervisor signs or existing chains fail to verify.
///
/// NOTE (S5-F4 clean break): adding the `ctx` tag changed the signed preimage,
/// so audit chains written before this change do not verify under this code.
/// This is intentional and documented; there is no v1→v2 migration.
pub fn canonical_bytes(event: &AuditEvent) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(event)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature_b64");
        let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // Domain tag. `ctx` sorts deterministically with the rest of the keys.
        sorted.insert(
            "ctx".to_string(),
            serde_json::Value::String(AUDIT_DOMAIN_TAG.to_string()),
        );
        return serde_json::to_vec(&sorted);
    }
    serde_json::to_vec(&value)
}

/// One signed event in the supervisor's audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Stable, globally unique event identifier (ULID encoded as
    /// Crockford base32, 26 chars).
    pub event_id: String,
    /// Milliseconds since the Unix epoch when the event was emitted.
    pub timestamp_ms: u64,
    /// Stable, machine-readable event classifier.
    pub event_type: EventType,
    /// Workspace this event scopes to, when applicable.
    pub workspace_id: Option<String>,
    /// Event-specific payload. Schema is per-`event_type` and will
    /// grow over time; readers branch on `event_type`.
    pub payload: serde_json::Value,
    /// Position in the supervisor's Merkle chain. Starts at 0 for
    /// the genesis event after key initialization.
    pub chain_index: u64,
    /// Hex-encoded SHA-256 of the canonical serialization of the
    /// previous event in the chain. `"0000…0000"` (64 chars) for
    /// the genesis event.
    pub prev_hash_hex: String,
    /// Base64-encoded Ed25519 signature over the canonical-JSON
    /// serialization of this event with ONLY the `signature_b64` field
    /// stripped. The `signer_pubkey_b64` field is intentionally part of
    /// the signed bytes so the public key cannot be swapped to forge an
    /// event. Verifiable against `signer_pubkey_b64`.
    pub signature_b64: String,
    /// Base64-encoded Ed25519 public key that signed this event.
    /// Carried inline so verifiers don't need a separate key fetch
    /// and so signer-key rotation doesn't invalidate prior entries.
    pub signer_pubkey_b64: String,
}

/// Stable, machine-readable event classifier.
///
/// `#[non_exhaustive]` so adding new event types lands without
/// breaking older consumers. New event types are an additive
/// protocol change; old consumers see them as `Unknown`-ish (they
/// can serialize but won't branch on the variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventType {
    /// Supervisor successfully launched a workspace.
    WorkspaceCreated,
    /// Workspace terminated and its host resources were reclaimed.
    WorkspaceTerminated,
    /// A `RunCommand` against a workspace completed (any exit code).
    CommandExecuted,
    /// A `RunCommand` failed without producing an exit code
    /// (vsock unreachable, guest agent error, etc.).
    CommandFailed,
    /// Per-workspace network namespace, veth pair, TAP, FORWARD
    /// chain, optional MASQUERADE, and optional DNS filter were
    /// provisioned for a workspace (one event per successful
    /// `NetworkController::setup`).
    NetworkSetup,
    /// Per-workspace network resources were reclaimed (one event
    /// per successful `NetworkController::teardown`).
    NetworkTeardown,
    /// The per-workspace DNS filter allowed a query (forwarded to
    /// the configured upstream). Emitted by the filter binary;
    /// chained into the supervisor's log via the stderr-relay
    /// path landed in E5.b.
    DnsAllowed,
    /// The per-workspace DNS filter denied a query (returned
    /// NXDOMAIN). Emitted by the filter binary.
    DnsDenied,
    /// The per-workspace DNS filter received a malformed query
    /// (returned FORMERR). Emitted by the filter binary.
    DnsMalformed,
    /// The per-workspace privacy router forwarded a request whose
    /// body the PII engine flagged in audit mode (body unmodified,
    /// detection count recorded). Emitted by the router binary;
    /// chained via the supervisor's stdout-relay path.
    PrivacyAudited,
    /// The per-workspace privacy router forwarded a request whose
    /// body was redacted in place before being passed upstream.
    PrivacyRedacted,
    /// The per-workspace privacy router refused a request because
    /// the active policy's enforcement mode is `block` and the body
    /// contained at least one detection.
    PrivacyBlocked,
    /// The per-workspace privacy router forwarded a request whose
    /// body the PII engine cleared (no detections). Emitted only
    /// when the operator opts into "log everything" mode — most
    /// deployments keep this off to avoid event-volume blow-up.
    PrivacyAllowed,
    /// A `WriteFile` RPC succeeded against a workspace. Payload
    /// contains `path`, `absolute_path`, `bytes_written`, `guest_port`.
    FileWritten,
    /// A `ReadFile` RPC succeeded against a workspace. Payload
    /// contains `path`, `absolute_path`, `bytes_returned`,
    /// `size_bytes`, `truncated`, `guest_port`.
    FileRead,
    /// A file RPC failed. Payload contains `op` (`write_file` or
    /// `read_file`), `path`, `error_kind`, `error`.
    FileOpFailed,
    /// A workspace was paused.
    WorkspacePaused,
    /// A paused workspace was resumed.
    WorkspaceResumed,
    /// A snapshot artifact was created from a workspace.
    SnapshotCreated,
    /// A workspace was restored from a snapshot artifact.
    WorkspaceRestored,
    /// A workspace was forked from a snapshot and its guest identity
    /// reset. Payload: `source_snapshot_id`, `new_workspace_id`,
    /// `hostname`, `machine_id`, `firecracker_pid`.
    WorkspaceForked,
    /// A snapshot operation failed.
    SnapshotFailed,
    /// A warm-pool member was provisioned and is ready in the pool.
    PoolMemberProvisioned,
    /// A `Create` request was satisfied from the warm pool (pool hit).
    PoolHit,
    /// A `Create` request found the pool empty and fell back to cold
    /// boot (pool miss).
    PoolMiss,
    /// A pool member was removed from the pool (eviction or shutdown).
    PoolMemberEvicted,
    /// An inbound connection to a workspace port was allowed by the
    /// ingress routing layer (after policy check).
    IngressRouteAllowed,
    /// An inbound connection to a workspace port was denied by the
    /// ingress routing layer (policy rejected or port not exposed).
    IngressRouteDenied,
    /// A workspace port was exposed via the ingress routing layer.
    IngressPortExposed,
    /// A workspace port was withdrawn from the ingress routing layer.
    IngressPortUnexposed,
    /// Attestation evidence was successfully generated and signed by the
    /// host and issued to the caller. The supervisor cannot observe the
    /// caller's client-side `verify()`, so this records issuance, not
    /// verification (audit `S1-F1`).
    AttestationEvidenceIssued,
    /// An attestation request failed (provider error, measurement
    /// mismatch, nonce validation failure, etc.).
    AttestationFailed,
    /// An attestation request was rejected because the nonce was
    /// replayed for the same workspace.
    AttestationReplayed,
}

/// Request shape for `ListEvents`. The current implementation supports
/// filter-by-workspace + a soft `limit`. Cursor-based pagination
/// (over `chain_index`) lands once the volume warrants it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEventsRequest {
    /// When set, only return events whose `workspace_id` matches.
    pub workspace_id: Option<String>,
    /// Skip events with `chain_index < since_chain_index`. `0`
    /// returns everything from genesis.
    pub since_chain_index: u64,
    /// Maximum number of events to return. `0` is treated as 100.
    pub limit: u32,
}

/// Response shape for `ListEvents`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEventsResponse {
    /// Events ordered by `chain_index` ascending. Empty when the
    /// log has no entries matching the filter.
    pub events: Vec<AuditEvent>,
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    /// Build a real signed chain of `n` events using a freshly generated key.
    fn signed_chain(n: u64) -> Vec<AuditEvent> {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_b64 = B64.encode(sk.verifying_key().as_bytes());
        let mut out: Vec<AuditEvent> = Vec::new();
        for i in 0..n {
            let prev_hash_hex = out.last().map_or_else(
                || "00".repeat(32),
                |p| hex::encode(Sha256::digest(canonical_bytes(p).unwrap())),
            );
            let mut e = AuditEvent {
                event_id: format!("e{i}"),
                timestamp_ms: 1_700_000_000_000 + i,
                event_type: EventType::CommandExecuted,
                workspace_id: Some("w".into()),
                payload: serde_json::json!({ "i": i }),
                chain_index: i,
                prev_hash_hex,
                signature_b64: String::new(),
                signer_pubkey_b64: pk_b64.clone(),
            };
            let sig = sk.sign(&canonical_bytes(&e).unwrap());
            e.signature_b64 = B64.encode(sig.to_bytes());
            out.push(e);
        }
        out
    }

    /// Pre-S5-F4 canonical form: sorted map, no `ctx` domain tag.
    fn untagged_canonical_bytes(event: &AuditEvent) -> Vec<u8> {
        let mut value = serde_json::to_value(event).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("signature_b64");
        let sorted: std::collections::BTreeMap<String, serde_json::Value> =
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        serde_json::to_vec(&sorted).unwrap()
    }

    #[test]
    fn canonical_bytes_carries_audit_domain_tag() {
        // S5-F4: the signed canonical form must embed an explicit domain tag so
        // audit signatures are domain-separated from snapshot/attestation ones.
        let event = &signed_chain(1)[0];
        let bytes = canonical_bytes(event).expect("canonical");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(
            text.contains("\"ctx\":\"ne-enclave-audit-v1\""),
            "audit canonical must carry the domain tag, got: {text}"
        );
    }

    #[test]
    fn signature_over_untagged_canonical_does_not_verify() {
        // S5-F4 clean break: a signature produced over the OLD (untagged)
        // canonical form must NOT verify against the new domain-tagged verifier.
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut e = AuditEvent {
            event_id: "e0".into(),
            timestamp_ms: 1_700_000_000_000,
            event_type: EventType::CommandExecuted,
            workspace_id: Some("w".into()),
            payload: serde_json::json!({ "i": 0 }),
            chain_index: 0,
            prev_hash_hex: "00".repeat(32),
            signature_b64: String::new(),
            signer_pubkey_b64: B64.encode(sk.verifying_key().as_bytes()),
        };
        // Sign over the PRE-S5-F4 (untagged) bytes.
        e.signature_b64 = B64.encode(sk.sign(&untagged_canonical_bytes(&e)).to_bytes());
        let v = verify_chain(&[e]);
        assert!(
            !v.ok,
            "an untagged-canonical signature must be rejected post-break"
        );
    }

    #[test]
    fn valid_chain_verifies_with_root() {
        let v = verify_chain(&signed_chain(3));
        assert!(v.ok, "valid chain must verify: {:?}", v.first_error);
        assert_eq!(v.count, 3);
        assert_eq!(v.first_index, Some(0));
        assert_eq!(v.last_index, Some(2));
        assert!(v.root_hex.is_some());
    }

    #[test]
    fn flipped_signature_is_bad_signature() {
        let mut c = signed_chain(3);
        // corrupt the middle event's signature
        let mut sig = B64.decode(&c[1].signature_b64).unwrap();
        sig[0] ^= 0xFF;
        c[1].signature_b64 = B64.encode(sig);
        let v = verify_chain(&c);
        assert!(!v.ok);
        assert_eq!(
            v.first_error.as_ref().unwrap().reason,
            ChainErrorReason::BadSignature
        );
        assert_eq!(v.first_error.as_ref().unwrap().index, 1);
    }

    #[test]
    fn edited_payload_breaks_signature() {
        let mut c = signed_chain(3);
        c[2].payload = serde_json::json!({ "i": 999 });
        let v = verify_chain(&c);
        assert!(!v.ok);
        assert_eq!(
            v.first_error.unwrap().reason,
            ChainErrorReason::BadSignature
        );
    }

    #[test]
    fn deleted_event_breaks_link() {
        let mut c = signed_chain(3);
        c.remove(1); // now indices 0, 2 — non-sequential / broken link
        let v = verify_chain(&c);
        assert!(!v.ok);
        let reason = v.first_error.unwrap().reason;
        assert!(
            matches!(
                reason,
                ChainErrorReason::NonSequentialIndex | ChainErrorReason::BrokenLink
            ),
            "unexpected reason: {reason:?}"
        );
    }

    #[test]
    fn tail_truncation_changes_root() {
        // Build one chain and compare the root of the full slice vs a truncated slice.
        let c = signed_chain(3);
        let root_full = verify_chain(&c).root_hex.unwrap();
        let root_trunc = verify_chain(&c[..2]).root_hex.unwrap();
        assert_ne!(
            root_full, root_trunc,
            "truncated tail must yield a different root"
        );
    }
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent {
            event_id: "01HZZZ".into(),
            timestamp_ms: 1_700_000_000_000,
            event_type: EventType::WorkspaceCreated,
            workspace_id: Some("wks-1".into()),
            payload: serde_json::json!({ "b": 2, "a": 1 }),
            chain_index: 0,
            prev_hash_hex: "00".repeat(32),
            signature_b64: "SIGNATURE_PLACEHOLDER".into(),
            signer_pubkey_b64: "PUBKEY".into(),
        }
    }

    #[test]
    fn canonical_bytes_strips_signature_and_sorts_top_level() {
        let bytes = canonical_bytes(&sample()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            !s.contains("SIGNATURE_PLACEHOLDER"),
            "signature must be stripped"
        );
        // top-level keys sorted: chain_index before event_id before ...
        let ci = s.find("chain_index").unwrap();
        let ei = s.find("event_id").unwrap();
        assert!(ci < ei, "top-level keys must be sorted");
        // payload value is preserved verbatim (inner not re-sorted)
        assert!(s.contains("\"payload\""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_serde() {
        let event = AuditEvent {
            event_id: "01HBQXYZ".into(),
            timestamp_ms: 1_700_000_000_000,
            event_type: EventType::WorkspaceCreated,
            workspace_id: Some("wks-1".into()),
            payload: serde_json::json!({ "kernel": "/k", "rootfs": "/r" }),
            chain_index: 7,
            prev_hash_hex: "ab".repeat(32),
            signature_b64: "sig".into(),
            signer_pubkey_b64: "key".into(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: AuditEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, event);
    }

    #[test]
    fn event_type_serializes_as_snake_case() {
        let s = serde_json::to_string(&EventType::WorkspaceCreated).expect("serialize");
        assert_eq!(s, r#""workspace_created""#);
        let back: EventType = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, EventType::WorkspaceCreated);
    }

    #[test]
    fn network_event_types_round_trip_through_snake_case() {
        // Pin the wire encoding so downstream consumers (control
        // plane, evidence packager) can match on the exact strings.
        for (variant, expected) in [
            (EventType::NetworkSetup, "network_setup"),
            (EventType::NetworkTeardown, "network_teardown"),
            (EventType::DnsAllowed, "dns_allowed"),
            (EventType::DnsDenied, "dns_denied"),
            (EventType::DnsMalformed, "dns_malformed"),
            (EventType::PrivacyAudited, "privacy_audited"),
            (EventType::PrivacyRedacted, "privacy_redacted"),
            (EventType::PrivacyBlocked, "privacy_blocked"),
            (EventType::PrivacyAllowed, "privacy_allowed"),
            (EventType::FileWritten, "file_written"),
            (EventType::FileRead, "file_read"),
            (EventType::FileOpFailed, "file_op_failed"),
        ] {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(s, format!("\"{expected}\""), "encoding for {variant:?}");
            let back: EventType = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn attestation_event_types_round_trip_through_snake_case() {
        // Pin the wire encoding. `AttestationEvidenceIssued`,
        // renamed from `AttestationVerified`) records host-side issuance, not
        // caller verification.
        for (variant, expected) in [
            (
                EventType::AttestationEvidenceIssued,
                "attestation_evidence_issued",
            ),
            (EventType::AttestationFailed, "attestation_failed"),
            (EventType::AttestationReplayed, "attestation_replayed"),
        ] {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(s, format!("\"{expected}\""), "encoding for {variant:?}");
            let back: EventType = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn list_events_request_roundtrips() {
        let req = ListEventsRequest {
            workspace_id: Some("wks-2".into()),
            since_chain_index: 42,
            limit: 50,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: ListEventsRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn snapshot_event_types_serialize_snake_case() {
        let cases = [
            (EventType::WorkspacePaused, "\"workspace_paused\""),
            (EventType::WorkspaceResumed, "\"workspace_resumed\""),
            (EventType::SnapshotCreated, "\"snapshot_created\""),
            (EventType::WorkspaceRestored, "\"workspace_restored\""),
            (EventType::SnapshotFailed, "\"snapshot_failed\""),
        ];
        for (ev, json) in cases {
            assert_eq!(serde_json::to_string(&ev).unwrap(), json);
        }
    }

    #[test]
    fn workspace_forked_event_type_serializes_snake_case() {
        let s = serde_json::to_string(&EventType::WorkspaceForked).unwrap();
        assert_eq!(s, "\"workspace_forked\"");
        assert_eq!(
            serde_json::from_str::<EventType>(&s).unwrap(),
            EventType::WorkspaceForked
        );
    }

    #[test]
    fn ingress_event_types_pin_wire_encoding() {
        for (v, expected) in [
            (EventType::IngressRouteAllowed, "ingress_route_allowed"),
            (EventType::IngressRouteDenied, "ingress_route_denied"),
            (EventType::IngressPortExposed, "ingress_port_exposed"),
            (EventType::IngressPortUnexposed, "ingress_port_unexposed"),
        ] {
            assert_eq!(
                serde_json::to_string(&v).expect("ser"),
                format!("\"{expected}\"")
            );
        }
    }
}

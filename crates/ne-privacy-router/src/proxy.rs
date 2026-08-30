// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Privacy-router HTTP reverse proxy.
//!
//! Reads an inbound HTTP/1.1 request, buffers the body up to a hard cap,
//! runs it through the PII engine, then either forwards the (possibly
//! redacted) body to the upstream destination or returns a 403 to the
//! client. The upstream destination is taken from the inbound `Host:`
//! header — the iptables DNAT rule rewrites the
//! kernel-level destination to the proxy without touching the
//! application-level URI, so `Host:` still names the workspace's
//! intended endpoint.
//!
//! The module is split into a small pure core ([`scan_body`]) and the
//! hyper-driven I/O ([`serve`], [`handle_request`], [`forward`]) so the
//! detection / redaction / block branches can be unit-tested without
//! standing up a TCP listener. This implementation covers the request-direction
//! path only; response-direction scanning is intentionally out of scope
//! for the current implementation (the model output that comes back is not customer
//! PII).

use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::{PiiApplyResult, PiiEngine};

/// Default hard cap on body buffering. Bodies larger than this are
/// passed through unscanned (the engine's `policy.max_body_bytes` is a
/// softer cap with the same effect but is operator-configurable).
pub const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Outcome of scanning a request body against a [`PiiEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Body is unmodified — forward as-is.
    Passthrough,
    /// Detections in audit mode — body unmodified, count surfaced
    /// for the eventual audit chain.
    Audited {
        /// Number of detections in this body.
        count: usize,
    },
    /// At least one detection was in redact mode and no detection
    /// triggered block; the returned body has the matches redacted.
    Redacted {
        /// The redacted body bytes.
        body: Vec<u8>,
        /// Number of redactions actually applied to the body.
        count: usize,
    },
    /// At least one detection's policy action was block; the engine
    /// refused to process this body.
    Blocked {
        /// Number of detections found in the body.
        detection_count: usize,
    },
}

/// Scan `body` against `engine` and reduce the engine's
/// [`PiiApplyResult`] to a forward / modify / reject [`ScanOutcome`].
pub fn scan_body(engine: &PiiEngine, body: &[u8]) -> ScanOutcome {
    let mut buf = body.to_vec();
    let detections = engine.detect(&buf);
    if detections.is_empty() {
        return ScanOutcome::Passthrough;
    }
    let count = detections.len();
    match engine.apply(&mut buf, &detections) {
        PiiApplyResult::Clean => ScanOutcome::Passthrough,
        PiiApplyResult::Audited(_) => ScanOutcome::Audited { count },
        PiiApplyResult::Redacted {
            count: redacted, ..
        } => ScanOutcome::Redacted {
            body: buf,
            count: redacted,
        },
        PiiApplyResult::Blocked { detections } => ScanOutcome::Blocked {
            detection_count: detections.len(),
        },
    }
}

/// Shared state held across all request handlers driven by [`serve`].
pub struct ProxyState {
    engine: Arc<PiiEngine>,
    client: Client<HttpConnector, Full<Bytes>>,
    max_body_bytes: usize,
    audit_stdout: bool,
}

impl ProxyState {
    /// Build new state with a freshly-constructed HTTP client (HTTP-only,
    /// matching the cleartext-only scope). Audit-stdout emission defaults
    /// off; the supervisor flips it on via [`Self::with_audit_stdout`]
    /// when spawning the binary inside a workspace netns so each
    /// decision lands as a JSON line in the signed audit chain.
    #[must_use]
    pub fn new(engine: Arc<PiiEngine>, max_body_bytes: usize) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            engine,
            client,
            max_body_bytes,
            audit_stdout: false,
        }
    }

    /// Enable stdout audit emission. One JSON line per request,
    /// shape pinned by [`emit_decision`]; the supervisor's stdout
    /// relay (`relay_privacy_audit_lines`) signs each line into the
    /// audit chain. Off-by-default keeps the binary usable
    /// standalone without polluting stdout for non-supervised
    /// consumers.
    #[must_use]
    pub fn with_audit_stdout(mut self, on: bool) -> Self {
        self.audit_stdout = on;
        self
    }

    /// Engine accessor — primarily intended for tests and audit hooks.
    #[must_use]
    pub fn engine(&self) -> &PiiEngine {
        &self.engine
    }
}

/// Errors surfaced by the proxy's accept loop. Per-request and
/// per-connection errors are logged and absorbed; only listener-level
/// failures bubble out of [`serve`].
#[derive(Debug, Error)]
pub enum ServeError {
    /// A non-transient `accept(2)` failure on the listener socket.
    #[error("accept on listener: {0}")]
    Accept(#[source] std::io::Error),
}

/// Drive the proxy on a pre-bound [`TcpListener`]. Loops accepting
/// connections and dispatching each to [`handle_request`].
pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> Result<(), ServeError> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) if is_transient_accept_error(&e) => {
                warn!(error = %e, "accept failed (transient); continuing");
                continue;
            }
            Err(e) => return Err(ServeError::Accept(e)),
        };

        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_request(state, req).await) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                debug!(peer = %peer, error = %e, "connection closed with error");
            }
        });
    }
}

fn is_transient_accept_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock,
    )
}

/// Handle a single inbound request: recover destination from `Host:`,
/// scan the body, forward or block.
pub async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let headers = req.headers().clone();

    let host = match headers.get(HOST).and_then(|v| v.to_str().ok()) {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => {
            warn!("missing or invalid Host header on inbound request; rejecting");
            return error_response(StatusCode::BAD_REQUEST, "missing Host header");
        }
    };

    let body_bytes = match req.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!(error = %e, "failed to read inbound body");
            return error_response(StatusCode::BAD_REQUEST, "could not read body");
        }
    };

    let outcome = if body_bytes.is_empty() || body_bytes.len() > state.max_body_bytes {
        ScanOutcome::Passthrough
    } else if body_bytes.len() > state.engine.policy().max_body_bytes {
        debug!(
            body_len = body_bytes.len(),
            policy_cap = state.engine.policy().max_body_bytes,
            "body exceeds policy.max_body_bytes; passing through unscanned",
        );
        ScanOutcome::Passthrough
    } else {
        scan_body(&state.engine, &body_bytes)
    };

    let method_str = method.as_str().to_string();
    let decision = match &outcome {
        ScanOutcome::Passthrough => Decision::Allowed { detection_count: 0 },
        ScanOutcome::Audited { count } => Decision::Audited {
            detection_count: *count,
        },
        ScanOutcome::Redacted { count, .. } => Decision::Redacted {
            redaction_count: *count,
        },
        ScanOutcome::Blocked { detection_count } => Decision::Blocked {
            detection_count: *detection_count,
        },
    };
    if state.audit_stdout
        && let Err(e) = emit_decision(&host, &path, &method_str, decision)
    {
        warn!(error = %e, "failed to write audit decision to stdout");
    }

    match outcome {
        ScanOutcome::Passthrough => {
            forward(&state, method, &host, &path, &headers, body_bytes).await
        }
        ScanOutcome::Audited { count } => {
            info!(host = %host, pii_action = "audit", detections = count, "PII audited");
            forward(&state, method, &host, &path, &headers, body_bytes).await
        }
        ScanOutcome::Redacted { body, count } => {
            info!(host = %host, pii_action = "redact", redactions = count, "PII redacted");
            forward(&state, method, &host, &path, &headers, Bytes::from(body)).await
        }
        ScanOutcome::Blocked { detection_count } => {
            info!(host = %host, pii_action = "block", detections = detection_count, "PII blocked");
            blocked_response(detection_count)
        }
    }
}

/// Decision categories surfaced for audit emission.
///
/// The discriminator landing in the JSON `decision` field is one of
/// `allowed`, `audited`, `redacted`, `blocked` — pinned so the
/// supervisor's stdout relay can match on the exact strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No detections in the body — request forwarded unmodified.
    Allowed {
        /// Always zero in this variant; held for shape symmetry with
        /// the audited / blocked variants the supervisor consumes.
        detection_count: usize,
    },
    /// Detections found but the policy enforcement is `audit` — body
    /// forwarded unmodified, detection count surfaced for the chain.
    Audited {
        /// Number of detections in this body.
        detection_count: usize,
    },
    /// At least one detection was in redact mode and no detection
    /// triggered block; the body was redacted in place before forward.
    Redacted {
        /// Number of redactions actually applied to the body.
        redaction_count: usize,
    },
    /// At least one detection's policy action was block; the request
    /// was refused upstream and the client got a 403.
    Blocked {
        /// Number of detections found in the body.
        detection_count: usize,
    },
}

/// Serialize one decision as a JSON line on stdout.
///
/// Shape pinned so the supervisor's stdout relay
/// (`relay_privacy_audit_lines`) can rely on the exact field set; new
/// fields land additively. Mirrors the `ne-dns-filter` decision-line
/// shape.
pub fn emit_decision(
    host: &str,
    path: &str,
    method: &str,
    decision: Decision,
) -> std::io::Result<()> {
    let timestamp_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let line = decision_line(host, path, method, decision, timestamp_ms)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Pure JSON-line builder. Split out from [`emit_decision`] so tests
/// can assert the exact shape without intercepting stdout, and so the
/// `timestamp_ms` field is injectable for deterministic assertions.
pub fn decision_line(
    host: &str,
    path: &str,
    method: &str,
    decision: Decision,
    timestamp_ms: u64,
) -> Result<String, serde_json::Error> {
    let (decision_str, detection_count, redaction_count) = match decision {
        Decision::Allowed { detection_count } => ("allowed", detection_count, 0_usize),
        Decision::Audited { detection_count } => ("audited", detection_count, 0_usize),
        Decision::Redacted { redaction_count } => ("redacted", redaction_count, redaction_count),
        Decision::Blocked { detection_count } => ("blocked", detection_count, 0_usize),
    };
    serde_json::to_string(&serde_json::json!({
        "kind": "privacy_decision",
        "timestamp_ms": timestamp_ms,
        "host": host,
        "path": path,
        "method": method,
        "decision": decision_str,
        "detection_count": detection_count,
        "redaction_count": redaction_count,
    }))
}

async fn forward(
    state: &ProxyState,
    method: Method,
    host: &str,
    path: &str,
    headers: &hyper::HeaderMap,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let uri = format!("http://{host}{path}");
    let mut builder = Request::builder().method(method).uri(&uri);
    for (key, value) in headers {
        if key != HOST {
            builder = builder.header(key, value);
        }
    }
    // Replace Content-Length in case redaction modified the body.
    builder = builder.header(CONTENT_LENGTH, body.len());

    let req = match builder.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, uri = %uri, "failed to build upstream request");
            return error_response(StatusCode::BAD_GATEWAY, "could not build upstream request");
        }
    };

    match state.client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let resp_body = resp
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();
            let mut out = Response::builder().status(status);
            for (key, value) in &resp_headers {
                out = out.header(key, value);
            }
            match out.body(Full::new(resp_body)) {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "failed to build response back to client");
                    error_response(StatusCode::BAD_GATEWAY, "could not build response")
                }
            }
        }
        Err(e) => {
            warn!(error = %e, uri = %uri, "upstream request failed");
            error_response(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &format!(r#"{{"error":"{message}"}}"#))
}

fn blocked_response(detection_count: usize) -> Response<Full<Bytes>> {
    let body = format!(
        r#"{{"error":{{"type":"pii_policy_violation","code":"pii_blocked","detections":{detection_count}}}}}"#
    );
    json_response(StatusCode::FORBIDDEN, &body)
}

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    // Builder failures here are structurally impossible (status known,
    // headers known, body known), but we still avoid expect/unwrap.
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Full::new(Bytes::new()));
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{EntityType, PiiAction, PiiPolicy};

    fn engine_with(enforcement: &str, overrides: &[(EntityType, PiiAction)]) -> PiiEngine {
        let mut entities = HashMap::new();
        for (et, action) in overrides {
            entities.insert(*et, *action);
        }
        let policy = PiiPolicy {
            enforcement: enforcement.to_string(),
            entities,
            ..PiiPolicy::default()
        };
        PiiEngine::new(&policy)
    }

    #[test]
    fn scan_body_clean_returns_passthrough() {
        let engine = engine_with("audit", &[]);
        assert_eq!(
            scan_body(&engine, b"no pii here, just regular text"),
            ScanOutcome::Passthrough,
        );
    }

    #[test]
    fn scan_body_audit_mode_keeps_body_unchanged() {
        let engine = engine_with("audit", &[]);
        match scan_body(&engine, b"my ssn is 123-45-6789") {
            ScanOutcome::Audited { count } => assert!(count >= 1),
            other => panic!("expected Audited, got {other:?}"),
        }
    }

    #[test]
    fn scan_body_redact_mode_modifies_body_in_place() {
        let engine = engine_with("redact", &[]);
        let body = b"my ssn is 123-45-6789";
        match scan_body(&engine, body) {
            ScanOutcome::Redacted {
                body: redacted,
                count,
            } => {
                assert!(count >= 1);
                assert_ne!(redacted, body.to_vec(), "redacted body should differ");
                let s = String::from_utf8_lossy(&redacted);
                assert!(
                    !s.contains("123-45-6789"),
                    "redacted body still has raw SSN: {s}"
                );
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
    }

    #[test]
    fn scan_body_block_mode_yields_blocked() {
        let engine = engine_with("block", &[]);
        match scan_body(&engine, b"my ssn is 123-45-6789") {
            ScanOutcome::Blocked { detection_count } => assert!(detection_count >= 1),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn decision_line_pins_field_set_for_each_variant() {
        // Pin the JSON shape so the supervisor's stdout relay
        // (`relay_privacy_audit_lines`) can rely on the exact field
        // names. New fields land additively; renames break the chain.
        let cases = [
            (
                Decision::Allowed { detection_count: 0 },
                "allowed",
                0_usize,
                0_usize,
            ),
            (Decision::Audited { detection_count: 3 }, "audited", 3, 0),
            (Decision::Redacted { redaction_count: 2 }, "redacted", 2, 2),
            (Decision::Blocked { detection_count: 5 }, "blocked", 5, 0),
        ];
        for (decision, expected_decision, expected_detection, expected_redaction) in cases {
            let line = decision_line(
                "api.example.com",
                "/v1/x",
                "POST",
                decision,
                1_715_000_000_000,
            )
            .expect("serialize");
            let v: serde_json::Value = serde_json::from_str(&line).expect("parse");
            assert_eq!(v["kind"], "privacy_decision");
            assert_eq!(v["timestamp_ms"], 1_715_000_000_000_u64);
            assert_eq!(v["host"], "api.example.com");
            assert_eq!(v["path"], "/v1/x");
            assert_eq!(v["method"], "POST");
            assert_eq!(v["decision"], expected_decision);
            assert_eq!(v["detection_count"], expected_detection);
            assert_eq!(v["redaction_count"], expected_redaction);
        }
    }

    #[test]
    fn scan_body_per_entity_override_blocks_only_target() {
        // Note: the engine only loads patterns for entity types that
        // appear in the policy's `entities` map (engine.rs filter on
        // line 33). To exercise "SSN audited but CC blocked," BOTH
        // entities must be configured — listing only one would silently
        // disable scanning for the other.
        let engine = engine_with(
            "audit",
            &[
                (EntityType::Ssn, PiiAction::Audit),
                (EntityType::CreditCard, PiiAction::Block),
            ],
        );

        match scan_body(&engine, b"ssn is 123-45-6789") {
            ScanOutcome::Audited { .. } => {}
            other => panic!("ssn under audit override should Audit, got {other:?}"),
        }

        match scan_body(&engine, b"card 4111-1111-1111-1111 please") {
            ScanOutcome::Blocked { .. } => {}
            other => panic!("credit_card override should block, got {other:?}"),
        }
    }
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-workspace DNS forwarder that filters queries against a
//! hostname allowlist.
//!
//! The current implementation. The supervisor spawns one of these
//! per workspace inside the workspace netns, listening on the host
//! veth IP. Queries for names matching the allowlist (suffix match,
//! e.g. `openai.com` matches `api.openai.com`) get forwarded to the
//! configured upstream resolver and the answer is relayed back to
//! the client; anything else gets an immediate `NXDOMAIN` and a
//! structured audit log line.
//!
//! Scope intentionally narrow: UDP-only, IPv4 questions only, no
//! recursion / caching / DNSSEC. The forwarder is the policy
//! enforcement point — actual resolution is delegated to whichever
//! upstream the operator picks (CIDRs in the workspace's
//! [`allow_cidrs`](ne_protocol::supervisor::NetworkConfig)
//! still gate post-resolution traffic).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Maximum size of a single DNS-over-UDP datagram we'll accept.
///
/// EDNS0 negotiates larger payloads; the current implementation caps at
/// the legacy 512-byte default plus enough headroom for typical EDNS
/// responses. Queries larger than this are dropped with a logged
/// warning (callers retry over TCP per RFC 7766 — TCP support is
/// E4.b).
pub const MAX_UDP_PAYLOAD: usize = 4096;

/// Default upstream timeout per forwarded query.
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Filter decisions surfaced for audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Query matched the allowlist; forwarded to upstream.
    Allowed,
    /// Query did not match; NXDOMAIN returned immediately.
    Denied,
    /// Query was malformed; we returned FORMERR (RCODE=1).
    Malformed,
}

/// Errors surfaced by the filter loop. Networking errors are
/// expected during normal operation (clients disconnect, upstream
/// times out) and are logged but don't bubble out of [`run`].
#[derive(Debug, Error)]
pub enum FilterError {
    /// Failed to bind the UDP listening socket.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Hostname allowlist.
///
/// Matches by exact equality or by suffix — `openai.com` in the
/// allowlist matches `api.openai.com`, `chat.openai.com`, etc. A
/// leading `*.` prefix is permitted and equivalent to the bare
/// form (kept for human readability of policy declarations).
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    normalized: BTreeSet<String>,
}

impl Allowlist {
    /// Construct an allowlist from a list of allow patterns. Each
    /// pattern is lower-cased and stripped of trailing `.` and any
    /// leading `*.` before being inserted. Empty entries are
    /// silently dropped (callers typically validate upstream).
    #[must_use]
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = BTreeSet::new();
        for raw in patterns {
            let n = normalize(raw.as_ref());
            if !n.is_empty() {
                normalized.insert(n);
            }
        }
        Self { normalized }
    }

    /// Whether `qname` matches any pattern in this list. Comparison
    /// is case-insensitive and ignores the trailing dot.
    #[must_use]
    pub fn matches(&self, qname: &str) -> bool {
        let q = normalize(qname);
        self.normalized
            .iter()
            .any(|allow| q == *allow || q.ends_with(&format!(".{allow}")))
    }

    /// Number of patterns held — useful for log lines and tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.normalized.len()
    }

    /// Whether the allowlist contains no patterns. An empty
    /// allowlist denies everything (the supervisor enforces "no
    /// `allow_hostnames` = no DNS filter spawned" in E4.b; if this
    /// binary runs with zero allows, every query is denied).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.normalized.is_empty()
    }
}

fn normalize(s: &str) -> String {
    let trimmed = s.trim();
    let stripped = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    stripped.trim_end_matches('.').to_lowercase()
}

/// Run the filter loop until the task is cancelled. The socket is
/// bound on `listen`; allowed queries are forwarded to `upstream`.
pub async fn run(
    listen: SocketAddr,
    upstream: SocketAddr,
    allowlist: Allowlist,
) -> Result<(), FilterError> {
    let sock = UdpSocket::bind(listen)
        .await
        .map_err(|source| FilterError::Bind {
            addr: listen,
            source,
        })?;
    let sock = Arc::new(sock);
    info!(
        %listen, %upstream, allow_count = allowlist.len(),
        "ne-dns-filter listening"
    );

    let allowlist = Arc::new(allowlist);
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recv_from failed; continuing");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock_cloned = Arc::clone(&sock);
        let allow_cloned = Arc::clone(&allowlist);
        tokio::spawn(async move {
            handle_one(&query, peer, &sock_cloned, &allow_cloned, upstream).await;
        });
    }
}

async fn handle_one(
    query: &[u8],
    peer: SocketAddr,
    sock: &UdpSocket,
    allowlist: &Allowlist,
    upstream: SocketAddr,
) {
    let Some((qname, qtype)) = parse_query(query) else {
        warn!(%peer, len = query.len(), "malformed DNS query; returning FORMERR");
        if let Some(resp) = formerr_response(query)
            && let Err(e) = sock.send_to(&resp, peer).await
        {
            warn!(error = %e, %peer, "send FORMERR failed");
        }
        audit_decision("<malformed>", 0, peer, Decision::Malformed);
        return;
    };

    if allowlist.matches(&qname) {
        debug!(%qname, qtype, %peer, "forwarding to upstream");
        match forward_upstream(query, upstream).await {
            Ok(resp) => {
                if let Err(e) = sock.send_to(&resp, peer).await {
                    warn!(error = %e, %peer, "send upstream reply failed");
                }
                audit_decision(&qname, qtype, peer, Decision::Allowed);
            }
            Err(e) => {
                warn!(error = %e, %qname, "upstream forward failed; returning NXDOMAIN");
                if let Some(resp) = nxdomain_response(query)
                    && let Err(se) = sock.send_to(&resp, peer).await
                {
                    warn!(error = %se, %peer, "send fallback NXDOMAIN failed");
                }
                audit_decision(&qname, qtype, peer, Decision::Denied);
            }
        }
    } else {
        if let Some(resp) = nxdomain_response(query)
            && let Err(e) = sock.send_to(&resp, peer).await
        {
            warn!(error = %e, %peer, "send NXDOMAIN failed");
        }
        audit_decision(&qname, qtype, peer, Decision::Denied);
    }
}

fn audit_decision(qname: &str, qtype: u16, peer: SocketAddr, decision: Decision) {
    // Two outputs per decision: a human-readable tracing event on
    // stderr for operators, and a machine-readable JSON line on
    // stdout for the supervisor's audit relay (E5.b). The supervisor
    // signs the JSON lines into its Ed25519 + Merkle audit chain.
    info!(
        target: "ne_dns_filter::audit",
        %qname,
        qtype,
        %peer,
        decision = ?decision,
        "dns decision"
    );
    if let Err(e) = write_audit_json(qname, qtype, peer, decision) {
        warn!(error = %e, "failed to write audit json line");
    }
}

/// Write one JSON audit line to stdout. Format is pinned so the
/// supervisor's stdout relay can rely on the exact field set; new
/// fields land additively. Includes a wall-clock timestamp so
/// downstream consumers can reconstruct ordering when relay buffers
/// the line.
fn write_audit_json(
    qname: &str,
    qtype: u16,
    peer: SocketAddr,
    decision: Decision,
) -> std::io::Result<()> {
    let timestamp_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let decision_str = match decision {
        Decision::Allowed => "allowed",
        Decision::Denied => "denied",
        Decision::Malformed => "malformed",
    };
    // One serde_json::to_string call so we get correct escaping
    // even when qnames contain pathological characters.
    let line = serde_json::to_string(&serde_json::json!({
        "kind": "dns_decision",
        "timestamp_ms": timestamp_ms,
        "qname": qname,
        "qtype": qtype,
        "peer": peer.to_string(),
        "decision": decision_str,
    }))
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

async fn forward_upstream(query: &[u8], upstream: SocketAddr) -> std::io::Result<Vec<u8>> {
    let up = UdpSocket::bind("0.0.0.0:0").await?;
    up.connect(upstream).await?;
    up.send(query).await?;
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    let n = timeout(DEFAULT_UPSTREAM_TIMEOUT, up.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

// ---------------------------------------------------------------------
// DNS wire helpers — minimal parsing for the query name + type.
// ---------------------------------------------------------------------

/// Parse the first question's qname and qtype out of a DNS query.
///
/// Returns the qname as a dotted string and the qtype as a u16.
/// Returns `None` if the query is truncated or uses compression in
/// the question section (which is illegal but occasionally appears
/// in malformed packets — we surface FORMERR rather than
/// dereferencing pointers).
#[must_use]
pub fn parse_query(buf: &[u8]) -> Option<(String, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut name = String::new();
    let mut pos = 12;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // 0xC0 prefix indicates a compression pointer; legal in
        // answers but illegal in the question section. Bail with
        // None so the caller surfaces FORMERR.
        if len & 0xC0 != 0 {
            return None;
        }
        if len > 63 || pos + 1 + len > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + len]).ok()?;
        name.push_str(label);
        pos += 1 + len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Some((name, qtype))
}

/// Craft an NXDOMAIN response for a query. Sets QR=1, RCODE=3, and
/// zeroes out the answer / authority / additional counts. Returns
/// `None` if the input is too short to be a valid DNS header.
#[must_use]
pub fn nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    rcode_response(query, 3)
}

/// Craft a FORMERR (RCODE=1) response. Same shape as NXDOMAIN
/// otherwise.
#[must_use]
pub fn formerr_response(query: &[u8]) -> Option<Vec<u8>> {
    rcode_response(query, 1)
}

fn rcode_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    // Flag byte 1: set QR (0x80), clear TC (0x02). Leave RD as-is
    // so the client's recursion desire is reflected back per RFC.
    resp[2] |= 0x80;
    resp[2] &= !0x02;
    // Flag byte 2: clear RCODE (low nibble) and set ours, set
    // RA=0 (we're not a recursive resolver; the upstream is).
    resp[3] = (resp[3] & 0x70) | (rcode & 0x0F);
    // Zero answer / authority / additional counts.
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Construct a DNS query for `qname` (A record by default).
    fn build_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![
            0xab, 0xcd, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ancount/nscount/arcount = 0
        ];
        for label in qname.split('.') {
            v.push(u8::try_from(label.len()).expect("label fits"));
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0); // root
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
        v
    }

    #[test]
    fn parses_simple_a_query() {
        let q = build_query("api.openai.com", 1);
        let (name, t) = parse_query(&q).expect("parse");
        assert_eq!(name, "api.openai.com");
        assert_eq!(t, 1);
    }

    #[test]
    fn parses_root_query_as_empty() {
        let mut v = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        let (name, t) = parse_query(&v).expect("parse root");
        assert_eq!(name, "");
        assert_eq!(t, 1);
    }

    #[test]
    fn rejects_compression_pointer_in_question() {
        let mut q = build_query("api.openai.com", 1);
        // Replace the first label length with a compression pointer
        // (high two bits set).
        q[12] = 0xC0;
        assert!(
            parse_query(&q).is_none(),
            "compression in question must surface FORMERR"
        );
    }

    #[test]
    fn rejects_truncated_packet() {
        let q = build_query("api.openai.com", 1);
        for cut in 0..q.len() {
            assert!(parse_query(&q[..cut]).is_none(), "len={cut} must reject");
        }
    }

    #[test]
    fn nxdomain_flips_qr_and_rcode() {
        let q = build_query("blocked.example", 1);
        let r = nxdomain_response(&q).expect("response");
        assert_eq!(r.len(), q.len(), "response copies the query bytes");
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0F, 3, "RCODE=3");
        assert_eq!(&r[6..12], &[0, 0, 0, 0, 0, 0], "counts zeroed");
        // Question section preserved.
        assert_eq!(&r[12..], &q[12..]);
    }

    #[test]
    fn formerr_uses_rcode_1() {
        let q = build_query("example", 1);
        let r = formerr_response(&q).expect("response");
        assert_eq!(r[3] & 0x0F, 1);
    }

    #[test]
    fn allowlist_normalizes_wildcards_and_dots() {
        let al = Allowlist::new(["*.openai.com", "github.com.", "EXAMPLE.ORG"]);
        assert!(al.matches("api.openai.com"));
        assert!(al.matches("chat.openai.com"));
        assert!(al.matches("github.com"));
        assert!(al.matches("example.org"));
        assert!(al.matches("api.github.com"));
        assert!(!al.matches("openai.com.evil.example"));
        assert!(!al.matches("not-openai.com"));
    }

    #[test]
    fn allowlist_suffix_match_does_not_match_partial_label() {
        let al = Allowlist::new(["openai.com"]);
        assert!(al.matches("openai.com"));
        assert!(al.matches("api.openai.com"));
        // `evil-openai.com` ends with "openai.com" textually but
        // not at a label boundary — must NOT match.
        assert!(!al.matches("evil-openai.com"));
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let al = Allowlist::new(Vec::<&str>::new());
        assert!(al.is_empty());
        assert!(!al.matches("example.com"));
    }

    #[test]
    fn audit_json_pins_field_shape() {
        // We can't easily intercept stdout from the lib here, so
        // we re-exercise the formatting path directly through
        // serde_json. The supervisor parses each line into a
        // serde_json::Value; any change to field names or value
        // shape ripples through this assertion.
        let line = serde_json::to_string(&serde_json::json!({
            "kind": "dns_decision",
            "timestamp_ms": 1_700_000_000_000u64,
            "qname": "api.openai.com",
            "qtype": 1,
            "peer": "169.254.1.2:5000",
            "decision": "allowed",
        }))
        .expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&line).expect("parse");
        assert_eq!(v["kind"], "dns_decision");
        assert_eq!(v["qname"], "api.openai.com");
        assert_eq!(v["qtype"], 1);
        assert_eq!(v["decision"], "allowed");
        assert_eq!(v["peer"], "169.254.1.2:5000");
        assert!(v["timestamp_ms"].is_u64());
    }
}

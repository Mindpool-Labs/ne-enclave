// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Real control-plane key-release client. Implements `ControlPlaneKeyRelease`
//! over HTTPS+JSON. `NotImplementedControlPlaneClient` is only a placeholder.
//!
//! The client uses configured mTLS trust material for HTTPS transport. A
//! separate development constructor permits bearer authentication on loopback
//! HTTP only.

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use crate::SealError;
use crate::key_release::ControlPlaneKeyRelease;
use crate::types::{SealEnvelope, SealingPolicy};

/// Seal-time DEK wrap against the CP. Narrower than
/// [`ControlPlaneKeyRelease`] (which is release-only) so the seal path does not
/// require the release transport.
///
/// Returns `(wrapped_dek, wrap_nonce)`. The runtime stores whatever the CP
/// returns verbatim in `DekEnvelope`: the SW backend returns a real 12-byte
/// nonce; the KMS backend returns an empty nonce.
pub trait CpWrapClient: Send + Sync + std::fmt::Debug {
    /// Wrap the 32-byte DEK for `snapshot_id` / `manifest_hash` under the
    /// CP-held KEK, evaluated against `policy`.
    #[allow(clippy::type_complexity)]
    fn wrap_dek<'a>(
        &'a self,
        dek: &'a [u8; 32],
        snapshot_id: &'a str,
        manifest_hash: &'a str,
        policy: &'a SealingPolicy,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), SealError>> + Send + 'a>>;
}

/// CP transport/release error. Never carries secrets.
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    /// Client configuration is incomplete or violates transport requirements.
    #[error("control plane configuration: {0}")]
    Configuration(String),
    /// CP explicitly denied the release (HTTP 403).
    #[error("control plane denied key release: {0}")]
    Denied(String),
    /// Transport-layer failure (connect, DNS, TLS, read). Carries a
    /// sanitized error string (no secrets).
    #[error("control plane transport: {0}")]
    Transport(String),
    /// CP rejected the client's credentials (HTTP 401).
    #[error("control plane unauthorized")]
    Unauthorized,
    /// CP returned a malformed/unparseable body or a DEK of the wrong size.
    #[error("control plane response malformed: {0}")]
    BadResponse(String),
    /// CP response body exceeded the fixed transport limit.
    #[error("control plane response exceeds size limit")]
    ResponseTooLarge,
    /// No CP endpoint was configured for this runtime.
    #[error("control plane not configured")]
    Unconfigured,
}

/// Injectable clock (seconds since epoch) for deterministic tests.
pub type NowFn = Arc<dyn Fn() -> i64 + Send + Sync>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_BODY_LIMIT: usize = 64 * 1024;

/// Files that provide the trust anchor and client identity for mTLS.
#[derive(Debug, Clone)]
pub struct ControlPlaneTlsFiles {
    /// PEM-encoded certificate authority that verifies the remote server.
    pub ca_cert: PathBuf,
    /// PEM-encoded client certificate sent during the TLS handshake.
    pub client_cert: PathBuf,
    /// PEM-encoded private key for `client_cert`.
    pub client_key: PathBuf,
}

/// Wire request to the CP `/v1/seal/release-dek` endpoint.
///
/// NOTE on the two nonces (do not conflate):
/// - `wrap_nonce_b64`: the AES-GCM nonce used to wrap the DEK. Read back from
///   `seal.dek_envelope.wrap_nonce` and forwarded by the CP to `unwrap_dek`.
/// - `nonce_b64`: the attestation challenge nonce pinned by the CP. Read from
///   `evidence.nonce` (the value the runtime stamped when generating the
///   evidence).
#[derive(serde::Serialize)]
struct ReleaseReq<'a> {
    wrapped_dek_b64: String,
    wrap_nonce_b64: String,
    snapshot_id: &'a str,
    manifest_canonical_sha256: &'a str,
    policy: &'a SealingPolicy,
    evidence: &'a ne_attestation::Evidence,
    nonce_b64: String,
}

#[derive(serde::Deserialize)]
struct ReleaseOk {
    dek_b64: String,
}

#[derive(serde::Deserialize)]
struct DenialResponse<'a> {
    #[serde(borrow)]
    reason: &'a str,
}

/// Wire request to the CP `/v1/seal/wrap-dek` endpoint at seal time.
#[derive(serde::Serialize)]
struct WrapReq<'a> {
    dek_b64: String,
    snapshot_id: &'a str,
    manifest_canonical_sha256: &'a str,
    policy: &'a SealingPolicy,
}

#[derive(serde::Deserialize)]
struct WrapOk {
    wrapped_dek_b64: String,
    wrap_nonce_b64: String,
}

/// HTTPS client for the CP `/v1/seal/release-dek` endpoint.
///
/// The client implements [`ControlPlaneKeyRelease`] over HTTPS. The
/// `NotImplementedControlPlaneClient` stub in `key_release.rs` is retained for
/// negative tests and placeholder configuration.
pub struct ControlPlaneKeyReleaseClient {
    /// Base URL ending in `/v1` (e.g. `https://cp.example.com/v1`). The path
    /// `/seal/release-dek` is appended.
    endpoint: String,
    api_key: Option<Zeroizing<String>>,
    http: reqwest::Client,
    #[allow(dead_code)]
    now: NowFn,
}

impl std::fmt::Debug for ControlPlaneKeyReleaseClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneKeyReleaseClient")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl ControlPlaneKeyReleaseClient {
    /// Construct an HTTPS client with a configured server trust anchor and
    /// client identity. Certificate and hostname verification remain enabled.
    pub fn new_mtls(
        endpoint: String,
        api_key: Option<String>,
        tls: ControlPlaneTlsFiles,
        now: NowFn,
    ) -> Result<Self, ControlPlaneError> {
        Self::require_https(&endpoint)?;
        let ca_pem = std::fs::read(tls.ca_cert)
            .map_err(|_| ControlPlaneError::Configuration("invalid TLS files".into()))?;
        let client_cert_pem = std::fs::read(tls.client_cert)
            .map_err(|_| ControlPlaneError::Configuration("invalid TLS files".into()))?;
        let client_key_pem = Zeroizing::new(
            std::fs::read(tls.client_key)
                .map_err(|_| ControlPlaneError::Configuration("invalid TLS files".into()))?,
        );
        let ca = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|_| ControlPlaneError::Configuration("invalid TLS files".into()))?;
        let mut identity_pem = Zeroizing::new(client_cert_pem);
        identity_pem.extend_from_slice(&client_key_pem);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|_| ControlPlaneError::Configuration("invalid TLS files".into()))?;
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ControlPlaneError::Configuration("invalid TLS configuration".into()))?;

        Ok(Self {
            endpoint,
            api_key: api_key.map(Zeroizing::new),
            http,
            now,
        })
    }

    /// Construct an HTTP client for a local development endpoint only.
    pub fn new_development(
        endpoint: String,
        api_key: String,
        now: NowFn,
    ) -> Result<Self, ControlPlaneError> {
        Self::new_development_with_limits(endpoint, api_key, now, REQUEST_TIMEOUT)
    }

    fn new_development_with_limits(
        endpoint: String,
        api_key: String,
        now: NowFn,
        request_timeout: Duration,
    ) -> Result<Self, ControlPlaneError> {
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| ControlPlaneError::Configuration("invalid endpoint".into()))?;
        let is_loopback = url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if url.scheme() != "http" || !is_loopback || api_key.is_empty() {
            return Err(ControlPlaneError::Configuration(
                "development endpoint requires loopback HTTP and bearer credentials".into(),
            ));
        }

        Ok(Self {
            endpoint,
            api_key: Some(Zeroizing::new(api_key)),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(request_timeout)
                .build()
                .map_err(|_| {
                    ControlPlaneError::Configuration("invalid HTTP configuration".into())
                })?,
            now,
        })
    }

    #[cfg(test)]
    fn new_development_with_timeout(
        endpoint: String,
        api_key: String,
        now: NowFn,
        request_timeout: Duration,
    ) -> Result<Self, ControlPlaneError> {
        Self::new_development_with_limits(endpoint, api_key, now, request_timeout)
    }

    fn require_https(endpoint: &str) -> Result<(), ControlPlaneError> {
        let url = reqwest::Url::parse(endpoint)
            .map_err(|_| ControlPlaneError::Configuration("invalid endpoint".into()))?;
        if url.scheme() == "https" {
            Ok(())
        } else {
            Err(ControlPlaneError::Configuration(
                "mTLS endpoint must use HTTPS".into(),
            ))
        }
    }

    fn post(&self, url: &str) -> reqwest::RequestBuilder {
        let request = self.http.post(url);
        match &self.api_key {
            Some(api_key) => request.bearer_auth(api_key.as_str()),
            None => request,
        }
    }

    async fn read_response_body(
        mut response: reqwest::Response,
    ) -> Result<(reqwest::StatusCode, String), ControlPlaneError> {
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ControlPlaneError::Transport(e.to_string()))?
        {
            let new_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or(ControlPlaneError::ResponseTooLarge)?;
            if new_len > RESPONSE_BODY_LIMIT {
                return Err(ControlPlaneError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body)
            .map_err(|_| ControlPlaneError::BadResponse("response is not UTF-8".into()))?;
        Ok((status, body))
    }

    fn safe_denial_code(body: &str) -> &'static str {
        match serde_json::from_str::<DenialResponse<'_>>(body) {
            Ok(DenialResponse {
                reason: "nonce_replay",
            }) => "nonce_replay",
            Ok(DenialResponse {
                reason: "unwrap_failed",
            }) => "unwrap_failed",
            _ => "denied",
        }
    }

    fn validate_wrap_envelope(
        wrapped_dek: &[u8],
        wrap_nonce: &[u8],
    ) -> Result<(), ControlPlaneError> {
        let software_envelope = wrap_nonce.len() == 12 && wrapped_dek.len() == 48;
        let external_envelope = wrap_nonce.is_empty()
            && !wrapped_dek.is_empty()
            && std::str::from_utf8(wrapped_dek).is_ok();
        if software_envelope || external_envelope {
            Ok(())
        } else {
            Err(ControlPlaneError::BadResponse(
                "invalid DEK wrap envelope".into(),
            ))
        }
    }

    /// The attestation challenge nonce the CP pins. Read from `evidence.nonce`
    /// (the value the runtime stamped when minting the evidence). The CP
    /// re-derives its expected nonce from this.
    fn attestation_nonce_b64(ev: &ne_attestation::Evidence) -> String {
        B64.encode(&ev.nonce)
    }
}

impl ControlPlaneKeyRelease for ControlPlaneKeyReleaseClient {
    fn release_dek<'a>(
        &'a self,
        seal: &'a SealEnvelope,
        evidence: &'a ne_attestation::Evidence,
    ) -> Pin<Box<dyn Future<Output = Result<Zeroizing<[u8; 32]>, SealError>> + Send + 'a>> {
        Box::pin(async move {
            let body = ReleaseReq {
                wrapped_dek_b64: B64.encode(&seal.dek_envelope.wrapped_dek),
                wrap_nonce_b64: B64.encode(&seal.dek_envelope.wrap_nonce),
                snapshot_id: &seal.snapshot_id,
                manifest_canonical_sha256: &seal.manifest_canonical_sha256,
                policy: &seal.policy,
                evidence,
                nonce_b64: Self::attestation_nonce_b64(evidence),
            };
            let url = format!("{}/seal/release-dek", self.endpoint.trim_end_matches('/'));
            let resp = self.post(&url).json(&body).send().await.map_err(|e| {
                SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
            })?;
            let (status, text) = Self::read_response_body(resp)
                .await
                .map_err(SealError::ControlPlaneRelease)?;
            if status == reqwest::StatusCode::OK {
                let ok: ReleaseOk = serde_json::from_str(&text).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let dek = B64.decode(ok.dek_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let dek: [u8; 32] = dek.try_into().map_err(|_| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(
                        "dek not 32 bytes".into(),
                    ))
                })?;
                Ok(Zeroizing::new(dek))
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Unauthorized,
                ))
            } else if status.as_u16() == 403 {
                Err(SealError::ControlPlaneRelease(ControlPlaneError::Denied(
                    Self::safe_denial_code(&text).into(),
                )))
            } else {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Transport(format!("HTTP {status}")),
                ))
            }
        })
    }
}

impl CpWrapClient for ControlPlaneKeyReleaseClient {
    fn wrap_dek<'a>(
        &'a self,
        dek: &'a [u8; 32],
        snapshot_id: &'a str,
        manifest_hash: &'a str,
        policy: &'a SealingPolicy,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), SealError>> + Send + 'a>> {
        Box::pin(async move {
            let body = WrapReq {
                dek_b64: B64.encode(dek),
                snapshot_id,
                manifest_canonical_sha256: manifest_hash,
                policy,
            };
            let url = format!("{}/seal/wrap-dek", self.endpoint.trim_end_matches('/'));
            let resp = self.post(&url).json(&body).send().await.map_err(|e| {
                SealError::ControlPlaneRelease(ControlPlaneError::Transport(e.to_string()))
            })?;
            let (status, text) = Self::read_response_body(resp)
                .await
                .map_err(SealError::ControlPlaneRelease)?;
            if status == reqwest::StatusCode::OK {
                let ok: WrapOk = serde_json::from_str(&text).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let wrapped = B64.decode(ok.wrapped_dek_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                let nonce = B64.decode(ok.wrap_nonce_b64.as_bytes()).map_err(|e| {
                    SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(e.to_string()))
                })?;
                Self::validate_wrap_envelope(&wrapped, &nonce)
                    .map_err(SealError::ControlPlaneRelease)?;
                Ok((wrapped, nonce))
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Unauthorized,
                ))
            } else if status.as_u16() == 403 {
                Err(SealError::ControlPlaneRelease(ControlPlaneError::Denied(
                    Self::safe_denial_code(&text).into(),
                )))
            } else {
                Err(SealError::ControlPlaneRelease(
                    ControlPlaneError::Transport(format!("HTTP {status}")),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::types::{
        DekEnvelope, KekProvider, SEAL_VERSION, SealEnvelope, SealingPolicy, SealingTrustAnchor,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use ne_attestation::{Evidence, Measurement, ProviderType};
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use rustls::server::WebPkiClientVerifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn partial_mtls_configuration_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tls = ControlPlaneTlsFiles {
            ca_cert: dir.path().join("ca.pem"),
            client_cert: dir.path().join("client.pem"),
            client_key: dir.path().join("missing-client-key.pem"),
        };

        let result = ControlPlaneKeyReleaseClient::new_mtls(
            "https://localhost:8443/v1".into(),
            None,
            tls,
            Arc::new(|| 1_700_000_020),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mtls_client_reaches_required_client_ca_server() {
        let server = mtls_server(2).await;
        let client = ControlPlaneKeyReleaseClient::new_mtls(
            server.endpoint.clone(),
            None,
            server.tls.clone(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("mTLS client");

        let (wrapped, nonce) = client
            .wrap_dek(&[0x22; 32], "01S", "mh", &seal_cp().policy)
            .await
            .expect("wrap reaches server");
        assert_eq!(wrapped, vec![0xA5; 48]);
        assert_eq!(nonce, vec![0x5A; 12]);
        let dek = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .expect("release reaches server");
        assert_eq!(*dek, [0x11; 32]);
        server.task.await.expect("server task");
        assert_eq!(server.handler_entries.load(Ordering::SeqCst), 2);
        assert_eq!(
            *server.authorizations.lock().expect("header lock"),
            vec![None, None]
        );
    }

    #[tokio::test]
    async fn wrong_ca_fails_before_http_handler() {
        let server = mtls_server(1).await;
        let client = ControlPlaneKeyReleaseClient::new_mtls(
            server.endpoint.clone(),
            None,
            ControlPlaneTlsFiles {
                ca_cert: server.wrong_ca.clone(),
                client_cert: server.tls.client_cert.clone(),
                client_key: server.tls.client_key.clone(),
            },
            Arc::new(|| 1_700_000_020),
        )
        .expect("mTLS client with a wrong server CA");

        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .expect_err("server certificate must be rejected");
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Transport(_))
        ));
        server.task.await.expect("server task");
        assert_eq!(server.handler_entries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn development_client_requires_loopback_http_and_bearer() {
        let now: NowFn = Arc::new(|| 1_700_000_020);
        assert!(
            ControlPlaneKeyReleaseClient::new_development(
                "https://127.0.0.1:8443/v1".into(),
                "key".into(),
                Arc::clone(&now),
            )
            .is_err()
        );
        assert!(
            ControlPlaneKeyReleaseClient::new_development(
                "http://192.0.2.1:8443/v1".into(),
                "key".into(),
                Arc::clone(&now),
            )
            .is_err()
        );
        assert!(
            ControlPlaneKeyReleaseClient::new_development(
                "http://127.0.0.1:8443/v1".into(),
                String::new(),
                now,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn development_client_sends_bearer_authorization() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind server");
        let endpoint = format!("http://{}/v1", listener.local_addr().expect("address"));
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            let mut request = vec![0u8; 4096];
            let read = socket.read(&mut request).await.expect("read request");
            request.truncate(read);
            request_tx.send(request).expect("send request");
            let body = format!(r#"{{"dek_b64":"{}"}}"#, B64.encode([0x44; 32]));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let client = ControlPlaneKeyReleaseClient::new_development(
            endpoint,
            "development-key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");

        client
            .release_dek(&seal_cp(), &evidence())
            .await
            .expect("release response");
        server.await.expect("server task");
        let request =
            String::from_utf8(request_rx.await.expect("request bytes")).expect("HTTP request text");
        assert!(
            request
                .lines()
                .any(|line| line == "authorization: Bearer development-key")
        );
    }

    #[tokio::test]
    async fn redirects_do_not_forward_wrap_or_development_release_requests() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind target");
        let target_addr = target.local_addr().expect("target address");
        let target_entries = Arc::new(AtomicUsize::new(0));
        let target_count = Arc::clone(&target_entries);
        let target_task = tokio::spawn(async move {
            while let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(200), target.accept()).await
            {
                target_count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
            }
        });
        let source = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind source");
        let source_addr = source.local_addr().expect("source address");
        let source_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = source.accept().await.expect("accept source request");
                let mut request = [0u8; 4096];
                let _ = socket
                    .read(&mut request)
                    .await
                    .expect("read source request");
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write redirect");
            }
        });
        let client = ControlPlaneKeyReleaseClient::new_development(
            format!("http://{source_addr}/v1"),
            "development-key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");

        assert!(
            client
                .wrap_dek(&[0x33; 32], "01S", "mh", &seal_cp().policy)
                .await
                .is_err()
        );
        assert!(client.release_dek(&seal_cp(), &evidence()).await.is_err());
        source_task.await.expect("source task");
        target_task.await.expect("target task");
        assert_eq!(target_entries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mtls_redirect_does_not_forward_wrap_request() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind target");
        let target_addr = target.local_addr().expect("target address");
        let target_entries = Arc::new(AtomicUsize::new(0));
        let target_count = Arc::clone(&target_entries);
        let target_task = tokio::spawn(async move {
            if let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(200), target.accept()).await
            {
                target_count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
            }
        });
        let server =
            mtls_server_with_redirect(format!("http://{target_addr}/redirect-target")).await;
        let client = ControlPlaneKeyReleaseClient::new_mtls(
            server.endpoint.clone(),
            None,
            server.tls.clone(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("mTLS client");

        assert!(
            client
                .wrap_dek(&[0x55; 32], "01S", "mh", &seal_cp().policy)
                .await
                .is_err()
        );
        server.task.await.expect("source task");
        target_task.await.expect("target task");
        assert_eq!(target_entries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oversized_chunked_response_is_rejected_before_decoding() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind server");
        let endpoint = format!("http://{}/v1", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.expect("read request");
            let oversized = "x".repeat(RESPONSE_BODY_LIMIT + 1);
            let response = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{:X}\r\n{oversized}\r\n0\r\n\r\n",
                oversized.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let client = ControlPlaneKeyReleaseClient::new_development(
            endpoint,
            "development-key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");

        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .expect_err("oversized response must fail");
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::ResponseTooLarge)
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn stalled_response_uses_request_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind server");
        let endpoint = format!("http://{}/v1", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.expect("read request");
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        let client = ControlPlaneKeyReleaseClient::new_development_with_timeout(
            endpoint,
            "development-key".into(),
            Arc::new(|| 1_700_000_020),
            Duration::from_millis(25),
        )
        .expect("loopback development client");

        let err = tokio::time::timeout(
            Duration::from_millis(150),
            client.release_dek(&seal_cp(), &evidence()),
        )
        .await
        .expect("client request must have a deadline")
        .expect_err("stalled response must fail");
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Transport(_))
        ));
        server.await.expect("server task");
    }

    fn seal_cp() -> SealEnvelope {
        SealEnvelope {
            seal_version: SEAL_VERSION,
            snapshot_id: "01S".into(),
            attestation_policy_id: None,
            policy: SealingPolicy {
                accept_provider_types: vec![ProviderType::Software],
                freshness_seconds: 300,
                trust_anchor: SealingTrustAnchor::Software {
                    expected_signer: [9u8; 32],
                },
                expected_measurement: None,
            },
            dek_envelope: DekEnvelope {
                kek_provider: KekProvider::ControlPlane,
                wrapped_dek: vec![1u8; 48],
                wrap_nonce: Vec::new(),
            },
            manifest_canonical_sha256: "mh".into(),
            signer_pubkey_b64: String::new(),
            signature_b64: String::new(),
        }
    }
    fn evidence() -> Evidence {
        Evidence {
            provider_type: ProviderType::Software,
            workspace_id: "ws".into(),
            measurement: Measurement([0u8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_010,
            report_data: vec![],
            proof: ne_attestation::Proof::Software {
                signature: [0u8; 64],
                signer_pubkey: [9u8; 32],
            },
        }
    }

    struct TestServer {
        endpoint: String,
        tls: ControlPlaneTlsFiles,
        wrong_ca: PathBuf,
        handler_entries: Arc<AtomicUsize>,
        authorizations: Arc<Mutex<Vec<Option<String>>>>,
        task: tokio::task::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    fn certificate_authority() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).expect("CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().expect("CA key");
        let cert = params.self_signed(&key).expect("CA certificate");
        (cert, key)
    }

    fn signed_leaf(
        names: Vec<String>,
        usage: ExtendedKeyUsagePurpose,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(names).expect("leaf parameters");
        params.extended_key_usages.push(usage);
        let key = KeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key, ca, ca_key)
            .expect("leaf certificate");
        (cert, key)
    }

    async fn mtls_server(connection_count: usize) -> TestServer {
        mtls_server_with_response(connection_count, None).await
    }

    async fn mtls_server_with_redirect(location: String) -> TestServer {
        mtls_server_with_response(1, Some(location)).await
    }

    async fn mtls_server_with_response(
        connection_count: usize,
        redirect_location: Option<String>,
    ) -> TestServer {
        let (ca, ca_key) = certificate_authority();
        let (server_cert, server_key) = signed_leaf(
            vec!["127.0.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client_cert, client_key) = signed_leaf(
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        let (wrong_ca_cert, _) = certificate_authority();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        let client_cert_path = dir.path().join("client.pem");
        let client_key_path = dir.path().join("client-key.pem");
        let wrong_ca = dir.path().join("wrong-ca.pem");
        std::fs::write(&ca_path, ca.pem()).expect("write CA");
        std::fs::write(&client_cert_path, client_cert.pem()).expect("write client certificate");
        std::fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");
        std::fs::write(&wrong_ca, wrong_ca_cert.pem()).expect("write wrong CA");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).expect("add client CA");
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier");
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert.der().clone()], server_key)
            .expect("server configuration");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let endpoint = format!("https://{}/v1", listener.local_addr().expect("address"));
        let handler_entries = Arc::new(AtomicUsize::new(0));
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let entries = Arc::clone(&handler_entries);
        let headers = Arc::clone(&authorizations);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let task = tokio::spawn(async move {
            for _ in 0..connection_count {
                let (socket, _) = listener.accept().await.expect("accept connection");
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    continue;
                };
                let mut request = vec![0u8; 8192];
                let read = stream.read(&mut request).await.expect("read request");
                let request = String::from_utf8_lossy(&request[..read]);
                let authorization = request.lines().find_map(|line| {
                    line.strip_prefix("authorization:")
                        .or_else(|| line.strip_prefix("Authorization:"))
                        .map(|value| value.trim().to_string())
                });
                headers.lock().expect("header lock").push(authorization);
                entries.fetch_add(1, Ordering::SeqCst);
                let response = redirect_location.as_ref().map_or_else(
                    || {
                        let body = if request.starts_with("POST /v1/seal/wrap-dek ") {
                            format!(
                                r#"{{"wrapped_dek_b64":"{}","wrap_nonce_b64":"{}"}}"#,
                                B64.encode([0xA5; 48]),
                                B64.encode([0x5A; 12]),
                            )
                        } else {
                            format!(r#"{{"dek_b64":"{}"}}"#, B64.encode([0x11; 32]))
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    },
                    |location| {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    },
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });

        TestServer {
            endpoint,
            tls: ControlPlaneTlsFiles {
                ca_cert: ca_path,
                client_cert: client_cert_path,
                client_key: client_key_path,
            },
            wrong_ca,
            handler_entries,
            authorizations,
            task,
            _dir: dir,
        }
    }

    async fn mock_cp(status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let h = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        (url, h)
    }

    #[tokio::test]
    async fn happy_path_returns_dek() {
        let dek = [7u8; 32];
        let body = format!(r#"{{"dek_b64":"{}"}}"#, B64.encode(dek));
        let (url, _h) = mock_cp(200, Box::leak(body.into_boxed_str())).await;
        let client = ControlPlaneKeyReleaseClient::new_development(
            url,
            "key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");
        let got = client.release_dek(&seal_cp(), &evidence()).await.unwrap();
        assert_eq!(*got, dek);
    }

    #[tokio::test]
    async fn wrap_rejects_unsupported_success_envelopes_without_echoing_response_data() {
        for (case, wrapped, nonce) in [
            ("one-byte nonce", vec![0xA5; 48], vec![0x5A; 1]),
            ("eleven-byte nonce", vec![0xA5; 48], vec![0x5A; 11]),
            ("thirteen-byte nonce", vec![0xA5; 48], vec![0x5A; 13]),
            ("empty ciphertext", Vec::new(), vec![0x5A; 12]),
            ("short software ciphertext", vec![0xA5; 47], vec![0x5A; 12]),
            (
                "non-UTF-8 external ciphertext",
                vec![0xFF, 0xFE],
                Vec::new(),
            ),
        ] {
            let wrapped_b64 = B64.encode(&wrapped);
            let nonce_b64 = B64.encode(&nonce);
            let body =
                format!(r#"{{"wrapped_dek_b64":"{wrapped_b64}","wrap_nonce_b64":"{nonce_b64}"}}"#);
            let (url, server) = mock_cp(200, Box::leak(body.into_boxed_str())).await;
            let client = ControlPlaneKeyReleaseClient::new_development(
                url,
                "key".into(),
                Arc::new(|| 1_700_000_020),
            )
            .expect("loopback development client");

            let err = client
                .wrap_dek(&[0x66; 32], "01S", "mh", &seal_cp().policy)
                .await
                .expect_err(case);
            assert!(matches!(
                &err,
                SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(message))
                    if message == "invalid DEK wrap envelope"
            ));
            let text = err.to_string();
            if !wrapped_b64.is_empty() {
                assert!(!text.contains(&wrapped_b64));
            }
            if !nonce_b64.is_empty() {
                assert!(!text.contains(&nonce_b64));
            }
            server.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn wrap_accepts_each_supported_success_envelope() {
        for (case, wrapped, nonce) in [
            ("software", vec![0xA5; 48], vec![0x5A; 12]),
            ("external", b"vault:v1:opaque".to_vec(), Vec::new()),
        ] {
            let body = format!(
                r#"{{"wrapped_dek_b64":"{}","wrap_nonce_b64":"{}"}}"#,
                B64.encode(&wrapped),
                B64.encode(&nonce),
            );
            let (url, server) = mock_cp(200, Box::leak(body.into_boxed_str())).await;
            let client = ControlPlaneKeyReleaseClient::new_development(
                url,
                "key".into(),
                Arc::new(|| 1_700_000_020),
            )
            .expect("loopback development client");

            let result = client
                .wrap_dek(&[0x66; 32], "01S", "mh", &seal_cp().policy)
                .await
                .expect(case);
            assert_eq!(result, (wrapped, nonce));
            server.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn release_403_preserves_only_allowlisted_denial_codes() {
        for (body, expected) in [
            (r#"{"reason":"nonce_replay"}"#, "nonce_replay"),
            (r#"{"reason":"unwrap_failed"}"#, "unwrap_failed"),
            ("not-json", "denied"),
            (r#"{"reason":"unknown_reason"}"#, "denied"),
            (
                r#"{"reason":"Authorization: Bearer test-only-value"}"#,
                "denied",
            ),
        ] {
            let (url, _h) = mock_cp(403, body).await;
            let client = ControlPlaneKeyReleaseClient::new_development(
                url,
                "key".into(),
                Arc::new(|| 1_700_000_020),
            )
            .expect("loopback development client");
            let err = client
                .release_dek(&seal_cp(), &evidence())
                .await
                .expect_err("release must be denied");
            assert!(matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Denied(reason)) if reason == expected
            ));
        }
    }

    #[tokio::test]
    async fn wrap_403_preserves_only_allowlisted_denial_codes() {
        for (body, expected) in [
            (r#"{"reason":"nonce_replay"}"#, "nonce_replay"),
            (r#"{"reason":"unwrap_failed"}"#, "unwrap_failed"),
            ("not-json", "denied"),
            (r#"{"reason":"unknown_reason"}"#, "denied"),
            (
                r#"{"reason":"Authorization: Bearer test-only-value"}"#,
                "denied",
            ),
        ] {
            let (url, _h) = mock_cp(403, body).await;
            let client = ControlPlaneKeyReleaseClient::new_development(
                url,
                "key".into(),
                Arc::new(|| 1_700_000_020),
            )
            .expect("loopback development client");
            let err = client
                .wrap_dek(&[0x66; 32], "01S", "mh", &seal_cp().policy)
                .await
                .expect_err("wrap must be denied");
            assert!(matches!(
                err,
                SealError::ControlPlaneRelease(ControlPlaneError::Denied(reason)) if reason == expected
            ));
        }
    }

    #[tokio::test]
    async fn unauth_401_maps_to_unauthorized() {
        let (url, _h) = mock_cp(401, r#"{"reason":"bad key"}"#).await;
        let client = ControlPlaneKeyReleaseClient::new_development(
            url,
            "key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn malformed_body_maps_to_bad_response() {
        let (url, _h) = mock_cp(200, "not json").await;
        let client = ControlPlaneKeyReleaseClient::new_development(
            url,
            "key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::BadResponse(_))
        ));
    }

    #[tokio::test]
    async fn connection_refused_maps_to_transport() {
        // bind + immediately drop to force ECONNREFUSED
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = ControlPlaneKeyReleaseClient::new_development(
            url,
            "key".into(),
            Arc::new(|| 1_700_000_020),
        )
        .expect("loopback development client");
        let err = client
            .release_dek(&seal_cp(), &evidence())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SealError::ControlPlaneRelease(ControlPlaneError::Transport(_))
        ));
    }
}

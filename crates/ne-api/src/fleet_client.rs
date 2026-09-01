// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use ne_protocol::fleet::{
    FLEET_PROTOCOL_V1, FleetErrorCode, FleetErrorResponse, FleetPollRequest, FleetPollResponse,
    FleetProtocolRange, FleetSession, FleetUuid, RunnerCapacity, from_json_no_duplicate_keys,
};
use ne_protocol::supervisor::{CapacitySnapshotRequest, SupervisorRequest, SupervisorResponse};
use rand::Rng;
use thiserror::Error;
use zeroize::Zeroizing;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Optional HTTPS client configuration for fleet coordination.
#[derive(Clone)]
pub struct FleetClientConfig {
    /// HTTPS endpoint used for fleet requests.
    pub endpoint: reqwest::Url,
    /// PEM-encoded certificate authority that verifies the remote endpoint.
    pub ca_cert: PathBuf,
    /// PEM-encoded certificate chain presented to the remote endpoint.
    pub client_cert: PathBuf,
    /// PEM-encoded private key for [`Self::client_cert`].
    pub client_key: PathBuf,
    /// Interval between fleet requests.
    pub poll_interval: Duration,
    /// Maximum time to establish an outbound connection.
    pub connect_timeout: Duration,
    /// Maximum time for one complete outbound request.
    pub request_timeout: Duration,
    /// Maximum accepted response body size before JSON decoding.
    pub max_response_bytes: usize,
}

impl std::fmt::Debug for FleetClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetClientConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("ca_cert", &self.ca_cert)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("poll_interval", &self.poll_interval)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Errors from fleet-client configuration and bounded outbound requests.
#[derive(Debug, Error)]
pub enum FleetClientError {
    /// The optional configuration is incomplete or violates transport rules.
    #[error("fleet client configuration is invalid")]
    Configuration,
    /// The remote endpoint attempted a redirect.
    #[error("fleet client redirects are not permitted")]
    RedirectRefused,
    /// The response body exceeded its configured bound.
    #[error("fleet client response exceeds the configured limit")]
    ResponseTooLarge,
    /// The outbound request failed without exposing credential material.
    #[error("fleet client transport failed")]
    Transport,
    /// A response or locally obtained snapshot violates the fleet protocol.
    #[error("fleet client protocol validation failed")]
    Protocol,
    /// The remote endpoint cannot accept the current request body size.
    #[error("fleet client request is too large")]
    PayloadTooLarge,
    /// The remote endpoint rejected the current process identity.
    #[error("fleet client identity was rejected")]
    IdentityRejected,
    /// A newer fleet session superseded this process session.
    #[error("fleet client session was fenced")]
    SessionFenced,
    /// A transient transport or remote-service failure occurred.
    #[error("fleet client retry is required")]
    Retryable,
}

// State transitions for one optional fleet client:
//
// ```text
// snapshot -> build pending request -> send
//                    ^                 |
//                    | network/429/500/503/sequence-gap retry ------+
//                    |
//           accepted/obsolete/suspended -> advance sequence -> wait+jitter
//           413/protocol/revoked/fenced  -> stop fleet task only
// ```
struct FleetLoopState {
    process_instance_id: FleetUuid,
    session: Option<FleetSession>,
    next_sequence: u64,
    pending: Option<FleetPollRequest>,
}

impl FleetLoopState {
    fn new() -> Self {
        Self::with_process_instance_id(FleetUuid::new_v4())
    }

    fn with_process_instance_id(process_instance_id: FleetUuid) -> Self {
        Self {
            process_instance_id,
            session: None,
            next_sequence: 1,
            pending: None,
        }
    }

    fn prepare_pending(
        &mut self,
        capacity: RunnerCapacity,
    ) -> Result<&FleetPollRequest, FleetClientError> {
        if self.pending.is_none() {
            let request = FleetPollRequest {
                protocol: FleetProtocolRange::new(FLEET_PROTOCOL_V1, FLEET_PROTOCOL_V1)
                    .map_err(|_| FleetClientError::Protocol)?,
                process_instance_id: self.process_instance_id,
                session: self.session.clone(),
                request_id: FleetUuid::new_v4(),
                sequence: self.next_sequence,
                capacity,
                supported_contracts: Vec::new(),
                renewals: Vec::new(),
                releases: Vec::new(),
                terminal_reports: Vec::new(),
            };
            request.validate().map_err(|_| FleetClientError::Protocol)?;
            self.pending = Some(request);
        }
        self.pending.as_ref().ok_or(FleetClientError::Protocol)
    }

    fn pending(&self) -> Option<&FleetPollRequest> {
        self.pending.as_ref()
    }

    fn apply_response(&mut self, response: FleetPollResponse) -> Result<(), FleetClientError> {
        let pending = self.pending.as_ref().ok_or(FleetClientError::Protocol)?;
        validate_response_for(&response, pending)?;
        let next_sequence = pending
            .sequence
            .checked_add(1)
            .ok_or(FleetClientError::Protocol)?;

        self.session = Some(response.session);
        self.next_sequence = next_sequence;
        self.pending = None;
        Ok(())
    }
}

fn validate_response_for(
    response: &FleetPollResponse,
    pending: &FleetPollRequest,
) -> Result<(), FleetClientError> {
    response
        .validate()
        .map_err(|_| FleetClientError::Protocol)?;
    let accepted_sequence = response.accepted_sequence;
    let pending_sequence = pending.sequence;
    let matching_correlation =
        response.request_id == pending.request_id && accepted_sequence == pending_sequence;
    let selected_protocol = response.protocol_version;
    let supported_protocol = pending.protocol;
    if !matching_correlation
        || selected_protocol < supported_protocol.min_version
        || selected_protocol > supported_protocol.max_version
    {
        return Err(FleetClientError::Protocol);
    }
    if let Some(session) = &pending.session
        && (response.session.session_id != session.session_id
            || response.session.generation < session.generation)
    {
        return Err(FleetClientError::Protocol);
    }
    if response
        .leases
        .iter()
        .any(|lease| !pending.supported_contracts.contains(&lease.contract))
    {
        return Err(FleetClientError::Protocol);
    }
    Ok(())
}

/// An injected outbound transport for the fleet polling state machine.
pub trait FleetTransport {
    /// Sends one complete poll request.
    fn poll(
        &self,
        request: &FleetPollRequest,
    ) -> impl Future<Output = Result<FleetPollResponse, FleetClientError>> + Send;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FleetIteration {
    Retry { snapshot_failed: bool },
    Wait(Duration),
    Stop,
}

async fn poll_iteration<T, C, F>(
    state: &mut FleetLoopState,
    transport: &T,
    capacity_snapshot: C,
) -> FleetIteration
where
    T: FleetTransport + Sync,
    C: FnOnce() -> F + Send,
    F: Future<Output = Result<RunnerCapacity, FleetClientError>> + Send,
{
    if state.pending().is_none() {
        let Ok(capacity) = capacity_snapshot().await else {
            return FleetIteration::Retry {
                snapshot_failed: true,
            };
        };
        if state.prepare_pending(capacity).is_err() {
            return FleetIteration::Stop;
        }
    }
    let Some(pending) = state.pending().cloned() else {
        return FleetIteration::Stop;
    };
    match transport.poll(&pending).await {
        Ok(response) => {
            let delay = Duration::from_millis(u64::from(response.poll_after_ms));
            if state.apply_response(response).is_ok() {
                FleetIteration::Wait(delay)
            } else {
                FleetIteration::Stop
            }
        }
        Err(
            FleetClientError::PayloadTooLarge
            | FleetClientError::Protocol
            | FleetClientError::IdentityRejected
            | FleetClientError::SessionFenced,
        ) => FleetIteration::Stop,
        Err(
            FleetClientError::Retryable
            | FleetClientError::Configuration
            | FleetClientError::RedirectRefused
            | FleetClientError::ResponseTooLarge
            | FleetClientError::Transport,
        ) => FleetIteration::Retry {
            snapshot_failed: false,
        },
    }
}

trait FleetJitter {
    fn apply(&mut self, delay: Duration) -> Duration;
}

struct RandomFleetJitter;

impl FleetJitter for RandomFleetJitter {
    fn apply(&mut self, delay: Duration) -> Duration {
        let millis = delay.as_millis();
        let adjustment = rand::thread_rng().gen_range(-20_i128..=20_i128);
        let factor = u128::try_from(100_i128 + adjustment).unwrap_or(100);
        let adjusted = millis.saturating_mul(factor) / 100;
        Duration::from_millis(u64::try_from(adjusted).unwrap_or(u64::MAX))
    }
}

fn retry_delay(attempt: u32, jitter: &mut impl FleetJitter) -> Duration {
    const RETRY_CAP: Duration = Duration::from_secs(30);
    let multiplier = 1_u32.checked_shl(attempt.min(5)).unwrap_or(u32::MAX);
    let delay = Duration::from_secs(u64::from(multiplier)).min(RETRY_CAP);
    jitter.apply(delay)
}

async fn wait_for_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

/// Runs the optional fleet loop until shutdown or a terminal fleet outcome.
pub async fn run_fleet_loop(
    transport: FleetClient,
    supervisor: crate::supervisor_client::SupervisorClient,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut state = FleetLoopState::new();
    let mut jitter = RandomFleetJitter;
    let mut retry_attempt = 0_u32;
    loop {
        let supervisor_for_snapshot = supervisor.clone();
        let iteration = tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => return,
            iteration = poll_iteration(&mut state, &transport, || async move {
                match supervisor_for_snapshot.call(&SupervisorRequest::CapacitySnapshot(CapacitySnapshotRequest {})).await {
                    Ok(SupervisorResponse::CapacitySnapshot(capacity)) => {
                        capacity.validate().map_err(|_| FleetClientError::Protocol)?;
                        Ok(capacity)
                    }
                    _ => Err(FleetClientError::Transport),
                }
            }) => iteration,
        };
        let wait = match iteration {
            FleetIteration::Retry { snapshot_failed } => {
                if snapshot_failed {
                    tracing::warn!(
                        event = "fleet_capacity_snapshot_failed",
                        "fleet poll deferred"
                    );
                }
                let delay = retry_delay(retry_attempt, &mut jitter);
                retry_attempt = retry_attempt.saturating_add(1);
                delay
            }
            FleetIteration::Wait(delay) => {
                retry_attempt = 0;
                jitter.apply(delay)
            }
            FleetIteration::Stop => {
                tracing::warn!(event = "fleet_poll_stopped", "fleet polling stopped");
                return;
            }
        };
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

impl FleetClientConfig {
    /// Builds optional configuration from the fleet endpoint and the existing
    /// control-plane TLS file settings. An absent fleet endpoint disables this
    /// consumer. When the endpoint is present, all three TLS paths are required.
    pub fn from_optional(
        endpoint: Option<String>,
        ca_cert: Option<PathBuf>,
        client_cert: Option<PathBuf>,
        client_key: Option<PathBuf>,
    ) -> Result<Option<Self>, FleetClientError> {
        match endpoint {
            None => Ok(None),
            Some(endpoint) => match (ca_cert, client_cert, client_key) {
                (Some(ca_cert), Some(client_cert), Some(client_key)) => {
                    let endpoint = Self::validate_endpoint(&endpoint)?;
                    Ok(Some(Self {
                        endpoint,
                        ca_cert,
                        client_cert,
                        client_key,
                        poll_interval: DEFAULT_POLL_INTERVAL,
                        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                        request_timeout: DEFAULT_REQUEST_TIMEOUT,
                        max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
                    }))
                }
                _ => Err(FleetClientError::Configuration),
            },
        }
    }

    /// Reads the optional fleet endpoint and existing control-plane TLS file
    /// settings without starting any remote work.
    pub fn from_environment() -> Result<Option<Self>, FleetClientError> {
        Self::from_optional(
            std::env::var("NE_CP_FLEET_ENDPOINT").ok(),
            std::env::var_os("NE_CP_TLS_CA_CERT").map(PathBuf::from),
            std::env::var_os("NE_CP_TLS_CLIENT_CERT").map(PathBuf::from),
            std::env::var_os("NE_CP_TLS_CLIENT_KEY").map(PathBuf::from),
        )
    }

    fn validate_endpoint(value: &str) -> Result<reqwest::Url, FleetClientError> {
        let endpoint = reqwest::Url::parse(value).map_err(|_| FleetClientError::Configuration)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(FleetClientError::Configuration);
        }
        Ok(endpoint)
    }
}

/// Hardened outbound HTTPS client for fleet coordination.
pub struct FleetClient {
    endpoint: reqwest::Url,
    http: reqwest::Client,
    max_response_bytes: usize,
}

struct HttpResponse {
    status: reqwest::StatusCode,
    body: Vec<u8>,
}

impl std::fmt::Debug for FleetClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetClient")
            .field("endpoint", &self.endpoint)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl FleetClient {
    /// Constructs the client from configured trust material. The client trusts
    /// only the configured certificate authority and keeps certificate input in
    /// zeroizing temporary memory while it builds the TLS identity.
    pub fn new(config: FleetClientConfig) -> Result<Self, FleetClientError> {
        let endpoint = FleetClientConfig::validate_endpoint(config.endpoint.as_str())?;
        let ca_pem = Self::read_pem(config.ca_cert)?;
        let client_cert_pem = Self::read_pem(config.client_cert)?;
        let client_key_pem = Self::read_pem(config.client_key)?;

        Self::validate_certificate_pem(&ca_pem)?;
        Self::validate_certificate_pem(&client_cert_pem)?;
        let ca =
            reqwest::Certificate::from_pem(&ca_pem).map_err(|_| FleetClientError::Configuration)?;
        let mut identity_pem = Zeroizing::new(Vec::with_capacity(
            client_cert_pem.len().saturating_add(client_key_pem.len()),
        ));
        identity_pem.extend_from_slice(&client_cert_pem);
        identity_pem.extend_from_slice(&client_key_pem);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|_| FleetClientError::Configuration)?;

        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| FleetClientError::Configuration)?;

        Ok(Self {
            endpoint,
            http,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Sends a JSON request and returns its bounded response body.
    async fn post_json(&self, body: &[u8]) -> Result<HttpResponse, FleetClientError> {
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| FleetClientError::Transport)?;
        if response.status().is_redirection() {
            return Err(FleetClientError::RedirectRefused);
        }
        let mut response_body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FleetClientError::Transport)?
        {
            let size = response_body
                .len()
                .checked_add(chunk.len())
                .ok_or(FleetClientError::ResponseTooLarge)?;
            if size > self.max_response_bytes {
                return Err(FleetClientError::ResponseTooLarge);
            }
            response_body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status: response.status(),
            body: response_body,
        })
    }

    fn read_pem(path: PathBuf) -> Result<Zeroizing<Vec<u8>>, FleetClientError> {
        std::fs::read(path)
            .map(Zeroizing::new)
            .map_err(|_| FleetClientError::Configuration)
    }

    fn validate_certificate_pem(pem: &[u8]) -> Result<(), FleetClientError> {
        let mut reader = std::io::Cursor::new(pem);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| FleetClientError::Configuration)?;
        if certificates.is_empty() {
            return Err(FleetClientError::Configuration);
        }
        Ok(())
    }
}

impl FleetTransport for FleetClient {
    async fn poll(
        &self,
        request: &FleetPollRequest,
    ) -> Result<FleetPollResponse, FleetClientError> {
        let body = serde_json::to_vec(request).map_err(|_| FleetClientError::Protocol)?;
        let response = self.post_json(&body).await?;
        Self::decode_poll_response(response.status.as_u16(), &response.body, request.sequence)
    }
}

impl FleetClient {
    fn decode_poll_response(
        status: u16,
        body: &[u8],
        pending_sequence: u64,
    ) -> Result<FleetPollResponse, FleetClientError> {
        match status {
            200..=299 => {
                let body = std::str::from_utf8(body).map_err(|_| FleetClientError::Protocol)?;
                from_json_no_duplicate_keys(body).map_err(|_| FleetClientError::Protocol)
            }
            413 => Err(FleetClientError::PayloadTooLarge),
            429 | 500 | 503 => Err(FleetClientError::Retryable),
            _ => Self::map_error_response(body, pending_sequence),
        }
    }
    fn map_error_response(
        body: &[u8],
        pending_sequence: u64,
    ) -> Result<FleetPollResponse, FleetClientError> {
        let body = std::str::from_utf8(body).map_err(|_| FleetClientError::Protocol)?;
        let error: FleetErrorResponse =
            from_json_no_duplicate_keys(body).map_err(|_| FleetClientError::Protocol)?;
        match error.code {
            FleetErrorCode::SequenceGap
                if error
                    .expected_sequence
                    .is_some_and(|expected| expected > pending_sequence) =>
            {
                Err(FleetClientError::Retryable)
            }
            FleetErrorCode::RateLimited | FleetErrorCode::Unavailable => {
                Err(FleetClientError::Retryable)
            }
            FleetErrorCode::PayloadTooLarge => Err(FleetClientError::PayloadTooLarge),
            FleetErrorCode::Unauthenticated => Err(FleetClientError::IdentityRejected),
            FleetErrorCode::SessionFenced => Err(FleetClientError::SessionFenced),
            _ => Err(FleetClientError::Protocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;

    use std::path::PathBuf;

    use ne_protocol::fleet::{
        FleetPollResponse, FleetReplayStatus, FleetSession, FleetUuid, JobContract, LeaseHeader,
        RunnerCapacity,
    };

    use super::{
        FleetClient, FleetClientConfig, FleetClientError, FleetIteration, FleetLoopState,
        FleetTransport, poll_iteration,
    };

    #[test]
    fn absent_optional_configuration_disables_fleet_client() {
        let config = FleetClientConfig::from_optional(None, None, None, None)
            .expect("absent optional configuration is valid");

        assert!(config.is_none());
    }

    #[test]
    fn incomplete_endpoint_or_tls_configuration_is_rejected() {
        let endpoint = Some("https://fleet.example.test/v1/poll".to_owned());
        let ca = Some(PathBuf::from("ca.pem"));
        let cert = Some(PathBuf::from("client.pem"));
        let key = Some(PathBuf::from("client-key.pem"));

        for fields in [
            (endpoint.clone(), None, None, None),
            (endpoint.clone(), ca.clone(), cert.clone(), None),
            (endpoint.clone(), ca, None, key.clone()),
            (endpoint, None, cert, key),
        ] {
            assert!(
                FleetClientConfig::from_optional(fields.0, fields.1, fields.2, fields.3).is_err()
            );
        }
    }

    #[test]
    fn shared_tls_without_fleet_endpoint_disables_only_fleet() {
        let config = FleetClientConfig::from_optional(
            None,
            Some(PathBuf::from("ca.pem")),
            Some(PathBuf::from("client.pem")),
            Some(PathBuf::from("client-key.pem")),
        )
        .expect("shared TLS values do not enable fleet");
        assert!(config.is_none());
    }

    #[test]
    fn endpoint_requires_https_without_credentials_query_or_fragment() {
        let ca = PathBuf::from("ca.pem");
        let cert = PathBuf::from("client.pem");
        let key = PathBuf::from("client-key.pem");

        for endpoint in [
            "http://fleet.example.test/v1/poll",
            "https://operator@fleet.example.test/v1/poll",
            "https://fleet.example.test/v1/poll?next=other",
            "https://fleet.example.test/v1/poll#other",
        ] {
            assert!(
                FleetClientConfig::from_optional(
                    Some(endpoint.to_owned()),
                    Some(ca.clone()),
                    Some(cert.clone()),
                    Some(key.clone()),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn direct_configuration_cannot_bypass_endpoint_validation() {
        for endpoint in [
            "http://fleet.example.test/v1",
            "https://user@fleet.example.test/v1",
        ] {
            let config = FleetClientConfig {
                endpoint: reqwest::Url::parse(endpoint).expect("URL"),
                ca_cert: PathBuf::from("missing-ca.pem"),
                client_cert: PathBuf::from("missing-client.pem"),
                client_key: PathBuf::from("missing-key.pem"),
                poll_interval: Duration::from_secs(1),
                connect_timeout: Duration::from_secs(1),
                request_timeout: Duration::from_secs(1),
                max_response_bytes: 1,
            };
            assert!(matches!(
                FleetClient::new(config),
                Err(FleetClientError::Configuration)
            ));
        }
    }

    #[test]
    fn debug_shows_configuration_locations_not_pem_contents() {
        let config = FleetClientConfig::from_optional(
            Some("https://fleet.example.test/v1/poll".to_owned()),
            Some(PathBuf::from("ca.pem")),
            Some(PathBuf::from("client.pem")),
            Some(PathBuf::from("client-key.pem")),
        )
        .expect("complete configuration")
        .expect("enabled client");

        let debug = format!("{config:?}");
        assert!(debug.contains("https://fleet.example.test/v1/poll"));
        assert!(debug.contains("ca.pem"));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn first_pending_poll_has_stable_identity_and_no_contract_or_report_data() {
        let process_instance_id = FleetUuid::new_v4();
        let mut state = FleetLoopState::with_process_instance_id(process_instance_id);

        let pending = state
            .prepare_pending(sample_capacity())
            .expect("first pending poll");

        assert_eq!(pending.process_instance_id, process_instance_id);
        assert_eq!(pending.sequence, 1);
        assert!(pending.session.is_none());
        assert!(pending.supported_contracts.is_empty());
        assert!(pending.renewals.is_empty());
        assert!(pending.releases.is_empty());
        assert!(pending.terminal_reports.is_empty());
        assert!(
            !serde_json::to_string(pending)
                .expect("serialize request")
                .contains("ne.test.lease-header")
        );
    }

    #[test]
    fn accepted_replay_obsolete_and_suspended_responses_advance_once() {
        for replay_status in [
            FleetReplayStatus::Fresh,
            FleetReplayStatus::Replayed,
            FleetReplayStatus::ReceiptObsolete,
            FleetReplayStatus::SuspendedAcknowledgement,
        ] {
            let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
            let pending = state
                .prepare_pending(sample_capacity())
                .expect("first pending poll")
                .clone();
            let response = valid_response(&pending, replay_status);

            state.apply_response(response).expect("accepted response");

            assert_eq!(state.next_sequence, 2);
            assert!(state.pending().is_none());
            assert!(state.session.is_some());
        }
    }

    #[test]
    fn invalid_response_fields_stop_without_changing_pending_state() {
        for field in [
            "request_id",
            "sequence",
            "protocol",
            "delay",
            "lease_count",
            "replay",
        ] {
            let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
            let pending = state
                .prepare_pending(sample_capacity())
                .expect("first pending poll")
                .clone();
            let mut response = valid_response(&pending, FleetReplayStatus::Fresh);
            match field {
                "request_id" => response.request_id = FleetUuid::new_v4(),
                "sequence" => response.accepted_sequence = pending.sequence + 1,
                "protocol" => response.protocol_version = 2,
                "delay" => response.poll_after_ms = 4_999,
                "lease_count" => response.leases = vec![sample_lease(); 17],
                "replay" => {
                    response.replay_status = FleetReplayStatus::ReceiptObsolete;
                    response.leases = vec![sample_lease()];
                }
                _ => unreachable!("fixed test case"),
            }
            assert!(matches!(
                state.apply_response(response),
                Err(FleetClientError::Protocol)
            ));
            assert_eq!(state.next_sequence, 1);
            assert_eq!(state.pending(), Some(&pending));
            assert!(state.session.is_none());
        }
    }

    #[test]
    fn session_identity_and_generation_cannot_move_backwards() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let first = state
            .prepare_pending(sample_capacity())
            .expect("first pending")
            .clone();
        state
            .apply_response(valid_response(&first, FleetReplayStatus::Fresh))
            .expect("first response");
        let pending = state
            .prepare_pending(sample_capacity())
            .expect("second pending")
            .clone();
        let current = state.session.clone().expect("session");

        for response_session in [
            FleetSession {
                session_id: FleetUuid::new_v4(),
                generation: current.generation,
            },
            FleetSession {
                session_id: current.session_id,
                generation: current.generation.saturating_sub(1),
            },
        ] {
            let mut response = valid_response(&pending, FleetReplayStatus::Fresh);
            response.session = response_session;
            assert!(matches!(
                state.apply_response(response),
                Err(FleetClientError::Protocol)
            ));
            assert_eq!(state.next_sequence, 2);
            assert_eq!(state.pending(), Some(&pending));
            assert_eq!(state.session.as_ref(), Some(&current));
        }
    }

    fn valid_response(
        pending: &ne_protocol::fleet::FleetPollRequest,
        replay_status: FleetReplayStatus,
    ) -> FleetPollResponse {
        FleetPollResponse {
            protocol_version: 1,
            session: FleetSession {
                session_id: FleetUuid::new_v4(),
                generation: 1,
            },
            request_id: pending.request_id,
            accepted_sequence: pending.sequence,
            server_time_unix_ms: 0,
            poll_after_ms: 5_000,
            replay_status,
            leases: Vec::new(),
        }
    }

    #[tokio::test]
    async fn retryable_outcomes_resend_the_exact_pending_request_without_new_snapshot() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let transport = TestTransport::new(vec![
            Err(FleetClientError::Retryable),
            Ok(FleetPollResponse {
                protocol_version: 1,
                session: FleetSession {
                    session_id: FleetUuid::new_v4(),
                    generation: 1,
                },
                request_id: FleetUuid::new_v4(),
                accepted_sequence: 1,
                server_time_unix_ms: 0,
                poll_after_ms: 5_000,
                replay_status: FleetReplayStatus::Fresh,
                leases: Vec::new(),
            }),
        ]);
        let snapshots = AtomicUsize::new(0);

        let first = poll_iteration(&mut state, &transport, || async {
            snapshots.fetch_add(1, Ordering::SeqCst);
            Ok(sample_capacity())
        })
        .await;
        assert_eq!(
            first,
            FleetIteration::Retry {
                snapshot_failed: false
            }
        );
        let pending = state.pending().expect("pending after retry").clone();
        transport.replace_last_response(valid_response(&pending, FleetReplayStatus::Fresh));

        let second = poll_iteration(&mut state, &transport, || async {
            snapshots.fetch_add(1, Ordering::SeqCst);
            Ok(sample_capacity())
        })
        .await;

        assert_eq!(second, FleetIteration::Wait(Duration::from_secs(5)));
        assert_eq!(snapshots.load(Ordering::SeqCst), 1);
        let sent = transport.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
    }

    #[tokio::test]
    async fn capacity_snapshot_failure_sends_nothing_and_keeps_sequence() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let transport = TestTransport::new(Vec::new());

        let outcome = poll_iteration(&mut state, &transport, || async {
            Err(FleetClientError::Transport)
        })
        .await;

        assert_eq!(
            outcome,
            FleetIteration::Retry {
                snapshot_failed: true
            }
        );
        assert!(transport.sent().is_empty());
        assert_eq!(state.next_sequence, 1);
        assert!(state.pending().is_none());
    }

    #[tokio::test]
    async fn payload_too_large_stops_with_pending_sequence_unchanged() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let transport = TestTransport::new(vec![Err(FleetClientError::PayloadTooLarge)]);

        let outcome =
            poll_iteration(&mut state, &transport, || async { Ok(sample_capacity()) }).await;

        assert_eq!(outcome, FleetIteration::Stop);
        assert_eq!(state.next_sequence, 1);
        assert!(state.pending().is_some());
    }

    #[tokio::test]
    async fn retryable_http_outcomes_preserve_the_pending_request() {
        let sequence_gap = serde_json::to_vec(&ne_protocol::fleet::FleetErrorResponse {
            code: ne_protocol::fleet::FleetErrorCode::SequenceGap,
            expected_sequence: Some(2),
            retry_after_ms: Some(5_000),
            supported_protocol: None,
        })
        .expect("serialize sequence gap");
        for (status, body) in [
            (429, Vec::new()),
            (500, Vec::new()),
            (503, Vec::new()),
            (409, sequence_gap),
        ] {
            let mapped = FleetClient::decode_poll_response(status, &body, 1)
                .expect_err("retryable response maps to an error");
            assert!(matches!(mapped, FleetClientError::Retryable));

            let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
            let transport = TestTransport::new(vec![Err(mapped)]);
            let snapshots = AtomicUsize::new(0);
            let first = poll_iteration(&mut state, &transport, || async {
                snapshots.fetch_add(1, Ordering::SeqCst);
                Ok(sample_capacity())
            })
            .await;
            assert_eq!(
                first,
                FleetIteration::Retry {
                    snapshot_failed: false
                }
            );
            let pending = state.pending().expect("pending retry").clone();
            transport.replace_last_response(valid_response(&pending, FleetReplayStatus::Fresh));
            let second = poll_iteration(&mut state, &transport, || async {
                snapshots.fetch_add(1, Ordering::SeqCst);
                Ok(sample_capacity())
            })
            .await;
            assert_eq!(second, FleetIteration::Wait(Duration::from_secs(5)));
            assert_eq!(snapshots.load(Ordering::SeqCst), 1);
            let sent = transport.sent();
            assert_eq!(sent.len(), 2);
            assert_eq!(sent[0].request_id, sent[1].request_id);
            assert_eq!(
                serde_json::to_vec(&sent[0]).expect("first request"),
                serde_json::to_vec(&sent[1]).expect("retry request")
            );
        }
    }

    #[test]
    fn sequence_gap_requires_a_forward_expected_sequence() {
        for (expected, retryable) in [(2, true), (1, false)] {
            let body = serde_json::to_vec(&ne_protocol::fleet::FleetErrorResponse {
                code: ne_protocol::fleet::FleetErrorCode::SequenceGap,
                expected_sequence: Some(expected),
                retry_after_ms: Some(5_000),
                supported_protocol: None,
            })
            .expect("serialize sequence gap");
            let result = FleetClient::decode_poll_response(409, &body, 1);
            assert_eq!(
                matches!(result, Err(FleetClientError::Retryable)),
                retryable
            );
            assert_eq!(
                matches!(result, Err(FleetClientError::Protocol)),
                !retryable
            );
        }
    }

    #[test]
    fn unadvertised_lease_contract_does_not_mutate_state() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let pending = state
            .prepare_pending(sample_capacity())
            .expect("pending")
            .clone();
        let mut response = valid_response(&pending, FleetReplayStatus::Fresh);
        response.leases = vec![LeaseHeader {
            job_id: ne_protocol::fleet::FleetToken::parse("job-1").expect("job"),
            lease_id: FleetUuid::new_v4(),
            attempt_generation: 1,
            lease_expires_at_unix_ms: 1,
            contract: JobContract::new("ne.test.lease-header", "1").expect("contract"),
            payload_digest: vec![0; 32],
        }];
        assert!(matches!(
            state.apply_response(response),
            Err(FleetClientError::Protocol)
        ));
        assert_eq!(state.next_sequence, 1);
        assert_eq!(state.pending(), Some(&pending));
    }

    #[test]
    fn advertised_lease_contract_is_accepted_by_response_validation() {
        let mut state = FleetLoopState::with_process_instance_id(FleetUuid::new_v4());
        let mut pending = state
            .prepare_pending(sample_capacity())
            .expect("pending")
            .clone();
        let contract = JobContract::new("example.contract", "1").expect("contract");
        pending.supported_contracts.push(contract.clone());
        let mut response = valid_response(&pending, FleetReplayStatus::Fresh);
        response.leases = vec![LeaseHeader {
            job_id: ne_protocol::fleet::FleetToken::parse("job-1").expect("job"),
            lease_id: FleetUuid::new_v4(),
            attempt_generation: 1,
            lease_expires_at_unix_ms: 1,
            contract,
            payload_digest: vec![0; 32],
        }];

        super::validate_response_for(&response, &pending)
            .expect("an exact advertised contract may be assigned");
    }

    struct TestTransport {
        outcomes: Mutex<Vec<Result<FleetPollResponse, FleetClientError>>>,
        requests: Mutex<Vec<ne_protocol::fleet::FleetPollRequest>>,
    }

    impl TestTransport {
        fn new(outcomes: Vec<Result<FleetPollResponse, FleetClientError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().rev().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn replace_last_response(&self, response: FleetPollResponse) {
            let mut outcomes = self.outcomes.lock().expect("outcomes lock");
            outcomes.clear();
            outcomes.push(Ok(response));
        }

        fn sent(&self) -> Vec<ne_protocol::fleet::FleetPollRequest> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    impl FleetTransport for TestTransport {
        async fn poll(
            &self,
            request: &ne_protocol::fleet::FleetPollRequest,
        ) -> Result<FleetPollResponse, FleetClientError> {
            self.requests
                .lock()
                .expect("requests lock")
                .push(request.clone());
            self.outcomes
                .lock()
                .expect("outcomes lock")
                .pop()
                .unwrap_or(Err(FleetClientError::Transport))
        }
    }

    fn sample_capacity() -> RunnerCapacity {
        RunnerCapacity {
            revision: 1,
            configured_workspace_ceiling: 1,
            registered_workspaces: 0,
            resident_workspaces: 0,
            runnable_workspaces: 0,
            allocated_cpu_millicores: 0,
            allocated_memory_bytes: 0,
            warm_pool_reserved_slots: 0,
            profiles: Vec::new(),
            operations: Vec::new(),
        }
    }

    fn sample_lease() -> LeaseHeader {
        LeaseHeader {
            job_id: ne_protocol::fleet::FleetToken::parse("job-1").expect("job ID"),
            lease_id: FleetUuid::new_v4(),
            attempt_generation: 1,
            lease_expires_at_unix_ms: 1,
            contract: JobContract::new("example.contract", "1").expect("contract"),
            payload_digest: vec![0; 32],
        }
    }

    #[test]
    fn unreadable_or_invalid_pem_is_rejected() {
        let dir = tempfile::tempdir().expect("temporary files");
        let (certificate, key) = certificate_and_key();
        let cert = write(dir.path(), "client.pem", &certificate);
        let key = write(dir.path(), "client-key.pem", &key);
        let missing = dir.path().join("missing-ca.pem");
        let invalid_ca = write(dir.path(), "invalid-ca.pem", "not PEM");

        for ca in [missing, invalid_ca] {
            let config = complete_config(
                "https://localhost:8443/v1/poll",
                ca,
                cert.clone(),
                key.clone(),
            );
            assert!(matches!(
                FleetClient::new(config),
                Err(FleetClientError::Configuration)
            ));
        }
    }

    #[test]
    fn certificate_private_key_mismatch_is_rejected() {
        let dir = tempfile::tempdir().expect("temporary files");
        let (first_certificate, _) = certificate_and_key();
        let (_, second_key) = certificate_and_key();
        let ca = write(dir.path(), "ca.pem", &first_certificate);
        let cert = write(dir.path(), "client.pem", &first_certificate);
        let key = write(dir.path(), "client-key.pem", &second_key);

        let config = complete_config("https://localhost:8443/v1/poll", ca, cert, key);
        assert!(matches!(
            FleetClient::new(config),
            Err(FleetClientError::Configuration)
        ));
    }

    #[test]
    fn matching_ca_certificate_and_key_build_client() {
        let dir = tempfile::tempdir().expect("temporary files");
        let (certificate, key) = certificate_and_key();
        let config = complete_config(
            "https://localhost:8443/v1/poll",
            write(dir.path(), "ca.pem", &certificate),
            write(dir.path(), "client.pem", &certificate),
            write(dir.path(), "client-key.pem", &key),
        );

        FleetClient::new(config).expect("matching TLS material");
    }

    #[tokio::test]
    async fn redirect_response_is_refused() {
        let server = tls_server(
            "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
            None,
        )
        .await;
        let client = FleetClient::new(server.config.clone()).expect("client");

        let result = client.post_json(b"{}").await;

        assert!(matches!(result, Err(FleetClientError::RedirectRefused)));
        server.task.await.expect("server task");
    }

    #[tokio::test]
    async fn slow_tls_handshake_obeys_request_timeout() {
        let server = stalled_tcp_server().await;
        let mut config = server.config.clone();
        config.request_timeout = Duration::from_millis(25);
        config.connect_timeout = Duration::from_millis(25);
        let client = FleetClient::new(config).expect("client");

        let result = tokio::time::timeout(Duration::from_millis(75), client.post_json(b"{}"))
            .await
            .expect("request timeout bounds the TLS handshake");

        assert!(matches!(result, Err(FleetClientError::Transport)));
        server.task.await.expect("server task");
    }

    #[tokio::test]
    async fn slow_response_obeys_request_timeout() {
        let server = tls_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_owned(),
            Some(Duration::from_millis(100)),
        )
        .await;
        let mut config = server.config.clone();
        config.request_timeout = Duration::from_millis(25);
        let client = FleetClient::new(config).expect("client");

        let result = tokio::time::timeout(Duration::from_millis(75), client.post_json(b"{}"))
            .await
            .expect("request timeout bounds the response");

        assert!(matches!(result, Err(FleetClientError::Transport)));
        server.task.await.expect("server task");
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_json_decoding() {
        let body = "x".repeat(33);
        let server = tls_server(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            None,
        )
        .await;
        let mut config = server.config.clone();
        config.max_response_bytes = 32;
        let client = FleetClient::new(config).expect("client");

        let result = client.post_json(b"{}").await;

        assert!(matches!(result, Err(FleetClientError::ResponseTooLarge)));
        server.task.await.expect("server task");
    }

    fn certificate_and_key() -> (String, String) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed certificate");
        (certificate.cert.pem(), certificate.key_pair.serialize_pem())
    }

    fn write(directory: &std::path::Path, name: &str, value: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, value).expect("write PEM");
        path
    }

    fn complete_config(
        endpoint: &str,
        ca_cert: PathBuf,
        client_cert: PathBuf,
        client_key: PathBuf,
    ) -> FleetClientConfig {
        FleetClientConfig::from_optional(
            Some(endpoint.to_owned()),
            Some(ca_cert),
            Some(client_cert),
            Some(client_key),
        )
        .expect("complete configuration")
        .expect("enabled client")
    }

    struct TestServer {
        config: FleetClientConfig,
        task: JoinHandle<()>,
        _files: tempfile::TempDir,
    }

    async fn tls_server(response: String, delay: Option<Duration>) -> TestServer {
        crate::tls::install_crypto_provider();
        let (ca, ca_key) = certificate_authority();
        let (server_certificate, server_key) = signed_leaf(
            vec!["localhost".to_owned()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client_certificate, client_key) = signed_leaf(
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        let files = tempfile::tempdir().expect("temporary files");
        let ca_cert = write(files.path(), "ca.pem", &ca.pem());
        let client_cert = write(files.path(), "client.pem", &client_certificate.pem());
        let client_key = write(files.path(), "client-key.pem", &client_key.serialize_pem());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).expect("add client CA");
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier");
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_certificate.der().clone()], private_key)
            .expect("TLS server configuration");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS server");
        let endpoint = format!(
            "https://localhost:{}/v1/poll",
            listener.local_addr().expect("listener address").port()
        );
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept connection");
            let mut stream = acceptor.accept(socket).await.expect("TLS handshake");
            let mut request = [0_u8; 1024];
            let request_size = stream.read(&mut request).await.expect("read request");
            if request_size == 0 {
                return;
            }
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let config = complete_config(&endpoint, ca_cert, client_cert, client_key);

        TestServer {
            config,
            task,
            _files: files,
        }
    }

    async fn stalled_tcp_server() -> TestServer {
        let (certificate, key) = certificate_and_key();
        let files = tempfile::tempdir().expect("temporary files");
        let ca_cert = write(files.path(), "ca.pem", &certificate);
        let client_cert = write(files.path(), "client.pem", &certificate);
        let client_key = write(files.path(), "client-key.pem", &key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP server");
        let endpoint = format!(
            "https://localhost:{}/v1/poll",
            listener.local_addr().expect("listener address").port()
        );
        let task = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept connection");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let config = complete_config(&endpoint, ca_cert, client_cert, client_key);

        TestServer {
            config,
            task,
            _files: files,
        }
    }

    fn certificate_authority() -> (rcgen::Certificate, KeyPair) {
        let mut parameters = CertificateParams::new(Vec::new()).expect("CA parameters");
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().expect("CA key");
        let certificate = parameters.self_signed(&key).expect("CA certificate");
        (certificate, key)
    }

    fn signed_leaf(
        names: Vec<String>,
        usage: ExtendedKeyUsagePurpose,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut parameters = CertificateParams::new(names).expect("leaf parameters");
        parameters.extended_key_usages.push(usage);
        let key = KeyPair::generate().expect("leaf key");
        let certificate = parameters
            .signed_by(&key, ca, ca_key)
            .expect("leaf certificate");
        (certificate, key)
    }
}

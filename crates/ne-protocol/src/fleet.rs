// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Stable wire types for the fleet poll protocol.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::profile::{ExecutionProfile, WorkspaceOperation};

/// The first stable fleet poll protocol version.
pub const FLEET_PROTOCOL_V1: u16 = 1;

/// Largest workspace ceiling representable by the fleet wire contract.
pub const MAX_RUNNER_WORKSPACES: u32 = 1_000_000;
const MAX_CPU_MILLICORES: u64 = 1_000_000_000;
const MAX_MEMORY_BYTES: u64 = 1_u64 << 50;

/// A validation error for a fleet wire value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FleetValidationError {
    /// A UUID is not canonical lowercase version four text.
    #[error("fleet UUID must be canonical lowercase version four text")]
    InvalidUuid,
    /// A token does not use the fleet identifier grammar.
    #[error("fleet token is outside the allowed identifier grammar")]
    InvalidToken,
    /// A job contract identifier is invalid.
    #[error("job contract identifier is outside the allowed grammar")]
    InvalidContractId,
    /// A job contract version is invalid.
    #[error("job contract version is outside the allowed grammar")]
    InvalidContractVersion,
    /// A terminal result code is invalid.
    #[error("terminal result code is outside the allowed grammar")]
    InvalidResultCode,
    /// A capacity integer exceeds the protocol limit.
    #[error("fleet capacity value is outside the protocol limit")]
    CapacityOutOfRange,
    /// Capacity counts do not have a valid relationship.
    #[error("fleet capacity counts are inconsistent")]
    InconsistentCapacity,
    /// A session or attempt generation is zero.
    #[error("fleet generation must be positive")]
    InvalidGeneration,
    /// A request or accepted sequence is zero.
    #[error("fleet sequence must be positive")]
    InvalidSequence,
    /// A bounded request or response collection exceeds its maximum size.
    #[error("fleet collection exceeds its protocol limit")]
    TooManyEntries,
    /// More than one operation targets the same lease attempt.
    #[error("fleet request contains duplicate attempt operations")]
    DuplicateAttemptOperation,
    /// A lease header does not carry an exact 32-byte digest.
    #[error("fleet lease payload digest must contain exactly 32 bytes")]
    InvalidPayloadDigest,
    /// A successful response has an unsupported poll delay.
    #[error("fleet poll delay is outside the supported range")]
    InvalidPollDelay,
    /// A sanitized replay response includes lease headers.
    #[error("fleet sanitized replay response must not contain leases")]
    InvalidReplayResponse,
    /// A fleet error includes missing, invalid, or irrelevant guidance.
    #[error("fleet error guidance is inconsistent with its error code")]
    InvalidErrorGuidance,
}

/// A canonical version-four UUID used by the fleet protocol.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FleetUuid(uuid::Uuid);

impl FleetUuid {
    /// Create a new random version-four fleet UUID.
    #[must_use]
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Parse canonical lowercase version-four UUID text.
    pub fn parse_canonical(value: &str) -> Result<Self, FleetValidationError> {
        let parsed = uuid::Uuid::parse_str(value).map_err(|_| FleetValidationError::InvalidUuid)?;
        if parsed.is_nil()
            || parsed.get_version_num() != 4
            || parsed.hyphenated().to_string() != value
        {
            return Err(FleetValidationError::InvalidUuid);
        }
        Ok(Self(parsed))
    }
}

impl fmt::Debug for FleetUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.0.hyphenated().to_string();
        write!(formatter, "FleetUuid({}…)", &text[..8])
    }
}

impl Serialize for FleetUuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

impl<'de> Deserialize<'de> for FleetUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_canonical(&value).map_err(serde::de::Error::custom)
    }
}

/// An ASCII tenant, runner, or job identifier.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FleetToken(String);

impl FleetToken {
    /// Parse a fleet identifier token.
    pub fn parse(value: impl Into<String>) -> Result<Self, FleetValidationError> {
        let value = value.into();
        if !is_fleet_token(&value) {
            return Err(FleetValidationError::InvalidToken);
        }
        Ok(Self(value))
    }

    /// Return the validated token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FleetToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix_end = self.0.len().min(8);
        write!(formatter, "FleetToken({}…)", &self.0[..prefix_end])
    }
}

impl Serialize for FleetToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FleetToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// A validated machine-readable terminal result code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct FleetResultCode(String);

impl FleetResultCode {
    /// Parse an uppercase terminal result code.
    pub fn parse(value: impl Into<String>) -> Result<Self, FleetValidationError> {
        let value = value.into();
        if !is_result_code(&value) {
            return Err(FleetValidationError::InvalidResultCode);
        }
        Ok(Self(value))
    }

    /// Return the validated result-code text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FleetResultCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// A supported fleet protocol-version range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetProtocolRange {
    /// The lowest compatible protocol version.
    pub min_version: u16,
    /// The highest compatible protocol version.
    pub max_version: u16,
}

impl FleetProtocolRange {
    /// Build a non-empty inclusive protocol-version range.
    pub fn new(min_version: u16, max_version: u16) -> Result<Self, FleetValidationError> {
        if min_version == 0 || min_version > max_version {
            return Err(FleetValidationError::CapacityOutOfRange);
        }
        Ok(Self {
            min_version,
            max_version,
        })
    }

    /// Validate this inclusive protocol-version range.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        Self::new(self.min_version, self.max_version).map(|_| ())
    }
}

/// Aggregate inventory reported by a running runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerCapacity {
    /// A monotonically increasing local snapshot revision.
    pub revision: u64,
    /// The configured upper bound on resident workspaces and warm-pool slots.
    pub configured_workspace_ceiling: u32,
    /// The number of workspaces registered by the runtime.
    pub registered_workspaces: u32,
    /// The number of registered workspaces and ready warm-pool members.
    pub resident_workspaces: u32,
    /// The number of registered workspaces that are runnable.
    pub runnable_workspaces: u32,
    /// Allocated CPU in millicores.
    pub allocated_cpu_millicores: u64,
    /// Allocated memory in bytes.
    pub allocated_memory_bytes: u64,
    /// Ready and in-flight warm-pool capacity reservations.
    pub warm_pool_reserved_slots: u32,
    /// Execution profiles available from the runtime.
    pub profiles: Vec<ExecutionProfile>,
    /// Workspace operations available from the runtime.
    pub operations: Vec<WorkspaceOperation>,
}

impl RunnerCapacity {
    /// Validate limits, count relationships, and set-like capability lists.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        if self.configured_workspace_ceiling > MAX_RUNNER_WORKSPACES
            || self.registered_workspaces > MAX_RUNNER_WORKSPACES
            || self.resident_workspaces > MAX_RUNNER_WORKSPACES
            || self.runnable_workspaces > MAX_RUNNER_WORKSPACES
            || self.warm_pool_reserved_slots > MAX_RUNNER_WORKSPACES
            || self.allocated_cpu_millicores > MAX_CPU_MILLICORES
            || self.allocated_memory_bytes > MAX_MEMORY_BYTES
        {
            return Err(FleetValidationError::CapacityOutOfRange);
        }
        if self.runnable_workspaces > self.registered_workspaces
            || self.registered_workspaces > self.resident_workspaces
            || self
                .registered_workspaces
                .checked_add(self.warm_pool_reserved_slots)
                .is_none_or(|total| total > self.configured_workspace_ceiling)
            || has_duplicates(&self.profiles)
            || has_duplicates(&self.operations)
        {
            return Err(FleetValidationError::InconsistentCapacity);
        }
        Ok(())
    }
}

fn is_fleet_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_contract_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_contract_version(value: &str) -> bool {
    (1..=32).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_result_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn has_duplicates<T>(values: &[T]) -> bool
where
    T: Eq + std::hash::Hash,
{
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(value))
}

/// A supported header-only job contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct JobContract {
    /// The lowercase contract identifier.
    pub id: String,
    /// The printable contract version.
    pub version: String,
}

impl JobContract {
    /// Build a validated job contract.
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, FleetValidationError> {
        let id = id.into();
        let version = version.into();
        if !is_contract_id(&id) {
            return Err(FleetValidationError::InvalidContractId);
        }
        if !is_contract_version(&version) {
            return Err(FleetValidationError::InvalidContractVersion);
        }
        Ok(Self { id, version })
    }

    /// Validate the contract fields.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        Self::new(self.id.clone(), self.version.clone()).map(|_| ())
    }
}

impl<'de> Deserialize<'de> for JobContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawJobContract {
            id: String,
            version: String,
        }

        let raw = RawJobContract::deserialize(deserializer)?;
        Self::new(raw.id, raw.version).map_err(serde::de::Error::custom)
    }
}

/// A server-issued fleet session and its fencing generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSession {
    /// The server-issued session identifier.
    pub session_id: FleetUuid,
    /// The strictly positive session fencing generation.
    pub generation: u64,
}

impl FleetSession {
    /// Validate the session fencing generation.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        if self.generation == 0 {
            return Err(FleetValidationError::InvalidGeneration);
        }
        Ok(())
    }
}

/// A lease renewal fenced to one job attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRenewal {
    /// The job identifier.
    pub job_id: FleetToken,
    /// The lease identifier.
    pub lease_id: FleetUuid,
    /// The strictly positive attempt generation.
    pub attempt_generation: u32,
}

/// A lease release fenced to one job attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRelease {
    /// The job identifier.
    pub job_id: FleetToken,
    /// The lease identifier.
    pub lease_id: FleetUuid,
    /// The strictly positive attempt generation.
    pub attempt_generation: u32,
}

/// The closed outcome of a terminal job attempt report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    /// The job completed successfully.
    Succeeded,
    /// The job failed and may be retried.
    FailedRetryable,
    /// The job failed and must not be retried.
    FailedTerminal,
}

/// A terminal job-attempt report with no executable or textual payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalReport {
    /// The job identifier.
    pub job_id: FleetToken,
    /// The lease identifier.
    pub lease_id: FleetUuid,
    /// The strictly positive attempt generation.
    pub attempt_generation: u32,
    /// The closed attempt outcome.
    pub outcome: TerminalOutcome,
    /// The machine-readable result code.
    pub result_code: FleetResultCode,
    /// CPU time consumed by the attempt, in milliseconds.
    pub cpu_milliseconds: u64,
    /// Number of output bytes produced by the attempt.
    pub output_bytes: u64,
}

/// One leased header with a fixed-size opaque payload digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseHeader {
    /// The job identifier.
    pub job_id: FleetToken,
    /// The lease identifier.
    pub lease_id: FleetUuid,
    /// The strictly positive attempt generation.
    pub attempt_generation: u32,
    /// The lease expiry expressed as milliseconds since the Unix epoch.
    pub lease_expires_at_unix_ms: i64,
    /// The contract accepted for this lease.
    pub contract: JobContract,
    /// The 32-byte payload digest.
    pub payload_digest: Vec<u8>,
}

impl LeaseHeader {
    /// Validate the lease header bounds.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        if self.attempt_generation == 0 {
            return Err(FleetValidationError::InvalidGeneration);
        }
        if self.payload_digest.len() != 32 {
            return Err(FleetValidationError::InvalidPayloadDigest);
        }
        self.contract.validate()
    }
}

/// The replay classification for a successful fleet poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetReplayStatus {
    /// The server accepted a new poll.
    Fresh,
    /// The server replayed an exact prior accepted poll.
    Replayed,
    /// A replay receipt exists but its leases are no longer current.
    ReceiptObsolete,
    /// The server acknowledged a poll while the runner is suspended.
    #[serde(rename = "suspended_ack")]
    SuspendedAcknowledgement,
}

/// The stable machine-readable class of a fleet poll error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetErrorCode {
    /// The request body is malformed.
    MalformedRequest,
    /// A known value failed validation.
    ValidationFailed,
    /// The request body is too large.
    PayloadTooLarge,
    /// The caller is not authenticated.
    Unauthenticated,
    /// The current lifecycle state denies the request.
    LifecycleDenied,
    /// The request sequence has a forward gap.
    SequenceGap,
    /// The caller exceeded a rate limit.
    RateLimited,
    /// No mutually compatible protocol version exists.
    ProtocolConflict,
    /// The request conflicts with an accepted request.
    RequestConflict,
    /// The session has been fenced by a newer generation.
    SessionFenced,
    /// The server encountered an internal failure.
    Internal,
    /// A required dependency is unavailable.
    Unavailable,
}

/// A stable fleet error with machine-readable guidance only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FleetErrorResponse {
    /// The error class.
    pub code: FleetErrorCode,
    /// The next sequence expected by the server, when applicable.
    pub expected_sequence: Option<u64>,
    /// The suggested retry delay in milliseconds, when applicable.
    pub retry_after_ms: Option<u32>,
    /// The server-supported protocol range, when applicable.
    pub supported_protocol: Option<FleetProtocolRange>,
}

impl FleetErrorResponse {
    /// Validate code-specific error guidance before client control flow uses it.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        if let Some(protocol) = &self.supported_protocol {
            protocol.validate()?;
        }

        let positive_expected_sequence =
            self.expected_sequence.is_some_and(|sequence| sequence > 0);
        let positive_retry_delay = self.retry_after_ms.is_some_and(|delay| delay > 0);
        let valid = match self.code {
            FleetErrorCode::SequenceGap => {
                positive_expected_sequence
                    && positive_retry_delay
                    && self.supported_protocol.is_none()
            }
            FleetErrorCode::RateLimited | FleetErrorCode::Unavailable => {
                self.expected_sequence.is_none()
                    && positive_retry_delay
                    && self.supported_protocol.is_none()
            }
            FleetErrorCode::ProtocolConflict => {
                self.expected_sequence.is_none()
                    && self.retry_after_ms.is_none()
                    && self.supported_protocol.is_some()
            }
            _ => {
                self.expected_sequence.is_none()
                    && self.retry_after_ms.is_none()
                    && self.supported_protocol.is_none()
            }
        };
        if !valid {
            return Err(FleetValidationError::InvalidErrorGuidance);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for FleetErrorResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawFleetErrorResponse {
            code: FleetErrorCode,
            expected_sequence: Option<u64>,
            retry_after_ms: Option<u32>,
            supported_protocol: Option<FleetProtocolRange>,
        }

        let raw = RawFleetErrorResponse::deserialize(deserializer)?;
        let response = Self {
            code: raw.code,
            expected_sequence: raw.expected_sequence,
            retry_after_ms: raw.retry_after_ms,
            supported_protocol: raw.supported_protocol,
        };
        response.validate().map_err(serde::de::Error::custom)?;
        Ok(response)
    }
}

/// A complete fleet poll request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FleetPollRequest {
    /// The client-supported protocol range.
    pub protocol: FleetProtocolRange,
    /// The random process instance identifier.
    pub process_instance_id: FleetUuid,
    /// The server-issued session, omitted on the first poll from a process.
    pub session: Option<FleetSession>,
    /// The unique request identifier.
    pub request_id: FleetUuid,
    /// The process-local request sequence.
    pub sequence: u64,
    /// The atomic runtime capacity snapshot.
    pub capacity: RunnerCapacity,
    /// The job contracts supported by the runtime.
    pub supported_contracts: Vec<JobContract>,
    /// The lease renewals included in this poll.
    pub renewals: Vec<LeaseRenewal>,
    /// The lease releases included in this poll.
    pub releases: Vec<LeaseRelease>,
    /// The terminal reports included in this poll.
    pub terminal_reports: Vec<TerminalReport>,
}

impl FleetPollRequest {
    /// Validate the complete request before it is accepted for processing.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        self.protocol.validate()?;
        if self.sequence == 0 || (self.session.is_none() && self.sequence != 1) {
            return Err(FleetValidationError::InvalidSequence);
        }
        if let Some(session) = &self.session {
            session.validate()?;
        }
        self.capacity.validate()?;
        if self.supported_contracts.len() > 32
            || self.renewals.len() + self.releases.len() + self.terminal_reports.len() > 64
            || has_duplicates(&self.supported_contracts)
        {
            return Err(FleetValidationError::TooManyEntries);
        }
        for contract in &self.supported_contracts {
            contract.validate()?;
        }
        let mut attempts = HashSet::new();
        for renewal in &self.renewals {
            validate_attempt(renewal.attempt_generation)?;
            insert_attempt_operation(&mut attempts, renewal.lease_id, renewal.attempt_generation)?;
        }
        for release in &self.releases {
            validate_attempt(release.attempt_generation)?;
            insert_attempt_operation(&mut attempts, release.lease_id, release.attempt_generation)?;
        }
        for report in &self.terminal_reports {
            validate_attempt(report.attempt_generation)?;
            insert_attempt_operation(&mut attempts, report.lease_id, report.attempt_generation)?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for FleetPollRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawFleetPollRequest {
            protocol: FleetProtocolRange,
            process_instance_id: FleetUuid,
            session: Option<FleetSession>,
            request_id: FleetUuid,
            sequence: u64,
            capacity: RunnerCapacity,
            supported_contracts: Vec<JobContract>,
            renewals: Vec<LeaseRenewal>,
            releases: Vec<LeaseRelease>,
            terminal_reports: Vec<TerminalReport>,
        }

        let raw = RawFleetPollRequest::deserialize(deserializer)?;
        let request = Self {
            protocol: raw.protocol,
            process_instance_id: raw.process_instance_id,
            session: raw.session,
            request_id: raw.request_id,
            sequence: raw.sequence,
            capacity: raw.capacity,
            supported_contracts: raw.supported_contracts,
            renewals: raw.renewals,
            releases: raw.releases,
            terminal_reports: raw.terminal_reports,
        };
        request.validate().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

/// A successful fleet poll response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FleetPollResponse {
    /// The selected protocol version.
    pub protocol_version: u16,
    /// The accepted session and fencing generation.
    pub session: FleetSession,
    /// The accepted request identifier.
    pub request_id: FleetUuid,
    /// The accepted request sequence.
    pub accepted_sequence: u64,
    /// The server time in milliseconds since the Unix epoch.
    pub server_time_unix_ms: i64,
    /// The recommended delay before the next poll, in milliseconds.
    pub poll_after_ms: u32,
    /// The replay classification.
    pub replay_status: FleetReplayStatus,
    /// The assigned header-only leases.
    pub leases: Vec<LeaseHeader>,
}

impl FleetPollResponse {
    /// Validate response invariants and bounded lease headers.
    pub fn validate(&self) -> Result<(), FleetValidationError> {
        if self.protocol_version == 0 || self.accepted_sequence == 0 {
            return Err(FleetValidationError::InvalidSequence);
        }
        if !(5_000..=60_000).contains(&self.poll_after_ms) {
            return Err(FleetValidationError::InvalidPollDelay);
        }
        self.session.validate()?;
        if self.leases.len() > 16 {
            return Err(FleetValidationError::TooManyEntries);
        }
        if matches!(
            self.replay_status,
            FleetReplayStatus::ReceiptObsolete | FleetReplayStatus::SuspendedAcknowledgement
        ) && !self.leases.is_empty()
        {
            return Err(FleetValidationError::InvalidReplayResponse);
        }
        for header in &self.leases {
            header.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for FleetPollResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawFleetPollResponse {
            protocol_version: u16,
            session: FleetSession,
            request_id: FleetUuid,
            accepted_sequence: u64,
            server_time_unix_ms: i64,
            poll_after_ms: u32,
            replay_status: FleetReplayStatus,
            leases: Vec<LeaseHeader>,
        }

        let raw = RawFleetPollResponse::deserialize(deserializer)?;
        let response = Self {
            protocol_version: raw.protocol_version,
            session: raw.session,
            request_id: raw.request_id,
            accepted_sequence: raw.accepted_sequence,
            server_time_unix_ms: raw.server_time_unix_ms,
            poll_after_ms: raw.poll_after_ms,
            replay_status: raw.replay_status,
            leases: raw.leases,
        };
        response.validate().map_err(serde::de::Error::custom)?;
        Ok(response)
    }
}

/// A JSON decoding error for the fleet protocol.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FleetJsonError {
    /// The JSON syntax is malformed.
    #[error("invalid fleet JSON")]
    MalformedJson,
    /// The JSON contains a duplicate object key.
    #[error("duplicate fleet JSON object key")]
    DuplicateKey,
    /// A typed fleet value is invalid.
    #[error("invalid fleet wire value")]
    InvalidValue,
}

/// Decode JSON after rejecting duplicate keys at every object level.
///
/// Unknown fields remain compatible with serde's normal struct behavior.
pub fn from_json_no_duplicate_keys<T>(input: &str) -> Result<T, FleetJsonError>
where
    T: serde::de::DeserializeOwned,
{
    let mut duplicate_check = serde_json::Deserializer::from_str(input);
    RejectDuplicateKeys::deserialize(&mut duplicate_check)
        .map_err(classify_json_structure_error)?;
    duplicate_check
        .end()
        .map_err(classify_json_structure_error)?;
    serde_json::from_str(input).map_err(|_| FleetJsonError::InvalidValue)
}

struct RejectDuplicateKeys;

impl<'de> Deserialize<'de> for RejectDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateKeysVisitor)
    }
}

struct RejectDuplicateKeysVisitor;

impl<'de> serde::de::Visitor<'de> for RejectDuplicateKeysVisitor {
    type Value = RejectDuplicateKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateKeys)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        RejectDuplicateKeys::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while sequence.next_element::<RejectDuplicateKeys>()?.is_some() {}
        Ok(RejectDuplicateKeys)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<RejectDuplicateKeys>()?;
        }
        Ok(RejectDuplicateKeys)
    }
}

fn validate_attempt(generation: u32) -> Result<(), FleetValidationError> {
    if generation == 0 {
        return Err(FleetValidationError::InvalidGeneration);
    }
    Ok(())
}

fn insert_attempt_operation(
    attempts: &mut HashSet<(FleetUuid, u32)>,
    lease_id: FleetUuid,
    attempt_generation: u32,
) -> Result<(), FleetValidationError> {
    if !attempts.insert((lease_id, attempt_generation)) {
        return Err(FleetValidationError::DuplicateAttemptOperation);
    }
    Ok(())
}

fn classify_json_structure_error(error: serde_json::Error) -> FleetJsonError {
    if error.to_string().starts_with("duplicate JSON object key") {
        FleetJsonError::DuplicateKey
    } else {
        FleetJsonError::MalformedJson
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ExecutionProfile, WorkspaceOperation};

    #[test]
    fn rejects_noncanonical_process_and_request_identifiers() {
        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        assert!(FleetUuid::parse_canonical(canonical).is_ok());
        assert!(FleetUuid::parse_canonical("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(FleetUuid::parse_canonical("550e8400e29b41d4a716446655440000").is_err());
        assert!(FleetUuid::parse_canonical("00000000-0000-0000-0000-000000000000").is_err());
        assert!(FleetUuid::parse_canonical("550e8400-e29b-11d4-a716-446655440000").is_err());
    }

    #[test]
    fn rejects_tokens_outside_the_fleet_identifier_grammar() {
        assert!(FleetToken::parse("tenant.runner:job-1_2").is_ok());
        assert!(FleetToken::parse("").is_err());
        assert!(FleetToken::parse("a".repeat(65)).is_err());
        assert!(FleetToken::parse("runner name").is_err());
        assert!(FleetToken::parse("runner/name").is_err());
        assert!(FleetToken::parse("runnér").is_err());
    }

    #[test]
    fn rejects_contracts_outside_the_wire_limits() {
        assert!(JobContract::new("ne.test.contract", "v1").is_ok());
        assert!(JobContract::new("Ne.test.contract", "v1").is_err());
        assert!(JobContract::new("ne.test.contract", "").is_err());
        assert!(JobContract::new("ne.test.contract", "v".repeat(33)).is_err());
        assert!(JobContract::new("ne.test.contract", "version 1").is_err());
    }

    #[test]
    fn rejects_result_codes_outside_the_wire_limits() {
        assert!(FleetResultCode::parse("SUCCEEDED").is_ok());
        assert!(FleetResultCode::parse("succeeded").is_err());
        assert!(FleetResultCode::parse("RESULT-CODE").is_err());
        assert!(FleetResultCode::parse("R".repeat(65)).is_err());
    }

    #[test]
    fn rejects_capacity_values_and_relationships_outside_the_wire_limits() {
        let valid = RunnerCapacity {
            revision: 1,
            configured_workspace_ceiling: 1_000_000,
            registered_workspaces: 1,
            resident_workspaces: 1,
            runnable_workspaces: 1,
            allocated_cpu_millicores: 1_000_000_000,
            allocated_memory_bytes: 1_u64 << 50,
            warm_pool_reserved_slots: 0,
            profiles: vec![ExecutionProfile::Standard],
            operations: vec![WorkspaceOperation::Create],
        };
        assert!(valid.validate().is_ok());

        let mut over_cpu = valid.clone();
        over_cpu.allocated_cpu_millicores = 1_000_000_001;
        assert!(over_cpu.validate().is_err());

        let mut over_memory = valid.clone();
        over_memory.allocated_memory_bytes = (1_u64 << 50) + 1;
        assert!(over_memory.validate().is_err());

        let mut too_many_workspaces = valid.clone();
        too_many_workspaces.configured_workspace_ceiling = 1_000_001;
        assert!(too_many_workspaces.validate().is_err());

        let mut too_many_resident_workspaces = valid.clone();
        too_many_resident_workspaces.resident_workspaces = 1_000_001;
        assert!(too_many_resident_workspaces.validate().is_err());

        let mut too_many_reserved_slots = valid.clone();
        too_many_reserved_slots.warm_pool_reserved_slots = 1_000_001;
        assert!(too_many_reserved_slots.validate().is_err());

        let mut runnable_outside_registered = valid.clone();
        runnable_outside_registered.runnable_workspaces = 2;
        assert!(runnable_outside_registered.validate().is_err());

        let mut reserved_outside_ceiling = valid;
        reserved_outside_ceiling.warm_pool_reserved_slots = 1_000_000;
        assert!(reserved_outside_ceiling.validate().is_err());
    }

    #[test]
    fn serializes_the_initial_poll_request_with_the_stable_v1_shape() {
        let request = sample_request();

        let json = serde_json::to_string(&request).expect("serialize request");

        assert_eq!(
            json,
            r#"{"protocol":{"min_version":1,"max_version":1},"process_instance_id":"550e8400-e29b-41d4-a716-446655440000","session":null,"request_id":"550e8400-e29b-41d4-a716-446655440001","sequence":1,"capacity":{"revision":1,"configured_workspace_ceiling":10,"registered_workspaces":0,"resident_workspaces":0,"runnable_workspaces":0,"allocated_cpu_millicores":0,"allocated_memory_bytes":0,"warm_pool_reserved_slots":0,"profiles":["standard"],"operations":["create"]},"supported_contracts":[],"renewals":[],"releases":[],"terminal_reports":[]}"#
        );
    }

    #[test]
    fn serializes_replay_and_sanitized_response_states_with_stable_values() {
        let replayed = FleetPollResponse {
            protocol_version: FLEET_PROTOCOL_V1,
            session: sample_session(),
            request_id: request_id(),
            accepted_sequence: 1,
            server_time_unix_ms: 1_700_000_000_000,
            poll_after_ms: 10_000,
            replay_status: FleetReplayStatus::Replayed,
            leases: Vec::new(),
        };
        assert_eq!(
            serde_json::to_string(&replayed).expect("serialize replay"),
            r#"{"protocol_version":1,"session":{"session_id":"550e8400-e29b-41d4-a716-446655440002","generation":1},"request_id":"550e8400-e29b-41d4-a716-446655440001","accepted_sequence":1,"server_time_unix_ms":1700000000000,"poll_after_ms":10000,"replay_status":"replayed","leases":[]}"#
        );

        for status in [
            FleetReplayStatus::ReceiptObsolete,
            FleetReplayStatus::SuspendedAcknowledgement,
        ] {
            let response = FleetPollResponse {
                replay_status: status,
                ..replayed.clone()
            };
            assert!(response.validate().is_ok());
            assert!(response.leases.is_empty());
        }

        let mut invalid_sanitized_response = replayed;
        invalid_sanitized_response.replay_status = FleetReplayStatus::ReceiptObsolete;
        invalid_sanitized_response.leases = vec![sample_lease_header(32)];
        assert!(invalid_sanitized_response.validate().is_err());

        let error = FleetErrorResponse {
            code: FleetErrorCode::SequenceGap,
            expected_sequence: Some(2),
            retry_after_ms: Some(1_000),
            supported_protocol: None,
        };
        assert_eq!(
            serde_json::to_string(&error).expect("serialize error"),
            r#"{"code":"SEQUENCE_GAP","expected_sequence":2,"retry_after_ms":1000,"supported_protocol":null}"#
        );
    }

    #[test]
    fn rejects_a_first_poll_without_session_after_sequence_one() {
        let mut request = sample_request();
        request.sequence = 2;

        assert!(request.validate().is_err());
    }

    #[test]
    fn rejects_conflicting_attempt_operations_when_job_identifiers_differ() {
        let mut request = sample_request();
        let renewal = sample_renewal(FleetUuid::new_v4());
        request.renewals.push(renewal.clone());
        request.releases.push(LeaseRelease {
            job_id: FleetToken::parse("job-2").expect("different job ID"),
            lease_id: renewal.lease_id,
            attempt_generation: renewal.attempt_generation,
        });

        assert!(request.validate().is_err());
    }

    #[test]
    fn rejects_invalid_or_irrelevant_error_guidance() {
        for error_json in [
            r#"{"code":"SEQUENCE_GAP","expected_sequence":0,"retry_after_ms":1000,"supported_protocol":null}"#,
            r#"{"code":"SEQUENCE_GAP","expected_sequence":null,"retry_after_ms":1000,"supported_protocol":null}"#,
            r#"{"code":"PROTOCOL_CONFLICT","expected_sequence":null,"retry_after_ms":null,"supported_protocol":{"min_version":0,"max_version":1}}"#,
            r#"{"code":"INTERNAL","expected_sequence":2,"retry_after_ms":null,"supported_protocol":null}"#,
        ] {
            assert!(from_json_no_duplicate_keys::<FleetErrorResponse>(error_json).is_err());
        }

        let valid_sequence_gap = r#"{"code":"SEQUENCE_GAP","expected_sequence":2,"retry_after_ms":1000,"supported_protocol":null}"#;
        assert!(from_json_no_duplicate_keys::<FleetErrorResponse>(valid_sequence_gap).is_ok());
    }

    #[test]
    fn redacts_attacker_controlled_json_values_from_decoder_errors() {
        let error_json = r#"{"code":"ATTACKER_CONTROLLED_VALUE","expected_sequence":null,"retry_after_ms":null,"supported_protocol":null}"#;

        let error = from_json_no_duplicate_keys::<FleetErrorResponse>(error_json)
            .expect_err("invalid enum must fail");

        assert_eq!(error.to_string(), "invalid fleet wire value");
        assert!(!format!("{error:?}").contains("ATTACKER_CONTROLLED_VALUE"));
    }

    #[test]
    fn decodes_unknown_fields_without_losing_known_request_and_response_values() {
        let mut request_value = serde_json::to_value(sample_request()).expect("request value");
        request_value["future_request_field"] = serde_json::json!({ "enabled": true });
        let request: FleetPollRequest = from_json_no_duplicate_keys(
            &serde_json::to_string(&request_value).expect("request JSON"),
        )
        .expect("unknown request field accepted");
        assert_eq!(request.sequence, 1);
        assert_eq!(request.capacity.revision, 1);

        let mut response_value = serde_json::to_value(sample_response()).expect("response value");
        response_value["future_response_field"] = serde_json::json!(true);
        let response: FleetPollResponse = from_json_no_duplicate_keys(
            &serde_json::to_string(&response_value).expect("response JSON"),
        )
        .expect("unknown response field accepted");
        assert_eq!(response.accepted_sequence, 1);
        assert_eq!(response.replay_status, FleetReplayStatus::Fresh);
    }

    #[test]
    fn rejects_duplicate_request_keys_before_typed_parsing_at_each_object_level() {
        let request_json = serde_json::to_string(&sample_request()).expect("request JSON");
        let top_known = request_json.replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":1", 1);
        let nested_known =
            request_json.replacen("\"revision\":1", "\"revision\":1,\"revision\":1", 1);
        let top_unknown = format!(
            "{},\"future\":true,\"future\":false}}",
            &request_json[..request_json.len() - 1]
        );
        let nested_unknown = request_json.replacen(
            "\"capacity\":{",
            "\"capacity\":{\"future\":true,\"future\":false,",
            1,
        );

        for duplicate_json in [top_known, nested_known, top_unknown, nested_unknown] {
            assert!(from_json_no_duplicate_keys::<FleetPollRequest>(&duplicate_json).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_response_keys_before_typed_parsing_at_each_object_level() {
        let response_json = serde_json::to_string(&sample_response()).expect("response JSON");
        let top_known = response_json.replacen(
            "\"accepted_sequence\":1",
            "\"accepted_sequence\":1,\"accepted_sequence\":1",
            1,
        );
        let nested_known =
            response_json.replacen("\"generation\":1", "\"generation\":1,\"generation\":1", 1);
        let top_unknown = format!(
            "{},\"future\":true,\"future\":false}}",
            &response_json[..response_json.len() - 1]
        );
        let nested_unknown = response_json.replacen(
            "\"session\":{",
            "\"session\":{\"future\":true,\"future\":false,",
            1,
        );
        let response_with_lease = serde_json::to_string(&FleetPollResponse {
            leases: vec![sample_lease_header(32)],
            ..sample_response()
        })
        .expect("response with lease JSON");
        let lease_known = response_with_lease.replacen(
            "\"payload_digest\":",
            "\"payload_digest\":[17],\"payload_digest\":",
            1,
        );
        let lease_unknown = response_with_lease.replacen(
            "\"payload_digest\":",
            "\"future\":true,\"future\":false,\"payload_digest\":",
            1,
        );

        for duplicate_json in [
            top_known,
            nested_known,
            top_unknown,
            nested_unknown,
            lease_known,
            lease_unknown,
        ] {
            assert!(from_json_no_duplicate_keys::<FleetPollResponse>(&duplicate_json).is_err());
        }
    }

    #[test]
    fn rejects_request_and_response_collection_limits_and_duplicate_set_members() {
        let mut too_many_contracts = sample_request();
        too_many_contracts.supported_contracts = (0..33)
            .map(|index| JobContract::new(format!("ne.test.{index}"), "v1").expect("contract"))
            .collect();
        assert!(too_many_contracts.validate().is_err());

        let mut too_many_reports = sample_request();
        too_many_reports.renewals = (0..65)
            .map(|_| sample_renewal(FleetUuid::new_v4()))
            .collect();
        assert!(too_many_reports.validate().is_err());

        let mut duplicate_contracts = sample_request();
        duplicate_contracts.supported_contracts = vec![
            JobContract::new("ne.test.contract", "v1").expect("contract"),
            JobContract::new("ne.test.contract", "v1").expect("contract"),
        ];
        assert!(duplicate_contracts.validate().is_err());

        let mut duplicate_profiles = sample_request();
        duplicate_profiles
            .capacity
            .profiles
            .push(ExecutionProfile::Standard);
        assert!(duplicate_profiles.validate().is_err());

        let mut duplicate_operations = sample_request();
        duplicate_operations
            .capacity
            .operations
            .push(WorkspaceOperation::Create);
        assert!(duplicate_operations.validate().is_err());

        let mut duplicate_attempt_operation = sample_request();
        let renewal = sample_renewal(FleetUuid::new_v4());
        duplicate_attempt_operation.renewals.push(renewal.clone());
        duplicate_attempt_operation.releases.push(LeaseRelease {
            job_id: renewal.job_id,
            lease_id: renewal.lease_id,
            attempt_generation: renewal.attempt_generation,
        });
        assert!(duplicate_attempt_operation.validate().is_err());

        let mut too_many_leases = sample_response();
        too_many_leases.leases = (0..17).map(|_| sample_lease_header(32)).collect();
        assert!(too_many_leases.validate().is_err());

        assert!(sample_lease_header(31).validate().is_err());
    }

    fn request_id() -> FleetUuid {
        FleetUuid::parse_canonical("550e8400-e29b-41d4-a716-446655440001").expect("request ID")
    }

    fn sample_session() -> FleetSession {
        FleetSession {
            session_id: FleetUuid::parse_canonical("550e8400-e29b-41d4-a716-446655440002")
                .expect("session ID"),
            generation: 1,
        }
    }

    fn sample_capacity() -> RunnerCapacity {
        RunnerCapacity {
            revision: 1,
            configured_workspace_ceiling: 10,
            registered_workspaces: 0,
            resident_workspaces: 0,
            runnable_workspaces: 0,
            allocated_cpu_millicores: 0,
            allocated_memory_bytes: 0,
            warm_pool_reserved_slots: 0,
            profiles: vec![ExecutionProfile::Standard],
            operations: vec![WorkspaceOperation::Create],
        }
    }

    fn sample_request() -> FleetPollRequest {
        FleetPollRequest {
            protocol: FleetProtocolRange::new(FLEET_PROTOCOL_V1, FLEET_PROTOCOL_V1)
                .expect("protocol range"),
            process_instance_id: FleetUuid::parse_canonical("550e8400-e29b-41d4-a716-446655440000")
                .expect("process ID"),
            session: None,
            request_id: request_id(),
            sequence: 1,
            capacity: sample_capacity(),
            supported_contracts: Vec::new(),
            renewals: Vec::new(),
            releases: Vec::new(),
            terminal_reports: Vec::new(),
        }
    }

    fn sample_renewal(lease_id: FleetUuid) -> LeaseRenewal {
        LeaseRenewal {
            job_id: FleetToken::parse("job-1").expect("job ID"),
            lease_id,
            attempt_generation: 1,
        }
    }

    fn sample_lease_header(digest_length: usize) -> LeaseHeader {
        LeaseHeader {
            job_id: FleetToken::parse("job-1").expect("job ID"),
            lease_id: FleetUuid::new_v4(),
            attempt_generation: 1,
            lease_expires_at_unix_ms: 1_700_000_030_000,
            contract: JobContract::new("ne.test.contract", "v1").expect("contract"),
            payload_digest: vec![17; digest_length],
        }
    }

    fn sample_response() -> FleetPollResponse {
        FleetPollResponse {
            protocol_version: FLEET_PROTOCOL_V1,
            session: sample_session(),
            request_id: request_id(),
            accepted_sequence: 1,
            server_time_unix_ms: 1_700_000_000_000,
            poll_after_ms: 10_000,
            replay_status: FleetReplayStatus::Fresh,
            leases: Vec::new(),
        }
    }
}

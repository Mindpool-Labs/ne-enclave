// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave attestation foundation.
//!
//! Provides the [`AttestationProvider`] trait, the shared [`Evidence`]
//! envelope (with a swappable [`Proof`]), the [`SoftwareProvider`]
//! software-fallback, and the pure [`verify`] function. Hardware backends
//! (SEV-SNP / TDX) implement the same trait and reuse the same envelope.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod snp_report;
pub mod snp_source;
pub mod tpm_attest;
pub mod vcek;

pub use snp_source::{
    AZURE_DEFAULT_AK_HANDLE, AZURE_HCL_IGVM_OFF, AZURE_HCL_REPORT_TYPE_SNP, AZURE_HCL_VAR_DATA_OFF,
    AZURE_HCLA_HEADER_LEN, AZURE_HCLA_NV_INDEX, SevSnpProvider, SnpReport, SnpReportSource,
    ak_modulus_from_jwk, extract_snp_report, extract_var_data, hcl_report_type,
    sha256_matches_report_data,
};
#[cfg(target_os = "linux")]
pub use snp_source::{AzureEvidence, AzureVtpmReportSource};
pub use tpm_attest::{TpmAttest, parse_tpm2b_attest};

use serde::{Deserialize, Serialize};

/// Canonical string encoding for a `u64` that crosses a JSON boundary.
///
/// # Why the SEV-SNP pins are strings
///
/// [`TrustAnchor::SevSnp::min_tcb`] is compared against the raw 64-bit AMD
/// `REPORTED_TCB` word, whose high byte is the microcode SVN, so production
/// values exceed 2^53. Any consumer that parses JSON numbers as IEEE-754
/// doubles — every JS and TS client — silently rounds them.
/// At that magnitude one unit in the last place spans 128, which covers the
/// whole low byte of the packed word, so two adjacent representable doubles
/// are *different security levels*. Encoding as a string removes the double
/// from the path for every consumer, in every language.
///
/// # Why the encoding is canonical and not merely lossless
///
/// `u64::from_str` accepts a leading `+` and leading zeros, so `"+5"`, `"05"`
/// and `"5"` all parse to the same integer. Within Rust that is harmless,
/// because the policy hash is computed over the *re-serialized* struct, which
/// normalises them. It is not harmless across implementations: a peer that
/// hashes the bytes it received — which is what `JSON.stringify` over a parsed
/// object does — derives a different policy identity for the same value, and
/// a policy hash is exactly the thing that must not have two spellings.
///
/// Deserialization therefore accepts only the canonical form: no sign, no
/// leading zeros. A JSON number is rejected outright rather than coerced,
/// because a producer still emitting numbers is the lossy path this encoding
/// exists to remove, and failing loudly is the point of a breaking change.
pub mod u64_str {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a `u64` as its canonical decimal string.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's `with` signature
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    /// Parse a canonical decimal string into a `u64`.
    ///
    /// # Errors
    ///
    /// Fails on a JSON number, on a non-canonical spelling (leading `+` or
    /// leading zeros), and on anything `u64::from_str` rejects.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let v: u64 = s.parse().map_err(serde::de::Error::custom)?;
        if v.to_string() == s {
            Ok(v)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected a canonical decimal string with no sign and no \
                 leading zeros, got {s:?}"
            )))
        }
    }
}

/// Which platform produced the evidence. Serialized as a stable
/// `snake_case` string so it survives the proto boundary and so an
/// attestation policy can branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProviderType {
    /// Ed25519-rooted software fallback. NOT firmware-rooted.
    Software,
    /// AMD SEV-SNP firmware-rooted host-CVM attestation.
    SevSnp,
}

/// 32-byte measurement of the workspace launch configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement(pub [u8; 32]);

/// Host-CVM launch digest (MEAS) from the SEV-SNP report — 48 bytes.
/// Deliberately a distinct type from the 32-byte per-workspace [`Measurement`]
/// so the two cannot be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvmMeasurement(#[serde(with = "b64_48")] pub [u8; 48]);

/// Caller-supplied challenge nonce, 16..=64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce(Vec<u8>);

impl Nonce {
    /// Construct a nonce, enforcing the 16..=64 byte length bound.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if (16..=64).contains(&bytes.len()) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Input to `AttestationProvider::generate`. The caller (supervisor)
/// supplies an already-computed measurement and a validated nonce.
#[derive(Debug, Clone)]
pub struct EvidenceRequest {
    /// Workspace identifier for which attestation is being generated.
    pub workspace_id: String,
    /// Measurement of the workspace launch configuration.
    pub measurement: Measurement,
    /// Caller-supplied challenge nonce.
    pub nonce: Nonce,
}

/// Provider-specific cryptographic proof over the report data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Proof {
    /// Ed25519 signature over the canonical report data, plus the
    /// signer's public key.
    Software {
        /// Ed25519 signature bytes (64 bytes, base64-encoded).
        #[serde(with = "b64_64")]
        signature: [u8; 64],
        /// Ed25519 public key of the signer (32 bytes, base64-encoded).
        #[serde(with = "b64_32")]
        signer_pubkey: [u8; 32],
    },
    /// AMD SEV-SNP firmware-signed report + the VCEK cert chain (DER) the
    /// supervisor fetched+cached and embedded so `verify()` stays pure/offline.
    /// This is the `/dev/sev-guest` ioctl path (GCP / bare-metal / AWS).
    SevSnp {
        /// Raw SEV-SNP firmware Attestation Report (base64-encoded).
        #[serde(with = "b64_vec")]
        report: Vec<u8>,
        /// Concatenated DER VCEK cert chain, leaf first (base64-encoded).
        #[serde(with = "b64_vec")]
        vcek_cert_chain: Vec<u8>,
    },
    /// Azure SEV-SNP (`OpenHCL` paravisor vTPM path) + the TPM-Quote binding.
    ///
    /// The boot-fixed AMD report (read via `tpm2_nvread`) + the VCEK chain +
    /// the `var_data` (the AK JWK) + the AK `TPM2B_PUBLIC` + the TPM Quote
    /// (message + RSASSA-PKCS1v1.5-SHA256 signature). The verify arm performs
    /// the 2-layer binding (spec v2 §3.4): L1 anchors the AK into the
    /// hardware-signed `REPORT_DATA`; L2 verifies the AK signature over the
    /// nonce-bearing quote. See `2026-06-29-azure-snp-vtpm-v2-design.md`.
    SevSnpAzure {
        /// Raw 1184-byte AMD SNP report (base64-encoded) — the `[0x20..0x4C0]`
        /// window of the HCLA blob.
        #[serde(with = "b64_vec")]
        report: Vec<u8>,
        /// Concatenated DER VCEK cert chain `[VCEK, ASK]` (base64-encoded).
        #[serde(with = "b64_vec")]
        vcek_cert_chain: Vec<u8>,
        /// The HCL `variable_data` (the JWK Set carrying the AK) — the Layer-1
        /// hash input: `SHA256(var_data) == report.REPORT_DATA[..32]`.
        #[serde(with = "b64_vec")]
        var_data: Vec<u8>,
        /// The AK `TPM2B_PUBLIC` (raw, `tpm2_readpublic -f tss`) — the Layer-2
        /// verifying key source.
        #[serde(with = "b64_vec")]
        ak_pub_tpm2b: Vec<u8>,
        /// The `TPM2B_ATTEST` the AK signed (`tpm2_quote -m`), embedding the
        /// qualifying-data nonce in `extraData`.
        #[serde(with = "b64_vec")]
        quote_msg: Vec<u8>,
        /// The RSASSA-PKCS1v1.5-SHA256 signature over `quote_msg` (base64-encoded).
        #[serde(with = "b64_vec")]
        quote_sig: Vec<u8>,
    },
}

/// The shared attestation evidence envelope. Every provider fills the
/// same fields; only [`Proof`] differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Which provider produced this evidence.
    pub provider_type: ProviderType,
    /// Workspace identifier.
    pub workspace_id: String,
    /// Measurement of the workspace launch configuration.
    pub measurement: Measurement,
    /// Caller-supplied challenge nonce (base64-encoded).
    #[serde(with = "b64_vec")]
    pub nonce: Vec<u8>,
    /// Unix timestamp (seconds) when the evidence was issued.
    pub issued_at: i64,
    /// The canonical report data that was signed (base64-encoded).
    #[serde(with = "b64_vec")]
    pub report_data: Vec<u8>,
    /// Provider-specific cryptographic proof.
    pub proof: Proof,
}

/// Build the canonical bytes that the proof signs/covers. Deterministic:
/// a sorted-key JSON object over the non-proof fields.
///
/// F3: the `ctx` tag `"ne-enclave-attestation-v1"` domain-separates these
/// signatures from audit-chain and snapshot-manifest signatures that may
/// share the same host key. It is stable — changing it would invalidate
/// all previously issued attestations.
#[must_use]
pub fn canonical_report_data(
    provider_type: ProviderType,
    req: &EvidenceRequest,
    issued_at: i64,
) -> Vec<u8> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "ctx",
        serde_json::Value::String("ne-enclave-attestation-v1".to_string()),
    );
    map.insert(
        "provider_type",
        serde_json::to_value(provider_type).unwrap_or(serde_json::Value::Null),
    );
    map.insert(
        "workspace_id",
        serde_json::Value::String(req.workspace_id.clone()),
    );
    map.insert(
        "measurement",
        serde_json::Value::String(hex::encode(req.measurement.0)),
    );
    map.insert(
        "nonce",
        serde_json::Value::String(hex::encode(req.nonce.as_bytes())),
    );
    map.insert(
        "issued_at",
        serde_json::Value::Number(serde_json::Number::from(issued_at)),
    );
    // INVARIANT: every value here is a String / hex String / i64 Number /
    // a ProviderType that serializes infallibly, so to_vec never errors in
    // practice. The empty-Vec fallback is a defensive floor; the signing
    // provider (SoftwareProvider::generate) MUST reject empty report_data as
    // an error rather than sign a predictable constant.
    serde_json::to_vec(&map).unwrap_or_default()
}

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Error generating attestation evidence.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The canonical report-data encoding produced an empty result.
    #[error("failed to encode report data")]
    CanonicalEncode,
    /// The signing operation failed (reserved for fallible providers,
    /// e.g. hardware TPM/SEV-SNP bindings where the key lives off-chip).
    #[error("signing failed")]
    Sign,
    /// Fetching the firmware attestation report failed (e.g. the `/dev/sev-guest`
    /// device is absent, or the response was short/garbled). Distinct from
    /// [`Self::Sign`], which is reserved for the cryptographic operation itself.
    #[error("failed to fetch firmware attestation report")]
    ReportFetch,
    /// The `/dev/sev-guest` `SNP_GET_REPORT` ioctl returned an error, with the
    /// firmware/VMM diagnostic detail (`exitinfo2` + the ioctl `errno`) preserved
    /// — the primary silicon-evidence diagnostic. Carries the detail so the crate
    /// stays logger-free; callers (supervisor / e2e) format/log it.
    #[error(
        "SNP_GET_REPORT ioctl failed (errno {errno}, fw_error {fw_error:#x}, vmm_error {vmm_error:#x})"
    )]
    ReportFetchIoctl {
        /// The `ioctl(2)` errno (e.g. `EIO`, `EINVAL`).
        errno: i32,
        /// SEV-SNP firmware error (`exitinfo2 [31:0]`).
        fw_error: u32,
        /// VMM/hypervisor error (`exitinfo2 [63:32]`).
        vmm_error: u32,
    },
    /// Fetching the VCEK certificate chain failed (transport or parse failure
    /// from the [`VcekFetcher`](crate::vcek::VcekFetcher)).
    #[error("failed to fetch VCEK certificate chain")]
    VcekFetch,
    /// A host-binary shell-out (the Azure vTPM report source: `tpm2`/`dd`)
    /// failed or produced no usable bytes. Carries the program alias + trimmed
    /// stderr so the supervisor / e2e can format the primary Azure evidence
    /// diagnostic. Distinct from [`Self::ReportFetchIoctl`] (the
    /// `/dev/sev-guest` errno path used by the GCP/bare-metal report source).
    #[error("report-fetch shell-out '{program}' failed: {stderr}")]
    ReportFetchShellout {
        /// The program alias that failed (e.g. `tpm2`, `dd`).
        program: &'static str,
        /// Trimmed stderr from the failed program (no secrets).
        stderr: String,
    },
}

/// A source of attestation evidence. Software now; SEV-SNP / TDX later
/// implement the same trait and return the same [`Evidence`] envelope.
pub trait AttestationProvider: Send + Sync + std::fmt::Debug {
    /// Returns the [`ProviderType`] this implementation represents.
    fn provider_type(&self) -> ProviderType;

    /// Generate attestation [`Evidence`] for `req`, timestamped at
    /// `issued_at` (Unix seconds).
    fn generate(&self, req: &EvidenceRequest, issued_at: i64)
    -> Result<Evidence, AttestationError>;
}

/// Ed25519-rooted software-fallback provider. The signing key is the
/// runtime instance's identity key (the same key that signs the audit
/// chain — see the spec's key-reuse decision).
pub struct SoftwareProvider {
    signing_key: SigningKey,
}

impl SoftwareProvider {
    /// Create a new [`SoftwareProvider`] from an Ed25519 `signing_key`.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

// Manual `Debug` redacts the signing key — the secret scalar must never
// reach a log line or panic message. Required because `AttestationProvider`
// carries a `Debug` supertrait so trait objects can live in `#[derive(Debug)]`
// structs (e.g. the supervisor's `WorkspaceManager`).
impl std::fmt::Debug for SoftwareProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareProvider")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl AttestationProvider for SoftwareProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Software
    }

    fn generate(
        &self,
        req: &EvidenceRequest,
        issued_at: i64,
    ) -> Result<Evidence, AttestationError> {
        let report_data = canonical_report_data(ProviderType::Software, req, issued_at);
        if report_data.is_empty() {
            return Err(AttestationError::CanonicalEncode);
        }
        let signature = self.signing_key.sign(&report_data);
        Ok(Evidence {
            provider_type: ProviderType::Software,
            workspace_id: req.workspace_id.clone(),
            measurement: req.measurement,
            nonce: req.nonce.as_bytes().to_vec(),
            issued_at,
            report_data,
            proof: Proof::Software {
                signature: signature.to_bytes(),
                signer_pubkey: self.signing_key.verifying_key().to_bytes(),
            },
        })
    }
}

/// Why verification failed (for events/logs; never carries secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailReason {
    /// The evidence's [`ProviderType`] is not in the allowed set.
    ProviderTypeNotAccepted,
    /// The nonce in the evidence does not match the expected nonce.
    NonceMismatch,
    /// The measurement in the evidence does not match the expected value.
    MeasurementMismatch,
    /// The evidence was issued outside the freshness window.
    Stale,
    /// The cryptographic signature is invalid or the report data was tampered.
    BadSignature,
    /// The proof or nonce bytes are structurally malformed.
    MalformedProof,
    /// Evidence was signed by a key other than the caller-pinned trust anchor.
    ///
    /// F1: the embedded `signer_pubkey` in the (attacker-supplied) evidence
    /// did not match `TrustAnchor::Software::expected_signer`. The signature
    /// is never checked against an untrusted key.
    UntrustedSigner,
    /// The top-level `provider_type` disagrees with the proof variant.
    ///
    /// F2: forward-binding guard so that when SEV-SNP / TDX variants land a
    /// cross-wired envelope is caught before reaching cryptographic checks.
    ProviderProofMismatch,
    /// SEV-SNP: `SHA-512(report_data)` did not match the report's `REPORT_DATA`.
    ReportDataMismatch,
    /// SEV-SNP: the VCEK cert chain did not validate to the AMD root, or the
    /// firmware signature over the report did not verify under the VCEK key.
    BadCertChain,
    /// SEV-SNP: a reference-value policy pin (TCB / `guest_policy`) was not met.
    PolicyMismatch,
    /// Azure SEV-SNP: the TPM Quote Layer-2 binding failed — the AK signature did
    /// not verify, the embedded nonce did not match, or the quote was malformed.
    /// See spec v2 §3.4.
    TpmQuoteInvalid,
}

/// Result of [`verify`]. Pure — replay is the caller's concern, not an
/// outcome here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// All checks passed; the evidence is valid.
    Verified,
    /// At least one check failed; the reason is included.
    Failed(FailReason),
}

/// Caller-pinned trust anchor.
///
/// The variant MUST match the evidence's provider/proof variant; a mismatch
/// is `ProviderProofMismatch`. This preserves F1 (caller-pinned, never taken
/// from evidence) for every tier: Software pins an Ed25519 key; hardware
/// tiers will pin a vendor root.
#[non_exhaustive]
pub enum TrustAnchor<'a> {
    /// Ed25519 software-tier anchor.
    Software {
        /// Out-of-band runtime identity key (NOT taken from the evidence).
        expected_signer: &'a VerifyingKey,
    },
    /// AMD SEV-SNP firmware-tier anchor.
    SevSnp {
        /// AMD product (ARK) root certificate the caller trusts out-of-band.
        amd_product_root: &'a vcek::AmdRootCert,
        /// Optional policy-pin on the host-CVM launch digest (MEAS) in the report.
        expected_host_cvm_meas: Option<&'a CvmMeasurement>,
        /// Minimum accepted `reported_tcb`.
        min_tcb: u64,
        /// Required guest-policy bits.
        guest_policy: u64,
    },
}

/// Verification policy passed to [`verify`].
pub struct VerifyParams<'a> {
    /// The nonce the caller expects to find in the evidence.
    pub expected_nonce: &'a Nonce,
    /// Optional per-workspace measurement the caller expects; `None` skips.
    pub expected_measurement: Option<&'a Measurement>,
    /// Set of [`ProviderType`] values the caller will accept.
    pub accept_provider_types: &'a [ProviderType],
    /// Maximum age of the evidence (applied symmetrically around `now`).
    pub freshness: std::time::Duration,
    /// Current Unix timestamp (seconds) used for freshness evaluation.
    pub now: i64,
    /// Caller-pinned trust anchor (replaces the old `expected_signer`).
    pub trust_anchor: TrustAnchor<'a>,
}

/// Verify an [`Evidence`] envelope against `params`. Pure function;
/// never panics. For `Software`, checks the Ed25519 signature, nonce,
/// optional measurement, provider-type acceptability, and freshness.
///
/// Security: recomputes the canonical report data from the envelope's
/// structured fields and requires it to match the stored `report_data`
/// before checking the signature, so a tampered field cannot pass even
/// though the stored bytes and signature are internally consistent.
///
/// F1: the signature is verified against the caller-pinned
/// `TrustAnchor` (see [`VerifyParams::trust_anchor`]), not against the
/// key embedded in the (untrusted) evidence. Evidence embedding a
/// different key is rejected with [`FailReason::UntrustedSigner`] before
/// any cryptographic check.
#[must_use]
pub fn verify(ev: &Evidence, params: &VerifyParams<'_>) -> VerifyOutcome {
    if !params.accept_provider_types.contains(&ev.provider_type) {
        return VerifyOutcome::Failed(FailReason::ProviderTypeNotAccepted);
    }
    if ev.nonce != params.expected_nonce.as_bytes() {
        return VerifyOutcome::Failed(FailReason::NonceMismatch);
    }
    if let Some(m) = params.expected_measurement
        && ev.measurement != *m
    {
        return VerifyOutcome::Failed(FailReason::MeasurementMismatch);
    }
    let freshness = i64::try_from(params.freshness.as_secs()).unwrap_or(i64::MAX);
    if params.now.saturating_sub(ev.issued_at).saturating_abs() > freshness {
        return VerifyOutcome::Failed(FailReason::Stale);
    }
    let Some(nonce) = Nonce::new(ev.nonce.clone()) else {
        return VerifyOutcome::Failed(FailReason::MalformedProof);
    };
    let recomputed = canonical_report_data(
        ev.provider_type,
        &EvidenceRequest {
            workspace_id: ev.workspace_id.clone(),
            measurement: ev.measurement,
            nonce,
        },
        ev.issued_at,
    );
    if recomputed != ev.report_data {
        return VerifyOutcome::Failed(FailReason::BadSignature);
    }
    match &ev.proof {
        Proof::Software {
            signature,
            signer_pubkey,
        } => {
            // F2: bind provider_type to the proof variant.
            if ev.provider_type != ProviderType::Software {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            }
            // Anchor agreement: the caller-pinned anchor must match the
            // proof variant (F1 — caller-pinned, never taken from evidence).
            let TrustAnchor::Software { expected_signer } = &params.trust_anchor else {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            };
            // F1: pin to the caller's trust anchor. The embedded key is
            // only a consistency hint; the signature is checked against
            // the caller-pinned expected_signer, never against a key
            // carried in the (untrusted) evidence.
            if signer_pubkey != expected_signer.as_bytes() {
                return VerifyOutcome::Failed(FailReason::UntrustedSigner);
            }
            let sig = Signature::from_bytes(signature);
            match expected_signer.verify_strict(&ev.report_data, &sig) {
                Ok(()) => VerifyOutcome::Verified,
                Err(_) => VerifyOutcome::Failed(FailReason::BadSignature),
            }
        }
        Proof::SevSnp {
            report,
            vcek_cert_chain,
        } => {
            use sha2::Digest;
            // F2: per-arm provider_type binding.
            if ev.provider_type != ProviderType::SevSnp {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            }
            // Anchor agreement: only a SevSnp anchor is valid for a SevSnp
            // proof. The policy also binds the remaining fields (MEAS / min_tcb /
            // guest_policy) so the reference-value pins below can enforce them.
            let TrustAnchor::SevSnp {
                amd_product_root,
                expected_host_cvm_meas,
                min_tcb,
                guest_policy,
            } = &params.trust_anchor
            else {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            };
            let Some(fields) = snp_report::parse(report) else {
                return VerifyOutcome::Failed(FailReason::MalformedProof);
            };
            // Binding: SHA-512 of the canonical report_data must equal the
            // firmware-stamped REPORT_DATA. This ties the SNP report to the
            // envelope's structured fields (and through them to the nonce /
            // measurement / workspace_id checked above).
            let mut h = sha2::Sha512::new();
            h.update(&ev.report_data);
            let digest: [u8; 64] = h.finalize().into();
            if digest != fields.report_data {
                return VerifyOutcome::Failed(FailReason::ReportDataMismatch);
            }
            // Firmware chain + signature (pure, offline). The pins run
            // AFTER chain-success and BEFORE the `Verified` return, so a
            // cryptographically valid report can still be refused on policy.
            // The chain-error mapping (BadSignature→BadSignature, other
            // VcekError→BadCertChain) is preserved verbatim.
            match vcek::verify_report(report, vcek_cert_chain, amd_product_root) {
                Ok(()) => {
                    // Reference-value pin: reported TCB must meet the floor.
                    if fields.reported_tcb < *min_tcb {
                        return VerifyOutcome::Failed(FailReason::PolicyMismatch);
                    }
                    // Reference-value pin: all required guest-policy bits set.
                    if (fields.guest_policy & guest_policy) != *guest_policy {
                        return VerifyOutcome::Failed(FailReason::PolicyMismatch);
                    }
                    // Reference-value pin: optional host-CVM launch digest.
                    if let Some(expected) = expected_host_cvm_meas
                        && fields.measurement != expected.0
                    {
                        return VerifyOutcome::Failed(FailReason::MeasurementMismatch);
                    }
                    VerifyOutcome::Verified
                }
                Err(vcek::VcekError::BadSignature) => {
                    VerifyOutcome::Failed(FailReason::BadSignature)
                }
                Err(_) => VerifyOutcome::Failed(FailReason::BadCertChain),
            }
        }
        Proof::SevSnpAzure {
            report,
            vcek_cert_chain,
            var_data,
            ak_pub_tpm2b,
            quote_msg,
            quote_sig,
        } => {
            use sha2::Digest;
            // F2: per-arm provider_type binding (same guard as the ioctl arm).
            if ev.provider_type != ProviderType::SevSnp {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            }
            // Anchor agreement: only a SevSnp anchor is valid (same as SevSnp).
            let TrustAnchor::SevSnp {
                amd_product_root,
                expected_host_cvm_meas,
                min_tcb,
                guest_policy,
            } = &params.trust_anchor
            else {
                return VerifyOutcome::Failed(FailReason::ProviderProofMismatch);
            };
            let Some(fields) = snp_report::parse(report) else {
                return VerifyOutcome::Failed(FailReason::MalformedProof);
            };

            // ===== Layer 1: hardware anchoring (the boot-fixed report) =====
            // L1c: the AK (in var_data) is bound into the hardware-signed report
            // via REPORT_DATA[..32] == SHA256(var_data). The paravisor stamps this
            // at boot; bytes [32..] must be zero (Milan/Azure convention). This
            // replaces the ioctl arm's SHA-512(canonical) binding — on Azure the
            // report is boot-fixed, so the binding is to the AK, not our nonce.
            if !sha256_matches_report_data(var_data, &fields.report_data) {
                return VerifyOutcome::Failed(FailReason::ReportDataMismatch);
            }
            // REPORT_DATA[32..] must be zero (the paravisor only fills [..32]).
            if fields.report_data.iter().skip(32).any(|&b| b != 0) {
                return VerifyOutcome::Failed(FailReason::MalformedProof);
            }
            // L1a: firmware chain + signature (reused verbatim from the SevSnp arm).
            match vcek::verify_report(report, vcek_cert_chain, amd_product_root) {
                Ok(()) => {
                    // Policy pins (identical to the SevSnp arm).
                    if fields.reported_tcb < *min_tcb {
                        return VerifyOutcome::Failed(FailReason::PolicyMismatch);
                    }
                    if (fields.guest_policy & guest_policy) != *guest_policy {
                        return VerifyOutcome::Failed(FailReason::PolicyMismatch);
                    }
                    if let Some(expected) = expected_host_cvm_meas
                        && fields.measurement != expected.0
                    {
                        return VerifyOutcome::Failed(FailReason::MeasurementMismatch);
                    }
                }
                Err(vcek::VcekError::BadSignature) => {
                    return VerifyOutcome::Failed(FailReason::BadSignature);
                }
                Err(_) => return VerifyOutcome::Failed(FailReason::BadCertChain),
            }

            // ===== Layer 2: freshness + nonce binding (the TPM Quote) =====
            // L2a: the AK whose signature we verify must be the one anchored in
            // var_data. Re-derive the modulus from the JWK + from the TPM2B_PUBLIC
            // and assert they agree (a forged ak_pub_tpm2b that doesn't match the
            // anchored AK fails here).
            let Some(var_data_modulus) = ak_modulus_from_jwk(var_data) else {
                return VerifyOutcome::Failed(FailReason::MalformedProof);
            };
            let Ok(tpm2b_modulus) = azure_ak_rsa_modulus(ak_pub_tpm2b) else {
                return VerifyOutcome::Failed(FailReason::MalformedProof);
            };
            if var_data_modulus.as_slice() != tpm2b_modulus {
                return VerifyOutcome::Failed(FailReason::ReportDataMismatch);
            }
            // L2b: parse the TPM2B_ATTEST + assert the embedded qualifying-data
            // nonce == SHA256(canonical_report_data) — the per-request binding.
            let Some(attest) = parse_tpm2b_attest(quote_msg) else {
                return VerifyOutcome::Failed(FailReason::TpmQuoteInvalid);
            };
            let expected_nonce = sha2::Sha256::digest(&ev.report_data);
            if attest.extra_data != expected_nonce.as_slice() {
                return VerifyOutcome::Failed(FailReason::TpmQuoteInvalid);
            }
            // L2c: verify the AK RSASSA-PKCS1v1.5-SHA256 signature over the quote
            // message under the anchored AK. `rsa::pkcs1v15` is already a workspace
            // dep (used for ARK/ASK PSS verify); ring is NOT used.
            if !verify_ak_rsassa_sha256(&tpm2b_modulus, quote_msg, quote_sig) {
                return VerifyOutcome::Failed(FailReason::TpmQuoteInvalid);
            }
            VerifyOutcome::Verified
        }
    }
}

// ---------------------------------------------------------------------------
// Azure TPM-Quote helpers (Layer 2 of the SevSnpAzure verify arm).
// Pure; no cfg gate (must compile to WASM for the control-plane gate). These
// reach into the TPM2B_PUBLIC marshaled form + the rsa crate (already a dep).
// ---------------------------------------------------------------------------

/// The TPM algorithm id for RSA (`TPM_ALG_RSA == 0x0001`). A `TPM2B_PUBLIC` whose
/// `type` field is this describes an RSA key.
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_SHA256: u16 = 0x000B;

/// Azure AK `TPM2B_PUBLIC` parsing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid Azure AK TPM2B_PUBLIC")]
pub struct AttestationParseError;

/// Extract the canonical 256-byte RSA-2048 modulus from one exact Azure AK
/// `TPM2B_PUBLIC` public area.
///
/// # Errors
///
/// Returns [`AttestationParseError`] for malformed, non-RSA, non-2048-bit,
/// truncated, or trailing input.
pub fn azure_ak_rsa_modulus(ak_pub_tpm2b: &[u8]) -> Result<[u8; 256], AttestationParseError> {
    fn read_u16(input: &[u8], offset: &mut usize) -> Result<u16, AttestationParseError> {
        let end = offset.checked_add(2).ok_or(AttestationParseError)?;
        let bytes: [u8; 2] = input
            .get(*offset..end)
            .ok_or(AttestationParseError)?
            .try_into()
            .map_err(|_| AttestationParseError)?;
        *offset = end;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32, AttestationParseError> {
        let end = offset.checked_add(4).ok_or(AttestationParseError)?;
        let bytes: [u8; 4] = input
            .get(*offset..end)
            .ok_or(AttestationParseError)?
            .try_into()
            .map_err(|_| AttestationParseError)?;
        *offset = end;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_bytes<'a>(
        input: &'a [u8],
        offset: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], AttestationParseError> {
        let end = offset.checked_add(len).ok_or(AttestationParseError)?;
        let bytes = input.get(*offset..end).ok_or(AttestationParseError)?;
        *offset = end;
        Ok(bytes)
    }

    let declared_len = u16::from_be_bytes(
        ak_pub_tpm2b
            .get(..2)
            .ok_or(AttestationParseError)?
            .try_into()
            .map_err(|_| AttestationParseError)?,
    ) as usize;
    let body = ak_pub_tpm2b.get(2..).ok_or(AttestationParseError)?;
    if body.len() != declared_len {
        return Err(AttestationParseError);
    }

    let mut offset = 0;
    if read_u16(body, &mut offset)? != TPM_ALG_RSA {
        return Err(AttestationParseError);
    }
    let _name_alg = read_u16(body, &mut offset)?;
    let _object_attributes = read_u32(body, &mut offset)?;
    let auth_policy_len = usize::from(read_u16(body, &mut offset)?);
    let _auth_policy = read_bytes(body, &mut offset, auth_policy_len)?;
    if read_u16(body, &mut offset)? != TPM_ALG_NULL {
        return Err(AttestationParseError);
    }
    if read_u16(body, &mut offset)? != TPM_ALG_RSASSA
        || read_u16(body, &mut offset)? != TPM_ALG_SHA256
    {
        return Err(AttestationParseError);
    }
    if read_u16(body, &mut offset)? != 2048 {
        return Err(AttestationParseError);
    }
    let exponent = read_u32(body, &mut offset)?;
    if exponent != 0 && exponent != 65_537 {
        return Err(AttestationParseError);
    }
    if read_u16(body, &mut offset)? != 256 {
        return Err(AttestationParseError);
    }
    let modulus: [u8; 256] = read_bytes(body, &mut offset, 256)?
        .try_into()
        .map_err(|_| AttestationParseError)?;
    if offset != body.len() {
        return Err(AttestationParseError);
    }
    Ok(modulus)
}

/// Verify an AK RSASSA-PKCS1-v1.5-SHA256 signature over a message, given the
/// AK modulus (big-endian). `quote_sig` is the raw RSA signature (256 bytes for
/// RSA-2048). The exponent is the TPM default 65537 (the Azure AK does not set
/// a custom exponent — confirmed on-box). Returns `false` on any verification
/// failure or a malformed key/signature (fail-closed). Pure.
///
/// Uses `rsa::pkcs1v15::VerifyingKey::<Sha256>` — the `rsa` crate is already a
/// `ne-attestation` dep (`Cargo.toml:42`, for ARK/ASK PSS verify); `ring` is
/// NOT used. Compiles to WASM.
fn verify_ak_rsassa_sha256(modulus_be: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    // TPM RSA keys use the default public exponent 65537 unless set otherwise
    // (the Azure AK's exponent field is empty → 65537).
    let n = rsa::BigUint::from_bytes_be(modulus_be);
    // Build the RSA public key directly from modulus + exponent. `new` checks
    // the modulus is a valid RSA modulus (rejects obviously-forged keys).
    let Ok(pubkey) = rsa::RsaPublicKey::new(n, rsa::BigUint::from(65_537u32)) else {
        return false;
    };
    let vk = VerifyingKey::<sha2::Sha256>::new(pubkey);
    // `tpm2_quote -s` writes a TPMT_SIGNATURE: [scheme alg(u16), hashAlg(u16),
    // sigLen(u16), <sig bytes>]. Strip the 6-byte header to get the raw RSA
    // signature (256 bytes for RSA-2048). The on-box capture confirms this layout.
    let raw_sig = strip_tpmt_signature_header(sig);
    let Ok(signature) = Signature::try_from(raw_sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

/// Strip the `TPMT_SIGNATURE` marshaled header that `tpm2_quote -s` emits, to
/// recover the raw RSA signature bytes. The header is `[alg(u16 BE), hashAlg(u16
/// BE), sigLen(u16 BE)]` followed by the signature. Returns the signature slice
/// on match, or the input as-is if it's already a raw signature (no header).
fn strip_tpmt_signature_header(sig: &[u8]) -> &[u8] {
    // A TPMT_SIGNATURE for RSASSA-SHA256 starts with 0x0014 (rsassa) 0x000b (sha256),
    // then a u16 sig length, then the sig bytes. If the input matches this shape,
    // return the trailing sig bytes; otherwise return the input verbatim (a raw sig).
    const RSASSA: [u8; 2] = 0x0014u16.to_be_bytes();
    const SHA256: [u8; 2] = 0x000Bu16.to_be_bytes();
    if sig.len() >= 6 && sig[0..2] == RSASSA && sig[2..4] == SHA256 {
        let inner_len = u16::from_be_bytes([sig[4], sig[5]]) as usize;
        // The raw signature follows the 6-byte header.
        if 6 + inner_len <= sig.len() {
            return &sig[6..6 + inner_len];
        }
    }
    sig
}

/// Whether the software-fallback provider may be the active provider.
///
/// In dev mode it is always allowed. Outside dev mode it is refused
/// unless the operator explicitly opted in (the
/// `NE_ATTEST_ALLOW_SOFTWARE` env var), mirroring how
/// `NE_DEV_MODE` gates non-localhost auth. Callers that get `false`
/// must fail closed (refuse to start) rather than silently issuing
/// software evidence in production.
#[must_use]
pub fn software_provider_allowed(dev_mode: bool, allow_software_env: bool) -> bool {
    dev_mode || allow_software_env
}

#[allow(unreachable_pub)]
mod b64_vec {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[allow(unreachable_pub)]
mod b64_64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[allow(unreachable_pub)]
mod b64_32 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[allow(unreachable_pub)]
mod b64_48 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 48 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample_request() -> EvidenceRequest {
        EvidenceRequest {
            workspace_id: "ws-1".to_string(),
            measurement: Measurement([7u8; 32]),
            nonce: Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).unwrap(),
        }
    }

    #[test]
    fn canonical_report_data_is_deterministic() {
        let req = sample_request();
        let issued_at = 1_700_000_000i64;
        let a = canonical_report_data(ProviderType::Software, &req, issued_at);
        let b = canonical_report_data(ProviderType::Software, &req, issued_at);
        assert_eq!(
            a, b,
            "canonical encoding must be byte-identical for equal inputs"
        );
        assert!(!a.is_empty());
    }

    #[test]
    fn nonce_rejects_out_of_range_lengths() {
        assert!(Nonce::new(vec![0u8; 15]).is_none(), "15 bytes < 16 min");
        assert!(Nonce::new(vec![0u8; 16]).is_some());
        assert!(Nonce::new(vec![0u8; 64]).is_some());
        assert!(Nonce::new(vec![0u8; 65]).is_none(), "65 bytes > 64 max");
    }

    #[test]
    fn software_provider_generates_verifiable_evidence() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let provider = SoftwareProvider::new(sk);
        assert_eq!(provider.provider_type(), ProviderType::Software);

        let req = sample_request();
        let ev = provider.generate(&req, 1_700_000_000).expect("generate");
        assert_eq!(ev.provider_type, ProviderType::Software);
        assert_eq!(ev.workspace_id, "ws-1");
        assert_eq!(ev.measurement, req.measurement);
        assert_eq!(ev.nonce, req.nonce.as_bytes());
        match ev.proof {
            Proof::Software { signer_pubkey, .. } => {
                assert_eq!(
                    signer_pubkey,
                    SigningKey::from_bytes(&[3u8; 32])
                        .verifying_key()
                        .to_bytes()
                );
            }
            Proof::SevSnp { .. } | Proof::SevSnpAzure { .. } => panic!("expected software proof"),
        }
    }

    /// Returns `(evidence, nonce, verifying_key)` — all signed by `[9u8; 32]`.
    fn fresh_evidence() -> (Evidence, Nonce, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let provider = SoftwareProvider::new(sk);
        let req = sample_request();
        let nonce = req.nonce.clone();
        (provider.generate(&req, 1_700_000_000).unwrap(), nonce, vk)
    }

    fn params<'a>(
        nonce: &'a Nonce,
        now: i64,
        expected_signer: &'a VerifyingKey,
    ) -> VerifyParams<'a> {
        VerifyParams {
            expected_nonce: nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::Software],
            freshness: std::time::Duration::from_secs(300),
            now,
            trust_anchor: TrustAnchor::Software { expected_signer },
        }
    }

    #[test]
    fn verify_accepts_fresh_valid_evidence() {
        let (ev, nonce, vk) = fresh_evidence();
        assert!(matches!(
            verify(&ev, &params(&nonce, 1_700_000_010, &vk)),
            VerifyOutcome::Verified
        ));
    }

    #[test]
    fn verify_rejects_tampered_workspace_id() {
        let (mut ev, nonce, vk) = fresh_evidence();
        ev.workspace_id = "ws-evil".to_string();
        assert!(matches!(
            verify(&ev, &params(&nonce, 1_700_000_010, &vk)),
            VerifyOutcome::Failed(_)
        ));
    }

    #[test]
    fn verify_rejects_wrong_nonce() {
        let (ev, _nonce, vk) = fresh_evidence();
        let other = Nonce::new(vec![42u8; 16]).unwrap();
        assert!(matches!(
            verify(&ev, &params(&other, 1_700_000_010, &vk)),
            VerifyOutcome::Failed(_)
        ));
    }

    #[test]
    fn verify_rejects_stale_issued_at() {
        let (ev, nonce, vk) = fresh_evidence();
        assert!(matches!(
            verify(&ev, &params(&nonce, 1_700_000_600, &vk)),
            VerifyOutcome::Failed(_)
        ));
    }

    #[test]
    fn verify_rejects_disallowed_provider_type() {
        let (ev, nonce, vk) = fresh_evidence();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_010,
            trust_anchor: TrustAnchor::Software {
                expected_signer: &vk,
            },
        };
        assert!(matches!(verify(&ev, &p), VerifyOutcome::Failed(_)));
    }

    #[test]
    fn verify_checks_optional_measurement() {
        let (ev, nonce, vk) = fresh_evidence();
        let wrong = Measurement([0u8; 32]);
        let p = VerifyParams {
            expected_measurement: Some(&wrong),
            ..params(&nonce, 1_700_000_010, &vk)
        };
        assert!(matches!(verify(&ev, &p), VerifyOutcome::Failed(_)));
    }

    #[test]
    fn verify_rejects_extreme_issued_at_without_panic() {
        let (mut ev, nonce, vk) = fresh_evidence();
        ev.issued_at = i64::MIN;
        assert!(matches!(
            verify(&ev, &params(&nonce, 1_700_000_010, &vk)),
            VerifyOutcome::Failed(_)
        ));
    }

    #[test]
    fn verify_rejects_corrupt_signature_with_valid_structure() {
        // Valid evidence whose report_data still matches its fields (so the
        // recompute check passes), but with a flipped signature byte — this
        // is the only case that actually drives the Ed25519 verify() failure.
        let (mut ev, nonce, vk) = fresh_evidence();
        let Proof::Software { signature, .. } = &mut ev.proof else {
            panic!("expected software proof");
        };
        signature[0] ^= 0x01;
        assert_eq!(
            verify(&ev, &params(&nonce, 1_700_000_010, &vk)),
            VerifyOutcome::Failed(FailReason::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_mismatched_embedded_key() {
        // Evidence where the embedded signer_pubkey was swapped to a different
        // (well-formed) key. With F1, this hits UntrustedSigner before reaching
        // the Ed25519 path. The [0u8;32] identity point is NOT a valid compressed
        // Ed25519 point, so this exercises the pin-check short-circuit rather than
        // the from_bytes structural guard (which no longer runs in the normal path).
        let (mut ev, nonce, vk) = fresh_evidence();
        let Proof::Software { signer_pubkey, .. } = &mut ev.proof else {
            panic!("expected software proof");
        };
        *signer_pubkey = [0u8; 32];
        let outcome = verify(&ev, &params(&nonce, 1_700_000_010, &vk));
        assert!(
            matches!(outcome, VerifyOutcome::Failed(FailReason::UntrustedSigner)),
            "expected UntrustedSigner, got {outcome:?}"
        );
    }

    #[test]
    fn verify_rejects_evidence_signed_by_untrusted_key() {
        // Evidence minted by an attacker key, verified against the trusted anchor.
        let attacker = SigningKey::from_bytes(&[0xAB; 32]);
        let provider = SoftwareProvider::new(attacker);
        let req = sample_request();
        let nonce = req.nonce.clone();
        let ev = provider.generate(&req, 1_700_000_000).unwrap();
        let trusted = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::Software],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_010,
            trust_anchor: TrustAnchor::Software {
                expected_signer: &trusted,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::UntrustedSigner)
        );
    }

    #[test]
    fn software_gate_matrix() {
        // dev mode: always allowed
        assert!(software_provider_allowed(true, false));
        assert!(software_provider_allowed(true, true));
        // prod (non-dev): only with explicit opt-in env
        assert!(!software_provider_allowed(false, false));
        assert!(software_provider_allowed(false, true));
    }

    // ---- SEV-SNP verify arm -----------------------------------------------

    use crate::vcek::test_support::{self, SyntheticChain};

    /// Concatenate the synthetic chain leaf-first as `[VCEK, ASK]` — the shape
    /// `verify_report` walks (VCEK → ASK → ARK root). Mirrors what
    /// `KdsVcekFetcher::fetch` returns in production (`[VCEK, AMD_MILAN_ASK_DER]`).
    fn chain_with_ask(sc: &SyntheticChain) -> Vec<u8> {
        [sc.vcek_leaf_der.as_slice(), sc.ask_der.as_slice()].concat()
    }

    fn sev_snp_evidence_with_report(report: Vec<u8>, chain_der: Vec<u8>) -> Evidence {
        // report_data is the canonical recompute of the structured fields so the
        // uniform pre-check (tamper check) passes and execution reaches the
        // SevSnp arm. The arm then binds SHA-512(report_data) to the report's
        // REPORT_DATA, which each test sets independently.
        let report_data = canonical_report_data(
            ProviderType::SevSnp,
            &EvidenceRequest {
                workspace_id: "ws".into(),
                measurement: Measurement([0u8; 32]),
                nonce: Nonce::new(vec![1u8; 16]).unwrap(),
            },
            1_700_000_000,
        );
        Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws".into(),
            measurement: Measurement([0u8; 32]),
            nonce: vec![1u8; 16],
            issued_at: 1_700_000_000,
            report_data,
            proof: Proof::SevSnp {
                report,
                vcek_cert_chain: chain_der,
            },
        }
    }

    #[test]
    fn sev_snp_rejects_software_anchor_mismatch() {
        // SevSnp evidence + Software anchor -> ProviderProofMismatch.
        let ev = sev_snp_evidence_with_report(vec![0u8; snp_report::REPORT_SIZE], Vec::new());
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let vk = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::Software {
                expected_signer: &vk,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::ProviderProofMismatch)
        );
    }

    #[test]
    fn sev_snp_rejects_report_data_mismatch() {
        let sc = test_support::synthetic_chain();
        let mut report = vec![0u8; snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&[0x55u8; 64]); // report's REPORT_DATA
        test_support::sign_report(&mut report, &sc.vcek_signing_key);
        // ev.report_data is the canonical bytes (passes recompute), but its
        // SHA-512 != the report's [0x55;64] REPORT_DATA. Pass a chain-valid
        // bundle so the only failure is the report-data binding.
        let ev = sev_snp_evidence_with_report(report, chain_with_ask(&sc));
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &sc.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::ReportDataMismatch)
        );
    }

    #[test]
    fn sev_snp_verifies_synthetic_chain() {
        use sha2::Digest;
        let sc = test_support::synthetic_chain();
        // Stamp the report's REPORT_DATA with SHA-512 of the canonical bytes,
        // so the arm's binding (SHA-512(report_data) == REPORT_DATA) holds.
        let canonical = canonical_report_data(
            ProviderType::SevSnp,
            &EvidenceRequest {
                workspace_id: "ws".into(),
                measurement: Measurement([0u8; 32]),
                nonce: Nonce::new(vec![1u8; 16]).unwrap(),
            },
            1_700_000_000,
        );
        let mut h = sha2::Sha512::new();
        h.update(&canonical);
        let rd64: [u8; 64] = h.finalize().into();
        let mut report = vec![0u8; snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&rd64);
        test_support::sign_report(&mut report, &sc.vcek_signing_key);
        let ev = sev_snp_evidence_with_report(report, chain_with_ask(&sc));
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &sc.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(verify(&ev, &p), VerifyOutcome::Verified);
    }

    // ---- SEV-SNP reference-value policy pins ------------------------------

    /// Builds SEV-SNP evidence that passes every check up to AND INCLUDING the
    /// VCEK chain+signature, with all policy-relevant report fields at their
    /// default (zero) values: `reported_tcb = 0`, `guest_policy = 0`,
    /// `measurement = [0; 48]`. Each policy test borrows the returned
    /// [`SyntheticChain`] (for `root`) and flips exactly one anchor pin so the
    /// failure is attributable to that pin alone.
    fn sev_snp_chain_ok_evidence() -> (Evidence, Nonce, SyntheticChain) {
        use sha2::Digest;
        let chain = test_support::synthetic_chain();
        let canonical = canonical_report_data(
            ProviderType::SevSnp,
            &EvidenceRequest {
                workspace_id: "ws".into(),
                measurement: Measurement([0u8; 32]),
                nonce: Nonce::new(vec![1u8; 16]).unwrap(),
            },
            1_700_000_000,
        );
        let mut h = sha2::Sha512::new();
        h.update(&canonical);
        let rd64: [u8; 64] = h.finalize().into();
        let mut report = vec![0u8; snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&rd64);
        test_support::sign_report(&mut report, &chain.vcek_signing_key);
        let ev = sev_snp_evidence_with_report(report, chain_with_ask(&chain));
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        (ev, nonce, chain)
    }

    fn sev_snp_params<'a>(nonce: &'a Nonce, anchor: TrustAnchor<'a>) -> VerifyParams<'a> {
        VerifyParams {
            expected_nonce: nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: anchor,
        }
    }

    #[test]
    fn sev_snp_rejects_report_id_mutation_after_signing() {
        let (mut evidence, nonce, chain) = sev_snp_chain_ok_evidence();
        let Proof::SevSnp { report, .. } = &mut evidence.proof else {
            panic!("expected SEV-SNP proof");
        };
        report[0x140] ^= 0xFF;

        assert_eq!(
            verify(
                &evidence,
                &sev_snp_params(
                    &nonce,
                    TrustAnchor::SevSnp {
                        amd_product_root: &chain.root,
                        expected_host_cvm_meas: None,
                        min_tcb: 0,
                        guest_policy: 0,
                    },
                ),
            ),
            VerifyOutcome::Failed(FailReason::BadSignature)
        );
    }

    #[test]
    fn sev_snp_rejects_tcb_below_min() {
        // Chain-valid evidence (reported_tcb == 0); anchor pins min_tcb = 1.
        let (ev, nonce, chain) = sev_snp_chain_ok_evidence();
        let p = sev_snp_params(
            &nonce,
            TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 1,
                guest_policy: 0,
            },
        );
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::PolicyMismatch)
        );
    }

    #[test]
    fn sev_snp_rejects_guest_policy_bits() {
        // Chain-valid evidence (report guest_policy == 0); anchor requires bit 0.
        let (ev, nonce, chain) = sev_snp_chain_ok_evidence();
        let p = sev_snp_params(
            &nonce,
            TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0x1,
            },
        );
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::PolicyMismatch)
        );
    }

    #[test]
    fn sev_snp_rejects_meas_mismatch_when_pinned() {
        // Chain-valid evidence (report measurement == [0; 48]); anchor pins a
        // different host-CVM launch digest.
        let (ev, nonce, chain) = sev_snp_chain_ok_evidence();
        let pinned = CvmMeasurement([0xFFu8; 48]);
        let p = sev_snp_params(
            &nonce,
            TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: Some(&pinned),
                min_tcb: 0,
                guest_policy: 0,
            },
        );
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::MeasurementMismatch)
        );
    }

    #[test]
    fn sev_snp_rejects_malformed_report() {
        // Short/garbage report → snp_report::parse returns None → MalformedProof.
        // Uses a chain-valid anchor so the only failure path is the parse.
        let SyntheticChain {
            vcek_leaf_der,
            root,
            ..
        } = test_support::synthetic_chain();
        let ev = sev_snp_evidence_with_report(vec![0u8; 10], vcek_leaf_der);
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let p = sev_snp_params(
            &nonce,
            TrustAnchor::SevSnp {
                amd_product_root: &root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        );
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::MalformedProof)
        );
    }

    #[test]
    fn sev_snp_rejects_broken_chain() {
        // Well-formed, correctly-signed report but a garbage VCEK cert chain →
        // the chain-error mapping's non-BadSignature arm (BadCertChain).
        let (mut ev, nonce, chain) = sev_snp_chain_ok_evidence();
        let Proof::SevSnp {
            vcek_cert_chain, ..
        } = &mut ev.proof
        else {
            panic!("expected SevSnp proof");
        };
        *vcek_cert_chain = vec![0u8; 16];
        let p = sev_snp_params(
            &nonce,
            TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        );
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::BadCertChain)
        );
    }

    // ---- Azure SEV-SNP TPM-Quote verify arm (spec v2 §3.4) ----------------

    /// Build a synthetic `TPM2B_ATTEST` (Quote) body embedding `extra_data` as the
    /// qualifying-data nonce, in the on-box `TPMS_ATTEST` layout (magic + type +
    /// qualifiedSigner + extraData). Pure; mirrors the real `tpm2_quote` output.
    fn synthetic_tpm_quote(extra_data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        // magic: TPM_GENERATED_VALUE (big-endian).
        msg.extend_from_slice(&0xFF54_4347u32.to_be_bytes());
        // type: TPM_ST_ATTEST_QUOTE (0x8018).
        msg.extend_from_slice(&0x8018u16.to_be_bytes());
        // qualifiedSigner: TPM2B_NAME = u16 len + a 34-byte AK Name placeholder.
        let qs = [0u8; 34];
        msg.extend_from_slice(&u16::try_from(qs.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(&qs);
        // extraData: TPM2B_DATA = u16 len + the nonce bytes.
        msg.extend_from_slice(&u16::try_from(extra_data.len()).unwrap().to_be_bytes());
        msg.extend_from_slice(extra_data);
        msg
    }

    /// Build a synthetic `TPM2B_PUBLIC` (tss marshaled) for an RSA-2048 key with
    /// the given modulus, matching the on-box `tpm2_readpublic -f tss` layout
    /// (the field walk `azure_ak_rsa_modulus` parses).
    fn synthetic_tpm2b_public(modulus_be: &[u8]) -> Vec<u8> {
        // TPMT_PUBLIC body: type=RSA, nameAlg=sha256, attrs, empty authPolicy,
        // sym=NULL, scheme=rsassa+sha256, keyBits=2048, exponent(empty=65537),
        // modulus(u16 len + bytes).
        let mut tp = Vec::new();
        tp.extend_from_slice(&0x0001u16.to_be_bytes()); // type = RSA
        tp.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg = sha256
        tp.extend_from_slice(&0x0005_0472u32.to_be_bytes()); // objectAttributes
        tp.extend_from_slice(&0u16.to_be_bytes()); // authPolicy len = 0
        tp.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = NULL
        tp.extend_from_slice(&0x0014u16.to_be_bytes()); // scheme = rsassa
        tp.extend_from_slice(&0x000Bu16.to_be_bytes()); // scheme hashAlg = sha256
        tp.extend_from_slice(&2048u16.to_be_bytes()); // keyBits
        tp.extend_from_slice(&0u32.to_be_bytes()); // exponent (u32; 0 = default 65537)
        tp.extend_from_slice(&u16::try_from(modulus_be.len()).unwrap().to_be_bytes()); // modulus len
        tp.extend_from_slice(modulus_be);
        // TPM2B_PUBLIC = u16 size prefix (BE) + body.
        let size = u16::try_from(tp.len()).expect("tp body < 64KiB");
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(&tp);
        out
    }

    #[test]
    fn azure_ak_public_parser_returns_only_the_canonical_rsa_2048_modulus() {
        let modulus = [0xA5; 256];
        let public = synthetic_tpm2b_public(&modulus);
        assert_eq!(
            azure_ak_rsa_modulus(&public).expect("RSA-2048 public area"),
            modulus
        );

        // `nameAlg` changes the key name representation but not the RSA public
        // modulus. Identity consumers receive only the canonical modulus.
        let mut alternate_representation = public;
        alternate_representation[4..6].copy_from_slice(&0x000Cu16.to_be_bytes());
        assert_eq!(
            azure_ak_rsa_modulus(&alternate_representation)
                .expect("alternate valid public representation"),
            modulus
        );
    }

    #[test]
    fn azure_ak_public_parser_rejects_ambiguous_or_invalid_public_areas() {
        let public = synthetic_tpm2b_public(&[0xA5; 256]);

        let mut non_rsa = public.clone();
        non_rsa[2..4].copy_from_slice(&0x0023u16.to_be_bytes());
        assert!(azure_ak_rsa_modulus(&non_rsa).is_err());

        let mut non_2048 = public.clone();
        non_2048[18..20].copy_from_slice(&3072u16.to_be_bytes());
        assert!(azure_ak_rsa_modulus(&non_2048).is_err());

        assert!(azure_ak_rsa_modulus(&public[..public.len() - 1]).is_err());

        let mut trailing = public;
        trailing.push(0x00);
        assert!(azure_ak_rsa_modulus(&trailing).is_err());
    }

    /// Build a full synthetic `Proof::SevSnpAzure` that passes the L1+L2 verify
    /// arm, plus the `var_data` JWK + the canonical `report_data` it binds. Returns
    /// `(evidence, nonce, chain)` so each deny-matrix test can mutate one field.
    ///
    /// The AK is a fresh RSA-2048 keypair (`rsa::pkcs1v15::SigningKey`); the quote
    /// message is signed with it. The report's `REPORT_DATA[..32]` is stamped
    /// with `SHA256(var_data)` (the AK JWK) — the Layer-1 binding — and signed by
    /// the synthetic VCEK.
    fn azure_evidence_ok() -> (
        Evidence,
        Nonce,
        SyntheticChain,
        rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    ) {
        use base64::Engine as _;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use rsa::traits::PublicKeyParts;
        use sha2::Digest;
        // 1. A fresh RSA-2048 AK keypair.
        let mut rng = rand::thread_rng();
        let ak_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("gen RSA-2048 AK");
        let ak_pub = ak_priv.to_public_key();
        let signing_key = SigningKey::<sha2::Sha256>::new(ak_priv);
        let modulus_be = ak_pub.n().to_bytes_be();

        // 2. var_data: a JWK Set with the AK modulus (base64url).
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modulus_be);
        let var_data =
            format!(r#"{{"keys":[{{"kid":"HCLAkPub","kty":"RSA","e":"AQAB","n":"{n_b64}"}}]}}"#)
                .into_bytes();

        // 3. The canonical report_data + the TPM Quote qualifying-data nonce.
        let nonce = Nonce::new(vec![1u8; 16]).unwrap();
        let canonical = canonical_report_data(
            ProviderType::SevSnp,
            &EvidenceRequest {
                workspace_id: "ws".into(),
                measurement: Measurement([0u8; 32]),
                nonce: nonce.clone(),
            },
            1_700_000_000,
        );
        let qd = sha2::Sha256::digest(&canonical);

        // 4. The report: REPORT_DATA[..32] = SHA256(var_data); [32..] = 0.
        let chain = test_support::synthetic_chain();
        let mut report = vec![0u8; snp_report::REPORT_SIZE];
        let mut h = sha2::Sha256::new();
        h.update(&var_data);
        let rd_hash: [u8; 32] = h.finalize().into();
        report[0x50..0x70].copy_from_slice(&rd_hash);
        // [0x70..0x90] stays zero (the verify arm checks this).
        test_support::sign_report(&mut report, &chain.vcek_signing_key);

        // 5. The TPM Quote: AK signs a TPM2B_ATTEST embedding the nonce.
        let quote_msg = synthetic_tpm_quote(&qd);
        let signature = signing_key.sign_with_rng(&mut rng, &quote_msg);
        let quote_sig = signature.to_bytes().to_vec();

        // 6. The AK TPM2B_PUBLIC.
        let ak_pub_tpm2b = synthetic_tpm2b_public(&modulus_be);

        let ev = Evidence {
            provider_type: ProviderType::SevSnp,
            workspace_id: "ws".into(),
            measurement: Measurement([0u8; 32]),
            nonce: nonce.as_bytes().to_vec(),
            issued_at: 1_700_000_000,
            report_data: canonical,
            proof: Proof::SevSnpAzure {
                report,
                vcek_cert_chain: chain_with_ask(&chain),
                var_data,
                ak_pub_tpm2b,
                quote_msg,
                quote_sig,
            },
        };
        (ev, nonce, chain, signing_key)
    }

    /// The `SevSnpAzure` evidence verifies end-to-end on the synthetic chain.
    #[test]
    fn azure_sev_snp_verifies_synthetic_2_layer() {
        let (ev, nonce, chain, _) = azure_evidence_ok();
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(verify(&ev, &p), VerifyOutcome::Verified);
    }

    /// Layer-1 break: a tampered `var_data` (wrong AK) → `ReportDataMismatch`
    /// (`SHA256(var_data)` no longer matches `REPORT_DATA`[..32]).
    #[test]
    fn azure_sev_snp_rejects_tampered_var_data() {
        let (mut ev, nonce, chain, _) = azure_evidence_ok();
        let Proof::SevSnpAzure { var_data, .. } = &mut ev.proof else {
            panic!("expected SevSnpAzure proof");
        };
        var_data[0] ^= 0xFF; // corrupt the JWK
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::ReportDataMismatch)
        );
    }

    /// Layer-2 break: a tampered quote signature → `TpmQuoteInvalid` (the AK
    /// signature no longer verifies).
    #[test]
    fn azure_sev_snp_rejects_tampered_quote_sig() {
        let (mut ev, nonce, chain, _) = azure_evidence_ok();
        let Proof::SevSnpAzure { quote_sig, .. } = &mut ev.proof else {
            panic!("expected SevSnpAzure proof");
        };
        quote_sig[0] ^= 0xFF; // corrupt the signature
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::TpmQuoteInvalid)
        );
    }

    /// Layer-2 break: a wrong nonce in the quote → `TpmQuoteInvalid` (extraData !=
    /// SHA256(canonical)).
    #[test]
    fn azure_sev_snp_rejects_wrong_quote_nonce() {
        // Build evidence with a DIFFERENT qualifying-data nonce than the canonical
        // hash, so L2b (extraData == SHA256(canonical)) fails.
        let (mut ev, nonce, chain, _) = azure_evidence_ok();
        let Proof::SevSnpAzure { quote_msg, .. } = &mut ev.proof else {
            panic!("expected SevSnpAzure proof");
        };
        // Replace the embedded nonce with a different 32 bytes.
        *quote_msg = synthetic_tpm_quote(&[0xAA; 32]);
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::TpmQuoteInvalid)
        );
    }

    /// L2a break: an `ak_pub_tpm2b` whose modulus differs from the anchored AK →
    /// `ReportDataMismatch` (the quoted key is not the var_data-anchored key).
    #[test]
    fn azure_sev_snp_rejects_mismatched_ak_pub() {
        let (mut ev, nonce, chain, _) = azure_evidence_ok();
        let Proof::SevSnpAzure { ak_pub_tpm2b, .. } = &mut ev.proof else {
            panic!("expected SevSnpAzure proof");
        };
        // Swap in a different AK modulus (a zero key). The modulus differs from
        // the var_data AK, so the L2a identity check (var_data_modulus ==
        // tpm2b_modulus) fails first → ReportDataMismatch (the quoted key is not
        // the hardware-anchored key).
        *ak_pub_tpm2b = synthetic_tpm2b_public(&[0u8; 256]);
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::ReportDataMismatch)
        );
    }

    /// Layer-1 structural: `REPORT_DATA`[32..] non-zero → `MalformedProof`.
    #[test]
    fn azure_sev_snp_rejects_nonzero_report_data_tail() {
        let (mut ev, nonce, chain, _) = azure_evidence_ok();
        let Proof::SevSnpAzure { report, .. } = &mut ev.proof else {
            panic!("expected SevSnpAzure proof");
        };
        report[0x80] = 0xFF; // corrupt the [32..] tail of REPORT_DATA
        // NOTE: this invalidates the VCEK signature, but the [32..]-zero check
        // runs BEFORE the chain verify in the arm, so MalformedProof fires first.
        let p = VerifyParams {
            expected_nonce: &nonce,
            expected_measurement: None,
            accept_provider_types: &[ProviderType::SevSnp],
            freshness: std::time::Duration::from_secs(300),
            now: 1_700_000_000,
            trust_anchor: TrustAnchor::SevSnp {
                amd_product_root: &chain.root,
                expected_host_cvm_meas: None,
                min_tcb: 0,
                guest_policy: 0,
            },
        };
        assert_eq!(
            verify(&ev, &p),
            VerifyOutcome::Failed(FailReason::MalformedProof)
        );
    }
}

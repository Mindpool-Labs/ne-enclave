// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust parse of the AMD SEV-SNP firmware Attestation Report.
//!
//! ## Source of truth
//!
//! The authoritative layout is the **AMD SEV-SNP Firmware ABI Specification**
//! (Pub #56860, Table `ATTESTATION_REPORT`). The public Linux UAPI header
//! `include/uapi/linux/sev-guest.h` does NOT carry this struct — the kernel
//! exposes the report as an opaque `__u8 data[4000]` blob in
//! `struct snp_report_resp` and defers the layout to the AMD spec (verified
//! absent across kernel v5.19, v6.0, and current `master`). This module
//! transcribes the spec offsets directly, and each offset is additionally
//! cross-verified against two independent, peer-reviewed reference
//! transcriptions of the same spec:
//!   * `virtee/sev` Rust crate — `src/firmware/guest/types/snp.rs`
//!     (`AttestationReport`), whose signature comment reads "Signature of
//!     bytes 0 to 0x29F inclusive" (i.e. `SIGNED_LEN == 0x2A0`).
//!   * Google `go-sev-guest` — `abi/abi.go`, which names `ReportSize = 0x4A0`,
//!     `policyOffset = 0x08`, `signatureOffset = 0x2A0`, `SignatureSize = 512`,
//!     and parses the body with explicit `data[0x__:0x__]` ranges.
//!
//! Reads are by-offset via `buf.get(..)` + `TryInto` — no `unsafe`, no
//! unaligned pointer aliasing, no panics. Every accessor returns `None` on
//! short or malformed input.

/// Fixed total size of the firmware report (AMD spec: full `ATTESTATION_REPORT`
/// including the trailing VCEK signature). Confirmed by `go-sev-guest`'s
/// `ReportSize = 0x4A0`.
pub const REPORT_SIZE: usize = 0x4A0;

/// Length of the VCEK-signed region — every byte before the trailing
/// signature. AMD spec: signature covers bytes 0x000..=0x29F, i.e. 0x2A0
/// bytes. Confirmed by `go-sev-guest`'s `signatureOffset = 0x2A0`.
pub const SIGNED_LEN: usize = REPORT_SIZE - 512;

/// Subset of report fields the verifier binds over.
///
/// Offsets are the spec's; `measurement` here is the host-CVM launch digest
/// (AMD `MEAS`) — NOT NeuronEdge's per-workspace
/// [`Measurement`](crate::Measurement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFields {
    /// AMD `VERSION` (u32). Offset 0x00.
    pub version: u32,
    /// AMD `GUEST_POLICY` (u64). Offset 0x08.
    pub guest_policy: u64,
    /// AMD `SIG_ALGO` (u32). Offset 0x34.
    pub sig_algo: u32,
    /// AMD `REPORT_DATA` (512-bit). Offset 0x50, len 64.
    pub report_data: [u8; 64],
    /// AMD `MEASUREMENT` (384-bit). Offset 0x90, len 48. Host-CVM launch
    /// digest, distinct from the per-workspace measurement.
    pub measurement: [u8; 48],
    /// AMD `REPORT_ID` (256-bit). Offset 0x140. This value is inside the
    /// firmware-signed report body and is exposed only through [`Self::report_id`].
    report_id: [u8; 32],
    /// AMD `REPORTED_TCB` (u64). Offset 0x180 — the TCB the VCEK was signed
    /// against (distinct from `CURRENT_TCB` at 0x38).
    pub reported_tcb: u64,
    /// AMD `CHIP_ID` (512-bit). Offset 0x1A0, len 64.
    pub chip_id: [u8; 64],
}

impl ReportFields {
    /// Return the VCEK-signed AMD `REPORT_ID` bytes.
    #[must_use]
    pub const fn report_id(&self) -> &[u8; 32] {
        &self.report_id
    }
}

/// Parse the firmware Attestation Report out of `buf`, returning the fields
/// the verifier consumes. Returns `None` unless `buf.len() == REPORT_SIZE`.
///
/// # Panics
/// Never. Short slices yield `None` via `buf.get(..)?`.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<ReportFields> {
    if buf.len() != REPORT_SIZE {
        return None;
    }
    // Offset helpers. `buf.get(o..o+n)?` is panic-free (None on OOB, which
    // cannot happen after the length guard but keeps the indexing local and
    // robust to any future offset edits). Each closure returns `Option<T>`;
    // the `?` at the call site propagates `None` out of `parse`.
    let u32_at =
        |o: usize| -> Option<u32> { Some(u32::from_le_bytes(buf.get(o..o + 4)?.try_into().ok()?)) };
    let u64_at =
        |o: usize| -> Option<u64> { Some(u64::from_le_bytes(buf.get(o..o + 8)?.try_into().ok()?)) };
    let arr64_at =
        |o: usize| -> Option<[u8; 64]> { <[u8; 64]>::try_from(buf.get(o..o + 64)?).ok() };
    let arr48_at =
        |o: usize| -> Option<[u8; 48]> { <[u8; 48]>::try_from(buf.get(o..o + 48)?).ok() };
    let arr32_at =
        |o: usize| -> Option<[u8; 32]> { <[u8; 32]>::try_from(buf.get(o..o + 32)?).ok() };
    // Offsets transcribed from AMD SEV-SNP FW ABI Table `ATTESTATION_REPORT`
    // and cross-verified against virtee/sev + go-sev-guest (see module doc).
    // The Step-4 tests assert the load-bearing ones, so a transcription error
    // fails the build rather than silently mis-binding attestation.
    Some(ReportFields {
        version: u32_at(0x00)?, // AMD VERSION        | go-sev-guest data[0x00:0x04]
        guest_policy: u64_at(0x08)?, // AMD GUEST_POLICY   | go-sev-guest data[0x08:0x10]
        sig_algo: u32_at(0x34)?, // AMD SIG_ALGO       | go-sev-guest report[0x34:0x38]
        report_data: arr64_at(0x50)?, // AMD REPORT_DATA    | go-sev-guest data[0x50:0x90]
        measurement: arr48_at(0x90)?, // AMD MEASUREMENT    | go-sev-guest data[0x90:0xC0]
        report_id: arr32_at(0x140)?, // AMD REPORT_ID      | go-sev-guest data[0x140:0x160]
        reported_tcb: u64_at(0x180)?, // AMD REPORTED_TCB   | go-sev-guest data[0x180:0x188]
        chip_id: arr64_at(0x1A0)?, // AMD CHIP_ID        | go-sev-guest data[0x1A0:0x1E0]
    })
}

/// Return the VCEK-signed region (bytes `0x000..SIGNED_LEN`) of a report, or
/// `None` if `buf` is not exactly `REPORT_SIZE` bytes.
///
/// # Panics
/// Never — short slices yield `None` (the slice is only computed once the
/// length is confirmed, unlike a `.then_some(&buf[..])` which would evaluate
/// the index eagerly and panic on short input).
#[must_use]
pub fn signed_bytes(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() == REPORT_SIZE {
        Some(&buf[..SIGNED_LEN])
    } else {
        None
    }
}

/// Return the trailing 512-byte VCEK signature (bytes `SIGNED_LEN..`) of a
/// report, or `None` if `buf` is not exactly `REPORT_SIZE` bytes.
#[must_use]
pub fn signature(buf: &[u8]) -> Option<[u8; 512]> {
    if buf.len() != REPORT_SIZE {
        return None;
    }
    buf[SIGNED_LEN..].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_size_and_signed_len_are_consistent() {
        assert_eq!(REPORT_SIZE, SIGNED_LEN + 512);
    }

    /// Pins the constants to the exact authoritative values so a future edit
    /// that drifts from the AMD spec / go-sev-guest `ReportSize = 0x4A0` /
    /// `signatureOffset = 0x2A0` fails loudly here.
    #[test]
    fn constants_match_authoritative_values() {
        assert_eq!(REPORT_SIZE, 0x4A0, "AMD ATTESTATION_REPORT total size");
        assert_eq!(SIGNED_LEN, 0x2A0, "AMD signed region 0x000..=0x29F");
        assert_eq!(SIGNED_LEN, REPORT_SIZE - 512);
    }

    #[test]
    fn parse_rejects_wrong_size() {
        assert!(parse(&[0u8; 10]).is_none());
        assert!(parse(&[0u8; REPORT_SIZE]).is_some());
        assert!(parse(&[0u8; REPORT_SIZE - 1]).is_none());
        assert!(parse(&[0u8; REPORT_SIZE + 1]).is_none());
    }

    /// Round-trips the load-bearing offsets: each byte range the verifier
    /// binds over is written at the transcribed offset and must come back out
    /// of `parse`. If `parse`'s offset and this test's literal disagree, the
    /// assertion fails — coupling the test to the transcribed offsets.
    #[test]
    fn parse_reads_fields_at_transcribed_offsets() {
        let mut buf = vec![0u8; REPORT_SIZE];

        // Little-endian scalars at their transcribed offsets.
        buf[0x00..0x04].copy_from_slice(&0x1122_3344_u32.to_le_bytes()); // version
        buf[0x08..0x10].copy_from_slice(&0xABCD_EF01_2345_6789_u64.to_le_bytes()); // guest_policy
        buf[0x34..0x38].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // sig_algo (ECDSA P-384)
        buf[0x180..0x188].copy_from_slice(&0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes()); // reported_tcb

        // Fixed-size byte arrays at their transcribed offsets.
        buf[0x50..0x90].copy_from_slice(&[0xAB; 64]); // report_data
        buf[0x90..0xC0].copy_from_slice(&[0xCD; 48]); // measurement
        buf[0x140..0x160].copy_from_slice(&[0xD0; 32]); // report_id
        buf[0x1A0..0x1E0].copy_from_slice(&[0xEF; 64]); // chip_id

        let f = parse(&buf).expect("REPORT_SIZE buffer must parse");
        assert_eq!(f.version, 0x1122_3344);
        assert_eq!(f.guest_policy, 0xABCD_EF01_2345_6789);
        assert_eq!(f.sig_algo, 0x0000_0001);
        assert_eq!(f.reported_tcb, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(f.report_data, [0xAB; 64]);
        assert_eq!(f.measurement, [0xCD; 48]);
        assert_eq!(f.report_id(), &[0xD0; 32]);
        assert_eq!(f.chip_id, [0xEF; 64]);
    }

    #[test]
    fn signed_and_signature_split_correctly() {
        let mut buf = vec![7u8; REPORT_SIZE];
        // Distinctive signature bytes so we also confirm the exact split point.
        buf[SIGNED_LEN..SIGNED_LEN + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let signed = signed_bytes(&buf).expect("REPORT_SIZE buffer has a signed region");
        assert_eq!(signed.len(), SIGNED_LEN);
        // Signed region must end exactly where the signature begins.
        assert_eq!(&signed[..4], &[7u8; 4]);
        let sig = signature(&buf).expect("REPORT_SIZE buffer has a 512-byte signature");
        assert_eq!(sig.len(), 512);
        assert_eq!(&sig[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn signed_bytes_and_signature_reject_wrong_size() {
        assert!(signed_bytes(&[0u8; 10]).is_none());
        assert!(signature(&[0u8; REPORT_SIZE - 1]).is_none());
        assert!(signature(&[0u8; REPORT_SIZE + 1]).is_none());
    }
}

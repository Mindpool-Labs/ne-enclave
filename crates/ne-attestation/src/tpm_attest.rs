// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Pure parser for the TPM 2.0 `TPM2B_ATTEST` / `TPMS_ATTEST` structure that
//! `tpm2_quote` produces.
//!
//! Used by the Azure SEV-SNP TPM-Quote binding (spec v2 §3.4 Layer 2). This
//! module extracts the `extraData` field (the caller's qualifying-data nonce)
//! from a TPM Quote so the verify arm can bind the quote to the attestation
//! request.
//!
//! ## Layout (TPM 2.0 Part 2; confirmed against a real `tpm2_quote` on
//! `ne-snp-azure`)
//!
//! `tpm2_quote -m <file>` writes the `TPM2B_ATTEST` as a `TPMS_ATTEST` body —
//! `tpm2-tools` strips the outer `u16` size prefix. For robustness the parser
//! accepts **both** forms (with and without the prefix) by auto-detecting the
//! `TPM_GENERATED_VALUE` magic.
//!
//! `TPMS_ATTEST` (big-endian — all TPM 2.0 integers are big-endian):
//! ```text
//!   +0   TPM_GENERATED magic       u32 BE   = 0xFF544347
//!   +4   TPMI_ST_ATTEST type       u16 BE   = 0x8018 (TPM_ST_ATTEST_QUOTE)
//!   +6   qualifiedSigner           TPM2B_NAME  (u16 BE size + name bytes)
//!   +6+2+qs_len   extraData        TPM2B_DATA  (u16 BE size + data bytes)  ← the nonce
//!   …    clockInfo, firmwareID, (for QUOTE:) TPMS_QUOTE_INFO { pcrSelect, pcrDigest }
//! ```
//! `extraData` is at a **variable** offset (it follows the variable-length
//! `qualifiedSigner` name), so the parser walks the two leading `TPM2B_*`
//! fields rather than using a fixed offset.
//!
//! ## No TPM dependency
//! This is pure byte-slice arithmetic — no `tss-esapi`, no `tpm2-bindings`.
//! `tpm2_checkquote` (exit 0 on-box) is the reference for correctness.

/// The TPM 2.0 `TPM_GENERATED_VALUE` magic marking a genuine `TPMS_ATTEST`
/// (`0xFF544347`). A quote that does not start with this was not produced by a
/// real TPM (forged) — the verify arm denies.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE` — the `TPMI_ST_ATTEST` type for a `TPM2_Quote`
/// response (`0x8018`). The verify arm asserts this (only a Quote attestation
/// carries the PCR digest + nonce binding we need).
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// A parsed `TPMS_ATTEST` (the body of a `TPM2B_ATTEST` produced by
/// `tpm2_quote`). Only the fields the verify arm needs are extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmAttest {
    /// The `TPM_GENERATED_VALUE` magic (`0xFF544347` for a genuine TPM).
    pub magic: u32,
    /// The attestation structure type (`TPM_ST_ATTEST_QUOTE` for a Quote).
    pub attest_type: u16,
    /// The `extraData` qualifying-data bytes — the caller's nonce that the AK
    /// signature covers. This is the Layer-2 binding target.
    pub extra_data: Vec<u8>,
}

/// Parse a `TPM2B_ATTEST` / `TPMS_ATTEST` byte slice (the output of
/// `tpm2_quote -m`) into a [`TpmAttest`], extracting the `extraData` nonce.
///
/// Accepts both the raw `TPMS_ATTEST` body (what `tpm2_quote -m` writes — no
/// outer `u16` prefix) and a full `TPM2B_ATTEST` (with the `u16` size prefix),
/// auto-detecting via the magic. Returns `None` on any malformed/truncated
/// input or a bad magic (fail-closed — the verify arm denies rather than
/// trusting a forged quote). Pure; Mac-testable.
#[must_use]
pub fn parse_tpm2b_attest(msg: &[u8]) -> Option<TpmAttest> {
    // Auto-detect the outer TPM2B_ATTEST u16 prefix: a genuine TPMS_ATTEST
    // starts with the magic 0xFF544347 (big-endian). If the first two bytes are
    // a plausible u16 size followed by the magic, treat them as the prefix.
    let body = if msg.len() >= 6
        && u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]) == TPM_GENERATED_VALUE
    {
        // Looks like a TPM2B_ATTEST: skip the 2-byte size prefix.
        msg.get(2..)?
    } else {
        // Raw TPMS_ATTEST body (tpm2_quote -m output).
        msg
    };

    // A genuine TPMS_ATTEST needs at least magic(4) + type(2) + qs.size(2) = 8 bytes.
    if body.len() < 8 {
        return None;
    }
    // magic: u32 BE @0 — a genuine quote starts with TPM_GENERATED_VALUE.
    let magic = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if magic != TPM_GENERATED_VALUE {
        return None;
    }
    // attest_type: u16 BE @4
    let attest_type = u16::from_be_bytes([body[4], body[5]]);
    // qualifiedSigner: TPM2B_NAME = u16 BE size @6, then name bytes.
    let qs_len = u16::from_be_bytes([body[6], body[7]]) as usize;
    let qs_end = 8usize.checked_add(qs_len)?;
    // extraData: TPM2B_DATA = u16 BE size @qs_end, then data bytes.
    let ed_off = qs_end;
    if body.len() < ed_off + 2 {
        return None;
    }
    let ed_len = u16::from_be_bytes([body[ed_off], body[ed_off + 1]]) as usize;
    let ed_start = ed_off + 2;
    let ed_end = ed_start.checked_add(ed_len)?;
    let extra_data = body.get(ed_start..ed_end)?.to_vec();

    Some(TpmAttest {
        magic,
        attest_type,
        extra_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real `tpm2_quote` output from ne-snp-azure, captured
    // with a 32-byte qualifying-data nonce of 0x42. This is the TPMS_ATTEST body
    // (tpm2_quote -m writes the body without the outer TPM2B_ATTEST u16 prefix):
    //   magic=0xff544347, type=0x8018 (QUOTE), qualifiedSigner=34B (the AK Name),
    //   extraData=32B (0x42 * 32 = our nonce).
    const REAL_QUOTE_MSG_HEX: &str = "ff54434780180022000bc92a0e915a89adc0cf88e5e1ccb88e5114631e072843f88ea162c9440cd4216d0020424242424242424242424242424242424242424242424242424242424242424200000000002a9925000000020000000001202003120012000300000001000b0301000000205e83d048bbcb9341641a0ed4777abe91cb2f272976f08973f07fe783738669c5";

    /// The parser recovers the exact 32-byte qualifying-data nonce (0x42 * 32)
    /// from a real `tpm2_quote` message, and the magic + Quote type are correct.
    #[test]
    fn parse_tpm2b_attest_extracts_extra_data_from_real_quote() {
        let msg = hex::decode(REAL_QUOTE_MSG_HEX).unwrap();
        let parsed = parse_tpm2b_attest(&msg).expect("real quote must parse");
        assert_eq!(parsed.magic, TPM_GENERATED_VALUE);
        assert_eq!(parsed.attest_type, TPM_ST_ATTEST_QUOTE);
        // The qualifying-data nonce: 32 bytes of 0x42.
        assert_eq!(parsed.extra_data, vec![0x42; 32]);
    }

    /// A `TPM2B_ATTEST` WITH the outer `u16` size prefix also parses (robust to
    /// both forms — some callers wrap the body).
    #[test]
    fn parse_tpm2b_attest_handles_outer_size_prefix() {
        let body = hex::decode(REAL_QUOTE_MSG_HEX).unwrap();
        let len = u16::try_from(body.len()).expect("quote body < 64 KiB");
        let mut wrapped = len.to_be_bytes().to_vec();
        wrapped.extend_from_slice(&body);
        let parsed = parse_tpm2b_attest(&wrapped).expect("wrapped TPM2B_ATTEST must parse");
        assert_eq!(parsed.extra_data, vec![0x42; 32]);
    }

    /// A forged quote (wrong magic) is rejected — the verify arm must never
    /// trust a structure that did not come from a real TPM.
    #[test]
    fn parse_tpm2b_attest_rejects_bad_magic() {
        // Same structure, but magic corrupted to 0x00… .
        let mut msg = hex::decode(REAL_QUOTE_MSG_HEX).unwrap();
        msg[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(parse_tpm2b_attest(&msg).is_none());
    }

    /// Truncated / empty inputs are rejected (fail-closed).
    #[test]
    fn parse_tpm2b_attest_rejects_truncated_and_empty() {
        assert!(parse_tpm2b_attest(&[]).is_none());
        assert!(parse_tpm2b_attest(&[0xff]).is_none());
        // Magic + type but no qualifiedSigner length.
        assert!(parse_tpm2b_attest(&[0xff, 0x54, 0x43, 0x47, 0x80, 0x18]).is_none());
    }

    /// A truncated `extraData` (size field claims more than available) is
    /// rejected, not silently truncated.
    #[test]
    fn parse_tpm2b_attest_rejects_truncated_extra_data() {
        // magic + type + qs(0 len) + ed.size=32 but no ed body.
        let msg = [
            0xff, 0x54, 0x43, 0x47, // magic
            0x80, 0x18, // type
            0x00, 0x00, // qs size = 0
            0x00, 0x20, // ed size = 32
        ];
        assert!(parse_tpm2b_attest(&msg).is_none());
    }
}

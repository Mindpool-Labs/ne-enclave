// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP VCEK certificate-chain verification + firmware-signature check.
//!
//! The real AMD SEV-SNP trust hierarchy is **mixed-algorithm**:
//! - **ARK** (product root): RSA-4096, self-signed **RSASSA-PSS-SHA384**.
//! - **ASK** (intermediate): RSA-4096, signed by the ARK (RSASSA-PSS-SHA384).
//! - **VCEK** (leaf): ECDSA **P-384**, signed by the ASK.
//! - **Firmware report signature**: ECDSA P-384 over SHA-384.
//!
//! Only the VCEK leaf + the report signature are P-384; the ARK and ASK are
//! RSA-4096. This module therefore dispatches on the certificate SPKI /
//! signature-algorithm OIDs and verifies RSA-PSS-SHA384 (ARK/ASK) via the
//! pure-Rust `rsa` crate and ECDSA P-384 (VCEK/report) via `p384`. `ring` is
//! banned (Mac-native + the wasm re-vendor), so RSA uses `rsa` verify-only.
//!
//! The genuine Milan ARK + ASK (public AMD KDS certs) are baked here as the
//! default trust anchor (`AmdRootCert::milan_default`). Mac tests verify the
//! REAL AMD RSA signatures (ARK self-sig; ASK-under-ARK) — verification-only,
//! genuine signatures on genuine public certs. The synthetic P-384 chain tests
//! cover the ECDSA chain-walk logic. Nothing here claims a hardware-rooted
//! attestation *report* validates — that is proven on silicon by the hardware
//! integration test.
//!
//! References: AMD "SEV Secure Nested Paging Firmware ABI Specification"
//! (VCEK certificate format; report signature algorithm ECDSA P-384 over
//! SHA-384). The report signature layout — `R` at `[0x00:0x48]`, `S` at
//! `[0x48:0x90]`, each a **72-byte LITTLE-ENDIAN** integer (significant bytes
//! first, zero-padded in `[48:72]`) — is the authoritative AMD ABI encoding.
//! Cross-verified against Google `go-sev-guest` `abi.go`: `ecdsaRSsize = 72`,
//! `EcdsaP384Sha384SignatureSize = 144`, `ecdsaGetR`/`ecdsaGetS` return the
//! 72-byte halves, and `AmdBigInt(b) = SetBytes(reverse(b))` — i.e. each half
//! is little-endian and must be reversed to big-endian before use. Cert issuer
//! signatures are standard DER-encoded ECDSA-Sig-Values (VCEK) or raw RSASSA-
//! PSS octets (ARK/ASK) inside the X.509 BIT STRING.

use p384::ecdsa::signature::Verifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use thiserror::Error;
use x509_cert::der::Decode;
use x509_cert::der::asn1::ObjectIdentifier;

/// `rsaEncryption` (1.2.840.113549.1.1.1) — RSA public-key SPKI algorithm.
const OID_SPKI_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `rsassaPss` (1.2.840.113549.1.1.10) — RSASSA-PSS cert signature algorithm.
/// AMD's ARK/ASK use PSS with SHA-384 / MGF1-SHA384 / salt = 48 (= hash size).
const OID_SIG_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3) — ECDSA P-384 cert signature
/// algorithm (the VCEK leaf, signed by the ASK).
const OID_SIG_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// The genuine Milan ARK DER (RSA-4096, self-signed RSASSA-PSS-SHA384). Public
/// AMD KDS trust material. SHA-256 pinned in `milan_default` tests.
pub const AMD_MILAN_ARK_DER: &[u8] = include_bytes!("../certs/amd-milan-ark.der");

/// The genuine Milan ASK DER (RSA-4096, signed by the ARK).
///
/// Public AMD KDS trust material, baked for test-reference; the supervisor
/// fetches the ASK at runtime to embed alongside the VCEK in
/// `Proof::SevSnp`.
pub const AMD_MILAN_ASK_DER: &[u8] = include_bytes!("../certs/amd-milan-ask.der");

/// Failures raised by VCEK-chain / firmware-signature verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VcekError {
    /// A certificate or the report blob could not be parsed.
    #[error("malformed certificate")]
    MalformedCert,
    /// The VCEK chain did not validate to the supplied AMD root (ARK).
    #[error("chain did not validate to the AMD root")]
    BadChain,
    /// The firmware signature over the report did not verify under the VCEK key.
    #[error("firmware signature did not verify under the VCEK key")]
    BadSignature,
    /// A transport-level failure fetching VCEK material (network unreachable,
    /// HTTP error, connection reset, etc.). Distinct from [`Self::MalformedCert`],
    /// which is reserved for an unparseable response body.
    #[cfg(feature = "kds")]
    #[error("network error fetching VCEK material")]
    Network,
}

/// A parsed certificate public key — the AMD SEV-SNP chain is mixed: the ARK
/// and ASK are RSA-4096 (RSASSA-PSS-SHA384); only the VCEK leaf is ECDSA P-384.
#[derive(Debug, Clone)]
pub enum PubKey {
    /// RSA-4096 (ARK / ASK). Used to verify RSASSA-PSS-SHA384 issuer signatures.
    Rsa(RsaPssVerifyingKey<sha2::Sha384>),
    /// ECDSA P-384 (VCEK leaf). Used to verify the firmware report signature
    /// (ECDSA-P384-SHA384) and, for synthetic chains, ECDSA issuer signatures.
    EcP384(p384::ecdsa::VerifyingKey),
}

/// The trusted AMD product (ARK) root.
///
/// The crate ships the genuine Milan ARK as a known-good default via
/// [`Self::milan_default`]; callers may supply their own ARK DER via
/// `SealingPolicy.trust_anchor.amd_product_root_der`, which the gate
/// re-parses through [`Self::from_der`].
#[derive(Debug, Clone)]
pub struct AmdRootCert {
    /// The ARK public key (RSA for the genuine AMD hierarchy; EC P-384 for the
    /// synthetic test chain), extracted from a DER ARK certificate.
    pub verifying_key: PubKey,
}

impl AmdRootCert {
    /// Parse the ARK public key from a DER-encoded ARK certificate. Dispatches
    /// on the certificate's SPKI algorithm: RSA-4096 (genuine AMD) or ECDSA
    /// P-384 (synthetic test chain).
    ///
    /// # Errors
    /// [`VcekError::MalformedCert`] if `ark_der` is not a parseable X.509
    /// certificate whose `SubjectPublicKeyInfo` carries a recognized key.
    pub fn from_der(ark_der: &[u8]) -> Result<Self, VcekError> {
        let verifying_key = cert_pubkey(ark_der)?;
        Ok(Self { verifying_key })
    }

    /// The genuine AMD Milan ARK (RSA-4096) baked into the crate as the default
    /// SEV-SNP trust anchor. Public KDS material — see `AMD_MILAN_ARK_DER`.
    ///
    /// # Errors
    /// [`VcekError::MalformedCert`] only if the baked ARK DER is corrupt (it is
    /// pinned at build time; this never fails in practice).
    pub fn milan_default() -> Result<Self, VcekError> {
        Self::from_der(AMD_MILAN_ARK_DER)
    }
}

/// Validate the VCEK chain and the firmware signature over `report`.
///
/// `vcek_chain_der` is a concatenation of DER certificates, leaf (VCEK) first,
/// followed by any intermediate issuers (e.g. ASK). The chain is walked to the
/// supplied `root` (ARK): every certificate is verified under the next
/// certificate's public key, and the final certificate is verified under
/// `root.verifying_key`. The firmware signature is then checked under the leaf
/// (VCEK) public key. A structurally-valid report whose chain does NOT validate
/// to `root` returns [`VcekError::BadChain`] — never `Ok`.
///
/// This function is pure: it performs no network I/O. VCEK material is fetched
/// out-of-band by a [`VcekFetcher`] and embedded by the caller.
///
/// # Errors
/// [`VcekError::MalformedCert`] on a short report or unparseable chain;
/// [`VcekError::BadChain`] if any issuer signature fails; [`VcekError::BadSignature`]
/// if the firmware signature does not verify under the VCEK key.
pub fn verify_report(
    report: &[u8],
    vcek_chain_der: &[u8],
    root: &AmdRootCert,
) -> Result<(), VcekError> {
    let signed = crate::snp_report::signed_bytes(report).ok_or(VcekError::MalformedCert)?;
    let sig_field = crate::snp_report::signature(report).ok_or(VcekError::MalformedCert)?;

    let certs = split_concat_der(vcek_chain_der).ok_or(VcekError::MalformedCert)?;
    let leaf = certs.first().ok_or(VcekError::BadChain)?;
    let leaf_pubkey = cert_pubkey(leaf)?;

    // Walk: each cert[i] is signed by cert[i+1], or by the root for the last.
    for (i, cert_der) in certs.iter().enumerate() {
        // The issuer is the next cert in the chain, or the ARK root for the
        // last. `PubKey` is `Clone` (RSA verify-key wraps a `RsaPublicKey`;
        // P-384 verify-key is a few field elements), so cloning the root once
        // per chain keeps the borrow graph flat.
        let issuer_vk = match certs.get(i + 1) {
            Some(issuer) => cert_pubkey(issuer)?,
            None => root.verifying_key.clone(),
        };
        verify_cert_signature(cert_der, &issuer_vk)?;
    }

    // The firmware report signature is always ECDSA P-384; the VCEK leaf that
    // owns it is therefore always EC. An RSA leaf here is a malformed chain
    // (e.g. an ARK/ASK presented where a VCEK was expected), not a bad
    // signature — surface it as `BadSignature`.
    let vcek_vk = match &leaf_pubkey {
        PubKey::EcP384(vk) => vk,
        PubKey::Rsa(_) => return Err(VcekError::BadSignature),
    };

    let signature = amd_sig_to_p384(&sig_field).ok_or(VcekError::BadSignature)?;
    vcek_vk
        .verify(signed, &signature)
        .map_err(|_| VcekError::BadSignature)
}

/// Extract the public key from a DER X.509 certificate's SPKI, dispatching on
/// the SPKI algorithm OID: `rsaEncryption` → RSA-PSS verify key (ARK/ASK),
/// otherwise ECDSA P-384 (VCEK leaf / synthetic chain).
fn cert_pubkey(cert_der: &[u8]) -> Result<PubKey, VcekError> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| VcekError::MalformedCert)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(VcekError::MalformedCert)?;
    if spki.algorithm.oid == OID_SPKI_RSA {
        // The SPKI `subjectPublicKey` bitstring for `rsaEncryption` carries a
        // DER-encoded `RSAPublicKey` (PKCS#1): modulus || publicExponent.
        let rsa_pub =
            rsa::RsaPublicKey::from_pkcs1_der(key_bytes).map_err(|_| VcekError::MalformedCert)?;
        // `new` sets salt length = `Sha384::output_size()` = 48, which matches
        // the AMD ARK/ASK `Salt Length: 0x30` (confirmed via `openssl x509 -text`).
        return Ok(PubKey::Rsa(RsaPssVerifyingKey::<sha2::Sha384>::new(
            rsa_pub,
        )));
    }
    // `ecPublicKey` (1.2.840.10045.2.1): the bitstring is the SEC1 EC point.
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
        .map_err(|_| VcekError::MalformedCert)?;
    Ok(PubKey::EcP384(vk))
}

/// Verify the X.509 issuer signature on `cert_der` under `issuer`, dispatching
/// on the certificate's `signatureAlgorithm` OID: `rsassaPss` → RSA-PSS-SHA384
/// verify against `PubKey::Rsa`; `ecdsa-with-SHA384` → P-384 verify against
/// `PubKey::EcP384`. A signature-algorithm / issuer-key mismatch (e.g. an RSA
/// signature presented to an EC issuer key) yields [`VcekError::BadChain`].
fn verify_cert_signature(cert_der: &[u8], issuer: &PubKey) -> Result<(), VcekError> {
    let (tbs, sig_bytes) = cert_tbs_and_sig(cert_der).ok_or(VcekError::MalformedCert)?;
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| VcekError::MalformedCert)?;
    let sig_alg = cert.signature_algorithm.oid;

    if sig_alg == OID_SIG_RSASSA_PSS {
        let rsa_vk = match issuer {
            PubKey::Rsa(vk) => vk,
            PubKey::EcP384(_) => return Err(VcekError::BadChain),
        };
        // `cert_tbs_and_sig` returns the raw signatureValue octets; for PSS
        // these are the raw RSASSA-PSS bytes (512 for RSA-4096), which is what
        // `Signature::try_from` + `Verifier::verify` expect.
        let signature =
            rsa::pss::Signature::try_from(sig_bytes).map_err(|_| VcekError::MalformedCert)?;
        return rsa_vk
            .verify(tbs, &signature)
            .map_err(|_| VcekError::BadChain);
    }

    if sig_alg == OID_SIG_ECDSA_SHA384 {
        let ec_vk = match issuer {
            PubKey::EcP384(vk) => vk,
            PubKey::Rsa(_) => return Err(VcekError::BadChain),
        };
        let signature =
            p384::ecdsa::Signature::from_der(sig_bytes).map_err(|_| VcekError::MalformedCert)?;
        return ec_vk
            .verify(tbs, &signature)
            .map_err(|_| VcekError::BadChain);
    }

    // Unknown signature algorithm (e.g. RSASSA-PKCS1-v1_5).
    Err(VcekError::MalformedCert)
}

/// Convert the AMD report signature field into the 96-byte fixed `r||s`
/// big-endian form `p384::ecdsa::Signature` expects.
///
/// The AMD ABI stores each of `R` and `S` as a **72-byte little-endian**
/// integer: the significant value occupies the first 48 bytes (LE), the
/// remaining `[48:72]` bytes are zero padding (confirmed against Google
/// `go-sev-guest` `abi.go`: `AmdBigInt(b) = SetBytes(reverse(b))`,
/// `bigIntToAMDRS = reverse(FillBytes(72))`). We mirror `AmdBigInt` exactly:
/// reverse the full 72-byte half, then take the low 48 bytes as the
/// big-endian scalar. Returns `None` if the field is not the AMD layout or the
/// reserved tail `[0x90:0x200]` of the 512-byte signature region is non-zero.
#[allow(clippy::similar_names)]
fn amd_sig_to_p384(sig: &[u8; 512]) -> Option<p384::ecdsa::Signature> {
    const R_OFF: usize = 0x00;
    const S_OFF: usize = 0x48;
    const RS_LEN: usize = 0x48; // 72 bytes per AMD `ecdsaRSsize`
    // The bytes after the 144-byte R||S region are reserved-must-be-zero
    // (go-sev-guest `ReportToProto` enforces `mbz(data, signatureOffset +
    // EcdsaP384Sha384SignatureSize, ReportSize)`). Reject if non-zero so a
    // malformed/garbage signature field cannot slip through.
    if sig.get(0x90..0x200)?.iter().any(|&b| b != 0) {
        return None;
    }
    let r72 = sig.get(R_OFF..R_OFF + RS_LEN)?;
    let s72 = sig.get(S_OFF..S_OFF + RS_LEN)?;
    let r48 = amd_le_field_to_be48(r72)?;
    let s48 = amd_le_field_to_be48(s72)?;
    let mut bytes = [0u8; 96];
    bytes[..48].copy_from_slice(&r48);
    bytes[48..].copy_from_slice(&s48);
    p384::ecdsa::Signature::from_slice(&bytes).ok()
}

/// Reverse a 72-byte AMD little-endian field to its 48-byte big-endian scalar,
/// mirroring `AmdBigInt(reverse(b))`. The value fits in 48 bytes (P-384 order
/// n < 2^384), so after reversing the 72 bytes the leading 24 are zero padding
/// and the trailing 48 are the magnitude.
fn amd_le_field_to_be48(field72: &[u8]) -> Option<[u8; 48]> {
    if field72.len() != 72 {
        return None;
    }
    let mut rev = [0u8; 72];
    rev.copy_from_slice(field72);
    rev.reverse();
    let mut out = [0u8; 48];
    out.copy_from_slice(&rev[24..]);
    Some(out)
}

/// Decode a DER length octet starting at `idx`. Returns `(length, content_start)`.
fn der_len(buf: &[u8], idx: usize) -> Option<(usize, usize)> {
    let first = *buf.get(idx)?;
    if first < 0x80 {
        return Some((first as usize, idx + 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None; // indefinite form or implausibly long
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | usize::from(*buf.get(idx + 1 + i)?);
    }
    Some((len, idx + 1 + n))
}

/// Split a concatenation of DER certificate bodies into their byte slices.
/// Each element must be a SEQUENCE (tag `0x30`); returns `None` on any parse
/// error or trailing garbage.
fn split_concat_der(blob: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < blob.len() {
        if *blob.get(p)? != 0x30 {
            return None;
        }
        let (len, cs) = der_len(blob, p + 1)?;
        let end = cs.checked_add(len)?;
        let slice = blob.get(p..end)?;
        out.push(slice);
        p = end;
    }
    Some(out)
}

/// From a DER X.509 certificate, return `(tbs_der, signature_value_bytes)` where
/// `tbs_der` is the full `tbsCertificate` TLV (tag+length+content — the exact
/// bytes the issuer signed) and `signature_value_bytes` is the content of the
/// outer signatureValue BIT STRING. For an ECDSA-signed cert (VCEK) this is the
/// DER-encoded ECDSA-Sig-Value; for an RSASSA-PSS-signed cert (ARK/ASK) it is
/// the raw PSS octets (512 bytes for RSA-4096).
#[allow(clippy::similar_names)]
fn cert_tbs_and_sig(cert_der: &[u8]) -> Option<(&[u8], &[u8])> {
    // Outer SEQUENCE: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    if cert_der.first()? != &0x30 {
        return None;
    }
    let (_, outer_cs) = der_len(cert_der, 1)?;
    let outer = cert_der.get(outer_cs..)?;

    // First child: tbsCertificate (SEQUENCE) — full TLV is the signed region.
    if outer.first()? != &0x30 {
        return None;
    }
    let (tbs_len, tbs_cs) = der_len(outer, 1)?;
    let tbs_end = tbs_cs.checked_add(tbs_len)?;
    let tbs = outer.get(..tbs_end)?;

    // Second child: signatureAlgorithm (SEQUENCE) — skip.
    let mut p = tbs_end;
    if outer.get(p)? != &0x30 {
        return None;
    }
    let (sa_len, sa_cs) = der_len(outer, p + 1)?;
    p = sa_cs.checked_add(sa_len)?;

    // Third child: signatureValue (BIT STRING, tag 0x03).
    if outer.get(p)? != &0x03 {
        return None;
    }
    let (sv_len, sv_cs) = der_len(outer, p + 1)?;
    let bitstring = outer.get(sv_cs..sv_cs.checked_add(sv_len)?)?;
    let unused_bits = *bitstring.first()?;
    if unused_bits != 0 {
        return None;
    }
    let sig = bitstring.get(1..)?;
    Some((tbs, sig))
}

/// A VCEK-certifacte fetcher. Production implementations hit the AMD KDS over
/// HTTPS; tests inject [`FakeVcekFetcher`].
pub trait VcekFetcher: Send + Sync {
    /// Fetch the DER-encoded VCEK certificate chain for `chip_id` at TCB level
    /// `tcb`.
    ///
    /// # Errors
    /// See implementors.
    fn fetch(&self, chip_id: &[u8; 64], tcb: u64) -> Result<Vec<u8>, VcekError>;
}

/// In-memory VCEK cache keyed by `(chip_id, tcb)`. A VCEK is TCB-versioned and
/// long-lived, so the supervisor caches aggressively and refreshes only on TCB
/// change.
pub struct VcekCache<F: VcekFetcher> {
    fetcher: F,
    cache: std::sync::Mutex<CacheMap>,
}

/// Underlying key/value store for [`VcekCache`].
type CacheMap = std::collections::HashMap<([u8; 64], u64), Vec<u8>>;

impl<F: VcekFetcher> VcekCache<F> {
    /// Construct a cache wrapping `fetcher`.
    #[must_use]
    pub fn new(fetcher: F) -> Self {
        Self {
            fetcher,
            cache: std::sync::Mutex::new(CacheMap::new()),
        }
    }

    /// Return the VCEK chain for `(chip_id, tcb)`, fetching + caching on miss.
    ///
    /// # Errors
    /// Propagates [`VcekError`] from the inner [`VcekFetcher`] on a miss.
    pub fn get(&self, chip_id: &[u8; 64], tcb: u64) -> Result<Vec<u8>, VcekError> {
        // Poison recovery: take the inner guard rather than panic. A poisoned
        // mutex means a prior holder panicked; the cache is advisory, so we
        // prefer liveness. (No `expect`/`unwrap` in non-test code.)
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (*chip_id, tcb);
        if let Some(v) = guard.get(&key).cloned() {
            return Ok(v);
        }
        let v = self.fetcher.fetch(chip_id, tcb)?;
        guard.insert(key, v.clone());
        Ok(v)
    }
}

/// A [`VcekCache`] is itself a [`VcekFetcher`]: the provider holds it behind
/// `Arc<dyn VcekFetcher>` and transparently benefits from the cache. On a hit
/// the inner fetcher is never consulted.
impl<F: VcekFetcher> VcekFetcher for VcekCache<F> {
    fn fetch(&self, chip_id: &[u8; 64], tcb: u64) -> Result<Vec<u8>, VcekError> {
        self.get(chip_id, tcb)
    }
}

/// Test double for [`VcekFetcher`] that always returns the same canned bytes.
pub struct FakeVcekFetcher(pub Vec<u8>);

impl VcekFetcher for FakeVcekFetcher {
    fn fetch(&self, _chip_id: &[u8; 64], _tcb: u64) -> Result<Vec<u8>, VcekError> {
        Ok(self.0.clone())
    }
}

/// AMD KDS HTTPS fetcher. Feature-gated behind `kds` so the default crate stays
/// Mac-pure and network-free.
#[cfg(feature = "kds")]
#[derive(Debug, Clone, Copy, Default)]
pub struct KdsVcekFetcher {
    base_url: &'static str,
}

#[cfg(feature = "kds")]
impl KdsVcekFetcher {
    /// Construct a fetcher targeting the production AMD KDS endpoint.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base_url: "https://kdsintf.amd.com/vcek/v1/Milan",
        }
    }

    /// The fully-qualified VCEK URL for `chip_id` (lowercase hex), pinned to
    /// the exact VCEK revision described by `tcb` (`REPORTED_TCB`).
    ///
    /// `TCB_VERSION` byte→SPL mapping (confirmed against Google `go-sev-guest`
    /// `kds.go` `DecomposeTCBVersion` + `VCEKCertURL`, and AMD SEV-SNP FW ABI
    /// §2.3 / KDS spec): the `tcb` u64 — read little-endian from the report
    /// (`snp_report` parses `REPORTED_TCB` with `u64::from_le_bytes`) —
    /// decomposes as big-endian-of-the-numeric-value:
    ///
    /// - bits `[56:64)` (MSB) → `UcodeSpl` → `ucodeSPL`
    /// - bits `[48:56)`       → `SnpSpl`   → `snpSPL`
    /// - bits `[40:48)`..`[16:24)` → Spl7/Spl6/Spl5/Spl4 (reserved, no query param)
    /// - bits `[8:16)`        → `TeeSpl`   → `teeSPL`
    /// - bits `[0:8)`  (LSB)  → `BlSpl`    → `blSPL`
    ///
    /// i.e. for the LE-decoded `tcb`: `blSPL = tcb & 0xff`,
    /// `teeSPL = (tcb >> 8) & 0xff`, `snpSPL = (tcb >> 48) & 0xff`,
    /// `ucodeSPL = (tcb >> 56) & 0xff`. KDS ignores the four reserved SPLs.
    #[allow(clippy::similar_names)]
    fn vcek_url(&self, chip_id: &[u8; 64], tcb: u64) -> String {
        use std::fmt::Write;
        let mut hex = String::with_capacity(128);
        for b in chip_id {
            // Ignore the intra-string formatting error (infallible for String).
            let _ = write!(hex, "{b:02x}");
        }
        let bl_spl = (tcb & 0xff) as u8;
        let tee_spl = ((tcb >> 8) & 0xff) as u8;
        let snp_spl = ((tcb >> 48) & 0xff) as u8;
        let ucode_spl = ((tcb >> 56) & 0xff) as u8;
        format!(
            "{}/{hex}?blSPL={bl_spl}&teeSPL={tee_spl}&snpSPL={snp_spl}&ucodeSPL={ucode_spl}",
            self.base_url
        )
    }
}

#[cfg(feature = "kds")]
#[cfg(test)]
mod kds_url_tests {
    use super::KdsVcekFetcher;

    #[test]
    fn vcek_url_pins_tcb_spls_and_chip_hex() {
        // REPORTED_TCB laid out so every SPL nibble is distinct. We assert the
        // go-sev-guest byte→param mapping holds: LSB→blSPL, +1 byte→teeSPL,
        // +6 bytes→snpSPL, +7 bytes (MSB)→ucodeSPL.
        let tcb: u64 = 0xDD_CC_00_00_00_00_BB_AA; // be: ucode=dd,snp=cc,...,tee=bb,bl=aa
        let chip = [0u8; 64];
        let url = KdsVcekFetcher::new().vcek_url(&chip, tcb);
        assert_eq!(
            url,
            "https://kdsintf.amd.com/vcek/v1/Milan/\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             ?blSPL=170&teeSPL=187&snpSPL=204&ucodeSPL=221"
        );
    }

    #[test]
    fn vcek_url_zero_tcb_emits_all_zero_spls() {
        let url = KdsVcekFetcher::new().vcek_url(&[1u8; 64], 0);
        assert!(url.ends_with("?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0"));
        assert!(url.contains("/01010101"));
    }
}

#[cfg(feature = "kds")]
impl VcekFetcher for KdsVcekFetcher {
    fn fetch(&self, chip_id: &[u8; 64], tcb: u64) -> Result<Vec<u8>, VcekError> {
        use std::io::Read;
        // The VCEK leaf — the only per-chip/per-TCB cert — fetched live from
        // KDS over HTTPS. Transport / HTTP-level failures → Network (not
        // MalformedCert, which is reserved for an unparseable response body).
        let url = self.vcek_url(chip_id, tcb);
        let resp = ureq::get(&url).call().map_err(|_| VcekError::Network)?;
        let mut vcek = Vec::new();
        resp.into_reader()
            .read_to_end(&mut vcek)
            .map_err(|_| VcekError::Network)?;
        // The ASK intermediate — a static AMD Milan product cert (baked, like
        // the ARK); signed by the ARK, signs every VCEK. Embed it leaf-first so
        // `verify_report`'s walk validates VCEK -> ASK -> ARK(root). The ARK
        // root is NOT embedded (it is the gate's anchor, AmdRootCert::milan_default).
        // AMD KDS serves only the VCEK leaf; the ASK + ARK are the genuine baked
        // product certs (see `AMD_MILAN_ASK_DER`).
        Ok([vcek.as_slice(), AMD_MILAN_ASK_DER].concat())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_long_first_doc_paragraph,
    clippy::similar_names
)]
pub mod test_support {
    //! Shared synthetic P-384 cert material + report-signing helpers.
    //!
    //! Reused by `SevSnp` verify tests. All material here is synthetic:
    //! rcgen-minted P-384 ARK/ASK/VCEK + reports signed by the synthetic VCEK.
    //! Nothing is a real AMD-signed artifact.

    use p384::ecdsa::signature::RandomizedSigner;
    use p384::ecdsa::{Signature, SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use rand::rngs::OsRng;
    use rcgen::{CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use x509_cert::der::Decode;

    use super::AmdRootCert;
    use crate::snp_report;

    /// A synthetic VCEK signing key + the VCEK leaf cert DER, plus the
    /// [`AmdRootCert`] whose ARK key signed the chain. Test-only.
    pub struct SyntheticChain {
        /// VCEK ECDSA P-384 signing key — use to sign synthetic reports.
        pub vcek_signing_key: SigningKey,
        /// DER-encoded VCEK leaf certificate, signed by the synthetic ASK.
        pub vcek_leaf_der: Vec<u8>,
        /// DER-encoded synthetic ASK intermediate certificate (P-384 ECDSA,
        /// signed by the synthetic ARK; signs the synthetic VCEK). The real AMD
        /// ASK is RSA-4096; this synthetic P-384 ASK mirrors the 3-cert
        /// ARK→ASK→VCEK *topology* that `verify_report` walks — the real RSA
        /// topology is covered by the baked `AMD_MILAN_ASK_DER` fixture tests.
        /// Embed leaf-first alongside `vcek_leaf_der` for `verify_report`.
        pub ask_der: Vec<u8>,
        /// The ARK root as an [`AmdRootCert`] (built from the synthetic ARK DER).
        pub root: AmdRootCert,
        /// The DER bytes of the synthetic ARK certificate the chain is rooted in.
        /// Use this verbatim as a `SevSnp` policy's `amd_product_root_der` so the
        /// gate re-parses the exact root the chain validates to. (A standalone
        /// accessor cannot reproduce this: each `synthetic_chain()` call mints a
        /// fresh random ARK, so the binding DER must travel with the chain.)
        pub ark_der: Vec<u8>,
    }

    /// Mint a synthetic ARK→ASK→VCEK chain (3-cert P-384 topology) and return
    /// the VCEK signing key, the VCEK leaf DER, the ASK intermediate DER, and
    /// the ARK root.
    ///
    /// This mirrors the real AMD chain's 3-cert walk (ARK self-signed → ASK CA
    /// signed by ARK → VCEK leaf signed by ASK) in pure P-384: `verify_report`
    /// walks `[VCEK, ASK]` leaf-first, verifying VCEK under the ASK key and the
    /// ASK under the ARK root. The real RSA-4096 topology is exercised by the
    /// baked `AMD_MILAN_ARK_DER` / `AMD_MILAN_ASK_DER` fixture tests.
    pub fn synthetic_chain() -> SyntheticChain {
        // ARK: self-signed P-384 CA (the synthetic root).
        let ark_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen ark keygen");
        let mut ark_params =
            CertificateParams::new(vec!["CN=ne-test-ark".to_string()]).expect("rcgen ark params");
        ark_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-ark");
        ark_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ark_cert = ark_params
            .self_signed(&ark_kp)
            .expect("rcgen ark self-signed");
        let ark_der: Vec<u8> = ark_cert.der().to_vec();
        let root = AmdRootCert::from_der(&ark_der).expect("synthetic ARK parses");

        // ASK: intermediate CA, signed by the ARK (real AMD topology — the ASK
        // is a CA one hop below the root).
        let ask_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen ask keygen");
        let mut ask_params =
            CertificateParams::new(vec!["CN=ne-test-ask".to_string()]).expect("rcgen ask params");
        ask_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-ask");
        ask_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ask_cert = ask_params
            .signed_by(&ask_kp, &ark_cert, &ark_kp)
            .expect("rcgen ask signed_by ark");
        let ask_der: Vec<u8> = ask_cert.der().to_vec();

        // VCEK: leaf, signed by the ASK (NOT by the ARK — real AMD topology).
        let vcek_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen vcek keygen");
        let mut vcek_params =
            CertificateParams::new(vec!["CN=ne-test-vcek".to_string()]).expect("rcgen vcek params");
        vcek_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-vcek");
        let vcek_cert = vcek_params
            .signed_by(&vcek_kp, &ask_cert, &ask_kp)
            .expect("rcgen vcek signed_by ask");
        let vcek_leaf_der = vcek_cert.der().to_vec();

        // Recover the P-384 signing key from the VCEK KeyPair's PKCS8 DER so we
        // can sign synthetic reports with the exact key whose public half is in
        // the VCEK cert.
        let vcek_pkcs8 = vcek_kp.serialize_der();
        let vcek_signing_key = SigningKey::from_pkcs8_der(&vcek_pkcs8).expect("vcek pkcs8 load");

        SyntheticChain {
            vcek_signing_key,
            vcek_leaf_der,
            ask_der,
            root,
            ark_der,
        }
    }

    /// Mint a synthetic ARK→ASK→VCEK leaf chain signed by an INDEPENDENT ARK
    /// (different from the one in [`synthetic_chain`]). Used to test the
    /// wrong-issuer path: a structurally valid chain that does NOT validate to
    /// the supplied root. Returns `(vcek_leaf_der, ask_der, signing_key)`.
    pub fn wrong_issuer_vcek_leaf() -> (Vec<u8>, Vec<u8>, SigningKey) {
        let other_ark_kp =
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen ark2 keygen");
        let mut other_ark_params = CertificateParams::new(vec!["CN=ne-test-ark-other".to_string()])
            .expect("rcgen ark2 params");
        other_ark_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-ark-other");
        other_ark_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let other_ark_cert = other_ark_params
            .self_signed(&other_ark_kp)
            .expect("rcgen ark2 self-signed");

        // Independent ASK under the rogue ARK.
        let other_ask_kp =
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen ask2 keygen");
        let mut other_ask_params = CertificateParams::new(vec!["CN=ne-test-ask-other".to_string()])
            .expect("rcgen ask2 params");
        other_ask_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-ask-other");
        other_ask_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let other_ask_cert = other_ask_params
            .signed_by(&other_ask_kp, &other_ark_cert, &other_ark_kp)
            .expect("rcgen ask2 signed_by ark2");
        let ask_der: Vec<u8> = other_ask_cert.der().to_vec();

        // VCEK leaf signed by the rogue ASK.
        let vcek_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("rcgen vcek2 keygen");
        let mut vcek_params = CertificateParams::new(vec!["CN=ne-test-vcek-other".to_string()])
            .expect("rcgen vcek2 params");
        vcek_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ne-test-vcek-other");
        let vcek_cert = vcek_params
            .signed_by(&vcek_kp, &other_ask_cert, &other_ask_kp)
            .expect("rcgen vcek2 signed_by ask2");
        let vcek_leaf_der = vcek_cert.der().to_vec();
        let vcek_pkcs8 = vcek_kp.serialize_der();
        let vcek_signing_key = SigningKey::from_pkcs8_der(&vcek_pkcs8).expect("vcek2 pkcs8 load");
        (vcek_leaf_der, ask_der, vcek_signing_key)
    }

    /// Sign `report`'s signed region with the synthetic VCEK key, writing the
    /// signature in the **true AMD ABI format** (R||S, each a 72-byte
    /// LITTLE-ENDIAN integer: significant 48 bytes first, zero-padded
    /// `[48:72]`) into the trailing 512-byte signature field. Mirrors
    /// `bigIntToAMDRS` from Google `go-sev-guest` `abi.go`.
    pub fn sign_report(report: &mut [u8], vcek_sk: &SigningKey) {
        let signed = snp_report::signed_bytes(report).expect("test report sized correctly");
        let sig: Signature = vcek_sk.sign_with_rng(&mut OsRng, signed);
        let bytes = sig.to_bytes(); // 96 bytes: r(48 BE) || s(48 BE)
        let (r48, s48) = bytes.split_at(48);
        let sig_start = snp_report::SIGNED_LEN;
        let mut field = [0u8; 512];
        // bigIntToAMDRS: take the 48-byte BE scalar, left-pad into a 72-byte
        // BE buffer, then reverse the whole buffer → 72-byte LE field =
        // [LE_scalar(48), zeros(24)].
        let mut r72 = [0u8; 72];
        r72[24..].copy_from_slice(r48);
        r72.reverse();
        let mut s72 = [0u8; 72];
        s72[24..].copy_from_slice(s48);
        s72.reverse();
        field[0x00..0x48].copy_from_slice(&r72);
        field[0x48..0x90].copy_from_slice(&s72);
        report[sig_start..sig_start + 512].copy_from_slice(&field);
    }

    /// Parse a DER cert to confirm it is well-formed (used by test helpers).
    #[allow(dead_code)]
    pub fn _assert_parses(cert_der: &[u8]) -> bool {
        x509_cert::Certificate::from_der(cert_der).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use test_support::SyntheticChain;

    /// Concatenate a synthetic chain leaf-first as `[VCEK, ASK]` — the exact
    /// shape `verify_report` walks (VCEK → ASK → ARK root). Mirrors what
    /// `KdsVcekFetcher::fetch` returns in production (`[VCEK, AMD_MILAN_ASK_DER]`).
    fn chain_with_ask(sc: &SyntheticChain) -> Vec<u8> {
        [sc.vcek_leaf_der.as_slice(), sc.ask_der.as_slice()].concat()
    }

    #[test]
    fn synthetic_report_verifies_under_synthetic_vcek() {
        let sc = test_support::synthetic_chain();
        let mut report = vec![0u8; crate::snp_report::REPORT_SIZE];
        let rd = [0x55u8; 64];
        report[0x50..0x90].copy_from_slice(&rd);
        test_support::sign_report(&mut report, &sc.vcek_signing_key);
        assert!(verify_report(&report, &chain_with_ask(&sc), &sc.root).is_ok());
    }

    #[test]
    fn flipped_signature_byte_is_rejected_as_bad_signature() {
        let sc = test_support::synthetic_chain();
        let mut report = vec![0u8; crate::snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&[0x55u8; 64]);
        test_support::sign_report(&mut report, &sc.vcek_signing_key);
        // Flip one byte inside the R scalar of the AMD signature field.
        let s = crate::snp_report::SIGNED_LEN + 0x20;
        report[s] ^= 0xFF;
        assert_eq!(
            verify_report(&report, &chain_with_ask(&sc), &sc.root),
            Err(VcekError::BadSignature)
        );
    }

    #[test]
    fn wrong_issuer_chain_is_rejected_as_bad_chain() {
        // VCEK signed by a DIFFERENT root than the one we pass in. The rogue
        // chain is itself a well-formed ARK→ASK→VCEK (so the leaf→ASK hop
        // verifies), but the ASK does NOT validate to `sc.root` → BadChain.
        let (rogue_leaf, rogue_ask, rogue_signing_key) = test_support::wrong_issuer_vcek_leaf();
        let sc = test_support::synthetic_chain();
        let mut report = vec![0u8; crate::snp_report::REPORT_SIZE];
        report[0x50..0x90].copy_from_slice(&[0x33u8; 64]);
        test_support::sign_report(&mut report, &rogue_signing_key);
        let rogue_chain = [rogue_leaf.as_slice(), rogue_ask.as_slice()].concat();
        // The report signature is valid under the rogue VCEK, but the chain does
        // NOT validate to `sc.root` → BadChain (never Ok, never BadSignature).
        assert_eq!(
            verify_report(&report, &rogue_chain, &sc.root),
            Err(VcekError::BadChain)
        );
    }

    #[test]
    fn malformed_report_is_rejected() {
        let SyntheticChain {
            vcek_leaf_der,
            root,
            ..
        } = test_support::synthetic_chain();
        let short = vec![0u8; 10];
        assert_eq!(
            verify_report(&short, &vcek_leaf_der, &root),
            Err(VcekError::MalformedCert)
        );
    }

    #[test]
    fn empty_chain_is_bad_chain() {
        let SyntheticChain { root, .. } = test_support::synthetic_chain();
        let report = vec![0u8; crate::snp_report::REPORT_SIZE];
        assert_eq!(verify_report(&report, &[], &root), Err(VcekError::BadChain));
    }

    // ---- Genuine AMD Milan ARK/ASK (public KDS trust material) ----
    // These exercise the REAL RSA-4096 RSASSA-PSS-SHA384 path. The ARK + ASK are
    // public certs fetched from AMD KDS; verifying their signatures is
    // verification-only (no private key). Nothing here claims a hardware-rooted
    // report validates — that is proven on silicon by the hardware integration test.

    #[test]
    fn milan_default_ark_parses_and_matches_pinned_hash() {
        // Pin the genuine Milan ARK SHA-256 (public KDS trust material).
        const PINNED_ARK_SHA256: [u8; 32] = [
            0x69, 0xd0, 0x63, 0xb4, 0x53, 0x44, 0xd2, 0x6a, 0x2e, 0x94, 0xe1, 0xf4, 0x21, 0x0d,
            0xe4, 0x9e, 0xf5, 0x55, 0x30, 0x82, 0x87, 0xd4, 0xc1, 0x74, 0x44, 0x5c, 0x95, 0x63,
            0x9a, 0x54, 0x0b, 0xcd,
        ];
        let root = AmdRootCert::milan_default().expect("Milan ARK must parse");
        assert!(
            matches!(root.verifying_key, PubKey::Rsa(_)),
            "genuine ARK must be RSA-4096, got {:?}",
            root.verifying_key
        );
        let hash = sha2::Sha256::digest(AMD_MILAN_ARK_DER);
        assert_eq!(
            hash.as_slice(),
            &PINNED_ARK_SHA256,
            "baked ARK DER SHA-256 must match the pinned KDS value"
        );
    }

    #[test]
    fn real_milan_ark_self_signature_verifies() {
        // Genuine AMD ARK: its self-signature (RSASSA-PSS-SHA384) must verify
        // under its own RSA-4096 key. Verification-only — no private key.
        let ark = AmdRootCert::milan_default().expect("ARK must parse");
        assert_eq!(
            verify_cert_signature(AMD_MILAN_ARK_DER, &ark.verifying_key),
            Ok(()),
            "genuine ARK self-signature must verify under the ARK RSA key"
        );
    }

    #[test]
    fn real_milan_ask_signature_verifies_under_ark() {
        // Genuine AMD ASK intermediate: signed by the ARK (RSASSA-PSS-SHA384).
        // Its issuer signature must verify under the ARK's RSA-4096 key.
        let ark = AmdRootCert::milan_default().expect("ARK must parse");
        assert_eq!(
            verify_cert_signature(AMD_MILAN_ASK_DER, &ark.verifying_key),
            Ok(()),
            "genuine ASK signature must verify under the ARK RSA key"
        );
    }

    #[test]
    fn golden_amd_le_decode_recovers_scalars_independently() {
        // Golden vector that proves the decoder honors the AMD LITTLE-ENDIAN
        // signature layout WITHOUT going through `sign_report` (so it is not a
        // round-trip tautology). We hand-pick two distinct 48-byte big-endian
        // scalars, render the 144-byte AMD-LE R||S field by hand, then assert
        // the decoder recovers the originals.
        //
        // Both values have a zero top byte so they are comfortably below the
        // P-384 order n and accepted by `Signature::from_slice`.
        let mut r_be = [0u8; 48];
        for (b, i) in r_be.iter_mut().zip(0u8..) {
            *b = (0x0A + (i & 0x0F)) ^ 0x55;
        }
        r_be[0] = 0x00; // ensure < n
        let mut s_be = [0u8; 48];
        for (b, i) in s_be.iter_mut().zip(0u8..) {
            *b = (0x01 + (i & 0x1F)).wrapping_mul(3);
        }
        s_be[0] = 0x00; // ensure < n
        // Render AMD LE: each 72-byte field = reverse([zeros(24) ++ BE_scalar(48)])
        //              = [LE_scalar(48) ++ zeros(24)]. This is an INDEPENDENT
        // rendering from `sign_report`/`amd_le_field_to_be48`.
        let mut sig512 = [0u8; 512];
        let mut r72 = [0u8; 72];
        r72[24..].copy_from_slice(&r_be);
        r72.reverse();
        let mut s72 = [0u8; 72];
        s72[24..].copy_from_slice(&s_be);
        s72.reverse();
        sig512[0x00..0x48].copy_from_slice(&r72);
        sig512[0x48..0x90].copy_from_slice(&s72);

        let decoded = amd_sig_to_p384(&sig512).expect("AMD-LE field must decode");
        let db = decoded.to_bytes(); // 96 bytes r(48 BE) || s(48 BE)
        assert_eq!(
            &db[..48],
            &r_be,
            "decoded R must equal golden R (LE decode)"
        );
        assert_eq!(
            &db[48..],
            &s_be,
            "decoded S must equal golden S (LE decode)"
        );
    }

    #[test]
    fn golden_amd_le_decode_rejects_nonzero_reserved_tail() {
        let mut sig512 = [0u8; 512];
        // Put a minimal valid-looking R in [0x00:0x48] (value 1, LE).
        sig512[0x00] = 0x01;
        sig512[0x48] = 0x01; // S
        sig512[0x90] = 0x01; // reserved [0x90:0x200] must be zero
        assert!(amd_sig_to_p384(&sig512).is_none());
    }

    #[test]
    fn cache_returns_cached_value_on_hit() {
        let canned = vec![0xAB; 32];
        let cache = VcekCache::new(FakeVcekFetcher(canned.clone()));
        let chip = [1u8; 64];
        let first = cache.get(&chip, 7).expect("miss fetch");
        let second = cache.get(&chip, 7).expect("hit fetch");
        assert_eq!(first, canned);
        assert_eq!(second, canned);
    }

    #[test]
    fn cache_distinguishes_keys() {
        let canned = vec![0xCD; 16];
        let cache = VcekCache::new(FakeVcekFetcher(canned));
        let chip_a = [1u8; 64];
        let chip_b = [2u8; 64];
        let a = cache.get(&chip_a, 1).expect("a");
        let b = cache.get(&chip_b, 2).expect("b");
        assert_eq!(a, b); // same canned bytes (FakeVcekFetcher ignores key)
        assert_eq!(a, vec![0xCD; 16]);
    }
}

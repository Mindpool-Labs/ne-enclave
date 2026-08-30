// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! e2e: Azure SEV-SNP real-silicon evidence validation against an external
//! non-production test endpoint (OpenHCL vTPM + TPM Quote).
//!
//! HOST-GATED: requires an Azure DCasv5/ECasv5 SEV-SNP CVM with `tpm2-tools` ≥ 5.2
//! installed (`sudo tpm2_nvread -C o 0x01400001` succeeds — NOT `/dev/sev-guest`,
//! which Azure does not expose) AND an external non-production test endpoint reachable from
//! the CVM with configured TLS files. NOT claimed to pass
//! until exercised on provisioned hardware — `#[ignore]` everywhere without a CVM.
//!
//! This validates Azure real-silicon evidence against a non-production test
//! endpoint, using the **TPM-Quote 2-layer binding**:
//! - Layer 1: the boot-fixed AMD SNP report (read via `tpm2_nvread`) validated to
//!   the baked Milan ARK, with `SHA256(var_data) == report.REPORT_DATA[..32]`
//!   anchoring the vTPM Attestation Key (AK) into the hardware-signed report.
//! - Layer 2: a `tpm2_quote` under the AK (RSA-2048 RSASSA-PKCS1v1.5-SHA256)
//!   whose signature covers a `TPM2B_ATTEST` embedding our per-workspace nonce.
//!
//! TCB = the OpenHCL paravisor + UEFI launch digest (the report's `MEAS`), NOT
//! guest-code measurement. No nested Firecracker microVM is booted.
//!
//! Run manually on a provisioned Azure CVM with a configured test endpoint:
//! ```sh
//! NE_CP_KEY_RELEASE_ENDPOINT=https://<endpoint>/v1 \
//! NE_CP_TLS_CA_CERT=<ca-pem-path> \
//! NE_CP_TLS_CLIENT_CERT=<client-cert-pem-path> \
//! NE_CP_TLS_CLIENT_KEY=<client-key-pem-path> \
//! cargo test -p ne-e2e --test sev_snp_azure -- --ignored --nocapture --test-threads=1
//! ```
//!
//! A pass on a named DCasv5 pinned to the real Milan ARK validates the evidence
//! path and emits genuine fingerprints. It does not select or make a production
//! key-release backend ready.

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use ne_attestation::{
    AttestationProvider, AzureVtpmReportSource, EvidenceRequest, Measurement, Nonce, ProviderType,
    SevSnpProvider,
    vcek::{AMD_MILAN_ARK_DER, AmdRootCert, KdsVcekFetcher, VcekCache, VcekFetcher},
};
use ne_protocol::snapshot::{GuestIdentity, MANIFEST_VERSION, SnapshotManifest};
use ne_seal::key_release_cp::{ControlPlaneKeyReleaseClient, ControlPlaneTlsFiles};
use ne_seal::orchestration::{seal_artifacts, unseal_artifacts};
use ne_seal::types::{KekProvider, SealingPolicy, SealingTrustAnchor};
use sha2::Digest;

fn wall_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `#[ignore]` Azure real-silicon evidence validation against a test endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an Azure DCasv5 CVM + tpm2-tools + an external test endpoint"]
async fn sev_snp_azure_vtpm_key_release_round_trip() {
    // Pre-flight: the Azure path uses the vTPM (NVRAM 0x01400001), NOT
    // /dev/sev-guest. `tpm2_nvread -C o 0x01400001` (POSITIONAL index — tpm2-tools
    // 5.2; the `-i` flag is invalid) MUST succeed: the paravisor wrote the HCLA
    // blob at boot. `/dev/sev-guest` is EXPECTED to be absent on Azure.
    let probe = Command::new("tpm2")
        .args(["nvread", "-C", "o", "0x01400001"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    if !matches!(probe, Ok(o) if o.status.success()) {
        eprintln!(
            "skip: tpm2_nvread 0x01400001 failed — run on a provisioned \
             Azure DCasv5 with tpm2-tools installed (the OpenHCL paravisor must have run)"
        );
        return;
    }
    let endpoint = std::env::var("NE_CP_KEY_RELEASE_ENDPOINT")
        .expect("NE_CP_KEY_RELEASE_ENDPOINT must point at a test endpoint");
    let tls = ControlPlaneTlsFiles {
        ca_cert: std::env::var("NE_CP_TLS_CA_CERT")
            .expect("NE_CP_TLS_CA_CERT must name a CA PEM file")
            .into(),
        client_cert: std::env::var("NE_CP_TLS_CLIENT_CERT")
            .expect("NE_CP_TLS_CLIENT_CERT must name a client certificate PEM file")
            .into(),
        client_key: std::env::var("NE_CP_TLS_CLIENT_KEY")
            .expect("NE_CP_TLS_CLIENT_KEY must name a client key PEM file")
            .into(),
    };
    let api_key = std::env::var("NE_CP_API_KEY").ok();

    // --- SEV-SNP provider + the Azure vTPM source (generate() dispatches to SevSnpAzure) ---
    let azure_source = AzureVtpmReportSource::open().expect("open Azure vTPM source");
    let vcek: Arc<dyn VcekFetcher> = Arc::new(VcekCache::new(KdsVcekFetcher::new()));
    let provider = SevSnpProvider::new_azure(azure_source, vcek);

    // --- External test client ---
    let cp = ControlPlaneKeyReleaseClient::new_mtls(endpoint, api_key, tls, Arc::new(wall_now))
        .expect("mTLS client configuration");
    let cp_wrap: Option<&dyn ne_seal::key_release_cp::CpWrapClient> = Some(&cp);

    // --- Ed25519 host key for seal.json + manifest.json signing ---
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying = signing_key.verifying_key();

    // --- Snapshot dir with plaintext mem/vmstate ---
    let tmp = tempfile::tempdir().expect("tempdir");
    let snap = tmp.path().join("snap");
    tokio::fs::create_dir_all(&snap).await.expect("dir");
    let plaintext_mem = b"AZURE-SILICON-SEALED-MEM";
    let plaintext_vmstate = b"AZURE-SILICON-SEALED-VMSTATE";
    tokio::fs::write(snap.join("mem"), plaintext_mem)
        .await
        .expect("write mem");
    tokio::fs::write(snap.join("vmstate"), plaintext_vmstate)
        .await
        .expect("write vmstate");

    let mut manifest = SnapshotManifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id: "01AZURESILICON".into(),
        created_from_workspace_id: "ws-azure-silicon".into(),
        firecracker_version: "1.7.0".into(),
        mem_sha256: hex_sha256(plaintext_mem),
        vmstate_sha256: hex_sha256(plaintext_vmstate),
        kernel_sha256: "bb".repeat(32),
        rootfs_sha256: "cc".repeat(32),
        guest_identity: GuestIdentity {
            hostname: "h".into(),
            mac: "06:00:00:00:00:01".into(),
            guest_vsock_cid: 3,
            vcpu_count: 1,
            mem_size_mib: 128,
        },
        kernel_boot_args: "console=ttyS0".into(),
        signer_pubkey_b64: String::new(),
        signature_b64: String::new(),
    };

    // --- Sign + persist manifest.json BEFORE sealing ---
    manifest.signer_pubkey_b64 = B64.encode(verifying.as_bytes());
    let manifest_sig = signing_key.sign(
        &manifest
            .canonical_bytes()
            .expect("manifest canonical_bytes"),
    );
    manifest.signature_b64 = B64.encode(manifest_sig.to_bytes());
    tokio::fs::write(
        snap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .await
    .expect("write manifest.json");

    // --- Sealing policy: SevSnp anchor pinned to the BAKED genuine Milan ARK ---
    let policy = SealingPolicy {
        accept_provider_types: vec![ProviderType::SevSnp],
        freshness_seconds: 300,
        trust_anchor: SealingTrustAnchor::SevSnp {
            amd_product_root_der: AMD_MILAN_ARK_DER.to_vec(),
            expected_host_cvm_meas: None,
            min_tcb: 0,
            guest_policy: 0,
        },
        expected_measurement: None,
    };

    // --- Seal via the external test client ---
    let envelope = seal_artifacts(
        &snap,
        &manifest,
        &signing_key,
        policy.clone(),
        KekProvider::ControlPlane,
        cp_wrap,
    )
    .await
    .expect("seal (CP wrap-dek) succeeds");
    eprintln!(
        "sealed snapshot_id={} kek_provider={:?}",
        envelope.snapshot_id, envelope.dek_envelope.kek_provider
    );

    // --- Generate genuine SEV-SNP Azure evidence (2-layer) for fingerprinting.
    // generate() dispatches to generate_azure (azure_source is set), producing
    // Proof::SevSnpAzure. This same path runs inside unseal_artifacts (below). ---
    let nonce = Nonce::new(vec![0xACu8; 32]).expect("nonce");
    let req = EvidenceRequest {
        workspace_id: "ws-azure-silicon".to_string(),
        measurement: Measurement([0u8; 32]),
        nonce: nonce.clone(),
    };
    let evidence = provider
        .generate(&req, wall_now())
        .expect("generate Azure evidence");
    assert_eq!(evidence.provider_type, ProviderType::SevSnp);

    // --- Emit genuine evidence fingerprints ---
    print_fingerprints(&evidence, &envelope);

    // --- Unseal (the restore trust path): fail-fast local gate -> authoritative
    //     CP gate (wasm verify_against_policy on the 2-layer binding) -> DEK ---
    let cp_release: Option<&dyn ne_seal::key_release::ControlPlaneKeyRelease> = Some(&cp);
    let out_mem = tmp.path().join("out_mem");
    let out_vmstate = tmp.path().join("out_vmstate");
    unseal_artifacts(
        &snap,
        &verifying,
        None,
        cp_release,
        &provider,
        "ws-azure-silicon",
        Measurement([0u8; 32]),
        wall_now(),
        &out_mem,
        &out_vmstate,
    )
    .await
    .expect("unseal (CP release-dek) restores the plaintext");

    let restored_mem = tokio::fs::read(&out_mem).await.expect("read restored mem");
    let restored_vmstate = tokio::fs::read(&out_vmstate)
        .await
        .expect("read restored vmstate");
    assert_eq!(
        restored_mem, plaintext_mem,
        "restored mem must be byte-identical"
    );
    assert_eq!(
        restored_vmstate, plaintext_vmstate,
        "restored vmstate must be byte-identical"
    );

    eprintln!(
        "sev_snp_azure_vtpm_key_release_round_trip: PASSED \
         (Azure real-silicon evidence validated through an \
          external non-production test endpoint)"
    );
}

// --- helpers ---

fn hex_sha256(b: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// Print the genuine chip_id, REPORTED_TCB, MEASUREMENT, the AK modulus, the
/// Layer-1 var_data→REPORT_DATA match, the VCEK+ASK chain + ARK SHA-256 — captured
/// by this test. Public, non-secret values.
fn print_fingerprints(
    evidence: &ne_attestation::Evidence,
    envelope: &ne_seal::types::SealEnvelope,
) {
    let ne_attestation::Proof::SevSnpAzure {
        report,
        vcek_cert_chain,
        var_data,
        ak_pub_tpm2b,
        quote_msg,
        quote_sig,
    } = &evidence.proof
    else {
        panic!("expected SevSnpAzure proof");
    };
    let chip_id = report.get(0x1A0..0x1E0).unwrap_or(&[]);
    let reported_tcb = report.get(0x180..0x188).map_or(0u64, |b| {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    });
    let report_data = report.get(0x50..0x90).unwrap_or(&[]);
    let layer1_ok = ne_attestation::sha256_matches_report_data(var_data, report_data);
    eprintln!("=== Azure DCasv5 SEV-SNP (vTPM + TPM Quote) validation fingerprints ===");
    eprintln!("report source: vTPM NVRAM 0x01400001 (OpenHCL paravisor-relayed, boot-fixed)");
    eprintln!("binding: TPM-Quote 2-layer (L1: var_data→REPORT_DATA; L2: AK-signed nonce)");
    eprintln!("chip_id (hex, 64B): {}", hex::encode(chip_id));
    eprintln!("REPORTED_TCB (u64): {reported_tcb} (0x{reported_tcb:016x})");
    eprintln!(
        "REPORT_DATA[..32] (hex): {}",
        hex::encode(&report_data[..32])
    );
    eprintln!("Layer-1 binding (SHA256(var_data)==REPORT_DATA[..32]): {layer1_ok}");
    eprintln!("var_data (JWK) bytes: {}", var_data.len());
    eprintln!("ak_pub_tpm2b bytes: {}", ak_pub_tpm2b.len());
    eprintln!("quote_msg bytes: {} (TPM2B_ATTEST)", quote_msg.len());
    eprintln!("quote_sig bytes: {} (RSASSA-SHA256)", quote_sig.len());
    eprintln!("firmware report SHA-256: {}", hex_sha256(report));
    eprintln!("VCEK+ASK chain SHA-256: {}", hex_sha256(vcek_cert_chain));
    eprintln!("baked Milan ARK SHA-256: {}", hex_sha256(AMD_MILAN_ARK_DER));
    eprintln!("snapshot_id: {}", envelope.snapshot_id);
    eprintln!("=== end fingerprints ===");
    let _ = AmdRootCert::milan_default(); // confirm the baked ARK still parses on-box
}

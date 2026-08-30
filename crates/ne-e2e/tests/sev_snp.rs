// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! e2e: SEV-SNP real-silicon evidence validation against an external
//! non-production test endpoint.
//!
//! HOST-GATED: requires `/dev/sev-guest` + SEV-SNP silicon (Azure `DCasv5`) AND
//! an external test endpoint reachable from the CVM with configured TLS files.
//!
//! NOT claimed to pass until exercised on provisioned hardware — `#[ignore]`
//! everywhere without a CVM.
//!
//! This validates real-silicon evidence against an external non-production test
//! endpoint: a genuine `/dev/sev-guest` `SNP_GET_REPORT` plus a VCEK+ASK chain
//! fetched from the AMD KDS and validated to the baked AMD Milan ARK. It does
//! not validate or claim production hardware-rooted key release.
//!
//! No nested Firecracker microVM is booted: the supervisor's attestation and
//! seal/unseal path are exercised directly.
//!
//! Run manually on a provisioned SEV-SNP host with a configured test endpoint:
//! ```sh
//! NE_CP_KEY_RELEASE_ENDPOINT=https://<endpoint>/v1 \
//! NE_CP_TLS_CA_CERT=<ca-pem-path> \
//! NE_CP_TLS_CLIENT_CERT=<client-cert-pem-path> \
//! NE_CP_TLS_CLIENT_KEY=<client-key-pem-path> \
//! cargo test -p ne-e2e --test sev_snp -- --ignored --nocapture --test-threads=1
//! ```
//!
//! A pass on a named DCasv5 pinned to the real Milan ARK validates the evidence
//! path and emits genuine fingerprints. It does not select or make a production
//! key-release backend ready.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use ne_attestation::{
    AttestationProvider, EvidenceRequest, Measurement, Nonce, ProviderType, SevSnpProvider,
    snp_source::IoctlSnpReportSource,
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

/// `#[ignore]` real-silicon evidence validation against a test endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires /dev/sev-guest + SEV-SNP silicon + an external test endpoint"]
async fn sev_snp_silicon_key_release_round_trip() {
    if !Path::new("/dev/sev-guest").exists() {
        eprintln!("skip: no /dev/sev-guest — run on a provisioned SEV-SNP host");
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

    // --- SEV-SNP provider: real ioctl report source + real KDS VCEK/ASK fetch ---
    // Typed as `Arc<dyn AttestationProvider>` so it coerces to the `&dyn
    // AttestationProvider` param of `unseal_artifacts` and still serves `.generate()`.
    let source = Arc::new(IoctlSnpReportSource::open().expect("open /dev/sev-guest"));
    let vcek: Arc<dyn VcekFetcher> = Arc::new(VcekCache::new(KdsVcekFetcher::new()));
    let provider: Arc<dyn AttestationProvider> = Arc::new(SevSnpProvider::new(source, vcek));

    // --- External test client ---
    // Implements BOTH `CpWrapClient` (seal-time DEK wrap) and
    // `ControlPlaneKeyRelease` (restore-time DEK release).
    let cp = ControlPlaneKeyReleaseClient::new_mtls(endpoint, api_key, tls, Arc::new(wall_now))
        .expect("mTLS client configuration");
    let cp_wrap: Option<&dyn ne_seal::key_release_cp::CpWrapClient> = Some(&cp);

    // --- Ed25519 host key for seal.json + manifest.json signing (self-signed
    //     test key here; the real supervisor uses AuditLog's key — a fresh key is
    //     sufficient to exercise the seal/unseal binding on the CVM). ---
    let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying = signing_key.verifying_key();

    // --- Snapshot dir with plaintext mem/vmstate ---
    let tmp = tempfile::tempdir().expect("tempdir");
    let snap = tmp.path().join("snap");
    tokio::fs::create_dir_all(&snap).await.expect("dir");
    let plaintext_mem = b"SILICON-SEALED-MEM";
    let plaintext_vmstate = b"SILICON-SEALED-VMSTATE";
    tokio::fs::write(snap.join("mem"), plaintext_mem)
        .await
        .expect("write mem");
    tokio::fs::write(snap.join("vmstate"), plaintext_vmstate)
        .await
        .expect("write vmstate");

    let mut manifest = SnapshotManifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id: "01SILICON".into(),
        created_from_workspace_id: "ws-silicon".into(),
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

    // --- Sign + persist manifest.json BEFORE sealing. `unseal_artifacts` reads
    //     `manifest.json` back from disk and verifies its Ed25519 signature
    //     pinned to the host key (orchestration step 1), so it MUST exist and
    //     be signed by the same key that signs seal.json. `seal_artifacts`
    //     binds the seal to THIS manifest struct's canonical hash, so the same
    //     struct is passed to seal below. (Mirrors `SupervisorSealer`'s
    //     caller-writes-manifest contract.) ---
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

    // --- Generate genuine SEV-SNP evidence (real ioctl) for fingerprinting ---
    // (The authoritative gate evidence is minted INSIDE `unseal_artifacts` with
    // its own fresh nonce; this call exists only to emit the genuine
    // chip_id / REPORTED_TCB / chain fingerprints for evidence-validation output.)
    let nonce_bytes = vec![0xABu8; 32];
    let nonce = Nonce::new(nonce_bytes).expect("nonce");
    let req = EvidenceRequest {
        workspace_id: "ws-silicon".to_string(),
        measurement: Measurement([0u8; 32]),
        nonce: nonce.clone(),
    };
    let evidence = provider
        .generate(&req, wall_now())
        .expect("generate SEV-SNP evidence");
    assert_eq!(evidence.provider_type, ProviderType::SevSnp);

    // --- Emit genuine public, non-secret evidence fingerprints ---
    print_fingerprints(&evidence, &envelope);

    // --- Unseal (the restore trust path): fail-fast local gate -> authoritative
    //     CP gate (wasm verify_against_policy on the genuine chain) -> DEK -> decrypt ---
    let cp_release: Option<&dyn ne_seal::key_release::ControlPlaneKeyRelease> = Some(&cp);
    let out_mem = tmp.path().join("out_mem");
    let out_vmstate = tmp.path().join("out_vmstate");
    unseal_artifacts(
        &snap,
        &verifying,
        None, // no SoftwareFallback release — the CP arm is authoritative
        cp_release,
        provider.as_ref(),
        "ws-silicon",
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
        "sev_snp_silicon_key_release_round_trip: PASSED (real-silicon evidence \
         validated through an external non-production test endpoint)"
    );
}

// --- helpers ---

fn hex_sha256(b: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// Print the genuine chip_id, REPORTED_TCB, VCEK+ASK chain + ARK SHA-256 —
/// emitted by this test. Public, non-secret values.
fn print_fingerprints(
    evidence: &ne_attestation::Evidence,
    envelope: &ne_seal::types::SealEnvelope,
) {
    let ne_attestation::Proof::SevSnp {
        report,
        vcek_cert_chain,
    } = &evidence.proof
    else {
        panic!("expected SevSnp proof");
    };
    // chip_id is at report offset 0x1A0 (64 bytes), REPORTED_TCB at 0x180 (u64 LE)
    // (AMD SEV-SNP FW ABI; cross-verified in `ne_attestation::snp_report`).
    let chip_id = report.get(0x1A0..0x1E0).unwrap_or(&[]);
    let reported_tcb = report.get(0x180..0x188).map_or(0u64, |b| {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    });
    let report_hash = hex_sha256(report);
    let chain_hash = hex_sha256(vcek_cert_chain);
    let ark_hash = hex_sha256(AMD_MILAN_ARK_DER);
    eprintln!("=== DCasv5 SEV-SNP validation fingerprints ===");
    eprintln!("chip_id (hex, 64B): {}", hex::encode(chip_id));
    eprintln!("REPORTED_TCB (u64): {reported_tcb} (0x{reported_tcb:016x})");
    eprintln!("firmware report SHA-256: {report_hash}");
    eprintln!("VCEK+ASK chain SHA-256: {chain_hash}");
    eprintln!("baked Milan ARK SHA-256: {ark_hash}");
    eprintln!("snapshot_id: {}", envelope.snapshot_id);
    eprintln!("=== end fingerprints ===");
    let _ = AmdRootCert::milan_default(); // confirm the baked ARK still parses on-box
}

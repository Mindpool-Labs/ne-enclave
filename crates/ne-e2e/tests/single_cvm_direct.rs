// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Host-gated Azure DCasv5 product-wiring e2e for the confidential profile.
//!
//! This test assumes `nee install --execution-profile confidential-azure` has
//! already installed the release candidate. Its primary assertions use only
//! the installed binary, systemd services, and public REST/CLI surfaces:
//! capabilities, create, execute, file I/O, complete Azure evidence, destroy,
//! and audit export/verification. Low-level vTPM fingerprints are emitted only
//! after the product round trip succeeds.
//!
//! Run as root on a provisioned Azure confidential VM:
//! ```sh
//! cargo test -p ne-e2e --features confidential-cvm \
//!   --test single_cvm_direct -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(all(target_os = "linux", feature = "confidential-cvm"))]

use std::os::unix::fs::FileTypeExt as _;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const API: &str = "http://127.0.0.1:8080/v1";
const NEE: &str = "/opt/ne-enclave/bin/nee";

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn checked_output(program: &str, args: &[&str]) -> Output {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run {program} {args:?}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn curl(method: &str, url: &str, body: Option<&str>) -> Vec<u8> {
    let mut command = Command::new("curl");
    command.args(["-fsS", "-X", method, url]);
    if let Some(body) = body {
        command.args(["-H", "content-type: application/json", "-d", body]);
    }
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("curl {method} {url}: {error}"));
    assert!(
        output.status.success(),
        "curl {method} {url} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn curl_json(method: &str, url: &str, body: Option<&str>) -> Value {
    let bytes = curl(method, url, body);
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode JSON from {method} {url}: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct WorkspaceCleanup {
    workspace_id: String,
    armed: bool,
}

impl WorkspaceCleanup {
    fn new(workspace_id: String) -> Self {
        Self {
            workspace_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkspaceCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = Command::new("curl")
                .args([
                    "-fsS",
                    "-X",
                    "DELETE",
                    &format!("{API}/workspaces/{}", self.workspace_id),
                ])
                .status();
        }
    }
}

#[test]
#[ignore = "requires the installed confidential-azure release candidate on Azure DCasv5"]
fn single_cvm_direct_round_trip() {
    assert!(
        !std::path::Path::new("/dev/kvm").exists(),
        "Azure confidential profile must not depend on nested KVM"
    );
    let vtpm = std::fs::metadata("/dev/tpmrm0").expect("/dev/tpmrm0 must exist");
    assert!(
        vtpm.file_type().is_char_device(),
        "/dev/tpmrm0 must be a character device"
    );
    assert!(
        std::path::Path::new(NEE).is_file(),
        "installed nee binary missing at {NEE}"
    );

    checked_output(
        NEE,
        &["doctor", "--execution-profile", "confidential-azure"],
    );
    checked_output("systemctl", &["daemon-reload"]);
    checked_output(
        "systemctl",
        &["restart", "ne-supervisor.service", "ne-api.service"],
    );

    let mut healthy = false;
    for _attempt in 0..60 {
        if Command::new("curl")
            .args(["-fsS", &format!("{API}/host/health")])
            .status()
            .is_ok_and(|status| status.success())
        {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(healthy, "installed API did not become healthy");

    let capabilities = curl_json("GET", &format!("{API}/runtime/capabilities"), None);
    assert_eq!(capabilities["execution_profile"], "confidential-azure");
    assert_eq!(capabilities["execution_backend"], "open_shell");
    assert_eq!(capabilities["attestation_backend"], "sev_snp_azure");
    assert_eq!(capabilities["hard_workspace_capacity"], 1);

    let workspace_id = format!("r1-product-{}", wall_now());
    let mut cleanup = WorkspaceCleanup::new(workspace_id.clone());
    let create = serde_json::json!({
        "workspace_id": workspace_id,
        "kernel_sha256": "",
        "rootfs_sha256": "",
        "rootfs_read_only": true,
        "vcpu_count": 0,
        "mem_size_mib": 0,
        "guest_vsock_cid": 0
    });
    curl(
        "POST",
        &format!("{API}/workspaces"),
        Some(&create.to_string()),
    );

    let exec_body = serde_json::json!({
        "command": "/bin/echo",
        "args": ["r1-product-ok"]
    });
    let mut exec_response = None;
    for _attempt in 0..60 {
        let output = Command::new("curl")
            .args([
                "-fsS",
                "-X",
                "POST",
                "-H",
                "content-type: application/json",
                "-d",
                &exec_body.to_string(),
                &format!("{API}/workspaces/{workspace_id}/exec"),
            ])
            .output()
            .expect("run exec request");
        if output.status.success() {
            exec_response =
                Some(serde_json::from_slice::<Value>(&output.stdout).expect("exec JSON"));
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let exec_response = exec_response.expect("workspace exec never became ready");
    assert!(
        exec_response["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("r1-product-ok"))
    );

    let payload = b"r1-product-file-roundtrip";
    let payload_b64 = BASE64.encode(payload);
    let write = serde_json::json!({
        "path": "r1-proof.txt",
        "content": payload_b64
    });
    curl(
        "PUT",
        &format!("{API}/workspaces/{workspace_id}/files"),
        Some(&write.to_string()),
    );
    let read = curl_json(
        "GET",
        &format!("{API}/workspaces/{workspace_id}/files?path=r1-proof.txt"),
        None,
    );
    assert_eq!(read["content"], payload_b64);

    let nonce = BASE64.encode([0xacu8; 32]);
    let evidence = curl_json(
        "POST",
        &format!("{API}/workspaces/{workspace_id}/attestation"),
        Some(&serde_json::json!({ "nonce": nonce }).to_string()),
    );
    assert_eq!(evidence["provider"], "sev_snp_azure");
    assert_eq!(evidence["proof"]["proof_type"], "sev_snp_azure");
    for field in [
        "report",
        "vcek_cert_chain",
        "var_data",
        "ak_pub_tpm2b",
        "quote_msg",
        "quote_sig",
    ] {
        assert!(
            evidence["proof"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "Azure public proof field {field} is empty"
        );
    }

    curl("DELETE", &format!("{API}/workspaces/{workspace_id}"), None);
    cleanup.disarm();

    let export = checked_output(NEE, &["audit", "export", "--out", "/tmp"]);
    let export_dir = String::from_utf8(export.stdout)
        .expect("audit export path is UTF-8")
        .trim()
        .to_string();
    assert!(!export_dir.is_empty(), "audit export path missing");
    checked_output(NEE, &["audit", "verify", &export_dir]);

    eprintln!("installed confidential product round trip passed");
    eprintln!("  capabilities: {capabilities}");
    eprintln!("  evidence report_data: {}", evidence["report_data"]);

    let nvread = Command::new("tpm2")
        .args(["nvread", "-C", "o", "0x01400001"])
        .output();
    match nvread {
        Ok(output) if output.status.success() => {
            eprintln!(
                "diagnostic HCLA NV blob sha256={}",
                sha256_hex(&output.stdout)
            );
        }
        Ok(output) => eprintln!(
            "diagnostic HCLA NV read failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => eprintln!("diagnostic HCLA NV read unavailable: {error}"),
    }

    let diagnostic_dir = tempfile::tempdir().expect("diagnostic tempdir");
    let ak_path = diagnostic_dir.path().join("ak-public.tss");
    let ak_path_string = ak_path.to_string_lossy().into_owned();
    let ak = Command::new("tpm2")
        .args([
            "readpublic",
            "-c",
            "0x81000003",
            "-f",
            "tss",
            "-o",
            &ak_path_string,
        ])
        .output();
    match ak {
        Ok(output) if output.status.success() => match std::fs::read(&ak_path) {
            Ok(bytes) => eprintln!("diagnostic AK public sha256={}", sha256_hex(&bytes)),
            Err(error) => eprintln!("diagnostic AK public read failed: {error}"),
        },
        Ok(output) => eprintln!(
            "diagnostic AK readpublic failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => eprintln!("diagnostic AK readpublic unavailable: {error}"),
    }
}

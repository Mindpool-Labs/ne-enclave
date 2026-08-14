// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave single fused binary entry point.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cli;

use ne::install;

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // The per-workspace filter/router subcommands write their JSON
    // audit lines to stdout for the supervisor to relay into its
    // signed chain, so their tracing output must go to stderr to keep
    // stdout clean. The serve-* daemons have no such stdout contract
    // and log JSON to stdout.
    match &cli.command {
        // stdout must stay clean for the printed token / verify JSON line,
        // so api-key generate and audit subcommands route tracing to stderr
        // exactly like the audit-line producers.
        Command::DnsFilter(_)
        | Command::PrivacyRouter(_)
        | Command::ApiKey(_)
        | Command::Tls(_)
        | Command::Audit(_)
        | Command::Attestation(_)
        | Command::Runtime(_)
        | Command::Snapshot(_)
        | Command::Pool(_)
        | Command::Workspace(_) => {
            init_tracing_stderr()?;
        }
        Command::ServeApi(_)
        | Command::ServeSupervisor(_)
        | Command::Install(_)
        | Command::Uninstall(_)
        | Command::Doctor(_)
        | Command::Image(_) => init_tracing()?,
    }
    match cli.command {
        Command::ServeApi(a) => {
            let api_keys = match &a.api_key_file {
                Some(path) => std::sync::Arc::new(ne_api::auth::ApiKeyStore::load(path)?),
                None => std::sync::Arc::new(ne_api::auth::ApiKeyStore::default()),
            };
            let tls = match (&a.tls_cert, &a.tls_key) {
                (Some(cert), Some(key)) => Some(ne_api::tls::TlsConfig::from_pem_files(cert, key)?),
                (None, None) => None,
                (Some(_), None) => {
                    anyhow::bail!("--tls-cert was given without --tls-key (both are required)")
                }
                (None, Some(_)) => {
                    anyhow::bail!("--tls-key was given without --tls-cert (both are required)")
                }
            };
            ne_api::serve(ne_api::ApiConfig {
                grpc_bind: a.bind,
                rest_bind: a.rest_bind,
                supervisor_socket: a.supervisor_socket,
                dev_mode: a.dev_mode,
                api_keys,
                tls,
            })
            .await
        }
        Command::ServeSupervisor(a) => {
            install_parent_death_signal();
            let a = *a;
            ne_supervisor::serve::serve(ne_supervisor::serve::SupervisorConfig {
                execution_profile: a.execution_profile,
                socket: a.socket,
                expected_peer_uid: a.expected_peer_uid,
                dev_mode: a.dev_mode,
                firecracker_binary: a.firecracker_binary,
                jailer_binary: a.jailer_binary,
                jailer_chroot_base: a.jailer_chroot_base,
                image_store: a.image_store,
                jailer_uid: a.jailer_uid,
                jailer_gid: a.jailer_gid,
                openshell_sandbox_binary: a.openshell_sandbox_binary,
                api_socket_timeout_ms: a.api_socket_timeout_ms,
                state_dir: a.state_dir,
                max_workspaces: a.max_workspaces,
                max_workspace_mem_mib: a.max_workspace_mem_mib,
                enable_networking: a.enable_networking,
                ip_binary: a.ip_binary,
                iptables_binary: a.iptables_binary,
                upstream_iface: a.upstream_iface,
                dns_filter_binary: a.dns_filter_binary,
                dns_upstream: a.dns_upstream,
                privacy_router_binary: a.privacy_router_binary,
                privacy_router_policy: a.privacy_router_policy,
                warm_pool_tier: a.warm_pool_tier,
                warm_pool_snapshot: a.warm_pool_snapshot,
                warm_pool_size: a.warm_pool_size,
                warm_pool_max_in_flight: a.warm_pool_max_in_flight,
                ingress_domain: a.ingress_domain,
                ingress_listen: a.ingress_listen,
                ingress_max_connections: a.ingress_max_connections,
                ingress_tls_cert: a.ingress_tls_cert,
                ingress_tls_key: a.ingress_tls_key,
            })
            .await
        }
        Command::DnsFilter(a) => {
            let allowlist = ne_dns_filter::Allowlist::new(a.allow);
            ne_dns_filter::run(a.listen, a.upstream, allowlist).await?;
            Ok(())
        }
        Command::PrivacyRouter(a) => {
            ne_privacy_router::run(ne_privacy_router::RouterConfig {
                listen: a.listen,
                policy: a.policy,
                max_body_bytes: a.max_body_bytes,
                emit_audit_stdout: a.emit_audit_stdout,
            })
            .await
        }
        Command::Install(a) => {
            let root = a.prefix.clone().unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            let ne_uid = resolve_ne_uid(a.prefix.is_some());
            install::run::install(install::run::InstallOptions {
                execution_profile: a.execution_profile,
                layout,
                fakeroot: a.prefix.is_some(),
                no_start: a.no_start,
                no_image: a.no_image,
                dry_run: a.dry_run,
                ne_uid,
                openshell_sandbox_source: a.openshell_sandbox_source,
                openshell_policy_rules_source: a.openshell_policy_rules_source,
                openshell_policy_data_source: a.openshell_policy_data_source,
            })
        }
        Command::Doctor(a) => {
            let root = a.prefix.unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            let report = install::run::doctor(&layout, a.execution_profile);
            for c in &report.checks {
                tracing::info!(name = %c.name, ok = c.ok, detail = %c.detail, "preflight check");
            }
            if report.ok() {
                Ok(())
            } else {
                anyhow::bail!("preflight failed")
            }
        }
        Command::Uninstall(a) => {
            let root = a.prefix.clone().unwrap_or_else(|| "/".into());
            let layout = install::layout::Layout::new(root);
            install::run::uninstall(&layout, a.purge, a.prefix.is_some())
        }
        Command::Image(a) => match a.command {
            cli::ImageCommand::Import {
                kernel,
                kernel_sha256,
                rootfs,
                rootfs_sha256,
                prefix,
            } => {
                // Validate the complete pair before either import can mutate the store.
                install::image::validate_sha256(&kernel_sha256)?;
                install::image::validate_sha256(&rootfs_sha256)?;
                let fakeroot = prefix.is_some();
                let root = prefix.unwrap_or_else(|| "/".into());
                let layout = install::layout::Layout::new(root);
                install::run::prepare_image_store(&layout, fakeroot)?;
                install::image::import_artifact(
                    &layout.images_dir(),
                    "kernels",
                    "vmlinux",
                    &kernel,
                    &kernel_sha256,
                )?;
                install::image::import_artifact(
                    &layout.images_dir(),
                    "rootfs",
                    "rootfs.img",
                    &rootfs,
                    &rootfs_sha256,
                )?;
                install::image::harden_store(&layout.images_dir(), fakeroot)?;
                Ok(())
            }
        },
        Command::ApiKey(a) => match a.command {
            cli::ApiKeyCommand::Generate { key_file } => {
                let token = ne::apikey::generate_api_key(&key_file)?;
                // Intentional: token is printed ONCE to stdout for the operator to capture;
                // notices go to stderr so scripts can isolate the token via `$(...)`.
                print_api_key_result(&token, &key_file);
                Ok(())
            }
        },
        Command::Tls(a) => match a.command {
            cli::TlsCommand::GenerateCert {
                out_dir,
                subject_alt_name,
            } => {
                let (cert, key) = ne::tls_cli::generate_cert(&out_dir, &subject_alt_name)?;
                print_tls_generate_cert_result(&cert, &key);
                Ok(())
            }
        },
        Command::Audit(a) => match a.command {
            cli::AuditCommand::Export {
                state_dir,
                out,
                allow_broken,
            } => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let dir = ne::audit_cli::export(&state_dir, &out, allow_broken, now_ms)?;
                print_audit_export_result(&dir);
                Ok(())
            }
            cli::AuditCommand::Verify { path } => ne::audit_cli::verify(&path),
        },
        Command::Attestation(a) => match a.command {
            cli::AttestationCommand::Verify { evidence, policy } => {
                ne::attestation_cli::verify_files(&evidence, &policy)
            }
        },
        Command::Runtime(a) => match a.command {
            cli::RuntimeCommand::Capabilities { endpoint } => {
                use ne_protocol::grpc::runtime::v1::GetRuntimeCapabilitiesRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;

                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let response = client
                    .get_runtime_capabilities(GetRuntimeCapabilitiesRequest {})
                    .await
                    .context("GetRuntimeCapabilities RPC failed")?
                    .into_inner();
                let body = render_runtime_capabilities(&response)?;
                write_cli_output(&body, None)
            }
        },
        Command::Snapshot(a) => match a.command {
            cli::SnapshotCommand::Verify { path } => ne::snapshot_cli::verify(&path).await,
        },
        Command::Pool(a) => match a.command {
            cli::PoolCommand::Status { endpoint } => {
                use ne_protocol::grpc::runtime::v1::GetPoolStatusRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .get_pool_status(GetPoolStatusRequest {})
                    .await
                    .context("GetPoolStatus RPC failed")?
                    .into_inner();
                print_pool_status(
                    resp.configured,
                    &resp.tier,
                    resp.target_size,
                    resp.available,
                    resp.in_flight,
                );
                Ok(())
            }
        },
        Command::Workspace(a) => match a.command {
            cli::WorkspaceCommand::ExposePort {
                workspace_id,
                port,
                headers,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                use ne_protocol::grpc::runtime::v1::{
                    ExposePortRequest, ExposedPort, HeaderInjection,
                };
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .expose_port(ExposePortRequest {
                        workspace_id,
                        port: Some(ExposedPort {
                            port: u32::from(port),
                            inject_headers: headers
                                .into_iter()
                                .map(|(name, value)| HeaderInjection { name, value })
                                .collect(),
                        }),
                    })
                    .await
                    .context("ExposePort RPC failed")?
                    .into_inner();
                print_expose_port_result(&resp.workspace_id, resp.port);
                Ok(())
            }
            cli::WorkspaceCommand::UnexposePort {
                workspace_id,
                port,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::UnexposePortRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .unexpose_port(UnexposePortRequest {
                        workspace_id,
                        port: u32::from(port),
                    })
                    .await
                    .context("UnexposePort RPC failed")?
                    .into_inner();
                print_unexpose_port_result(&resp.workspace_id, resp.port);
                Ok(())
            }
            cli::WorkspaceCommand::Attest {
                workspace_id,
                nonce,
                output,
                out,
                endpoint,
            } => {
                use ne_protocol::grpc::runtime::v1::GetAttestationEvidenceRequest;
                use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
                let nonce_bytes = if let Some(hexstr) = nonce {
                    hex::decode(&hexstr).context("nonce must be valid hex")?
                } else {
                    use rand::RngCore;
                    let mut b = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut b);
                    b.to_vec()
                };
                let mut client = RuntimeClient::connect(endpoint)
                    .await
                    .context("connecting to Enclave API gRPC endpoint")?;
                let resp = client
                    .get_attestation_evidence(GetAttestationEvidenceRequest {
                        workspace_id,
                        nonce: nonce_bytes,
                    })
                    .await
                    .context("GetAttestationEvidence RPC failed")?
                    .into_inner();
                let body = render_attestation_evidence(&resp, output)?;
                write_cli_output(&body, out.as_deref())
            }
        },
    }
}

/// Print the audit export result to the operator.
///
/// The export directory path is emitted to stdout so it can be captured by
/// scripts; the human notice goes to stderr.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_audit_export_result(dir: &std::path::Path) {
    eprintln!("exported to {}", dir.display());
    println!("{}", dir.display());
}

/// Print the generated API key result to the operator.
///
/// The token is emitted to stdout exactly once so the operator can capture it
/// with `$(…)` or shell redirection. All notices go to stderr to keep stdout
/// clean for scripting.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_api_key_result(token: &str, key_file: &std::path::Path) {
    eprintln!("API key generated. Store it now \u{2014} it is shown only once:");
    println!("{token}");
    eprintln!("Hash appended to {}", key_file.display());
}

/// Print the warm-pool status from `nee pool status`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_pool_status(
    configured: bool,
    tier: &str,
    target_size: u32,
    available: u32,
    in_flight: u32,
) {
    println!(
        "configured={} tier={} target={} available={} in_flight={}",
        configured,
        if tier.is_empty() { "-" } else { tier },
        target_size,
        available,
        in_flight,
    );
}

/// Print the TLS generate-cert result to the operator.
///
/// The cert and key paths are emitted to stdout so they can be captured by
/// scripts; the human warning goes to stderr to keep stdout clean.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn print_tls_generate_cert_result(cert: &std::path::Path, key: &std::path::Path) {
    eprintln!("DEV/TEST ONLY \u{2014} self-signed, not for production.");
    println!("{}", cert.display());
    println!("{}", key.display());
}

/// Print the result of `nee workspace expose-port`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_expose_port_result(workspace_id: &str, port: u32) {
    println!("exposed {workspace_id}:{port}");
}

/// Print the result of `nee workspace unexpose-port`.
///
/// Output goes to stdout so operators and scripts can capture it directly.
#[allow(clippy::print_stdout)]
fn print_unexpose_port_result(workspace_id: &str, port: u32) {
    println!("unexposed {workspace_id}:{port}");
}

fn render_attestation_evidence(
    response: &ne_protocol::grpc::runtime::v1::GetAttestationEvidenceResponse,
    output: cli::EvidenceOutput,
) -> Result<String> {
    match output {
        cli::EvidenceOutput::Summary => {
            let lines = attestation_evidence_lines(
                response.public_evidence.as_ref(),
                legacy_attestation_evidence(response),
            )?;
            Ok(format!("{}\n", lines.join("\n")))
        }
        cli::EvidenceOutput::Json => {
            let public = response.public_evidence.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "runtime did not return versioned public evidence; upgrade the runtime before exporting JSON"
                )
            })?;
            let public = ne_protocol::PublicAttestationEvidence::try_from(public.clone())
                .context("invalid public attestation evidence returned by runtime")?;
            Ok(format!("{}\n", serde_json::to_string_pretty(&public)?))
        }
    }
}

fn attestation_evidence_lines(
    public: Option<&ne_protocol::grpc::runtime::v1::PublicAttestationEvidence>,
    legacy: Option<&ne_protocol::grpc::runtime::v1::AttestationEvidence>,
) -> Result<Vec<String>> {
    if let Some(evidence) = public {
        let evidence = ne_protocol::PublicAttestationEvidence::try_from(evidence.clone())
            .context("invalid public attestation evidence returned by runtime")?;
        let provider = match evidence.provider {
            ne_protocol::PublicAttestationProvider::Software => "software",
            ne_protocol::PublicAttestationProvider::SevSnpDirect => "sev_snp_direct",
            ne_protocol::PublicAttestationProvider::SevSnpAzure => "sev_snp_azure",
        };
        return Ok(vec![
            format!("provider:    {provider}"),
            format!("workspace:   {}", evidence.workspace_id),
            format!(
                "measurement: {}",
                hex::encode(evidence.workspace_measurement)
            ),
            format!("nonce:       {}", hex::encode(evidence.nonce)),
            format!("issued_at:   {}", evidence.issued_at),
        ]);
    }
    if let Some(evidence) = legacy {
        return Ok(vec![
            format!("provider:    {}", evidence.provider_type),
            format!("workspace:   {}", evidence.workspace_id),
            format!("measurement: {}", hex::encode(&evidence.measurement)),
            format!("nonce:       {}", hex::encode(&evidence.nonce)),
            format!("issued_at:   {}", evidence.issued_at),
        ]);
    }
    Ok(vec!["(no evidence returned)".to_string()])
}

fn render_runtime_capabilities(
    response: &ne_protocol::grpc::runtime::v1::GetRuntimeCapabilitiesResponse,
) -> Result<String> {
    use ne_protocol::grpc::runtime::v1 as pb;
    use ne_protocol::profile::{
        AttestationBackend, ExecutionBackend, ExecutionProfile, RuntimeCapabilitiesInfo,
        WorkspaceOperation,
    };

    let execution_profile = match pb::ExecutionProfile::try_from(response.execution_profile) {
        Ok(pb::ExecutionProfile::Standard) => ExecutionProfile::Standard,
        Ok(pb::ExecutionProfile::ConfidentialAzure) => ExecutionProfile::ConfidentialAzure,
        Ok(pb::ExecutionProfile::Unspecified) | Err(_) => {
            anyhow::bail!(
                "runtime returned invalid execution profile value {}",
                response.execution_profile
            )
        }
    };
    let execution_backend = match pb::ExecutionBackend::try_from(response.execution_backend) {
        Ok(pb::ExecutionBackend::Firecracker) => ExecutionBackend::Firecracker,
        Ok(pb::ExecutionBackend::OpenShell) => ExecutionBackend::OpenShell,
        Ok(pb::ExecutionBackend::Unspecified) | Err(_) => {
            anyhow::bail!(
                "runtime returned invalid execution backend value {}",
                response.execution_backend
            )
        }
    };
    let attestation_backend = match pb::AttestationBackend::try_from(response.attestation_backend) {
        Ok(pb::AttestationBackend::Software) => AttestationBackend::Software,
        Ok(pb::AttestationBackend::SevSnpDirect) => AttestationBackend::SevSnpDirect,
        Ok(pb::AttestationBackend::SevSnpAzure) => AttestationBackend::SevSnpAzure,
        Ok(pb::AttestationBackend::Unspecified) | Err(_) => {
            anyhow::bail!(
                "runtime returned invalid attestation backend value {}",
                response.attestation_backend
            )
        }
    };
    let supported_operations = response
        .supported_operations
        .iter()
        .map(|value| match pb::WorkspaceOperation::try_from(*value) {
            Ok(pb::WorkspaceOperation::Create) => Ok(WorkspaceOperation::Create),
            Ok(pb::WorkspaceOperation::Destroy) => Ok(WorkspaceOperation::Destroy),
            Ok(pb::WorkspaceOperation::Execute) => Ok(WorkspaceOperation::Execute),
            Ok(pb::WorkspaceOperation::WriteFile) => Ok(WorkspaceOperation::WriteFile),
            Ok(pb::WorkspaceOperation::ReadFile) => Ok(WorkspaceOperation::ReadFile),
            Ok(pb::WorkspaceOperation::Pause) => Ok(WorkspaceOperation::Pause),
            Ok(pb::WorkspaceOperation::Resume) => Ok(WorkspaceOperation::Resume),
            Ok(pb::WorkspaceOperation::Snapshot) => Ok(WorkspaceOperation::Snapshot),
            Ok(pb::WorkspaceOperation::Restore) => Ok(WorkspaceOperation::Restore),
            Ok(pb::WorkspaceOperation::Fork) => Ok(WorkspaceOperation::Fork),
            Ok(pb::WorkspaceOperation::WarmPool) => Ok(WorkspaceOperation::WarmPool),
            Ok(pb::WorkspaceOperation::Ingress) => Ok(WorkspaceOperation::Ingress),
            Ok(pb::WorkspaceOperation::Attest) => Ok(WorkspaceOperation::Attest),
            Ok(pb::WorkspaceOperation::Unspecified) | Err(_) => {
                Err(anyhow::anyhow!("invalid workspace operation value {value}"))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let capabilities = RuntimeCapabilitiesInfo {
        runtime_version: response.runtime_version.clone(),
        execution_profile,
        execution_backend,
        attestation_backend,
        supported_operations,
        hard_workspace_capacity: response.hard_workspace_capacity,
        confidential_snapshot_supported: response.confidential_snapshot_supported,
        evidence_schema_version: response.evidence_schema_version,
    };
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&capabilities)?
    ))
}

#[allow(clippy::print_stdout)]
fn write_cli_output(body: &str, out: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = out {
        std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
    } else {
        print!("{body}");
    }
    Ok(())
}

#[allow(deprecated)]
fn legacy_attestation_evidence(
    response: &ne_protocol::grpc::runtime::v1::GetAttestationEvidenceResponse,
) -> Option<&ne_protocol::grpc::runtime::v1::AttestationEvidence> {
    response.evidence.as_ref()
}

/// Resolve the uid of the `ne` service account for the Install dispatch.
/// Under fakeroot (`--prefix`) return a deterministic test uid (991).
/// On real Linux installs the user is created inside `install()` before this
/// value is needed for rendering; the returned value here is only the initial
/// seed — `install()` re-resolves the uid after `ensure_service_user`.
fn resolve_ne_uid(fakeroot: bool) -> u32 {
    if fakeroot {
        return 991; // deterministic for tests
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(Some(u)) = nix::unistd::User::from_name("ne") {
            return u.uid.as_raw();
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn install_parent_death_signal() {
    if let Err(e) = nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGTERM)) {
        tracing::warn!("PR_SET_PDEATHSIG failed: {e} (supervisor may outlive its parent)");
    }
}

#[cfg(not(target_os = "linux"))]
fn install_parent_death_signal() {}

fn init_tracing() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Route human-readable tracing to stderr so stdout stays clean for
/// the JSON audit decision lines the supervisor relays into its signed
/// chain (`relay_dns_audit_lines` / `relay_privacy_audit_lines`). Used
/// by the `dns-filter` and `privacy-router` subcommands.
fn init_tracing_stderr() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .json()
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod attestation_output_tests {
    use super::*;
    use crate::cli::EvidenceOutput;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use ne_attestation::{
        AttestationProvider as _, EvidenceRequest, Measurement, Nonce, SoftwareProvider,
    };
    use ne_protocol::grpc::runtime::v1 as pb;

    fn public_software_evidence() -> pb::PublicAttestationEvidence {
        pb::PublicAttestationEvidence {
            schema_version: 1,
            provider: pb::AttestationProvider::Software as i32,
            workspace_id: "ws-public".into(),
            workspace_measurement: vec![0x11; 32],
            nonce: vec![0x22; 16],
            issued_at: 1_700_000_011,
            report_data: vec![0x33],
            proof: Some(pb::public_attestation_evidence::Proof::Software(
                pb::SoftwareProof {
                    signature: vec![0x44; 64],
                    signer_pubkey: vec![0x55; 32],
                },
            )),
        }
    }

    fn legacy_evidence() -> pb::AttestationEvidence {
        pb::AttestationEvidence {
            provider_type: "software".into(),
            workspace_id: "ws-legacy".into(),
            measurement: vec![0x66; 32],
            nonce: vec![0x77; 16],
            issued_at: 1_700_000_012,
            report_data: vec![0x88],
            proof: Some(pb::AttestationProof {
                signature: vec![0x99; 64],
                signer_pubkey: vec![0xaa; 32],
                sev_snp_report: Vec::new(),
                sev_snp_vcek_chain: Vec::new(),
            }),
        }
    }

    #[test]
    fn attestation_output_prefers_public_evidence() {
        let public = public_software_evidence();
        let legacy = legacy_evidence();

        let lines =
            attestation_evidence_lines(Some(&public), Some(&legacy)).expect("valid evidence");

        assert_eq!(lines[0], "provider:    software");
        assert_eq!(lines[1], "workspace:   ws-public");
        assert_eq!(
            lines[2],
            format!("measurement: {}", hex::encode([0x11; 32]))
        );
    }

    #[test]
    fn attestation_output_falls_back_to_legacy_evidence() {
        let legacy = legacy_evidence();

        let lines = attestation_evidence_lines(None, Some(&legacy)).expect("legacy evidence");

        assert_eq!(lines[0], "provider:    software");
        assert_eq!(lines[1], "workspace:   ws-legacy");
        assert_eq!(
            lines[2],
            format!("measurement: {}", hex::encode([0x66; 32]))
        );
    }

    #[test]
    #[allow(deprecated)]
    fn attestation_json_output_preserves_complete_azure_proof() {
        let response = pb::GetAttestationEvidenceResponse {
            evidence: None,
            public_evidence: Some(pb::PublicAttestationEvidence {
                schema_version: 1,
                provider: pb::AttestationProvider::SevSnpAzure as i32,
                workspace_id: "ws-azure".into(),
                workspace_measurement: vec![0x11; 32],
                nonce: vec![0x22; 16],
                issued_at: 1_700_000_013,
                report_data: vec![0x33],
                proof: Some(pb::public_attestation_evidence::Proof::SevSnpAzure(
                    pb::SevSnpAzureProof {
                        report: vec![1],
                        vcek_cert_chain: vec![2],
                        var_data: vec![3],
                        ak_pub_tpm2b: vec![4],
                        quote_msg: vec![5],
                        quote_sig: vec![6],
                    },
                )),
            }),
        };

        let body =
            render_attestation_evidence(&response, EvidenceOutput::Json).expect("render JSON");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["provider"], "sev_snp_azure");
        assert_eq!(json["proof"]["proof_type"], "sev_snp_azure");
        assert_eq!(
            json["proof"]["var_data"],
            base64::prelude::BASE64_STANDARD.encode([3])
        );
        assert_eq!(
            json["proof"]["ak_pub_tpm2b"],
            base64::prelude::BASE64_STANDARD.encode([4])
        );
        assert_eq!(
            json["proof"]["quote_msg"],
            base64::prelude::BASE64_STANDARD.encode([5])
        );
        assert_eq!(
            json["proof"]["quote_sig"],
            base64::prelude::BASE64_STANDARD.encode([6])
        );
    }

    #[test]
    #[allow(deprecated)]
    fn attestation_json_output_requires_versioned_public_evidence() {
        let response = pb::GetAttestationEvidenceResponse {
            evidence: Some(legacy_evidence()),
            public_evidence: None,
        };

        let error = render_attestation_evidence(&response, EvidenceOutput::Json)
            .expect_err("legacy envelope is incomplete for JSON export");
        assert!(error.to_string().contains("versioned public evidence"));
    }

    #[test]
    fn capabilities_json_uses_stable_public_names() {
        let response = pb::GetRuntimeCapabilitiesResponse {
            runtime_version: "0.2.0".into(),
            execution_profile: pb::ExecutionProfile::ConfidentialAzure as i32,
            execution_backend: pb::ExecutionBackend::OpenShell as i32,
            attestation_backend: pb::AttestationBackend::SevSnpAzure as i32,
            supported_operations: vec![
                pb::WorkspaceOperation::Create as i32,
                pb::WorkspaceOperation::Attest as i32,
            ],
            hard_workspace_capacity: Some(1),
            confidential_snapshot_supported: false,
            evidence_schema_version: 1,
        };

        let body = render_runtime_capabilities(&response).expect("render capabilities");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["execution_profile"], "confidential-azure");
        assert_eq!(json["execution_backend"], "open_shell");
        assert_eq!(json["attestation_backend"], "sev_snp_azure");
        assert_eq!(
            json["supported_operations"],
            serde_json::json!(["create", "attest"])
        );
        assert_eq!(json["hard_workspace_capacity"], 1);
    }

    #[test]
    #[allow(deprecated)]
    fn exported_json_verifies_offline() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time")
            .as_secs();
        let now = i64::try_from(now).expect("timestamp fits i64");
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let signer = signing_key.verifying_key();
        let domain = SoftwareProvider::new(signing_key)
            .generate(
                &EvidenceRequest {
                    workspace_id: "secret-1".into(),
                    measurement: Measurement([0x11; 32]),
                    nonce: Nonce::new(vec![0xaa; 16]).expect("valid nonce"),
                },
                now,
            )
            .expect("generate evidence");
        let public =
            ne_protocol::PublicAttestationEvidence::try_from(domain).expect("domain -> public");
        let response = pb::GetAttestationEvidenceResponse {
            evidence: None,
            public_evidence: Some(
                pb::PublicAttestationEvidence::try_from(public).expect("public -> protobuf"),
            ),
        };
        let body =
            render_attestation_evidence(&response, EvidenceOutput::Json).expect("render JSON");

        let dir = tempfile::tempdir().expect("tempdir");
        let evidence_path = dir.path().join("evidence.json");
        let policy_path = dir.path().join("policy.json");
        write_cli_output(&body, Some(&evidence_path)).expect("write evidence");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "accepted_providers": ["software"],
                "expected_workspace_id": "secret-1",
                "expected_nonce_hex": "aa".repeat(16),
                "freshness_seconds": 300,
                "expected_workspace_measurement_hex": null,
                "expected_host_cvm_measurement_hex": null,
                "expected_signer_b64": base64::prelude::BASE64_STANDARD.encode(signer.as_bytes()),
                "min_tcb": "0",
                "guest_policy": "0"
            }))
            .expect("policy JSON"),
        )
        .expect("write policy");

        ne::attestation_cli::verify_files(&evidence_path, &policy_path)
            .expect("exported evidence verifies offline");
    }
}

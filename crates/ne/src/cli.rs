// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! `nee` command-line surface. Each subcommand maps to a library
//! entrypoint in the corresponding crate.
// Items are `pub` so clap's derive macros see them, but they live in a
// private `mod cli` so they can't be named from outside the crate.
#![allow(unreachable_pub)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use ne_privacy_router::proxy::DEFAULT_MAX_BODY_BYTES;

const DEFAULT_IMAGE_STORE: &str = "/var/lib/ne-enclave/images";

#[derive(Debug, Parser)]
#[command(name = "nee", version, about = "NeuronEdge Enclave runtime")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the unprivileged API front door (gRPC + REST).
    ServeApi(ServeApiArgs),
    /// Run the privileged supervisor.
    ServeSupervisor(Box<ServeSupervisorArgs>),
    /// Run a per-workspace DNS filter (spawned by the supervisor).
    DnsFilter(DnsFilterArgs),
    /// Run a per-workspace privacy router (spawned by the supervisor).
    PrivacyRouter(PrivacyRouterArgs),
    /// Provision the host (user/dirs/config/units/image) and enable units.
    Install(InstallArgs),
    /// Reverse an install (stop/disable units; optionally purge state).
    Uninstall(UninstallArgs),
    /// Run preflight checks and print a report.
    Doctor(DoctorArgs),
    /// Manage guest images.
    Image(ImageArgs),
    /// Manage runtime API keys.
    ApiKey(ApiKeyArgs),
    /// Export and verify the signed audit chain.
    Audit(AuditArgs),
    /// Verify exported attestation evidence offline.
    Attestation(AttestationArgs),
    /// Inspect runtime capabilities.
    Runtime(RuntimeArgs),
    /// Generate a self-signed TLS cert for dev/test (NOT for production).
    Tls(TlsArgs),
    /// Inspect and verify snapshot artifacts.
    Snapshot(SnapshotArgs),
    /// Inspect the warm pool.
    Pool(PoolArgs),
    /// Manage host-based ingress routing for a workspace.
    Workspace(WorkspaceArgs),
}

#[derive(Debug, Parser)]
pub struct ServeApiArgs {
    /// TCP bind address for the gRPC server. SDK clients connect here.
    #[arg(long, env = "NE_API_BIND", default_value = "127.0.0.1:50051")]
    pub bind: SocketAddr,

    /// TCP bind address for the REST gateway.
    #[arg(long, env = "NE_REST_BIND", default_value = "127.0.0.1:8080")]
    pub rest_bind: SocketAddr,

    /// Path to the privileged supervisor's unix socket.
    #[arg(
        long,
        env = "NE_SUPERVISOR_SOCKET",
        default_value = "/run/ne-enclave/supervisor.sock"
    )]
    pub supervisor_socket: PathBuf,

    /// Disable caller authentication (`NE_DEV_MODE=1`).
    #[arg(long, env = "NE_DEV_MODE", action = ArgAction::SetTrue)]
    pub dev_mode: bool,

    /// Path to the API key file (sha256:<hex> per line). Required unless
    /// --dev-mode is set.
    #[arg(long, env = "NE_API_KEY_FILE")]
    pub api_key_file: Option<PathBuf>,

    /// Path to the server TLS certificate chain (PEM). Enables in-process
    /// TLS when set together with --tls-key.
    #[arg(long, env = "NE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// Path to the server TLS private key (PEM). Required with --tls-cert.
    #[arg(long, env = "NE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ServeSupervisorArgs {
    /// Execution and attestation profile for this supervisor.
    #[arg(
        long,
        env = "NE_EXECUTION_PROFILE",
        default_value = "standard",
        value_parser = parse_execution_profile
    )]
    pub execution_profile: ne_protocol::profile::ExecutionProfile,

    /// Path to the unix domain socket the API daemon connects on.
    #[arg(
        long,
        env = "NE_SUPERVISOR_SOCKET",
        default_value = "/run/ne-enclave/supervisor.sock"
    )]
    pub socket: PathBuf,

    /// Expected UID of the API daemon. Required in production.
    #[arg(long, env = "NE_SUPERVISOR_PEER_UID")]
    pub expected_peer_uid: Option<u32>,

    /// Disable peer-credential authentication (`NE_DEV_MODE=1`).
    #[arg(long, env = "NE_DEV_MODE", action = ArgAction::SetTrue)]
    pub dev_mode: bool,

    /// Path to the Firecracker binary on the host.
    #[arg(
        long,
        env = "NE_FIRECRACKER_BIN",
        default_value = "/opt/ne-enclave/bin/firecracker"
    )]
    pub firecracker_binary: PathBuf,

    /// Path to the jailer binary on the host.
    #[arg(
        long,
        env = "NE_JAILER_BIN",
        default_value = "/opt/ne-enclave/bin/jailer"
    )]
    pub jailer_binary: PathBuf,

    /// Base directory under which jailer creates per-workspace chroots.
    #[arg(long, env = "NE_JAILER_CHROOT_BASE", default_value = "/srv/jailer")]
    pub jailer_chroot_base: PathBuf,

    /// Supervisor-owned content-addressed kernel and rootfs image store.
    #[arg(
        long,
        env = "NE_IMAGE_STORE",
        default_value = DEFAULT_IMAGE_STORE
    )]
    pub image_store: PathBuf,

    /// UID that jailer drops Firecracker to.
    #[arg(long, env = "NE_JAILER_UID", default_value_t = 1000)]
    pub jailer_uid: u32,

    /// GID that jailer drops Firecracker to.
    #[arg(long, env = "NE_JAILER_GID", default_value_t = 1000)]
    pub jailer_gid: u32,

    /// Path to the `openshell-sandbox` binary on the host.
    ///
    /// Only used by the `confidential-azure` execution profile. The supervisor
    /// spawns this binary as a subprocess per workspace and controls it over
    /// SSH. Unused by the standard (Firecracker) profile.
    #[arg(
        long,
        env = "NE_OPENSHELL_SANDBOX_BIN",
        default_value = "/opt/ne-enclave/bin/openshell-sandbox"
    )]
    pub openshell_sandbox_binary: PathBuf,

    /// Milliseconds to wait for Firecracker's API socket to appear.
    #[arg(long, env = "NE_API_SOCKET_TIMEOUT_MS", default_value_t = 10_000)]
    pub api_socket_timeout_ms: u64,

    /// Persistent state directory.
    #[arg(long, env = "NE_STATE_DIR", default_value = "/var/lib/ne-enclave")]
    pub state_dir: PathBuf,

    /// Max concurrent workspaces (0 = derive from host RAM). Soft ceiling —
    /// an exhaustion backstop, not a hard quota.
    #[arg(long, env = "NE_MAX_WORKSPACES", default_value_t = 0)]
    pub max_workspaces: usize,

    /// Max `mem_size_mib` per workspace (0 = min(host RAM, 32768)).
    #[arg(long, env = "NE_MAX_WORKSPACE_MEM_MIB", default_value_t = 0)]
    pub max_workspace_mem_mib: u32,

    /// Enable per-workspace network plumbing.
    #[arg(long, env = "NE_ENABLE_NETWORKING", action = ArgAction::SetTrue)]
    pub enable_networking: bool,

    /// Path to the `ip` binary (iproute2).
    #[arg(long, env = "NE_IP_BIN", default_value = "/usr/sbin/ip")]
    pub ip_binary: PathBuf,

    /// Path to the `iptables` binary.
    #[arg(long, env = "NE_IPTABLES_BIN", default_value = "/usr/sbin/iptables")]
    pub iptables_binary: PathBuf,

    /// Upstream interface MASQUERADE rules use for egress.
    #[arg(long, env = "NE_UPSTREAM_IFACE", default_value = "eth0")]
    pub upstream_iface: String,

    /// Optional path to the fused `nee` binary used as the DNS filter.
    #[arg(long, env = "NE_DNS_FILTER_BIN")]
    pub dns_filter_binary: Option<PathBuf>,

    /// Upstream resolver the per-workspace DNS filter forwards queries to.
    #[arg(long, env = "NE_DNS_UPSTREAM", default_value = "1.1.1.1:53")]
    pub dns_upstream: String,

    /// Optional path to the fused `nee` binary used as the privacy router.
    #[arg(long, env = "NE_PRIVACY_ROUTER_BIN")]
    pub privacy_router_binary: Option<PathBuf>,

    /// Path to the host-global PII policy YAML the privacy router enforces.
    #[arg(long, env = "NE_PRIVACY_ROUTER_POLICY")]
    pub privacy_router_policy: Option<PathBuf>,

    /// Warm-pool tier name. Enables the pool when set together with
    /// --warm-pool-snapshot and --warm-pool-size.
    #[arg(long, env = "NE_WARM_POOL_TIER")]
    pub warm_pool_tier: Option<String>,
    /// Base snapshot id every pool member is forked from.
    #[arg(long, env = "NE_WARM_POOL_SNAPSHOT")]
    pub warm_pool_snapshot: Option<String>,
    /// Target number of ready members (0 = pool disabled).
    #[arg(long, env = "NE_WARM_POOL_SIZE", default_value_t = 0)]
    pub warm_pool_size: usize,
    /// Max concurrent in-flight provisions during refill.
    #[arg(long, env = "NE_WARM_POOL_MAX_IN_FLIGHT", default_value_t = 2)]
    pub warm_pool_max_in_flight: usize,

    /// Ingress domain (e.g. `apps.example.com`). Enables the in-process
    /// ingress edge when set together with appropriate TLS or --dev-mode.
    #[arg(long, env = "NE_INGRESS_DOMAIN")]
    pub ingress_domain: Option<String>,
    /// TCP address the ingress edge listens on.
    #[arg(long, env = "NE_INGRESS_LISTEN", default_value = "0.0.0.0:443")]
    pub ingress_listen: SocketAddr,
    /// Maximum concurrent in-flight ingress connections. Excess connections
    /// wait in the kernel accept backlog until a slot frees (flood backstop).
    #[arg(long, env = "NE_INGRESS_MAX_CONNECTIONS", default_value_t = 1024)]
    pub ingress_max_connections: usize,
    /// Path to the ingress TLS certificate chain (PEM).
    #[arg(long, env = "NE_INGRESS_TLS_CERT")]
    pub ingress_tls_cert: Option<PathBuf>,
    /// Path to the ingress TLS private key (PEM).
    #[arg(long, env = "NE_INGRESS_TLS_KEY")]
    pub ingress_tls_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct DnsFilterArgs {
    /// Address to bind the UDP listener on.
    #[arg(long, env = "NE_DNS_LISTEN")]
    pub listen: SocketAddr,

    /// Upstream resolver to forward allowed queries to.
    #[arg(long, env = "NE_DNS_UPSTREAM", default_value = "1.1.1.1:53")]
    pub upstream: SocketAddr,

    /// Allowlist entry — repeatable.
    #[arg(long = "allow", value_name = "HOSTNAME")]
    pub allow: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct PrivacyRouterArgs {
    /// Address to bind the HTTP listener on.
    #[arg(long, env = "NE_PRIVACY_ROUTER_LISTEN")]
    pub listen: SocketAddr,

    /// Path to the PII policy YAML file.
    #[arg(long, env = "NE_PRIVACY_ROUTER_POLICY")]
    pub policy: PathBuf,

    /// Hard cap on bodies the proxy will buffer for scanning.
    #[arg(
        long,
        env = "NE_PRIVACY_ROUTER_MAX_BODY_BYTES",
        default_value_t = DEFAULT_MAX_BODY_BYTES,
    )]
    pub max_body_bytes: usize,

    /// Emit one JSON line per scan decision on stdout.
    #[arg(long, env = "NE_PRIVACY_ROUTER_EMIT_AUDIT_STDOUT", action = ArgAction::SetTrue)]
    pub emit_audit_stdout: bool,
}

#[derive(Debug, Parser)]
pub struct InstallArgs {
    /// Execution profile to provision.
    #[arg(
        long,
        env = "NE_EXECUTION_PROFILE",
        default_value = "standard",
        value_parser = parse_execution_profile
    )]
    pub execution_profile: ne_protocol::profile::ExecutionProfile,

    /// Source `openshell-sandbox` executable for confidential Azure installs.
    #[arg(long)]
    pub openshell_sandbox_source: Option<PathBuf>,
    /// Optional source OpenShell Rego policy.
    #[arg(long)]
    pub openshell_policy_rules_source: Option<PathBuf>,
    /// Optional source OpenShell YAML policy data.
    #[arg(long)]
    pub openshell_policy_data_source: Option<PathBuf>,

    /// Redirect all paths under this root (fakeroot testing). Skips
    /// user/group creation and systemctl when set.
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// Do not start/enable the units.
    #[arg(long, default_value_t = false)]
    pub no_start: bool,
    /// Do not fetch the default guest image. Custom/air-gap images are
    /// provisioned separately via `nee image import` / `nee image pull`.
    #[arg(long, default_value_t = false)]
    pub no_image: bool,
    /// Print actions without mutating anything.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct UninstallArgs {
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// Also delete /var/lib/ne-enclave state.
    #[arg(long, default_value_t = false)]
    pub purge: bool,
}

#[derive(Debug, Parser)]
pub struct DoctorArgs {
    /// Execution profile whose host requirements should be checked.
    #[arg(
        long,
        env = "NE_EXECUTION_PROFILE",
        default_value = "standard",
        value_parser = parse_execution_profile
    )]
    pub execution_profile: ne_protocol::profile::ExecutionProfile,

    #[arg(long)]
    pub prefix: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ImageCommand {
    /// Import a local kernel+rootfs (air-gapped install).
    Import {
        #[arg(long)]
        kernel: PathBuf,
        #[arg(long)]
        kernel_sha256: String,
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long)]
        rootfs_sha256: String,
        #[arg(long)]
        prefix: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
pub struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommand,
}

#[derive(Debug, Parser)]
pub struct ApiKeyArgs {
    #[command(subcommand)]
    pub command: ApiKeyCommand,
}

#[derive(Debug, Subcommand)]
pub enum ApiKeyCommand {
    /// Generate a new key, print it once, and append its hash to the key file.
    Generate {
        /// Key file to append the hash to (created 0600 if absent).
        #[arg(long, env = "NE_API_KEY_FILE")]
        key_file: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Export the signed chain (+manifest) for off-host/WORM retention.
    Export {
        /// State directory containing audit.jsonl.
        #[arg(long, env = "NE_STATE_DIR", default_value = "/var/lib/ne-enclave")]
        state_dir: PathBuf,
        /// Output directory (an audit-export-<ULID>/ dir is created under it).
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Export even if the chain fails verification (manifest marks verified:false).
        #[arg(long, default_value_t = false)]
        allow_broken: bool,
    },
    /// Verify a chain (an audit.jsonl, an export dir, or a manifest.json).
    Verify {
        /// Path to an audit.jsonl file, an export directory, or a manifest.json.
        path: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct AttestationArgs {
    #[command(subcommand)]
    pub command: AttestationCommand,
}

#[derive(Debug, Subcommand)]
pub enum AttestationCommand {
    /// Verify public evidence JSON against an explicit offline policy.
    Verify {
        /// Path to the public evidence JSON file.
        #[arg(long)]
        evidence: PathBuf,
        /// Path to the verification policy JSON file.
        #[arg(long)]
        policy: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct RuntimeArgs {
    #[command(subcommand)]
    pub command: RuntimeCommand,
}

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Print the running runtime's resolved capability contract as JSON.
    Capabilities {
        /// gRPC API endpoint.
        #[arg(
            long,
            env = "NE_API_ENDPOINT",
            default_value = "http://127.0.0.1:50051"
        )]
        endpoint: String,
    },
}

#[derive(Debug, Parser)]
pub struct TlsArgs {
    #[command(subcommand)]
    pub command: TlsCommand,
}

#[derive(Debug, Subcommand)]
pub enum TlsCommand {
    /// Generate a self-signed cert.pem + key.pem (DEV/TEST ONLY).
    GenerateCert {
        /// Output directory (created if absent); writes cert.pem + key.pem.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Subject Alternative Name(s). Defaults to `localhost,127.0.0.1,::1`.
        #[arg(long = "subject-alt-name")]
        subject_alt_name: Vec<String>,
    },
}

#[derive(Debug, Parser)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    pub command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCommand {
    /// Verify a snapshot artifact directory (signature + mem/vmstate hashes).
    Verify {
        /// Path to the snapshot artifact directory (contains manifest.json).
        path: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct PoolArgs {
    #[command(subcommand)]
    pub command: PoolCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum PoolCommand {
    /// Print warm-pool status from a running Enclave API gRPC endpoint.
    /// Targets a plaintext endpoint (dev / behind a trusted proxy); this
    /// convenience command does not perform API-key/TLS auth.
    Status {
        /// API gRPC endpoint URL.
        #[arg(
            long,
            env = "NE_API_ENDPOINT",
            default_value = "http://127.0.0.1:50051"
        )]
        endpoint: String,
    },
}

#[derive(Debug, clap::Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    pub command: WorkspaceCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EvidenceOutput {
    /// Human-readable provider and binding summary.
    Summary,
    /// Complete versioned public evidence envelope as JSON.
    Json,
}

#[derive(Debug, clap::Subcommand)]
pub enum WorkspaceCommand {
    /// Expose a guest port to host-based ingress routing.
    ExposePort {
        /// Workspace id.
        workspace_id: String,
        /// Guest TCP port to expose.
        #[arg(long)]
        port: u16,
        /// Header to inject at the edge (repeatable), as NAME=VALUE.
        #[arg(long = "header", value_parser = parse_header_kv)]
        headers: Vec<(String, String)>,
        /// gRPC API endpoint.
        #[arg(
            long,
            env = "NE_API_ENDPOINT",
            default_value = "http://127.0.0.1:50051"
        )]
        endpoint: String,
    },
    /// Stop routing ingress to a previously exposed guest port.
    UnexposePort {
        /// Workspace id.
        workspace_id: String,
        /// Guest TCP port to unexpose.
        #[arg(long)]
        port: u16,
        /// gRPC API endpoint.
        #[arg(
            long,
            env = "NE_API_ENDPOINT",
            default_value = "http://127.0.0.1:50051"
        )]
        endpoint: String,
    },
    /// Generate attestation evidence for a workspace (challenge-response).
    Attest {
        /// Workspace id.
        workspace_id: String,
        /// Caller nonce as hex (16..=64 bytes). If omitted, a random
        /// 32-byte nonce is generated.
        #[arg(long)]
        nonce: Option<String>,
        /// Evidence output format.
        #[arg(long, value_enum, default_value_t = EvidenceOutput::Summary)]
        output: EvidenceOutput,
        /// Write output to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// gRPC API endpoint.
        #[arg(
            long,
            env = "NE_API_ENDPOINT",
            default_value = "http://127.0.0.1:50051"
        )]
        endpoint: String,
    },
}

fn parse_header_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected NAME=VALUE, got {s:?}"))
}

fn parse_execution_profile(value: &str) -> Result<ne_protocol::profile::ExecutionProfile, String> {
    value.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_image_store_default_is_managed_store() {
        let cli =
            Cli::try_parse_from(["nee", "serve-supervisor", "--dev-mode"]).expect("parse defaults");
        match &cli.command {
            Command::ServeSupervisor(args) => {
                assert_eq!(args.image_store, PathBuf::from(DEFAULT_IMAGE_STORE));
            }
            other => assert!(
                matches!(other, Command::ServeSupervisor(_)),
                "expected serve-supervisor"
            ),
        }
    }

    #[test]
    fn execution_profile_defaults_to_standard() {
        let cli = Cli::try_parse_from(["nee", "serve-supervisor", "--dev-mode"]).expect("parse");
        let Command::ServeSupervisor(args) = cli.command else {
            panic!("expected supervisor command");
        };
        assert_eq!(
            args.execution_profile,
            ne_protocol::profile::ExecutionProfile::Standard
        );
    }

    #[test]
    fn execution_profile_accepts_confidential_azure() {
        let cli =
            Cli::try_parse_from(["nee", "doctor", "--execution-profile", "confidential-azure"])
                .expect("parse");
        let Command::Doctor(args) = cli.command else {
            panic!("expected doctor command");
        };
        assert_eq!(
            args.execution_profile,
            ne_protocol::profile::ExecutionProfile::ConfidentialAzure
        );
    }

    #[test]
    fn confidential_install_accepts_component_sources() {
        let cli = Cli::try_parse_from([
            "nee",
            "install",
            "--execution-profile",
            "confidential-azure",
            "--openshell-sandbox-source",
            "/tmp/openshell-sandbox",
            "--openshell-policy-rules-source",
            "/tmp/policy.rego",
            "--openshell-policy-data-source",
            "/tmp/policy.yaml",
        ])
        .expect("parse");
        let Command::Install(args) = cli.command else {
            panic!("expected install command");
        };
        assert_eq!(
            args.openshell_sandbox_source,
            Some(PathBuf::from("/tmp/openshell-sandbox"))
        );
        assert_eq!(
            args.openshell_policy_rules_source,
            Some(PathBuf::from("/tmp/policy.rego"))
        );
        assert_eq!(
            args.openshell_policy_data_source,
            Some(PathBuf::from("/tmp/policy.yaml"))
        );
    }

    #[test]
    fn attestation_verify_accepts_evidence_and_policy_paths() {
        let cli = Cli::try_parse_from([
            "nee",
            "attestation",
            "verify",
            "--evidence",
            "evidence.json",
            "--policy",
            "policy.json",
        ])
        .expect("parse attestation verify");
        let Command::Attestation(args) = cli.command else {
            panic!("expected attestation command");
        };
        let AttestationCommand::Verify { evidence, policy } = args.command;
        assert_eq!(evidence, PathBuf::from("evidence.json"));
        assert_eq!(policy, PathBuf::from("policy.json"));
    }

    #[test]
    fn workspace_attest_accepts_json_output_file() {
        let cli = Cli::try_parse_from([
            "nee",
            "workspace",
            "attest",
            "secret-1",
            "--output",
            "json",
            "--out",
            "evidence.json",
        ])
        .expect("parse workspace attest output");
        let Command::Workspace(args) = cli.command else {
            panic!("expected workspace command");
        };
        let WorkspaceCommand::Attest {
            output,
            out,
            endpoint,
            ..
        } = args.command
        else {
            panic!("expected attest command");
        };
        assert_eq!(output, EvidenceOutput::Json);
        assert_eq!(out, Some(PathBuf::from("evidence.json")));
        assert_eq!(endpoint, "http://127.0.0.1:50051");
    }

    #[test]
    fn runtime_capabilities_defaults_to_grpc_endpoint() {
        let cli =
            Cli::try_parse_from(["nee", "runtime", "capabilities"]).expect("parse capabilities");
        let Command::Runtime(args) = cli.command else {
            panic!("expected runtime command");
        };
        let RuntimeCommand::Capabilities { endpoint } = args.command;
        assert_eq!(endpoint, "http://127.0.0.1:50051");
    }
}

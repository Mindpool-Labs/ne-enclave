// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Library entrypoint for the privileged supervisor. The `nee` CLI
//! builds a [`SupervisorConfig`] from flags/env and calls [`serve`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::audit::AuditLog;
use crate::command::Dispatcher;
use crate::ipc::{IpcServer, PeerAuth};
use crate::workspace::{WorkspaceManager, WorkspaceManagerConfig};

#[cfg(unix)]
fn path_is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn path_is_executable(_path: &std::path::Path) -> bool {
    false
}

fn probe_startup_requirements(
    cfg: &SupervisorConfig,
) -> crate::attestation_factory::StartupRequirements {
    let sandbox_user = std::process::Command::new("getent")
        .args(["passwd", "sandbox"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    crate::attestation_factory::StartupRequirements {
        linux_x86_64: cfg!(all(target_os = "linux", target_arch = "x86_64")),
        kvm: std::path::Path::new("/dev/kvm").exists(),
        azure_vtpm: std::path::Path::new("/dev/tpmrm0").exists(),
        firecracker: path_is_executable(&cfg.firecracker_binary),
        jailer: path_is_executable(&cfg.jailer_binary),
        openshell_sandbox: path_is_executable(&cfg.openshell_sandbox_binary),
        openshell_policy_rules: cfg.state_dir.join("openshell/policy.rego").is_file(),
        openshell_policy_data: cfg.state_dir.join("openshell/policy.yaml").is_file(),
        sandbox_user,
    }
}

/// Read total host RAM in MiB from `/proc/meminfo`'s `MemTotal` line
/// (kB → MiB). Used to resolve `NE_MAX_WORKSPACES=0` /
/// `NE_MAX_WORKSPACE_MEM_MIB=0` ("auto") at startup.
///
/// Any failure — file missing, malformed line, non-Linux host — falls back
/// to a conservative fixed default rather than panicking or blocking
/// startup: a missing RAM signal must never crash the supervisor, and a
/// deliberately small default just yields a conservative (small) derived
/// ceiling instead of an unbounded one.
#[cfg(target_os = "linux")]
fn read_host_ram_mib() -> u64 {
    const FALLBACK_MIB: u64 = 2048;
    let Ok(contents) = std::fs::read_to_string("/proc/meminfo") else {
        return FALLBACK_MIB;
    };
    contents
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb_str| kb_str.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .filter(|&mib| mib > 0)
        .unwrap_or(FALLBACK_MIB)
}

/// Non-Linux fallback: `/proc/meminfo` doesn't exist, so always resolve to
/// the same conservative default `read_host_ram_mib` uses on Linux when it
/// can't read the real value.
#[cfg(not(target_os = "linux"))]
fn read_host_ram_mib() -> u64 {
    2048
}

/// Resolved supervisor configuration (mirrors the historical
/// `ne-supervisor` CLI flags 1:1 so behavior is unchanged).
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Execution and attestation profile selected for this process.
    pub execution_profile: ne_protocol::profile::ExecutionProfile,
    /// Path to the unix domain socket the API daemon connects on.
    pub socket: PathBuf,
    /// Expected UID of the API daemon. Required in production.
    pub expected_peer_uid: Option<u32>,
    /// Disable peer-credential authentication.
    pub dev_mode: bool,
    /// Absolute host path to the Firecracker binary.
    pub firecracker_binary: PathBuf,
    /// Absolute host path to the jailer binary.
    pub jailer_binary: PathBuf,
    /// Base directory under which jailer creates per-workspace chroots.
    pub jailer_chroot_base: PathBuf,
    /// Supervisor-owned content-addressed kernel and rootfs image store.
    pub image_store: PathBuf,
    /// UID that jailer drops Firecracker to.
    pub jailer_uid: u32,
    /// GID that jailer drops Firecracker to.
    pub jailer_gid: u32,
    /// Path to the `openshell-sandbox` binary (confidential tier, B). Unused on
    /// the standard (Firecracker) tier.
    pub openshell_sandbox_binary: PathBuf,
    /// Milliseconds to wait for Firecracker's API socket to appear.
    pub api_socket_timeout_ms: u64,
    /// Persistent state directory (audit signing keys + JSONL audit log).
    pub state_dir: PathBuf,
    /// Max concurrent workspaces (0 = derive from host RAM via
    /// [`crate::workspace::derive_max_workspaces`]). Soft ceiling — an
    /// exhaustion backstop, not a hard quota.
    pub max_workspaces: usize,
    /// Max `mem_size_mib` any single workspace may request (0 = `min(host
    /// RAM, 32768)`). Resolved once from `/proc/meminfo` in [`serve`] (audit
    /// O3).
    pub max_workspace_mem_mib: u32,
    /// Enable per-workspace network plumbing (netns + veth + TAP + MASQUERADE).
    pub enable_networking: bool,
    /// Path to the `ip` binary (iproute2).
    pub ip_binary: PathBuf,
    /// Path to the `iptables` binary.
    pub iptables_binary: PathBuf,
    /// Upstream interface MASQUERADE rules use for egress.
    pub upstream_iface: String,
    /// Optional path to the `ne-dns-filter` binary.
    pub dns_filter_binary: Option<PathBuf>,
    /// Upstream resolver the per-workspace DNS filter forwards allowed queries to.
    pub dns_upstream: String,
    /// Optional path to the `ne-privacy-router` binary.
    pub privacy_router_binary: Option<PathBuf>,
    /// Path to the host-global PII policy YAML the privacy router enforces.
    pub privacy_router_policy: Option<PathBuf>,
    /// Warm-pool tier name (enables the pool with the next two).
    pub warm_pool_tier: Option<String>,
    /// Base snapshot id pool members are forked from.
    pub warm_pool_snapshot: Option<String>,
    /// Target pool size (0 disables the pool).
    pub warm_pool_size: usize,
    /// Max concurrent in-flight provisions during refill.
    pub warm_pool_max_in_flight: usize,
    /// Ingress domain (e.g. `apps.example.com`). Enables the in-process
    /// ingress edge when set.
    pub ingress_domain: Option<String>,
    /// TCP address the ingress edge listens on.
    pub ingress_listen: SocketAddr,
    /// Maximum concurrent in-flight ingress connections (flood backstop, audit
    /// `S7-F2`). Excess connections wait in the kernel accept backlog.
    pub ingress_max_connections: usize,
    /// Path to the ingress TLS certificate chain (PEM).
    pub ingress_tls_cert: Option<PathBuf>,
    /// Path to the ingress TLS private key (PEM).
    pub ingress_tls_key: Option<PathBuf>,
}

impl SupervisorConfig {
    /// Resolve the peer-auth mode, refusing to start in production mode
    /// without an expected peer uid.
    pub fn resolve_auth(&self) -> Result<PeerAuth> {
        match (self.dev_mode, self.expected_peer_uid) {
            (true, _) => Ok(PeerAuth::DevDisabled),
            (false, Some(uid)) => Ok(PeerAuth::RequireUid(uid)),
            (false, None) => anyhow::bail!(
                "refusing to start: production mode requires --expected-peer-uid; pass \
                 --dev-mode for local development"
            ),
        }
    }
}

/// Adapts the supervisor's [`AuditLog`] to the [`ne_ingress::AuditSink`]
/// interface so ingress routing decisions land in the signed audit chain.
#[cfg(target_os = "linux")]
struct SupervisorIngressAudit {
    audit: AuditLog,
}

#[cfg(target_os = "linux")]
impl ne_ingress::AuditSink for SupervisorIngressAudit {
    fn route_allowed(&self, host: &str, wsid: &str, port: u16) {
        let audit = self.audit.clone();
        let (host, wsid) = (host.to_string(), wsid.to_string());
        tokio::spawn(async move {
            let _ = audit
                .emit(
                    ne_protocol::audit::EventType::IngressRouteAllowed,
                    Some(wsid),
                    serde_json::json!({ "host": host, "port": port }),
                )
                .await;
        });
    }

    fn route_denied(&self, host: &str, reason: ne_ingress::DenyReason) {
        let audit = self.audit.clone();
        let host = host.to_string();
        let reason = reason.as_str().to_string();
        tokio::spawn(async move {
            let _ = audit
                .emit(
                    ne_protocol::audit::EventType::IngressRouteDenied,
                    None,
                    serde_json::json!({ "host": host, "reason": reason }),
                )
                .await;
        });
    }
}

/// Assemble and run the supervisor. The caller initializes tracing and
/// installs the parent-death signal.
pub async fn serve(cfg: SupervisorConfig) -> Result<()> {
    tracing::info!(
        socket = %cfg.socket.display(),
        dev_mode = cfg.dev_mode,
        execution_profile = %cfg.execution_profile,
        firecracker = %cfg.firecracker_binary.display(),
        jailer = %cfg.jailer_binary.display(),
        "ne-supervisor starting"
    );

    let auth = cfg.resolve_auth()?;

    crate::attestation_factory::validate_legacy_confidential_switch(
        std::env::var_os("NE_CONFIDENTIAL_MODE").as_deref(),
    )?;
    let execution_profile = cfg.execution_profile;
    crate::attestation_factory::validate_startup_requirements(
        execution_profile,
        &probe_startup_requirements(&cfg),
    )?;
    let attestation_backend = execution_profile.attestation_backend();

    let audit = AuditLog::open(&cfg.state_dir)
        .await
        .context("opening audit log + signing key under --state-dir")?;
    let attestation =
        crate::attestation_factory::build_provider(attestation_backend, audit.signing_key())
            .context("construct profile-selected attestation provider")?;

    #[cfg(target_os = "linux")]
    let network = if cfg.enable_networking {
        Some(crate::network::NetworkController::new(
            cfg.ip_binary.clone(),
            cfg.iptables_binary.clone(),
            cfg.upstream_iface.clone(),
            cfg.dns_filter_binary.clone(),
            cfg.dns_upstream.clone(),
            cfg.privacy_router_binary.clone(),
            cfg.privacy_router_policy.clone(),
            // Pass the supervisor's audit log into the controller
            // so DNS + privacy decisions land in the signed chain
            // alongside workspace lifecycle events.
            Some(audit.clone()),
        ))
    } else {
        None
    };

    // Warm pool is enabled only when tier + snapshot + size>0 are all present.
    #[cfg(target_os = "linux")]
    let warm_pool = match (
        &cfg.warm_pool_tier,
        &cfg.warm_pool_snapshot,
        cfg.warm_pool_size,
    ) {
        (Some(tier), Some(snapshot), size) if size > 0 => Some(crate::pool::WarmPoolConfig {
            tier_name: tier.clone(),
            base_snapshot_id: snapshot.clone(),
            target_size: size,
            max_in_flight: cfg.warm_pool_max_in_flight.max(1),
        }),
        (None, None, 0) => None,
        _ => anyhow::bail!(
            "incomplete warm-pool config: set --warm-pool-tier, --warm-pool-snapshot, and --warm-pool-size together"
        ),
    };

    let allow_software_attestation = std::env::var("NE_ATTEST_ALLOW_SOFTWARE").is_ok();
    // The software-fallback provider is not firmware-rooted, so it must fail
    // closed outside dev unless the operator explicitly opts in. Only enforced
    // on the software path — a confidential (SEV-SNP) deployment bypasses it.
    if matches!(
        attestation_backend,
        ne_protocol::profile::AttestationBackend::Software
    ) && !ne_attestation::software_provider_allowed(cfg.dev_mode, allow_software_attestation)
    {
        anyhow::bail!(
            "software attestation refused: not in dev mode and \
             NE_ATTEST_ALLOW_SOFTWARE is not set. Set it to explicitly permit \
             non-firmware-rooted (software) attestation in this deployment, or \
             configure a hardware attestation provider."
        );
    }

    // Admission control: resolve NE_MAX_WORKSPACES /
    // NE_MAX_WORKSPACE_MEM_MIB "0 = auto" against host RAM, read once here
    // rather than per-request. `derive_max_workspaces` and the mem default
    // both key off the same reading so they stay consistent with each other.
    let host_ram_mib = read_host_ram_mib();
    let max_workspaces = if cfg.max_workspaces == 0 {
        crate::workspace::derive_max_workspaces(host_ram_mib)
    } else {
        cfg.max_workspaces
    };
    let max_workspaces = crate::workspace::validate_workspace_ceiling(max_workspaces)?;
    let max_workspace_mem_mib = if cfg.max_workspace_mem_mib == 0 {
        u32::try_from(host_ram_mib.min(32768)).unwrap_or(u32::MAX)
    } else {
        cfg.max_workspace_mem_mib
    };
    tracing::info!(
        max_workspaces,
        max_workspace_mem_mib,
        host_ram_mib,
        "admission control ceilings resolved"
    );

    let workspaces = Arc::new(
        WorkspaceManager::new(
            WorkspaceManagerConfig {
                execution_profile,
                firecracker_binary: cfg.firecracker_binary,
                jailer_binary: cfg.jailer_binary,
                chroot_base: cfg.jailer_chroot_base,
                image_store: cfg.image_store,
                jailer_uid: cfg.jailer_uid,
                jailer_gid: cfg.jailer_gid,
                openshell_sandbox_binary: cfg.openshell_sandbox_binary,
                api_socket_timeout: Duration::from_millis(cfg.api_socket_timeout_ms),
                default_kernel_boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
                #[cfg(target_os = "linux")]
                network,
                state_dir: cfg.state_dir,
                #[cfg(target_os = "linux")]
                warm_pool,
            },
            audit.clone(),
            attestation,
            usize::try_from(max_workspaces).context("convert validated workspace ceiling")?,
            max_workspace_mem_mib,
        )
        .context("construct workspace manager")?,
    );
    let dispatcher = Arc::new(Dispatcher::new(Arc::clone(&workspaces), audit.clone()));
    #[cfg(target_os = "linux")]
    workspaces.spawn_refill();

    // Spawn the in-process ingress edge when an ingress domain is configured.
    // The task runs until aborted at shutdown; bind failures are fatal.
    #[cfg(target_os = "linux")]
    let ingress_task: Option<tokio::task::JoinHandle<()>> = if let Some(domain) =
        cfg.ingress_domain.clone()
    {
        let registry = workspaces.ingress_registry();
        let audit_sink: Arc<dyn ne_ingress::AuditSink> = Arc::new(SupervisorIngressAudit {
            audit: audit.clone(),
        });
        let mut router_cfg = ne_ingress::RouterConfig::new(domain);
        router_cfg.max_connections = cfg.ingress_max_connections;
        let router = ne_ingress::IngressRouter::new(registry, router_cfg, audit_sink);
        let listener = tokio::net::TcpListener::bind(cfg.ingress_listen)
            .await
            .context("bind ingress listener")?;
        match (cfg.ingress_tls_cert.as_ref(), cfg.ingress_tls_key.as_ref()) {
            (Some(cert), Some(key)) => {
                let tls = ne_ingress::tls::load_server_config(cert, key)
                    .context("load ingress TLS cert/key")?;
                tracing::info!(
                    listen = %cfg.ingress_listen,
                    domain = %cfg.ingress_domain.as_deref().unwrap_or(""),
                    "ingress edge: HTTPS"
                );
                Some(tokio::spawn(router.serve_tls(listener, tls)))
            }
            // Fail closed: a partial TLS config must never silently serve
            // plaintext on the ingress port.
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!(
                    "ingress TLS requires BOTH --ingress-tls-cert and --ingress-tls-key (or neither for plaintext)"
                );
            }
            (None, None) => {
                ne_ingress::tls::plaintext_listener_allowed(cfg.ingress_listen.ip(), cfg.dev_mode)
                    .context("plaintext ingress guard")?;
                tracing::warn!(
                    listen = %cfg.ingress_listen,
                    "ingress edge: PLAINTEXT (no TLS cert configured)"
                );
                Some(tokio::spawn(router.serve_plaintext(listener)))
            }
        }
    } else {
        None
    };

    let server = IpcServer::bind(&cfg.socket, auth)
        .await
        .context("binding supervisor IPC socket")?;

    // Socket is bound + listening: tell systemd (Type=notify) we're ready.
    // Best-effort: outside a notify-socket environment this is a no-op.
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        tracing::debug!("sd_notify READY failed (not under systemd notify?): {e}");
    }

    #[cfg(target_os = "linux")]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        let server_result = tokio::select! {
            r = server.serve(dispatcher) => r,
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received — draining lifecycle work");
                Ok(())
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received — draining lifecycle work");
                Ok(())
            }
        };
        // Close before waiting so accepted connections cannot start more work.
        // Refill is woken by `close_lifecycle`; after all tracked work and
        // cleanup finish, idle pool members are explicitly reaped.
        workspaces.shutdown_lifecycle().await;
        // Abort the ingress edge on shutdown (it loops forever until cancelled).
        if let Some(t) = ingress_task {
            t.abort();
        }
        server_result.context("supervisor IPC server terminated with error")?;
    }
    #[cfg(not(target_os = "linux"))]
    server
        .serve(dispatcher)
        .await
        .context("supervisor IPC server terminated with error")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SupervisorConfig {
        SupervisorConfig {
            execution_profile: ne_protocol::profile::ExecutionProfile::Standard,
            socket: "/run/ne-enclave/supervisor.sock".into(),
            expected_peer_uid: None,
            dev_mode: false,
            firecracker_binary: "/opt/ne-enclave/bin/firecracker".into(),
            jailer_binary: "/opt/ne-enclave/bin/jailer".into(),
            jailer_chroot_base: "/srv/jailer".into(),
            image_store: "/var/lib/ne-enclave/images".into(),
            jailer_uid: 1000,
            jailer_gid: 1000,
            openshell_sandbox_binary: "/opt/ne-enclave/bin/openshell-sandbox".into(),
            api_socket_timeout_ms: 10_000,
            state_dir: "/var/lib/ne-enclave".into(),
            max_workspaces: 0,
            max_workspace_mem_mib: 0,
            enable_networking: false,
            ip_binary: "/usr/sbin/ip".into(),
            iptables_binary: "/usr/sbin/iptables".into(),
            upstream_iface: "eth0".into(),
            dns_filter_binary: None,
            dns_upstream: "1.1.1.1:53".into(),
            privacy_router_binary: None,
            privacy_router_policy: None,
            warm_pool_tier: None,
            warm_pool_snapshot: None,
            warm_pool_size: 0,
            warm_pool_max_in_flight: 2,
            ingress_domain: None,
            ingress_listen: "0.0.0.0:443".parse().unwrap(),
            ingress_max_connections: 1024,
            ingress_tls_cert: None,
            ingress_tls_key: None,
        }
    }

    #[test]
    fn prod_without_peer_uid_is_rejected() {
        let err = base().resolve_auth().expect_err("must reject");
        assert!(err.to_string().contains("expected-peer-uid"));
    }

    #[test]
    fn prod_with_peer_uid_requires_that_uid() {
        let mut c = base();
        c.expected_peer_uid = Some(4242);
        assert!(matches!(
            c.resolve_auth().unwrap(),
            PeerAuth::RequireUid(4242)
        ));
    }

    #[test]
    fn dev_mode_disables_peer_auth() {
        let mut c = base();
        c.dev_mode = true;
        assert!(matches!(c.resolve_auth().unwrap(), PeerAuth::DevDisabled));
    }

    #[test]
    fn resolved_workspace_ceiling_obeys_fleet_wire_limit() {
        assert_eq!(
            crate::workspace::validate_workspace_ceiling(1).expect("minimum"),
            1
        );
        assert_eq!(
            crate::workspace::validate_workspace_ceiling(1_000_000).expect("wire maximum"),
            1_000_000
        );
        assert!(crate::workspace::validate_workspace_ceiling(1_000_001).is_err());
        if usize::BITS > 32 {
            let above_u32 = usize::try_from(u64::from(u32::MAX) + 1)
                .expect("wide pointer targets represent one above u32::MAX");
            assert!(crate::workspace::validate_workspace_ceiling(above_u32).is_err());
        }
    }
}

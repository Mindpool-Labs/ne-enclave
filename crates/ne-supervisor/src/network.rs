// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-workspace network plumbing — Linux-only.
//!
//! Current scope:
//!   - per-workspace network namespace (`ip netns add ne-<id>`)
//!   - host-side veth (`vh-<id>`) ↔ guest-side veth (`vg-<id>`)
//!     pair, with `vg-` moved into the netns
//!   - TAP device (`tap-<id>`) inside the netns for Firecracker
//!   - /30 IP allocation out of `169.254.<slot>.0/24` (link-local
//!     space; collision-free with normal LAN/VPC ranges)
//!   - host-side NAT rule (iptables MASQUERADE) so the workspace
//!     can reach the internet through the host's default route
//!
//! Deferred to subsequent iterations:
//!   - deny-by-default egress + per-policy allow rules (nftables)
//!   - DNS mediation
//!   - L7 inspection / privacy-router integration
//!   - audit event emission for network decisions (`network.allowed`,
//!     `network.denied`, `network.dns_resolved`)
//!   - wiring into `WorkspaceManager::{create,terminate}` so each
//!     workspace gets a network automatically — existing tests keep
//!     passing because this module is currently invoked only by its
//!     own integration test.
//!
//! Implementation note: this module shells out to `ip` and
//! `iptables` rather than going through netlink directly. The
//! shell-out path matches what most Firecracker-using projects do
//! today and is well-understood operationally; a netlink rewrite is
//! a later follow-up once the shell-out semantics are pinned.

use std::path::PathBuf;
use std::process::Stdio;

use ne_protocol::audit::EventType;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::audit::AuditLog;

/// Maximum slot id we'll allocate out of the link-local pool. With a
/// /30 per workspace and `169.254.<slot>.0/24`, slots 1..=253 are
/// safe (skip .0 and .254 to avoid edge cases in tooling that treats
/// them as reserved).
const MAX_SLOT: u8 = 253;

/// Per-slot IPv4 layout for the two /30 subnets assigned to each workspace.
///
/// The veth /30 (`169.254.<s>.0/30`: host `.1`, workspace `.2`) is
/// unchanged from the egress plumbing. A second /30 (`169.254.<s>.4/30`:
/// tap gateway `.5`, guest `.6`) carries the guest `eth0` so a host-side
/// ingress proxy can reach a service inside the guest.
#[derive(Debug, Clone)]
pub struct SlotIpLayout {
    /// Host-side veth IP (`169.254.<slot>.1`).
    pub host_ip: String,
    /// Workspace-side veth IP inside the netns (`169.254.<slot>.2`).
    pub workspace_ip: String,
    /// TAP gateway IP inside the netns (`169.254.<slot>.5`).
    pub tap_gateway_ip: String,
    /// Guest `eth0` IP assigned via kernel boot arg (`169.254.<slot>.6`).
    pub guest_eth_ip: String,
    /// CIDR of the guest /30 (`169.254.<slot>.4/30`).
    pub guest_subnet_cidr: String,
    /// Subnet mask for the guest /30 (`255.255.255.252`).
    pub netmask: String,
}

impl SlotIpLayout {
    /// Build the layout for the given slot index.
    #[must_use]
    pub fn for_slot(slot: u8) -> Self {
        Self {
            host_ip: format!("169.254.{slot}.1"),
            workspace_ip: format!("169.254.{slot}.2"),
            tap_gateway_ip: format!("169.254.{slot}.5"),
            guest_eth_ip: format!("169.254.{slot}.6"),
            guest_subnet_cidr: format!("169.254.{slot}.4/30"),
            netmask: "255.255.255.252".to_string(),
        }
    }

    /// Kernel `ip=` static-autoconf directive for the guest `eth0`:
    /// `ip=<client>::<gateway>:<netmask>::<device>:<autoconf>`.
    #[must_use]
    pub fn ip_boot_arg(&self) -> String {
        format!(
            "ip={}::{}:{}::eth0:off",
            self.guest_eth_ip, self.tap_gateway_ip, self.netmask
        )
    }
}

/// Port the per-workspace `ne-privacy-router` binds inside the
/// workspace netns. Fixed because the netns isolates it from every
/// other workspace; iptables DNAT rewrites guest-side TCP/80 to this
/// destination.
const PRIVACY_ROUTER_PORT: u16 = 8888;

/// Errors returned by [`NetworkController`].
#[derive(Debug, Error)]
pub enum NetworkError {
    /// `ip` or `iptables` exited non-zero. The wrapped string is the
    /// stderr of the failing command.
    #[error("`{program}` failed: {stderr}")]
    Command {
        /// Which binary failed (`ip`, `iptables`, etc.).
        program: String,
        /// Captured stderr from the failing invocation.
        stderr: String,
    },
    /// IO failure spawning the helper command.
    #[error("spawn {program}: {source}")]
    Spawn {
        /// Program we tried to spawn.
        program: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The IP-slot pool is exhausted.
    #[error("no free network slot in 169.254.X.0/24 (max {})", MAX_SLOT)]
    PoolExhausted,
    /// `workspace_id` did not satisfy the short-name constraints for
    /// kernel interface names (`IFNAMSIZ` is 15, so we cap the
    /// hashed suffix at 8 chars and prefix it with `vh-` / `vg-` /
    /// `tap-`).
    #[error("workspace_id {0:?} hashes to a name that exceeds IFNAMSIZ")]
    InvalidWorkspaceId(String),
    /// A caller-supplied `allow_cidrs` entry was not a syntactically
    /// valid IPv4 CIDR. We reject these up-front so iptables doesn't
    /// see them — keeps the error attribution close to the policy.
    #[error("invalid CIDR {0:?} in NetworkPolicy.allow_cidrs")]
    InvalidCidr(String),
    /// A caller-supplied `allow_hostnames` entry was not a
    /// syntactically valid DNS name. Surfaced before the DNS filter
    /// binary sees it so callers get a clear typed error instead of
    /// a subprocess that silently denies every query.
    #[error("invalid hostname {0:?} in NetworkPolicy.allow_hostnames")]
    InvalidHostname(String),
}

/// Per-workspace network resources. The supervisor stores this on
/// the registry entry next to the Firecracker `Instance` so
/// `teardown` knows exactly what to reclaim.
#[derive(Debug, Clone)]
pub struct NetworkSlot {
    /// Echoes the workspace id this slot was allocated for.
    pub workspace_id: String,
    /// 8-char hash suffix used in interface names.
    pub short_id: String,
    /// Slot index in `169.254.<slot>.0/24`.
    pub slot: u8,
    /// Network namespace name (`ne-<short_id>`).
    pub netns: String,
    /// Host-side veth (in root netns).
    pub veth_host: String,
    /// Guest-side veth (in workspace netns).
    pub veth_guest: String,
    /// TAP device name (in workspace netns) — Firecracker attaches
    /// its virtio-net device to this.
    pub tap: String,
    /// Host-side veth IP (e.g. `169.254.1.1`).
    pub host_ip: String,
    /// Workspace-side veth IP inside the netns (e.g. `169.254.1.2`);
    /// guest egress is SNAT'd to this, and the host routes to the guest
    /// /30 via it. The guest's own eth0 IP is `guest_eth_ip`.
    pub workspace_ip: String,
    /// CIDR prefix (always 30 in this iteration).
    pub prefix: u8,
    /// TAP gateway IP (`169.254.<slot>.5`) — the guest's default route.
    pub tap_gateway_ip: String,
    /// Guest `eth0` IP (`169.254.<slot>.6`) — the ingress target.
    pub guest_eth_ip: String,
    /// Whether the host-side route into the guest /30 was installed
    /// (so `teardown` knows to remove it).
    pub host_route_installed: bool,
    /// Per-workspace FORWARD chain name in iptables (`NE-FWD-<short_id>`).
    /// Owned by this slot so teardown knows what to flush + delete.
    pub forward_chain: String,
    /// Whether the supervisor also installed a MASQUERADE rule for
    /// this slot. Determines whether teardown should attempt to
    /// remove one.
    pub masquerade_installed: bool,
    /// PID of the per-workspace `ne-dns-filter` process when one
    /// was spawned (only when `policy.allow_hostnames` was
    /// non-empty). Teardown sends SIGTERM to this PID and best-
    /// effort waits for it. `None` means no DNS filter was spawned;
    /// either the allowlist was empty or the supervisor was
    /// configured without a filter binary path.
    pub dns_filter_pid: Option<u32>,
    /// Handle to the tokio task that relays DNS-filter audit lines
    /// from the filter's stdout into the supervisor's signed audit
    /// chain. `None` when no filter was spawned (or when the
    /// controller was constructed without an `AuditLog`). Wrapped
    /// in `Arc` so the slot can be cloned cheaply during terminate.
    #[allow(clippy::struct_field_names)]
    pub dns_audit_relay: Option<std::sync::Arc<JoinHandle<()>>>,
    /// PID of the per-workspace `ne-privacy-router` process when
    /// one was spawned (only when `policy.enable_privacy_router` was
    /// true and the controller had both a binary path and a policy
    /// path). Teardown sends SIGTERM to this PID before deleting
    /// the netns, mirroring the DNS filter shape.
    pub privacy_router_pid: Option<u32>,
    /// Handle to the tokio task that relays privacy-router audit
    /// lines from the router's stdout into the supervisor's signed
    /// chain. `None` when no router was spawned (or the controller
    /// had no `AuditLog`).
    #[allow(clippy::struct_field_names)]
    pub privacy_audit_relay: Option<std::sync::Arc<JoinHandle<()>>>,
}

/// Per-workspace egress policy passed to [`NetworkController::setup`].
///
/// Mirrors [`ne_protocol::supervisor::NetworkConfig`] but stays
/// in the supervisor's own crate to keep the netfilter call sites
/// independent of the wire schema.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    /// Whether to install a MASQUERADE rule so workspace traffic
    /// egresses through the host's default route.
    pub enable_egress: bool,
    /// Destination CIDRs the workspace is allowed to reach. Empty
    /// list combined with [`Self::enable_egress`] true keeps the
    /// historic open-egress shape; empty list with egress off is a
    /// fully isolated workspace. Conntrack-tracked return traffic is
    /// always allowed regardless.
    pub allow_cidrs: Vec<String>,
    /// Hostname allowlist enforced by the per-workspace DNS filter
    /// (E4.b spawns `ne-dns-filter` with these). Empty list
    /// disables the filter entirely; non-empty switches the
    /// workspace into deny-by-default DNS. Validated up-front via
    /// [`validate_hostname`] so a typo never reaches the filter
    /// binary's CLI parser.
    pub allow_hostnames: Vec<String>,
    /// When `true`, the workspace opts into the host-side privacy
    /// router. The controller spawns `ne-privacy-router` inside
    /// the workspace netns and installs iptables DNAT to redirect
    /// TCP/80 egress to it. Requires the controller to have been
    /// constructed with both a binary path and a policy path;
    /// otherwise the opt-in is logged at warn and skipped (mirrors
    /// the dev-mode shape of the DNS filter).
    pub enable_privacy_router: bool,
}

/// Driver for the per-workspace network plumbing. Cheap to clone.
#[derive(Debug, Clone)]
pub struct NetworkController {
    inner: std::sync::Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    ip_binary: PathBuf,
    iptables_binary: PathBuf,
    upstream_iface: String,
    /// Optional path to the fused `nee` binary (invoked as
    /// `nee dns-filter`). When `None` the controller still accepts
    /// policies with non-empty `allow_hostnames` but logs at warn and
    /// skips the DNS filter spawn — useful for the macOS dev loop
    /// where the binary may not be available.
    dns_filter_binary: Option<PathBuf>,
    /// Upstream resolver the DNS filter forwards allowed queries to.
    /// Defaults to Cloudflare's public 1.1.1.1; operators override
    /// for air-gapped environments via supervisor CLI.
    dns_upstream: String,
    /// Optional path to the fused `nee` binary (invoked as
    /// `nee privacy-router`). `None` disables privacy routing
    /// entirely — workspace requests that opt in
    /// (`enable_privacy_router = true`) are logged at warn and
    /// otherwise ignored.
    privacy_router_binary: Option<PathBuf>,
    /// Optional path to the host-global PII policy YAML the privacy
    /// router enforces. Required alongside [`Self::privacy_router_binary`]
    /// — either both are set or the controller treats privacy routing
    /// as disabled.
    privacy_router_policy: Option<PathBuf>,
    /// Audit log handle used to chain DNS filter decisions
    /// (allowed/denied/malformed). `None` skips the stdout relay —
    /// the filter still runs, but its decisions only land in its
    /// own stderr log, not the supervisor's signed chain.
    audit: Option<AuditLog>,
    slots: Mutex<Vec<bool>>,
}

impl NetworkController {
    /// Construct a controller. `upstream_iface` is the host
    /// interface (typically `eth0`) the NAT MASQUERADE rule
    /// targets. `dns_filter_binary` is the path to the fused `nee`
    /// binary (spawned as `nee dns-filter`) the controller runs per
    /// workspace when the policy declares a non-empty `allow_hostnames`;
    /// pass `None` to disable DNS filtering (the controller logs at
    /// warn and skips the spawn).
    /// `dns_upstream` is the resolver allowed queries get forwarded
    /// to — defaults to Cloudflare's `1.1.1.1:53` in CLI defaults.
    /// `privacy_router_binary` and `privacy_router_policy` enable
    /// the per-workspace HTTP privacy router; both must be set
    /// together. When either is `None` the controller logs at warn
    /// for any `enable_privacy_router` opt-in and runs the workspace
    /// without payload scanning.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        ip_binary: PathBuf,
        iptables_binary: PathBuf,
        upstream_iface: String,
        dns_filter_binary: Option<PathBuf>,
        dns_upstream: String,
        privacy_router_binary: Option<PathBuf>,
        privacy_router_policy: Option<PathBuf>,
        audit: Option<AuditLog>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                ip_binary,
                iptables_binary,
                upstream_iface,
                dns_filter_binary,
                dns_upstream,
                privacy_router_binary,
                privacy_router_policy,
                audit,
                // index 0 unused so the slot number lines up 1:1 with
                // the `169.254.<slot>.0/24` octet.
                slots: Mutex::new(vec![true; (MAX_SLOT as usize) + 1]),
            }),
        }
    }

    /// Allocate a slot + provision the netns, veth pair, TAP, IP
    /// assignments, FORWARD filter chain, and (optionally) a NAT
    /// MASQUERADE rule. The FORWARD chain defaults to DROP; only
    /// flows matching `policy.allow_cidrs` (or conntrack
    /// ESTABLISHED/RELATED return traffic) are accepted. An empty
    /// `allow_cidrs` combined with `policy.enable_egress = true`
    /// inserts an explicit ACCEPT-all rule in the FORWARD chain so
    /// the historic open-egress shape stays available for callers
    /// that don't (yet) declare a CIDR allowlist.
    pub async fn setup(
        &self,
        workspace_id: &str,
        policy: &NetworkPolicy,
    ) -> Result<NetworkSlot, NetworkError> {
        let short_id = short_id_for(workspace_id);
        let netns = format!("ne-{short_id}");
        let veth_host = format!("vh-{short_id}");
        let veth_guest = format!("vg-{short_id}");
        let tap = format!("tap-{short_id}");
        let forward_chain = format!("NE-FWD-{short_id}");
        if veth_host.len() > 15 || veth_guest.len() > 15 || tap.len() > 15 {
            return Err(NetworkError::InvalidWorkspaceId(workspace_id.to_string()));
        }
        // iptables chain names cap at 28 chars. `NE-FWD-` is 10
        // chars and the 8-char short_id puts us at 18 — safe — but
        // gate explicitly so a future short_id change doesn't drift.
        if forward_chain.len() > 28 {
            return Err(NetworkError::InvalidWorkspaceId(workspace_id.to_string()));
        }
        for cidr in &policy.allow_cidrs {
            validate_cidr(cidr)?;
        }
        for host in &policy.allow_hostnames {
            validate_hostname(host)?;
        }

        let slot = self.allocate_slot().await?;
        let host_addr = format!("169.254.{slot}.1");
        let guest_addr = format!("169.254.{slot}.2");
        let prefix: u8 = 30;

        info!(
            workspace_id,
            netns,
            veth_host,
            veth_guest,
            tap,
            slot,
            %host_addr,
            %guest_addr,
            enable_egress = policy.enable_egress,
            allow_cidr_count = policy.allow_cidrs.len(),
            "provisioning workspace network"
        );

        // The list mirrors what we'd otherwise script in a small
        // shell file. Keeping it inline (rather than scripting via a
        // single `sh -c`) gives clearer error attribution per step.
        self.run("ip", &["netns", "add", &netns]).await?;
        self.run(
            "ip",
            &[
                "link",
                "add",
                &veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &veth_guest,
            ],
        )
        .await?;
        self.run("ip", &["link", "set", &veth_guest, "netns", &netns])
            .await?;
        self.run(
            "ip",
            &[
                "addr",
                "add",
                &format!("{host_addr}/{prefix}"),
                "dev",
                &veth_host,
            ],
        )
        .await?;
        self.run("ip", &["link", "set", &veth_host, "up"]).await?;
        self.run_in_netns(
            &netns,
            "ip",
            &[
                "addr",
                "add",
                &format!("{guest_addr}/{prefix}"),
                "dev",
                &veth_guest,
            ],
        )
        .await?;
        self.run_in_netns(&netns, "ip", &["link", "set", &veth_guest, "up"])
            .await?;
        self.run_in_netns(&netns, "ip", &["link", "set", "lo", "up"])
            .await?;
        self.run_in_netns(&netns, "ip", &["tuntap", "add", &tap, "mode", "tap"])
            .await?;
        self.run_in_netns(&netns, "ip", &["link", "set", &tap, "up"])
            .await?;
        // Default route inside the netns points back at the host
        // veth so workspace egress goes through us.
        self.run_in_netns(
            &netns,
            "ip",
            &["route", "add", "default", "via", &host_addr],
        )
        .await?;

        // --- Guest L3 path (ingress prerequisite) ---
        // The guest eth0 lives on a second /30 behind the TAP; the netns
        // forwards between it and the veth uplink, SNATing guest egress to
        // the veth workspace IP so the EXISTING host MASQUERADE/FORWARD rules
        // (matched on 169.254.<s>.0/30) and the deny-by-default egress policy
        // keep applying unchanged. The guest receives its IP via the `ip=`
        // kernel boot arg (set in workspace.rs from SlotIpLayout::ip_boot_arg).
        let layout = SlotIpLayout::for_slot(slot);
        // TAP gets the guest's gateway IP inside the netns.
        self.run_in_netns(
            &netns,
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/30", layout.tap_gateway_ip),
                "dev",
                &tap,
            ],
        )
        .await?;
        // Enable forwarding inside the netns so packets cross veth<->tap.
        self.run_in_netns(&netns, "sysctl", &["-w", "net.ipv4.ip_forward=1"])
            .await?;
        // SNAT guest egress to the veth workspace IP.
        self.run_in_netns(
            &netns,
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &layout.guest_subnet_cidr,
                "-o",
                &veth_guest,
                "-j",
                "SNAT",
                "--to-source",
                &layout.workspace_ip,
            ],
        )
        .await?;
        // Host route so the root-netns ingress proxy can reach the guest.
        self.run(
            "ip",
            &[
                "route",
                "add",
                &layout.guest_subnet_cidr,
                "via",
                &layout.workspace_ip,
                "dev",
                &veth_host,
            ],
        )
        .await?;
        let host_route_installed = true;

        // Per-workspace FORWARD chain (deny-by-default). Conntrack
        // accepts return traffic for any flow we previously allowed
        // out; declared CIDRs (or an explicit ACCEPT-all when
        // enable_egress=true and the allowlist is empty) populate the
        // rest. The implicit policy at chain bottom is DROP.
        self.install_forward_chain(slot, &forward_chain, policy)
            .await?;

        // Anti-spoof: bind this veth's traffic to the slot's own
        // /30 at the top of FORWARD so a root guest cannot craft a source
        // outside its subnet, bypass the netns SNAT, and have egress evaluated
        // against another slot's chain.
        self.install_antispoof_rule(&veth_host, slot).await?;

        // MASQUERADE only when the operator opted into egress;
        // otherwise workspace packets reach the host but never get
        // SNAT'd onto the upstream NIC.
        if policy.enable_egress {
            self.add_masquerade_rule(slot).await?;
        }

        // DNS filter: spawn one ne-dns-filter process per
        // workspace inside the workspace netns, then install
        // iptables DNAT in the netns so even guests that hardcode
        // 8.8.8.8 get caught and routed to our filter.
        let dns_filter_pid = if policy.allow_hostnames.is_empty() {
            None
        } else if let Some(filter_bin) = &self.inner.dns_filter_binary {
            // Bind + redirect target both use the workspace-side
            // veth IP because that's the only routable IP inside
            // the netns. The host_addr (169.254.X.1) lives in the
            // root netns; the filter spawned via `ip netns exec`
            // can't bind to it.
            let (pid, relay) =
                self.spawn_dns_filter(workspace_id, &netns, &guest_addr, filter_bin, policy)?;
            self.install_dns_redirect(&netns, &guest_addr).await?;
            Some((pid, relay))
        } else {
            warn!(
                workspace_id,
                "allow_hostnames was set but supervisor has no DNS filter binary; \
                 DNS will pass through unfiltered"
            );
            None
        };
        let (dns_filter_pid, dns_audit_relay) = match dns_filter_pid {
            Some((pid, relay)) => (Some(pid), relay),
            None => (None, None),
        };

        // Privacy router: spawn one ne-privacy-router process per
        // workspace inside the workspace netns, then install iptables
        // DNAT in the netns redirecting TCP/80 egress to it. Mirrors
        // the DNS-filter shape; both filters share the netns and the
        // teardown SIGTERM dance.
        let privacy_spawn = if !policy.enable_privacy_router {
            None
        } else if let (Some(bin), Some(policy_path)) = (
            &self.inner.privacy_router_binary,
            &self.inner.privacy_router_policy,
        ) {
            let (pid, relay) =
                self.spawn_privacy_router(workspace_id, &netns, &guest_addr, bin, policy_path)?;
            self.install_privacy_dnat(&netns, &guest_addr).await?;
            Some((pid, relay))
        } else {
            warn!(
                workspace_id,
                "enable_privacy_router was set but supervisor has no privacy-router \
                 binary or policy configured; HTTP egress will not be scanned"
            );
            None
        };
        let (privacy_router_pid, privacy_audit_relay) = match privacy_spawn {
            Some((pid, relay)) => (Some(pid), relay),
            None => (None, None),
        };

        Ok(NetworkSlot {
            workspace_id: workspace_id.to_string(),
            short_id,
            slot,
            netns,
            veth_host,
            veth_guest,
            tap,
            host_ip: host_addr,
            workspace_ip: guest_addr,
            prefix,
            tap_gateway_ip: layout.tap_gateway_ip,
            guest_eth_ip: layout.guest_eth_ip,
            host_route_installed,
            forward_chain,
            masquerade_installed: policy.enable_egress,
            dns_filter_pid,
            dns_audit_relay,
            privacy_router_pid,
            privacy_audit_relay,
        })
    }

    /// Tear down the resources owned by `slot`. Best-effort: each
    /// step's failure is logged but doesn't short-circuit the
    /// teardown — we want to reclaim as much as possible even when
    /// one piece is wedged.
    pub async fn teardown(&self, slot: NetworkSlot) -> Result<(), NetworkError> {
        info!(workspace_id = %slot.workspace_id, netns = %slot.netns, "tearing down workspace network");

        // Remove iptables state first so we don't leak rules if a
        // subsequent step fails. Order matters: drop the FORWARD jump
        // rule, then flush + delete the chain it pointed at.
        if slot.masquerade_installed
            && let Err(e) = self.delete_masquerade_rule(slot.slot).await
        {
            warn!(error = %e, slot = slot.slot, "MASQUERADE delete failed");
        }
        if let Err(e) = self
            .uninstall_forward_chain(slot.slot, &slot.forward_chain)
            .await
        {
            warn!(error = %e, chain = %slot.forward_chain, "FORWARD chain delete failed");
        }
        // Remove the anti-spoof rule; it references `-i <veth>`,
        // which outlives the netns, so iptables keeps a stale rule otherwise.
        if let Err(e) = self
            .uninstall_antispoof_rule(&slot.veth_host, slot.slot)
            .await
        {
            warn!(error = %e, veth = %slot.veth_host, "anti-spoof rule delete failed");
        }
        // Stop the DNS filter before deleting the netns. Sending
        // SIGTERM lets it close cleanly; if it ignores us, the
        // ensuing `ip netns del` will yank it.
        if let Some(pid) = slot.dns_filter_pid
            && let Err(e) = signal_pid(pid, nix::sys::signal::Signal::SIGTERM)
        {
            warn!(error = %e, pid, "SIGTERM to ne-dns-filter failed");
        }
        // The relay task ends naturally when the filter's stdout
        // closes, but abort defensively so a wedged child holding
        // the pipe open doesn't leak the task.
        if let Some(relay) = slot.dns_audit_relay {
            relay.abort();
        }
        // Same SIGTERM + relay-abort dance for the privacy router.
        // Order doesn't matter relative to the DNS filter — both
        // live inside the netns that's about to disappear.
        if let Some(pid) = slot.privacy_router_pid
            && let Err(e) = signal_pid(pid, nix::sys::signal::Signal::SIGTERM)
        {
            warn!(error = %e, pid, "SIGTERM to ne-privacy-router failed");
        }
        if let Some(relay) = slot.privacy_audit_relay {
            relay.abort();
        }
        // Remove the host-side route into the guest /30 before
        // deleting the netns. The SNAT rule + TAP IP inside the netns
        // are reclaimed automatically by `ip netns del`.
        if slot.host_route_installed {
            let layout = SlotIpLayout::for_slot(slot.slot);
            if let Err(e) = self
                .run(
                    "ip",
                    &[
                        "route",
                        "del",
                        &layout.guest_subnet_cidr,
                        "via",
                        &slot.workspace_ip,
                        "dev",
                        &slot.veth_host,
                    ],
                )
                .await
            {
                warn!(error = %e, slot = slot.slot, "guest-subnet host route delete failed");
            }
        }
        // Deleting the netns also reclaims everything inside it
        // (TAP, veth peer, route). The host-side veth was paired so
        // it's already gone too once the netns drops it; an explicit
        // `ip link del` is belt-and-suspenders.
        if let Err(e) = self.run("ip", &["netns", "del", &slot.netns]).await {
            warn!(error = %e, netns = %slot.netns, "netns delete failed");
        }
        if let Err(e) = self.run("ip", &["link", "del", &slot.veth_host]).await {
            // Often returns "Cannot find device" — that's fine, the
            // netns delete already reclaimed it.
            debug!(error = %e, veth = %slot.veth_host, "veth delete (already gone is ok)");
        }

        self.release_slot(slot.slot).await;
        Ok(())
    }

    async fn allocate_slot(&self) -> Result<u8, NetworkError> {
        let mut slots = self.inner.slots.lock().await;
        // Reserve slot 0 (unused); start at 1.
        for i in 1..=usize::from(MAX_SLOT) {
            if slots[i] {
                slots[i] = false;
                // The loop bound `MAX_SLOT` is a u8 constant, so the
                // index fits trivially. Use `unwrap_or(MAX_SLOT)` to
                // satisfy the `expect_used` lint without faking a
                // panic site.
                return Ok(u8::try_from(i).unwrap_or(MAX_SLOT));
            }
        }
        Err(NetworkError::PoolExhausted)
    }

    async fn release_slot(&self, slot: u8) {
        let mut slots = self.inner.slots.lock().await;
        if let Some(entry) = slots.get_mut(usize::from(slot)) {
            *entry = true;
        }
    }

    async fn run(&self, program_alias: &str, args: &[&str]) -> Result<(), NetworkError> {
        // Static dispatch over a closed set of helper-program names.
        // Treat any unknown alias as a programmer bug surfaced as a
        // typed error rather than a runtime panic (clippy::panic).
        let path = match program_alias {
            "ip" => &self.inner.ip_binary,
            "iptables" => &self.inner.iptables_binary,
            other => {
                return Err(NetworkError::Spawn {
                    program: other.to_string(),
                    source: std::io::Error::other(format!(
                        "unknown helper program alias {other:?}"
                    )),
                });
            }
        };
        debug!(program = %program_alias, ?args, "running helper");
        let output = Command::new(path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|source| NetworkError::Spawn {
                program: program_alias.to_string(),
                source,
            })?;
        if !output.status.success() {
            return Err(NetworkError::Command {
                program: program_alias.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(())
    }

    async fn run_in_netns(
        &self,
        netns: &str,
        program_alias: &str,
        args: &[&str],
    ) -> Result<(), NetworkError> {
        // `ip netns exec <netns> <cmd>` runs a command in the netns;
        // we keep this as a separate helper so the error attribution
        // still surfaces the original program name.
        let mut combined = vec!["netns", "exec", netns, program_alias];
        combined.extend_from_slice(args);
        self.run("ip", &combined).await
    }

    /// Create the per-workspace FORWARD chain and populate it with
    /// the policy's allow rules. The chain ends in an implicit DROP
    /// (no explicit DROP rule needed because the chain has no
    /// default policy — packets that fall off run back into the
    /// parent FORWARD chain, where our jump rule was the last action;
    /// returning here means "no allow matched", which we surface by
    /// adding a terminal DROP).
    async fn install_forward_chain(
        &self,
        slot: u8,
        chain: &str,
        policy: &NetworkPolicy,
    ) -> Result<(), NetworkError> {
        let src = format!("169.254.{slot}.0/30");
        // Create the chain. `-N` errors if it already exists; the
        // expected steady state is "doesn't exist yet", so this
        // should always succeed. If a previous teardown leaked the
        // chain, the caller has to clean it up — silent reuse would
        // mask state we want to know about.
        self.run("iptables", &["-N", chain]).await?;

        // Always allow conntrack-tracked return traffic first so
        // legitimate replies to flows we previously allowed get
        // through regardless of the destination CIDR.
        self.run(
            "iptables",
            &[
                "-A",
                chain,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )
        .await?;

        if policy.allow_cidrs.is_empty() && policy.enable_egress {
            // Back-compat shape: no allowlist + egress on means
            // "permit everything". E4 will tighten this when we add
            // DNS mediation; for now this preserves the open-egress
            // behavior the E2 test relied on.
            self.run("iptables", &["-A", chain, "-j", "ACCEPT"]).await?;
        } else {
            for cidr in &policy.allow_cidrs {
                self.run("iptables", &["-A", chain, "-d", cidr, "-j", "ACCEPT"])
                    .await?;
            }
            // Terminal DROP — anything that fell through the allows
            // is denied. We add it even when allow_cidrs is empty so
            // a workspace launched with `enable_egress=false` is
            // truly cut off rather than relying on the parent
            // FORWARD policy.
            self.run("iptables", &["-A", chain, "-j", "DROP"]).await?;
        }

        // Wire the chain into FORWARD. Source-filter on the slot's
        // /30 so this chain only sees that workspace's packets.
        self.run("iptables", &["-A", "FORWARD", "-s", &src, "-j", chain])
            .await?;
        Ok(())
    }

    /// Remove the FORWARD jump rule and flush + delete the chain.
    async fn uninstall_forward_chain(&self, slot: u8, chain: &str) -> Result<(), NetworkError> {
        let src = format!("169.254.{slot}.0/30");
        // Best-effort: ignore "Bad rule" / "Chain does not exist"
        // outputs by capturing failures and returning the first
        // error. Each step still gets a clear stderr.
        self.run("iptables", &["-D", "FORWARD", "-s", &src, "-j", chain])
            .await?;
        self.run("iptables", &["-F", chain]).await?;
        self.run("iptables", &["-X", chain]).await?;
        Ok(())
    }

    /// Install the per-veth anti-spoof rule (audit `S2-F5`).
    ///
    /// The netns SNAT only rewrites packets sourced from the guest's own /30,
    /// so a root guest can emit a source address outside that range to bypass
    /// SNAT and have egress evaluated against another slot's FORWARD chain
    /// (which selects by `-s <slot>/30`). Dropping any packet that arrives on
    /// this slot's host veth with a source outside the slot's /30 — placed at
    /// the top of FORWARD so it precedes every per-workspace jump — closes that
    /// cross-slot spoof.
    async fn install_antispoof_rule(&self, veth_host: &str, slot: u8) -> Result<(), NetworkError> {
        let argv = antispoof_forward_argv(AntiSpoofOp::Insert, veth_host, slot);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run("iptables", &refs).await
    }

    /// Remove the per-veth anti-spoof rule installed by
    /// [`Self::install_antispoof_rule`]. The rule references `-i <veth>`, which
    /// outlives the netns/veth on teardown, so it must be deleted explicitly.
    async fn uninstall_antispoof_rule(
        &self,
        veth_host: &str,
        slot: u8,
    ) -> Result<(), NetworkError> {
        let argv = antispoof_forward_argv(AntiSpoofOp::Delete, veth_host, slot);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run("iptables", &refs).await
    }

    /// Spawn `ne-dns-filter` inside the workspace netns via
    /// `ip netns exec`. Returns the resulting PID, which is the PID
    /// of `ip` (the supervisor's tracked process); the actual
    /// filter binary lives one fork down. SIGTERM to the tracked
    /// PID propagates down the process group because we leave it
    /// in the supervisor's pgrp; the kernel reaps the child when
    /// the netns goes away regardless.
    /// Spawn the DNS filter inside the workspace netns and (when
    /// an audit log was configured) wire its stdout into a relay
    /// task that signs each decision into the supervisor's audit
    /// chain.
    fn spawn_dns_filter(
        &self,
        workspace_id: &str,
        netns: &str,
        listen_addr: &str,
        filter_bin: &std::path::Path,
        policy: &NetworkPolicy,
    ) -> Result<DnsFilterSpawn, NetworkError> {
        let listen = format!("{listen_addr}:53");
        let args = dns_filter_args(
            filter_bin,
            netns,
            &listen,
            &self.inner.dns_upstream,
            &policy.allow_hostnames,
        );
        debug!(?args, netns, "spawning ne-dns-filter");
        // Stdout is piped (we read JSON audit lines from it); stderr
        // stays attached to our parent so operators can tail it.
        let mut child = Command::new(&self.inner.ip_binary)
            .args(&args)
            .stdout(if self.inner.audit.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::inherit())
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| NetworkError::Spawn {
                program: "ip netns exec".into(),
                source,
            })?;

        let pid = child.id().ok_or_else(|| NetworkError::Spawn {
            program: "ip netns exec".into(),
            source: std::io::Error::other("spawned process had no pid"),
        })?;
        info!(pid, netns, "ne-dns-filter spawned");

        let relay = if let Some(audit) = self.inner.audit.clone() {
            let stdout = child.stdout.take().ok_or_else(|| NetworkError::Spawn {
                program: "ip netns exec".into(),
                source: std::io::Error::other("could not capture filter stdout"),
            })?;
            let workspace_id = workspace_id.to_string();
            let handle = tokio::spawn(async move {
                relay_dns_audit_lines(stdout, workspace_id, audit).await;
            });
            Some(std::sync::Arc::new(handle))
        } else {
            None
        };

        Ok((pid, relay))
    }

    /// Spawn `ne-privacy-router` inside the workspace netns. The
    /// router binds on `<listen_addr>:PRIVACY_ROUTER_PORT` (fixed
    /// per workspace — the netns isolates the port). When the
    /// controller has an `AuditLog`, the router's stdout is piped
    /// into a relay task that signs each decision line into the
    /// supervisor's audit chain via [`relay_privacy_audit_lines`].
    fn spawn_privacy_router(
        &self,
        workspace_id: &str,
        netns: &str,
        listen_addr: &str,
        router_bin: &std::path::Path,
        policy_path: &std::path::Path,
    ) -> Result<PrivacyRouterSpawn, NetworkError> {
        let listen = format!("{listen_addr}:{PRIVACY_ROUTER_PORT}");
        let args = privacy_router_args(router_bin, netns, &listen, policy_path);
        debug!(?args, netns, "spawning ne-privacy-router");
        let mut child = Command::new(&self.inner.ip_binary)
            .args(&args)
            .stdout(if self.inner.audit.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::inherit())
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| NetworkError::Spawn {
                program: "ip netns exec (privacy-router)".into(),
                source,
            })?;

        let pid = child.id().ok_or_else(|| NetworkError::Spawn {
            program: "ip netns exec (privacy-router)".into(),
            source: std::io::Error::other("spawned process had no pid"),
        })?;
        info!(pid, netns, "ne-privacy-router spawned");

        let relay = if let Some(audit) = self.inner.audit.clone() {
            let stdout = child.stdout.take().ok_or_else(|| NetworkError::Spawn {
                program: "ip netns exec (privacy-router)".into(),
                source: std::io::Error::other("could not capture router stdout"),
            })?;
            let workspace_id = workspace_id.to_string();
            let handle = tokio::spawn(async move {
                relay_privacy_audit_lines(stdout, workspace_id, audit).await;
            });
            Some(std::sync::Arc::new(handle))
        } else {
            None
        };

        Ok((pid, relay))
    }

    /// Install iptables DNAT rules inside the workspace netns that
    /// redirect all TCP destination port 80 to the privacy router's
    /// listener. Both OUTPUT (packets originated inside the netns)
    /// and PREROUTING (packets entering through the veth from the
    /// guest) are covered, mirroring the DNS redirect shape.
    async fn install_privacy_dnat(&self, netns: &str, host_addr: &str) -> Result<(), NetworkError> {
        for chain in ["OUTPUT", "PREROUTING"] {
            self.run_in_netns(
                netns,
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    chain,
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{host_addr}:{PRIVACY_ROUTER_PORT}"),
                ],
            )
            .await?;
        }
        Ok(())
    }

    /// Install iptables DNAT rules inside the workspace netns that
    /// redirect all UDP+TCP destination port 53 to the host veth
    /// IP. Catches workloads that hardcode an upstream resolver
    /// (e.g. `8.8.8.8`) and bypass `/etc/resolv.conf`.
    async fn install_dns_redirect(&self, netns: &str, host_addr: &str) -> Result<(), NetworkError> {
        for proto in ["udp", "tcp"] {
            self.run_in_netns(
                netns,
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{host_addr}:53"),
                ],
            )
            .await?;
            // PREROUTING covers packets from the guest (which
            // enter the netns through the veth → kernel
            // forwarding path); OUTPUT alone catches only
            // packets originated inside the netns by the host
            // process running there.
            self.run_in_netns(
                netns,
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{host_addr}:53"),
                ],
            )
            .await?;
        }
        Ok(())
    }

    async fn add_masquerade_rule(&self, slot: u8) -> Result<(), NetworkError> {
        let src = format!("169.254.{slot}.0/30");
        self.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &src,
                "-o",
                &self.inner.upstream_iface,
                "-j",
                "MASQUERADE",
            ],
        )
        .await
    }

    async fn delete_masquerade_rule(&self, slot: u8) -> Result<(), NetworkError> {
        let src = format!("169.254.{slot}.0/30");
        self.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &src,
                "-o",
                &self.inner.upstream_iface,
                "-j",
                "MASQUERADE",
            ],
        )
        .await
    }
}

/// Build the `ip netns exec` arg vector for spawning `ne-dns-filter`
/// (or, post-binary-fusion, the single `nee` binary with the
/// `dns-filter` subcommand) inside a workspace network namespace.
///
/// The subcommand token `"dns-filter"` is inserted immediately after
/// `filter_bin` so that a fused binary dispatches to the correct
/// entry point. Helpers that were built before fusion passed no
/// subcommand; the token is the only difference relative to the
/// old inline vector.
fn dns_filter_args(
    filter_bin: &std::path::Path,
    netns: &str,
    listen: &str,
    upstream: &str,
    allow: &[String],
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "netns".into(),
        "exec".into(),
        netns.into(),
        filter_bin.display().to_string(),
        "dns-filter".into(),
        "--listen".into(),
        listen.to_string(),
        "--upstream".into(),
        upstream.to_string(),
    ];
    for h in allow {
        args.push("--allow".into());
        args.push(h.clone());
    }
    args
}

/// Build the `ip netns exec` arg vector for spawning
/// `ne-privacy-router` (or the fused `nee` binary with the
/// `privacy-router` subcommand) inside a workspace network namespace.
///
/// The subcommand token `"privacy-router"` is inserted immediately
/// after `router_bin` so that a fused binary dispatches correctly.
fn privacy_router_args(
    router_bin: &std::path::Path,
    netns: &str,
    listen: &str,
    policy: &std::path::Path,
) -> Vec<String> {
    vec![
        "netns".into(),
        "exec".into(),
        netns.into(),
        router_bin.display().to_string(),
        "privacy-router".into(),
        "--listen".into(),
        listen.to_string(),
        "--policy".into(),
        policy.display().to_string(),
        "--emit-audit-stdout".into(),
    ]
}

/// Whether an anti-spoof rule is being inserted or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AntiSpoofOp {
    /// Insert at the top of FORWARD (position 1).
    Insert,
    /// Delete the matching rule.
    Delete,
}

/// Build the iptables argv for the per-veth anti-spoof rule (audit `S2-F5`).
///
/// The match spec drops any packet arriving on `veth_host` whose source is
/// outside the slot's `169.254.<slot>.0/30` (the only range legitimate,
/// post-SNAT guest traffic carries). On [`AntiSpoofOp::Insert`] the rule is
/// placed at FORWARD position 1 so it precedes every per-workspace `-s
/// <slot>/30 -j <chain>` jump regardless of workspace creation order; the
/// matching [`AntiSpoofOp::Delete`] removes it by spec on teardown.
fn antispoof_forward_argv(op: AntiSpoofOp, veth_host: &str, slot: u8) -> Vec<String> {
    let src = format!("169.254.{slot}.0/30");
    let mut argv: Vec<String> = match op {
        AntiSpoofOp::Insert => {
            vec!["-I".into(), "FORWARD".into(), "1".into()]
        }
        AntiSpoofOp::Delete => vec!["-D".into(), "FORWARD".into()],
    };
    argv.extend([
        "-i".into(),
        veth_host.into(),
        "!".into(),
        "-s".into(),
        src,
        "-j".into(),
        "DROP".into(),
    ]);
    argv
}

/// Hash a workspace id to an 8-char hex suffix safe to embed in
/// kernel interface names (15-char IFNAMSIZ cap). We use the first
/// 8 hex chars of SHA-256 — stable, collision-resistant enough for
/// the slot pool, and platform-agnostic.
fn short_id_for(workspace_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(workspace_id.as_bytes());
    hex::encode(&digest[..4])
}

/// Read JSON audit lines emitted by an `ne-dns-filter` child and
/// sign each one into the supervisor's audit chain. Generic over
/// the reader so tests can substitute an in-memory cursor.
pub(crate) async fn relay_dns_audit_lines<R>(reader: R, workspace_id: String, audit: AuditLog)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(v) => {
                        let event_type = match v.get("decision").and_then(|d| d.as_str()) {
                            Some("allowed") => EventType::DnsAllowed,
                            Some("denied") => EventType::DnsDenied,
                            Some("malformed") => EventType::DnsMalformed,
                            other => {
                                warn!(?other, "unrecognized dns decision; skipping audit emit");
                                continue;
                            }
                        };
                        if let Err(e) = audit.emit(event_type, Some(workspace_id.clone()), v).await
                        {
                            warn!(error = %e, "audit.emit for dns decision failed");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, line = %line,
                              "malformed dns audit line; dropping");
                    }
                }
            }
            Ok(None) => {
                debug!(workspace_id, "dns filter stdout closed; relay exiting");
                return;
            }
            Err(e) => {
                warn!(error = %e, workspace_id, "read on dns filter stdout failed; relay exiting");
                return;
            }
        }
    }
}

/// What [`NetworkController::spawn_dns_filter`] hands back: the
/// filter's PID and (when an audit log was configured) the relay
/// task's join handle so teardown can abort it.
type DnsFilterSpawn = (u32, Option<std::sync::Arc<JoinHandle<()>>>);

/// What [`NetworkController::spawn_privacy_router`] hands back —
/// same shape as [`DnsFilterSpawn`].
type PrivacyRouterSpawn = (u32, Option<std::sync::Arc<JoinHandle<()>>>);

/// Read JSON audit lines emitted by an `ne-privacy-router` child
/// and sign each one into the supervisor's audit chain. Mirrors
/// [`relay_dns_audit_lines`] line-for-line; the `decision` field
/// drives which [`EventType`] variant is emitted.
pub(crate) async fn relay_privacy_audit_lines<R>(reader: R, workspace_id: String, audit: AuditLog)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(v) => {
                        let event_type = match v.get("decision").and_then(|d| d.as_str()) {
                            Some("allowed") => EventType::PrivacyAllowed,
                            Some("audited") => EventType::PrivacyAudited,
                            Some("redacted") => EventType::PrivacyRedacted,
                            Some("blocked") => EventType::PrivacyBlocked,
                            other => {
                                warn!(?other, "unrecognized privacy decision; skipping audit emit");
                                continue;
                            }
                        };
                        if let Err(e) = audit.emit(event_type, Some(workspace_id.clone()), v).await
                        {
                            warn!(error = %e, "audit.emit for privacy decision failed");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, line = %line,
                              "malformed privacy audit line; dropping");
                    }
                }
            }
            Ok(None) => {
                debug!(workspace_id, "privacy router stdout closed; relay exiting");
                return;
            }
            Err(e) => {
                warn!(error = %e, workspace_id,
                      "read on privacy router stdout failed; relay exiting");
                return;
            }
        }
    }
}

/// Send `sig` to `pid` using `kill(2)`. Best-effort: if the process
/// already exited we log and return `Ok(())` because the netns
/// teardown that follows would have reaped it anyway.
fn signal_pid(pid: u32, sig: nix::sys::signal::Signal) -> nix::Result<()> {
    let pid_i32 = i32::try_from(pid).unwrap_or(i32::MAX);
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid_i32), sig) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => {
            debug!(pid, "kill: process already gone");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Best-effort syntactic check on a DNS hostname allowlist entry.
///
/// Accepts patterns of the form `a.b.c`, `*.a.b.c`, and `a` (a
/// single label). Each label must be 1-63 chars, ASCII alphanumeric
/// or hyphen, not starting or ending with a hyphen. The leading
/// `*.` wildcard is permitted and stripped before per-label
/// validation. Rejects empty strings, IP literals, and anything
/// containing whitespace.
pub fn validate_hostname(host: &str) -> Result<(), NetworkError> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(NetworkError::InvalidHostname(host.to_string()));
    }
    let stripped = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    let stripped = stripped.trim_end_matches('.');
    if stripped.is_empty() {
        return Err(NetworkError::InvalidHostname(host.to_string()));
    }
    for label in stripped.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(NetworkError::InvalidHostname(host.to_string()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NetworkError::InvalidHostname(host.to_string()));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(NetworkError::InvalidHostname(host.to_string()));
        }
    }
    Ok(())
}

/// Best-effort syntactic check on an IPv4 CIDR. Accepts `A.B.C.D`,
/// `A.B.C.D/N`, with each octet in 0..=255 and 0 ≤ N ≤ 32. iptables
/// will give us the same "invalid network" rejection if a malformed
/// string slips through, but catching it here surfaces a clearer,
/// typed error with no partial netfilter state.
fn validate_cidr(cidr: &str) -> Result<(), NetworkError> {
    let (addr, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (cidr, None),
    };
    let octets: Vec<&str> = addr.split('.').collect();
    if octets.len() != 4 {
        return Err(NetworkError::InvalidCidr(cidr.to_string()));
    }
    for o in &octets {
        match o.parse::<u8>() {
            Ok(_) => {}
            Err(_) => return Err(NetworkError::InvalidCidr(cidr.to_string())),
        }
    }
    if let Some(p) = prefix {
        match p.parse::<u8>() {
            Ok(n) if n <= 32 => {}
            _ => return Err(NetworkError::InvalidCidr(cidr.to_string())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod fused_subcommand_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn dns_filter_args_insert_subcommand_after_binary() {
        let args = dns_filter_args(
            Path::new("/opt/ne-enclave/bin/nee"),
            "ws-netns",
            "10.0.0.1:53",
            "1.1.1.1:53",
            &["example.com".to_string()],
        );
        assert_eq!(args[3], "/opt/ne-enclave/bin/nee");
        assert_eq!(args[4], "dns-filter");
        assert_eq!(args[5], "--listen");
        assert!(args.contains(&"--allow".to_string()));
        assert!(args.contains(&"example.com".to_string()));
    }

    #[test]
    fn privacy_router_args_insert_subcommand_after_binary() {
        let args = privacy_router_args(
            Path::new("/opt/ne-enclave/bin/nee"),
            "ws-netns",
            "10.0.0.1:8080",
            Path::new("/etc/ne-enclave/privacy.yaml"),
        );
        assert_eq!(args[3], "/opt/ne-enclave/bin/nee");
        assert_eq!(args[4], "privacy-router");
        assert_eq!(args[5], "--listen");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_ip_layout_uses_second_30_for_guest() {
        let l = SlotIpLayout::for_slot(7);
        assert_eq!(l.host_ip, "169.254.7.1");
        assert_eq!(l.workspace_ip, "169.254.7.2");
        assert_eq!(l.tap_gateway_ip, "169.254.7.5");
        assert_eq!(l.guest_eth_ip, "169.254.7.6");
        assert_eq!(l.guest_subnet_cidr, "169.254.7.4/30");
        assert_eq!(l.netmask, "255.255.255.252");
    }

    #[test]
    fn guest_ip_boot_arg_is_kernel_ip_autoconf_form() {
        let l = SlotIpLayout::for_slot(7);
        assert_eq!(
            l.ip_boot_arg(),
            "ip=169.254.7.6::169.254.7.5:255.255.255.252::eth0:off"
        );
    }

    #[test]
    fn antispoof_rule_binds_veth_to_slot_subnet() {
        // Insert at FORWARD position 1, dropping any source outside the slot's
        // own /30 arriving on the workspace veth.
        let insert = antispoof_forward_argv(AntiSpoofOp::Insert, "vh-abcd1234", 7);
        assert_eq!(
            insert,
            vec![
                "-I",
                "FORWARD",
                "1",
                "-i",
                "vh-abcd1234",
                "!",
                "-s",
                "169.254.7.0/30",
                "-j",
                "DROP"
            ]
        );
        // Delete uses the same match spec (no position).
        let delete = antispoof_forward_argv(AntiSpoofOp::Delete, "vh-abcd1234", 7);
        assert_eq!(
            delete,
            vec![
                "-D",
                "FORWARD",
                "-i",
                "vh-abcd1234",
                "!",
                "-s",
                "169.254.7.0/30",
                "-j",
                "DROP"
            ]
        );
    }

    #[test]
    fn short_id_is_deterministic_and_short() {
        let a = short_id_for("wks-aaa");
        let b = short_id_for("wks-aaa");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_id_collisions_are_rare_at_thousand_workspace_scale() {
        // Sanity: distinct inputs produce distinct prefixes for the
        // sample set we care about.
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000 {
            assert!(seen.insert(short_id_for(&format!("wks-{i:08}"))));
        }
    }

    #[tokio::test]
    async fn slot_allocator_recycles_freed_slots() {
        let ctl = NetworkController::new(
            PathBuf::from("/bin/true"),
            PathBuf::from("/bin/true"),
            "eth0".into(),
            None,
            "1.1.1.1:53".into(),
            None,
            None,
            None,
        );
        let a = ctl.allocate_slot().await.expect("first");
        let b = ctl.allocate_slot().await.expect("second");
        assert_ne!(a, b);
        ctl.release_slot(a).await;
        let c = ctl.allocate_slot().await.expect("recycle");
        assert_eq!(c, a, "freed slot should be reused");
    }

    #[test]
    fn validate_hostname_accepts_common_forms() {
        for ok in [
            "openai.com",
            "*.openai.com",
            "api.github.com",
            "single",
            "a-b.c-d.example",
            "1cloudflare.com",
        ] {
            validate_hostname(ok).unwrap_or_else(|e| panic!("{ok:?} should be valid: {e}"));
        }
    }

    #[test]
    fn validate_hostname_rejects_garbage() {
        for bad in [
            "",
            "-leading.example",
            "trailing-.example",
            "has space.example",
            "underscore_.example",
            "127.0.0.1/8",
            &"x".repeat(64), // label too long
        ] {
            match validate_hostname(bad) {
                Err(NetworkError::InvalidHostname(s)) => assert_eq!(s, bad),
                other => panic!("expected InvalidHostname for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_cidr_accepts_bare_address_and_prefixed_address() {
        validate_cidr("10.0.0.0/8").expect("valid prefixed");
        validate_cidr("203.0.113.42").expect("valid bare");
        validate_cidr("0.0.0.0/0").expect("default route");
    }

    #[test]
    fn validate_cidr_rejects_garbage() {
        // Out-of-range octet, missing octet, non-numeric prefix,
        // wildly malformed string — each must surface InvalidCidr.
        for bad in [
            "10.0.0.256",
            "10.0.0",
            "10.0.0.0/abc",
            "not-a-cidr",
            "10.0.0.0/33",
        ] {
            match validate_cidr(bad) {
                Err(NetworkError::InvalidCidr(s)) => assert_eq!(s, bad),
                other => panic!("expected InvalidCidr for {bad:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn dns_audit_relay_signs_each_decision_into_the_chain() {
        // Three JSON lines (allowed, denied, malformed) + one
        // garbage line. The relay must emit three signed events
        // and skip the garbage without aborting.
        let tmp = tempfile::tempdir().expect("tmp");
        let audit = AuditLog::open(tmp.path()).await.expect("open audit");
        let payload = [
            r#"{"kind":"dns_decision","timestamp_ms":1,"qname":"api.openai.com","qtype":1,"peer":"169.254.1.2:5000","decision":"allowed"}"#,
            r#"{"kind":"dns_decision","timestamp_ms":2,"qname":"blocked.example","qtype":1,"peer":"169.254.1.2:5001","decision":"denied"}"#,
            "this is not json",
            r#"{"kind":"dns_decision","timestamp_ms":3,"qname":"junk","qtype":1,"peer":"169.254.1.2:5002","decision":"malformed"}"#,
        ]
        .join("\n");
        let cursor = std::io::Cursor::new(payload.into_bytes());
        relay_dns_audit_lines(cursor, "wks-relay-test".into(), audit.clone()).await;

        let events = audit
            .list(&ne_protocol::audit::ListEventsRequest {
                workspace_id: Some("wks-relay-test".into()),
                since_chain_index: 0,
                limit: 100,
            })
            .await
            .expect("list");
        // Three valid lines → three signed events. The garbage
        // line must be dropped without breaking the chain.
        assert_eq!(events.events.len(), 3, "got: {:?}", events.events);
        let types: Vec<_> = events.events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            types,
            vec![
                EventType::DnsAllowed,
                EventType::DnsDenied,
                EventType::DnsMalformed
            ],
        );
        // The chain indices must be contiguous starting at 0
        // (this audit log was just created).
        assert_eq!(events.events[0].chain_index, 0);
        assert_eq!(events.events[1].chain_index, 1);
        assert_eq!(events.events[2].chain_index, 2);
        // Each event carries the qname back in its payload so
        // downstream consumers can audit by hostname.
        assert_eq!(events.events[0].payload["qname"], "api.openai.com");
        assert_eq!(events.events[1].payload["qname"], "blocked.example");
    }

    #[tokio::test]
    async fn privacy_audit_relay_signs_each_decision_into_the_chain() {
        // Four valid lines (one per decision variant) + one garbage
        // line. The relay must emit four signed events and skip the
        // garbage without aborting — same shape as the DNS test.
        let tmp = tempfile::tempdir().expect("tmp");
        let audit = AuditLog::open(tmp.path()).await.expect("open audit");
        let payload = [
            r#"{"kind":"privacy_decision","timestamp_ms":1,"host":"api.openai.com","path":"/v1/chat","method":"POST","decision":"allowed","detection_count":0,"redaction_count":0}"#,
            r#"{"kind":"privacy_decision","timestamp_ms":2,"host":"api.openai.com","path":"/v1/chat","method":"POST","decision":"audited","detection_count":2,"redaction_count":0}"#,
            "garbage line — relay must skip without aborting",
            r#"{"kind":"privacy_decision","timestamp_ms":3,"host":"api.openai.com","path":"/v1/files","method":"POST","decision":"redacted","detection_count":1,"redaction_count":1}"#,
            r#"{"kind":"privacy_decision","timestamp_ms":4,"host":"api.openai.com","path":"/v1/files","method":"POST","decision":"blocked","detection_count":5,"redaction_count":0}"#,
        ]
        .join("\n");
        let cursor = std::io::Cursor::new(payload.into_bytes());
        relay_privacy_audit_lines(cursor, "wks-privacy-relay".into(), audit.clone()).await;

        let events = audit
            .list(&ne_protocol::audit::ListEventsRequest {
                workspace_id: Some("wks-privacy-relay".into()),
                since_chain_index: 0,
                limit: 100,
            })
            .await
            .expect("list");
        assert_eq!(events.events.len(), 4, "got: {:?}", events.events);
        let types: Vec<_> = events.events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            types,
            vec![
                EventType::PrivacyAllowed,
                EventType::PrivacyAudited,
                EventType::PrivacyRedacted,
                EventType::PrivacyBlocked,
            ],
        );
        // Chain indices must be contiguous starting at 0 (fresh log).
        for (i, evt) in events.events.iter().enumerate() {
            assert_eq!(evt.chain_index, i as u64);
        }
        // Each payload carries the host back so downstream consumers
        // can audit by destination.
        assert_eq!(events.events[0].payload["host"], "api.openai.com");
        assert_eq!(events.events[2].payload["decision"], "redacted");
        assert_eq!(events.events[3].payload["detection_count"], 5);
    }

    #[tokio::test]
    async fn slot_allocator_returns_pool_exhausted() {
        let ctl = NetworkController::new(
            PathBuf::from("/bin/true"),
            PathBuf::from("/bin/true"),
            "eth0".into(),
            None,
            "1.1.1.1:53".into(),
            None,
            None,
            None,
        );
        for _ in 1..=usize::from(MAX_SLOT) {
            ctl.allocate_slot().await.unwrap();
        }
        match ctl.allocate_slot().await {
            Err(NetworkError::PoolExhausted) => {}
            other => panic!("expected PoolExhausted, got {other:?}"),
        }
    }
}

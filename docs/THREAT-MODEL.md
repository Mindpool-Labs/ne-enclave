# NeuronEdge Enclave — Public Threat Model

**Status:** As-built security audit complete for the v0.2.0 candidate. The standard profile is Supported. The `confidential-azure` profile is Preview until the exact signed candidate passes the required KVM and Azure artifact gates without a rebuild.
**Date:** 2026-08-30
**Scope:** The Apache-2.0 NeuronEdge Enclave **runtime** as built for the v0.2.0 candidate. Its external key-release client is verified only against a local development integration topology; this is not a production-topology or GA claim.
**Canonical:** This document is the canonical, as-built threat model. The architecture doc is design intent; this is ground truth.

---

## 1. How to read this document

This is the **as-built** threat model for the NeuronEdge Enclave runtime. It describes what the
shipped code actually enforces today — not what the architecture intends to enforce once
later phases land. Where the two diverge, this document wins. Aspirational design lives in the
architecture doc; if you want to know what NeuronEdge Enclave *protects against right now*, read
this.

It is written for a hostile reader: a security researcher who will diff every claim here
against the source under `crates/`, and who rewards disclosed limits
and punishes concealment. We share that incentive. NeuronEdge Enclave's core value is an enforced execution
boundary with independently verifiable audit and attestation artifacts. The standard profile
uses software-rooted evidence and trusts the host operator. The Preview Azure profile exposes
hardware-rooted evidence for the outer CVM, but does not attest guest code or create a
per-workspace hardware boundary. An unfalsifiable security claim is worthless to a reviewer.
So the rule below is non-negotiable, for
us and for every future editor of this file.

**Status legend (used throughout):**

- ✅ **Implemented** — wired in the shipped runtime; cites a real code path under `crates/`
  that exists at the current commit. If it is marked ✅, you can go read it.
- ◐ **Partial** — present, but with specific limits that are enumerated inline. Do not
  read a ◐ as a complete control.
- ⏳ **Planned / not shipped** — design intent only. **Do not rely on it.** It is named
  here so it cannot be quietly mistaken for a present defense, and so its absence is on the
  record.

**Maintenance commitment.** The runtime publishes this threat model and updates
it **per release**. Any future editor who upgrades an item from ⏳ or ◐ to ✅ MUST cite the
code path that justifies the upgrade, verified against the release commit. A status tag
without a code citation is a bug in this document.

**Invitation to challenge.** This is a living document. Security
researchers are explicitly invited to challenge any claim in it. If you find an
✅ we cannot back with code, or a limitation we failed to disclose, that is exactly the
report we want. See [SECURITY.md](../SECURITY.md) for the disclosure process, or send reports to **security@mindpool.io**. The coordinated-disclosure timeline
is in §11.

---

## 2. What the v0.2.0 candidate contains

The NeuronEdge Enclave runtime runs untrusted agent code inside
**standard (non-confidential) Firecracker microVMs** with a minimized device model and a
jailer (chroot / seccomp / cgroups / namespaces). Egress is **deny-by-default** per
workspace network namespace, DNS is host-mediated, and every host-side policy decision is
written to a **signed audit Merkle chain** (per-event Ed25519 over a SHA-256 chain — this
is shipped, not aspirational). A **privacy router** redacts PII on LLM-bound egress, but
only partially (see §5/§9). **API-key authentication** gates both the gRPC and REST
surfaces — `crates/ne-api/src/auth.rs` (`ApiKeyStore`). The authentication requirement is
met: the daemon refuses to start in production posture unless at least one API key is
configured, and all endpoints (including health) require a valid `Authorization: Bearer
<token>` header. **In-process TLS is available** (`crates/ne-api/src/tls.rs`): when configured
(`--tls-cert`/`--tls-key`) the gRPC and REST wire is encrypted end-to-end. The daemon
**refuses to start** in production posture on a non-loopback bind without TLS
(`ApiConfig::guard` in `crates/ne-api/src/lib.rs`). The residual ⏳ is **mTLS
(mutual auth)** and control-plane JWT — server-TLS authenticates the *server* and
encrypts the wire, not the *client* (client identity is still established by API-key
auth, separately). Additionally, **`nee audit export` / `nee audit verify`** (`crates/ne/src/audit_cli.rs`)
produce an independently-verifiable, externally-pinnable artifact from the signed
Merkle chain — operators can ship the chain off-host and any party can confirm it is
unedited. Immutable off-host *storage* (WORM) remains the operator's responsibility
(see §7 T5, §9). **The attestation foundation is shipped**: the `ne-attestation` crate ships an `AttestationProvider` trait, a `SoftwareProvider` software-fallback (Ed25519, runtime-key-rooted, NOT firmware-rooted), and a pure `verify()`. The on-demand challenge–response evidence API is threaded end-to-end (proto → gRPC → REST → Python/TS SDK → `nee workspace attest` CLI). Three signed audit events flow through the Merkle chain: `AttestationEvidenceIssued` (evidence generated and signed by the host and issued to the caller — the supervisor cannot observe the caller's client-side `verify()`, so the event records issuance, **not** verification), `AttestationFailed` (provider error, or measurement/nonce validation failure), `AttestationReplayed` (nonce already seen; replay rejected). The production software-attestation gate is a startup `bail!` (refuses to serve before any audit sink exists) and so emits **no** audit event. Event payloads carry only hashes — `nonce_sha256`, `measurement_sha256`, `provider_type` — never the raw nonce, signing key, or proof bytes. See §4 / §9 for the honest software-evidence trust caveat.

The separate `confidential-azure` profile is **Preview**. It runs one OpenShell
workspace directly inside an Azure SEV-SNP CVM, selects the Azure vTPM provider
explicitly, and exposes complete typed evidence through REST, gRPC, the CLI,
and the Python/TypeScript SDKs. The Azure vTPM evidence primitive has been
verified on DCasv5 silicon. Product promotion still requires the exact signed
v0.2.0 candidate to pass the KVM and Azure artifact gates without a rebuild.
The profile does not use nested Firecracker, does not support
snapshot/restore/fork, and does not claim guest-code measurement,
per-workspace hardware isolation, or hardware-rooted key release. No public
v0.2.0 product profile selects the direct `/dev/sev-guest` provider.

Sealed snapshots ship runtime-side. The external key-release client uses native mTLS and binds the attested snapshot digest as associated data. A local Docker integration topology verified wrap and release through one key-release service, one PostgreSQL service for atomic nonce claims, and one OpenBao development-mode Transit service that retains the external KEK. If a dependency outage happens after a nonce claim, the original sealed snapshot requires fresh evidence before retry. This is not a production-topology, HA, certificate-lifecycle, audit-export, or hardware-rooted key-release claim. **Managed image enforcement is shipped**: cold create accepts only lowercase kernel/rootfs SHA-256 digests, resolves their fixed locations beneath the supervisor-owned image store, hashes retained no-follow file handles, and copies verified bytes into independent per-workspace files before launch (`crates/ne-supervisor/src/image.rs`, `crates/ne-supervisor/src/workspace.rs`). Restore and fork use the same resolver for the digest pair signed into the manifest. This prevents callers from supplying arbitrary host paths and prevents writable rootfs aliasing between the store or workspaces. It does not defend against a hostile host root, which remains trusted. **Paused-VM snapshot/restore
with a signed version-5 manifest is shipped**: a read-only-rootfs PAUSED microVM can be snapshotted
into a reusable artifact (`crates/ne-supervisor/src/firecracker.rs` `snapshot_create`,
`crates/ne-supervisor/src/workspace.rs` `WorkspaceManager::snapshot`); the artifact's
Ed25519-signed manifest and snapshot artifact hashes are verified before managed images are resolved on restore
(`crates/ne-supervisor/src/snapshot.rs` `verify_artifact`); the standalone `nee snapshot
verify` CLI runs the same verification offline. Version 4 and older manifests are rejected.
Snapshots require `rootfs_read_only=true` and remain limited to non-networked workspaces.
Unsealed snapshot artifacts remain plaintext at rest. The runtime-side sealed format is
shipped, but hardware-rooted sealed-snapshot confidentiality and live control-plane KMS /
silicon validation remain unclaimed (§4, §9). **Fork from snapshot and fork identity reset are
shipped**: `ForkWorkspace` spawns a fresh Firecracker process that loads the
snapshot via `PUT /snapshot/load {resume_vm: true}` — the same restore path, immune to the
deferred in-place Pause/Resume vsock bug — then sends a `ResetIdentity` vsock RPC to the
guest agent carrying a fresh hostname, machine-id, and 32 random entropy bytes; the guest
applies them via `sethostname(2)`, `/run/machine-id` symlink, and `/dev/urandom` write. A
fork is **never returned with un-reset identity**: if the guest is unreachable or
`ResetIdentity` fails the newly-booted VM is torn down (`ForkFailed`). Honest limits are
in §7 T2 and §9. Runtime supply-chain enforcement (OSV / OPA / CVSS) has **not** been
absorbed into the runtime workspace. **Warm-pool is shipped**: `CreateWorkspace(tier)` pops a pre-warmed, identity-reset, snapshot-forked member from a low-watermark pool; pool-hit latency ~2 ms vs cold-start P50 1404 ms; non-networked members only; `PoolHit`/`PoolMiss` audit events. **Live-state snapshot is shipped**: `snapshot(live=true)` captures and signs the running VM, boots a fresh Firecracker from the artifact under a temporary id, atomically swaps it into the registry under the source id, and reaps the frozen process — after the swap the source is `Running` and vsock-reachable under a new PID, but **during** capture + fresh-restore it is briefly paused and unreachable (a multi-second window; a `run_command` against the source in that window fails closed with a transient `Timeout`, and clients needing zero interruption should fork instead); see §7 T2 / §9 for residual risks. **Host-based ingress routing is shipped**: an in-process L7 reverse proxy (`ne-ingress` crate) routes `{port}-{workspace_id}.{ingress_domain}` (Host header) to the guest service over its TAP/netns — no public IP per workspace; `exposed_ports` create-time allowlist + dynamic `ExposePort`/`UnexposePort`; SSRF-guarded (registry-only targets, link-local pin); hop-by-hop header stripping; optional per-port auth-header injection; edge TLS with operator wildcard cert; deny-by-default; signed `IngressRouteAllowed`/`IngressRouteDenied`/`IngressPortExposed`/`IngressPortUnexposed` events; the guest gains a real L3 path (kernel `ip=` boot arg) and its egress is SNAT'd into the existing deny-by-default FORWARD chain — no bypass. WebSocket/`Connection: Upgrade` proxying is **deferred** to a follow-up (see §9).

---

## 3. Assets

What the runtime is trying to protect, as it exists today.

| Asset | Sensitivity | Notes |
|---|---|---|
| Customer agent code and data (in-memory, in-transit) | High | In `standard`, in-memory data is visible to the trusted host operator. In `confidential-azure` Preview, the outer Azure CVM supplies SEV-SNP memory encryption; OpenShell isolation inside the CVM remains shared-kernel (§4/§9). |
| Audit event chain | High (tamper-evidence required) | Protected by the signed Merkle chain, §5/§7 (T5). |
| Runtime audit signing key | High | Ed25519 keypair generated on the host at first run, persisted private-key `0600` under the state dir, and loaded on subsequent runs; the public half is inlined in every event so verifiers need no out-of-band key — `crates/ne-supervisor/src/audit.rs`. **Not** embedded in deployment artifacts (it is generated locally). There is **no rotation today**: the protocol can accommodate a later rotation without invalidating prior entries, but none is performed (key rotation is a future capability). |
| Operator credentials | High | Host-side operator access. |
| Image artifacts (guest kernel, rootfs) | Medium | Imported into a supervisor-owned content-addressed store, then re-verified by digest on create and restore before independent staging (§4); may carry upstream CVEs. |
| Telemetry / event metadata | Medium | Emitted for the security event surface. |

> **Key-release and sealed-snapshot assets (not hardware-rooted).** The following are
> listed here so their current status is explicit:
>
> - **Sealed-snapshot contents** — paused-VM snapshot/restore with a signed manifest is
>   shipped; the **runtime-side sealed format** (AES-256-GCM + signed `seal.json`
>   envelope + runtime-local attestation gate + software-fallback KEK) is shipped
>   but is **at-rest / confidentiality-vs-the-operator only** (software-fallback KEK), NOT
>   hardware-protected. The external key-release client is verified only in a
>   local Docker integration topology and does not make a hardware-rooted or
>   GA claim.
> - **KEKs in an external key-management system** — the verified local
>   integration keeps the KEK in OpenBao Transit. Vault, cloud KMS, and HSM
>   backends are not verified.

---

## 4. Trust boundaries (as-built)

The runtime exposes two product profiles with different trust boundaries:
`standard` and Preview `confidential-azure`.

**Trusted in `standard`.** Host kernel and KVM; the `ne-api`, `ne-supervisor`, and
operator-provided Firecracker binaries; host network policy (nftables); host storage metadata;
and the audit signing key. The v0.2.0 release candidate signs the shipped `nee` binary,
OpenShell binary and policies, SDK packages, component manifest, and checksums; publishes an
SPDX SBOM plus GitHub build provenance; and makes the bootstrap installer verify signatures,
checksums, and resolved manifest digests before installation. Firecracker and jailer remain
operator-provided and outside that signed bundle. These release controls do not make a hostile
root trusted, do not verify binaries continuously after installation, and do not implement
runtime package-policy enforcement. Guest kernels and rootfs images are checked
against operator-supplied SHA-256 values during import (`crates/ne/src/install/image.rs`).
Cold create, restore, and fork then resolve only fixed artifact names beneath the configured
managed store, reject symlinks and non-regular files, verify bytes through retained no-follow
handles, and copy them into independent chroot files (`crates/ne-supervisor/src/image.rs`,
`crates/ne-supervisor/src/workspace.rs`).
**The host operator is trusted in `standard`.** The operator can read guest memory; we do
not pretend otherwise (§6, §9). In `confidential-azure`, the Azure CVM boundary is intended
to exclude the cloud host operator, while guest root inside that CVM remains trusted.

**Partially trusted.** The guest agent — used for convenience and liveness, but the host
**must assume it can lie or be compromised**; the host enforces policy, never the guest.
Rootfs package content (signed at build, but carries upstream packages). External control
plane metadata is partially trusted and validated through the versioned
key-release contract in the tested local topology. Fleet enrollment and
certificate lifecycle are not implemented or verified.

**Azure confidential product profile — ◐ Preview.** The product routing,
single-workspace capacity limit, OpenShell execution backend, Azure vTPM
provider selection, public capability discovery, and typed evidence APIs are
implemented. The low-level evidence primitive is silicon-verified; the product
lane remains Preview until the exact signed v0.2.0 artifact passes both
required environment gates. Hardware-rooted key release, confidential
snapshot/restore/fork, guest-code measurement, and per-workspace hardware
isolation are not part of this profile.

**Software-fallback attestation foundation — ◐ Partial.** The `ne-attestation` crate and full evidence API are shipped. The software provider attests "this runtime instance, holding this key, asserts this workspace ran with this configuration." It is **NOT CPU-firmware-rooted**: it does not prove host-platform integrity, it does not exclude a compromised host operator, and it cannot substitute for hardware attestation where hardware is required. Honest caveats:

- The public complete-evidence envelope exposes a typed provider enum. The
  internal canonical `report_data` still signs `provider_type: software`, so a
  proof cannot be relabeled as hardware; an attestation policy can and should
  reject software evidence where hardware is required.
- `verify()` pins to a **caller-supplied `expected_signer`** (the runtime identity public key, obtained out-of-band via control-plane enrollment or manual pinning). The key embedded in the evidence is only a consistency check — it cannot self-vouch. Without this out-of-band pin, the caller cannot establish the trust anchor.
- The supervisor refuses to start with the software provider on a non-loopback bind unless `NE_ATTEST_ALLOW_SOFTWARE=1` is set (`crates/ne-supervisor/src/serve.rs`).
- The per-workspace nonce ring is **bounded (256 entries) and in-memory only** — it is not a durable or cross-host anti-replay store. The ring prevents naive replay within a single supervisor session; callers requiring strong single-use nonce guarantees MUST enforce nonce uniqueness out-of-band (e.g., via a control-plane-managed nonce registry).

**SEV-SNP host-CVM evidence primitive — ✅ Verified on Azure silicon; product
profile ◐ Preview.** The `ne-attestation` crate ships two SEV-SNP verify arms:
`Proof::SevSnp` (the `/dev/sev-guest` ioctl path — for GCP/bare-metal/AWS,
synthetic-unit-tested) and `Proof::SevSnpAzure` (the OpenHCL paravisor vTPM +
TPM-Quote path — **verified end-to-end on an Azure DCasv5**). Both share
`TrustAnchor::SevSnp` (AMD `AmdRootCert` / ARK), VCEK→ARK chain verification,
and reference-value policy pins. The honest claim this primitive supports is
**firmware-attested host CVM with hardware-anchored, per-request nonce
binding** — *not* "each microVM is independently hardware-isolated."
Specifically:

- The Azure path is a **two-layer binding**: (L1) the boot-fixed AMD report (read from vTPM NVRAM `0x01400001` via `tpm2_nvread`) with `SHA256(var_data) == report.REPORT_DATA[..32]` anchoring the vTPM Attestation Key (AK) into the hardware-signed report, validated VCEK→ASK→baked Milan ARK; (L2) a `tpm2_quote` under the AK (RSA-2048 RSASSA-PKCS1v1.5-SHA256) whose signature covers a `TPM2B_ATTEST` embedding `SHA256(canonical_report_data)` — genuine anti-replay (only the live, hardware-anchored AK can sign a fresh quote).
- **Paravisor-in-TCB.** Azure relays the report through the OpenHCL paravisor, so the paravisor is inside the measured, attested set. This is honestly *larger* than a bare-metal/GCP report (no paravisor) but is **not weaker on report authenticity** — the VCEK→ARK signature chain is identical and the report is the genuine AMD artifact.
- The report's `REPORT_DATA` is **boot-fixed** (the AK fingerprint), NOT a caller nonce. The per-request binding is via the TPM Quote (Layer 2), not the report's own `REPORT_DATA` field. The claim must not conflate the two.
- It is **not** per-microVM attestation. The confidential tier is **single-CVM-direct (B)** — the agent + OpenShell run directly inside the host CVM; there is no nested microVM. Workspace identity binds to *host-CVM* evidence. **Per-workspace hardware isolation (true per-microVM SNP) is deferred to a future bare-metal tier.**
- It is **not KMS-hardware-bound.** The runtime software fallback uses host-held key material. External evaluation coverage does not validate a production hardware-rooted key-release path.
- It is **not** guest-code measurement. The report's `MEASUREMENT` is the host-CVM/paravisor launch digest, not NeuronEdge runtime or workspace code.
- **Nesting is architecturally impossible on managed cloud.** Nesting a Firecracker microVM inside a SEV-SNP CVM is impossible — AMD SEV-SNP strips the virtualization extensions from the leaf guest, and VMPLs are not an escape hatch. Verified: [Azure CVM FAQ](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-faq), [AMDESE/AMDSEV #169](https://github.com/AMDESE/AMDSEV/issues/169). The `confidential-azure` profile therefore runs OpenShell directly inside the outer CVM and does not install or invoke Firecracker. Per-microVM `KVM_SEV_SNP_*` launch is retained only for a future bare-metal profile.
- **The confidential tier's isolation is shared-kernel, in-process.** On the confidential tier, OpenShell isolates the agent with Landlock/seccomp/network-namespaces/privilege-drop — strong, but **not a separate hardware-virtualized kernel**. The CVM boundary is the outer wall (operator-excluded, attested); OpenShell is defense-in-depth within it. A supervisor exploit yields the CVM guest's root, not a contained VM — the blast radius is bounded by the CVM. **One CVM per sensitive workspace** is mandated; multi-tenant-in-one-CVM is rejected (process-level isolation between workspaces in one CVM is too weak for the isolation guarantee).
- TDX, cross-host transfer, fleet enrollment, certificate lifecycle, and the
  control-plane attestation policy engine remain **⏳ Planned**. The external
  key-release path has locally verified mTLS and PostgreSQL nonce claims; that
  proof does not establish fleet-wide replay protection.

The `/dev/sev-guest` `Proof::SevSnp` path (GCP/bare-metal) remains synthetic-tested and silicon-unvalidated on those clouds; only the Azure `Proof::SevSnpAzure` path is silicon-verified.

**Sealed snapshots (runtime side) — ◐ Partial / CP- and silicon-gated.** The `ne-seal` crate ships the runtime side of sealed snapshots: an AES-256-GCM chunked-streaming content container, a separate signed `seal.json` envelope (`SealEnvelope`, domain-tagged `ne-enclave-seal-v1`) carrying a `SealingPolicy` + wrapped DEK + a `manifest_canonical_sha256` that binds the seal to its companion `SnapshotManifest` (a seal↔manifest swap fails `BindingMismatch`), and a **runtime-local** attestation gate (`ne_attestation::verify` against the embedded policy) that must pass before the DEK is released. The path is **synthetic-unit-tested** end-to-end, including policy-mismatch denial and binding-mismatch rejection. Honest caveats:

- The shipped local KEK is a **software fallback** (HKDF of the host Ed25519 key). Separately, the runtime-to-external `KeyRelease` contract is verified with native mTLS, PostgreSQL nonce claims, and OpenBao Transit KEK custody in one local Docker topology. **Still unverified:** HashiCorp Vault, cloud KMS, HSM backing, fleet enrollment, certificate lifecycle, audit export, HA, multi-region operation, and production deployment validation.
- The software-fallback path is **at-rest / confidentiality-vs-the-operator only — NOT hardware-protected.** An insider host operator who holds the runtime Ed25519 key material can derive the KEK and decrypt the artifact; the gate enforces *policy match*, not operator exclusion. It closes "plaintext snapshot at rest," not "operator can read the snapshot."
- The **hardware-rooted claim** — genuine SEV-SNP evidence gating production key release — is **unclaimed**. The local external-path proof does not validate a production deployment or silicon-rooted KMS claim.
- Sealed snapshots are wired into the supervisor snapshot path **Linux-gated**; they apply only where the existing snapshot path applies (non-networked workspaces today, §9).

Do not represent sealed snapshots as hardware-protected confidentiality today. The shipped artifact is a runtime-side format plus a runtime-local attestation gate over a software-fallback KEK. The external Transit path is verified only in its tested local topology.

**Untrusted.** Agent-generated code, package installs inside the workspace, shell commands,
files written by the agent, network destinations the guest requests, guest root after
compromise, and the calling SDK and its credentials.

---

## 5. Attack surface

Per-surface, as shipped. Every ✅ cites a code path that exists at the current commit.

| Surface | What is exposed | Current mitigation | Status |
|---|---|---|---|
| Firecracker microVM boundary | Virtio device model reachable from guest | Minimized device model; no unnecessary devices; operator-provided Firecracker is trusted as installed and is outside the signed NeuronEdge bundle; jailer applied — `crates/ne-supervisor/src/firecracker.rs` | ✅ |
| Jailer + host process hardening | Firecracker process privileges on the host | chroot / seccomp / cgroups v2 / namespaces via jailer, plus a hardened systemd capability set in the install templates — `crates/ne-supervisor/`, `crates/ne/templates/*.service.tmpl` | ✅ |
| vsock guest↔supervisor IPC | Control channel between guest agent and supervisor | vsock transport with the supervisor as policy authority; the guest agent is partially trusted and cannot reconfigure host policy — `crates/ne-guest-agent/src/main.rs`, `crates/ne-supervisor/src/firecracker.rs` | ✅ |
| NDJSON supervisor IPC socket | Local privileged control socket | NDJSON framing with `SO_PEERCRED` peer-UID authentication (`PeerAuth::RequireUid`) — only the expected local UID may issue commands — `crates/ne-supervisor/src/ipc.rs`. **Capacity bound:** single-threaded; drops under a boot-storm of concurrent creates (see §9). | ✅ |
| gRPC + REST API surface | The runtime's external API | **API-key authentication ✅ gates all endpoints** (gRPC tonic interceptor + REST axum middleware over `ApiKeyStore`) — `crates/ne-api/src/auth.rs`, `crates/ne-api/src/lib.rs`, `crates/ne-api/src/rest.rs`. The daemon refuses to start in production posture without at least one configured key. The authentication requirement is met. **Wire confidentiality ✅ when TLS is configured** — in-process TLS via `crates/ne-api/src/tls.rs` (`TlsConfig`); `serve_grpc` builds a `ServerTlsConfig` (tonic) and `serve_rest` builds a `RustlsConfig` (axum-server); `ApiConfig::guard` refuses a non-loopback production bind without TLS — `crates/ne-api/src/lib.rs`. Bearer tokens are in-the-clear only when the operator chooses loopback-only deployment without TLS or terminates TLS at a reverse proxy. **Remaining ⏳:** mTLS (mutual/client-cert auth) and control-plane JWT. | ◐ |
| Host networking (egress) | Guest network access | Per-workspace netns + TAP + nftables **deny-by-default** egress; guest has no `CAP_NET_ADMIN` to rewrite host policy — `crates/ne-supervisor/src/network.rs` | ✅ |
| DNS mediation | Name resolution from the guest | Host-controlled resolver / DNS filter mediates guest lookups — `crates/ne-dns-filter/src/lib.rs` | ✅ |
| Privacy router (LLM egress) | PII / credentials on LLM-bound traffic | Intercepts LLM egress and redacts PII — `crates/ne-privacy-router/{lib,proxy,policy_loader}.rs`. **Limits:** HTTP/1.1 cleartext only, tier-1 regex matching only, request-direction only; NER and HTTPS interception are deferred (see §9). | ◐ |
| Snapshot artifact and image integrity | Snapshot files on the host filesystem plus managed kernel/rootfs identities | Version-5 `SnapshotManifest` signs the snapshot hashes and both managed image digests (`crates/ne-protocol/src/snapshot.rs`). On restore/fork, `verify_artifact_pinned` (`crates/ne-supervisor/src/snapshot.rs`) pins the Ed25519 signature to the **host's own signing key** (`AuditLog::verifying_key()`) and verifies the memory/vmstate hashes. The supervisor then resolves and hashes the signed image digests through the same managed-image resolver used by cold create, staging independent files before launch. Pre-version-5 manifests, missing images, mutated images, symlinks, and non-regular artifacts fail closed. A self-signed manifest with an attacker key is rejected; the offline `nee snapshot verify` diagnostic remains integrity-only by design. **Limits:** writable-rootfs and networked workspaces cannot be snapshotted; a hostile host root remains trusted; sealed-snapshot confidentiality retains the caveats below. | ◐ |
| Runtime supply-chain enforcement | Package installs / dependency fetches at execution time | **Not absorbed into the runtime workspace.** The OSV / OPA / CVSS runtime-supply-chain engine lives in the OpenShell fork and is not wired into `crates/` at this revision. | ⏳ |

---

## 6. Adversary model

Adapted from the architecture doc, with an added column for what is actually defended
in the shipped runtime.

| Adversary | Capabilities | Goal | Defended today? |
|---|---|---|---|
| **Compromised agent** | Arbitrary code execution in workspace; egress within policy | Escape workspace; exfiltrate; pivot | **Yes** — Firecracker + jailer workspace boundary and deny-by-default egress contain it (§5, §7 T1). |
| **Malicious tenant** | Workspace-creation rights; worst-case workloads | Cross-tenant access; resource exhaustion | **Partially** — cgroups v2 resource caps apply. Cross-tenant snapshot leakage: snapshots are shipped; the manifest is signed by the host key and hashes all content — a tenant cannot substitute a foreign snapshot without breaking verification. **Fork with identity reset is shipped**: each fork boots in its own jailer chroot with a fresh vsock UDS path and a host-reset hostname/machine-id/RNG, fail-closed on reset failure. Per-fork memory copy cost means snapshot state (in-memory data at capture time) is present in each fork; usage contract is snapshot-a-warm-idle-base (see §7 T2, §9). CoW shared-backend (UFFD) deferred. |
| **Network attacker** | Position between SDK and API | Eavesdrop; tamper; replay | **Partially** — callers are authenticated via API-key auth (`crates/ne-api/src/auth.rs`); an unauthenticated caller is rejected before it can issue commands. **Wire confidentiality is now defended on the encrypted channel when in-process TLS is deployed** — `crates/ne-api/src/tls.rs` encrypts gRPC and REST; `ApiConfig::guard` prevents a production daemon from silently serving tokens in clear on a non-loopback bind (`crates/ne-api/src/lib.rs`). An on-path attacker cannot eavesdrop a TLS-configured deployment. Loopback-only operator deployments without TLS remain a supported configuration (no external network exposure). **Client impersonation (mTLS) ⏳ Planned** — server-TLS authenticates the server, not the client; client identity is API-key only. |
| **Insider host operator** | Full host access | Read agent memory; read disk; modify policy | **Profile-specific.** Not defended in `standard`: the operator is trusted and can read guest memory. The Preview `confidential-azure` profile uses the outer SEV-SNP CVM to exclude the cloud host operator, but guest root inside the CVM remains trusted and the lane is not Supported until the exact signed artifact gate passes (§4, §7 T3, §9). |
| **Insider control-plane operator** | Control-plane DB access | Tamper with audit; release keys to unattested host | **No** (later scope) — audit export to external WORM and attested key release are not yet shipped; the runtime's local Merkle chain is tamper-*evident* today but local-only (§7 T5, §9). |
| **Supply-chain attacker** | Inject into build pipeline / upstream deps | Plant backdoor in a release | **Partially.** The v0.2.0 candidate has signed components, checksums, an SPDX SBOM, GitHub provenance, installer verification, and no-rebuild environment gates. Upstream dependencies, GitHub Actions, operator-provided Firecracker/jailer, post-install host mutation, and runtime package installs remain trusted or outside this control (§4, §5, §9). |

---

## 7. Selected attack trees

Reproduced from the architecture doc, with every leaf status-tagged against shipped
code.

**T1 — Agent escapes workspace.**
- (a) Firecracker VM escape via a virtio device CVE. *Mitigation:* minimal device model,
  current Firecracker, jailer — `crates/ne-supervisor/src/firecracker.rs`,
  `crates/ne-supervisor/`. **✅**
- (b) Guest kernel exploit chained to a Firecracker exploit. *Mitigation:* minimal signed
  guest kernel + the CVE-response process (§11). **✅** (boundary mechanism) — note the
  residual risk of an undisclosed chained 0-day is inherent to any VM boundary and is
  handled by CVE response, not eliminated.
- (c) Credential exfiltration via prompt injection through the LLM proxy. *Mitigation:*
  the privacy router mediates LLM egress so credentials need not be visible to the guest —
  `crates/ne-privacy-router/{lib,proxy,policy_loader}.rs`. **◐** — partial: HTTP/1.1
  cleartext, tier-1 regex, request-direction only (§9).

**T2 — Cross-tenant data leak via snapshot / fork. ◐ Partial.**
Paused-VM snapshot/restore and fork-from-snapshot with identity reset are shipped.
Shipped mitigations:
- (a) A tenant restores a foreign workspace's snapshot artifact (cross-tenant swap). *Mitigation:*
  `verify_artifact_pinned` (`crates/ne-supervisor/src/snapshot.rs`) pins the Ed25519 signature to the
  **host signing key** and verifies all content hashes before booting; the manifest encodes
  `created_from_workspace_id` and `snapshot_id`. An artifact signed by any other key (incl. a tenant's own,
  fully self-consistent forgery) is rejected — authenticity, not merely integrity. Restore/fork
  IDs (`new_workspace_id`, `snapshot_id`) are also validated against `[A-Za-z0-9-]{1,64}` before any path
  is built, so neither can traverse the state/chroot tree. **✅**
- (b) A tenant manipulates snapshot data in transit on the host filesystem. *Mitigation:*
  same — any bit-flip or substitution breaks SHA-256 hash verification. **✅**
- (c) Two concurrent forks of the same snapshot share guest identity (hostname/MAC/CID).
  *Mitigation*: **`ResetIdentity` vsock RPC** resets hostname, machine-id, and
  RNG on each fork independently, delivered before the fork is returned to the caller; the
  call is fail-closed (fork torn down on reset failure, never returned with un-reset
  identity). Guest CID is inherited from the snapshot vmstate (Firecracker `/snapshot/load`
  has no `guest_cid` override); isolation is per-chroot UDS, not CID — verified empirically:
  two same-CID forks run concurrently with no cross-talk. **✅ hostname/machine-id/RNG;
  ◐ CID (inherited, isolated by chroot/UDS)**
- (d) Fork exposes snapshot in-memory data to the fork consumer. *Mitigation:* usage
  contract — snapshot a warm-but-idle base before any sensitive data is loaded; identity
  reset does not scrub in-memory workspace contents (§9). **◐ operational control only.**

Not yet shipped:
- Copy-on-write shared backend (UFFD) on fork — each fork currently copies the full memory
  image; shared CoW is deferred (§9).
- Production-topology sealed-snapshot key release, fleet enrollment, certificate lifecycle, audit export, and HA. The external path is verified only in its tested local topology; the runtime's local gate remains UX/latency-only.
- Tenant-scoped access policy on the snapshot/fork API — no multi-tenant control-plane in
  this runtime; the supervisor host key is the only signing authority.

**T3 — Insider operator reads workspace state. Profile-specific.**
In `standard`, the operator is trusted and this attack is not defended (§4,
§6). In Preview `confidential-azure`, Azure SEV-SNP protects the outer CVM's
memory from the cloud host operator and typed evidence lets a caller verify a
fresh host-CVM quote. The boundary does not exclude guest root inside the CVM,
does not measure the workspace code, and is not a hardware-rooted key-release
claim. The product lane remains Preview until the exact signed artifact gate
passes.

**T4 — Replay attack on key release. ◐ Partial (external path); ⏳ runtime-side.**
This document is scoped to the Apache-2.0 **runtime**; its local gate remains
UX/latency-only. The external path is locally verified with native mTLS and
atomic PostgreSQL nonce claims. A dependency outage after a claim requires
fresh evidence before the original sealed snapshot can retry. This does not
verify fleet-wide replay protection, certificate lifecycle, HA, or a production
deployment.

**T5 — Audit chain tampering. ◐ Partial.**
Leaves (a) and (b) are ✅; the chain is **tamper-evident locally only** — there is no
off-host export today, so leaf (c) is ⏳.
- (a) Operator edits or truncates events. *Mitigation:* a SHA-256 Merkle chain
  (`chain_index`, `prev_hash_hex`, genesis handling) makes any edit or truncation
  detectable to a party already holding an earlier chain root —
  `crates/ne-supervisor/src/audit.rs`, `crates/ne-protocol/src/audit.rs`. **✅**
- (b) Operator rewrites event content. *Mitigation:* a per-event Ed25519 signature with the
  signer public key inlined; any rewrite breaks the signature and the chain —
  `crates/ne-supervisor/src/audit.rs`. **✅**
- (c) Operator deletes the whole local log / no off-host retention. *Mitigation:* `nee
  audit export` / `nee audit verify` now produce an independently-verifiable,
  externally-pinnable artifact from the local chain — `crates/ne-protocol/src/audit.rs`
  (`verify_chain`), `crates/ne/src/audit_cli.rs`. Any party holding a previously-exported
  manifest can detect tail truncation (mismatched `root_hex`), **front-truncation** (mismatched
  `count`/`first_index`/`last_index` — `nee audit verify` now checks all of them, not just the root),
  edits, broken links, and signature forgeries against the pinned root. **◐**
  — the export tool exists and is
  independently runnable; however, **immutable off-host storage (WORM) remains
  operator-provided**: the tool ships the artifact, not the sink. A root operator who
  deletes the log *before* any off-host export still goes undetected. Automated periodic
  export to a WORM sink is the operator/control-plane responsibility (§9).

**T-ING — Inbound ingress attack surface. ✅ Shipped.**

The ingress edge adds a new inbound attack surface. Each threat below is tagged against the shipped mitigation.

**T-ING-1 — SSRF / cross-workspace routing.** An attacker crafts a Host header to reach another tenant's workspace or an arbitrary host IP. *Mitigation:* the proxy only ever dials the `IngressRegistry`-resolved `guest_ip`; before connecting, the resolved IP is asserted to lie within `169.254.0.0/16` (`ne-ingress` SSRF guard — hard error + deny audit if violated, never dialed). No client-controlled value reaches `connect`. Per-netns isolation means the edge can physically reach only the resolved workspace's guest; routing outside the link-local block is structurally impossible from the netns. **✅**

**T-ING-2 — Host-header spoofing / domain mismatch.** A client sends a crafted `Host` header that partially matches the ingress domain to slip into a different workspace's route. *Mitigation:* `parse_host` requires an exact suffix match on the configured `ingress_domain` (`ne-ingress` hostname parser); a mismatch → `421 Misdirected Request` + signed `IngressRouteDenied{reason: domain_mismatch}`. **✅**

**T-ING-3 — Unexposed-port access.** A client attempts to reach a port that the workspace operator has not exposed. *Mitigation:* deny-by-default; only `(workspace_id, port)` pairs present in `IngressRegistry` route; any other combination → `404` + signed `IngressRouteDenied{reason: unexposed_port}`. **✅**

**T-ING-4 — Stale route after workspace teardown.** A request arrives after a workspace is destroyed, routing to a now-defunct or recycled process. *Mitigation:* `WorkspaceManager::terminate` calls `IngressRegistry::remove_workspace` and removes the host route synchronously before returning; a torn-down workspace is immediately unroutable. Any registry mutation that spans a lock drop re-checks presence before re-inserting (resurrection-race discipline). **✅**

**T-ING-5 — Inbound DoS / resource exhaustion.** A high-rate flood of inbound connections could exhaust host-side sockets or task count. *Mitigation:* ◐ — **a per-process connection-count cap now ships**: the edge bounds concurrent in-flight connections with a `Semaphore` (default 1024, `--ingress-max-connections`); excess connections wait in the kernel accept backlog rather than spawning unboundedly. Slowloris is bounded by an HTTP/1 `header_read_timeout`, and a stalled TLS handshake by an `accept()` timeout. **Residual blast-radius disclosure:** the ingress edge still runs in the **same process and Tokio runtime as the privileged supervisor**, so the connection cap only bounds — does not isolate — the blast radius. The robust fix (a future item) runs ingress in a separate process/cgroup with its own `LimitNOFILE`/`MemoryMax`. Per-workspace / per-IP token buckets remain a flagged follow-up; operators should still front the edge with an upstream LB / rate-limiter for fuller protection.

**T-ING-6 — Plaintext exposure on the ingress wire.** Ingress traffic travels unencrypted and is readable by an on-path observer. *Mitigation:* the edge terminates TLS with an operator-provided wildcard `*.{ingress_domain}` cert (rustls/ring); the guard logic refuses to start the ingress listener on a non-loopback bind without TLS in production; partial TLS config (cert XOR key) fails startup closed. Dev-mode loopback plaintext is explicitly allowed. The edge TLS terminate path is unit-tested; the plaintext loopback path is exercised by the e2e. **✅ (TLS gate + plaintext guard); ◐ (e2e covers plaintext loopback; TLS terminate path is unit-tested only)**

**T-ING-7 — Header-injection abuse / secret leakage in audit.** A client strips or replaces an operator-injected auth header, or audit logs expose secret header values. *Mitigation:* injected headers overwrite any client-supplied header with the same name (per-port `inject_headers` in the `IngressRegistry`). Hop-by-hop headers (RFC 7230 §6.1 `Connection`-listed + always-stripped set) are removed from the upstream request before injection, so a client cannot abuse `Connection: foo` to strip a to-be-injected `foo` header or leak upgrade intent. Header *values* are never written to the audit log — only header *names* are recorded on `IngressPortExposed`. **✅**

**T-ING-8 — Egress-policy bypass via the new guest L3 path.** The guest gaining a real `eth0` IP could open egress routes that bypass the deny-by-default FORWARD chain. *Mitigation:* the guest's egress is SNAT'd to `.2` (the veth workspace IP) by a netns POSTROUTING rule before leaving the workspace netns, so the guest's packets hit the existing deny-by-default FORWARD chain and per-policy allow rules exactly as designed. The DNS filter and privacy router (which bind `.2` inside the netns) also engage on real traffic for the first time. No new egress path is introduced; the shipped policy is now effective on real guest packets. **✅**

*Known limitation / residual:* **WebSocket / `Connection: Upgrade` proxying is deferred.** The low-level hyper 1.x upgrade bridging is disproportionate for the initial implementation; standard HTTP request/response proxying (the primary use case) is complete. Until it ships, a workspace cannot proxy WebSocket connections through the ingress edge; clients attempting an upgrade receive a connection error rather than an upgrade response. This is an explicit missing capability, not a security control gap.

---

## 8. Assumptions & explicit non-goals

We solve **execution-boundary safety, not model-behavior safety.** A jailbroken agent
contained by NeuronEdge Enclave cannot escape to the host; it can still produce wrong or harmful
outputs. The following are out of scope, stated so they are not
mistaken for gaps we claim to close:

- **CPU side-channel attacks (Spectre/Meltdown class).** We track CPU-vendor mitigations and
  document our position; we do not claim to defeat these classes.
- **Physical attacks on the host (cold-boot, PCIe DMA).** Mitigation depends entirely on the
  deployment environment; the runtime does not address them.
- **Adversarial inputs to the model / model-behavior safety.** Prompt injection that
  produces a bad *decision* (as opposed to a boundary *escape*) is outside this boundary;
  the runtime contains the blast radius, it does not align the model.

---

## 9. Known limitations & residual-risk register

Full disclosure. Every item below is a place the as-built runtime does **not** protect you,
protects you only partially, **or imposes a capacity limit**, with the phase that addresses
it.

| Limitation | Current impact | Addressed by |
|---|---|---|
| **No production authentication — RESOLVED** | **Shipped:** API-key authentication gates both gRPC and REST via `ApiKeyStore` — `crates/ne-api/src/auth.rs` (load + verify), `crates/ne-api/src/lib.rs` (gRPC tonic interceptor), `crates/ne-api/src/rest.rs` (`authed_router` / `api_key_guard`). The daemon refuses to start in production posture without at least one configured key; every endpoint (including health/Ping) is authenticated. The authentication requirement is met. **In-process TLS ✅ shipped** — `crates/ne-api/src/tls.rs`; when `--tls-cert`/`--tls-key` are configured, gRPC (`serve_grpc`) and REST (`serve_rest`) wire traffic is encrypted; `ApiConfig::guard` refuses a non-loopback production bind without TLS (`crates/ne-api/src/lib.rs`). **Remaining ⏳:** mTLS (mutual/client-cert auth) and control-plane-signed JWT are planned. Server-TLS authenticates the server and encrypts the wire; it does not authenticate the client (that is API-key auth). | ✅ Auth shipped. ✅ In-process TLS shipped. ⏳ mTLS / JWT: planned. |
| **Boot-storm IPC capacity bound** | The single-threaded NDJSON supervisor IPC socket has a measured concurrency ceiling: under a burst of roughly 50 concurrent workspace-create requests, the socket can drop a request under contention (observed as a `serde: EOF` on the affected caller, which must retry). This is an availability/capacity limit under extreme concurrent load, not an isolation or authentication weakness; peer-UID auth (§5) is unaffected. Documented here as a known capacity bound. | Planned: concurrent IPC handling. |
| **Audit chain is local-only (no off-host/WORM export) — RESOLVED with caveat** | **Shipped:** `nee audit export` writes a copy of the signed chain plus a manifest (with pinnable `root_hex`) to any operator-chosen destination; `nee audit verify` independently confirms every signature, chain link, and — against a previously-retained manifest — detects tail truncation. Shared verifier: `crates/ne-protocol/src/audit.rs` (`verify_chain`, `canonical_bytes`); CLI: `crates/ne/src/audit_cli.rs`. Any party holding an exported manifest can now detect edits, broken links, and tail truncation without trusting the host. **Remaining ⏳:** immutable off-host storage (WORM) is operator-provided — the tool ships the verifiable artifact, not the sink. A root operator who deletes the local log *before* any export, or who controls the export destination, can still destroy evidence. Automated periodic export and a WORM sink are the operator/control-plane's responsibility. | ◐ Verifiable export tool shipped. ⏳ WORM sink + control-plane aggregation: operator-provided / future. |
| **Privacy router is partial** | PII redaction on LLM egress covers HTTP/1.1 cleartext only, uses tier-1 regex matching only, and inspects the request direction only. HTTPS interception and NER-based detection are not present, and response-direction leakage is not inspected. | Later: HTTPS interception, NER, response-direction coverage. |
| **Standard profile has no operator-excluding memory encryption** | In `standard`, the host operator is trusted and can read Firecracker guest memory in cleartext. The separate `confidential-azure` profile runs one OpenShell workspace directly inside an SEV-SNP CVM, with shared-kernel isolation inside that CVM. | `standard`: accepted boundary. `confidential-azure`: ◐ Preview until the signed v0.2.0 KVM and Azure artifact gates pass without a rebuild. |
| **Attestation foundation + Azure SEV-SNP evidence** | **Implemented:** `ne-attestation`; complete typed evidence over gRPC, REST, CLI, and Python/TypeScript SDKs; offline verification; signed audit events. The Azure vTPM + TPM-Quote two-layer primitive is verified on DCasv5 silicon. **Caveats:** the measurement covers the host-CVM/OpenHCL launch, not guest code; OpenShell is shared-kernel; no hardware-rooted key release; no mTLS/strong-global replay; direct `/dev/sev-guest` is not selected by a v0.2.0 product profile. | ✅ Azure evidence primitive verified. ◐ `confidential-azure` product lane Preview. ⏳ Direct `/dev/sev-guest` silicon validation, TDX, and policy engine. |
| **Snapshot: single-live-instance identity boundary — RESOLVED with caveats** | **Shipped:** `ForkWorkspace` sends a `ResetIdentity` vsock RPC after each fork boots, resetting hostname, machine-id, and RNG before the workspace is returned to the caller; fail-closed (fork torn down on failure). Two concurrent forks of the same snapshot now have distinct hostname and machine-id. **Remaining ◐:** guest CID is inherited from snapshot vmstate (Firecracker has no `guest_cid` override in `/snapshot/load`); isolation is per-chroot UDS — verified empirically safe. In-memory snapshot contents (data at capture time) are present in each fork; scrubbing is operational (snapshot-a-warm-idle-base usage contract, §9 below). | ✅ hostname/machine-id/RNG reset. ◐ CID inherited (UDS-isolated). ◐ In-memory state: operational contract. |
| **Fork residual risks** | (a) **Inherited snapshot state:** forks inherit all captured snapshot in-memory data and `/workspace` contents at capture time. Identity reset does not scrub memory contents — only hostname/machine-id/RNG are reset. Usage contract: snapshot a warm-but-idle base workspace before any sensitive data is loaded; fork → reset → dispatch. (b) **CID inherited by design:** each fork inherits the vsock CID from the snapshot vmstate; isolation is per-chroot UDS, not CID (verified: two same-CID forks run concurrently, no cross-talk). (c) **Per-fork memory copy cost:** each fork copies the full memory image into its own jailer chroot; shared-backend UFFD copy-on-write is deferred. (d) **RNG reset window:** a brief window between VM boot and the `ResetIdentity` call uses the snapshot's RNG state; the window is bounded by guest agent readiness. On reset the guest now issues `RNDRESEEDCRNG` after mixing the host-supplied seed, so the kernel CRNG diverges **immediately** rather than only at the next periodic reseed (a plain `/dev/urandom` write does not reseed the CRNG on kernels ≥ 5.18). Workload-internal userspace CSPRNGs seeded before snapshot remain identical across forks and can only be re-seeded by the workload itself. (e) **Networked forks unsupported:** Firecracker bakes the host TAP into vmstate, same as snapshot/restore. | (c) Planned: UFFD CoW shared backend. All others: operational or accepted. |
| **Warm-pool residual risks** | (a) **Inherited base-snapshot state:** pooled members inherit all captured base-snapshot state — in-memory contents and `/workspace` at capture time. Identity reset re-randomizes only hostname/machine-id/RNG; it does not scrub memory. Usage contract: pool from a *warm-but-idle* base (no sensitive data loaded at snapshot time). (b) **Provisional hostname:** a member's guest hostname is its pool id (`pool-{tier}-{ulid}`), not the caller's `workspace_id`. This is cosmetic — machine-id distinctness and RNG divergence hold; the cold path does not guarantee `hostname == workspace_id` either. (c) **Per-member full memory copy:** each pooled member copies the full memory image into its jailer chroot; shared-backend / UFFD copy-on-write is deferred. (d) **Non-networked members only:** snapshot/restore bakes the host TAP device into vmstate, so pooled members carry no network device. `Create(tier)` with network config is rejected (`InvalidRequest`) — the pool is not silently bypassed. | (c) Planned: UFFD CoW shared backend. All others: operational or accepted. |
| **Live-state snapshot residual risks** | (a) **Brief freeze gap during the swap:** the source is paused for the duration of capture plus the fresh-restore boot and guest-ready wait. While paused, the source id resolves to the frozen old instance and a command against it does not make progress; the registry swap to the fresh, already-ready instance happens only after `wait_for_guest_ready` succeeds, so callers never reach a half-booted VM. After the swap the source resolves to the new `Running` instance under a new PID. The interruption is bounded by capture + warm-restore latency; clients requiring zero interruption should use a fork instead. (b) **Source acquires a new Firecracker PID:** the post-swap pid is surfaced as `SnapshotInfo.firecracker_pid`; anything that keyed off the original PID (e.g., external process monitors, cgroup paths scoped to the old pid) must re-resolve. (c) **Transient shared guest CID:** during the brief window between the fresh FC process starting and the frozen old process being reaped, both share the inherited guest CID. This is safe — host↔guest isolation is per-chroot UDS, not CID; the old process is frozen and immediately reaped; the window is bounded and accepted. (d) **Inherited snapshot state-capture caveats:** live snapshot captures in-memory data and `/workspace` contents at the snapshot point; the source diverges from the artifact afterward. In-memory secrets and `/workspace` contents present at capture time are preserved in the artifact — the same usage contract as non-live snapshot/fork (snapshot-a-warm-idle-base). | (a)(b) Operational / accepted. (c) Accepted (per-chroot UDS isolation proven). (d) Future: sealed snapshots. |
| **Snapshot: non-networked workspaces only** | Snapshot/restore is supported only for `network: None` workspaces. Firecracker bakes the host TAP device name into vmstate, so restoring a networked workspace into a different workspace ID would reference a non-existent TAP. `WorkspaceManager::snapshot` rejects a networked source workspace (`crates/ne-supervisor/src/workspace.rs`); `firecracker::restore` rejects a networked restore config (`LaunchError::NetworkedRestoreUnsupported`, `crates/ne-supervisor/src/firecracker.rs`). Networked snapshot with TAP host-device remapping is deferred. | Future: networked snapshot (TAP remap). |
| **Snapshot artifacts are plaintext at rest — PARTIALLY RESOLVED** | **Runtime-side sealed format shipped:** the `ne-seal` crate provides AES-256-GCM chunked-streaming content encryption + a signed `seal.json` envelope (`ne-enclave-seal-v1`, manifest↔seal canonical-hash binding) + a runtime-local attestation gate (`ne_attestation::verify` against the embedded `SealingPolicy`) that must pass before the DEK is released. **Honest ceiling:** the shipped KEK is a **software fallback** (HKDF of the host Ed25519 key) — an insider host operator who holds the runtime key material can derive it. A separate external path is verified only in a local topology with native mTLS, PostgreSQL nonce claims, and OpenBao Transit KEK custody. Sealed snapshots are wired into the supervisor path **Linux-gated** and apply only where the snapshot path applies (non-networked workspaces). **Remaining ⏳:** Vault, cloud KMS, HSM, real-silicon policy validation, enrollment, certificate lifecycle, audit export, HA, multi-region operation, and production deployment validation — the hardware-rooted claim is unclaimed. | ◐ Runtime-side sealed format shipped. ◐ External path verified in one local topology. ⏳ Broader KMS, fleet, and production deployment gates. |
| **Snapshot/restore serialization under concurrent load** | The supervisor's instances-map mutex is held across the Firecracker pause + snapshot API call, so concurrent snapshots of different workspaces serialize during the capture window. This is an availability/throughput limit, not an isolation weakness — consistent with the existing create/terminate posture and the §9 boot-storm IPC note. Per-instance locking is a planned improvement. | Planned: per-instance locking for snapshot concurrency. |
| **In-place Pause/Resume API deferred** | After a Firecracker in-place `PATCH /vm Resumed`, the host→guest vsock control channel stops servicing new CONNECTs — the resumed guest is unreachable. The public `PauseWorkspace`/`ResumeWorkspace` API is therefore deferred and returns `Unsupported`; it does not represent a new attack surface. The low-level `crate::firecracker::pause`/`resume` calls remain and are used internally by `WorkspaceManager::snapshot` (pause-before-snapshot, resume-after). **Live-state snapshot is shipped via hot-swap restore** (capture + fresh-process restore + registry swap), which delivers the live-snapshot value — source VM survives reachable — without requiring the in-place resume path. In-place `PauseWorkspace`/`ResumeWorkspace` remains deferred. Any remediation must be compatible with upstream Firecracker integration; this document makes no implementation promise. | Future: upstream-compatible investigation of in-place resume. |
| **Runtime supply-chain enforcement not absorbed** | OSV / OPA / CVSS enforcement of package installs at execution time is not wired into the standard runtime workspace; it lives in the OpenShell fork. This is distinct from the v0.2.0 signed release bundle, checksums, SPDX SBOM, provenance, and installer verification. | Future: absorb runtime package-policy enforcement into `crates/`. |
| **Ingress residual risks** | (a) **WebSocket / `Connection: Upgrade` proxying deferred:** low-level hyper 1.x upgrade bridging is disproportionate for the initial implementation; clients attempting a WebSocket upgrade receive a connection error. Not a security control gap — the control plane should not rely on WebSocket ingress until a follow-up ships. (b) **Inbound rate-limiting is partial:** a per-process connection-count cap + header/handshake read timeouts now ship, bounding fd/memory exhaustion; per-workspace / per-IP token buckets and true process/cgroup isolation of the edge from the supervisor remain a flagged future follow-up — operators should front the edge with an upstream LB / rate-limiter until then. (c) **Ingress TLS terminate path unit-tested only:** the e2e exercises the plaintext loopback path (dev mode); the TLS terminate path is covered by unit tests (`crates/ne-ingress`). (d) **Ingress applies to cold-booted networked workspaces only:** warm-pool / forked / snapshot-restored members are non-networked; `Create(tier)` with `network_config` is rejected. This is by design (Firecracker bakes the TAP into vmstate) — it is not a missing control. | (a)(b) Follow-up. (c)(d) Operational / accepted. |

---

## 10. Mapping to external frameworks

A light-touch orientation only — there is no per-event mapping matrix in this document, by
design.

- **MITRE ATT&CK** — the escape and pivot trees (§7 T1) align with the relevant
  Execution / Privilege-Escalation / Lateral-Movement techniques an analyst would expect for
  VM-isolated untrusted code.
- **OWASP LLM / agentic** — the privacy-router and prompt-injection-via-egress surfaces
  (§5, §7 T1c) correspond to the OWASP LLM/agentic risk categories around sensitive-data
  disclosure and excessive-agency egress.
- **DeepMind agent threat taxonomy** — useful as orientation for reasoning about
  agent-initiated actions vs. boundary escapes.

Per-event annotation against these taxonomies is a **future control-plane feature**, not the responsibility of this document. We name the frameworks for orientation
and stop there.

---

## 11. Reporting & disclosure

The runtime follows the published CVE-response policy:

- **Acknowledge** a security report within **72 hours**.
- **Fix** high-severity issues within **30 days**.
- **Coordinated disclosure** with the reporter.
- **Public advisory** at fix release, with affected versions and remediation.
- **Subscriber notification** via the security mailing list.

**Security contact.** Send reports to **security@mindpool.io** (see [SECURITY.md](../SECURITY.md) for the full policy).

**Update commitment.** This threat model is published with the runtime and updated
**per release**. Each release revises the status tags against the shipped commit; an upgrade
to ✅ requires a code citation.

**Living document.** Security researchers are invited to challenge
any claim here publicly. Disclosed limits and corrected over-claims are exactly the feedback
this document is built to absorb.

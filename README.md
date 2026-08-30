# NeuronEdge Enclave

**The open-source execution boundary for AI agents, with a Preview Azure confidential profile.**

NeuronEdge Enclave joined Mindpool in July 2026. It remains a standalone, Apache-2.0 execution boundary for AI agents — see https://neuronedge.ai.

Autonomous agents run code, install packages, call APIs, and touch sensitive data. NeuronEdge Enclave gives each agent a governed sandbox: an upstream Firecracker microVM with its own kernel in the supported standard profile, or an OpenShell sandbox directly inside an SEV-SNP CVM in the Preview Azure confidential profile.

Apache-2.0. Self-hosted. Rust top-to-bottom.

```sh
# Install on any Linux + KVM host (Ubuntu 22.04+/24.04, x86_64):
curl -fsSL https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download/install.sh | sh
```

---

## Why

Agent frameworks (LangChain, Mastra, CrewAI, custom) need somewhere safe to execute the code they generate. Today's options each have a catch:

- **Containers (Docker/gVisor)** — share a kernel with the host. Container escapes are a long, real history; agent-generated code (from prompt injection, supply-chain compromise, adversarial inputs) is exactly the threat model where a shared-kernel boundary isn't enough.
- **Managed sandbox clouds (E2B, Modal)** — solve isolation but move your data to someone else's infrastructure. Regulated enterprises (finance, healthcare, government) can't approve them: data residency, DPAs, attestation gaps.
- **No boundary** — agents run on the developer's laptop or a shared CI runner. The blast radius of a compromised agent is the whole machine.

NeuronEdge Enclave is the **fourth option**: a self-hosted runtime where standard workspaces get their own kernel through upstream Firecracker. A separate Preview profile runs one sensitive workspace directly inside an Azure SEV-SNP CVM with OpenShell shared-kernel isolation and hardware-rooted evidence for the outer CVM.

**Core value:** *an evidence-backed execution boundary, deployable on customer-owned infrastructure, Apache-2.0.*

---

## What it is

A Rust runtime that creates, controls, snapshots, and destroys upstream-Firecracker-backed microVM sandboxes for agent workloads. The standard profile includes runtime-owned networking, privacy routing, and signed audit controls. The confidential profile uses a pinned [OpenShell](https://github.com/Mindpool-Labs/OpenShell) sandbox directly inside the CVM. OpenShell's package supply-chain engine is not wired into standard workspaces.

| Capability | Maturity |
|---|---|
| Standard Firecracker execution and lifecycle | Supported |
| gRPC + REST API + CLI + Python/TypeScript SDKs | Supported |
| Networking, DNS mediation, privacy routing, signed audit, snapshot/restore/fork, warm pool, and ingress | Supported in `standard`, subject to documented limits |
| Signed release bundle, checksums, SPDX SBOM, and Sigstore provenance | Implemented for the v0.2.0 candidate |
| Azure confidential execution (`confidential-azure`) | **Preview** until the exact signed v0.2.0 artifact gate passes |
| Azure vTPM SEV-SNP evidence primitive | Verified on DCasv5; product lane remains Preview |
| Runtime package supply-chain enforcement in standard workspaces | Not implemented |
| Confidential snapshot / restore / fork | Not implemented |
| Intel TDX and per-microVM SNP | Planned |

See the [capability ledger](docs/CAPABILITIES.md) for artifacts, verification
paths, promotion rules, and limits.

### The two tiers

Enclave ships one API with two discoverable execution profiles, selected by
`NE_EXECUTION_PROFILE`:

- **`standard`** (default, Supported) — each workspace is a Firecracker microVM with its own kernel.
- **`confidential-azure`** (Preview) — one workspace runs inside an Azure AMD SEV-SNP CVM. The public evidence binds the workspace request to the attested host-CVM/OpenHCL launch and a fresh TPM quote. Capacity is fixed at one workspace per CVM.

Call `GET /v1/runtime/capabilities`, `GetRuntimeCapabilities`, or
`nee runtime capabilities` before choosing operations. See
[deploy/README.md](deploy/README.md#execution-profiles-standard--confidential-azure)
for activation.

---

## Quickstart

**Prerequisites:** install [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) so the bootstrap installer can verify the release. The standard profile also requires a Linux x86_64 host with `/dev/kvm` and operator-installed [Firecracker](https://github.com/firecracker-microvm/firecracker/releases) + jailer at `/opt/ne-enclave/bin/`.

```sh
# 1. Install the runtime (renders config + hardened systemd units + starts them)
curl -fsSL https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download/install.sh | sh

# 2. Verify
/opt/ne-enclave/bin/nee doctor      # preflight: KVM, Firecracker, jailer
systemctl status ne-supervisor ne-api

# 3. Import into the privileged managed store and retain its verified digests
KERNEL_SHA256=$(sha256sum /path/to/vmlinux | cut -d' ' -f1)
ROOTFS_SHA256=$(sha256sum /path/to/rootfs.img | cut -d' ' -f1)
sudo /opt/ne-enclave/bin/nee image import \
  --kernel /path/to/vmlinux --kernel-sha256 "$KERNEL_SHA256" \
  --rootfs /path/to/rootfs.img --rootfs-sha256 "$ROOTFS_SHA256"

# 4. Create a workspace + run a command (REST)
curl -s http://127.0.0.1:8080/v1/workspaces \
  -H 'Content-Type: application/json' \
  -d "{\"workspace_id\":\"hello\",\"kernel_sha256\":\"$KERNEL_SHA256\",\"rootfs_sha256\":\"$ROOTFS_SHA256\",\"rootfs_read_only\":true,\"vcpu_count\":1,\"mem_size_mib\":512,\"guest_vsock_cid\":3}"

curl -s http://127.0.0.1:8080/v1/workspaces/hello/exec \
  -H 'Content-Type: application/json' \
  -d '{"command":"echo","args":["hello from a microVM"]}'
```

**Python SDK:**
```python
from ne import Client
c = Client("127.0.0.1:50051")
ws = c.create_workspace(
    workspace_id="hello",
    kernel_sha256="<kernel digest supplied during import>",
    rootfs_sha256="<rootfs digest supplied during import>",
    vcpu_count=1,
    mem_size_mib=512,
    guest_vsock_cid=3,
)
c.execute_command(workspace_id=ws.workspace_id, command="echo", args=["hello from Python"])
```

**TypeScript SDK:**
```typescript
import { Client } from "@neuronedge/enclave";
const c = new Client({ target: "127.0.0.1:50051" });
const ws = await c.createWorkspace({
  workspaceId: "hello",
  kernelSha256: "<kernel digest supplied during import>",
  rootfsSha256: "<rootfs digest supplied during import>",
  vcpuCount: 1,
  memSizeMib: 512,
  guestVsockCid: 3,
});
await c.executeCommand({ workspaceId: ws.workspaceId, command: "echo", args: ["hello from TS"] });
```

For air-gapped installs, custom images, and the full CLI surface, see [deploy/README.md](deploy/README.md).

---

## How it works

```
┌─── Host (Linux + KVM) ─────────────────────────────────────────────┐
│                                                                     │
│  Your agent framework (LangChain, Mastra, custom)                   │
│        │  gRPC / REST                                               │
│        ▼                                                            │
│  ┌─ ne-api (unprivileged, the front door) ──┐                       │
│  └───────────────┬──────────────────────────┘                       │
│                  │ Unix socket (peer-cred auth)                      │
│  ┌───────────────▼──────────────────────────┐                       │
│  │ ne-supervisor (privileged)               │                       │
│  │   ├─ Firecracker microVM (per workspace) │ ← standard tier       │
│  │   │   └─ guest agent over vsock          │                       │
│  │   ├─ L7 privacy router (PII, egress)     │                       │
│  │   └─ signed audit chain                  │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                     │
│  Confidential tier: the whole host is a SEV-SNP CVM; the workspace  │
│  runs directly in it, memory-encrypted + attested.                  │
└─────────────────────────────────────────────────────────────────────┘
```

Standard workspaces get a separate kernel and can use the runtime's networking,
DNS, privacy-router, audit, snapshot, fork, warm-pool, and ingress capabilities.
Confidential workspaces use the profile-specific OpenShell backend and expose a
smaller operation set. The capabilities endpoint is the contract; features are
not implied across profiles.

---

## Foundation

NeuronEdge integrates two production-credible Apache-2.0 Rust projects:

- **[NVIDIA OpenShell](https://github.com/Mindpool-Labs/OpenShell)** — the sandbox substrate used by the Preview confidential profile (Landlock/seccomp/netns isolation and OPA policy). Its package supply-chain engine is not part of the standard runtime profile.
- **[AWS Firecracker](https://github.com/firecracker-microvm/firecracker)** — the microVM substrate (upstream prebuilt binary for the standard tier).

---

## Security posture

- **Standard tier:** per-workspace kernel isolation via Firecracker + jailer (chroot, cgroups, seccomp, namespaces). The host operator is trusted (no memory encryption).
- **Confidential profile (Preview):** one workspace runs inside an Azure AMD SEV-SNP CVM. Evidence verification uses a two-layer binding: the boot-fixed AMD report anchors the vTPM attestation key, and a fresh TPM quote binds the caller nonce. The v0.2.0 product lane is not promoted to Supported until the exact signed release gate succeeds.
- **Honest ceiling:** the confidential tier attests the *host CVM launch*, not the agent's guest code (guest-code measurement is a tracked follow-on). The isolation within the CVM is OpenShell's shared-kernel sandbox (Landlock/seccomp/netns), not a separate per-workspace hardware boundary (that's a future bare-metal tier). Per-workspace hardware isolation via nested microVMs is architecturally impossible on managed cloud (AMD SEV-SNP strips the virtualization extensions from the leaf guest).

The full, as-built threat model — trust boundaries, attack trees, and an explicit residual-risk register — is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). It is written for a hostile reader and names every limitation honestly.

---

## Status

This branch prepares the evidence-backed v0.2.0 candidate. The standard profile
is Supported. Azure confidential execution remains Preview until the signed
candidate passes the required Azure artifact gate and the release is published
without a rebuild.

- Intel TDX confidential mode (needs DCesv5 silicon)
- Per-workspace hardware attestation (bare-metal SEV-SNP, the v2 premium tier)
- Snapshot/restore/fork for the confidential profile
- mTLS for the runtime↔control-plane transport
- Live AWS KMS backing
- Runtime package supply-chain enforcement for standard workspaces

---

## Documentation

- [**Self-host install guide**](deploy/README.md) — the operator-facing deep dive: install layout, hardened systemd units, networking model, air-gapped installs, and the confidential-tier activation path.
- [Capability ledger](docs/CAPABILITIES.md) — public maturity, artifact, verification, and limit matrix.
- [Threat model](docs/THREAT-MODEL.md) — the as-built security posture: trust boundaries, attack trees, and an explicit residual-risk register.
- [Benchmark harness](bench/README.md) — the measurement harness (cold start, boot storm, density, exec latency, snapshot/restore).

---

## Community

- **Issues:** [github.com/Mindpool-Labs/ne-enclave/issues](https://github.com/Mindpool-Labs/ne-enclave/issues)
- **Discussions:** [github.com/Mindpool-Labs/ne-enclave/discussions](https://github.com/Mindpool-Labs/ne-enclave/discussions)

We are looking for **design partners** — regulated enterprises (finance, healthcare, government) evaluating confidential agent execution. If your CISO has blocked an agent deployment on isolation or attestation grounds, we'd like to talk: `dev@mindpool.io`.

---

## License

Apache-2.0. The runtime, SDKs, guest agent, image builder, and deployment artifacts are all Apache-2.0, forever.

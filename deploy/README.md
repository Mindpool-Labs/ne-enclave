# NeuronEdge Enclave Self-Host Install Guide

Operator guide for running the NeuronEdge Enclave runtime on a single bare-metal or VM host.
The `standard` profile targets Ubuntu 24.04 / x86_64 with KVM. The
`confidential-azure` profile is Preview and targets an Azure confidential VM
with a vTPM.

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Ubuntu 24.04 (x86_64) |
| Release verification | Cosign 3 on `PATH`; the bootstrap installer fails before installation without it |
| Standard profile | `/dev/kvm` plus operator-installed upstream Firecracker + jailer at `/opt/ne-enclave/bin/{firecracker,jailer}` |
| Azure confidential profile (Preview) | `/dev/tpmrm0`, `tpm2-tools`, no `/dev/kvm`; the signed release supplies the pinned OpenShell binary and policies |
| Privileges | Root for install; the runtime itself drops to `nee` where possible |

The standard profile does not bundle Firecracker or jailer. Install them from the
[Firecracker releases page](https://github.com/firecracker-microvm/firecracker/releases)
and place both binaries at `/opt/ne-enclave/bin/` before running
`sudo /opt/ne-enclave/bin/nee install --execution-profile standard`.

---

## Security posture (read before installing)

> **API-key authentication and server TLS are implemented.** Production
> posture refuses to start without an API key and refuses a non-loopback bind
> without TLS. The default self-host configuration remains loopback-only
> (`127.0.0.1:50051` gRPC, `127.0.0.1:8080` REST). mTLS/client certificates and
> control-plane JWT are not implemented; client identity is API-key based.
> The supervisor IPC boundary independently enforces Unix-socket peer
> credentials.

---

## Hardening / resource limits

The supervisor exposes a handful of `NE_*` environment variables that bound
resource consumption per-guest and per-host. These are operational config
knobs — deploy-doc reference, not a security-capability claim — set them in
`/etc/ne-enclave/ne-enclave.env` if the defaults don't fit your host.

| Variable | Default | Purpose |
|---|---|---|
| `NE_MAX_GUEST_FRAME_BYTES` | `33554432` (32 MiB) | Host-side cap on a single guest vsock reply frame; the host does not trust the guest to honor its own matching cap (host-OOM DoS backstop). |
| `NE_MAX_EXEC_OUTPUT_BYTES` | `1048576` (1 MiB) | Cap on captured SSH exec output per stream on the confidential-tier OpenShell path. |
| `NE_MAX_EXEC_TIMEOUT_MS` | `3600000` (1 hour) | Ceiling a client-supplied exec `timeout_ms` is clamped to. `0` or an unparseable value falls back to this default (a `0` ceiling would otherwise mean "no bound"). |
| `NE_MAX_WORKSPACES` | `0` (auto, from host RAM) | Soft ceiling on concurrent workspaces; bounds live instances **plus** warm-pool members combined, not just running VMs. `0` derives a value from host RAM (~512 MiB nominal per VM, floored at 1, capped at 1024). |
| `NE_MAX_WORKSPACE_MEM_MIB` | `0` (auto, from host RAM) | Ceiling on `mem_size_mib` per workspace. `0` resolves to `min(host RAM MiB, 32768)`. |
| `NE_FC_API_TIMEOUT_MS` | `30000` (30s) | Deadline for a single Firecracker control-API call (machine-config, boot-source, drives, vsock, actions, pause/resume). `0` or an unparseable value falls back to this default. Snapshot create/load use a memory-scaled deadline instead (this value plus ~10ms per MiB of guest memory). |

---

## Quick install

```sh
# Install Cosign first:
# https://docs.sigstore.dev/cosign/system_config/installation/
curl -fsSL https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download/install.sh | sh
```

The thin `install.sh`:

1. Downloads the signed release manifest and `SHA256SUMS`, verifies both
   Sigstore bundles against the release workflow identity and GitHub OIDC
   issuer, then verifies the manifest checksum.
2. Downloads every component required by the selected profile, verifies its
   Sigstore bundle, `SHA256SUMS` entry, and resolved manifest digest.
3. Only after every check passes, drops `nee` to
   `/opt/ne-enclave/bin/nee` and execs
   `sudo /opt/ne-enclave/bin/nee install`.

To pin a specific release:

```sh
curl -fsSL \
  https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download/install.sh |
  NE_VERSION=v0.2.0 sh
```

The assignment is attached to `sh`, so the downloaded installer receives `NE_VERSION`.

---

## What `nee install` does

`nee install` is **idempotent** — safe to re-run on an already-provisioned
host (re-renders config; does not restart running services unless asked).

Steps in order:

1. **Preflight** — runs `/opt/ne-enclave/bin/nee doctor` (checks `/dev/kvm`, `firecracker`,
   `jailer` at expected paths, kernel module state).
2. **System user/group** — creates the `nee` system user + group if absent.
3. **Directory layout** — creates all directories listed in the
   [Filesystem layout](#filesystem-layout) section below.
4. **Guest image** — fetches and SHA-256-verifies the default guest image
   into the content-addressed store. Skip with `--no-image` for air-gapped
   installs (see [Air-gapped / custom images](#air-gapped--custom-images)).
5. **Config rendering** — writes `/etc/ne-enclave/ne-enclave.env` (EnvironmentFile
   sourced by both units) with paths resolved to the installed layout.
6. **systemd units** — renders `ne-supervisor.service` and
   `ne-api.service` into `/etc/systemd/system/` plus a tmpfiles entry
   into `/etc/tmpfiles.d/ne-enclave.conf`.
7. **Enable + start** — runs `systemctl daemon-reload &&
   systemctl enable --now ne-supervisor.service ne-api.service`
   (suppressed by `--no-start`).

### `nee install` flags

| Flag | Effect |
|---|---|
| `--execution-profile standard\|confidential-azure` | Render the explicit execution/attestation backend contract |
| `--no-start` | Render config + units but do not enable/start |
| `--no-image` | Skip guest image fetch (air-gapped; import manually) |
| `--prefix <dir>` | Install under `<dir>` instead of `/` (fakeroot / CI testing) |
| `--dry-run` | Print every action without executing |

---

## The single binary

One fused static binary at `/opt/ne-enclave/bin/nee`. Subcommands:

| Subcommand | Description |
|---|---|
| `serve-supervisor` | Privileged workspace lifecycle manager (spawns Firecracker via jailer) |
| `serve-api` | Unprivileged gRPC + REST API server |
| `dns-filter` | Per-workspace DNS filter (spawned by supervisor) |
| `privacy-router` | Per-workspace egress proxy (spawned by supervisor) |
| `install` | Host provisioner (described above) |
| `uninstall` | Remove units, config, user; optionally state |
| `doctor` | Profile-specific preflight checks |
| `image import` | Import a kernel + rootfs from local paths |
| `image pull` | Fetch a named image from the NeuronEdge Enclave image registry |
| `runtime capabilities` | Print the resolved public capability contract |
| `workspace attest` | Request summary or complete versioned evidence |
| `attestation verify` | Verify exported evidence against an explicit offline policy |
| `audit export` / `audit verify` | Export and independently verify the signed audit chain |

---

## Filesystem layout

```
/opt/ne-enclave/bin/nee                     # fused binary (this package)
/opt/ne-enclave/bin/firecracker              # operator-provided, standard only
/opt/ne-enclave/bin/jailer                    # operator-provided
/opt/ne-enclave/bin/openshell-sandbox         # signed release component, confidential-azure
/var/lib/ne-enclave/openshell/policy.rego
/var/lib/ne-enclave/openshell/policy.yaml
/etc/ne-enclave/ne-enclave.env                     # EnvironmentFile (both units)
/var/lib/ne-enclave/images/
    kernels/<sha256>/vmlinux               # content-addressed guest kernels
    rootfs/<sha256>/rootfs.img             # content-addressed guest rootfs
/var/lib/ne-enclave/workspaces/               # live workspace state  (ne:ne 0750)
/var/lib/ne-enclave/snapshots/                # snapshot state        (ne:ne 0750)
/run/ne-enclave/supervisor.sock               # IPC socket            (root:ne 0660)
/srv/jailer/                               # jailer chroot base
/etc/systemd/system/ne-supervisor.service
/etc/systemd/system/ne-api.service
/etc/tmpfiles.d/ne-enclave.conf
```

The supervisor's environment file sets the managed image root explicitly:

```sh
NE_IMAGE_STORE=/var/lib/ne-enclave/images
```

---

## The two systemd units

### `ne-supervisor.service`

Privileged service that owns the Firecracker jailer and workspace lifecycle.

- `User=root`, `Group=ne`, `Type=notify`
- IPC peer-credential auth: the supervisor verifies the connecting peer's UID
  via `SO_PEERCRED` (controlled by `NE_SUPERVISOR_PEER_UID` in the env
  file).
- Capability bounding set (the bounding set caps uid-0, so each required
  capability must be listed explicitly):

  ```
  CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_KILL, CAP_MKNOD,
  CAP_NET_ADMIN, CAP_SETGID, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_CHROOT
  ```

  - `CAP_KILL` — terminate the jailed Firecracker process (runs as a
    different uid inside the jailer chroot).
  - `CAP_MKNOD` + `CAP_SYS_CHROOT` — jailer chroot setup.
  - `CAP_NET_ADMIN` — TAP device creation for the workspace network
    namespace.

### `ne-api.service`

Unprivileged service that exposes the gRPC and REST API.

- `User=ne`, `Group=ne`
- Aggressively sandboxed: `NoNewPrivileges=true`,
  `CapabilityBoundingSet=` (empty), `MemoryDenyWriteExecute=true`,
  `ProtectSystem=strict`
- Binds `127.0.0.1:50051` (gRPC) and `127.0.0.1:8080` (REST).
- Communicates with the supervisor via the Unix socket
  `/run/ne-enclave/supervisor.sock` (group `ne`, mode `0660`).

---

## Execution profiles (`standard` + `confidential-azure`)

NeuronEdge Enclave exposes one API with discoverable profile capabilities.
`standard` is the supported default and uses upstream Firecracker. `confidential-azure`
is Preview and runs one OpenShell workspace directly inside an operator-provisioned
Azure SEV-SNP CVM. Inspect `GET /v1/runtime/capabilities`,
`GetRuntimeCapabilities`, or `nee runtime capabilities`; unsupported
operations fail explicitly.

### Activating `confidential-azure` (Preview)

On an Azure DCasv5 confidential VM with `tpm2-tools` and Cosign installed:

```sh
curl -fsSL \
  https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download/install.sh |
  NE_EXECUTION_PROFILE=confidential-azure sh
```

The installer verifies and provisions the pinned OpenShell binary and policies,
creates the sandbox service identity, and renders
`NE_EXECUTION_PROFILE=confidential-azure`. This product profile requires
`/dev/tpmrm0` and selects the Azure vTPM attestation provider explicitly; it
does not probe or fall back to `/dev/sev-guest`.

Confidential create carries only the workspace identity; image digests and VM
sizing fields are empty/zero. Use `create_confidential_workspace` in Python,
`createConfidentialWorkspace` in TypeScript, or the equivalent REST request.
The hard capacity is one workspace per CVM. Snapshot, restore, fork, warm pool,
pause/resume, ingress, and confidential snapshots are not implemented for this
profile.

The Azure evidence primitive has been verified on DCasv5, but the product lane
remains Preview until the exact signed v0.2.0 candidate passes the required
Azure release job. See [the capability ledger](../docs/CAPABILITIES.md).

---

## Air-gapped / custom images

```sh
# 1. Install without fetching the default image
sudo /opt/ne-enclave/bin/nee install --no-image

# 2. Import your own kernel + rootfs (SHA-256 values are verified on import)
KERNEL_SHA256=$(sha256sum /path/to/vmlinux | cut -d' ' -f1)
ROOTFS_SHA256=$(sha256sum /path/to/rootfs.img | cut -d' ' -f1)
sudo /opt/ne-enclave/bin/nee image import \
  --kernel /path/to/vmlinux --kernel-sha256 "$KERNEL_SHA256" \
  --rootfs /path/to/rootfs.img --rootfs-sha256 "$ROOTFS_SHA256"
```

Import runs with elevated privileges because it creates content-addressed directories in
the installed managed store, which is owned by `ne:ne` and mode `0750`.

When creating a cold Firecracker workspace, send the same verified values as
`kernel_sha256` and `rootfs_sha256`. The supervisor resolves only these fixed
managed-store locations and verifies their contents before allocating VM resources:

```text
$NE_IMAGE_STORE/kernels/<kernel_sha256>/vmlinux
$NE_IMAGE_STORE/rootfs/<rootfs_sha256>/rootfs.img
```

The source images are copied into each jailer chroot as independent files; writable
rootfs workspaces therefore cannot modify the managed source or another workspace's
copy. Image failures use stable codes: `INVALID_IMAGE_DIGEST`, `IMAGE_NOT_FOUND`,
`IMAGE_REJECTED`, `IMAGE_DIGEST_MISMATCH`, and `IMAGE_STAGE_FAILED`.

Snapshot manifests use schema version 5 and sign the kernel/rootfs digest pair.
Restore and fork re-resolve both digests from the managed store. Manifests older
than version 5 are rejected, and snapshotting a writable-rootfs workspace is not
supported; create snapshot sources with `rootfs_read_only=true`.

---

## Verifying the install

`deploy/smoke-install.sh` consumes a directory containing the exact signed
candidate bundle and drives a full standard-profile round trip:

```sh
sudo deploy/smoke-install.sh \
  /path/to/signed/staging \
  /path/to/vmlinux \
  /path/to/rootfs.img
```

The script runs the bootstrap installer against `file://` release assets, so
signature, checksum, and resolved-manifest verification happen before install.
It imports the image, asserts the `standard` capability contract, starts the
units, then runs **create → exec → write → read → destroy** against the REST
API. It exits `0` and prints `SMOKE OK` on success.

The script stages Firecracker + jailer into `/opt/ne-enclave/bin/` (where the
installed runtime expects them) from `NE_E2E_FIRECRACKER`/`NE_E2E_JAILER`, then
`/usr/local/bin`, then `PATH`, and errors with guidance if neither is found. An
operator-provided binary already under `/opt/ne-enclave/bin/` is left as-is.

> **Note:** File paths in `WriteFile` / `ReadFile` requests are **relative**
> to the `/workspace` jail root (e.g., `"path": "proof.txt"` lands at
> `/workspace/proof.txt`). The guest agent rejects absolute paths.

---

## Checking service status

```sh
systemctl --no-pager status ne-supervisor.service ne-api.service
journalctl -u ne-supervisor.service -u ne-api.service -f
/opt/ne-enclave/bin/nee doctor
```

---

## Uninstall

```sh
# Remove units + config + ne user; preserve /var/lib/ne-enclave state
sudo /opt/ne-enclave/bin/nee uninstall

# Full removal including workspace + image state
sudo /opt/ne-enclave/bin/nee uninstall --purge
```

---

## KVM dev host

Firecracker needs `/dev/kvm`, which macOS and most non-nested virtualization
guests cannot provide. Provision any KVM-capable Ubuntu 24.04 / x86_64 host
(bare metal, a VM with nested virtualization, or a cloud VM such as Azure
Dv4+/Ev4+). Install Firecracker v1.16.0 + jailer to `/opt/ne-enclave/bin/`
(see the Requirements section above), then run the same `install.sh` / `nee`
flow.

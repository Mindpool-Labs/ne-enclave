# ne-enclave

**NeuronEdge Enclave** — the single fused runtime binary (`nee`) for Confidential Agent
Execution Infrastructure: a hardware-attested execution boundary for autonomous-agent work on
Linux + KVM + Firecracker. The runtime is Apache-2.0. Optional external integrations use
`ne-protocol` compatibility types.

`nee` is one static musl binary that carries every runtime subcommand:

- `nee serve-supervisor` / `nee serve-api` — the privileged supervisor and unprivileged API daemon (systemd units).
- `nee install` / `nee uninstall` / `nee doctor` — idempotent host provisioning + preflight checks.
- `nee image import` / `nee image pull` — content-addressed, signed guest image management.
- `nee api-key generate` / `nee tls generate` / `nee snapshot ...` / `nee audit ...` — operational tooling.

## Install

Self-host operators install from a signed GitHub release artifact (a single static binary — no
build toolchain required). See [`deploy/README.md`](../../deploy/README.md) for the bootstrap
script and full operator guide.

## Documentation

- [Self-host install guide](../../deploy/README.md) — bootstrap script, layout, networking, the confidential tier.
- [Project README](../../README.md) — overview, quickstart, the two-tier model.

## License

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`).

# ne-bench — Reproduction Instructions

This README gives the exact steps to reproduce every benchmark from a fresh KVM Linux
host. The benchmark methodology — endpoint definitions, honesty rules, percentile
method — is described inline below.

---

## Prerequisites

1. **Linux with KVM.** `/dev/kvm` must be present and accessible. Nested KVM works but
   adds overhead (see the honesty note below).

2. **NeuronEdge Enclave installed and both systemd units running.** Follow
   [`../deploy/README.md`](../deploy/README.md) to install the `nee` binary, run
   `sudo /opt/ne-enclave/bin/nee install`, import a guest image, and verify the two units
   are active:

   ```bash
   systemctl --no-pager status ne-supervisor.service ne-api.service
   ```

   The installed `ne-api` unit binds `127.0.0.1:50051` (gRPC) and `127.0.0.1:8080`
   (REST). The bench drives the **gRPC** endpoint.

3. **Rust toolchain.** The harness is a standard Cargo crate. From the repo root:

   ```bash
   cargo build --release -p ne-bench
   ```

   The binary lands at `target/release/ne-bench`.

4. **Guest image digests.** Compute and retain the digests before importing into the
   privileged managed store:

   ```bash
   KERNEL=/path/to/vmlinux
   ROOTFS=/path/to/rootfs.img
   KERNEL_SHA256=$(sha256sum "$KERNEL" | cut -d' ' -f1)
   ROOTFS_SHA256=$(sha256sum "$ROOTFS" | cut -d' ' -f1)
   sudo /opt/ne-enclave/bin/nee image import \
     --kernel "$KERNEL" --kernel-sha256 "$KERNEL_SHA256" \
     --rootfs "$ROOTFS" --rootfs-sha256 "$ROOTFS_SHA256"
   ```

   Keep `KERNEL_SHA256` and `ROOTFS_SHA256` set in the shell used for the benchmark
   commands below. Image import verifies the supplied values but does not print them.

---

## Running the benchmarks

Set the shared flags once, then invoke each subcommand. Replace the representative Azure
SKU, storage backend, and environment notes with accurate values for your host.

```bash
BIN=target/release/ne-bench
: "${KERNEL_SHA256:?run the image-import step above in this shell}"
: "${ROOTFS_SHA256:?run the image-import step above in this shell}"

COMMON=(
  --endpoint "http://127.0.0.1:50051"
  --output-dir "results/$(date -u +%Y-%m-%d)"
  --run-timestamp "$(date -u +%FT%TZ)"
  --kernel-sha256 "$KERNEL_SHA256"
  --rootfs-sha256 "$ROOTFS_SHA256"
  --instance-sku "Azure Standard_D8s_v5"
  --storage-backend "ext4 on NVMe"
  --environment-notes "cloud VM, nested KVM; floor not ceiling"
  --vcpu-count 1
  --mem-size-mib 256
)

"$BIN" "${COMMON[@]}" cold-start --iterations 1000
"$BIN" "${COMMON[@]}" exec --iterations 10000
"$BIN" "${COMMON[@]}" teardown --iterations 1000
"$BIN" "${COMMON[@]}" boot-storm --concurrency 50
"$BIN" "${COMMON[@]}" density --ram-stop-percent 85 --max-consecutive-failures 3
```

Run each command to completion before starting the next. The runs are sequential by
design: concurrent benchmark invocations against the same daemon would contaminate
latency measurements.

---

## Where outputs land

Each invocation writes into `--output-dir` (default `results/<date>`):

```
results/<date>/
  raw/
    cold_start.csv       # one row per trial
    exec.csv
    teardown.csv
    boot_storm.csv
    density.csv
  summary/
    cold_start.csv       # P50/P90/P95/P99/min/max/mean/stddev/N
    exec.csv
    teardown.csv
    boot_storm.csv
    density.csv
  manifest.json          # required reporting block (see note below)
```

### manifest.json note

Each benchmark invocation **overwrites** `manifest.json` with the metadata for that
run. After running all five subcommands, `manifest.json` reflects the last benchmark
executed (density, in the order above). The per-benchmark distribution data is fully
preserved in the `summary/*.csv` and `raw/*.csv` files, which are never overwritten.

To assemble a single manifest covering all five runs, merge the `benchmarks` arrays
from each invocation's manifest by hand, or rely on the per-benchmark summary CSVs
for all quantitative analysis. This is a known limitation of the current release.

---

## Optional: generate plots

The `scripts/plot.py` script reads the CSVs and renders percentile-bar and
latency-distribution PNGs. It is a **reproduction tool only** — it is not part of the
build, not part of CI, and not a runtime dependency.

```bash
python3 -m pip install --user matplotlib
python3 scripts/plot.py results/<date>
```

Plots are written to `results/<date>/plots/`.

---

## Safety note for the density benchmark

The density run boots workspaces concurrently until the safety stop-rule triggers
(host committed RAM ≥ 85 % or 3 consecutive create failures). It never deliberately
OOMs the host, but on a shared host the RAM headroom shrinks steadily during the run.
**Run density during a maintenance window** on any host where other workloads are
present, or where an unplanned OOM would disrupt operations.

---

## Honesty note on cloud / nested-KVM results

If reproducing on a cloud VM (Azure, AWS, GCP) with nested KVM, the numbers you
measure are a **floor**, not a bare-metal ceiling. Nested virtualization adds VMM
overhead that disappears on a bare-metal KVM host. Record your host SKU and the
nested-virtualization caveat in `--environment-notes` and `--instance-sku` so the
manifest is accurate. Nightly bare-metal benchmark numbers require a future validation deliverable.

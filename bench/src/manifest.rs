// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Run manifest: the required-reporting block captured at run
//! start and committed alongside results so any reviewer sees the exact
//! measurement environment.

use serde::{Deserialize, Serialize};

/// The full benchmark run manifest (serialized to `manifest.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// ISO-8601 UTC timestamp, supplied by the caller (no clock in lib).
    pub run_timestamp: String,
    /// ne-bench crate version.
    pub bench_version: String,
    /// Host hardware facts.
    pub host: Host,
    /// Component versions.
    pub versions: Versions,
    /// Workspace resource tier under test.
    pub workspace_tier: WorkspaceTier,
    /// Storage backend description (e.g. "ext4 on `NVMe`", operator-supplied).
    pub storage_backend: String,
    /// Snapshot restore strategy; `"n/a"` when no snapshots are exercised.
    pub snapshot_restore_strategy: String,
    /// Confidential mode flag; false in this benchmark format.
    pub confidential_mode: bool,
    /// CC platform; `"none"` in this benchmark format.
    pub cc_platform: String,
    /// The honesty caveat block (SKU + nested-virt floor framing).
    pub environment_notes: String,
    /// Per-benchmark records (filled as benchmarks run).
    pub benchmarks: Vec<BenchmarkRecord>,
}

/// Host hardware facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Host {
    /// CPU model string from `/proc/cpuinfo`.
    pub cpu_model: String,
    /// Distinct physical cores.
    pub physical_cores: u32,
    /// Logical threads (hyperthreads).
    pub logical_threads: u32,
    /// Total RAM in KiB from `/proc/meminfo`.
    pub ram_total_kib: u64,
    /// Host kernel version (`uname -r`).
    pub kernel_version: String,
    /// Cloud SKU / instance type, operator-supplied (e.g. Azure VM size).
    pub instance_sku: String,
}

/// Component versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Versions {
    /// Upstream Firecracker version with source revision and build-hash provenance.
    pub firecracker: String,
    /// Jailer version.
    pub jailer: String,
    /// Guest kernel image digest (content-addressed store digest).
    pub guest_kernel_digest: String,
    /// Guest rootfs image digest.
    pub guest_rootfs_digest: String,
}

/// Workspace resource tier the benchmarks booted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceTier {
    /// Guest vCPU count.
    pub vcpu_count: u32,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
}

/// One benchmark's run metadata + summary, recorded into the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkRecord {
    /// Benchmark name (e.g. "`cold_start`").
    pub name: String,
    /// Human-readable workload description.
    pub workload: String,
    /// Iterations requested via CLI.
    pub iterations_requested: usize,
    /// Iterations actually completed.
    pub iterations_completed: usize,
    /// True if the run terminated early (autoshutdown, stop-rule, failure).
    pub terminated_early: bool,
    /// Free-form notes (e.g. density stop-rule that fired).
    pub notes: String,
}

/// Parse the first CPU model name from `/proc/cpuinfo` contents.
/// Parses the x86 `model name` field; returns `None` on architectures
/// (e.g. aarch64) that don't expose it.
#[must_use]
pub fn parse_cpu_model(cpuinfo: &str) -> Option<String> {
    cpuinfo
        .lines()
        .find_map(|l| l.strip_prefix("model name").map(str::trim))
        .and_then(|rest| rest.strip_prefix(':').map(str::trim))
        .map(str::to_string)
}

/// Count logical threads (`processor` lines) in `/proc/cpuinfo`.
#[must_use]
pub fn parse_logical_threads(cpuinfo: &str) -> u32 {
    u32::try_from(
        cpuinfo
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count(),
    )
    .unwrap_or(0)
}

/// Count distinct physical cores via `core id` per `physical id`.
/// Falls back to logical thread count when topology lines are absent.
#[must_use]
pub fn parse_physical_cores(cpuinfo: &str) -> u32 {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut cur_phys: Option<String> = None;
    for line in cpuinfo.lines() {
        if let Some(v) = line
            .strip_prefix("physical id")
            .and_then(|r| r.split(':').nth(1))
        {
            cur_phys = Some(v.trim().to_string());
        } else if let Some(v) = line
            .strip_prefix("core id")
            .and_then(|r| r.split(':').nth(1))
        {
            let phys = cur_phys.clone().unwrap_or_default();
            seen.insert((phys, v.trim().to_string()));
        }
    }
    if seen.is_empty() {
        parse_logical_threads(cpuinfo)
    } else {
        u32::try_from(seen.len()).unwrap_or(0)
    }
}

/// Parse `MemTotal:` (KiB) from `/proc/meminfo` contents.
#[must_use]
pub fn parse_mem_total_kib(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Inputs the operator supplies that aren't auto-discoverable.
#[derive(Debug, Clone)]
pub struct OperatorInputs {
    /// ISO-8601 UTC run timestamp.
    pub run_timestamp: String,
    /// Cloud SKU / instance type.
    pub instance_sku: String,
    /// Storage backend description.
    pub storage_backend: String,
    /// Guest kernel image digest.
    pub guest_kernel_digest: String,
    /// Guest rootfs image digest.
    pub guest_rootfs_digest: String,
    /// Environment honesty notes.
    pub environment_notes: String,
    /// Guest vCPU count.
    pub vcpu_count: u32,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
}

/// Collect the host/version block from the live environment, combining
/// auto-discovered facts with operator-supplied inputs.
pub fn collect(inputs: &OperatorInputs) -> anyhow::Result<Manifest> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();

    let cpu_model = parse_cpu_model(&cpuinfo).unwrap_or_else(|| {
        tracing::warn!(
            "could not auto-discover CPU model from /proc/cpuinfo; recording \"unknown\""
        );
        "unknown".to_string()
    });
    let ram_total_kib = parse_mem_total_kib(&meminfo).unwrap_or_else(|| {
        tracing::warn!("could not auto-discover MemTotal from /proc/meminfo; recording 0");
        0
    });
    let kernel = read_first_line_cmd("uname", &["-r"]).unwrap_or_else(|| {
        tracing::warn!("could not run `uname -r`; recording kernel version \"unknown\"");
        "unknown".to_string()
    });
    let firecracker = tool_version("firecracker");
    let jailer = tool_version("jailer");

    let logical_threads = parse_logical_threads(&cpuinfo);
    let physical_cores = parse_physical_cores(&cpuinfo);
    if logical_threads == 0 {
        tracing::warn!(
            "could not auto-discover logical thread count from /proc/cpuinfo; recording 0"
        );
    }
    if physical_cores == 0 {
        tracing::warn!(
            "could not auto-discover physical core count from /proc/cpuinfo; recording 0"
        );
    }

    Ok(Manifest {
        run_timestamp: inputs.run_timestamp.clone(),
        bench_version: env!("CARGO_PKG_VERSION").to_string(),
        host: Host {
            cpu_model,
            physical_cores,
            logical_threads,
            ram_total_kib,
            kernel_version: kernel,
            instance_sku: inputs.instance_sku.clone(),
        },
        versions: Versions {
            firecracker,
            jailer,
            guest_kernel_digest: inputs.guest_kernel_digest.clone(),
            guest_rootfs_digest: inputs.guest_rootfs_digest.clone(),
        },
        workspace_tier: WorkspaceTier {
            vcpu_count: inputs.vcpu_count,
            mem_size_mib: inputs.mem_size_mib,
        },
        storage_backend: inputs.storage_backend.clone(),
        snapshot_restore_strategy: "n/a".to_string(),
        confidential_mode: false,
        cc_platform: "none".to_string(),
        environment_notes: inputs.environment_notes.clone(),
        benchmarks: Vec::new(),
    })
}

fn read_first_line_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines().next().map(str::trim).map(str::to_string)
}

/// Best-effort `<tool> --version` first line; `"unknown"` if unavailable.
fn tool_version(tool: &str) -> String {
    read_first_line_cmd(tool, &["--version"]).unwrap_or_else(|| {
        tracing::warn!(
            tool,
            "could not auto-discover version via `--version`; recording \"unknown\""
        );
        "unknown".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPUINFO: &str = "\
processor\t: 0
model name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
physical id\t: 0
core id\t: 0
processor\t: 1
model name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
physical id\t: 0
core id\t: 1
processor\t: 2
model name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
physical id\t: 0
core id\t: 0
processor\t: 3
model name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
physical id\t: 0
core id\t: 1
";

    #[test]
    fn parses_cpu_model() {
        assert_eq!(
            parse_cpu_model(CPUINFO).as_deref(),
            Some("Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz")
        );
    }

    #[test]
    fn parses_logical_threads() {
        assert_eq!(parse_logical_threads(CPUINFO), 4);
    }

    #[test]
    fn parses_physical_cores_via_topology() {
        // 2 distinct (physical id, core id) pairs -> 2 cores, 4 threads.
        assert_eq!(parse_physical_cores(CPUINFO), 2);
    }

    #[test]
    fn physical_cores_falls_back_to_threads_without_topology() {
        let minimal = "processor\t: 0\nprocessor\t: 1\n";
        assert_eq!(parse_physical_cores(minimal), 2);
    }

    #[test]
    fn parses_mem_total() {
        let meminfo = "MemTotal:       32827145 kB\nMemFree:  100 kB\n";
        assert_eq!(parse_mem_total_kib(meminfo), Some(32_827_145));
    }

    #[test]
    fn manifest_json_round_trips() {
        let m = Manifest {
            run_timestamp: "2026-05-31T12:00:00Z".to_string(),
            bench_version: "0.0.0".to_string(),
            host: Host {
                cpu_model: "x".to_string(),
                physical_cores: 2,
                logical_threads: 4,
                ram_total_kib: 1000,
                kernel_version: "6.17".to_string(),
                instance_sku: "Standard_D4s_v5".to_string(),
            },
            versions: Versions {
                firecracker: "1.x".to_string(),
                jailer: "1.x".to_string(),
                guest_kernel_digest: "sha256:aa".to_string(),
                guest_rootfs_digest: "sha256:bb".to_string(),
            },
            workspace_tier: WorkspaceTier {
                vcpu_count: 1,
                mem_size_mib: 256,
            },
            storage_backend: "ext4 on NVMe".to_string(),
            snapshot_restore_strategy: "n/a".to_string(),
            confidential_mode: false,
            cc_platform: "none".to_string(),
            environment_notes: "floor not ceiling".to_string(),
            benchmarks: vec![],
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

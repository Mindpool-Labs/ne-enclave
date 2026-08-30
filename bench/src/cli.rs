// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Command-line surface for `ne-bench`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// NeuronEdge Enclave public benchmark harness.
#[derive(Debug, Parser)]
#[command(
    name = "ne-bench",
    version,
    about = "NeuronEdge Enclave runtime benchmarks"
)]
pub struct Args {
    /// Runtime gRPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    pub endpoint: String,

    /// Directory to write raw/, summary/, and manifest.json into.
    #[arg(long, default_value = "results")]
    pub output_dir: PathBuf,

    /// ISO-8601 UTC run timestamp (the harness has no wall clock of its
    /// own by policy; the operator supplies it, e.g. `date -u +%FT%TZ`).
    #[arg(long)]
    pub run_timestamp: String,

    /// Canonical lowercase SHA-256 digest of the managed guest kernel image.
    #[arg(long, value_parser = parse_sha256)]
    pub kernel_sha256: String,

    /// Canonical lowercase SHA-256 digest of the managed guest rootfs image.
    #[arg(long, value_parser = parse_sha256)]
    pub rootfs_sha256: String,

    /// Cloud SKU / instance type, recorded in the manifest.
    #[arg(long, default_value = "unknown")]
    pub instance_sku: String,

    /// Storage backend description, recorded in the manifest.
    #[arg(long, default_value = "unknown")]
    pub storage_backend: String,

    /// Environment honesty notes (floor-not-ceiling, nested-virt caveat).
    #[arg(long, default_value = "")]
    pub environment_notes: String,

    /// Workspace vCPU count for the tier under test.
    #[arg(long, default_value_t = 1)]
    pub vcpu_count: u32,

    /// Workspace memory (MiB) for the tier under test.
    #[arg(long, default_value_t = 256)]
    pub mem_size_mib: u32,

    /// Base guest vsock CID (incremented per concurrent workspace).
    #[arg(long, default_value_t = 3)]
    pub base_vsock_cid: u32,

    /// The benchmark to run.
    #[command(subcommand)]
    pub command: Command,
}

/// One subcommand per benchmark.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Cold start: report both launch and ready boundaries.
    ColdStart {
        /// Number of trials.
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
    /// Warm exec roundtrip of `/bin/true`.
    Exec {
        /// Number of execs in one long-lived workspace.
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
    },
    /// Density: boot concurrently to the safety stop-rule.
    Density {
        /// Stop when committed RAM reaches this percent of total.
        #[arg(long, default_value_t = 85)]
        ram_stop_percent: u32,
        /// Stop after this many consecutive create failures.
        #[arg(long, default_value_t = 3)]
        max_consecutive_failures: u32,
        /// Hard ceiling on workspaces to attempt (safety backstop).
        #[arg(long, default_value_t = 1000)]
        max_workspaces: usize,
    },
    /// Boot storm: N concurrent creates, measure time-to-all-ready.
    BootStorm {
        /// Concurrency.
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
    },
    /// Teardown: destroy latency.
    Teardown {
        /// Number of create->ready->destroy cycles (destroy is measured).
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
}

fn parse_sha256(raw: &str) -> Result<String, String> {
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(raw.to_owned())
    } else {
        Err("expected exactly 64 lowercase hexadecimal characters".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }

    #[test]
    fn parses_cold_start_with_defaults() {
        let a = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "2026-05-31T12:00:00Z",
            "--kernel-sha256",
            &"11".repeat(32),
            "--rootfs-sha256",
            &"22".repeat(32),
            "cold-start",
        ])
        .unwrap();
        assert_eq!(a.endpoint, "http://127.0.0.1:50051");
        assert_eq!(a.vcpu_count, 1);
        assert_eq!(a.mem_size_mib, 256);
        assert_eq!(a.kernel_sha256, "11".repeat(32));
        assert_eq!(a.rootfs_sha256, "22".repeat(32));
        assert!(matches!(a.command, Command::ColdStart { iterations: 1000 }));
    }

    #[test]
    fn parses_density_subcommand_flags() {
        let a = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "t",
            "--kernel-sha256",
            &"11".repeat(32),
            "--rootfs-sha256",
            &"22".repeat(32),
            "density",
            "--ram-stop-percent",
            "90",
            "--max-consecutive-failures",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            a.command,
            Command::Density {
                ram_stop_percent: 90,
                max_consecutive_failures: 5,
                max_workspaces: 1000
            }
        ));
    }

    #[test]
    fn missing_required_flags_errors() {
        // run-timestamp / kernel-sha256 / rootfs-sha256 are required.
        let r = Args::try_parse_from(["ne-bench", "cold-start"]);
        assert!(r.is_err());
    }

    #[test]
    fn obsolete_image_path_flags_are_rejected() {
        let result = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "t",
            "--kernel-path",
            "/k",
            "--rootfs-path",
            "/r",
            "cold-start",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn noncanonical_sha256_is_rejected() {
        let result = Args::try_parse_from([
            "ne-bench",
            "--run-timestamp",
            "t",
            "--kernel-sha256",
            &"AA".repeat(32),
            "--rootfs-sha256",
            &"22".repeat(32),
            "cold-start",
        ]);
        assert!(result.is_err());
    }
}

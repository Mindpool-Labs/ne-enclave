// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! `ne-image` — builds NeuronEdge Enclave guest kernel + rootfs images
//! via Buildroot.
//!
//! Current scope:
//!   - One subcommand: `build --template standard`.
//!   - Invokes Buildroot with our `BR2_EXTERNAL` tree under
//!     `images/buildroot/external/` and the `ne_standard_defconfig`.
//!   - Produces `vmlinux` + an ext4 rootfs in the configured output
//!     directory.
//!
//! Not yet here:
//!   - Signing (cosign) and SBOM (SPDX) generation.
//!   - arm64 cross-compile.
//!   - Baking `ne-guest-agent` into the rootfs (the `BR2_EXTERNAL`
//!     package recipe lands once the basic pipeline is proven).
//!   - Multiple templates (`python-node`, `browser-capable`).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Builds NeuronEdge Enclave guest images.
#[derive(Debug, Parser)]
#[command(name = "ne-image", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Path to a Buildroot checkout. Defaults to `$HOME/buildroot`.
    #[arg(long, env = "NE_BUILDROOT", global = true)]
    buildroot: Option<PathBuf>,

    /// Path to our `BR2_EXTERNAL` tree. Defaults to
    /// `<repo>/images/buildroot/external/`.
    #[arg(long, env = "NE_BR2_EXTERNAL", global = true)]
    br2_external: Option<PathBuf>,

    /// Output directory. Defaults to `<repo>/target/images/<template>/`.
    /// All Buildroot artifacts (kernel, rootfs, host toolchain) live
    /// inside this dir.
    #[arg(long, env = "NE_IMAGE_OUTPUT", global = true)]
    output: Option<PathBuf>,

    /// Path to the cross-compiled `ne-guest-agent` binary that the
    /// Buildroot post-build script bakes into `/usr/local/bin/` inside
    /// the rootfs. Defaults to
    /// `<repo>/target/x86_64-unknown-linux-musl/release/ne-guest-agent`.
    /// If the path is missing the build still runs but the rootfs
    /// ships without the agent (useful for early pipeline validation).
    #[arg(long, env = "NE_GUEST_AGENT_BIN", global = true)]
    agent_bin: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Build a guest image from a named template.
    Build {
        /// Template name. Currently only `standard` is shipped;
        /// it maps to `configs/ne_standard_defconfig` in our
        /// `BR2_EXTERNAL` tree.
        #[arg(long, default_value = "standard")]
        template: String,

        /// Number of parallel `make` jobs (`-jN`). Defaults to the
        /// host's CPU count; pass `1` to serialize for debugging.
        #[arg(short, long)]
        jobs: Option<u32>,
    },
    /// Print the resolved configuration without doing anything.
    Info,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let cli = Cli::parse();
    let cfg = resolve_config(&cli)?;
    info!(?cfg, "ne-image starting");

    match &cli.cmd {
        Cmd::Build { template, jobs } => build(&cfg, template, *jobs),
        Cmd::Info => {
            // `println!` is intentional here — `info` is the
            // operator-facing config dump. tracing's structured logs
            // would be wrong shape.
            #[allow(clippy::print_stdout)]
            {
                println!("{}", serde_json::to_string_pretty(&cfg)?);
            }
            Ok(())
        }
    }
}

/// Resolved configuration after merging CLI flags, env vars, and
/// repo-root defaults.
#[derive(Debug, serde::Serialize)]
struct ResolvedConfig {
    buildroot: PathBuf,
    br2_external: PathBuf,
    output: PathBuf,
    repo_root: PathBuf,
    /// Resolved path to the agent binary. `None` if neither the flag
    /// nor the default location yielded a file on disk.
    agent_bin: Option<PathBuf>,
}

fn resolve_config(cli: &Cli) -> Result<ResolvedConfig> {
    let repo_root = find_repo_root().context("locating repo root (walk up from CWD)")?;

    let buildroot = cli
        .buildroot
        .clone()
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join("buildroot")))
        .context("--buildroot not set and $HOME is unavailable")?;
    if !buildroot.join("Makefile").is_file() {
        bail!(
            "Buildroot Makefile not found under {}; clone Buildroot first \
             (see images/buildroot/README or pass --buildroot)",
            buildroot.display()
        );
    }

    let br2_external = cli
        .br2_external
        .clone()
        .unwrap_or_else(|| repo_root.join("images/buildroot/external"));
    if !br2_external.join("external.desc").is_file() {
        bail!(
            "BR2_EXTERNAL tree at {} is missing external.desc",
            br2_external.display()
        );
    }

    let output = cli
        .output
        .clone()
        .unwrap_or_else(|| repo_root.join("target/images"));

    let agent_bin_default =
        repo_root.join("target/x86_64-unknown-linux-musl/release/ne-guest-agent");
    let agent_bin = match cli.agent_bin.clone() {
        Some(p) if p.is_file() => Some(p),
        Some(p) => bail!("--agent-bin {} does not exist", p.display()),
        None if agent_bin_default.is_file() => Some(agent_bin_default),
        None => None,
    };

    Ok(ResolvedConfig {
        buildroot,
        br2_external,
        output,
        repo_root,
        agent_bin,
    })
}

/// Walk up from CWD until we find the workspace `Cargo.toml`.
fn find_repo_root() -> Result<PathBuf> {
    let mut cur = std::env::current_dir()?;
    loop {
        if cur.join("Cargo.toml").is_file() && cur.join("crates").is_dir() {
            return Ok(cur);
        }
        if !cur.pop() {
            bail!("could not locate workspace Cargo.toml walking up from CWD");
        }
    }
}

fn build(cfg: &ResolvedConfig, template: &str, jobs: Option<u32>) -> Result<()> {
    let defconfig = format!("ne_{}_defconfig", template.replace('-', "_"));
    let defconfig_path = cfg.br2_external.join("configs").join(&defconfig);
    if !defconfig_path.is_file() {
        bail!(
            "defconfig {} not found at {}",
            defconfig,
            defconfig_path.display()
        );
    }

    let template_out = cfg.output.join(template);
    std::fs::create_dir_all(&template_out)
        .with_context(|| format!("create output dir {}", template_out.display()))?;

    info!(
        defconfig = %defconfig,
        out = %template_out.display(),
        "running buildroot defconfig step"
    );
    run_make(cfg, &template_out, &[defconfig.as_str()], jobs)
        .with_context(|| format!("buildroot defconfig step for template {template}"))?;

    info!(out = %template_out.display(), "running buildroot build step");
    run_make(cfg, &template_out, &[], jobs)
        .with_context(|| format!("buildroot build step for template {template}"))?;

    let images_dir = template_out.join("images");
    if images_dir.is_dir() {
        info!(images = %images_dir.display(), "build complete; artifacts in images/");
        list_artifacts(&images_dir);
    } else {
        warn!(images = %images_dir.display(), "expected images/ subdirectory not present");
    }
    Ok(())
}

/// Run `make BR2_EXTERNAL=... O=... [args...]` from the Buildroot
/// source root, inheriting stdout / stderr so the operator sees
/// progress live.
fn run_make(
    cfg: &ResolvedConfig,
    output: &std::path::Path,
    args: &[&str],
    jobs: Option<u32>,
) -> Result<()> {
    let mut cmd = Command::new("make");
    cmd.current_dir(&cfg.buildroot);
    cmd.env("BR2_EXTERNAL", &cfg.br2_external);
    if let Some(agent) = &cfg.agent_bin {
        cmd.env("NE_GUEST_AGENT_BIN", agent);
    }
    cmd.arg(format!("O={}", output.display()));
    if let Some(j) = jobs {
        cmd.arg(format!("-j{j}"));
    } else {
        cmd.arg(format!("-j{}", num_cpus()));
    }
    cmd.args(args);
    let status = cmd
        .status()
        .with_context(|| format!("spawn `make` in {}", cfg.buildroot.display()))?;
    if !status.success() {
        bail!("`make {}` exited with {}", args.join(" "), status);
    }
    Ok(())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

fn list_artifacts(images_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(images_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
        {
            info!(
                artifact = %entry.path().display(),
                size_bytes = meta.len(),
                "build artifact"
            );
        }
    }
}

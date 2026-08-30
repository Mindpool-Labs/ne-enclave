// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Idempotent host provisioning.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ne_protocol::profile::ExecutionProfile;

use crate::install::image;
use crate::install::layout::Layout;
use crate::install::preflight;
use crate::install::render::{self, RenderVars};

/// Options resolved by the CLI before running an install.
// Four bools is the natural shape here; a state-machine refactor would add
// more complexity than clarity for a configuration struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Execution profile being provisioned.
    pub execution_profile: ExecutionProfile,
    /// Resolved filesystem layout (carries the `--prefix` root).
    pub layout: Layout,
    /// True when `--prefix` is set: skip user/group + systemctl.
    pub fakeroot: bool,
    /// Do not `systemctl enable --now` the units after rendering them.
    pub no_start: bool,
    /// Do not fetch the default guest image.
    pub no_image: bool,
    /// Print actions without mutating the filesystem.
    pub dry_run: bool,
    /// UID for the `ne` service account used in the env file.
    /// Callers should set this to a deterministic value (e.g. 991) for
    /// fakeroot tests. On real installs `install()` re-resolves the uid
    /// after `ensure_service_user` so any value passed here is overridden.
    pub ne_uid: u32,
    /// Source OpenShell sandbox executable for confidential installs.
    pub openshell_sandbox_source: Option<PathBuf>,
    /// Optional source Rego policy. Uses the embedded release policy when absent.
    pub openshell_policy_rules_source: Option<PathBuf>,
    /// Optional source YAML policy data. Uses the embedded release data when absent.
    pub openshell_policy_data_source: Option<PathBuf>,
}

/// Provision the host. Idempotent: re-running is a no-op where state exists.
pub fn install(opts: InstallOptions) -> Result<()> {
    if matches!(opts.execution_profile, ExecutionProfile::ConfidentialAzure) {
        validate_confidential_inputs(&opts)?;
    }
    let l = &opts.layout;

    let mut managed_dirs = vec![
        l.bin_dir(),
        l.etc_dir(),
        l.state_dir(),
        l.workspaces_dir(),
        l.snapshots_dir(),
        l.systemd_dir(),
        l.run_dir(),
    ];
    match opts.execution_profile {
        ExecutionProfile::Standard => {
            managed_dirs.push(l.images_dir());
            managed_dirs.push(l.jailer_base());
        }
        ExecutionProfile::ConfidentialAzure => managed_dirs.push(l.openshell_dir()),
    }

    // Inspect the complete legacy layout before any path-following filesystem
    // mutation. A service-owned state directory from an older install may
    // contain attacker-created symlinks.
    if !opts.dry_run {
        validate_existing_directory_chains(l.root(), &managed_dirs)?;
    }

    // 1. Service user/group (real installs only); resolve uid after creation.
    let ne_uid = if opts.fakeroot || opts.dry_run {
        opts.ne_uid
    } else {
        ensure_service_user("ne")?;
        if matches!(opts.execution_profile, ExecutionProfile::ConfidentialAzure) {
            ensure_sandbox_user()?;
        }
        resolve_uid_after_creation("ne")
    };

    // 2. Lock down the legacy state parent before creating or changing any
    // child beneath it. Once root:ne 0750, the API identity cannot swap the
    // preflighted children during the rest of the upgrade.
    if !opts.dry_run {
        ensure_directory_chain(l.root(), &l.state_dir())?;
        apply_directory_policy(&l.state_dir(), "root", "ne", 0o750, opts.fakeroot)?;
    }

    // 3. Create each remaining component one directory at a time, validating
    // existing entries with symlink_metadata instead of following them.
    for d in managed_dirs {
        if opts.dry_run {
            tracing::info!("[dry-run] mkdir -p {}", d.display());
        } else {
            ensure_directory_chain(l.root(), &d)?;
        }
    }

    // 3b. Apply exact directory policies through no-follow handles on Linux.
    if !opts.dry_run {
        apply_ownership(l, opts.fakeroot)?;
    }
    if !opts.dry_run && matches!(opts.execution_profile, ExecutionProfile::Standard) {
        image::harden_store(&l.images_dir(), opts.fakeroot)?;
    }

    // 3. Guest image (default pin), unless --no-image. Custom/air-gap
    //    images are provisioned separately via `nee image import`/`pull`.
    if matches!(opts.execution_profile, ExecutionProfile::Standard) && !opts.no_image {
        if opts.dry_run {
            tracing::info!("[dry-run] fetch default guest image");
        } else {
            fetch_default_image(l)?;
            image::harden_store(&l.images_dir(), opts.fakeroot)?;
        }
    }

    if matches!(opts.execution_profile, ExecutionProfile::ConfidentialAzure) {
        install_confidential_components(&opts)?;
    }

    // 4. Render config + units + tmpfiles.
    let vars = RenderVars {
        ne_uid,
        execution_profile: opts.execution_profile,
    };
    write_file(l.env_file(), &render::render_env(&vars), opts.dry_run)?;
    write_file(
        l.supervisor_unit(),
        &render::render_supervisor_unit(&vars),
        opts.dry_run,
    )?;
    write_file(l.api_unit(), &render::render_api_unit(), opts.dry_run)?;
    write_file(l.tmpfiles_conf(), &render::render_tmpfiles(), opts.dry_run)?;

    // 4b. Default PII policy — installed only when absent so operator
    //     edits survive a re-install. The supervisor references this via
    //     NE_PRIVACY_ROUTER_POLICY in the env file; without it the
    //     per-workspace privacy router is never spawned even for opt-in
    //     workspaces (both binary + policy must be set).
    let policy = l.privacy_policy_file();
    if opts.dry_run {
        tracing::info!(
            "[dry-run] install default PII policy -> {}",
            policy.display()
        );
    } else if !policy.exists() {
        write_file(policy, &render::render_privacy_policy(), false)?;
    }

    // 5. Activate (real installs only).
    if !opts.fakeroot && !opts.dry_run && !opts.no_start {
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "ne-supervisor.service", "ne-api.service"])?;
    }

    print_next_steps(&opts);
    Ok(())
}

fn validate_confidential_inputs(opts: &InstallOptions) -> Result<()> {
    let sandbox = opts
        .openshell_sandbox_source
        .as_deref()
        .context("confidential-azure requires --openshell-sandbox-source")?;
    validate_regular_source("OpenShell sandbox", sandbox)?;
    for (name, source) in [
        (
            "OpenShell policy rules",
            opts.openshell_policy_rules_source.as_deref(),
        ),
        (
            "OpenShell policy data",
            opts.openshell_policy_data_source.as_deref(),
        ),
    ] {
        if let Some(source) = source {
            validate_regular_source(name, source)?;
        }
    }
    Ok(())
}

fn validate_regular_source(name: &str, source: &Path) -> Result<()> {
    let metadata = fs::metadata(source).with_context(|| format!("inspect {}", source.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{name} source {} is not a regular file",
        source.display()
    );
    Ok(())
}

/// Prepare only the state/image-store portion of the layout for a direct
/// `nee image import`. The state parent is secured before the store is opened.
pub fn prepare_image_store(l: &Layout, fakeroot: bool) -> Result<()> {
    let paths = [l.state_dir(), l.images_dir()];
    validate_existing_directory_chains(l.root(), &paths)?;
    ensure_directory_chain(l.root(), &l.state_dir())?;
    apply_directory_policy(&l.state_dir(), "root", "ne", 0o750, fakeroot)?;
    ensure_directory_chain(l.root(), &l.images_dir())?;
    apply_directory_policy(&l.images_dir(), "root", "root", 0o755, fakeroot)?;
    image::harden_store(&l.images_dir(), fakeroot)
}

fn validate_existing_directory_chains(root: &Path, targets: &[PathBuf]) -> Result<()> {
    ensure_layout_root(root)?;
    for target in targets {
        let relative = target.strip_prefix(root).with_context(|| {
            format!(
                "{} is outside install root {}",
                target.display(),
                root.display()
            )
        })?;
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) => anyhow::ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "managed directory component {} is a symlink or non-directory",
                    current.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", current.display()));
                }
            }
        }
    }
    Ok(())
}

fn ensure_layout_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_directory(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).with_context(|| format!("mkdir {}", root.display()))?;
            validate_directory(root)
        }
        Err(error) => Err(error).with_context(|| format!("inspect {}", root.display())),
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "managed directory {} is a symlink or non-directory",
        path.display()
    );
    Ok(())
}

fn ensure_directory_chain(root: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "{} is outside install root {}",
            target.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "managed directory component {} is a symlink or non-directory",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        validate_directory(&current)?;
                    }
                    Err(error) => {
                        return Err(error).with_context(|| format!("mkdir {}", current.display()));
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", current.display()));
            }
        }
    }
    Ok(())
}

/// Reverse an install. Stops/disables the two units (unless fakeroot),
/// removes rendered unit files + env + tmpfiles, and optionally purges state.
pub fn uninstall(layout: &Layout, purge: bool, fakeroot: bool) -> Result<()> {
    if !fakeroot {
        // Best-effort: units may not be installed yet.
        let _ = systemctl(&[
            "disable",
            "--now",
            "ne-supervisor.service",
            "ne-api.service",
        ]);
    }

    for path in [
        layout.supervisor_unit(),
        layout.api_unit(),
        layout.env_file(),
        layout.tmpfiles_conf(),
        layout.privacy_policy_file(),
    ] {
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }

    if purge && layout.state_dir().exists() {
        fs::remove_dir_all(layout.state_dir())
            .with_context(|| format!("purging {}", layout.state_dir().display()))?;
    }

    Ok(())
}

/// Preflight wrapper for `nee doctor`.
pub fn doctor(l: &Layout, execution_profile: ExecutionProfile) -> preflight::Report {
    // /dev/kvm is always the real host device, even under `--prefix`: the
    // prefix redirects install paths, not the kernel's KVM character device.
    let tpm2 = find_command("tpm2").unwrap_or_else(|| PathBuf::from("/usr/bin/tpm2"));
    let sandbox_identity = if matches!(execution_profile, ExecutionProfile::ConfidentialAzure) {
        sandbox_identity_status()
    } else {
        Ok(())
    };
    let mut report = preflight::run_report(
        execution_profile,
        &preflight::PreflightPaths {
            kvm: PathBuf::from("/dev/kvm"),
            vtpm: PathBuf::from("/dev/tpmrm0"),
            firecracker: l.bin_dir().join("firecracker"),
            jailer: l.bin_dir().join("jailer"),
            openshell_sandbox: l.openshell_sandbox_binary(),
            openshell_policy_rules: l.openshell_policy_rules(),
            openshell_policy_data: l.openshell_policy_data(),
            tpm2: tpm2.clone(),
            sandbox_identity,
        },
    );
    if matches!(execution_profile, ExecutionProfile::ConfidentialAzure) {
        preflight::append_azure_tpm_checks(&mut report, &tpm2);
    }
    report
}

fn find_command(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn write_file(path: PathBuf, body: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        tracing::info!("[dry-run] write {}", path.display());
        return Ok(());
    }
    // Most parents are created by the step-1 dir loop in `install()`, but
    // `/etc/tmpfiles.d` is not — create the parent and surface the real error.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))
}

fn install_confidential_components(opts: &InstallOptions) -> Result<()> {
    let source = opts
        .openshell_sandbox_source
        .as_ref()
        .context("confidential-azure requires --openshell-sandbox-source")?;
    copy_executable(
        source,
        &opts.layout.openshell_sandbox_binary(),
        opts.dry_run,
    )?;
    install_policy_if_absent(
        opts.openshell_policy_rules_source.as_deref(),
        &opts.layout.openshell_policy_rules(),
        &render::render_openshell_policy_rules(),
        opts.dry_run,
    )?;
    install_policy_if_absent(
        opts.openshell_policy_data_source.as_deref(),
        &opts.layout.openshell_policy_data(),
        &render::render_openshell_policy_data(),
        opts.dry_run,
    )
}

fn install_policy_if_absent(
    source: Option<&Path>,
    destination: &Path,
    embedded: &str,
    dry_run: bool,
) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "OpenShell policy {} is a symlink or non-file",
                destination.display()
            );
            if !dry_run {
                set_policy_mode(destination)?;
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", destination.display()));
        }
    }
    let body = source.map_or_else(
        || Ok(embedded.to_string()),
        |path| {
            fs::read_to_string(path)
                .with_context(|| format!("reading policy source {}", path.display()))
        },
    )?;
    write_file(destination.to_path_buf(), &body, dry_run)?;
    if !dry_run {
        set_policy_mode(destination)?;
    }
    Ok(())
}

fn copy_executable(source: &Path, destination: &Path, dry_run: bool) -> Result<()> {
    if dry_run {
        tracing::info!(
            "[dry-run] copy executable {} -> {}",
            source.display(),
            destination.display()
        );
        return Ok(());
    }
    validate_regular_source("OpenShell sandbox", source)?;
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "refusing to replace symlink {}",
            destination.display()
        );
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "copying OpenShell sandbox {} -> {}",
            source.display(),
            destination.display()
        )
    })?;
    set_executable_mode(destination)
}

#[cfg(unix)]
fn set_executable_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_policy_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("chmod 0644 {}", path.display()))
}

#[cfg(not(unix))]
fn set_policy_mode(_path: &Path) -> Result<()> {
    Ok(())
}

fn fetch_default_image(l: &Layout) -> Result<()> {
    let pin = &image::DEFAULT_IMAGE;
    anyhow::ensure!(
        !pin.kernel_sha256.starts_with("PLACEHOLDER"),
        "no default image is pinned in this build; use `nee image import` or `--no-image`"
    );
    let tmp = tempfile::tempdir().context("temp dir for image download")?;
    let k = tmp.path().join("vmlinux");
    let r = tmp.path().join("rootfs.img");
    image::curl_download(&format!("{}/vmlinux", pin.url_base), &k)?;
    image::curl_download(&format!("{}/rootfs.img", pin.url_base), &r)?;
    image::import_artifact(&l.images_dir(), "kernels", "vmlinux", &k, pin.kernel_sha256)?;
    image::import_artifact(
        &l.images_dir(),
        "rootfs",
        "rootfs.img",
        &r,
        pin.rootfs_sha256,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_service_user(name: &str) -> Result<()> {
    // Idempotent: getent succeeds → already exists.
    let exists = std::process::Command::new("getent")
        .args(["passwd", name])
        .status()
        .is_ok_and(|s| s.success());
    if exists {
        return Ok(());
    }
    let status = std::process::Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            name,
        ])
        .status()
        .context("running useradd")?;
    anyhow::ensure!(status.success(), "useradd {name} failed ({status})");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_service_user(_name: &str) -> Result<()> {
    anyhow::bail!("user creation is only supported on Linux")
}

const SANDBOX_HOME: &str = "/home/sandbox";

fn validate_sandbox_account_fields(
    user_gid: u32,
    group_gid: u32,
    home: &Path,
) -> Result<(), String> {
    if user_gid != group_gid {
        return Err(format!(
            "sandbox primary gid {user_gid} does not match sandbox group gid {group_gid}"
        ));
    }
    if home != Path::new(SANDBOX_HOME) {
        return Err(format!(
            "sandbox home {} does not match {SANDBOX_HOME}",
            home.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_sandbox_user() -> Result<()> {
    use nix::unistd::{Group, User};

    let user_exists = User::from_name("sandbox")
        .context("looking up sandbox user")?
        .is_some();
    if !user_exists {
        if Group::from_name("sandbox")
            .context("looking up sandbox group")?
            .is_none()
        {
            let status = std::process::Command::new("groupadd")
                .args(["--system", "sandbox"])
                .status()
                .context("running groupadd for sandbox")?;
            anyhow::ensure!(status.success(), "groupadd sandbox failed ({status})");
        }
        let status = std::process::Command::new("useradd")
            .args([
                "--system",
                "--gid",
                "sandbox",
                "--home-dir",
                SANDBOX_HOME,
                "--create-home",
                "--shell",
                "/usr/sbin/nologin",
                "sandbox",
            ])
            .status()
            .context("running useradd for sandbox")?;
        anyhow::ensure!(status.success(), "useradd sandbox failed ({status})");
    }

    let user = User::from_name("sandbox")
        .context("looking up sandbox user after creation")?
        .context("sandbox user missing after creation")?;
    let group = Group::from_name("sandbox")
        .context("looking up sandbox group after creation")?
        .context("sandbox group missing after creation")?;
    validate_sandbox_account_fields(user.gid.as_raw(), group.gid.as_raw(), &user.dir)
        .map_err(anyhow::Error::msg)?;

    let home = Path::new(SANDBOX_HOME);
    ensure_directory_chain(Path::new("/"), home)?;
    apply_directory_policy(home, "sandbox", "sandbox", 0o750, false)?;
    sandbox_identity_status().map_err(anyhow::Error::msg)
}

#[cfg(not(target_os = "linux"))]
fn ensure_sandbox_user() -> Result<()> {
    anyhow::bail!("sandbox user creation is only supported on Linux")
}

#[cfg(unix)]
fn sandbox_identity_status() -> std::result::Result<(), String> {
    use nix::unistd::{Group, User};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let user = User::from_name("sandbox")
        .map_err(|error| format!("look up sandbox user: {error}"))?
        .ok_or_else(|| "sandbox account missing".to_string())?;
    let group = Group::from_name("sandbox")
        .map_err(|error| format!("look up sandbox group: {error}"))?
        .ok_or_else(|| "sandbox group missing".to_string())?;
    validate_sandbox_account_fields(user.gid.as_raw(), group.gid.as_raw(), &user.dir)?;

    let metadata = fs::symlink_metadata(SANDBOX_HOME)
        .map_err(|error| format!("inspect {SANDBOX_HOME}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{SANDBOX_HOME} is not a real directory"));
    }
    if metadata.uid() != user.uid.as_raw() || metadata.gid() != group.gid.as_raw() {
        return Err(format!("{SANDBOX_HOME} is not owned by sandbox:sandbox"));
    }
    if metadata.permissions().mode() & 0o777 != 0o750 {
        return Err(format!("{SANDBOX_HOME} mode is not 0750"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn sandbox_identity_status() -> std::result::Result<(), String> {
    Err("sandbox identity validation is only supported on Unix".to_string())
}

/// Resolve the uid of a user that was just created (or already existed).
/// Falls back to 0 on non-Linux or lookup failure (root — will be corrected
/// by the ownership-adjustment step).
#[cfg(target_os = "linux")]
fn resolve_uid_after_creation(name: &str) -> u32 {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map_or(0, |u| u.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
fn resolve_uid_after_creation(_name: &str) -> u32 {
    0
}

/// Apply the owner + mode from [`dir_ownership`] to each managed directory.
fn apply_ownership(l: &Layout, fakeroot: bool) -> Result<()> {
    for (abs, (user, group), mode) in dir_ownership() {
        let path = l.root().join(abs.trim_start_matches('/'));
        if path.exists() {
            apply_directory_policy(&path, user, group, mode, fakeroot)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn apply_directory_policy(
    path: &Path,
    user: &str,
    group: &str,
    mode: u32,
    fakeroot: bool,
) -> Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, fchmod};

    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| {
        format!(
            "open managed directory {} without following symlinks",
            path.display()
        )
    })?;
    let result = (|| {
        if !fakeroot {
            let uid = nix::unistd::User::from_name(user)
                .with_context(|| format!("looking up user {user}"))?
                .map(|entry| entry.uid)
                .ok_or_else(|| anyhow::anyhow!("required install user {user} does not exist"))?;
            let gid = nix::unistd::Group::from_name(group)
                .with_context(|| format!("looking up group {group}"))?
                .map(|entry| entry.gid)
                .ok_or_else(|| anyhow::anyhow!("required install group {group} does not exist"))?;
            nix::unistd::fchown(fd, Some(uid), Some(gid))
                .with_context(|| format!("fchown {} {user}:{group}", path.display()))?;
        }
        // `mode_t` is `u32` on Linux but narrower on some Unix targets, so the
        // checked conversion is intentionally an identity conversion on Linux.
        #[allow(clippy::useless_conversion)]
        let mode = mode
            .try_into()
            .context("directory mode does not fit mode_t")?;
        fchmod(fd, Mode::from_bits_truncate(mode))
            .with_context(|| format!("fchmod {} {mode:o}", path.display()))?;
        Ok(())
    })();
    let close_result = nix::unistd::close(fd).context("close managed directory handle");
    result.and(close_result)
}

#[cfg(not(unix))]
fn apply_directory_policy(
    path: &Path,
    _user: &str,
    _group: &str,
    mode: u32,
    _fakeroot: bool,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    validate_directory(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {} {mode:o}", path.display()))
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .context("running systemctl")?;
    anyhow::ensure!(status.success(), "systemctl {args:?} failed ({status})");
    Ok(())
}

fn print_next_steps(opts: &InstallOptions) {
    if opts.fakeroot || opts.dry_run {
        return;
    }
    tracing::info!(
        "NeuronEdge Enclave installed. API is dev-mode on 127.0.0.1:50051 (gRPC) / :8080 (REST). \
         Production external auth is NOT yet available; do not expose these ports."
    );
}

/// Desired owner + mode for each managed directory. `owner` is
/// ("user","group"); resolved to uids at apply time.
pub fn dir_ownership() -> Vec<(&'static str, (&'static str, &'static str), u32)> {
    vec![
        ("/var/lib/ne-enclave", ("root", "ne"), 0o750),
        ("/var/lib/ne-enclave/images", ("root", "root"), 0o755),
        ("/var/lib/ne-enclave/workspaces", ("ne", "ne"), 0o750),
        ("/var/lib/ne-enclave/snapshots", ("ne", "ne"), 0o750),
        ("/var/lib/ne-enclave/openshell", ("root", "root"), 0o755),
        ("/srv/jailer", ("root", "root"), 0o700),
        ("/etc/ne-enclave", ("root", "ne"), 0o750),
        ("/run/ne-enclave", ("root", "ne"), 0o750),
    ]
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn sandbox_account_contract_requires_matching_group_and_home() {
        assert!(validate_sandbox_account_fields(700, 700, Path::new("/home/sandbox")).is_ok());
        assert!(validate_sandbox_account_fields(700, 701, Path::new("/home/sandbox")).is_err());
        assert!(validate_sandbox_account_fields(700, 700, Path::new("/var/empty")).is_err());
    }

    #[test]
    fn jailer_base_is_root_only() {
        let t = dir_ownership();
        let j = t.iter().find(|(p, _, _)| *p == "/srv/jailer").unwrap();
        assert_eq!(j.1, ("root", "root"));
        assert_eq!(j.2, 0o700);
    }

    #[test]
    fn etc_is_group_ne_readable() {
        let t = dir_ownership();
        let e = t.iter().find(|(p, _, _)| *p == "/etc/ne-enclave").unwrap();
        assert_eq!(e.1, ("root", "ne"));
    }

    #[test]
    fn image_store_is_root_owned_and_not_service_writable() {
        let t = dir_ownership();
        let state = t
            .iter()
            .find(|(p, _, _)| *p == "/var/lib/ne-enclave")
            .unwrap();
        let images = t
            .iter()
            .find(|(p, _, _)| *p == "/var/lib/ne-enclave/images")
            .unwrap();
        assert_eq!(state.1, ("root", "ne"));
        assert_eq!(images.1, ("root", "root"));
        assert_eq!(
            images.2 & 0o022,
            0,
            "API identity must not write image store"
        );
    }
}

#[cfg(test)]
mod uninstall_tests {
    use super::*;

    #[test]
    fn purge_removes_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::new(tmp.path());
        // Create state dir + some nested content.
        let state = layout.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("audit.log"), b"data").unwrap();
        // Create unit files so uninstall has something to remove.
        fs::create_dir_all(layout.systemd_dir()).unwrap();
        fs::create_dir_all(layout.etc_dir()).unwrap();
        fs::create_dir_all(
            layout
                .tmpfiles_conf()
                .parent()
                .expect("tmpfiles_conf has parent"),
        )
        .unwrap();

        uninstall(&layout, true, true).unwrap();

        assert!(!state.exists(), "state_dir should be removed after --purge");
    }

    #[test]
    fn non_purge_leaves_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = Layout::new(tmp.path());
        let state = layout.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(layout.systemd_dir()).unwrap();
        fs::create_dir_all(layout.etc_dir()).unwrap();
        fs::create_dir_all(
            layout
                .tmpfiles_conf()
                .parent()
                .expect("tmpfiles_conf has parent"),
        )
        .unwrap();

        uninstall(&layout, false, true).unwrap();

        assert!(state.exists(), "state_dir should remain when purge=false");
    }
}

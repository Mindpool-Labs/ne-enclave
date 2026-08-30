// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Guest image provisioning: verify a SHA256 digest and place a file
//! into the content-addressed image store.
#![allow(unreachable_pub)]

use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Compute the lowercase-hex SHA256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Validate the canonical external digest grammar.
pub fn validate_sha256(expected_hex: &str) -> Result<()> {
    anyhow::ensure!(
        expected_hex.len() == 64
            && expected_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid SHA-256 digest: expected exactly 64 lowercase hexadecimal characters"
    );
    Ok(())
}

/// Verify `path` matches the canonical expected digest.
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    validate_sha256(expected_hex)?;
    let got = sha256_file(path)?;
    if got == expected_hex {
        Ok(())
    } else {
        anyhow::bail!(
            "checksum mismatch for {}: expected {}, got {}",
            path.display(),
            expected_hex,
            got
        )
    }
}

/// Copy a verified `kind` ("kernels"/"rootfs") artifact into the
/// content-addressed store under `images_dir`, returning its final path.
pub fn import_artifact(
    images_dir: &Path,
    kind: &str,
    filename: &str,
    src: &Path,
    expected_hex: &str,
) -> Result<PathBuf> {
    import_artifact_with_hook(images_dir, kind, filename, src, expected_hex, || {})
}

fn import_artifact_with_hook<F>(
    images_dir: &Path,
    kind: &str,
    filename: &str,
    src: &Path,
    expected_hex: &str,
    before_copy: F,
) -> Result<PathBuf>
where
    F: FnOnce(),
{
    // Validate before reading the source or creating any store directory.
    validate_sha256(expected_hex)?;
    let expected_filename = match kind {
        "kernels" => "vmlinux",
        "rootfs" => "rootfs.img",
        _ => anyhow::bail!("invalid managed image kind {kind:?}"),
    };
    anyhow::ensure!(
        filename == expected_filename,
        "invalid filename for managed {kind} artifact"
    );

    validate_directory(images_dir)?;
    let mut source = fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .with_context(|| format!("read {}", src.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let got = hex::encode(hasher.finalize());
    anyhow::ensure!(
        got == expected_hex,
        "checksum mismatch for {}: expected {}, got {}",
        src.display(),
        expected_hex,
        got
    );
    source
        .rewind()
        .with_context(|| format!("rewind {}", src.display()))?;
    before_copy();

    let kind_dir = ensure_store_child_directory(images_dir, kind)?;
    let dir = ensure_store_child_directory(&kind_dir, expected_hex)?;
    let dest = dir.join(filename);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&dest)
        .with_context(|| format!("create new managed artifact {}", dest.display()))?;
    let publish = (|| -> Result<()> {
        let mut copied_hasher = Sha256::new();
        loop {
            let count = source
                .read(&mut buffer)
                .with_context(|| format!("read verified source {}", src.display()))?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
            copied_hasher.update(&buffer[..count]);
        }
        let copied_digest = hex::encode(copied_hasher.finalize());
        anyhow::ensure!(
            copied_digest == expected_hex,
            "copied managed artifact digest mismatch: expected {expected_hex}, got {copied_digest}"
        );
        output
            .flush()
            .with_context(|| format!("flush {}", dest.display()))?;
        output
            .sync_all()
            .with_context(|| format!("sync {}", dest.display()))?;
        output
            .set_permissions(fs::Permissions::from_mode(0o444))
            .with_context(|| format!("chmod {} 444", dest.display()))?;
        Ok(())
    })();
    if let Err(error) = publish {
        drop(output);
        let cleanup = fs::remove_file(&dest);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "remove failed import artifact {}: {cleanup}",
                dest.display()
            ))),
        };
    }
    Ok(dest)
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "managed image directory {} is a symlink or non-directory",
        path.display()
    );
    Ok(())
}

fn ensure_store_child_directory(parent: &Path, child: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !child.is_empty() && child.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "invalid managed image directory component {child:?}"
    );
    let path = parent.join(child);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed image directory {} is a symlink or non-directory",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_directory(&path)?;
            }
            Err(error) => return Err(error).with_context(|| format!("mkdir {}", path.display())),
        },
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {} 755", path.display()))?;
    Ok(path)
}

/// Recursively enforce the managed store's non-writable install posture.
/// Symlinks and unexpected special files fail closed rather than being followed.
pub fn harden_store(images_dir: &Path, fakeroot: bool) -> Result<()> {
    harden_entry(images_dir, fakeroot)
}

fn harden_entry(path: &Path, fakeroot: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect managed image path {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "managed image store contains symlink {}",
        path.display()
    );
    if metadata.is_dir() {
        harden_entry_policy(path, true, 0o755, fakeroot)?;
        for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            harden_entry(&entry?.path(), fakeroot)?;
        }
    } else {
        anyhow::ensure!(
            metadata.is_file(),
            "managed image store contains non-regular file {}",
            path.display()
        );
        harden_entry_policy(path, false, 0o444, fakeroot)?;
    }
    Ok(())
}

#[cfg(unix)]
fn harden_entry_policy(path: &Path, directory: bool, mode: u32, fakeroot: bool) -> Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, fchmod};

    let mut flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW;
    if directory {
        flags |= OFlag::O_DIRECTORY;
    }
    let fd = open(path, flags, Mode::empty()).with_context(|| {
        format!(
            "open managed image path {} without following symlinks",
            path.display()
        )
    })?;
    let result = (|| {
        if !fakeroot {
            nix::unistd::fchown(
                fd,
                Some(nix::unistd::Uid::from_raw(0)),
                Some(nix::unistd::Gid::from_raw(0)),
            )
            .with_context(|| format!("fchown {} root:root", path.display()))?;
        }
        // `mode_t` is `u32` on Linux but narrower on some Unix targets, so the
        // checked conversion is intentionally an identity conversion on Linux.
        #[allow(clippy::useless_conversion)]
        let mode = mode.try_into().context("image mode does not fit mode_t")?;
        fchmod(fd, Mode::from_bits_truncate(mode))
            .with_context(|| format!("fchmod {} {mode:o}", path.display()))?;
        Ok(())
    })();
    let close_result = nix::unistd::close(fd).context("close managed image handle");
    result.and(close_result)
}

#[cfg(not(unix))]
fn harden_entry_policy(path: &Path, _directory: bool, mode: u32, _fakeroot: bool) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {} {mode:o}", path.display()))
}

/// The default guest image shipped with this release. Digests are filled
/// from the CI-published image asset (release automation sets these to real values).
pub struct ImagePin {
    /// Base URL the kernel + rootfs assets are downloaded from.
    pub url_base: &'static str,
    /// Expected lowercase-hex SHA256 of the kernel asset.
    pub kernel_sha256: &'static str,
    /// Expected lowercase-hex SHA256 of the rootfs asset.
    pub rootfs_sha256: &'static str,
}

/// The default guest image pinned for this build (placeholder digests until
/// CI publishes the real asset; `fetch_default_image` guards against them).
pub const DEFAULT_IMAGE: ImagePin = ImagePin {
    // Replace with the real release asset URL and digests before release.
    url_base: "https://github.com/Mindpool-Labs/ne-enclave/releases/latest/download",
    kernel_sha256: "PLACEHOLDER_KERNEL_SHA256",
    rootfs_sha256: "PLACEHOLDER_ROOTFS_SHA256",
};

/// Download `url` to `dest` via curl (keeps the HTTP dep surface at zero).
pub fn curl_download(url: &str, dest: &Path) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("spawning curl")?;
    if !status.success() {
        anyhow::bail!("curl failed for {url} (status {status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn verify_rejects_wrong_digest() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("vmlinux");
        fs::write(&f, b"hello").unwrap();
        assert!(verify_sha256(&f, "0".repeat(64).as_str()).is_err());
    }

    #[test]
    fn import_places_into_content_addressed_dir() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"kernel-bytes").unwrap();
        let digest = sha256_file(&src).unwrap();
        let images = dir.path().join("images");
        fs::create_dir(&images).unwrap();
        let dest = import_artifact(&images, "kernels", "vmlinux", &src, &digest).unwrap();
        assert!(dest.ends_with(format!("kernels/{digest}/vmlinux")));
        assert!(dest.exists());
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            fs::metadata(dest.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn import_rejects_noncanonical_digest_before_mutating_store() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"kernel-bytes").unwrap();
        let images = dir.path().join("images");

        for digest in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            assert!(
                import_artifact(&images, "kernels", "vmlinux", &src, &digest).is_err(),
                "accepted {digest}"
            );
            assert!(!images.exists(), "invalid digest mutated the image store");
        }
    }

    #[test]
    fn import_rejects_existing_destination_symlink_without_touching_target() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"new-kernel").unwrap();
        let digest = sha256_file(&src).unwrap();
        let images = dir.path().join("images");
        let digest_dir = images.join("kernels").join(&digest);
        fs::create_dir_all(&digest_dir).unwrap();
        let sentinel = dir.path().join("sentinel");
        fs::write(&sentinel, b"must-not-change").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&sentinel).unwrap();
        symlink(&sentinel, digest_dir.join("vmlinux")).unwrap();

        assert!(import_artifact(&images, "kernels", "vmlinux", &src, &digest).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"must-not-change");
        let after = fs::metadata(&sentinel).unwrap();
        assert_eq!(after.mode(), before.mode());
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }

    #[test]
    fn import_rejects_existing_regular_artifact_without_replacing_it() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"new-kernel").unwrap();
        let digest = sha256_file(&src).unwrap();
        let images = dir.path().join("images");
        let digest_dir = images.join("kernels").join(&digest);
        fs::create_dir_all(&digest_dir).unwrap();
        let dest = digest_dir.join("vmlinux");
        fs::write(&dest, b"existing").unwrap();

        assert!(import_artifact(&images, "kernels", "vmlinux", &src, &digest).is_err());
        assert_eq!(fs::read(dest).unwrap(), b"existing");
    }

    #[test]
    fn import_rejects_same_inode_mutation_between_verification_and_copy() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vmlinux");
        fs::write(&src, b"verified-kernel").unwrap();
        let digest = sha256_file(&src).unwrap();
        let images = dir.path().join("images");
        fs::create_dir(&images).unwrap();
        let dest = images.join("kernels").join(&digest).join("vmlinux");

        let result =
            import_artifact_with_hook(&images, "kernels", "vmlinux", &src, &digest, || {
                fs::write(&src, b"mutated-kernel").unwrap();
            });

        assert!(result.is_err());
        assert!(!dest.exists(), "mismatched copied bytes were published");
    }
}

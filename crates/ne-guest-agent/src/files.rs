// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unreachable_pub))]
#![allow(clippy::redundant_pub_crate)]

//! File operations under the workspace jail root.
//!
//! Two responsibilities:
//!
//! 1. [`validate_relative_path`] — pure function rejecting any path
//!    that escapes or attacks the `/workspace` jail. Cross-platform so
//!    its rules are unit-tested on any host the workspace builds on.
//! 2. [`write_file_atomic`] / [`read_file_capped`] — Linux-only
//!    syscall layer. Atomic writes go through temp file + fsync +
//!    rename. Reads use `O_NOFOLLOW` and a hard byte cap.
//!
//! The jail root is conventionally `/workspace` but callers supply it
//! explicitly so tests can substitute a temp dir.
//!
//! # Errors
//!
//! Each operation maps its failure mode to an [`ne_protocol::guest::GuestErrorKind`]
//! variant via the [`FileError`] enum.
//!
//! # Current scope
//!
//! - Inline bodies; the 10 MiB cap is enforced by the caller before
//!   it reaches the agent.
//! - Fixed mode 0644 for new files, 0755 for new parent directories.
//! - Symlinks are never followed.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

use ne_protocol::guest::GuestErrorKind;
use thiserror::Error;

/// Default 10 MiB cap matching the api daemon's request body cap.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Failure modes for [`write_file_atomic`] and [`read_file_capped`].
#[derive(Debug, Error)]
pub(crate) enum FileError {
    /// Path violated the jail policy.
    #[error("path rejected: {0}")]
    PathRejected(String),
    /// Read target does not exist.
    #[error("file not found")]
    NotFound,
    /// Request body exceeded the guest's accepted size cap.
    #[error("file too large: {actual} bytes > cap {cap}")]
    #[allow(dead_code)]
    TooLarge {
        /// Size the caller submitted.
        actual: u64,
        /// Active cap.
        cap: u64,
    },
    /// Underlying I/O failure (disk full, permission, fsync, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl FileError {
    /// Stable mapping into the wire-level [`GuestErrorKind`].
    #[must_use]
    pub(crate) fn kind(&self) -> GuestErrorKind {
        match self {
            Self::PathRejected(_) => GuestErrorKind::PathRejected,
            Self::NotFound => GuestErrorKind::FileNotFound,
            Self::TooLarge { .. } => GuestErrorKind::FileTooLarge,
            Self::Io(_) => GuestErrorKind::IoError,
        }
    }
}

/// Validate a caller-supplied relative path. Rejects:
///
/// 1. Empty strings.
/// 2. Absolute paths (`/...`).
/// 3. Any component that is empty, `.`, or `..`.
/// 4. Any component containing a null byte.
///
/// Returns the cleaned relative path on success — same shape as the
/// input but split-and-rejoined so callers can rely on a normalized
/// form.
pub(crate) fn validate_relative_path(raw: &str) -> Result<PathBuf, FileError> {
    if raw.is_empty() {
        return Err(FileError::PathRejected("path is empty".into()));
    }
    if raw.starts_with('/') {
        return Err(FileError::PathRejected(format!(
            "absolute path not allowed: {raw:?}"
        )));
    }
    let mut out = PathBuf::new();
    for component in raw.split('/') {
        if component.is_empty() {
            return Err(FileError::PathRejected(format!(
                "empty component in {raw:?}"
            )));
        }
        if component == "." || component == ".." {
            return Err(FileError::PathRejected(format!(
                "{component:?} segment in {raw:?}"
            )));
        }
        if component.contains('\0') {
            return Err(FileError::PathRejected(format!(
                "null byte in component of {raw:?}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

/// Compute the final absolute path under `jail_root` for a validated
/// relative `path`, AND verify that the parent dir (after creation if
/// missing) resolves inside `jail_root` — defense-in-depth against
/// workload-planted symlinks at intermediate directory components.
///
/// `O_NOFOLLOW` only guards the final leaf; this check catches
/// `ln -s /etc /workspace/a` → write to `a/b.txt`.
///
/// Returns the joined `final_path` on success. On Linux only — uses
/// `canonicalize` which resolves symlinks.
#[cfg(target_os = "linux")]
pub(crate) fn jailed_absolute(jail_root: &Path, path: &Path) -> Result<PathBuf, FileError> {
    let final_path = jail_root.join(path);
    let jail_canon = jail_root.canonicalize().map_err(FileError::Io)?;
    // If the parent doesn't exist yet, canonicalize the closest
    // ancestor that does. write_file_atomic calls create_dir_all
    // before this, so the parent should exist by the time we check.
    let parent = final_path.parent().unwrap_or(jail_root);
    let parent_canon = match parent.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FileError::NotFound);
        }
        Err(e) => return Err(FileError::Io(e)),
    };
    if !parent_canon.starts_with(&jail_canon) {
        return Err(FileError::PathRejected(format!(
            "resolved parent {} escapes jail root {}",
            parent_canon.display(),
            jail_canon.display(),
        )));
    }
    Ok(final_path)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{DEFAULT_MAX_BYTES, FileError, jailed_absolute, validate_relative_path};
    use rand::RngCore;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// Atomically write `content` to the file at `jail_root/relative`.
    ///
    /// 1. Validate the path.
    /// 2. Create any missing parent directories at mode 0755.
    /// 3. Write to `<final>.<rand>.tmp` (mode 0644, `O_EXCL`), fsync.
    /// 4. Rename the temp file into place.
    /// 5. fsync the parent dir so the rename survives a crash.
    ///
    /// Returns the absolute path the file landed at on success.
    pub(crate) fn write_file_atomic(
        jail_root: &Path,
        relative: &str,
        content: &[u8],
    ) -> Result<PathBuf, FileError> {
        let rel = validate_relative_path(relative)?;
        let final_path_unchecked = jail_root.join(&rel);
        // First make parents exist so canonicalize has something to resolve.
        if let Some(parent) = final_path_unchecked.parent() {
            fs::create_dir_all(parent)?;
            // create_dir_all is mode-derived from umask; tighten to 0755.
            let mut walked = jail_root.to_path_buf();
            for component in rel.parent().into_iter().flat_map(|p| p.components()) {
                walked.push(component);
                let perms = fs::Permissions::from_mode(0o755);
                let _ = fs::set_permissions(&walked, perms);
            }
        }
        // NOW that parents exist, defense-in-depth against symlinks at any
        // intermediate component.
        let final_path = jailed_absolute(jail_root, &rel)?;
        let mut rand_buf = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut rand_buf);
        let suffix = format!("{:08x}", u32::from_le_bytes(rand_buf));
        let tmp_path = final_path.parent().map_or_else(
            || PathBuf::from(format!(".tmp.{suffix}")),
            |parent| {
                parent.join(format!(
                    ".{}.{}.tmp",
                    final_path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("file"),
                    suffix,
                ))
            },
        );
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp_path)?;
        let result: std::io::Result<()> = (|| {
            tmp.write_all(content)?;
            tmp.sync_all()?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp_path);
            return Err(FileError::Io(e));
        }
        drop(tmp);
        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(FileError::Io(e));
        }
        if let Some(parent) = final_path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(final_path)
    }

    /// Read a file at `jail_root/relative` with a byte cap.
    ///
    /// `max_bytes` of `0` is replaced with [`DEFAULT_MAX_BYTES`].
    /// Refuses to follow symlinks. Returns `(content, size_bytes, truncated)`.
    pub(crate) fn read_file_capped(
        jail_root: &Path,
        relative: &str,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, u64, bool), FileError> {
        let rel = validate_relative_path(relative)?;
        let final_path = jailed_absolute(jail_root, &rel)?;

        // O_NOFOLLOW: refuse symlinks at the leaf. The jail rules
        // already reject ".." components, so directory traversal up
        // is already blocked.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&final_path);
        let file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FileError::NotFound),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(FileError::PathRejected(format!(
                    "refusing to follow symlink at {}",
                    final_path.display()
                )));
            }
            Err(e) => return Err(FileError::Io(e)),
        };
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            return Err(FileError::PathRejected(format!(
                "{} is a directory",
                final_path.display()
            )));
        }
        let size_bytes = metadata.len();
        let cap = if max_bytes == 0 {
            DEFAULT_MAX_BYTES
        } else {
            max_bytes
        };
        let to_read = std::cmp::min(size_bytes, cap);
        let mut buf = Vec::with_capacity(usize::try_from(to_read).unwrap_or(usize::MAX));
        file.take(to_read).read_to_end(&mut buf)?;
        let truncated = size_bytes > cap;
        Ok((buf, size_bytes, truncated))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{read_file_capped, write_file_atomic};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_simple_relative() {
        assert!(validate_relative_path("a.txt").is_ok());
        assert!(validate_relative_path("src/main.rs").is_ok());
        assert!(validate_relative_path("a/b/c/d.bin").is_ok());
    }

    #[test]
    fn validate_rejects_empty() {
        match validate_relative_path("") {
            Err(FileError::PathRejected(_)) => {}
            other => panic!("expected PathRejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_absolute() {
        match validate_relative_path("/etc/passwd") {
            Err(FileError::PathRejected(_)) => {}
            other => panic!("expected PathRejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_parent_segment() {
        for bad in ["../etc/passwd", "a/../b", "a/b/.."] {
            match validate_relative_path(bad) {
                Err(FileError::PathRejected(_)) => {}
                other => panic!("expected PathRejected for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_rejects_current_segment() {
        for bad in ["./a", "a/./b"] {
            match validate_relative_path(bad) {
                Err(FileError::PathRejected(_)) => {}
                other => panic!("expected PathRejected for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_rejects_null_byte() {
        match validate_relative_path("a\0b") {
            Err(FileError::PathRejected(_)) => {}
            other => panic!("expected PathRejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_double_slash() {
        match validate_relative_path("a//b") {
            Err(FileError::PathRejected(_)) => {}
            other => panic!("expected PathRejected, got {other:?}"),
        }
    }

    #[test]
    fn file_error_maps_to_guest_error_kind() {
        assert_eq!(
            FileError::PathRejected("x".into()).kind(),
            GuestErrorKind::PathRejected
        );
        assert_eq!(FileError::NotFound.kind(), GuestErrorKind::FileNotFound);
        assert_eq!(
            FileError::TooLarge { actual: 1, cap: 0 }.kind(),
            GuestErrorKind::FileTooLarge,
        );
        assert_eq!(
            FileError::Io(std::io::Error::other("x")).kind(),
            GuestErrorKind::IoError,
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::{read_file_capped, write_file_atomic};
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};

        #[test]
        fn write_then_read_round_trip() {
            let tmp = tempfile::tempdir().expect("tmp");
            let abs = write_file_atomic(tmp.path(), "a/b/hello.txt", b"hi there").expect("write");
            assert!(abs.starts_with(tmp.path()));
            let (content, size, truncated) =
                read_file_capped(tmp.path(), "a/b/hello.txt", 0).expect("read");
            assert_eq!(content, b"hi there");
            assert_eq!(size, 8);
            assert!(!truncated);
        }

        #[test]
        fn write_overwrites_existing() {
            let tmp = tempfile::tempdir().expect("tmp");
            write_file_atomic(tmp.path(), "x.txt", b"v1").expect("write1");
            write_file_atomic(tmp.path(), "x.txt", b"v2-longer").expect("write2");
            let (content, _, _) = read_file_capped(tmp.path(), "x.txt", 0).expect("read");
            assert_eq!(content, b"v2-longer");
        }

        #[test]
        fn write_creates_missing_parent_dirs() {
            let tmp = tempfile::tempdir().expect("tmp");
            write_file_atomic(tmp.path(), "a/b/c/d.txt", b"ok").expect("write");
            assert!(tmp.path().join("a/b/c/d.txt").exists());
        }

        #[test]
        fn write_leaves_no_temp_file_on_success() {
            let tmp = tempfile::tempdir().expect("tmp");
            write_file_atomic(tmp.path(), "x.txt", b"ok").expect("write");
            let entries: Vec<_> = fs::read_dir(tmp.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                entries.iter().all(|n| !n.contains(".tmp")),
                "expected no leftover .tmp files, got {entries:?}"
            );
        }

        #[test]
        fn read_missing_returns_not_found() {
            let tmp = tempfile::tempdir().expect("tmp");
            match read_file_capped(tmp.path(), "nope.txt", 0) {
                Err(super::super::FileError::NotFound) => {}
                other => panic!("expected NotFound, got {other:?}"),
            }
        }

        #[test]
        fn read_truncates_oversize_file() {
            let tmp = tempfile::tempdir().expect("tmp");
            write_file_atomic(tmp.path(), "big.bin", &vec![0u8; 4096]).expect("write");
            let (content, size, truncated) =
                read_file_capped(tmp.path(), "big.bin", 1024).expect("read");
            assert_eq!(content.len(), 1024);
            assert_eq!(size, 4096);
            assert!(truncated);
        }

        #[test]
        fn read_refuses_symlink() {
            let tmp = tempfile::tempdir().expect("tmp");
            let target = tmp.path().join("outside");
            fs::write(&target, b"secret").unwrap();
            symlink(&target, tmp.path().join("link.txt")).unwrap();
            match read_file_capped(tmp.path(), "link.txt", 0) {
                Err(super::super::FileError::PathRejected(_)) => {}
                other => panic!("expected PathRejected for symlink, got {other:?}"),
            }
        }

        #[test]
        fn read_refuses_directory() {
            let tmp = tempfile::tempdir().expect("tmp");
            fs::create_dir(tmp.path().join("subdir")).unwrap();
            match read_file_capped(tmp.path(), "subdir", 0) {
                Err(super::super::FileError::PathRejected(_)) => {}
                other => panic!("expected PathRejected for directory, got {other:?}"),
            }
        }

        #[test]
        fn write_cleans_up_temp_file_on_failure() {
            // Make the parent dir read-only after we create the file
            // so the rename(2) fails — that exercises the cleanup path
            // for the temp file (the only branch where cleanup matters,
            // since fsync of the parent can't be induced to fail cheaply).
            //
            // We make this test bullet-proof by writing once first to
            // ensure the parent dir exists, then chmod 0o555 it.
            let tmp = tempfile::tempdir().expect("tmp");
            write_file_atomic(tmp.path(), "x.txt", b"v1").expect("setup");
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o555)).expect("chmod ro");

            // This second write must fail (read-only parent prevents
            // rename's directory entry update) and leave no .tmp file.
            let result = write_file_atomic(tmp.path(), "x.txt", b"v2-longer");
            assert!(result.is_err(), "write to ro parent should fail");

            // Restore perms so tempdir teardown works.
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).expect("chmod back");

            // No leftover .tmp file (the create_new might or might not
            // have succeeded; either way, after the rename failure, the
            // cleanup branch must have removed any temp file).
            let entries: Vec<_> = fs::read_dir(tmp.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                entries.iter().all(|n| !n.contains(".tmp")),
                "expected no leftover .tmp files after failed write, got {entries:?}"
            );
        }
    }
}

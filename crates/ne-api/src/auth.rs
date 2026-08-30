// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! API-key authentication for the runtime front door.
//!
//! Keys are stored as SHA-256 hashes (never plaintext). The client
//! presents a high-entropy bearer token (`nee_<base64url 32 bytes>`);
//! the daemon hashes it and checks membership against the loaded set.
//! High entropy → SHA-256 is the correct at-rest form (no argon2 needed)
//! and a `HashSet` membership test is safe: the lookup key is a
//! preimage-resistant digest, not a low-entropy secret compared byte by
//! byte. The comparison uses fixed-length digests.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Loaded set of accepted API-key digests plus per-key labels (for
/// audit attribution). Cheap to clone via `Arc` at the call site.
#[derive(Debug, Default, Clone)]
pub struct ApiKeyStore {
    digests: HashSet<[u8; 32]>,
    labels: HashMap<[u8; 32], String>,
}

impl ApiKeyStore {
    /// Load a key file of `sha256:<64hex>  # optional label` lines.
    /// Blank lines and `#`-comment lines are ignored. Warns (does not
    /// fail) if the file mode is looser than 0600.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading api key file {}: {e}", path.display()))?;
        warn_if_world_readable(path);
        let mut store = Self::default();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (hash_part, label) = match line.split_once('#') {
                Some((h, l)) => (h.trim(), l.trim().to_string()),
                None => (line, String::new()),
            };
            let hex_digest = hash_part
                .strip_prefix("sha256:")
                .ok_or_else(|| {
                    anyhow::anyhow!("api key file line {}: expected `sha256:<hex>`", i + 1)
                })?
                .trim();
            let bytes = hex::decode(hex_digest)
                .map_err(|_| anyhow::anyhow!("api key file line {}: invalid hex digest", i + 1))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!("api key file line {}: digest must be 32 bytes", i + 1)
            })?;
            store.digests.insert(arr);
            if !label.is_empty() {
                store.labels.insert(arr, label);
            }
        }
        Ok(store)
    }

    /// Number of loaded keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// True when no keys are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Verify a presented bearer token. Returns the key's label (which
    /// may be empty) on success, `None` on rejection.
    ///
    /// Uses `HashSet` membership over a preimage-resistant SHA-256 digest
    /// rather than constant-time byte comparison: the stored value is
    /// already a one-way hash of a high-entropy token (32 random bytes),
    /// so there is no low-entropy secret to brute-force through timing.
    /// The preimage resistance of SHA-256 is the security primitive here.
    #[must_use]
    pub fn verify(&self, token: &str) -> Option<&str> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if self.digests.contains(&digest) {
            Some(self.labels.get(&digest).map_or("", String::as_str))
        } else {
            None
        }
    }

    /// Extract the token from an `Authorization: Bearer <token>` value.
    /// The prefix match is ASCII-case-insensitive. Returns `None` if the
    /// scheme is not Bearer, or if the token portion is empty.
    #[must_use]
    pub fn bearer_from_str(header: &str) -> Option<&str> {
        header
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("Bearer "))?;
        let token = header[7..].trim();
        if token.is_empty() { None } else { Some(token) }
    }
}

fn warn_if_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    path = %path.display(),
                    "api key file is group/world accessible; recommend chmod 0600"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(s: &str) -> String {
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    #[test]
    fn empty_store_verifies_nothing() {
        let s = ApiKeyStore::default();
        assert!(s.is_empty());
        assert_eq!(s.verify("nee_anything"), None);
    }

    #[test]
    fn loads_hashes_and_verifies_matching_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let token = "nee_testtoken123";
        std::fs::write(
            &path,
            format!("sha256:{}  # ci\n# a comment\n\n", sha256_hex(token)),
        )
        .unwrap();
        let s = ApiKeyStore::load(&path).expect("load");
        assert_eq!(s.len(), 1);
        assert_eq!(s.verify(token), Some("ci"));
        assert_eq!(s.verify("nee_wrong"), None);
    }

    #[test]
    fn rejects_malformed_line_with_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        std::fs::write(&path, "sha256:deadbeef\nnotahash\n").unwrap();
        let err = ApiKeyStore::load(&path).expect_err("must reject malformed");
        let msg = err.to_string();
        assert!(
            msg.contains("line 1") || msg.contains("line 2"),
            "got: {msg}"
        );
    }

    #[test]
    fn bearer_extraction() {
        assert_eq!(ApiKeyStore::bearer_from_str("Bearer abc"), Some("abc"));
        assert_eq!(ApiKeyStore::bearer_from_str("bearer abc"), Some("abc"));
        assert_eq!(ApiKeyStore::bearer_from_str("Bearer "), None);
        assert_eq!(ApiKeyStore::bearer_from_str("Basic abc"), None);
        assert_eq!(ApiKeyStore::bearer_from_str(""), None);
    }
}

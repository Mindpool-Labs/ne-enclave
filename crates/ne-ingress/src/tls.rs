// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for the NeuronEdge Enclave ingress edge.
//!
//! Exposes [`load_server_config`] to build a rustls [`ServerConfig`] from
//! operator-supplied PEM files, and [`plaintext_listener_allowed`] to enforce
//! the loopback-only plaintext guard (mirrors the ne-api TLS guard from
//! TLS integration).
//!
//! Uses the **ring** crypto provider (the workspace pins ring; aws-lc-rs is
//! musl-hostile and the release build targets musl).

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tokio_rustls::rustls::ServerConfig;

/// Errors from TLS material loading or the plaintext-guard check.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Plaintext ingress was requested on a non-loopback address in production.
    #[error("plaintext ingress refused on non-loopback bind in production")]
    PlaintextRefused,
    /// A PEM file could not be read from disk.
    #[error("read {path}: {source}")]
    Read {
        /// Path of the file that failed.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The certificate PEM file contained no certificates.
    #[error("no certificates in {0}")]
    NoCerts(String),
    /// The private-key PEM file contained no usable key.
    #[error("no private key in {0}")]
    NoKey(String),
    /// rustls rejected the cert/key combination.
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Refuse to serve plaintext ingress off-loopback.
///
/// Mirrors the ne-api TLS guard (S4-F1/S7-F3): loopback binds are always
/// allowed (local testing). A non-loopback plaintext bind exposes cleartext
/// ingress to the network and is refused even in dev mode, unless the operator
/// explicitly opts in with `NE_DEV_ALLOW_PUBLIC_BIND` — so a single
/// `NE_DEV_MODE` flag can no longer silently enable public plaintext.
pub fn plaintext_listener_allowed(bind: IpAddr, dev_mode: bool) -> Result<(), TlsError> {
    let dev_public_override = dev_mode && std::env::var_os("NE_DEV_ALLOW_PUBLIC_BIND").is_some();
    if bind.is_loopback() || dev_public_override {
        Ok(())
    } else {
        Err(TlsError::PlaintextRefused)
    }
}

/// Build a rustls `ServerConfig` from an operator cert + key (PEM files).
///
/// Uses the ring crypto provider explicitly via
/// `ServerConfig::builder_with_provider` so that this function is safe to
/// call from tests and library code without requiring a process-global
/// provider installation (contrast with the ne-api approach that uses
/// `install_default()`).
///
/// Validates:
/// - the cert PEM file is readable and contains ≥ 1 certificate
/// - the key PEM file is readable and contains a usable private key
///
/// Key↔cert correspondence is enforced by rustls inside
/// `with_single_cert`; we do not re-verify it here.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_pem = std::fs::read(cert_path).map_err(|source| TlsError::Read {
        path: cert_path.display().to_string(),
        source,
    })?;
    let key_pem = std::fs::read(key_path).map_err(|source| TlsError::Read {
        path: key_path.display().to_string(),
        source,
    })?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Read {
            path: cert_path.display().to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCerts(cert_path.display().to_string()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|source| TlsError::Read {
            path: key_path.display().to_string(),
            source,
        })?
        .ok_or_else(|| TlsError::NoKey(key_path.display().to_string()))?;

    // Use builder_with_provider to bind explicitly to ring, avoiding any
    // dependency on a process-global default provider being installed.
    let cfg =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Rustls)?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn plaintext_allowed_only_on_loopback() {
        // S7-F3: loopback is always allowed; a non-loopback plaintext bind is
        // refused in BOTH prod and dev (absent the explicit override env, which
        // this test environment does not set).
        // prod + non-loopback => refused
        assert!(plaintext_listener_allowed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), false).is_err());
        // prod + loopback => allowed
        assert!(plaintext_listener_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), false).is_ok());
        // dev + non-loopback => refused (no longer silently allowed by the flag)
        assert!(plaintext_listener_allowed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true).is_err());
        // dev + loopback => allowed
        assert!(plaintext_listener_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), true).is_ok());
    }

    #[test]
    fn load_server_config_rejects_missing_files() {
        let err = load_server_config(
            Path::new("/no/such/cert.pem"),
            Path::new("/no/such/key.pem"),
        );
        assert!(err.is_err());
    }

    #[test]
    fn load_server_config_accepts_a_generated_self_signed_pair() {
        // Generate an ephemeral cert+key with rcgen, write to temp files,
        // load them, and confirm a ServerConfig is produced.
        //
        // rcgen 0.13.x: `generate_simple_self_signed` returns
        // `CertifiedKey { cert, key_pair }`. Field is `key_pair` (NOT
        // `signing_key`), as confirmed from ne-api tls.rs.
        let cert = rcgen::generate_simple_self_signed(vec!["apps.example.com".to_string()])
            .expect("gen cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        let cfg = load_server_config(&cert_path, &key_path);
        assert!(cfg.is_ok(), "expected Ok, got {:?}", cfg.err());
    }
}

// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! NeuronEdge Enclave Runtime API daemon — gRPC mediation layer.
//!
//! This is the unprivileged front door SDK callers
//! reach. It validates requests, applies per-tenant rate limits
//! (in a later release), and relays the typed operation to
//! `ne-supervisor` over its NDJSON unix socket
//! (`SupervisorRequest` / `SupervisorResponse` in `ne_protocol`).
//!
//! Current API surface: `Ping`, `CreateWorkspace`, `DestroyWorkspace`,
//! `ExecuteCommand`, `WriteFile`, `ReadFile`, `ListEvents` — exposed
//! over both gRPC (`crate::server`) and REST/JSON (`crate::rest`),
//! sharing one transport-agnostic core (`crate::core`). Snapshots,
//! fork, attestation, and streaming (`ExecuteCommand` server-stream,
//! events SSE) are planned for a later compatible release.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod auth;
pub mod core;
/// Optional outbound HTTPS client for fleet coordination.
pub mod fleet_client;
pub mod rest;
pub mod server;
pub mod supervisor_client;
pub mod tls;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use ne_protocol::grpc::runtime::v1::runtime_server::RuntimeServer;
use tonic::transport::{Server, ServerTlsConfig};

use crate::auth::ApiKeyStore;
use crate::core::RuntimeCore;
use crate::fleet_client::{FleetClient, FleetClientConfig, run_fleet_loop};
use crate::server::RuntimeService;
use crate::tls::TlsConfig;

/// Transport-level message-size cap, aligned with the 10 MiB inline file
/// body limit (+1 MiB gRPC framing headroom). Tonic's 4 MiB default
/// would otherwise reject valid >4 MiB writes with `RESOURCE_EXHAUSTED`.
const TRANSPORT_MAX_MESSAGE_BYTES: usize = 11 * 1024 * 1024;

/// Build a tonic request interceptor that enforces API-key auth using
/// `store`. Returns `Status::unauthenticated` on missing/invalid keys.
/// Does NOT log the presented token.
///
/// `tonic::Status` is ~176 bytes so the large-err lint is suppressed here;
/// tonic interceptors are required to return `Result<_, Status>`.
#[allow(clippy::result_large_err)]
fn make_grpc_auth_interceptor(
    store: Arc<ApiKeyStore>,
) -> impl Fn(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> + Clone {
    move |req: tonic::Request<()>| {
        let ok = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(ApiKeyStore::bearer_from_str)
            .is_some_and(|t| store.verify(t).is_some());
        if ok {
            Ok(req)
        } else {
            Err(tonic::Status::unauthenticated("missing or invalid API key"))
        }
    }
}

/// Serve the gRPC and REST surfaces concurrently over a shared
/// [`RuntimeCore`]. Returns when either server exits.
///
/// `auth = Some(store)` installs the gRPC interceptor + REST middleware;
/// `None` serves both surfaces unauthenticated (dev mode only — `guard()`
/// has already decided this is acceptable). `tls = Some(_)` terminates TLS
/// on both listeners.
///
/// # Preconditions
/// When `tls = Some`, this installs the process-default rustls crypto
/// provider (ring) idempotently before building any server TLS config —
/// direct callers need not call `tls::install_crypto_provider` themselves.
pub async fn run(
    core: Arc<RuntimeCore>,
    grpc_bind: SocketAddr,
    rest_bind: SocketAddr,
    auth: Option<Arc<ApiKeyStore>>,
    tls: Option<TlsConfig>,
) -> anyhow::Result<()> {
    // run() is public; building a rustls server config (gRPC ServerTlsConfig /
    // axum-server RustlsConfig) requires a process-default crypto provider.
    // Install ring idempotently here so direct callers need not remember to.
    if tls.is_some() {
        tls::install_crypto_provider();
    }

    // Select the REST router once (auth is orthogonal to TLS).
    let router = auth.as_ref().map_or_else(
        || rest::router(Arc::clone(&core)),
        |store| rest::authed_router(Arc::clone(&core), Arc::clone(store)),
    );

    // Build per-transport TLS objects up front from the shared material.
    let grpc_tls = tls
        .as_ref()
        .map(|t| ServerTlsConfig::new().identity(t.tonic_identity()));
    let rest_tls = if let Some(t) = tls.as_ref() {
        Some(
            t.axum_rustls_config()
                .await
                .context("building REST TLS config")?,
        )
    } else {
        None
    };

    let grpc_fut = serve_grpc(Arc::clone(&core), grpc_bind, auth, grpc_tls);
    let rest_fut = serve_rest(router, rest_bind, rest_tls);
    tokio::try_join!(grpc_fut, rest_fut)?;
    Ok(())
}

/// Serve the gRPC surface. Owns its own auth×tls matrix.
async fn serve_grpc(
    core: Arc<RuntimeCore>,
    bind: SocketAddr,
    auth: Option<Arc<ApiKeyStore>>,
    tls: Option<ServerTlsConfig>,
) -> anyhow::Result<()> {
    let svc = RuntimeServer::new(RuntimeService::new(core))
        .max_decoding_message_size(TRANSPORT_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(TRANSPORT_MAX_MESSAGE_BYTES);

    let mut builder = Server::builder();
    if let Some(t) = tls {
        builder = builder.tls_config(t).context("applying gRPC TLS config")?;
    }

    let res = match auth {
        Some(store) => {
            let interceptor = make_grpc_auth_interceptor(store);
            builder
                .add_service(tonic::service::interceptor::InterceptedService::new(
                    svc,
                    interceptor,
                ))
                .serve(bind)
                .await
        }
        None => builder.add_service(svc).serve(bind).await,
    };
    res.context("gRPC server terminated with error")
}

/// Serve the REST surface. `tls = Some` uses axum-server's rustls binder;
/// `None` uses plaintext `axum::serve`.
async fn serve_rest(
    router: Router,
    bind: SocketAddr,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
) -> anyhow::Result<()> {
    if let Some(cfg) = tls {
        axum_server::bind_rustls(bind, cfg)
            .serve(router.into_make_service())
            .await
            .with_context(|| format!("REST (TLS) server on {bind} terminated with error"))
    } else {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("failed to bind REST listener on {bind}"))?;
        axum::serve(listener, router.into_make_service())
            .await
            .context("REST server terminated with error")
    }
}

/// Resolved configuration for the API front door. Built by the `nee`
/// CLI from flags/env and passed to [`serve`].
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Address the gRPC listener binds to.
    pub grpc_bind: SocketAddr,
    /// Address the REST/HTTP listener binds to.
    pub rest_bind: SocketAddr,
    /// Path to the supervisor NDJSON unix socket.
    pub supervisor_socket: PathBuf,
    /// When `true` the auth gate is bypassed for local development.
    pub dev_mode: bool,
    /// Loaded API keys. Empty is acceptable only in dev mode.
    pub api_keys: Arc<ApiKeyStore>,
    /// In-process TLS material. `None` = plaintext (allowed only in dev
    /// mode or on a loopback bind in production).
    pub tls: Option<TlsConfig>,
    /// Optional outbound fleet polling configuration.
    pub fleet: Option<FleetClientConfig>,
}

impl ApiConfig {
    /// Enforce start-up safety posture:
    /// - `dev_mode` → always OK, but emit a loud warning if keys are
    ///   configured (they are bypassed) or if none are configured.
    /// - `!dev_mode` + empty keys → bail (operator misconfiguration).
    /// - `!dev_mode` + keys + no TLS + non-loopback → bail.
    /// - `!dev_mode` + keys + no TLS + both loopback → warn and allow
    ///   (documented "terminate TLS at a local proxy" topology).
    /// - `!dev_mode` + keys + TLS → OK.
    pub fn guard(&self) -> anyhow::Result<()> {
        if self.dev_mode {
            // S4-F1: dev mode disables authentication, so a non-loopback bind
            // would expose an unauthenticated API to the network. Enforce the
            // documented "dev mode refuses non-localhost binds" invariant (which
            // the software-attestation prod-gate also claims to mirror). An
            // explicit operator override is available for intentional LAN dev.
            let grpc_lo = self.grpc_bind.ip().is_loopback();
            let rest_lo = self.rest_bind.ip().is_loopback();
            if (!grpc_lo || !rest_lo) && std::env::var_os("NE_DEV_ALLOW_PUBLIC_BIND").is_none() {
                anyhow::bail!(
                    "refusing to start: dev mode disables authentication and a non-loopback \
                     bind (grpc={}, rest={}) would expose an unauthenticated API to the network. \
                     Bind both listeners to loopback, or set NE_DEV_ALLOW_PUBLIC_BIND=1 to \
                     override for intentional LAN development.",
                    self.grpc_bind,
                    self.rest_bind
                );
            }
            if self.api_keys.is_empty() {
                tracing::warn!(
                    "dev mode: API authentication is DISABLED (localhost development only)"
                );
            } else {
                tracing::warn!("dev mode is set; API keys are configured but auth is BYPASSED");
            }
            return Ok(());
        }
        if self.api_keys.is_empty() {
            anyhow::bail!(
                "refusing to start: no API keys configured and --dev-mode not set. Provide \
                 --api-key-file with at least one key (see `nee api-key generate`), or pass \
                 --dev-mode for local development."
            );
        }
        // Production posture: require TLS unless BOTH listeners are loopback
        // (the documented "terminate TLS at a local proxy" topology, which
        // is not network-sniffable).
        if self.tls.is_none() {
            let grpc_lo = self.grpc_bind.ip().is_loopback();
            let rest_lo = self.rest_bind.ip().is_loopback();
            if grpc_lo && rest_lo {
                tracing::warn!(
                    "serving PLAINTEXT on loopback (no --tls-cert/--tls-key). Bearer tokens are \
                     in the clear on this host; terminate TLS at a local reverse proxy, or pass \
                     --tls-cert/--tls-key for in-process TLS."
                );
            } else {
                anyhow::bail!(
                    "refusing to start: no in-process TLS configured and a non-loopback bind is \
                     in use (grpc={}, rest={}). Either pass --tls-cert/--tls-key (see `nee tls \
                     generate-cert` for dev), or bind both listeners to loopback and front them \
                     with a TLS-terminating proxy.",
                    self.grpc_bind,
                    self.rest_bind
                );
            }
        }
        Ok(())
    }
}

/// Build the [`RuntimeCore`] and serve gRPC + REST. The caller is
/// responsible for initializing tracing.
pub async fn serve(cfg: ApiConfig) -> anyhow::Result<()> {
    use crate::supervisor_client::SupervisorClient;
    // `run()` installs the provider when tls.is_some(); mirror that here so
    // we don't pay even the Once overhead in plaintext deployments.
    if cfg.tls.is_some() {
        tls::install_crypto_provider();
    }
    cfg.guard()?;
    tracing::info!(
        grpc_bind = %cfg.grpc_bind,
        rest_bind = %cfg.rest_bind,
        supervisor = %cfg.supervisor_socket.display(),
        dev_mode = cfg.dev_mode,
        tls = cfg.tls.is_some(),
        "ne-api starting"
    );
    let supervisor = SupervisorClient::new(cfg.supervisor_socket);
    let core = Arc::new(RuntimeCore::new(supervisor.clone()));
    let auth = if cfg.dev_mode {
        None
    } else {
        Some(Arc::clone(&cfg.api_keys))
    };
    let fleet_task = cfg.fleet.map(|fleet| {
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let supervisor = supervisor.clone();
        let task = tokio::spawn(async move {
            if let Ok(client) = FleetClient::new(fleet) {
                run_fleet_loop(client, supervisor, receiver).await;
            } else {
                tracing::warn!(
                    event = "fleet_client_initialization_failed",
                    "fleet polling stopped"
                );
            }
        });
        (shutdown, task)
    });
    await_local_then_stop_fleet(
        run(core, cfg.grpc_bind, cfg.rest_bind, auth, cfg.tls),
        fleet_task,
    )
    .await
}

async fn await_local_then_stop_fleet<F>(
    local: F,
    fleet_task: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )>,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    await_local_then_stop_fleet_with_timeout(local, fleet_task, Duration::from_secs(1)).await
}

async fn await_local_then_stop_fleet_with_timeout<F>(
    local: F,
    fleet_task: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )>,
    shutdown_timeout: Duration,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let result = local.await;
    if let Some((shutdown, mut task)) = fleet_task {
        let _ = shutdown.send(true);
        if tokio::time::timeout(shutdown_timeout, &mut task)
            .await
            .is_err()
        {
            task.abort();
            tracing::warn!(
                event = "fleet_task_shutdown_timed_out",
                "fleet polling stopped"
            );
        }
    }
    result
}

#[cfg(test)]
mod serve_tests {
    use super::*;
    use std::time::Duration;

    fn empty_keys() -> Arc<ApiKeyStore> {
        Arc::new(ApiKeyStore::default())
    }

    fn keyed() -> Arc<ApiKeyStore> {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(
            &p,
            format!("sha256:{}\n", hex::encode(Sha256::digest(b"nee_x"))),
        )
        .unwrap();
        std::mem::forget(dir);
        Arc::new(ApiKeyStore::load(&p).unwrap())
    }

    #[test]
    fn guard_refuses_when_no_keys_and_not_dev_mode() {
        let cfg = ApiConfig {
            grpc_bind: "0.0.0.0:50051".parse().unwrap(),
            rest_bind: "0.0.0.0:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: false,
            api_keys: empty_keys(),
            tls: None,
            fleet: None,
        };
        let err = cfg.guard().expect_err("must reject");
        assert!(
            err.to_string().contains("no API keys configured"),
            "got: {err}"
        );
    }

    #[test]
    fn guard_accepts_dev_mode() {
        let cfg = ApiConfig {
            grpc_bind: "127.0.0.1:50051".parse().unwrap(),
            rest_bind: "127.0.0.1:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: true,
            api_keys: empty_keys(),
            tls: None,
            fleet: None,
        };
        cfg.guard().expect("dev mode passes");
    }

    #[test]
    fn guard_dev_mode_refuses_public_bind() {
        // S4-F1: dev mode disables auth, so a non-loopback bind must be refused
        // (absent the explicit NE_DEV_ALLOW_PUBLIC_BIND override, which this
        // test environment does not set).
        let cfg = ApiConfig {
            grpc_bind: "0.0.0.0:50051".parse().unwrap(),
            rest_bind: "0.0.0.0:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: true,
            api_keys: empty_keys(),
            tls: None,
            fleet: None,
        };
        let err = cfg
            .guard()
            .expect_err("dev mode + public bind must be refused");
        assert!(
            err.to_string().contains("dev mode disables authentication"),
            "got: {err}"
        );
    }

    #[test]
    fn guard_accepts_keys_without_dev_mode() {
        let cfg = ApiConfig {
            grpc_bind: "127.0.0.1:50051".parse().unwrap(),
            rest_bind: "127.0.0.1:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: false,
            api_keys: keyed(),
            tls: None,
            fleet: None,
        };
        // Keys + loopback + no TLS is the allowed "terminate TLS at a proxy"
        // posture: guard accepts (with a plaintext-on-loopback warning).
        cfg.guard().expect("keys present on loopback passes");
    }

    #[test]
    fn guard_refuses_non_loopback_plaintext_in_prod() {
        let cfg = ApiConfig {
            grpc_bind: "0.0.0.0:50051".parse().unwrap(),
            rest_bind: "0.0.0.0:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: false,
            api_keys: keyed(),
            tls: None,
            fleet: None,
        };
        let err = cfg
            .guard()
            .expect_err("non-loopback plaintext must be refused");
        assert!(err.to_string().contains("non-loopback bind"), "got: {err}");
    }

    #[test]
    fn guard_allows_loopback_plaintext_in_prod() {
        let cfg = ApiConfig {
            grpc_bind: "127.0.0.1:50051".parse().unwrap(),
            rest_bind: "127.0.0.1:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: false,
            api_keys: keyed(),
            tls: None,
            fleet: None,
        };
        cfg.guard()
            .expect("loopback plaintext is allowed (with a warning)");
    }

    #[test]
    fn guard_refuses_mixed_loopback_and_public_plaintext() {
        let cfg = ApiConfig {
            grpc_bind: "127.0.0.1:50051".parse().unwrap(),
            rest_bind: "0.0.0.0:8080".parse().unwrap(),
            supervisor_socket: "/run/ne-enclave/supervisor.sock".into(),
            dev_mode: false,
            api_keys: keyed(),
            tls: None,
            fleet: None,
        };
        let err = cfg
            .guard()
            .expect_err("mixed bind (one public) must be refused");
        assert!(err.to_string().contains("non-loopback bind"), "got: {err}");
    }

    #[tokio::test]
    async fn stalled_fleet_task_is_cancelled_before_local_result_returns() {
        let (shutdown, mut receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = receiver.changed() => {}
                () = std::future::pending() => {}
            }
        });

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            await_local_then_stop_fleet(async { Ok(()) }, Some((shutdown, task))),
        )
        .await
        .expect("fleet cancellation is bounded");

        result.expect("local result is retained");
    }

    #[tokio::test]
    async fn fleet_task_failure_does_not_replace_the_local_result() {
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            drop(receiver);
        });

        let err = await_local_then_stop_fleet(
            async { Err(anyhow::anyhow!("local server ended")) },
            Some((shutdown, task)),
        )
        .await
        .expect_err("local failure remains authoritative");

        assert_eq!(err.to_string(), "local server ended");
    }

    #[tokio::test]
    async fn uncooperative_fleet_task_hits_abort_timeout_without_changing_local_result() {
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            drop(receiver);
            std::future::pending::<()>().await;
        });
        let result = await_local_then_stop_fleet_with_timeout(
            async { Ok(()) },
            Some((shutdown, task)),
            Duration::from_millis(1),
        )
        .await;
        result.expect("local result");
    }
}

#[cfg(test)]
mod auth_interceptor_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tonic::Request;

    fn store(token: &str) -> Arc<ApiKeyStore> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(
            &p,
            format!("sha256:{}\n", hex::encode(Sha256::digest(token.as_bytes()))),
        )
        .unwrap();
        std::mem::forget(dir);
        Arc::new(ApiKeyStore::load(&p).unwrap())
    }

    #[test]
    fn interceptor_rejects_missing_and_accepts_valid() {
        let store = store("nee_good");
        let check = make_grpc_auth_interceptor(store);

        // missing metadata
        let req: Request<()> = Request::new(());
        assert!(check(req).is_err(), "missing metadata must be rejected");

        // bad token
        let mut req: Request<()> = Request::new(());
        req.metadata_mut()
            .insert("authorization", "Bearer nee_bad".parse().unwrap());
        assert!(check(req).is_err(), "bad token must be rejected");

        // valid token
        let mut req: Request<()> = Request::new(());
        req.metadata_mut()
            .insert("authorization", "Bearer nee_good".parse().unwrap());
        assert!(check(req).is_ok(), "valid token must pass");
    }
}

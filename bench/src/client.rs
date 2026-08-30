// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Thin gRPC client wrapper for benchmark operations.
//!
//! Wraps the generated `RuntimeClient` with timed create, exec, and
//! destroy operations, plus a readiness probe that retries a trivial
//! exec until the guest agent answers — the same poll a real SDK
//! client does (per the client contract).

use std::time::{Duration, Instant};

use ne_protocol::grpc::runtime::v1 as pb;
use ne_protocol::grpc::runtime::v1::runtime_client::RuntimeClient;
use tonic::transport::Channel;

/// Connected benchmark client.
pub struct BenchClient {
    inner: RuntimeClient<Channel>,
}

/// Parameters for creating a workspace under test.
#[derive(Debug, Clone)]
pub struct CreateParams {
    /// Caller-supplied workspace id.
    pub workspace_id: String,
    /// Managed guest kernel SHA-256 digest.
    pub kernel_sha256: String,
    /// Managed guest rootfs SHA-256 digest.
    pub rootfs_sha256: String,
    /// Guest vCPU count.
    pub vcpu_count: u32,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
    /// Guest vsock CID.
    pub guest_vsock_cid: u32,
}

/// Error from a benchmark client operation.
#[derive(Debug, thiserror::Error)]
pub enum BenchClientError {
    /// Transport-level connection failure.
    #[error("connect: {0}")]
    Connect(#[from] tonic::transport::Error),
    /// An RPC returned an error status.
    #[error("rpc: {0}")]
    Rpc(#[from] tonic::Status),
    /// Readiness was not reached within the deadline.
    #[error("workspace {0} not ready within {1:?}")]
    NotReady(String, Duration),
}

impl BenchClient {
    /// Connect to the runtime gRPC endpoint (e.g. `http://127.0.0.1:50051`).
    pub async fn connect(endpoint: String) -> Result<Self, BenchClientError> {
        let inner = RuntimeClient::connect(endpoint).await?;
        Ok(Self { inner })
    }

    /// Timed `CreateWorkspace`. Returns the elapsed launch latency.
    pub async fn create(&mut self, p: &CreateParams) -> Result<Duration, BenchClientError> {
        let req = pb::CreateWorkspaceRequest {
            workspace_id: p.workspace_id.clone(),
            kernel_sha256: p.kernel_sha256.clone(),
            rootfs_sha256: p.rootfs_sha256.clone(),
            rootfs_read_only: true,
            vcpu_count: p.vcpu_count,
            mem_size_mib: p.mem_size_mib,
            guest_vsock_cid: p.guest_vsock_cid,
            kernel_boot_args: None,
            network: None,
            tier: None,
        };
        let start = Instant::now();
        self.inner.create_workspace(req).await?;
        Ok(start.elapsed())
    }

    /// Run a single `/bin/true` exec; returns elapsed roundtrip on success.
    /// Used both as the exec benchmark op and as the readiness probe.
    pub async fn exec_true(&mut self, workspace_id: &str) -> Result<Duration, BenchClientError> {
        let req = pb::ExecuteCommandRequest {
            workspace_id: workspace_id.to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            timeout_ms: 10_000,
            guest_port: 0,
        };
        let start = Instant::now();
        self.inner.execute_command(req).await?;
        Ok(start.elapsed())
    }

    /// Poll `exec_true` until it succeeds or the deadline elapses.
    /// Returns elapsed time from `created_at` to first success (the
    /// readiness latency).
    ///
    /// The deadline is checked before each probe and after each failed
    /// probe. Because an in-flight `exec_true` carries its own RPC timeout
    /// (`timeout_ms`), a probe already running when the deadline passes can
    /// push total wall time up to that timeout beyond `deadline`; the
    /// returned `NotReady` reports the nominal `deadline`, not the overshoot.
    pub async fn wait_ready(
        &mut self,
        workspace_id: &str,
        created_at: Instant,
        deadline: Duration,
        poll_interval: Duration,
    ) -> Result<Duration, BenchClientError> {
        loop {
            if created_at.elapsed() >= deadline {
                return Err(BenchClientError::NotReady(
                    workspace_id.to_string(),
                    deadline,
                ));
            }
            if self.exec_true(workspace_id).await.is_ok() {
                return Ok(created_at.elapsed());
            }
            if created_at.elapsed() >= deadline {
                return Err(BenchClientError::NotReady(
                    workspace_id.to_string(),
                    deadline,
                ));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Timed `DestroyWorkspace`. Returns elapsed teardown latency.
    pub async fn destroy(&mut self, workspace_id: &str) -> Result<Duration, BenchClientError> {
        let req = pb::DestroyWorkspaceRequest {
            workspace_id: workspace_id.to_string(),
            grace_period_ms: 0,
        };
        let start = Instant::now();
        self.inner.destroy_workspace(req).await?;
        Ok(start.elapsed())
    }
}

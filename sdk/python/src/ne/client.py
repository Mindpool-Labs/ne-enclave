"""gRPC client wrapper for the NeuronEdge Enclave Runtime API.

Current scope: insecure channel (dev mode); mTLS / JWT / API
key arrive alongside the API daemon's auth surface. All
methods are synchronous; an async variant is a separate follow-up.
"""

from __future__ import annotations

from collections.abc import Iterable

import grpc

from ne.runtime.v1 import runtime_pb2, runtime_pb2_grpc


class Client:
    """Synchronous gRPC client for the NeuronEdge Enclave Runtime API.

    Construct with a `target` like ``"127.0.0.1:50051"``. Use as a
    context manager so the underlying channel is closed on exit:

        >>> with Client("127.0.0.1:50051") as c:
        ...     pong = c.ping()

    Each method returns the raw protobuf response message. Callers
    that want native Python types can access fields directly
    (``pong.supervisor_version``) — wrapping into dataclasses is a
    deliberate non-goal for the current implementation.
    """

    def __init__(
        self,
        target: str,
        *,
        channel_options: Iterable[tuple[str, object]] | None = None,
    ) -> None:
        self._channel = grpc.insecure_channel(target, options=list(channel_options or []))
        self._stub = runtime_pb2_grpc.RuntimeStub(self._channel)

    # ----- context manager ----------------------------------------

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying gRPC channel."""
        self._channel.close()

    # ----- gRPC methods -------------------------------------------

    def ping(self, *, timeout: float | None = None) -> runtime_pb2.PingResponse:
        """Liveness probe. Returns versions of both the API daemon and
        the supervisor it relayed to."""
        return self._stub.Ping(runtime_pb2.PingRequest(), timeout=timeout)

    def get_runtime_capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> runtime_pb2.GetRuntimeCapabilitiesResponse:
        """Return the runtime's resolved execution and attestation capabilities."""
        return self._stub.GetRuntimeCapabilities(
            runtime_pb2.GetRuntimeCapabilitiesRequest(),
            timeout=timeout,
        )

    def create_confidential_workspace(
        self,
        *,
        workspace_id: str,
        timeout: float | None = None,
    ) -> runtime_pb2.CreateWorkspaceResponse:
        """Launch one workspace through the confidential-azure profile.

        Confidential capacity belongs to the enclosing CVM, so the request
        intentionally carries empty image digests and zero runtime sizing
        fields.
        """
        return self._stub.CreateWorkspace(
            runtime_pb2.CreateWorkspaceRequest(
                workspace_id=workspace_id,
                kernel_sha256="",
                rootfs_sha256="",
                rootfs_read_only=True,
                vcpu_count=0,
                mem_size_mib=0,
                guest_vsock_cid=0,
            ),
            timeout=timeout,
        )

    def create_workspace(
        self,
        *,
        workspace_id: str,
        kernel_sha256: str | None = None,
        rootfs_sha256: str | None = None,
        vcpu_count: int,
        mem_size_mib: int,
        guest_vsock_cid: int,
        rootfs_read_only: bool = True,
        kernel_boot_args: str | None = None,
        tier: str | None = None,
        enable_network: bool = False,
        enable_egress: bool = False,
        allow_cidrs: Iterable[str] = (),
        allow_hostnames: Iterable[str] = (),
        enable_privacy_router: bool = False,
        exposed_ports: Iterable[int | tuple[int, list[tuple[str, str]]]] = (),
        timeout: float | None = None,
    ) -> runtime_pb2.CreateWorkspaceResponse:
        """Launch one Firecracker microVM workspace.

        `workspace_id` must satisfy jailer's grammar
        ``[a-zA-Z0-9-]{1,64}``. `vcpu_count` must be in 1..=255.
        ``kernel_sha256`` and ``rootfs_sha256`` identify artifacts in
        the supervisor-managed image store. Cold Firecracker creates
        require both as 64-character lowercase SHA-256 digests. Tier-
        or backend-managed creates may omit both; a half-pair is rejected
        locally while digest syntax remains a server-side contract.

        Network: pass ``enable_network=True`` to ask the supervisor
        to provision a per-workspace netns + veth + TAP. When
        ``enable_egress=True`` the supervisor additionally installs a
        MASQUERADE rule so the workspace can reach the outside world.
        ``allow_cidrs`` populates the per-workspace FORWARD chain;
        empty + ``enable_egress=True`` keeps the open-egress shape,
        while a non-empty list switches the workspace into
        deny-by-default mode (only the listed destinations are
        reachable, conntrack return traffic is always allowed).
        ``allow_hostnames`` populates the per-workspace DNS filter
        (suffix-match; ``openai.com`` allows ``api.openai.com``).
        Empty disables the DNS filter; non-empty switches the
        workspace into deny-by-default DNS — unlisted names return
        NXDOMAIN.
        ``enable_privacy_router=True`` opts the workspace into the
        host-side HTTP privacy router (PII scanning of TCP/80 egress
        bodies). The PII policy itself is operator-set on the
        supervisor today; a per-workspace policy override can be added
        in a later compatible extension. Requires the supervisor to have been started with
        ``--privacy-router-binary`` and ``--privacy-router-policy``.
        ``exposed_ports`` declares which guest ports the host-side
        ingress router should proxy inbound traffic to. Each element
        is either a bare ``int`` port number or a
        ``(port, [(header_name, header_value), ...])`` tuple that
        additionally injects HTTP headers into every proxied request.
        All network flags require the supervisor to have been
        started with ``--enable-networking``; without that the
        request still succeeds but the workspace runs without an
        eth0.
        """
        kernel_digest = kernel_sha256 or ""
        rootfs_digest = rootfs_sha256 or ""
        if bool(kernel_digest) != bool(rootfs_digest):
            raise ValueError("kernel_sha256 and rootfs_sha256 must be provided together")

        req = runtime_pb2.CreateWorkspaceRequest(
            workspace_id=workspace_id,
            kernel_sha256=kernel_digest,
            rootfs_sha256=rootfs_digest,
            rootfs_read_only=rootfs_read_only,
            vcpu_count=vcpu_count,
            mem_size_mib=mem_size_mib,
            guest_vsock_cid=guest_vsock_cid,
        )
        if kernel_boot_args is not None:
            req.kernel_boot_args = kernel_boot_args
        if tier is not None:
            req.tier = tier
        if enable_network:
            network = runtime_pb2.NetworkConfig(
                enable_egress=enable_egress,
                allow_cidrs=list(allow_cidrs),
                allow_hostnames=list(allow_hostnames),
            )
            if enable_privacy_router:
                network.privacy_router.SetInParent()
            for ep in exposed_ports:
                port, headers = (ep, []) if isinstance(ep, int) else ep
                ep_msg = network.exposed_ports.add()
                ep_msg.port = port
                for name, value in headers:
                    h = ep_msg.inject_headers.add()
                    h.name = name
                    h.value = value
            req.network.CopyFrom(network)
        return self._stub.CreateWorkspace(req, timeout=timeout)

    def execute_command(
        self,
        *,
        workspace_id: str,
        command: str,
        args: Iterable[str] = (),
        timeout_ms: int = 0,
        guest_port: int = 0,
        timeout: float | None = None,
    ) -> runtime_pb2.ExecuteCommandResponse:
        """Run one command inside a workspace.

        `timeout_ms` is the per-call guest-side timeout; `timeout` is
        the gRPC-level transport deadline (seconds).
        `guest_port` 0 → API daemon defaults to 52.
        """
        req = runtime_pb2.ExecuteCommandRequest(
            workspace_id=workspace_id,
            command=command,
            args=list(args),
            timeout_ms=timeout_ms,
            guest_port=guest_port,
        )
        return self._stub.ExecuteCommand(req, timeout=timeout)

    def write_file(
        self,
        *,
        workspace_id: str,
        path: str,
        content: bytes,
        guest_port: int = 0,
        timeout: float | None = None,
    ) -> runtime_pb2.WriteFileResponse:
        """Write `content` to `path` inside the workspace jail.

        ``path`` is relative; absolute paths and ``..`` segments are
        rejected by the guest agent and surface as
        ``grpc.RpcError(INVALID_ARGUMENT)``. ``content`` is raw bytes,
        capped at 10 MiB.
        """
        req = runtime_pb2.WriteFileRequest(
            workspace_id=workspace_id,
            path=path,
            content=content,
            guest_port=guest_port,
        )
        return self._stub.WriteFile(req, timeout=timeout)

    def read_file(
        self,
        *,
        workspace_id: str,
        path: str,
        max_bytes: int = 0,
        guest_port: int = 0,
        timeout: float | None = None,
    ) -> runtime_pb2.ReadFileResponse:
        """Read up to ``max_bytes`` bytes from ``path`` inside the
        workspace jail. ``max_bytes=0`` uses the server default
        (10 MiB). The ``truncated`` field on the response is True if
        the file is larger than the cap.
        """
        req = runtime_pb2.ReadFileRequest(
            workspace_id=workspace_id,
            path=path,
            max_bytes=max_bytes,
            guest_port=guest_port,
        )
        return self._stub.ReadFile(req, timeout=timeout)

    def destroy_workspace(
        self,
        *,
        workspace_id: str,
        grace_period_ms: int = 2_000,
        timeout: float | None = None,
    ) -> runtime_pb2.DestroyWorkspaceResponse:
        """Tear down a workspace and reclaim its host resources."""
        req = runtime_pb2.DestroyWorkspaceRequest(
            workspace_id=workspace_id,
            grace_period_ms=grace_period_ms,
        )
        return self._stub.DestroyWorkspace(req, timeout=timeout)

    def pause(
        self,
        *,
        workspace_id: str,
        timeout: float | None = None,
    ) -> runtime_pb2.PauseWorkspaceResponse:
        """Pause a running workspace (freeze vCPUs in place).

        The workspace must already exist and be in the running state.
        Use ``resume`` to unfreeze it afterwards.

        Deferred: unsupported on current Firecracker; the server returns an
        Unsupported error. Use snapshot/restore instead.
        """
        return self._stub.PauseWorkspace(
            runtime_pb2.PauseWorkspaceRequest(workspace_id=workspace_id),
            timeout=timeout,
        )

    def resume(
        self,
        *,
        workspace_id: str,
        timeout: float | None = None,
    ) -> runtime_pb2.ResumeWorkspaceResponse:
        """Resume a previously paused workspace.

        Deferred: unsupported on current Firecracker; the server returns an
        Unsupported error. Use snapshot/restore instead.
        """
        return self._stub.ResumeWorkspace(
            runtime_pb2.ResumeWorkspaceRequest(workspace_id=workspace_id),
            timeout=timeout,
        )

    def snapshot(
        self,
        *,
        workspace_id: str,
        live: bool = False,
        timeout: float | None = None,
    ) -> runtime_pb2.SnapshotWorkspaceResponse:
        """Snapshot a workspace into a reusable artifact.

        Returns a ``SnapshotWorkspaceResponse`` whose ``snapshot_id``
        (ULID) can be passed to ``restore`` to boot a new workspace
        from this image.

        When ``live=False`` (default) the workspace must be paused first.
        When ``live=True`` the source keeps running and stays reachable
        during the snapshot (the workspace must be in the running state);
        the response ``firecracker_pid`` field carries the source's new
        Firecracker PID after the live hot-swap completes. For non-live
        snapshots ``firecracker_pid`` is not set; use
        ``resp.HasField("firecracker_pid")`` to test presence rather than
        comparing against zero.
        """
        return self._stub.SnapshotWorkspace(
            runtime_pb2.SnapshotWorkspaceRequest(workspace_id=workspace_id, live=live),
            timeout=timeout,
        )

    def restore(
        self,
        *,
        snapshot_id: str,
        new_workspace_id: str,
        timeout: float | None = None,
    ) -> runtime_pb2.RestoreWorkspaceResponse:
        """Restore a fresh workspace from an existing snapshot artifact.

        ``snapshot_id`` is the ULID returned by a prior ``snapshot``
        call. ``new_workspace_id`` must satisfy the jailer's grammar
        ``[a-zA-Z0-9-]{1,64}`` and must not already exist.
        """
        return self._stub.RestoreWorkspace(
            runtime_pb2.RestoreWorkspaceRequest(
                snapshot_id=snapshot_id,
                new_workspace_id=new_workspace_id,
            ),
            timeout=timeout,
        )

    def fork(
        self,
        *,
        snapshot_id: str,
        new_workspace_id: str,
        hostname: str | None = None,
        timeout: float | None = None,
    ) -> runtime_pb2.ForkWorkspaceResponse:
        """Fork a fresh workspace from a snapshot, resetting its identity.

        ``snapshot_id`` is the ULID returned by a prior ``snapshot`` call.
        ``new_workspace_id`` must satisfy the jailer grammar
        ``[a-zA-Z0-9-]{1,64}`` and must not already exist. The new guest's
        hostname, machine-id, and RNG are reset so the fork is distinct
        from the source and any sibling fork; ``hostname`` defaults to
        ``new_workspace_id``. To fork N times, call this N times.
        """
        return self._stub.ForkWorkspace(
            runtime_pb2.ForkWorkspaceRequest(
                snapshot_id=snapshot_id,
                new_workspace_id=new_workspace_id,
                hostname=hostname or "",
            ),
            timeout=timeout,
        )

    def pool_status(
        self,
        *,
        timeout: float | None = None,
    ) -> runtime_pb2.GetPoolStatusResponse:
        """Query the warm-pool status for the configured tier (if any).

        Returns immediately from the pool manager's in-memory state; safe
        to call at high frequency for dashboard/health probes. When the
        pool manager is not configured, ``configured`` is False and the
        remaining fields are zero-valued.
        """
        return self._stub.GetPoolStatus(
            runtime_pb2.GetPoolStatusRequest(),
            timeout=timeout,
        )

    def expose_port(
        self,
        *,
        workspace_id: str,
        port: int,
        inject_headers: Iterable[tuple[str, str]] = (),
        timeout: float | None = None,
    ) -> runtime_pb2.ExposePortResponse:
        """Add (or update) a host-side ingress route for ``port`` on a
        running workspace.

        ``port`` is the guest TCP port to expose. ``inject_headers`` is
        an iterable of ``(name, value)`` pairs that the ingress router
        will inject into every HTTP request proxied to this port.
        Requires the supervisor to have been started with
        ``--enable-networking``.
        """
        req = runtime_pb2.ExposePortRequest(workspace_id=workspace_id)
        req.port.port = port
        for name, value in inject_headers:
            h = req.port.inject_headers.add()
            h.name = name
            h.value = value
        return self._stub.ExposePort(req, timeout=timeout)

    def unexpose_port(
        self,
        *,
        workspace_id: str,
        port: int,
        timeout: float | None = None,
    ) -> runtime_pb2.UnexposePortResponse:
        """Remove the host-side ingress route for ``port`` on a running
        workspace.

        ``port`` must correspond to a previously exposed guest TCP port.
        Requires the supervisor to have been started with
        ``--enable-networking``.
        """
        return self._stub.UnexposePort(
            runtime_pb2.UnexposePortRequest(workspace_id=workspace_id, port=port),
            timeout=timeout,
        )

    def get_attestation_evidence(
        self,
        *,
        workspace_id: str,
        nonce: bytes,
        timeout: float | None = None,
    ) -> runtime_pb2.GetAttestationEvidenceResponse:
        """Generate attestation evidence for a running workspace.

        ``nonce`` is the caller challenge (16..=64 bytes); it is bound
        into the returned evidence. The software-fallback provider signs
        the evidence with the runtime's Ed25519 identity key.
        """
        return self._stub.GetAttestationEvidence(
            runtime_pb2.GetAttestationEvidenceRequest(workspace_id=workspace_id, nonce=nonce),
            timeout=timeout,
        )

    def list_events(
        self,
        *,
        workspace_id: str | None = None,
        since_chain_index: int = 0,
        limit: int = 0,
        timeout: float | None = None,
    ) -> runtime_pb2.ListEventsResponse:
        """Read entries from the supervisor's signed audit event log.

        Each ``AuditEvent`` is signed with the supervisor's Ed25519
        key (``signature_b64``) and linked into a Merkle chain via
        ``prev_hash_hex``. Consumers that want tamper-evidence
        re-verify both before trusting an entry.

        ``limit=0`` is treated as 100 by the API daemon.
        """
        req = runtime_pb2.ListEventsRequest(
            since_chain_index=since_chain_index,
            limit=limit,
        )
        if workspace_id is not None:
            req.workspace_id = workspace_id
        return self._stub.ListEvents(req, timeout=timeout)

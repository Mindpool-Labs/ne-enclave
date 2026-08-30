"""Unit tests for the NeuronEdge Enclave Python SDK client.

Spawns a tiny in-process gRPC server that implements the Runtime
service with caller-supplied responses, then exercises the Client
against it. No external prerequisites — the same tests run on the
dev machine and in CI.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Iterator
from concurrent import futures
from pathlib import Path

import grpc
import pytest

from ne import Client
from ne.runtime.v1 import runtime_pb2, runtime_pb2_grpc

# --------------------------------------------------------------------
# Test scaffolding
# --------------------------------------------------------------------


class _FakeRuntime(runtime_pb2_grpc.RuntimeServicer):
    """Adjustable in-process RuntimeServicer.

    Each handler delegates to a stored callable so individual tests
    can dictate the response without subclassing.
    """

    def __init__(self) -> None:
        self.on_ping: Callable[[runtime_pb2.PingRequest], runtime_pb2.PingResponse] = lambda _: (
            runtime_pb2.PingResponse(
                api_version="0.0.0-fake-api",
                api_uptime_ms=11,
                supervisor_version="0.0.0-fake-sup",
                supervisor_uptime_ms=22,
            )
        )
        self.on_get_runtime_capabilities: Callable[
            [runtime_pb2.GetRuntimeCapabilitiesRequest],
            runtime_pb2.GetRuntimeCapabilitiesResponse,
        ] = lambda _: runtime_pb2.GetRuntimeCapabilitiesResponse(
            runtime_version="0.2.0",
            execution_profile=runtime_pb2.EXECUTION_PROFILE_STANDARD,
            execution_backend=runtime_pb2.EXECUTION_BACKEND_FIRECRACKER,
            attestation_backend=runtime_pb2.ATTESTATION_BACKEND_SOFTWARE,
            supported_operations=[runtime_pb2.WORKSPACE_OPERATION_CREATE],
            evidence_schema_version=1,
        )
        self.on_create: Callable[
            [runtime_pb2.CreateWorkspaceRequest], runtime_pb2.CreateWorkspaceResponse
        ] = lambda req: runtime_pb2.CreateWorkspaceResponse(
            workspace_id=req.workspace_id,
            firecracker_pid=4242,
            vsock_host_socket="/tmp/fake/vsock.sock",
            jailer_chroot="/tmp/fake/chroot",
        )
        self.on_execute: Callable[
            [runtime_pb2.ExecuteCommandRequest], runtime_pb2.ExecuteCommandResponse
        ] = lambda req: runtime_pb2.ExecuteCommandResponse(
            workspace_id=req.workspace_id,
            stdout=f"ran: {req.command} {' '.join(req.args)}\n",
            stderr="",
            exit_code=0,
            elapsed_ms=5,
        )
        self.on_destroy: Callable[
            [runtime_pb2.DestroyWorkspaceRequest], runtime_pb2.DestroyWorkspaceResponse
        ] = lambda req: runtime_pb2.DestroyWorkspaceResponse(workspace_id=req.workspace_id)
        self.on_list_events: Callable[
            [runtime_pb2.ListEventsRequest], runtime_pb2.ListEventsResponse
        ] = lambda _req: runtime_pb2.ListEventsResponse(
            events=[
                runtime_pb2.AuditEvent(
                    event_id="01HBQ",
                    timestamp_ms=1,
                    event_type="workspace_created",
                    payload_json="{}",
                    chain_index=0,
                    prev_hash_hex="0" * 64,
                    signature_b64="sig",
                    signer_pubkey_b64="key",
                )
            ]
        )
        self.on_write_file: Callable[[runtime_pb2.WriteFileRequest, object], runtime_pb2.WriteFileResponse] | None = None
        self.on_read_file: Callable[[runtime_pb2.ReadFileRequest, object], runtime_pb2.ReadFileResponse] | None = None
        self.on_pause: Callable[
            [runtime_pb2.PauseWorkspaceRequest], runtime_pb2.PauseWorkspaceResponse
        ] = lambda req: runtime_pb2.PauseWorkspaceResponse(workspace_id=req.workspace_id)
        self.on_resume: Callable[
            [runtime_pb2.ResumeWorkspaceRequest], runtime_pb2.ResumeWorkspaceResponse
        ] = lambda req: runtime_pb2.ResumeWorkspaceResponse(workspace_id=req.workspace_id)
        self.on_snapshot: Callable[
            [runtime_pb2.SnapshotWorkspaceRequest], runtime_pb2.SnapshotWorkspaceResponse
        ] = lambda req: runtime_pb2.SnapshotWorkspaceResponse(
            snapshot_id=f"snap-{req.workspace_id}",
            created_from_workspace_id=req.workspace_id,
            mem_sha256="a" * 64,
            vmstate_sha256="b" * 64,
            size_bytes=1024,
        )
        self.on_restore: Callable[
            [runtime_pb2.RestoreWorkspaceRequest], runtime_pb2.RestoreWorkspaceResponse
        ] = lambda req: runtime_pb2.RestoreWorkspaceResponse(
            workspace_id=req.new_workspace_id,
            firecracker_pid=4343,
            vsock_host_socket="/tmp/fake/restored.sock",
            jailer_chroot="/tmp/fake/restored-chroot",
        )
        self.on_fork: Callable[
            [runtime_pb2.ForkWorkspaceRequest], runtime_pb2.ForkWorkspaceResponse
        ] = lambda req: runtime_pb2.ForkWorkspaceResponse(
            workspace_id=req.new_workspace_id,
            firecracker_pid=4444,
            vsock_host_socket="/tmp/fake/forked.sock",
            jailer_chroot="/tmp/fake/forked-chroot",
            source_snapshot_id=req.snapshot_id,
            hostname=req.hostname or req.new_workspace_id,
            machine_id="0" * 32,
            guest_vsock_cid=3,
        )
        self.on_expose_port: Callable[
            [runtime_pb2.ExposePortRequest], runtime_pb2.ExposePortResponse
        ] = lambda req: runtime_pb2.ExposePortResponse(
            workspace_id=req.workspace_id,
            port=req.port.port,
        )
        self.on_unexpose_port: Callable[
            [runtime_pb2.UnexposePortRequest], runtime_pb2.UnexposePortResponse
        ] = lambda req: runtime_pb2.UnexposePortResponse(
            workspace_id=req.workspace_id,
            port=req.port,
        )
        self.on_get_attestation_evidence: Callable[
            [runtime_pb2.GetAttestationEvidenceRequest],
            runtime_pb2.GetAttestationEvidenceResponse,
        ] = lambda req: runtime_pb2.GetAttestationEvidenceResponse(
            evidence=runtime_pb2.AttestationEvidence(
                provider_type="software",
                workspace_id=req.workspace_id,
                measurement=b"\x00" * 32,
                nonce=req.nonce,
                issued_at=0,
                report_data=b"",
                proof=runtime_pb2.AttestationProof(
                    signature=b"\x00" * 64,
                    signer_pubkey=b"\x00" * 32,
                ),
            )
        )

    # gRPC method names follow proto naming (PascalCase).

    def Ping(self, request, context):
        return self.on_ping(request)

    def GetRuntimeCapabilities(self, request, context):
        return self.on_get_runtime_capabilities(request)

    def CreateWorkspace(self, request, context):
        return self.on_create(request)

    def ExecuteCommand(self, request, context):
        return self.on_execute(request)

    def DestroyWorkspace(self, request, context):
        return self.on_destroy(request)

    def ListEvents(self, request, context):
        return self.on_list_events(request)

    def WriteFile(self, request, context):
        if self.on_write_file is None:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, "no on_write_file handler")
        return self.on_write_file(request, context)

    def ReadFile(self, request, context):
        if self.on_read_file is None:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, "no on_read_file handler")
        return self.on_read_file(request, context)

    def PauseWorkspace(self, request, context):
        return self.on_pause(request)

    def ResumeWorkspace(self, request, context):
        return self.on_resume(request)

    def SnapshotWorkspace(self, request, context):
        return self.on_snapshot(request)

    def RestoreWorkspace(self, request, context):
        return self.on_restore(request)

    def ForkWorkspace(self, request, context):
        return self.on_fork(request)

    def ExposePort(self, request, context):
        return self.on_expose_port(request)

    def UnexposePort(self, request, context):
        return self.on_unexpose_port(request)

    def GetAttestationEvidence(self, request, context):
        return self.on_get_attestation_evidence(request)


@pytest.fixture
def fake_server() -> Iterator[tuple[_FakeRuntime, str]]:
    """Yields (servicer, "127.0.0.1:<port>") for a running in-process
    Runtime service. Stops the server in teardown."""
    servicer = _FakeRuntime()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    runtime_pb2_grpc.add_RuntimeServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        yield servicer, f"127.0.0.1:{port}"
    finally:
        server.stop(grace=0)


# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------


def test_ping_round_trips(fake_server) -> None:
    _, target = fake_server
    with Client(target) as client:
        pong = client.ping()
    assert pong.api_version == "0.0.0-fake-api"
    assert pong.supervisor_version == "0.0.0-fake-sup"
    assert pong.supervisor_uptime_ms == 22


def test_get_runtime_capabilities_returns_resolved_profile(fake_server) -> None:
    servicer, target = fake_server
    servicer.on_get_runtime_capabilities = lambda _: runtime_pb2.GetRuntimeCapabilitiesResponse(
        runtime_version="0.2.0",
        execution_profile=runtime_pb2.EXECUTION_PROFILE_CONFIDENTIAL_AZURE,
        execution_backend=runtime_pb2.EXECUTION_BACKEND_OPEN_SHELL,
        attestation_backend=runtime_pb2.ATTESTATION_BACKEND_SEV_SNP_AZURE,
        supported_operations=[
            runtime_pb2.WORKSPACE_OPERATION_CREATE,
            runtime_pb2.WORKSPACE_OPERATION_ATTEST,
        ],
        hard_workspace_capacity=1,
        evidence_schema_version=1,
    )

    with Client(target) as client:
        capabilities = client.get_runtime_capabilities()

    assert capabilities.execution_profile == runtime_pb2.EXECUTION_PROFILE_CONFIDENTIAL_AZURE
    assert capabilities.hard_workspace_capacity == 1
    assert capabilities.evidence_schema_version == 1


def test_create_workspace_passes_fields_through(fake_server) -> None:
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(
            workspace_id=req.workspace_id,
            firecracker_pid=99,
            vsock_host_socket="/x",
            jailer_chroot="/y",
        )

    servicer.on_create = capture
    with Client(target) as client:
        resp = client.create_workspace(
            workspace_id="wks-py-1",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=2,
            mem_size_mib=512,
            guest_vsock_cid=3,
            kernel_boot_args="console=ttyS0",
        )

    sent = seen["req"]
    assert sent.workspace_id == "wks-py-1"
    assert sent.kernel_sha256 == "11" * 32
    assert sent.rootfs_sha256 == "22" * 32
    assert sent.vcpu_count == 2
    assert sent.mem_size_mib == 512
    assert sent.guest_vsock_cid == 3
    assert sent.kernel_boot_args == "console=ttyS0"
    assert sent.rootfs_read_only is True  # SDK default
    assert resp.workspace_id == "wks-py-1"
    assert resp.firecracker_pid == 99


def test_create_confidential_workspace_sends_profile_neutral_zero_fields(fake_server) -> None:
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        response = client.create_confidential_workspace(workspace_id="secret-1")

    sent = seen["req"]
    assert sent.workspace_id == "secret-1"
    assert sent.kernel_sha256 == ""
    assert sent.rootfs_sha256 == ""
    assert sent.rootfs_read_only is True
    assert sent.vcpu_count == 0
    assert sent.mem_size_mib == 0
    assert sent.guest_vsock_cid == 0
    assert response.workspace_id == "secret-1"


def test_create_workspace_tier_omits_managed_image_digests(fake_server) -> None:
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-tier",
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            tier="warm-small",
        )

    sent = seen["req"]
    assert sent.kernel_sha256 == ""
    assert sent.rootfs_sha256 == ""
    assert sent.tier == "warm-small"


@pytest.mark.parametrize(
    "digest_kwargs",
    [
        {"kernel_sha256": "11" * 32},
        {"rootfs_sha256": "22" * 32},
    ],
)
def test_create_workspace_rejects_half_digest_pair(fake_server, digest_kwargs) -> None:
    _, target = fake_server
    with Client(target) as client, pytest.raises(ValueError, match="provided together"):
        client.create_workspace(
            workspace_id="wks-py-half",
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            tier="warm-small",
            **digest_kwargs,
        )


def test_create_workspace_exposes_only_digest_image_parameters() -> None:
    parameters = inspect.signature(Client.create_workspace).parameters
    assert "kernel_sha256" in parameters
    assert "rootfs_sha256" in parameters
    assert "kernel_" + "image_path" not in parameters
    assert "rootfs_" + "image_path" not in parameters


def test_declared_runtime_floors_support_generated_stubs() -> None:
    def numeric_version(value: str) -> tuple[int, ...]:
        return tuple(int(part) for part in value.split("."))

    sdk_root = Path(__file__).parents[1]
    pyproject = (sdk_root / "pyproject.toml").read_text()
    protobuf_source = (sdk_root / "src/ne/runtime/v1/runtime_pb2.py").read_text()

    grpc_bounds = re.search(r'"grpcio >=([^,]+),<([^"]+)', pyproject)
    protobuf_bounds = re.search(r'"protobuf >=([^,]+),<([^"]+)', pyproject)
    codegen_bounds = re.search(r'"grpcio-tools >=([^,]+),<([^"]+)', pyproject)
    generated_protobuf = re.search(r"# Protobuf Python Version: ([^\n]+)", protobuf_source)

    assert grpc_bounds is not None
    assert protobuf_bounds is not None
    assert codegen_bounds is not None
    assert generated_protobuf is not None
    generated_grpc = numeric_version(runtime_pb2_grpc.GRPC_GENERATED_VERSION)
    generated_pb = numeric_version(generated_protobuf.group(1))
    grpc_floor, grpc_ceiling = map(numeric_version, grpc_bounds.groups())
    protobuf_floor, protobuf_ceiling = map(numeric_version, protobuf_bounds.groups())
    codegen_floor, codegen_ceiling = map(numeric_version, codegen_bounds.groups())

    assert grpc_floor >= generated_grpc
    assert grpc_ceiling > generated_grpc
    assert protobuf_floor >= generated_pb
    assert protobuf_ceiling > generated_pb
    assert codegen_floor >= generated_grpc
    assert codegen_floor == grpc_floor
    assert codegen_ceiling == grpc_ceiling


@pytest.mark.parametrize(
    ("status", "details"),
    [
        (grpc.StatusCode.NOT_FOUND, "kernel image not found"),
        (grpc.StatusCode.FAILED_PRECONDITION, "rootfs image digest mismatch"),
        (grpc.StatusCode.INTERNAL, "rootfs image staging failed"),
    ],
)
def test_create_workspace_preserves_image_error_status_and_details(status, details) -> None:
    class _ImageErrorRuntime(runtime_pb2_grpc.RuntimeServicer):
        def CreateWorkspace(self, request, context):
            context.abort(status, details)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    runtime_pb2_grpc.add_RuntimeServicer_to_server(_ImageErrorRuntime(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        with Client(f"127.0.0.1:{port}") as client, pytest.raises(grpc.RpcError) as exc:
            client.create_workspace(
                workspace_id="wks-image-error",
                kernel_sha256="11" * 32,
                rootfs_sha256="22" * 32,
                vcpu_count=1,
                mem_size_mib=256,
                guest_vsock_cid=3,
            )
        assert exc.value.code() == status
        assert exc.value.details() == details
    finally:
        server.stop(grace=0)


def test_create_workspace_with_network_round_trips(fake_server) -> None:
    """`enable_network=True, enable_egress=True` must populate the
    nested `NetworkConfig`; the populated `WorkspaceNetwork` on the
    response must surface back to the caller."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(
            workspace_id=req.workspace_id,
            firecracker_pid=9001,
            vsock_host_socket="/x",
            jailer_chroot="/y",
            network=runtime_pb2.WorkspaceNetwork(
                netns_path="/var/run/netns/ne-feedfa",
                tap_device="tap-feedfa",
                host_ip="169.254.42.1",
                guest_ip="169.254.42.2",
                prefix=30,
            ),
        )

    servicer.on_create = capture
    with Client(target) as client:
        resp = client.create_workspace(
            workspace_id="wks-py-net",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
            enable_egress=True,
        )

    sent = seen["req"]
    assert sent.HasField("network")
    assert sent.network.enable_egress is True
    assert resp.HasField("network")
    assert resp.network.tap_device == "tap-feedfa"
    assert resp.network.guest_ip == "169.254.42.2"
    assert resp.network.prefix == 30


def test_create_workspace_passes_allow_hostnames(fake_server) -> None:
    """Hostname allowlist must reach the supervisor verbatim and in
    declared order — the DNS filter binary uses the order for
    deterministic logging."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-dns",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
            allow_hostnames=["openai.com", "*.github.com", "api.anthropic.com"],
        )
    sent = seen["req"]
    assert sent.HasField("network")
    assert list(sent.network.allow_hostnames) == [
        "openai.com",
        "*.github.com",
        "api.anthropic.com",
    ]


def test_create_workspace_passes_allow_cidrs(fake_server) -> None:
    """Deny-by-default mode: a populated allow_cidrs list must
    reach the supervisor verbatim and in declared order."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-allow",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
            enable_egress=True,
            allow_cidrs=["10.0.0.0/8", "203.0.113.0/24"],
        )
    sent = seen["req"]
    assert sent.HasField("network")
    assert sent.network.enable_egress is True
    assert list(sent.network.allow_cidrs) == ["10.0.0.0/8", "203.0.113.0/24"]


def test_create_workspace_opts_into_privacy_router(fake_server) -> None:
    """``enable_privacy_router=True`` must surface as a populated
    ``privacy_router`` nested message — the supervisor branches on
    field presence to decide whether to spawn the per-workspace
    router. The message is empty today; future fields can be added
    additively without an SDK migration."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-privacy",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
            enable_egress=True,
            enable_privacy_router=True,
        )
    sent = seen["req"]
    assert sent.HasField("network")
    assert sent.network.HasField("privacy_router")


def test_create_workspace_without_privacy_router_omits_field(fake_server) -> None:
    """Default ``enable_privacy_router=False`` must NOT populate the
    nested ``privacy_router`` field; presence is the opt-in signal."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-no-privacy",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
        )
    sent = seen["req"]
    assert sent.HasField("network")
    assert not sent.network.HasField("privacy_router")


def test_create_workspace_without_network_omits_field(fake_server) -> None:
    """Default call must NOT populate the optional `network` field —
    the supervisor branches on field presence."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-py-no-net",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
        )
    assert not seen["req"].HasField("network")


def test_execute_command_round_trips(fake_server) -> None:
    _, target = fake_server
    with Client(target) as client:
        result = client.execute_command(
            workspace_id="wks-py-2",
            command="/bin/echo",
            args=["hello", "enclave"],
            timeout_ms=5_000,
        )
    assert result.exit_code == 0
    assert "hello enclave" in result.stdout


def test_write_file_round_trips(fake_server) -> None:
    """``write_file`` must round-trip path, content, and guest_port,
    and surface the response's ``bytes_written`` and ``absolute_path``."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.WriteFileRequest, _context) -> runtime_pb2.WriteFileResponse:
        seen["req"] = req
        return runtime_pb2.WriteFileResponse(
            workspace_id=req.workspace_id,
            bytes_written=len(req.content),
            absolute_path=f"/workspace/{req.path}",
        )

    servicer.on_write_file = capture
    with Client(target) as client:
        resp = client.write_file(
            workspace_id="wks-w-1",
            path="src/main.rs",
            content=b"fn main() {}",
        )
    assert seen["req"].path == "src/main.rs"
    assert seen["req"].content == b"fn main() {}"
    assert resp.bytes_written == 12
    assert resp.absolute_path == "/workspace/src/main.rs"


def test_read_file_round_trips(fake_server) -> None:
    """``read_file`` must round-trip the workspace_id and path and
    surface content / size_bytes / truncated from the response."""
    servicer, target = fake_server

    def reply(req: runtime_pb2.ReadFileRequest, _context) -> runtime_pb2.ReadFileResponse:
        return runtime_pb2.ReadFileResponse(
            workspace_id=req.workspace_id,
            content=b"hello there",
            size_bytes=11,
            truncated=False,
        )

    servicer.on_read_file = reply
    with Client(target) as client:
        resp = client.read_file(workspace_id="wks-r-1", path="hello.txt")
    assert resp.content == b"hello there"
    assert resp.size_bytes == 11
    assert resp.truncated is False


def test_write_file_path_rejection_raises_invalid_argument(fake_server) -> None:
    """A `path_rejected` supervisor error must surface as
    ``RpcError(INVALID_ARGUMENT)`` to SDK callers."""
    servicer, target = fake_server

    def deny(_req, context):
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "path contains '..' segment")

    servicer.on_write_file = deny
    with Client(target) as client, pytest.raises(grpc.RpcError) as exc:
        client.write_file(workspace_id="wks-bad", path="../etc/passwd", content=b"x")
    assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT


def test_read_file_not_found_raises_not_found(fake_server) -> None:
    """A `file_not_found` supervisor error must surface as
    ``RpcError(NOT_FOUND)``."""
    servicer, target = fake_server

    def deny(_req, context):
        context.abort(grpc.StatusCode.NOT_FOUND, "no such file")

    servicer.on_read_file = deny
    with Client(target) as client, pytest.raises(grpc.RpcError) as exc:
        client.read_file(workspace_id="wks-miss", path="nope.txt")
    assert exc.value.code() == grpc.StatusCode.NOT_FOUND


def test_read_file_truncated_flag_round_trips(fake_server) -> None:
    """A truncated read must surface ``truncated=True`` and
    ``size_bytes`` separate from ``content`` length."""
    servicer, target = fake_server

    def reply(req: runtime_pb2.ReadFileRequest, _context) -> runtime_pb2.ReadFileResponse:
        return runtime_pb2.ReadFileResponse(
            workspace_id=req.workspace_id,
            content=b"x" * 1024,
            size_bytes=4096,
            truncated=True,
        )

    servicer.on_read_file = reply
    with Client(target) as client:
        resp = client.read_file(workspace_id="wks-big", path="big.bin", max_bytes=1024)
    assert len(resp.content) == 1024
    assert resp.size_bytes == 4096
    assert resp.truncated is True


def test_write_file_default_guest_port_is_zero_in_request(fake_server) -> None:
    """The SDK must not impose 52 itself — the server picks the
    default. Pinning this so the conversion never sneaks into the
    client."""
    servicer, target = fake_server

    def capture(req: runtime_pb2.WriteFileRequest, _context) -> runtime_pb2.WriteFileResponse:
        assert req.guest_port == 0
        return runtime_pb2.WriteFileResponse(
            workspace_id=req.workspace_id,
            bytes_written=len(req.content),
            absolute_path=f"/workspace/{req.path}",
        )

    servicer.on_write_file = capture
    with Client(target) as client:
        client.write_file(workspace_id="wks-port", path="a.txt", content=b"x")


def test_list_events_returns_signed_envelope(fake_server) -> None:
    _, target = fake_server
    with Client(target) as client:
        resp = client.list_events(workspace_id="wks-py-3", since_chain_index=0, limit=10)
    assert len(resp.events) == 1
    e = resp.events[0]
    assert e.event_type == "workspace_created"
    assert e.signature_b64 != ""
    assert e.signer_pubkey_b64 != ""
    assert e.prev_hash_hex == "0" * 64


def test_destroy_workspace_echoes_id(fake_server) -> None:
    _, target = fake_server
    with Client(target) as client:
        resp = client.destroy_workspace(workspace_id="wks-py-3", grace_period_ms=1_000)
    assert resp.workspace_id == "wks-py-3"


def test_pause_resume_snapshot_restore(fake_server) -> None:
    """pause/resume/snapshot/restore must round-trip through the fake
    server and return the correct identifiers."""
    _fake, addr = fake_server
    with Client(addr) as c:
        assert c.pause(workspace_id="ws-a").workspace_id == "ws-a"
        assert c.resume(workspace_id="ws-a").workspace_id == "ws-a"
        snap = c.snapshot(workspace_id="ws-a")
        assert snap.snapshot_id  # non-empty
        restored = c.restore(snapshot_id=snap.snapshot_id, new_workspace_id="ws-b")
        assert restored.workspace_id == "ws-b"


def test_fork_relays_request_and_returns_identity(fake_server) -> None:
    """fork() must relay all three request fields to the server and
    surface the response's workspace_id, hostname, and guest_vsock_cid."""
    servicer, target = fake_server
    captured: dict[str, str] = {}

    def fork_handler(request: runtime_pb2.ForkWorkspaceRequest) -> runtime_pb2.ForkWorkspaceResponse:
        captured["snapshot_id"] = request.snapshot_id
        captured["new_workspace_id"] = request.new_workspace_id
        captured["hostname"] = request.hostname
        return runtime_pb2.ForkWorkspaceResponse(
            workspace_id=request.new_workspace_id,
            firecracker_pid=99,
            vsock_host_socket="/x/vsock.sock",
            jailer_chroot="/x",
            source_snapshot_id=request.snapshot_id,
            hostname=request.hostname or "default",
            machine_id="0123456789abcdef0123456789abcdef",
            guest_vsock_cid=3,
        )

    servicer.on_fork = fork_handler
    with Client(target) as client:
        resp = client.fork(snapshot_id="01J0SNAP", new_workspace_id="fork-a", hostname="fork-a")

    assert captured["snapshot_id"] == "01J0SNAP"
    assert captured["new_workspace_id"] == "fork-a"
    assert captured["hostname"] == "fork-a"
    assert resp.workspace_id == "fork-a"
    assert resp.hostname == "fork-a"
    assert resp.guest_vsock_cid == 3


def test_create_workspace_exposed_ports_round_trips(fake_server) -> None:
    """``exposed_ports`` tuples must populate ``network.exposed_ports``
    with correct port numbers, header names, and header values. Plain
    ``int`` entries must produce an ``ExposedPort`` with no headers."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.CreateWorkspaceRequest) -> runtime_pb2.CreateWorkspaceResponse:
        seen["req"] = req
        return runtime_pb2.CreateWorkspaceResponse(workspace_id=req.workspace_id)

    servicer.on_create = capture
    with Client(target) as client:
        client.create_workspace(
            workspace_id="wks-ep",
            kernel_sha256="11" * 32,
            rootfs_sha256="22" * 32,
            vcpu_count=1,
            mem_size_mib=256,
            guest_vsock_cid=3,
            enable_network=True,
            exposed_ports=[
                8080,
                (3000, [("X-Forwarded-Proto", "https"), ("X-Real-IP", "1.2.3.4")]),
            ],
        )

    sent = seen["req"]
    assert sent.HasField("network")
    ports = list(sent.network.exposed_ports)
    assert len(ports) == 2
    assert ports[0].port == 8080
    assert len(ports[0].inject_headers) == 0
    assert ports[1].port == 3000
    hdrs = list(ports[1].inject_headers)
    assert len(hdrs) == 2
    assert hdrs[0].name == "X-Forwarded-Proto"
    assert hdrs[0].value == "https"
    assert hdrs[1].name == "X-Real-IP"
    assert hdrs[1].value == "1.2.3.4"


def test_expose_port_round_trips(fake_server) -> None:
    """``expose_port`` must send workspace_id, port number, and
    inject_headers to the server and surface the echoed response."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.ExposePortRequest) -> runtime_pb2.ExposePortResponse:
        seen["req"] = req
        return runtime_pb2.ExposePortResponse(workspace_id=req.workspace_id, port=req.port.port)

    servicer.on_expose_port = capture
    with Client(target) as client:
        resp = client.expose_port(
            workspace_id="wks-ep-1",
            port=8080,
            inject_headers=[("X-Forwarded-Proto", "https")],
        )

    sent = seen["req"]
    assert sent.workspace_id == "wks-ep-1"
    assert sent.port.port == 8080
    assert len(sent.port.inject_headers) == 1
    assert sent.port.inject_headers[0].name == "X-Forwarded-Proto"
    assert sent.port.inject_headers[0].value == "https"
    assert resp.workspace_id == "wks-ep-1"
    assert resp.port == 8080


def test_unexpose_port_round_trips(fake_server) -> None:
    """``unexpose_port`` must send workspace_id and port number and
    surface the echoed response."""
    servicer, target = fake_server
    seen = {}

    def capture(req: runtime_pb2.UnexposePortRequest) -> runtime_pb2.UnexposePortResponse:
        seen["req"] = req
        return runtime_pb2.UnexposePortResponse(workspace_id=req.workspace_id, port=req.port)

    servicer.on_unexpose_port = capture
    with Client(target) as client:
        resp = client.unexpose_port(workspace_id="wks-ep-1", port=8080)

    assert seen["req"].workspace_id == "wks-ep-1"
    assert seen["req"].port == 8080
    assert resp.workspace_id == "wks-ep-1"
    assert resp.port == 8080


def test_get_attestation_evidence_round_trips(fake_server) -> None:
    servicer, target = fake_server
    seen = {}

    def capture(req):
        seen["req"] = req
        return runtime_pb2.GetAttestationEvidenceResponse(
            evidence=runtime_pb2.AttestationEvidence(
                provider_type="software",
                workspace_id=req.workspace_id,
                measurement=b"\x07" * 32,
                nonce=req.nonce,
                issued_at=1,
                report_data=b"rd",
                proof=runtime_pb2.AttestationProof(signature=b"\x01" * 64, signer_pubkey=b"\x02" * 32),
            )
        )

    servicer.on_get_attestation_evidence = capture
    with Client(target) as client:
        resp = client.get_attestation_evidence(workspace_id="ws-att", nonce=b"\x09" * 16)

    assert seen["req"].workspace_id == "ws-att"
    assert seen["req"].nonce == b"\x09" * 16
    assert resp.evidence.provider_type == "software"
    assert resp.evidence.workspace_id == "ws-att"
    assert len(resp.evidence.measurement) == 32


def test_get_attestation_evidence_preserves_all_azure_typed_proof_fields(fake_server) -> None:
    servicer, target = fake_server

    def capture(req):
        return runtime_pb2.GetAttestationEvidenceResponse(
            public_evidence=runtime_pb2.PublicAttestationEvidence(
                schema_version=1,
                provider=runtime_pb2.ATTESTATION_PROVIDER_SEV_SNP_AZURE,
                workspace_id=req.workspace_id,
                workspace_measurement=b"\x01" * 32,
                nonce=req.nonce,
                issued_at=1,
                report_data=b"\x02",
                sev_snp_azure=runtime_pb2.SevSnpAzureProof(
                    report=b"\x03",
                    vcek_cert_chain=b"\x04",
                    var_data=b"\x05",
                    ak_pub_tpm2b=b"\x06",
                    quote_msg=b"\x07",
                    quote_sig=b"\x08",
                ),
            )
        )

    servicer.on_get_attestation_evidence = capture
    with Client(target) as client:
        response = client.get_attestation_evidence(
            workspace_id="ws-azure",
            nonce=b"\x09" * 16,
        )

    evidence = response.public_evidence
    assert evidence.provider == runtime_pb2.ATTESTATION_PROVIDER_SEV_SNP_AZURE
    assert evidence.WhichOneof("proof") == "sev_snp_azure"
    assert evidence.sev_snp_azure.report == b"\x03"
    assert evidence.sev_snp_azure.vcek_cert_chain == b"\x04"
    assert evidence.sev_snp_azure.var_data == b"\x05"
    assert evidence.sev_snp_azure.ak_pub_tpm2b == b"\x06"
    assert evidence.sev_snp_azure.quote_msg == b"\x07"
    assert evidence.sev_snp_azure.quote_sig == b"\x08"


def test_client_surfaces_grpc_status_as_rpcerror() -> None:
    """Stand up a fresh servicer subclass that aborts the
    DestroyWorkspace handler with NotFound. Verifies the Python
    SDK surfaces gRPC Status codes as `grpc.RpcError` (the standard
    pattern callers branch on)."""

    class _NotFoundRuntime(runtime_pb2_grpc.RuntimeServicer):
        def DestroyWorkspace(self, request, context):
            context.abort(grpc.StatusCode.NOT_FOUND, "no such workspace")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    runtime_pb2_grpc.add_RuntimeServicer_to_server(_NotFoundRuntime(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        with Client(f"127.0.0.1:{port}") as client, pytest.raises(grpc.RpcError) as exc_info:
            client.destroy_workspace(workspace_id="wks-ghost")
        assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND
    finally:
        server.stop(grace=0)

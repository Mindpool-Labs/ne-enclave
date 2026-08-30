# NeuronEdge Enclave Python SDK

Python client for the NeuronEdge Enclave Runtime API (gRPC). Current surface:
`Ping`, `CreateWorkspace`, `ExecuteCommand`, `DestroyWorkspace`.

## Install

```sh
cd sdk/python
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Use

```python
from ne import Client

with Client("127.0.0.1:50051") as client:
    pong = client.ping()
    print(pong.api_version, pong.supervisor_version)

    created = client.create_workspace(
        workspace_id="wks-demo-1",
        kernel_sha256="11" * 32,
        rootfs_sha256="22" * 32,
        vcpu_count=1,
        mem_size_mib=256,
        guest_vsock_cid=3,
    )

    result = client.execute_command(
        workspace_id="wks-demo-1",
        command="/bin/echo",
        args=["hello, enclave"],
        timeout_ms=5_000,
    )
    print(result.stdout)

    client.destroy_workspace(workspace_id="wks-demo-1", grace_period_ms=2_000)
```

The two SHA-256 values identify artifacts already installed in the
supervisor-managed image store. They must be 64-character lowercase hex
digests for a cold Firecracker create; callers cannot provide host paths.

## Regenerating protobuf stubs

The generated `src/ne/runtime/v1/runtime_pb2*.py` files are committed
under source control. Regenerate after editing `proto/ne/runtime/v1/runtime.proto`:

```sh
./scripts/codegen.sh
```

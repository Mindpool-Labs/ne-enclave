# neuronedge-enclave-langchain

A LangChain adapter for the [NeuronEdge Enclave](https://neuronedge.ai) Runtime API. Gives an LLM agent a managed, confidential Firecracker microVM sandbox: run shell commands and move files in/out.

> **Development mode.** The base `neuronedge-enclave` SDK opens an insecure gRPC channel. Use this adapter against a local `nee` daemon until TLS + API-key client credentials ship.

## Install

```bash
pip install neuronedge-enclave-langchain
```

## Quickstart

```python
from langchain_openai import ChatOpenAI
from ne_langchain import EnclaveWorkspace

model = ChatOpenAI(model="gpt-5.2")

with EnclaveWorkspace(target="127.0.0.1:50051") as ws:
    agent = model.bind_tools(ws.tools.get_tools())
    reply = agent.invoke(
        "Write 'hello' to /workspace/out.txt inside the sandbox, then cat it back."
    )
    print(reply.content)
```

## Configuration

Import the guest images with `sudo /opt/ne-enclave/bin/nee image import`, then configure
`EnclaveWorkspace` with the same lowercase SHA-256 values. Any environment value can be
overridden by a matching kwarg.

| Env var | Meaning |
|---|---|
| `NE_KERNEL_SHA256` | SHA-256 of the managed guest kernel |
| `NE_ROOTFS_SHA256` | SHA-256 of the managed guest rootfs |
| `NE_VSOCK_CID_BASE` | Guest vsock CID (must be unique per concurrent workspace on a host) |

## Tools

`EnclaveToolkit` exposes three tools to the agent:

| Tool | Action | Returns to the LLM |
|---|---|---|
| `enclave_exec` | Run a command | `exit: <N>\n<stdout><stderr>` (8 KiB cap) |
| `enclave_write_file` | Write a UTF-8 file | `wrote <path> (<n> bytes)` |
| `enclave_read_file` | Read a file | file content (8 KiB cap) |

Non-zero exit is reported in the string (not raised). Transport/argument errors raise `ToolException`.

## License

Apache-2.0.

# @neuronedge/enclave-mastra

A [Mastra](https://mastra.ai) adapter for the [NeuronEdge Enclave](https://neuronedge.ai) Runtime API. Gives an LLM agent a managed, confidential Firecracker microVM sandbox: run shell commands and move files in/out.

> **Development mode.** The base `@neuronedge/enclave` SDK opens an insecure gRPC channel. Use this adapter against a local `nee` daemon until TLS + API-key client credentials ship.

## Install

```bash
npm install @neuronedge/enclave-mastra
```

## Quickstart

```ts
import { openai } from "@ai-sdk/openai";
import { Agent } from "@mastra/core/agent";
import { withWorkspace } from "@neuronedge/enclave-mastra";

const model = openai("gpt-5.2");

await withWorkspace({ target: "127.0.0.1:50051" }, async (ws) => {
  const agent = new Agent({
    name: "enclave-agent",
    model,
    tools: ws.tools,
  });
  const stream = await agent.stream("Write 'hi from enclave' to /workspace/out.txt, then cat it back.");
  for await (const chunk of stream.textStream) {
    process.stdout.write(chunk);
  }
});
```

## Configuration

Import the guest images with `sudo /opt/ne-enclave/bin/nee image import`, then configure
`withWorkspace` / `EnclaveWorkspace` with the same lowercase SHA-256 values. Any environment
value can be overridden by a matching option.

| Env var | Meaning |
|---|---|
| `NE_KERNEL_SHA256` | SHA-256 of the managed guest kernel |
| `NE_ROOTFS_SHA256` | SHA-256 of the managed guest rootfs |
| `NE_VSOCK_CID_BASE` | Guest vsock CID (must be unique per concurrent workspace on a host) |

## Tools

`ws.tools` is a Mastra tool record (spread straight into `new Agent({ tools: ws.tools })`) with three entries:

| Tool | Action | Returns to the LLM (`{ message }`) |
|---|---|---|
| `enclave_exec` | Run a command | `exit: <N>\n<stdout><stderr>` (8 KiB cap) |
| `enclave_write_file` | Write a UTF-8 file | `wrote <path> (<n> bytes)` |
| `enclave_read_file` | Read a file | file content (8 KiB cap) |

Non-zero exit is reported in the string (not thrown). Transport/argument errors throw — Mastra surfaces them to the agent as tool-call errors.

## License

Apache-2.0.

"""NeuronEdge Enclave Python SDK.

Thin client wrapper over the NeuronEdge Enclave Runtime API (gRPC). The current
surface: Ping, CreateWorkspace, ExecuteCommand, DestroyWorkspace.
"""

from ne.client import Client

__all__ = ["Client"]
__version__ = "0.2.0"

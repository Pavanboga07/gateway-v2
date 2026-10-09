# Nexus Gateway (V2)

Independent transport relay and presence server for the Nexus agent network.

## Overview

The Nexus Gateway is a standalone, state-minimized relay server that routes signed protocol frames between independently owned Nexus agents over persistent WebSocket connections.

In accordance with Nexus Version 2 architectural rules:
- The Gateway validates transport envelopes, verifies cryptographic signatures, resolves recipients, and routes messages.
- The Gateway buffers messages for temporarily offline agents.
- The Gateway never executes LLMs, never invokes LangGraph or agent reasoning, never calls MCP tools, and never accesses agent memory or private credentials.

## Architecture

- `gateway/app.py`: WebSocket server process, wire frame dispatching, lifecycle management.
- `gateway/connections.py`: Connection registry, rate limiting, Ed25519 handshake verification.
- `gateway/delivery.py`: Message delivery pipeline, transport outcome resolution.
- `gateway/routing.py`: Recipient resolution and sender binding checks.
- `gateway/buffering.py`: Bounded in-memory FIFO buffer for offline recipients.
- `gateway/models.py`: Transport state models and gateway safety configuration.
- `gateway/errors.py`: Typed transport and authentication error hierarchy.

## Running the Gateway

```bash
python -m gateway.app --host 127.0.0.1 --port 8765
```

## Testing

```bash
pytest
```

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
python -m gateway --host 127.0.0.1 --port 8765
```

(`python -m gateway.app` still works but re-executes the module after
the package import; prefer `python -m gateway` or the `nexus-gateway`
console script. The server also answers `GET /healthz` with 200 JSON
on the same port for host health probes; see "Render deployment"
in `docs/GATEWAY.md`.)

## Keeping the Render deployment warm

Render suspends free web services after ~15 minutes without inbound
traffic, and every suspend wipes the Gateway's in-memory state
(connections, replay guards, and buffered mail for offline agents).
No code deployed *on* the service can prevent that — a suspended
process runs nothing — so the fix pings the public `/healthz`
endpoint from the *outside* on a schedule:

- `.github/workflows/keepalive.yml` runs every 10 minutes (inside
  the idle window, with margin for one missed tick) plus on demand
  (`workflow_dispatch`). It fails loudly when the Gateway does not
  answer, so a real outage pages you instead of hiding behind a nap.
- `scripts/keepalive.sh` holds the retry logic; run it locally or
  from any cron with `scripts/keepalive.sh <public-url>`.

Setup: the workflow pings `https://gateway-v2-ub7w.onrender.com` by
default; set an Actions repository Variable named
`RENDER_GATEWAY_URL` to point it elsewhere. Scheduled workflows run
from the default branch, so merge this to `main` for the pings to
start. No secrets involved: `/healthz` is public and
unauthenticated. (On a paid Render plan with sleep disabled, delete
the workflow — it becomes a no-op health log.)

## Testing

```bash
pytest
```

Standalone (no Nexus checkout on `PYTHONPATH`): install the pinned
Nexus protocol/identity modules first, then the test extras — see
"Standalone setup and testing" in `docs/GATEWAY.md`.

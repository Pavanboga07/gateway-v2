# Nexus Gateway (Component 3)

Dependency: `websockets==16.1.1` (asyncio server) plus Components 1–2.
No other runtime dependencies.

## Responsibility

The Gateway is transport infrastructure, not an agent. It receives,
authenticates, verifies, routes, delivers, acknowledges, and buffers
Nexus protocol messages. It never reasons, never calls models or tools,
never reads user data, and never decides whether a query or capability
is acceptable — those judgments belong to the receiving Nexus agent.

## Connection model

Each Nexus instance holds one persistent outbound WebSocket to the
gateway (no inbound public server required per agent). The gateway
tracks per agent: `agent_id`, `connection_id`, state
(CONNECTING → AUTHENTICATING → CONNECTED → DISCONNECTED), `connected_at`
and last activity. Identity is the Component 2 `agent_id`, never a
username. Presence is an in-memory registry; durable discovery arrives
later.

## Handshake

One frame opens the connection:

```json
{"type": "HANDSHAKE",
 "identity": {"agent_id": "agent_…", "algorithm": "Ed25519",
              "public_key": "<base64url>"},
 "message": {<signed CONNECT_REQUEST to "gateway">}}
```

Acceptance requires all three to agree: the claimed id, the public
identity document (whose embedded id is re-derived from its key), and a
fresh Ed25519 proof — a signed CONNECT_REQUEST verified with Component
2 (structure, binding, expiry, replay, signature). Possession is proven
by signing fresh timestamped bytes; replays die in the transport replay
registry. Every failure mode surfaces as `HandshakeError`. On success
the gateway replies `WELCOME`, replaces any prior connection for the
agent (the old socket is closed), and drains that agent's buffer.

## Routing

Routes purely on the recipient `agent_id`: CONNECTED → transmit now,
OFFLINE (valid but absent) → buffer, INVALID (unusable id) → reject.
The sender envelope must equal the connection identity before routing
and before cryptography. Payload meaning is never inspected.

## Delivery states

- `DELIVERY_ACCEPTED` — verified and taken into gateway responsibility
- `DELIVERED` — bytes written to the recipient's live connection
- `BUFFERED` — recipient offline; stored for reconnect
- `FAILED` — rejected, with a machine-readable code prefix
  (`INVALID_MESSAGE`, `SENDER_MISMATCH`, `INVALID_SIGNATURE`,
  `EXPIRED`, `REPLAYED`, `UNKNOWN_RECIPIENT`, `MESSAGE_TOO_LARGE`,
  `RATE_LIMITED`, `BUFFER_FULL`)

Delivery is transport only: DELIVERED never means the remote task
completed. Each MESSAGE frame gets exactly one ACK; error frames carry
safe codes, never secrets or traces.

## Buffering

Per-recipient FIFO of deep-copied wire envelopes (mutation-proof).
Original `message_id`/`request_id`/payload/signature preserved; nothing
is re-signed or rewritten. Expired entries are dropped at drain, never
delivered as work. Capacity per recipient is bounded (explicit
`BUFFER_FULL` back-pressure instead of silent drops). In-memory by
design in Component 3; durable queues belong to persistence.

## Reconnect behavior

Disconnect removes the live connection but keeps buffered messages.
Reconnect re-authenticates, restores presence, and drains eligible
buffered mail in order; confirmed deliveries are never repeated, and a
failed transmit returns unsent mail to the queue head.

## Duplicate handling

`message_id` is the dedup key (never `request_id`: siblings under one
request are legitimate). Component 2 records an id only after
successful verification, so forged messages cannot poison replay state.

## Message verification

Every MESSAGE frame runs: parse → Component 1 structure → sender
binding → Component 2 verify (binding, expiry, replay, signature) →
route. Raw frames are size-checked before parsing; per-connection rate
is bounded (120 msgs/60 s sliding window — a safety boundary, not a
distributed limiter).

## Sender identity binding

Connection identity and envelope sender must agree; a connection for A
can never emit `sender = B`, signature or not.

## Message immutability

Validated envelopes are treated as final: the gateway forwards the
authenticated content exactly (deterministic re-emission, signature
still verifies) and never touches sender, recipient, ids, payload,
timestamps, version, or signature.

## Size limits

1 MiB per message frame by default (`GatewayConfig.max_message_size`),
measured as canonical-JSON UTF-8 bytes of the inner message envelope
(the same expression clients use for their sender-side check), plus an
8 KiB headroom on the raw socket frame for the outer `MESSAGE` wrapper.
Oversize inner envelopes get an explicit FAILED ack
(`MESSAGE_TOO_LARGE`, carrying the sender's own ids when recoverable);
only frames exceeding the raw socket limit are dropped at the
transport level. Compliant Nexus clients enforce the same limit before
transmitting, so a well-behaved sender never triggers either path. No
chunking/streaming yet.

## Rate limits

Sliding-window cap per connection (defaults above). Exceeding it fails
the message (`RATE_LIMITED`) without killing the connection. No Redis
or distributed machinery.

## Failure behavior

Unauthenticated sends, bad handshakes, malformed/invalid/expired/
replayed/spoofed messages, unknown recipients, offline recipients,
full buffers, send failures, and stale connections each have an
explicit outcome. Every MESSAGE rejection is answered with exactly one
FAILED ack addressed to the sender's own ids whenever they can be
safely extracted from the frame (`RATE_LIMITED`, `MESSAGE_TOO_LARGE`,
`INVALID_MESSAGE` and post-parse failures all correlate); frames so
malformed that no id is recoverable keep a bare ERROR reply and the
sender falls back to its bounded ack timeout — never a false success.
A non-MESSAGE frame carrying a message envelope likewise receives a
correlated FAILED ack (`UNKNOWN_FRAME`) instead of an uncorrelated
ERROR. Stale (long-idle) connections are swept; unregister
is connection-id-guarded so a dying handler never evicts a reconnect.

While the server runs, a lightweight janitor task wakes every
`stale_after_s` seconds to sweep idle connections (their sockets are
closed), purge expired replay ids, and drop expired buffered mail. It
is cancelled on shutdown and never blocks message handling. All gateway
state stays in-memory by design: a process restart loses connections,
buffered mail, and replay state. Durable queues arrive with
persistence; until then the guarantee is AT-MOST-ONCE per `message_id`
within process lifetime — never exactly-once.

## Sequence diagrams

Online:

```text
Agent A ──HANDSHAKE──▶ Gateway ──WELCOME──▶ Agent A
Agent B ──HANDSHAKE──▶ Gateway ──WELCOME──▶ Agent B
Agent A ──MESSAGE(signed REMOTE_QUERY)──▶ Gateway
Gateway : verify → route(B connected)
Gateway ──DELIVER──▶ Agent B
Gateway ──ACK(DELIVERED)──▶ Agent A
Agent B : independently verifies with A's public key
```

Offline then reconnect:

```text
Agent A ──MESSAGE──▶ Gateway ──ACK(BUFFERED)──▶ Agent A
Agent B ──HANDSHAKE──▶ Gateway ──WELCOME──▶ Agent B
Gateway ──DELIVER(buffered, unchanged ids)──▶ Agent B
```

## What the Gateway explicitly does NOT do

No LLM/LangGraph/LangChain/MCP calls, no user data access, no tool
execution, no response generation, no request lifecycle, no approvals,
no capability policy, no REST, no frontend, no database, no queues.
Run one process with `python -m gateway` (defaults localhost:8765);
tests use `GatewayServer` in-process (`python -m pytest tests/`).

## Render deployment

The same process serves plain HTTP health on the WebSocket port:
`GET /healthz` answers `200 {"status":"ok","service":"nexus-gateway"}`
via the `process_request` hook, without touching the A2A path. Deploy
as a Web Service from `render.yaml` (branch pinned there):

- Build: pinned `nexus-v2` protocol/identity modules `--no-deps`,
  then `pip install -e .`
- Start: `python -m gateway --host 0.0.0.0 --port $PORT`
  (bind `0.0.0.0`: the `127.0.0.1` default is unreachable from the
  Render proxy and the deploy will hang).
- Health Check Path: `/healthz` (leave HTTP checks on this path;
  the server has no other HTTP surface).
- TLS terminates at Render's proxy: agents connect with
  `wss://<service>.onrender.com`. The Ed25519 handshake still runs
  end-to-end inside the tunnel.

Hosting notes (not code gaps, but deployment facts): the free plan
sleeps after idle, and every restart loses buffered mail, connections,
and replay state (AT-MOST-ONCE, in-memory by design). Non-`GET`
probes (e.g. `HEAD /`) are rejected by the vendored HTTP parser
before our code runs — logged handshake noise, no A2A impact, and the
server keeps serving afterwards.

## Standalone setup and testing

The gateway's only shared definitions are the Nexus protocol and
identity modules (`backend.protocol`, `backend.identity`: stdlib plus
`cryptography`, no LLM/MCP stack). They stay authoritative in the
Nexus application repository; this repository never copies them. The
Nexus distribution declares explicit namespace packaging
(`backend*`), so it installs cleanly and this gateway consumes it as
an explicit version-pinned dependency without the application's heavy
extras:

```bash
python -m venv .venv && . .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install "nexus-v2 @ git+https://github.com/Pavanboga07/Nexus-V2.git@573c1a82e831371c653afe9e7102bb8a437c040a" --no-deps
pip install -e ".[test]"
python -m pytest tests/ -q
```

The pinned SHA above is the audited Nexus commit carrying the
protocol/identity modules (`573c1a8` on
`fix/gateway-client-integration`). Advance it only when those two
modules change, and re-run both suites. `--no-deps` is intentional:
it keeps
the gateway environment free of the application's
LangGraph/MCP/persistence stack, which nothing here imports (the
client-side guard test `test_client_has_clean_dependencies` pins the
same boundary on the Nexus side). Until those two modules are
extracted into their own published distribution (the narrowest safe
follow-up, requiring cross-repo authorization), do not replace this
with an undocumented `PYTHONPATH` pointing at a local checkout.

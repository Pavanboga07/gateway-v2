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
enforced on raw frames (connection dropped on violation) and inside the
pipeline (explicit FAILED ack). No chunking/streaming yet.

## Rate limits

Sliding-window cap per connection (defaults above). Exceeding it fails
the message (`RATE_LIMITED`) without killing the connection. No Redis
or distributed machinery.

## Failure behavior

Unauthenticated sends, bad handshakes, malformed/invalid/expired/
replayed/spoofed messages, unknown recipients, offline recipients,
full buffers, send failures, and stale connections each have an
explicit outcome. Stale (long-idle) connections are swept; unregister
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
Run one process with `python -m gateway.app` (defaults localhost:8765);
tests use `GatewayServer` in-process (`python -m pytest tests/`).

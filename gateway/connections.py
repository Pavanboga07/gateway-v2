"""Agent connections: handshake verification, registry, rate safety.

Handshake (documented contract): the agent opens the socket and sends one
frame::

    {"type": "HANDSHAKE",
     "identity": <PublicIdentity dict: agent_id + base64url public key>,
     "message":  <signed CONNECT_REQUEST envelope dict>}

The gateway accepts the connection only when three facts agree: the
claimed ``agent_id``, the provided public identity (whose embedded id
is re-derived from its key), and a fresh Ed25519 proof — a signed
CONNECT_REQUEST from the claimant, verified with Component 2
(structure, binding, expiry, replay, signature). No second auth system,
no nonces, no OAuth: possession is proven by signing fresh timestamped
bytes, replay is blocked by the transport replay registry plus short
handshake-message expiry.
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from backend.identity.errors import IdentityError
from backend.identity.identity import public_identity_from_dict
from backend.identity.verification import verify_message
from backend.protocol.models import NexusMessage
from backend.protocol.serialization import message_from_dict
from backend.protocol.types import MessageType

from .errors import HandshakeError
from .models import ConnectionInfo, ConnectionState


@dataclass(frozen=True)
class HandshakeAccept:
    """Verified handshake outcome (identity proven, not yet registered)."""

    agent_id: str
    public_key: Any
    message: NexusMessage


class RateLimiter:
    """Simple per-connection safety boundary (sliding window count).

    Not a distributed rate system: just enough that one connection
    cannot trivially consume unbounded gateway resources. The clock is
    injected (monotonic seconds) so behavior is deterministic in tests.
    """

    def __init__(self, max_messages: int, window_s: float) -> None:
        self._max = max_messages
        self._window = window_s
        self._hits: deque[float] = deque()

    def allow(self, now: float) -> bool:
        """Consume one unit iff the window still has capacity."""
        while self._hits and self._hits[0] <= now - self._window:
            self._hits.popleft()
        if len(self._hits) >= self._max:
            return False
        self._hits.append(now)
        return True


def verify_handshake(
    frame: Any,
    *,
    now: datetime,
    replay_registry: Any,
    gateway_agent_id: str,
) -> HandshakeAccept:
    """Verify one handshake frame; raise :class:`HandshakeError` or return.

    Every failure mode (malformed frame, identity mismatch, bad proof,
    replayed proof) becomes ``HandshakeError`` chained to its cause, so
    callers handle a single type while diagnostics keep the root reason.
    """
    if not isinstance(frame, dict):
        raise HandshakeError("handshake must be a JSON object")
    identity_doc = frame.get("identity")
    envelope = frame.get("message")
    if identity_doc is None or envelope is None:
        raise HandshakeError("handshake needs identity and message")
    try:
        identity = public_identity_from_dict(identity_doc)
    except IdentityError as exc:
        raise HandshakeError(f"invalid public identity: {exc}") from exc
    try:
        public_key = Ed25519PublicKey.from_public_bytes(identity.public_key)
    except Exception as exc:
        raise HandshakeError("invalid handshake public key") from exc
    try:
        message = message_from_dict(envelope)
    except Exception as exc:
        raise HandshakeError(f"invalid handshake message: {exc}") from exc
    if message.type is not MessageType.CONNECT_REQUEST:
        raise HandshakeError("handshake message must be CONNECT_REQUEST")
    if message.recipient != gateway_agent_id:
        raise HandshakeError("handshake message must address the gateway")
    if message.sender != identity.agent_id:
        raise HandshakeError("handshake sender does not match identity")
    try:
        verify_message(
            message, public_key, now=now, replay_registry=replay_registry
        )
    except Exception as exc:
        raise HandshakeError(f"handshake proof rejected: {exc}") from exc
    return HandshakeAccept(
        agent_id=identity.agent_id, public_key=public_key, message=message
    )


@dataclass
class _Entry:
    info: ConnectionInfo
    transport: Any = None
    limiter: RateLimiter | None = None


class ConnectionRegistry:
    """In-memory active connection map (presence for this component).

    Thread-safe. ``unregister`` only removes the exact connection id it
    is given, so a dying old handler can never evict a fresh reconnect.
    Persistent discovery across restarts belongs to a later component.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    def register(
        self,
        agent_id: str,
        public_key: Any,
        transport: Any,
        limiter: RateLimiter | None,
        now: datetime,
    ) -> tuple[ConnectionInfo, Any]:
        """Register (or replace) the live connection; return it plus any
        superseded transport the caller should close."""
        info = ConnectionInfo(
            agent_id=agent_id,
            connection_id=uuid.uuid4().hex,
            state=ConnectionState.CONNECTED,
            connected_at=now,
            last_activity=now,
            public_key=public_key,
        )
        with self._lock:
            previous = self._entries.get(agent_id)
            self._entries[agent_id] = _Entry(
                info=info, transport=transport, limiter=limiter
            )
        return info, (previous.transport if previous is not None else None)

    def unregister(self, agent_id: str, connection_id: str) -> bool:
        """Remove a connection only if it is still the registered one."""
        with self._lock:
            current = self._entries.get(agent_id)
            if current is None or current.info.connection_id != connection_id:
                return False
            del self._entries[agent_id]
            return True

    def lookup(self, agent_id: str) -> _Entry | None:
        """Return the live entry for ``agent_id``, if any."""
        with self._lock:
            return self._entries.get(agent_id)

    def is_connected(self, agent_id: object) -> bool:
        """Presence check used by routing."""
        return isinstance(agent_id, str) and self.lookup(agent_id) is not None

    def connected_agents(self) -> list[str]:
        """Agent ids with a live connection."""
        with self._lock:
            return sorted(self._entries)

    def touch(self, agent_id: str, now: datetime) -> None:
        """Record activity (heartbeat for stale cleanup)."""
        with self._lock:
            entry = self._entries.get(agent_id)
            if entry is not None:
                entry.info.last_activity = now

    def sweep_stale(
        self, now: datetime, stale_after_s: float
    ) -> list[tuple[ConnectionInfo, Any]]:
        """Drop connections idle beyond the boundary; return them so the
        caller can close their transports. Never touches process state."""
        removed: list[tuple[ConnectionInfo, Any]] = []
        with self._lock:
            for agent_id, entry in list(self._entries.items()):
                idle = (now - entry.info.last_activity).total_seconds()
                if idle > stale_after_s:
                    del self._entries[agent_id]
                    removed.append((entry.info, entry.transport))
        return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

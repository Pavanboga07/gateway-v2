"""Offline buffering: ordered per-recipient queues (in-memory).

Stored entries are deep copies of the received wire envelope, so later
caller-side mutation cannot alter buffered content, and forwarding never
re-signs or rewrites anything: message_id, request_id, payload, and the
signature travel byte-identical. FIFO order is preserved per recipient.
Expired entries are never delivered as new work — they are dropped at
drain time and reported. Durable (PostgreSQL-backed) queues belong to
the persistence component; this in-memory buffer is the documented
Component 3 store.
"""

from __future__ import annotations

import copy
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

from backend.protocol.serialization import parse_timestamp
from backend.protocol.types import is_valid_message_id

from .errors import BufferFullError


def _require_aware(value: object, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


class MessageBuffer:
    """Thread-safe FIFO buffer keyed by recipient agent id."""

    def __init__(self, max_per_recipient: int = 1000) -> None:
        self._max = max_per_recipient
        self._lock = threading.Lock()
        self._queues: dict[str, deque[dict[str, Any]]] = {}

    def _checked_recipient(self, recipient: object) -> str:
        if not isinstance(recipient, str) or not recipient:
            raise ValueError(f"invalid recipient: {recipient!r}")
        return recipient

    def store(
        self, recipient: str, envelope: dict[str, Any], now: datetime
    ) -> int:
        """Buffer a wire-envelope copy; return the queue depth.

        Raises :class:`BufferFullError` at capacity (explicit back
        pressure, never silent drops) and ``ValueError`` for malformed
        input or expired content (expired messages are never worth
        storing).
        """
        agent = self._checked_recipient(recipient)
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be a dict")
        current = _require_aware(now, "now")
        try:
            expires_at = parse_timestamp(envelope.get("expires_at"))
        except Exception as exc:
            raise ValueError(f"buffered envelope needs expiry: {exc}") from exc
        if current >= expires_at:
            raise ValueError("refusing to buffer an expired message")
        with self._lock:
            queue = self._queues.setdefault(agent, deque())
            if len(queue) >= self._max:
                raise BufferFullError(
                    f"buffer full for recipient {agent!r}"
                )
            queue.append(copy.deepcopy(envelope))
            return len(queue)

    def drain_eligible(
        self, recipient: str, now: datetime
    ) -> tuple[list[dict[str, Any]], int]:
        """Remove and return live envelopes in FIFO order.

        Returns ``(messages, dropped_expired)``. Drained messages are
        gone from the buffer, so a confirmed delivery is never repeated;
        expired ones are silently dropped (they must not become work).
        """
        agent = self._checked_recipient(recipient)
        current = _require_aware(now, "now")
        live: list[dict[str, Any]] = []
        dropped = 0
        with self._lock:
            queue = self._queues.get(agent)
            if queue is None:
                return [], 0
            while queue:
                envelope = queue.popleft()
                try:
                    expires_at = parse_timestamp(envelope.get("expires_at"))
                except Exception:
                    dropped += 1
                    continue
                if current >= expires_at:
                    dropped += 1
                else:
                    live.append(envelope)
            if not queue:
                del self._queues[agent]
        return live, dropped

    def restore_front(
        self, recipient: str, envelopes: list[dict[str, Any]]
    ) -> None:
        """Prepend undelivered envelopes back in order (send failure path).

        Capacity is not re-checked here: these messages were already
        admitted, and losing them would be worse than a transient
        overfill, which drains first.
        """
        agent = self._checked_recipient(recipient)
        with self._lock:
            queue = self._queues.setdefault(agent, deque())
            for envelope in reversed(envelopes):
                queue.appendleft(envelope)

    def pending_count(self, recipient: str) -> int:
        """Buffered depth for one recipient."""
        agent = self._checked_recipient(recipient)
        with self._lock:
            queue = self._queues.get(agent)
            return 0 if queue is None else len(queue)

    def drop_expired(self, now: datetime) -> int:
        """Proactively purge stale entries everywhere; return the count."""
        current = _require_aware(now, "now")
        removed = 0
        with self._lock:
            for agent in list(self._queues):
                queue = self._queues[agent]
                kept: deque[dict[str, Any]] = deque()
                while queue:
                    envelope = queue.popleft()
                    try:
                        live = current < parse_timestamp(
                            envelope.get("expires_at")
                        )
                    except Exception:
                        live = False
                    if live:
                        kept.append(envelope)
                    else:
                        removed += 1
                if kept:
                    self._queues[agent] = kept
                else:
                    del self._queues[agent]
        return removed

    def recipients(self) -> list[str]:
        """Recipients with pending buffered messages."""
        with self._lock:
            return sorted(self._queues)

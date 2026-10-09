"""Gateway data models (transport state only, no behavior).

Nothing here reasons about queries, scopes, human decisions, or task
results. ``DeliveryStatus`` describes transport disposition exclusively:
a DELIVERED message was handed to the recipient's connection — it says
nothing about remote task completion, which the gateway never observes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


class ConnectionState(str, Enum):
    """Lifecycle of one agent connection."""

    CONNECTING = "CONNECTING"
    AUTHENTICATING = "AUTHENTICATING"
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"


class DeliveryStatus(str, Enum):
    """Transport disposition of one protocol message.

    DELIVERY_ACCEPTED marks the milestone where a message passed every
    security check and the gateway accepted transport responsibility;
    DELIVERED / BUFFERED / FAILED record its final disposition.
    """

    DELIVERY_ACCEPTED = "DELIVERY_ACCEPTED"
    DELIVERED = "DELIVERED"
    BUFFERED = "BUFFERED"
    FAILED = "FAILED"


@dataclass
class ConnectionInfo:
    """Identity and lifecycle metadata for one agent connection."""

    agent_id: str
    connection_id: str
    state: ConnectionState
    connected_at: datetime
    last_activity: datetime
    public_key: Ed25519PublicKey = field(repr=False, compare=False)


@dataclass(frozen=True)
class DeliveryAck:
    """Transport-level acknowledgement (never a task result)."""

    message_id: str
    request_id: str
    status: DeliveryStatus
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "ACK",
            "message_id": self.message_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class GatewayConfig:
    """Gateway safety boundaries (documented, no hidden behavior)."""

    max_message_size: int = 1_048_576  # 1 MiB per protocol message frame
    rate_limit_max: int = 120  # messages per connection per window
    rate_limit_window_s: float = 60.0
    buffer_max_per_recipient: int = 1000
    stale_after_s: float = 300.0  # drop connections idle longer than this
    handshake_timeout_s: float = 30.0  # deadline for the first frame
    handshake_message_ttl_s: float = 300.0  # informational: proofs must be fresh
    gateway_agent_id: str = "gateway"  # recipient id for handshake messages

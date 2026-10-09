"""Transport pipeline: validate → verify → route → deliver-or-buffer.

``process_transport_message`` is pure logic over injected registries: no
sockets, no clock of its own, no interpretation of payload meaning. It
never raises for message problems — every failure becomes a FAILED
:class:`DeliveryAck` with a safe code — and only raises ``TypeError`` /
``ValueError`` for caller misuse. Forwarded envelopes are the sender's
original wire dicts: nothing is re-signed, rewritten, or reordered, so
the receiver verifies the exact bytes the sender signed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from backend.identity.errors import (
    ExpiredMessageError,
    IdentityError,
    InvalidSignatureError,
    MalformedSignatureError,
    ReplayDetectedError,
    SenderMismatchError,
)
from backend.identity.replay import ReplayRegistry
from backend.identity.verification import verify_message
from backend.protocol.serialization import (
    ProtocolSerializationError,
    message_from_dict,
    message_to_dict,
)
from backend.protocol.validation import ProtocolValidationError
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .buffering import MessageBuffer
from .connections import ConnectionRegistry, RateLimiter
from .errors import BufferFullError
from .models import ConnectionInfo, DeliveryAck, DeliveryStatus, GatewayConfig
from .routing import RecipientState, check_sender_binding, resolve_recipient


@dataclass(frozen=True)
class TransportOutcome:
    """One processed message: ack for the sender plus optional forward.

    ``accepted`` records the DELIVERY_ACCEPTED milestone (verified and
    taken into gateway responsibility); ``ack.status`` records the final
    disposition (DELIVERED intent, BUFFERED, or FAILED). ``forward`` is
    the sender's original envelope dict, present only when the recipient
    is connected and the caller should transmit it now.
    """

    accepted: bool
    ack: DeliveryAck
    forward: Optional[dict[str, Any]]
    target: Optional[str]


def _fail(
    message_id: str, request_id: str, code: str, detail: str = ""
) -> TransportOutcome:
    """Build a FAILED outcome whose detail always leads with the code."""
    return TransportOutcome(
        accepted=False,
        ack=DeliveryAck(
            message_id=message_id,
            request_id=request_id,
            status=DeliveryStatus.FAILED,
            detail=f"{code}: {detail}" if detail else code,
        ),
        forward=None,
        target=None,
    )


def process_transport_message(
    envelope: Any,
    *,
    connection: ConnectionInfo,
    public_key: Ed25519PublicKey,
    registry: ConnectionRegistry,
    buffer: MessageBuffer,
    replay: ReplayRegistry,
    limiter: RateLimiter | None,
    config: GatewayConfig,
    now: datetime,
    mono_now: float,
) -> TransportOutcome:
    """Run the ten-step transport pipeline for one sender frame."""
    if limiter is not None and not limiter.allow(mono_now):
        return _fail("unknown", "unknown", "RATE_LIMITED",
                      "connection messaging boundary exceeded")
    if not isinstance(envelope, dict):
        return _fail("unknown", "unknown", "INVALID_MESSAGE",
                      "message must be a JSON object")
    try:
        size = len(
            json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError):
        return _fail("unknown", "unknown", "INVALID_MESSAGE",
                      "message is not JSON serializable")
    if size > config.max_message_size:
        return _fail("unknown", "unknown", "MESSAGE_TOO_LARGE",
                      f"limit is {config.max_message_size} bytes")
    try:
        message = message_from_dict(envelope)
    except ProtocolSerializationError as exc:
        return _fail("unknown", "unknown", "INVALID_MESSAGE", str(exc))
    try:
        check_sender_binding(message.sender, connection.agent_id)
    except SenderMismatchError as exc:
        return _fail(message.message_id, message.request_id,
                      "SENDER_MISMATCH", str(exc))
    try:
        verify_message(message, public_key, now=now, replay_registry=replay)
    except ReplayDetectedError as exc:
        return _fail(message.message_id, message.request_id,
                      "REPLAYED", str(exc))
    except ExpiredMessageError as exc:
        return _fail(message.message_id, message.request_id,
                      "EXPIRED", str(exc))
    except (InvalidSignatureError, MalformedSignatureError) as exc:
        return _fail(message.message_id, message.request_id,
                      "INVALID_SIGNATURE", str(exc))
    except SenderMismatchError as exc:  # defense in depth; checked above
        return _fail(message.message_id, message.request_id,
                      "SENDER_MISMATCH", str(exc))
    except (ProtocolValidationError, ProtocolSerializationError) as exc:
        return _fail(message.message_id, message.request_id,
                      "INVALID_MESSAGE", str(exc))
    except IdentityError as exc:
        return _fail(message.message_id, message.request_id,
                      "INVALID_MESSAGE", str(exc))
    state = resolve_recipient(message.recipient, registry)
    if state is RecipientState.INVALID:
        return _fail(message.message_id, message.request_id,
                      "UNKNOWN_RECIPIENT",
                      f"recipient {message.recipient!r} is not routable")
    if state is RecipientState.OFFLINE:
        try:
            buffer.store(message.recipient, envelope, now)
        except BufferFullError as exc:
            return _fail(message.message_id, message.request_id,
                          "BUFFER_FULL", str(exc))
        except ValueError as exc:
            return _fail(message.message_id, message.request_id,
                          "INVALID_MESSAGE", str(exc))
        return TransportOutcome(
            accepted=True,
            ack=DeliveryAck(
                message_id=message.message_id, request_id=message.request_id,
                status=DeliveryStatus.BUFFERED,
                detail="recipient offline; buffered for reconnect",
            ),
            forward=None,
            target=None,
        )
    # Connected: emit a validated wire copy and let the caller transmit
    # it. The wire copy round-trips through Component 1 so emission
    # rules apply; content is byte-equivalent to the sender's bytes and
    # the signature still verifies (canonical form is order/whitespace
    # independent).
    try:
        wire = message_to_dict(message)
    except ProtocolSerializationError as exc:  # unreachable; validated above
        return _fail(message.message_id, message.request_id,
                      "INVALID_MESSAGE", str(exc))
    return TransportOutcome(
        accepted=True,
        ack=DeliveryAck(
            message_id=message.message_id, request_id=message.request_id,
            status=DeliveryStatus.DELIVERED,
            detail="accepted; delivering to recipient connection",
        ),
        forward=wire,
        target=message.recipient,
    )

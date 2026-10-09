"""Recipient resolution and sender binding (routing decisions only).

Routing keys exclusively on the recipient ``agent_id``. No usernames,
display names, URLs, or payload interpretation participate: the gateway
never inspects what a query means, only where the envelope is addressed.
"""

from __future__ import annotations

from enum import Enum

from backend.identity.errors import SenderMismatchError
from backend.protocol.types import is_valid_agent_id

from .connections import ConnectionRegistry


class RecipientState(str, Enum):
    """Routing verdict for one recipient id."""

    CONNECTED = "CONNECTED"
    OFFLINE = "OFFLINE"
    INVALID = "INVALID"


def resolve_recipient(
    recipient_id: object, registry: ConnectionRegistry
) -> RecipientState:
    """Resolve ``recipient_id`` against live presence.

    Syntactically unusable ids are INVALID (rejected outright); valid
    but absent ids are OFFLINE (eligible for buffering, since the agent
    may simply be disconnected — the gateway performs no discovery).
    """
    if not is_valid_agent_id(recipient_id):
        return RecipientState.INVALID
    assert isinstance(recipient_id, str)
    if registry.is_connected(recipient_id):
        return RecipientState.CONNECTED
    return RecipientState.OFFLINE


def check_sender_binding(message_sender: str, connection_agent_id: str) -> None:
    """Require the envelope sender to equal the connection identity.

    Runs before routing and before cryptography: a connection
    authenticated as A may never inject ``sender = B``, regardless of
    signatures. Raises :class:`SenderMismatchError` on mismatch.
    """
    if message_sender != connection_agent_id:
        raise SenderMismatchError(
            f"connection {connection_agent_id!r} cannot send "
            f"as {message_sender!r}"
        )

"""Nexus Gateway (Component 3): transport infrastructure, not an agent.

Receives, authenticates, verifies, routes, delivers, acknowledges, and
buffers Nexus protocol messages between connected agents. Never reasons,
never executes tasks, never touches models, tools, or user data.
"""

from .app import GatewayServer, main, utcnow
from .buffering import MessageBuffer
from .connections import (
    ConnectionRegistry,
    HandshakeAccept,
    RateLimiter,
    verify_handshake,
)
from .delivery import TransportOutcome, process_transport_message
from .errors import (
    AuthenticationError,
    BufferFullError,
    DeliveryError,
    GatewayError,
    HandshakeError,
    NotConnectedError,
    OversizedMessageError,
    RateLimitedError,
    UnknownRecipientError,
    error_frame,
)
from .models import (
    ConnectionInfo,
    ConnectionState,
    DeliveryAck,
    DeliveryStatus,
    GatewayConfig,
)
from .routing import RecipientState, check_sender_binding, resolve_recipient

__all__ = [
    "GatewayServer",
    "main",
    "utcnow",
    "MessageBuffer",
    "ConnectionRegistry",
    "HandshakeAccept",
    "RateLimiter",
    "verify_handshake",
    "TransportOutcome",
    "process_transport_message",
    "GatewayError",
    "HandshakeError",
    "AuthenticationError",
    "UnknownRecipientError",
    "NotConnectedError",
    "OversizedMessageError",
    "RateLimitedError",
    "BufferFullError",
    "DeliveryError",
    "error_frame",
    "ConnectionInfo",
    "ConnectionState",
    "DeliveryAck",
    "DeliveryStatus",
    "GatewayConfig",
    "RecipientState",
    "check_sender_binding",
    "resolve_recipient",
]

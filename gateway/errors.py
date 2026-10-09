"""Gateway error model and wire-safe error frames.

Exception messages carry only non-sensitive transport facts (agent ids,
message ids, limits, error codes). Private keys, secrets, stack traces,
and filesystem paths never appear here.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for gateway transport errors."""

    code = "GATEWAY_ERROR"


class HandshakeError(GatewayError):
    """Connection handshake (authentication) failed."""

    code = "HANDSHAKE_FAILED"


class AuthenticationError(GatewayError):
    """Operation requires an authenticated connection."""

    code = "AUTH_REQUIRED"


class UnknownRecipientError(GatewayError):
    """Recipient agent id is not usable for routing."""

    code = "UNKNOWN_RECIPIENT"


class NotConnectedError(GatewayError):
    """No active connection exists for the agent."""

    code = "NOT_CONNECTED"


class OversizedMessageError(GatewayError):
    """Frame exceeds the gateway message size limit."""

    code = "MESSAGE_TOO_LARGE"


class RateLimitedError(GatewayError):
    """Connection exceeded its messaging safety boundary."""

    code = "RATE_LIMITED"


class BufferFullError(GatewayError):
    """Recipient offline buffer has no remaining capacity."""

    code = "BUFFER_FULL"


class DeliveryError(GatewayError):
    """Transport-level delivery failed."""

    code = "DELIVERY_FAILED"


def error_frame(exc: BaseException) -> dict[str, str]:
    """Build a safe wire ERROR frame for any failure.

    Only the public code and a sanitized message cross the wire. Raw
    third-party exceptions are reduced to a generic transport failure
    so internals never leak to remote agents.
    """
    if isinstance(exc, GatewayError):
        return {
            "type": "ERROR",
            "code": exc.code,
            "message": str(exc) or exc.code,
        }
    return {
        "type": "ERROR",
        "code": DeliveryError.code,
        "message": "delivery failed",
    }

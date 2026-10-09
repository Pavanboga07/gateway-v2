"""Connection tests: handshake, registry lifecycle, presence."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.identity.identity import create_identity
from backend.identity.replay import ReplayRegistry
from backend.identity.signing import sign_message
from backend.protocol.models import (
    ConnectRequestPayload,
    NexusMessage,
    RemoteQueryPayload,
)
from backend.protocol.serialization import message_to_dict
from backend.protocol.types import PROTOCOL_VERSION, MessageType
from gateway.connections import (
    ConnectionRegistry,
    RateLimiter,
    verify_handshake,
)
from gateway.errors import HandshakeError
from gateway.models import ConnectionState

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = BASE + timedelta(minutes=1)


def _handshake_frame(identity, **overrides):
    message = NexusMessage(
        protocol_version=PROTOCOL_VERSION,
        message_id="hs_msg_001",
        request_id="hs_req_001",
        sender=identity.agent_id,
        recipient="gateway",
        type=MessageType.CONNECT_REQUEST,
        created_at=BASE,
        expires_at=BASE + timedelta(minutes=5),
        payload=ConnectRequestPayload(agent_id=identity.agent_id),
        signature="",
    )
    signed = sign_message(message, identity.private_key)
    frame = {
        "type": "HANDSHAKE",
        "identity": identity.public_identity().to_dict(),
        "message": message_to_dict(signed),
    }
    frame.update(overrides)
    return frame


def _registry():
    return ConnectionRegistry(), ReplayRegistry()


def test_valid_agent_connects():  # 1
    identity = create_identity()
    registry, replay = _registry()
    accept = verify_handshake(
        _handshake_frame(identity), now=NOW,
        replay_registry=replay, gateway_agent_id="gateway",
    )
    assert accept.agent_id == identity.agent_id
    info, replaced = registry.register(
        accept.agent_id, accept.public_key, object(), None, NOW
    )
    assert replaced is None
    assert info.state is ConnectionState.CONNECTED
    assert registry.is_connected(identity.agent_id)
    assert registry.connected_agents() == [identity.agent_id]


def test_invalid_identity_rejected():  # 2
    first, second = create_identity(), create_identity()
    frame = _handshake_frame(first)
    frame["identity"] = second.public_identity().to_dict()  # id/key split
    _, replay = _registry()
    with pytest.raises(HandshakeError):
        verify_handshake(frame, now=NOW, replay_registry=replay,
                         gateway_agent_id="gateway")


def test_invalid_cryptographic_proof_rejected():  # 3
    identity = create_identity()
    frame = _handshake_frame(identity)
    frame["message"]["payload"]["agent_id"] = "agent:forged"
    _, replay = _registry()
    with pytest.raises(HandshakeError):
        verify_handshake(frame, now=NOW, replay_registry=replay,
                         gateway_agent_id="gateway")


def test_same_agent_reconnects_cleanly():  # 4
    identity = create_identity()
    registry, replay = _registry()
    first, _ = registry.register(identity.agent_id, identity.public_key,
                                 object(), None, NOW)
    second, replaced = registry.register(identity.agent_id, identity.public_key,
                                         object(), None, NOW)
    assert first.connection_id != second.connection_id
    assert replaced is not None
    assert registry.lookup(identity.agent_id).info.connection_id == (
        second.connection_id
    )
    assert registry.unregister(identity.agent_id, first.connection_id) is False
    assert registry.unregister(identity.agent_id, second.connection_id) is True


def test_disconnect_removes_active_connection():  # 5
    identity = create_identity()
    registry, _ = _registry()
    info, _ = registry.register(identity.agent_id, identity.public_key,
                                object(), None, NOW)
    assert registry.unregister(identity.agent_id, info.connection_id) is True
    assert not registry.is_connected(identity.agent_id)
    assert len(registry) == 0


def test_multiple_agents_can_remain_connected():  # 6
    registry, _ = _registry()
    ids = set()
    for _ in range(3):
        identity = create_identity()
        ids.add(identity.agent_id)
        registry.register(identity.agent_id, identity.public_key,
                          object(), None, NOW)
    assert set(registry.connected_agents()) == ids


def test_handshake_replay_rejected():
    identity = create_identity()
    _, replay = _registry()
    frame = _handshake_frame(identity)
    verify_handshake(frame, now=NOW, replay_registry=replay,
                     gateway_agent_id="gateway")
    with pytest.raises(HandshakeError):
        verify_handshake(frame, now=NOW, replay_registry=replay,
                         gateway_agent_id="gateway")


def test_handshake_wrong_message_type_rejected():
    identity = create_identity()
    message = NexusMessage(
        protocol_version=PROTOCOL_VERSION,
        message_id="hs_msg_002",
        request_id="hs_req_002",
        sender=identity.agent_id,
        recipient="gateway",
        type=MessageType.REMOTE_QUERY,
        created_at=BASE,
        expires_at=BASE + timedelta(minutes=5),
        payload=RemoteQueryPayload(query="hi", requested_capabilities=[]),
        signature="",
    )
    frame = {
        "type": "HANDSHAKE",
        "identity": identity.public_identity().to_dict(),
        "message": message_to_dict(sign_message(message, identity.private_key)),
    }
    _, replay = _registry()
    with pytest.raises(HandshakeError):
        verify_handshake(frame, now=NOW, replay_registry=replay,
                         gateway_agent_id="gateway")


def test_rate_limiter_bounds_bursts():
    limiter = RateLimiter(3, 60.0)
    assert [limiter.allow(1000.0 + i) for i in range(3)] == [True] * 3
    assert limiter.allow(1003.0) is False
    assert limiter.allow(1061.0) is True  # window slid past first hits


def test_handshake_error_is_gateway_error():
    from gateway.errors import GatewayError

    assert issubclass(HandshakeError, GatewayError)

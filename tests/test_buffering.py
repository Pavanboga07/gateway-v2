"""Buffering tests: offline store, drain, expiry, order, preservation."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.identity.identity import create_identity
from backend.identity.replay import ReplayRegistry
from backend.identity.signing import sign_message
from backend.protocol.models import NexusMessage, RemoteQueryPayload
from backend.protocol.serialization import message_to_dict
from backend.protocol.types import PROTOCOL_VERSION, MessageType
from gateway.buffering import MessageBuffer
from gateway.connections import ConnectionRegistry, RateLimiter
from gateway.delivery import process_transport_message
from gateway.errors import BufferFullError
from gateway.models import GatewayConfig

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = BASE + timedelta(minutes=1)


def _envelope(sender, recipient_id, message_id="msg_001"):
    message = NexusMessage(
        protocol_version=PROTOCOL_VERSION,
        message_id=message_id,
        request_id="req_123",
        sender=sender.agent_id,
        recipient=recipient_id,
        type=MessageType.REMOTE_QUERY,
        created_at=BASE,
        expires_at=BASE + timedelta(hours=1),
        payload=RemoteQueryPayload(query="hi", requested_capabilities=[]),
        signature="",
    )
    return message_to_dict(sign_message(message, sender.private_key))


def test_offline_recipient_message_buffered():  # 21
    alice, bob = create_identity(), create_identity()
    registry, buffer, replay = (
        ConnectionRegistry(), MessageBuffer(), ReplayRegistry(),
    )
    info, _ = registry.register(alice.agent_id, alice.public_key, object(),
                                RateLimiter(1000, 60.0), NOW)
    outcome = process_transport_message(
        _envelope(alice, bob.agent_id),
        connection=info, public_key=alice.public_key, registry=registry,
        buffer=buffer, replay=replay, limiter=None, config=GatewayConfig(),
        now=NOW, mono_now=1000.0,
    )
    assert outcome.accepted is True
    assert outcome.ack.status.value == "BUFFERED"
    assert buffer.pending_count(bob.agent_id) == 1


def test_reconnect_delivers_buffered_message():  # 22
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    envelope = _envelope(alice, bob.agent_id)
    buffer.store(bob.agent_id, envelope, NOW)
    live, dropped = buffer.drain_eligible(bob.agent_id, NOW)
    assert dropped == 0
    assert live == [envelope]


def test_expired_buffered_message_not_delivered():  # 23
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    buffer.store(bob.agent_id, _envelope(alice, bob.agent_id), NOW)
    live, dropped = buffer.drain_eligible(
        bob.agent_id, BASE + timedelta(hours=2)
    )
    assert live == []
    assert dropped == 1
    assert buffer.pending_count(bob.agent_id) == 0


def test_already_delivered_message_not_delivered_twice():  # 24
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    buffer.store(bob.agent_id, _envelope(alice, bob.agent_id), NOW)
    first, _ = buffer.drain_eligible(bob.agent_id, NOW)
    assert len(first) == 1
    second, _ = buffer.drain_eligible(bob.agent_id, NOW)
    assert second == []


def test_message_id_request_id_preserved():  # 25
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    envelope = _envelope(alice, bob.agent_id, message_id="msg_007")
    buffer.store(bob.agent_id, envelope, NOW)
    live, dropped = buffer.drain_eligible(bob.agent_id, NOW)
    assert dropped == 0
    assert live[0]["message_id"] == "msg_007"
    assert live[0]["request_id"] == "req_123"
    assert live[0]["payload"] == envelope["payload"]
    assert live[0]["signature"] == envelope["signature"]


def test_buffer_full_rejects_new_messages():
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer(max_per_recipient=1)
    buffer.store(bob.agent_id, _envelope(alice, bob.agent_id, "m1"), NOW)
    with pytest.raises(BufferFullError):
        buffer.store(bob.agent_id, _envelope(alice, bob.agent_id, "m2"), NOW)


def test_expired_message_never_stored():
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    with pytest.raises(ValueError):
        buffer.store(
            bob.agent_id, _envelope(alice, bob.agent_id),
            BASE + timedelta(hours=2),
        )


def test_fifo_order_and_restore():
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    envelopes = [_envelope(alice, bob.agent_id, f"m{i}") for i in range(3)]
    for envelope in envelopes:
        buffer.store(bob.agent_id, envelope, NOW)
    live, _ = buffer.drain_eligible(bob.agent_id, NOW)
    assert [item["message_id"] for item in live] == ["m0", "m1", "m2"]
    buffer.restore_front(bob.agent_id, live)
    again, _ = buffer.drain_eligible(bob.agent_id, NOW)
    assert [item["message_id"] for item in again] == ["m0", "m1", "m2"]


def test_buffered_copy_isolated_from_mutation():
    alice, bob = create_identity(), create_identity()
    buffer = MessageBuffer()
    envelope = _envelope(alice, bob.agent_id)
    buffer.store(bob.agent_id, envelope, NOW)
    envelope["payload"]["query"] = "mutated after store"
    live, _ = buffer.drain_eligible(bob.agent_id, NOW)
    assert live[0]["payload"]["query"] == "hi"

"""Routing tests: recipient resolution and sender binding."""

from datetime import datetime, timedelta, timezone

from backend.identity.identity import create_identity
from backend.identity.replay import ReplayRegistry
from backend.identity.signing import sign_message
from backend.protocol.models import NexusMessage, RemoteQueryPayload
from backend.protocol.serialization import message_to_dict
from backend.protocol.types import PROTOCOL_VERSION, MessageType
from gateway.buffering import MessageBuffer
from gateway.connections import ConnectionRegistry, RateLimiter
from gateway.delivery import process_transport_message
from gateway.models import ConnectionInfo, ConnectionState, GatewayConfig

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
        payload=RemoteQueryPayload(
            query="What projects are you working on?",
            requested_capabilities=["memory.read"],
        ),
        signature="",
    )
    return message_to_dict(sign_message(message, sender.private_key))


def _wired(*agents):
    registry = ConnectionRegistry()
    infos = {}
    for identity in agents:
        info, _ = registry.register(
            identity.agent_id, identity.public_key, object(),
            RateLimiter(1000, 60.0), NOW,
        )
        infos[identity.agent_id] = info
    return registry, infos


def _process(envelope, sender_info, sender_key, registry, buffer=None,
             replay=None):
    return process_transport_message(
        envelope,
        connection=sender_info,
        public_key=sender_key,
        registry=registry,
        buffer=buffer or MessageBuffer(),
        replay=replay or ReplayRegistry(),
        limiter=None,
        config=GatewayConfig(),
        now=NOW,
        mono_now=1000.0,
    )


def test_message_reaches_correct_recipient():  # 7
    alice, bob = create_identity(), create_identity()
    registry, infos = _wired(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry)
    assert outcome.accepted is True
    assert outcome.target == bob.agent_id
    assert outcome.forward["payload"] == envelope["payload"]
    assert outcome.forward["signature"] == envelope["signature"]


def test_unknown_recipient_is_rejected():  # 8
    from gateway.routing import RecipientState, resolve_recipient

    alice, bob = create_identity(), create_identity()
    registry, infos = _wired(alice)
    # Unroutable ids never survive Component 1 parsing, so rejection
    # happens at the parse gate with an explicit code.
    envelope = _envelope(alice, bob.agent_id)
    envelope["recipient"] = "not a valid id!!"
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_MESSAGE")
    assert outcome.forward is None
    # The routing verdict itself distinguishes unusable ids directly.
    assert resolve_recipient("not a valid id!!", registry) is (
        RecipientState.INVALID
    )


def test_sender_identity_must_match_connection_identity():  # 9
    alice, bob = create_identity(), create_identity()
    registry, infos = _wired(alice, bob)
    envelope = _envelope(bob, alice.agent_id)  # valid sig from Bob...
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry)  # ...but sent over Alice's connection
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("SENDER_MISMATCH")


def test_recipient_routing_uses_agent_id():  # 10
    alice, bob = create_identity(), create_identity()
    registry, infos = _wired(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry)
    assert outcome.target == bob.agent_id
    assert outcome.target != "Bob"
    assert registry.lookup(outcome.target).info.agent_id == bob.agent_id


def test_offline_valid_recipient_buffers():
    alice, bob = create_identity(), create_identity()
    registry, infos = _wired(alice)  # Bob valid but offline
    buffer, replay = MessageBuffer(), ReplayRegistry()
    envelope = _envelope(alice, bob.agent_id)
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry, buffer=buffer, replay=replay)
    assert outcome.accepted is True
    assert outcome.ack.status.value == "BUFFERED"
    assert buffer.pending_count(bob.agent_id) == 1


def test_connection_info_carries_identity():
    alice = create_identity()
    info = ConnectionInfo(
        agent_id=alice.agent_id, connection_id="c1",
        state=ConnectionState.CONNECTED, connected_at=NOW,
        last_activity=NOW, public_key=alice.public_key,
    )
    assert info.agent_id == alice.agent_id
    assert info.state is ConnectionState.CONNECTED

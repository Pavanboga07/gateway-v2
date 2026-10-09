"""Delivery tests: verification outcomes, acks, failures, boundaries."""

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
from gateway.models import DeliveryStatus, GatewayConfig

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = BASE + timedelta(minutes=1)


def _envelope(sender, recipient_id, message_id="msg_001", **overrides):
    fields = {
        "protocol_version": PROTOCOL_VERSION,
        "message_id": message_id,
        "request_id": "req_123",
        "sender": sender.agent_id,
        "recipient": recipient_id,
        "type": MessageType.REMOTE_QUERY,
        "created_at": BASE,
        "expires_at": BASE + timedelta(hours=1),
        "payload": RemoteQueryPayload(
            query="What projects are you working on?",
            requested_capabilities=["memory.read"],
        ),
        "signature": "",
    }
    fields.update(overrides)
    return message_to_dict(
        sign_message(NexusMessage(**fields), sender.private_key)
    )


class _World:
    def __init__(self, *agents, config=None):
        self.registry = ConnectionRegistry()
        self.config = config or GatewayConfig()
        self.buffer = MessageBuffer(
            max_per_recipient=self.config.buffer_max_per_recipient
        )
        self.replay = ReplayRegistry()
        self.infos = {}
        for identity in agents:
            info, _ = self.registry.register(
                identity.agent_id, identity.public_key, object(),
                RateLimiter(1000, 60.0), NOW,
            )
            self.infos[identity.agent_id] = info

    def process(self, envelope, sender, sender_key=None, limiter=None,
                mono_now=1000.0, now=NOW):
        return process_transport_message(
            envelope,
            connection=self.infos[sender.agent_id],
            public_key=sender_key or sender.public_key,
            registry=self.registry,
            buffer=self.buffer,
            replay=self.replay,
            limiter=limiter,
            config=self.config,
            now=now,
            mono_now=mono_now,
        )


def test_valid_signed_message_accepted():  # 11
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    outcome = world.process(_envelope(alice, bob.agent_id), alice)
    assert outcome.accepted is True
    assert outcome.ack.status is DeliveryStatus.DELIVERED


def test_invalid_signature_rejected():  # 12
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    envelope["payload"]["query"] = "forged after signing"
    outcome = world.process(envelope, alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_SIGNATURE")


def test_tampered_message_rejected():  # 13
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    envelope["message_id"] = "msg_forged"
    outcome = world.process(envelope, alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_SIGNATURE")


def test_expired_message_rejected():  # 14
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    outcome = world.process(envelope, alice, now=BASE + timedelta(hours=2))
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("EXPIRED")


def test_replayed_message_rejected():  # 15
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    assert world.process(envelope, alice).accepted is True
    again = world.process(envelope, alice)
    assert again.accepted is False
    assert again.ack.detail.startswith("REPLAYED")


def test_signature_transplanted_message_rejected():  # 16
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    first = _envelope(alice, bob.agent_id, message_id="msg_001")
    second = _envelope(alice, bob.agent_id, message_id="msg_002")
    second["signature"] = first["signature"]
    outcome = world.process(second, alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_SIGNATURE")


def test_connected_recipient_receives_message():  # 17
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    outcome = world.process(envelope, alice)
    assert outcome.forward == envelope
    assert outcome.forward["message_id"] == "msg_001"
    assert outcome.forward["request_id"] == "req_123"
    assert outcome.forward["signature"] == envelope["signature"]


def test_delivery_acknowledgement_generated():  # 18
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    outcome = world.process(_envelope(alice, bob.agent_id), alice)
    ack = outcome.ack.to_dict()
    assert set(ack) == {"type", "message_id", "request_id", "status", "detail"}
    assert ack["type"] == "ACK"
    assert (ack["message_id"], ack["request_id"]) == ("msg_001", "req_123")
    assert ack["status"] == "DELIVERED"


def test_delivery_failure_reported():  # 19
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob, config=GatewayConfig(buffer_max_per_recipient=1))
    world.buffer.store(bob.agent_id, _envelope(alice, bob.agent_id, "m0"), NOW)
    world.registry.unregister(
        bob.agent_id,
        world.registry.lookup(bob.agent_id).info.connection_id,
    )
    outcome = world.process(_envelope(alice, bob.agent_id, "m1"), alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("BUFFER_FULL")


def test_gateway_does_not_report_task_completion():  # 20
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    outcome = world.process(_envelope(alice, bob.agent_id), alice)
    ack = outcome.ack.to_dict()
    for forbidden in ("result", "answer", "completed", "output", "response"):
        assert forbidden not in ack
    assert ack["status"] in ("DELIVERED", "BUFFERED", "FAILED")


def test_oversized_message_rejected():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob,
                   config=GatewayConfig(max_message_size=256))
    envelope = _envelope(alice, bob.agent_id)
    outcome = world.process(envelope, alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("MESSAGE_TOO_LARGE")


def test_rate_limited_connection_rejected():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    limiter = RateLimiter(1, 60.0)
    first = world.process(_envelope(alice, bob.agent_id, "r1"), alice,
                          limiter=limiter, mono_now=500.0)
    assert first.accepted is True
    second = world.process(_envelope(alice, bob.agent_id, "r2"), alice,
                           limiter=limiter, mono_now=500.0)
    assert second.accepted is False
    assert second.ack.detail.startswith("RATE_LIMITED")


def test_malformed_wire_rejected():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    outcome = world.process(["not", "a", "dict"], alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_MESSAGE")


def test_forgery_does_not_consume_replay_state():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    forged = _envelope(alice, bob.agent_id, "m9")
    forged["payload"]["query"] = "forged after signing"
    outcome = world.process(forged, alice)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_SIGNATURE")
    legitimate = _envelope(alice, bob.agent_id, "m9")
    again = world.process(legitimate, alice)
    assert again.accepted is True
    assert again.ack.status is DeliveryStatus.DELIVERED


def test_replay_after_expiration_reports_expiry():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id, "m9")
    assert world.process(envelope, alice).accepted is True
    late = world.process(envelope, alice, now=BASE + timedelta(hours=2))
    assert late.accepted is False
    assert late.ack.detail.startswith("EXPIRED")


def test_acceptance_immutable_against_caller_mutation():
    alice, bob = create_identity(), create_identity()
    world = _World(alice, bob)
    envelope = _envelope(alice, bob.agent_id, "live")
    outcome = world.process(envelope, alice)
    envelope["payload"]["query"] = "mutated after acceptance"
    envelope["payload"]["requested_capabilities"].append("admin.write")
    envelope["signature"] = "mutated"
    assert outcome.forward["payload"]["query"].startswith("What projects")
    assert outcome.forward["payload"]["requested_capabilities"] == [
        "memory.read"
    ]
    assert outcome.forward["signature"] != "mutated"
    world.registry.unregister(
        bob.agent_id,
        world.registry.lookup(bob.agent_id).info.connection_id,
    )
    buffered = world.process(_envelope(alice, bob.agent_id, "off"), alice)
    assert buffered.ack.status is DeliveryStatus.BUFFERED
    stored, _ = world.buffer.drain_eligible(bob.agent_id, NOW)
    assert stored[0]["payload"]["query"].startswith("What projects")

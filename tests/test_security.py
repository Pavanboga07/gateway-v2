"""Security tests: spoofing, keys, sizes, auth, architectural isolation."""

import asyncio
import ast
import json
import pathlib
import sys
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
from gateway.models import GatewayConfig

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = BASE + timedelta(minutes=1)
GATEWAY_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent / "gateway"


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


def _world(*agents, config=None):
    registry = ConnectionRegistry()
    infos = {}
    for identity in agents:
        info, _ = registry.register(
            identity.agent_id, identity.public_key, object(),
            RateLimiter(1000, 60.0), NOW,
        )
        infos[identity.agent_id] = info
    return registry, infos


def _process(envelope, info, key, registry, **over):
    params = {
        "connection": info, "public_key": key, "registry": registry,
        "buffer": MessageBuffer(), "replay": ReplayRegistry(),
        "limiter": None, "config": GatewayConfig(), "now": NOW,
        "mono_now": 1000.0,
    }
    params.update(over)
    return process_transport_message(envelope, **params)


def test_sender_spoofing_rejected():  # 30
    alice, bob = create_identity(), create_identity()
    registry, infos = _world(alice, bob)
    forged = _envelope(bob, alice.agent_id)  # Bob's valid signature...
    outcome = _process(forged, infos[alice.agent_id], alice.public_key,
                       registry)  # ...over Alice's connection
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("SENDER_MISMATCH")


def test_unknown_public_key_rejected():  # 31
    alice, intruder = create_identity(), create_identity()
    registry, infos = _world(alice)
    # Attacker signs as Alice but owns a different key: the gateway
    # verifies with Alice's registered key, so this must fail.
    impostor = _envelope(intruder, alice.agent_id)
    impostor["sender"] = alice.agent_id
    outcome = _process(impostor, infos[alice.agent_id], alice.public_key,
                       registry)
    assert outcome.accepted is False


def test_malformed_signature_rejected():  # 32
    alice, bob = create_identity(), create_identity()
    registry, infos = _world(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    envelope["signature"] = "!!!not-base64!!!"
    outcome = _process(envelope, infos[alice.agent_id], alice.public_key,
                       registry)
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("INVALID_SIGNATURE")


def test_oversized_message_rejected():  # 33
    alice, bob = create_identity(), create_identity()
    registry, infos = _world(alice, bob)
    envelope = _envelope(alice, bob.agent_id)
    outcome = _process(
        envelope, infos[alice.agent_id], alice.public_key, registry,
        config=GatewayConfig(max_message_size=64),
    )
    assert outcome.accepted is False
    assert outcome.ack.detail.startswith("MESSAGE_TOO_LARGE")


class _StubSocket:
    """Duck-typed stand-in for a websocket (records sends)."""

    def __init__(self, incoming):
        self._incoming = list(incoming)
        self.sent = []
        self.closed = False

    def __aiter__(self):
        async def gen():
            for frame in self._incoming:
                yield frame
        return gen()

    async def send(self, text):
        self.sent.append(json.loads(text))

    async def recv(self):
        if not self._incoming:
            raise _Closed()
        return self._incoming.pop(0)

    async def close(self):
        self.closed = True


class _Closed(Exception):
    pass


def test_unauthenticated_connection_cannot_send():  # 34
    from gateway.app import GatewayServer

    server = GatewayServer()
    envelope = {"payload": "x"}
    socket = _StubSocket(
        [json.dumps({"type": "MESSAGE", "message": envelope})]
    )

    async def scenario():
        await server.handle_connection(socket)

    asyncio.run(scenario())
    assert socket.sent, "expected an auth error frame"
    assert socket.sent[0]["type"] == "ERROR"
    assert socket.sent[0]["code"] == "AUTH_REQUIRED"
    assert len(server.registry) == 0


def _gateway_imports():
    modules = set()
    for path in GATEWAY_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    modules.add(node.module.split(".")[0])
    return modules


def test_gateway_imports_no_langgraph():  # 35
    assert "langgraph" not in _gateway_imports()


def test_gateway_imports_no_langchain():  # 36
    assert "langchain" not in _gateway_imports()


def test_gateway_imports_no_mcp():  # 37
    assert "mcp" not in _gateway_imports()


def test_gateway_imports_no_frontend_code():  # 38
    modules = _gateway_imports()
    assert "frontend" not in modules
    assert not any("frontend" in m for m in modules)


def test_gateway_does_not_access_agent_memory():  # 39
    modules = _gateway_imports()
    assert "memory" not in modules
    assert not any("memory" in m for m in modules)
    import gateway.app  # noqa: F401  (runtime: forbidden libs never load)

    # NOTE: no sys.modules assertion here by design. Component 7
    # legitimately uses LangGraph/LangChain, so those libraries are
    # present in any full-suite process; the AST import scan above is
    # the meaningful isolation proof for gateway sources.
    for loaded in ("mcp", "frontend", "memory"):
        assert loaded not in sys.modules


def test_gateway_has_no_authorization_logic():  # 40
    forbidden = (
        "REMOTE_QUERY", "APPROVAL", "authoriz", "approv", "capabilit",
        "allowed", "deny", "permit", "forbid", "memory.read",
    )
    hits = []
    for path in GATEWAY_ROOT.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for word in forbidden:
            if word in text:
                hits.append(f"{path.name}:{word}")
    assert hits == [], f"business-logic leakage: {hits}"

"""Integration tests: real server, real WebSockets, real signatures.

Covers connection reliability (26-29) plus the full online and
offline/reconnect delivery flows with end-to-end field preservation.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed

from backend.identity.identity import create_identity
from backend.identity.signing import sign_message
from backend.identity.verification import verify_message
from backend.protocol.models import (
    ConnectRequestPayload,
    NexusMessage,
    RemoteQueryPayload,
)
from backend.protocol.serialization import message_to_dict
from backend.protocol.types import (
    PROTOCOL_VERSION,
    MessageType,
    generate_message_id,
    generate_request_id,
)
from gateway.app import GatewayServer, utcnow


def _signed_envelope(sender, recipient_id, now, message_id=None, query="hi"):
    message = NexusMessage(
        protocol_version=PROTOCOL_VERSION,
        message_id=message_id or generate_message_id(),
        request_id=generate_request_id(),
        sender=sender.agent_id,
        recipient=recipient_id,
        type=MessageType.REMOTE_QUERY,
        created_at=now,
        expires_at=now + timedelta(minutes=30),
        payload=RemoteQueryPayload(query=query, requested_capabilities=[]),
        signature="",
    )
    return message_to_dict(sign_message(message, sender.private_key))


def _handshake_frame(identity, now):
    message = NexusMessage(
        protocol_version=PROTOCOL_VERSION,
        message_id=generate_message_id(),
        request_id=generate_request_id(),
        sender=identity.agent_id,
        recipient="gateway",
        type=MessageType.CONNECT_REQUEST,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        payload=ConnectRequestPayload(agent_id=identity.agent_id),
        signature="",
    )
    return {
        "type": "HANDSHAKE",
        "identity": identity.public_identity().to_dict(),
        "message": message_to_dict(
            sign_message(message, identity.private_key)
        ),
    }


async def _next(ws, timeout=10.0):
    return json.loads(await asyncio.wait_for(ws.recv(), timeout))


async def _started_server():
    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    return server, f"ws://127.0.0.1:{port}"


async def _connect(url, identity):
    ws = await ws_connect(url)
    await ws.send(json.dumps(_handshake_frame(identity, utcnow())))
    welcome = await _next(ws)
    assert welcome["type"] == "WELCOME", welcome
    assert welcome["agent_id"] == identity.agent_id
    return ws


async def _wait_until(predicate, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


@pytest.mark.asyncio
async def test_disconnect_handled():  # 26
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        assert server.presence() == {alice.agent_id: "CONNECTED"}
        await ws.close()
        assert await _wait_until(lambda: server.presence() == {})
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_reconnect_handled():  # 27
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        first = server.registry.lookup(alice.agent_id).info.connection_id
        await ws.close()
        assert await _wait_until(lambda: server.presence() == {})
        ws2 = await _connect(url, alice)
        try:
            second = server.registry.lookup(alice.agent_id).info.connection_id
            assert first != second
            assert server.presence() == {alice.agent_id: "CONNECTED"}
        finally:
            await ws2.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_buffered_messages_survive_reconnect():  # 28
    server, url = await _started_server()
    try:
        alice, bob = create_identity(), create_identity()
        ws_bob = await _connect(url, bob)
        await ws_bob.close()
        assert await _wait_until(lambda: server.presence() == {})
        ws_alice = await _connect(url, alice)
        try:
            envelope = _signed_envelope(alice, bob.agent_id, utcnow())
            await ws_alice.send(
                json.dumps({"type": "MESSAGE", "message": envelope})
            )
            ack = await _next(ws_alice)
            assert ack["status"] == "BUFFERED"
            ws_bob2 = await _connect(url, bob)
            try:
                delivered = await _next(ws_bob2)
                assert delivered["type"] == "DELIVER"
                assert delivered["message"]["message_id"] == (
                    envelope["message_id"]
                )
            finally:
                await ws_bob2.close()
        finally:
            await ws_alice.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_stale_connection_cleanup():  # 29
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        try:
            old = utcnow() - timedelta(seconds=3600)
            server.registry.touch(alice.agent_id, old)
            removed = server.registry.sweep_stale(utcnow(), stale_after_s=300.0)
            assert [info.agent_id for info, _ in removed] == [alice.agent_id]
            assert server.presence() == {}
        finally:
            await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_online_delivery_end_to_end():
    server, url = await _started_server()
    try:
        alice, bob = create_identity(), create_identity()
        ws_alice = await _connect(url, alice)
        ws_bob = await _connect(url, bob)
        try:
            envelope = _signed_envelope(
                alice, bob.agent_id, utcnow(), query="projects?"
            )
            await ws_alice.send(
                json.dumps({"type": "MESSAGE", "message": envelope})
            )
            ack = await _next(ws_alice)
            assert ack["status"] == "DELIVERED"
            assert ack["message_id"] == envelope["message_id"]
            delivered = await _next(ws_bob)
            assert delivered["type"] == "DELIVER"
            received = delivered["message"]
            # 6-9: unchanged transport of every signed field.
            assert received["message_id"] == envelope["message_id"]
            assert received["request_id"] == envelope["request_id"]
            assert received["payload"] == envelope["payload"]
            assert received["signature"] == envelope["signature"]
            assert received == envelope
            # 5: B independently verifies with A's public key.
            from backend.protocol.serialization import message_from_dict

            result = verify_message(
                message_from_dict(received), alice.public_key,
                now=utcnow(),
            )
            assert result.agent_id == alice.agent_id
        finally:
            await ws_alice.close()
            await ws_bob.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_oversized_wire_frame_dropped():
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        try:
            await ws.send("x" * 2_000_000)
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 10)
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_wire_level_handshake_replay_rejected():
    server, url = await _started_server()
    try:
        alice = create_identity()
        frame = _handshake_frame(alice, utcnow())
        first = await ws_connect(url)
        try:
            await first.send(json.dumps(frame))
            assert (await _next(first))["type"] == "WELCOME"
            replay = await ws_connect(url)
            try:
                await replay.send(json.dumps(frame))
                answer = await _next(replay)
                assert answer["type"] == "ERROR"
                assert answer["code"] == "HANDSHAKE_FAILED"
            finally:
                await replay.close()
            assert server.presence() == {alice.agent_id: "CONNECTED"}
        finally:
            await first.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_same_agent_dual_connection_race():
    server, url = await _started_server()
    try:
        alice, bob = create_identity(), create_identity()
        await _connect(url, bob)
        first = await ws_connect(url)
        await first.send(json.dumps(_handshake_frame(alice, utcnow())))
        assert (await _next(first))["type"] == "WELCOME"
        second = await ws_connect(url)
        await second.send(json.dumps(_handshake_frame(alice, utcnow())))
        assert (await _next(second))["type"] == "WELCOME"
        try:
            # The server closes the superseded socket...
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(first.recv(), 10)
            # ...while the new one stays fully functional.
            envelope = _signed_envelope(alice, bob.agent_id, utcnow())
            await second.send(
                json.dumps({"type": "MESSAGE", "message": envelope})
            )
            ack = await _next(second)
            assert ack["status"] == "DELIVERED"
            # Closing the dead socket must not evict the live registration.
            try:
                await first.close()
            except Exception:
                pass
            await asyncio.sleep(0.2)
            assert server.registry.is_connected(alice.agent_id)
            envelope2 = _signed_envelope(alice, bob.agent_id, utcnow())
            await second.send(
                json.dumps({"type": "MESSAGE", "message": envelope2})
            )
            assert (await _next(second))["status"] == "DELIVERED"
        finally:
            await second.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_restart_loses_in_memory_state():
    first, url = await _started_server()
    try:
        alice, bob = create_identity(), create_identity()
        ws_alice = await _connect(url, alice)
        try:
            envelope = _signed_envelope(alice, bob.agent_id, utcnow())
            await ws_alice.send(
                json.dumps({"type": "MESSAGE", "message": envelope})
            )
            assert (await _next(ws_alice))["status"] == "BUFFERED"
            assert first.buffer.pending_count(bob.agent_id) == 1
        finally:
            await ws_alice.close()
    finally:
        await first.stop()
    # A restarted process starts empty: no connections, buffer, or replay.
    second, url2 = await _started_server()
    try:
        assert second.buffer.pending_count(bob.agent_id) == 0
        ws_bob = await _connect(url2, bob)
        try:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(ws_bob.recv(), 1.0)
        finally:
            await ws_bob.close()
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_janitor_starts_and_stops_cleanly():
    from gateway.app import GatewayServer as Server

    server = Server("127.0.0.1", 0)
    assert server._janitor_task is None
    await server.start()
    try:
        task = server._janitor_task
        assert task is not None and not task.done()
        await server.start()  # second start must not spawn a second task
        assert server._janitor_task is task
    finally:
        await server.stop()
    assert task.done() and task.cancelled()
    lingering = [
        task_
        for task_ in asyncio.all_tasks()
        if task_ is not asyncio.current_task()
        and "_janitor_loop" in getattr(task_.get_coro(), "__qualname__", "")
    ]
    assert lingering == []


@pytest.mark.asyncio
async def test_janitor_reclaims_stale_state():
    from gateway.app import GatewayServer as Server

    server = Server("127.0.0.1", 0)
    alice = create_identity()
    old = utcnow() - timedelta(seconds=3600)
    server.registry.register(
        alice.agent_id, alice.public_key, object(), None, old
    )
    server.replay.record("msg_stale", old)
    server.buffer.store(
        alice.agent_id,
        {
            "message_id": "msg_old",
            "expires_at": (old + timedelta(seconds=10)).isoformat(),
        },
        old,
    )
    result = server.run_cleanup()
    assert result["stale_connections"] == [alice.agent_id]
    assert len(result["stale_transports"]) == 1
    assert result["purged_replay"] == 1
    assert result["dropped_buffered"] == 1
    assert len(server.registry) == 0
    assert server.replay.has_seen("msg_stale", utcnow()) is False


@pytest.mark.asyncio
async def test_janitor_runs_periodically():
    from gateway.app import GatewayServer as Server
    from gateway.models import GatewayConfig

    server = Server(
        "127.0.0.1", 0, GatewayConfig(stale_after_s=0.05)
    )
    await server.start()
    try:
        server.replay.record(
            "msg_old", utcnow() - timedelta(seconds=1)
        )
        await asyncio.sleep(0.4)
        assert len(server.replay) == 0  # background pass purged it
        alice = create_identity()  # server still serves normally
        ws = await _connect(f"ws://127.0.0.1:{server.port}", alice)
        await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_frame_with_id_gets_correlated_failed_ack():
    server, url = await _started_server()
    try:
        alice, bob = create_identity(), create_identity()
        ws = await _connect(url, alice)
        try:
            envelope = _signed_envelope(
                alice, bob.agent_id, utcnow(),
                message_id="msg_uf1", query="unused",
            )
            await ws.send(json.dumps({
                "type": "PING",
                "message": envelope,
            }))
            reply = await _next(ws)
            assert reply["type"] == "ACK"
            assert reply["message_id"] == "msg_uf1"
            assert reply["request_id"] == envelope["request_id"]
            assert reply["status"] == "FAILED"
            assert reply["detail"].startswith("UNKNOWN_FRAME")
            # The connection stays usable after the rejection.
            live = _signed_envelope(alice, bob.agent_id, utcnow())
            await ws.send(
                json.dumps({"type": "MESSAGE", "message": live})
            )
            assert (await _next(ws))["status"] == "BUFFERED"
        finally:
            await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_frame_without_id_gets_error():
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        try:
            await ws.send(json.dumps({"type": "PING"}))
            reply = await _next(ws)
            assert reply["type"] == "ERROR"
            assert reply["code"] == "UNKNOWN_FRAME"
            assert "message_id" not in reply
        finally:
            await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_malformed_json_frame_gets_error():
    server, url = await _started_server()
    try:
        alice = create_identity()
        ws = await _connect(url, alice)
        try:
            await ws.send("{not json")
            reply = await _next(ws)
            assert reply["type"] == "ERROR"
            assert reply["code"] == "MALFORMED_FRAME"
        finally:
            await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_oversized_message_ack_carries_real_id():
    import json as _json

    from gateway.models import GatewayConfig

    server = GatewayServer(
        "127.0.0.1", 0, GatewayConfig(max_message_size=4096)
    )
    await server.start()
    try:
        alice, bob = create_identity(), create_identity()
        ws = await _connect(f"ws://127.0.0.1:{server.port}", alice)
        try:
            envelope = _signed_envelope(
                alice, bob.agent_id, utcnow(),
                message_id="msg_big1", query="x" * 8192,
            )
            inner = len(_json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8"))
            assert inner > 4096
            await ws.send(_json.dumps(
                {"type": "MESSAGE", "message": envelope}))
            ack = await _next(ws)
            assert ack["type"] == "ACK"
            assert ack["message_id"] == "msg_big1"
            assert ack["status"] == "FAILED"
            assert ack["detail"].startswith("MESSAGE_TOO_LARGE")
        finally:
            await ws.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rate_limited_ack_carries_real_id():
    from gateway.models import GatewayConfig

    server = GatewayServer(
        "127.0.0.1", 0,
        GatewayConfig(rate_limit_max=1, rate_limit_window_s=60.0),
    )
    await server.start()
    try:
        alice, bob = create_identity(), create_identity()
        ws = await _connect(f"ws://127.0.0.1:{server.port}", alice)
        try:
            first = _signed_envelope(
                alice, bob.agent_id, utcnow(), message_id="msg_rl1")
            await ws.send(json.dumps(
                {"type": "MESSAGE", "message": first}))
            assert (await _next(ws))["status"] == "BUFFERED"
            second = _signed_envelope(
                alice, bob.agent_id, utcnow(), message_id="msg_rl2")
            await ws.send(json.dumps(
                {"type": "MESSAGE", "message": second}))
            ack = await _next(ws)
            assert ack["type"] == "ACK"
            assert ack["message_id"] == "msg_rl2"
            assert ack["status"] == "FAILED"
            assert ack["detail"].startswith("RATE_LIMITED")
        finally:
            await ws.close()
    finally:
        await server.stop()

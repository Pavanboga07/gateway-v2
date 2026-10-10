"""Health endpoint: plain HTTP on the WebSocket port.

Render and other hosts probe HTTP even though this process speaks
WebSocket. ``GET /healthz`` must answer 200 JSON without touching the
A2A path; every other request — including WebSocket upgrades — must
fall through to the normal handshake.
"""

import asyncio
import json
import urllib.error
import urllib.request

import pytest
from websockets.asyncio.client import connect as ws_connect
from websockets.datastructures import Headers
from websockets.http11 import Request

from backend.identity.identity import create_identity
from gateway.app import HEALTHZ_PATH, GatewayServer, health_check


def _http_get(url, method="GET", timeout=10.0):
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


async def _http_get_async(url, method="GET", timeout=10.0):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: _http_get(url, method=method, timeout=timeout))


@pytest.mark.asyncio
async def test_healthz_answers_200_json():
    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    try:
        status, body = await _http_get_async(
            f"http://127.0.0.1:{port}{HEALTHZ_PATH}")
        assert status == 200, (status, body)
        assert json.loads(body) == {
            "status": "ok", "service": "nexus-gateway"}
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_head_probe_does_not_harm_server():
    # websockets 16.1 parses only GET at the HTTP layer, so HEAD dies
    # inside the library before process_request runs (logged handshake
    # noise, connection closed, no A2A message). The server must stay
    # up and keep serving health + WebSocket afterwards.
    from websockets.asyncio.client import connect as ws_connect

    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    try:
        try:
            await _http_get_async(
                f"http://127.0.0.1:{port}{HEALTHZ_PATH}", method="HEAD")
        except Exception:
            pass
        status, body = await _http_get_async(
            f"http://127.0.0.1:{port}{HEALTHZ_PATH}")
        assert status == 200, (status, body)
        assert json.loads(body) == {
            "status": "ok", "service": "nexus-gateway"}
        async with ws_connect(f"ws://127.0.0.1:{port}"):
            pass
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_http_path_is_not_a_health_reply():
    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    try:
        # Plain HTTP to a non-health path must NOT get the health body:
        # the handshake fails instead (no A2A message is fabricated).
        status, body = await _http_get_async(
            f"http://127.0.0.1:{port}/")
        assert status != 200 or body != (
            b'{"status":"ok","service":"nexus-gateway"}'
        ), (status, body)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_websocket_still_works_alongside_health():
    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    try:
        status, _ = await _http_get_async(
            f"http://127.0.0.1:{port}{HEALTHZ_PATH}")
        assert status == 200
        identity = create_identity()
        assert identity.agent_id
        async with ws_connect(f"ws://127.0.0.1:{port}"):
            pass  # entering the context proves the handshake succeeded
    finally:
        await server.stop()


def test_health_check_unit_interceptor():
    """The interceptor only answers the exact path (query stripped)."""

    async def run():
        ok = await health_check(
            object(),
            Request(path="/healthz", headers=Headers({"Host": "x"})))
        assert ok is not None and ok.status_code == 200
        assert json.loads(ok.body) == {
            "status": "ok", "service": "nexus-gateway"}
        assert await health_check(
            object(),
            Request(path="/", headers=Headers({"Host": "x"}))) is None
        assert await health_check(
            object(),
            Request(path="/healthz?x=1", headers=Headers({"Host": "x"}))
        ) is not None

    asyncio.run(run())

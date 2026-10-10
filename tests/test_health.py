"""Health endpoint: plain HTTP on the WebSocket port.

Render and other hosts probe HTTP even though this process speaks
WebSocket. ``/healthz`` answers 200 JSON without touching the A2A
path; other plain-HTTP requests get a clean 404 (never a handshake
traceback); WebSocket upgrades fall through to normal authentication.
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
from gateway.app import HEALTHZ_PATH, GatewayServer, handle_http_request


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
async def test_head_probes_answered_cleanly():
    # HEAD /, HEAD /healthz: clean statuses, no health-body leak on /,
    # and the server keeps serving afterwards.
    from websockets.asyncio.client import connect as ws_connect

    server = GatewayServer("127.0.0.1", 0)
    port = await server.start()
    try:
        status, _ = await _http_get_async(
            f"http://127.0.0.1:{port}{HEALTHZ_PATH}", method="HEAD")
        assert status == 200, status
        status, _ = await _http_get_async(
            f"http://127.0.0.1:{port}/", method="HEAD")
        assert status == 404, status
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
    """Exact path answered; plain HTTP 404s; upgrades fall through."""

    async def run():
        ok = await handle_http_request(
            object(),
            Request(path="/healthz", headers=Headers({"Host": "x"})))
        assert ok is not None and ok.status_code == 200
        assert json.loads(ok.body) == {
            "status": "ok", "service": "nexus-gateway"}
        plain = await handle_http_request(
            object(),
            Request(path="/", headers=Headers({"Host": "x"})))
        assert plain is not None and plain.status_code == 404
        assert await handle_http_request(
            object(),
            Request(path="/healthz?x=1", headers=Headers({"Host": "x"}))
        ) is not None
        upgrade = await handle_http_request(
            object(),
            Request(path="/", headers=Headers({
                "Host": "x", "Upgrade": "websocket",
                "Connection": "Upgrade",
            })),
        )
        assert upgrade is None

    asyncio.run(run())

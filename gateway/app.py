"""Gateway WebSocket process (asyncio + ``websockets``).

Wire frames (all JSON objects with a ``type`` field):

- agent → gateway ``HANDSHAKE`` {identity, message} → ``WELCOME`` | ``ERROR``
- agent → gateway ``MESSAGE`` {message} → ``ACK`` (DELIVERED/BUFFERED/FAILED)
- gateway → agent ``DELIVER`` {message} (live delivery or reconnect drain)
- gateway → agent ``ERROR`` {code, message} (safe codes only)

The process owns sockets and scheduling only. All trust decisions live
in ``connections`` (handshake), ``delivery`` (pipeline), and Components
1–2. Forwarded envelopes are never mutated: the gateway transmits the
validated content exactly as authenticated.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from backend.identity.replay import ReplayRegistry

from .buffering import MessageBuffer
from .connections import ConnectionRegistry, RateLimiter, verify_handshake
from .delivery import TransportOutcome, extract_envelope_ids
from .delivery import process_transport_message
from .errors import AuthenticationError, HandshakeError, error_frame
from .models import ConnectionState, DeliveryStatus, GatewayConfig


def utcnow() -> datetime:
    """Timezone-aware UTC clock for message timestamps."""
    return datetime.now(timezone.utc)


class GatewayServer:
    """One gateway process: presence, routing, delivery, buffering."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        config: GatewayConfig | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self.config = config or GatewayConfig()
        self.registry = ConnectionRegistry()
        self.buffer = MessageBuffer(
            max_per_recipient=self.config.buffer_max_per_recipient
        )
        self.replay = ReplayRegistry()
        self._server: Any = None
        self._bound_port: int = port
        self._janitor_task: Any = None

    @property
    def port(self) -> int:
        """Actual bound port (useful with ephemeral ``port=0``)."""
        return self._bound_port

    async def start(self) -> int:
        """Begin listening; returns the bound port."""
        self._server = await serve(
            self.handle_connection,
            self._host,
            self._port,
            max_size=self.config.max_message_size + 8192,
        )
        sockets = getattr(self._server, "sockets", None) or []
        if sockets:
            self._bound_port = sockets[0].getsockname()[1]
        if self._janitor_task is None:
            self._janitor_task = asyncio.get_running_loop().create_task(
                self._janitor_loop()
            )
        return self._bound_port

    async def stop(self) -> None:
        """Stop listening; established handlers finish via cleanup."""
        task, self._janitor_task = self._janitor_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def run_cleanup(self, now: datetime | None = None) -> dict[str, Any]:
        """Run one cleanup pass; return what was reclaimed.

        Sweeps idle connections, purges expired replay ids, and drops
        expired buffered mail. Synchronous and side-effect-scoped so
        tests can drive it deterministically; the background janitor
        calls it on a period of ``stale_after_s``. Returned stale
        transports are left for the caller to close.
        """
        current = now if now is not None else utcnow()
        stale = self.registry.sweep_stale(current, self.config.stale_after_s)
        return {
            "stale_connections": [info.agent_id for info, _ in stale],
            "stale_transports": [transport for _, transport in stale],
            "purged_replay": self.replay.purge_expired(current),
            "dropped_buffered": self.buffer.drop_expired(current),
        }

    async def _janitor_loop(self) -> None:
        """Periodic cleanup; cancelled by :meth:`stop`, never blocks mail."""
        while True:
            await asyncio.sleep(self.config.stale_after_s)
            result = self.run_cleanup()
            for transport in result["stale_transports"]:
                try:
                    await transport.close()
                except Exception:
                    pass

    async def serve_forever(self) -> None:
        """Run until cancelled (entry point for the real process)."""
        await self.start()
        try:
            await asyncio.get_event_loop().create_future()
        finally:
            await self.stop()

    async def _send(self, transport: Any, frame: dict[str, Any]) -> bool:
        """Best-effort frame transmit; False means delivery failed.

        Any transport failure uniformly means "not delivered" — the
        caller requeues. Deliberately broad: sockets fail in varied
        ways and the response (buffer + BUFFERED ack) is identical.
        """
        try:
            await transport.send(json.dumps(frame))
        except Exception:
            return False
        return True

    async def _drain_to(
        self, agent_id: str, transport: Any, now: datetime
    ) -> tuple[int, int]:
        """Deliver buffered envelopes in order; requeue on first failure.

        Returns ``(sent, dropped_expired)``. Expired entries are never
        transmitted; unsent live entries return to the queue head in
        original order.
        """
        pending, dropped = self.buffer.drain_eligible(agent_id, now)
        for index, envelope in enumerate(pending):
            if await self._send(transport, {"type": "DELIVER", "message": envelope}):
                continue
            self.buffer.restore_front(agent_id, pending[index:])
            return index, dropped
        return len(pending), dropped

    async def handle_connection(self, transport: Any) -> None:
        """Lifecycle for one agent socket: handshake → frames → cleanup."""
        agent_id: Optional[str] = None
        connection_id: Optional[str] = None
        try:
            try:
                raw = await asyncio.wait_for(
                    transport.recv(), timeout=self.config.handshake_timeout_s
                )
            except (asyncio.TimeoutError, ConnectionClosed):
                return
            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                await self._send(
                    transport, error_frame(AuthenticationError("handshake required"))
                )
                return
            if not isinstance(frame, dict) or frame.get("type") != "HANDSHAKE":
                await self._send(
                    transport, error_frame(AuthenticationError("handshake required"))
                )
                return
            try:
                accept = verify_handshake(
                    frame,
                    now=utcnow(),
                    replay_registry=self.replay,
                    gateway_agent_id=self.config.gateway_agent_id,
                )
            except HandshakeError as exc:
                await self._send(transport, error_frame(exc))
                return
            limiter = RateLimiter(
                self.config.rate_limit_max, self.config.rate_limit_window_s
            )
            info, replaced = self.registry.register(
                accept.agent_id, accept.public_key, transport, limiter, utcnow()
            )
            agent_id, connection_id = info.agent_id, info.connection_id
            if replaced is not None:
                try:
                    await replaced.close()
                except Exception:
                    pass
            await self._send(
                transport,
                {
                    "type": "WELCOME",
                    "agent_id": agent_id,
                    "connection_id": connection_id,
                },
            )
            await self._drain_to(agent_id, transport, utcnow())
            async for raw in transport:
                self.registry.touch(agent_id, utcnow())
                try:
                    frame = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    await self._send(
                        transport,
                        {"type": "ERROR", "code": "MALFORMED_FRAME",
                         "message": "frame must be JSON"},
                    )
                    continue
                if not isinstance(frame, dict):
                    await self._send(
                        transport,
                        {"type": "ERROR", "code": "MALFORMED_FRAME",
                         "message": "frame must be a JSON object"},
                    )
                    continue
                if frame.get("type") != "MESSAGE":
                    await self._send_unknown_frame(
                        transport, frame,
                    )
                    continue
                await self._handle_message_frame(
                    frame, agent_id, info, transport
                )
        finally:
            if agent_id is not None and connection_id is not None:
                self.registry.unregister(agent_id, connection_id)

    async def _send_unknown_frame(
        self, transport: Any, frame: dict[str, Any]
    ) -> None:
        """Answer a non-MESSAGE frame: correlated FAILED ack if possible.

        When the frame carries a ``message`` envelope with extractable
        ids, the sender gets a terminal FAILED ack addressed to its
        exact pending waiter (status FAILED, never success) instead of
        an uncorrelated ERROR that would leave the waiter to time out.
        Frames with no recoverable id keep the previous ERROR reply.
        """
        message_id, request_id = extract_envelope_ids(frame.get("message"))
        if message_id == "unknown":
            await self._send(
                transport,
                {"type": "ERROR", "code": "UNKNOWN_FRAME",
                 "message": "unknown frame type"},
            )
            return
        await self._send(
            transport,
            {
                "type": "ACK",
                "message_id": message_id,
                "request_id": request_id,
                "status": DeliveryStatus.FAILED.value,
                "detail": "UNKNOWN_FRAME: unknown frame type",
            },
        )

    async def _handle_message_frame(
        self, frame: dict[str, Any], agent_id: str, info: Any, transport: Any
    ) -> None:
        """Run one MESSAGE frame through the pipeline and answer."""
        entry = self.registry.lookup(agent_id)
        if entry is None:
            await self._send(
                transport, error_frame(AuthenticationError("not connected"))
            )
            return
        outcome: TransportOutcome = process_transport_message(
            frame.get("message"),
            connection=entry.info,
            public_key=entry.info.public_key,
            registry=self.registry,
            buffer=self.buffer,
            replay=self.replay,
            limiter=entry.limiter,
            config=self.config,
            now=utcnow(),
            mono_now=time.monotonic(),
        )
        if outcome.forward is not None and outcome.target is not None:
            target = self.registry.lookup(outcome.target)
            if target is None or target.transport is None:
                self.buffer.restore_front(outcome.target, [outcome.forward])
                buffered = outcome.ack.to_dict()
                buffered["status"] = DeliveryStatus.BUFFERED.value
                buffered["detail"] = "recipient disconnected; buffered"
                await self._send(transport, buffered)
                return
            if await self._send(
                target.transport,
                {"type": "DELIVER", "message": outcome.forward},
            ):
                await self._send(transport, outcome.ack.to_dict())
            else:
                self.buffer.restore_front(outcome.target, [outcome.forward])
                buffered = outcome.ack.to_dict()
                buffered["status"] = DeliveryStatus.BUFFERED.value
                buffered["detail"] = "recipient send failed; buffered"
                await self._send(transport, buffered)
            return
        await self._send(transport, outcome.ack.to_dict())

    def presence(self) -> dict[str, str]:
        """Agent id → connection state (for tests and operators)."""
        return {
            agent_id: ConnectionState.CONNECTED.value
            for agent_id in self.registry.connected_agents()
        }


def main(argv: list[str] | None = None) -> None:
    """Run one gateway process (defaults bind localhost only)."""
    parser = argparse.ArgumentParser(description="Nexus Gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    asyncio.run(GatewayServer(args.host, args.port).serve_forever())


if __name__ == "__main__":
    main()

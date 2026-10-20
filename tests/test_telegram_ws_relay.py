"""Tests for tools/router/telegram_ws_relay.py with local fake servers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import os
import socket
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "telegram_ws_relay_test", ROOT / "tools" / "router" / "telegram_ws_relay.py"
)
RELAY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RELAY
SPEC.loader.exec_module(RELAY)
MT = RELAY.mtproto


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeWebSocketServer:
    """Accepts the upgrade, records the client's bytes, answers with a frame."""

    def __init__(self, reply: bytes, status: bytes = b"101 Switching Protocols") -> None:
        self.reply = reply
        self.status = status
        self.received = bytearray()
        self.request = b""
        self.masked = []
        self.done = asyncio.Event()

    async def handle(self, reader, writer):
        request = b""
        while not request.endswith(b"\r\n\r\n"):
            request += await reader.read(1)
        self.request = request
        key = next(
            line.split(b":", 1)[1].strip()
            for line in request.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key")
        )
        accept = base64.b64encode(hashlib.sha1(key + RELAY.WS_GUID).digest())
        writer.write(b"HTTP/1.1 " + self.status + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        await writer.drain()
        if not self.status.startswith(b"101"):
            writer.close()
            return
        while len(self.received) < 64 + 5:
            first = await reader.readexactly(2)
            self.masked.append(bool(first[1] & 0x80))
            length = first[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await reader.readexactly(2), "big")
            mask = await reader.readexactly(4)
            payload = await reader.readexactly(length)
            self.received += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        writer.write(bytes([0x82, len(self.reply)]) + self.reply)  # unmasked server frame
        await writer.drain()
        self.done.set()
        await asyncio.sleep(0.2)
        writer.close()


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def start_relay(self, relay):
        port = free_port()
        ready = asyncio.Event()
        task = asyncio.create_task(RELAY.serve(("127.0.0.1", port), relay, ready))
        await ready.wait()
        self.addAsyncCleanup(self.stop_task, task)
        return port

    @staticmethod
    async def stop_task(task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def test_mtproto_goes_through_websocket_unchanged(self):
        fake = FakeWebSocketServer(reply=b"resPQ")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        ws_port = server.sockets[0].getsockname()[1]
        relay = RELAY.Relay(use_tls=False, ws_port=ws_port, address_override="127.0.0.1")
        port = await self.start_relay(relay)

        header, encryptor, _ = MT.make_header(-4)  # media connection to DC4
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header + b"hello")
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(100), 5)
        writer.close()

        self.assertEqual(answer, b"resPQ")
        self.assertEqual(bytes(fake.received), header + b"hello")
        self.assertTrue(all(fake.masked))
        self.assertIn(b"GET /apiws HTTP/1.1", fake.request)
        self.assertIn(b"Host: kws4-1.web.telegram.org", fake.request)
        self.assertIn(b"Sec-WebSocket-Protocol: binary", fake.request)
        self.assertEqual(relay.stats["ws"], 1)

    async def test_falls_back_to_direct_when_websocket_fails(self):
        received = bytearray()

        async def data_center(reader, writer):
            received.extend(await reader.readexactly(64 + 3))
            writer.write(b"direct-answer")
            await writer.drain()
            writer.close()

        dc_server = await asyncio.start_server(data_center, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, dc_server)
        relay = RELAY.Relay(
            use_tls=False, ws_port=free_port(), address_override="127.0.0.1",
            fallback_port=dc_server.sockets[0].getsockname()[1], connect_timeout=2,
        )
        port = await self.start_relay(relay)
        header, _, _ = MT.make_header(2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header + b"abc")
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        self.assertEqual(answer, b"direct-answer")
        self.assertEqual(bytes(received), header + b"abc")
        self.assertEqual(relay.stats["direct"], 1)

    async def test_rejected_upgrade_falls_back_too(self):
        fake = FakeWebSocketServer(reply=b"", status=b"403 Forbidden")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", fallback_port=free_port(), connect_timeout=2)
        port = await self.start_relay(relay)
        header, _, _ = MT.make_header(2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(10), 5), b"")
        writer.close()
        self.assertEqual(relay.stats, {"ws": 0, "direct": 0, "rejected": 0})

    async def test_non_mtproto_and_unknown_dc_are_closed(self):
        relay = RELAY.Relay(use_tls=False, ws_port=free_port(), address_override="127.0.0.1")
        port = await self.start_relay(relay)
        for payload in (b"\x16\x03\x01" + os.urandom(61), MT.make_header(0)[0], MT.make_header(9)[0]):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(10), 5), b"")
            writer.close()
        self.assertEqual(relay.stats["rejected"], 3)

    @staticmethod
    async def close_server(server):
        server.close()
        await server.wait_closed()


class HelperTests(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual(RELAY.ws_hosts(2, False), ["kws2.web.telegram.org"])
        self.assertEqual(RELAY.ws_hosts(5, True), ["kws5-1.web.telegram.org", "kws5.web.telegram.org"])
        self.assertEqual(RELAY.ws_hosts(203, False), ["kws2.web.telegram.org"])
        self.assertEqual(RELAY.WS_FIXED_ADDRESS, {2: "149.154.167.220", 4: "149.154.167.220"})

    def test_frame_round_trip(self):
        for size in (0, 5, 200, 70000):
            payload = os.urandom(size)
            frame = RELAY.ws_frame(RELAY.OP_BINARY, payload)
            self.assertEqual(frame[0], 0x82)
            self.assertTrue(frame[1] & 0x80)

            async def parse(data):
                reader = asyncio.StreamReader()
                reader.feed_data(data)
                reader.feed_eof()
                return await RELAY.read_ws_frame(reader)

            self.assertEqual(asyncio.run(parse(frame)), (RELAY.OP_BINARY, payload))

    def test_log_rotation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay.log"
            original = (RELAY.LOG_PATH, RELAY.LOG_LIMIT)
            RELAY.LOG_PATH, RELAY.LOG_LIMIT = path, 100
            try:
                for number in range(10):
                    RELAY.log(f"line {number} " + "x" * 20)
            finally:
                RELAY.LOG_PATH, RELAY.LOG_LIMIT = original
            self.assertTrue(path.with_name("relay.log.1").exists())
            self.assertLessEqual(path.stat().st_size, 200)

    def test_listen_validation(self):
        self.assertEqual(RELAY.parse_listen("127.0.0.1:18443"), ("127.0.0.1", 18443))
        for bad in ("8.8.8.8:1", "127.0.0.1:0", "127.0.0.1:x", "18443"):
            with self.subTest(bad=bad), self.assertRaises(RELAY.argparse.ArgumentTypeError):
                RELAY.parse_listen(bad)


if __name__ == "__main__":
    unittest.main()

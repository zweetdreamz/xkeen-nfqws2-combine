"""Tests for tools/router/telegram_ws_relay.py with local fake servers."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import importlib.util
import io
import os
import socket
import sys
import time
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
        self.requests = []
        self.sessions = 0
        self.masked = []
        self.done = asyncio.Event()

    async def handle(self, reader, writer):
        request = b""
        while not request.endswith(b"\r\n\r\n"):
            chunk = await reader.read(1)
            if not chunk:
                return
            request += chunk
        self.requests.append(request)
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
        received = bytearray()
        while len(received) < 64 + 5:
            try:
                first = await reader.readexactly(2)
            except asyncio.IncompleteReadError:
                return  # a pooled WebSocket closed unused
            self.masked.append(bool(first[1] & 0x80))
            length = first[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await reader.readexactly(2), "big")
            mask = await reader.readexactly(4)
            payload = await reader.readexactly(length)
            received += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.received += received
        self.sessions += 1
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
        relay.ws_state[4] = "ok"  # as after a successful probe
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
        self.assertIn(b"GET /apiws HTTP/1.1", fake.requests[0])
        self.assertIn(b"Host: kws4-1.web.telegram.org", fake.requests[0])
        self.assertIn(b"Sec-WebSocket-Protocol: binary", fake.requests[0])
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
            cf_domains=["cf.example.test"],
        )
        relay.ws_state[2] = "ok"
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
        # The refused WebSocket and Cloudflare routes are now skipped.
        self.assertEqual(relay.ws_state[2], "blocked")
        self.assertTrue(relay.blocked(("cf", "cf.example.test")))
        self.assertEqual(relay.cf_order(2), [])

    async def test_cloudflare_carries_dcs_without_a_fixed_address(self):
        fake = FakeWebSocketServer(reply=b"resPQ")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", cf_domains=["cf.example.test"])
        port = await self.start_relay(relay)
        header, _, _ = MT.make_header(-1)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header + b"hello")
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        self.assertEqual(answer, b"resPQ")
        self.assertEqual(bytes(fake.received), header + b"hello")
        self.assertIn(b"Host: kws1.cf.example.test", fake.requests[0])
        self.assertEqual((relay.stats["ws"], relay.stats["cf"]), (0, 1))
        self.assertEqual(relay.cf_active, {1: "cf.example.test"})

    async def test_cloudflare_follows_a_failed_websocket(self):
        fake = FakeWebSocketServer(reply=b"ok")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", cf_domains=["cf.example.test"])
        relay.ws_failed(4)  # as after a timeout to 149.154.167.220
        port = await self.start_relay(relay)
        header, _, _ = MT.make_header(4)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header + b"hello")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(100), 5), b"ok")
        writer.close()
        self.assertIn(b"Host: kws4.cf.example.test", fake.requests[0])
        self.assertEqual(relay.stats["cf"], 1)

    async def test_new_connections_get_a_ready_websocket(self):
        fake = FakeWebSocketServer(reply=b"ok")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", cf_domains=["cf.example.test"], pool_size=1)
        port = await self.start_relay(relay)
        for number in range(2):
            header, _, _ = MT.make_header(3)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(header + b"hello")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(100), 5), b"ok")
            writer.close()
            if number == 0:
                await self.wait_for(lambda: len(relay.pool.get(("cf", 3), ())) == 1)
        self.assertEqual((relay.stats["cf"], relay.stats["pooled"]), (2, 1))
        self.assertEqual(fake.sessions, 2)

    async def test_unknown_websocket_is_probed_in_the_background(self):
        fake = FakeWebSocketServer(reply=b"ok")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", cf_domains=["cf.example.test"], pool_size=0)
        port = await self.start_relay(relay)

        async def connect():
            header, _, _ = MT.make_header(2)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(header + b"hello")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(100), 5), b"ok")
            writer.close()

        await connect()  # does not wait for the direct WebSocket
        self.assertEqual(relay.stats["cf"], 1)
        await self.wait_for(lambda: relay.ws_state.get(2) == "ok")
        await connect()
        self.assertEqual(relay.stats["ws"], 1)
        self.assertTrue(any(b"Host: kws2.web.telegram.org" in r for r in fake.requests))

    @staticmethod
    async def wait_for(condition, timeout=5.0):
        deadline = time.monotonic() + timeout
        while not condition():
            if time.monotonic() > deadline:
                raise AssertionError("condition not reached")
            await asyncio.sleep(0.05)

    async def test_rejected_upgrade_falls_back_too(self):
        fake = FakeWebSocketServer(reply=b"", status=b"403 Forbidden")
        server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        self.addAsyncCleanup(self.close_server, server)
        relay = RELAY.Relay(use_tls=False, ws_port=server.sockets[0].getsockname()[1],
                            address_override="127.0.0.1", fallback_port=free_port(), connect_timeout=2,
                            cf_enabled=False)
        relay.ws_state[2] = "ok"
        port = await self.start_relay(relay)
        header, _, _ = MT.make_header(2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(header)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(10), 5), b"")
        writer.close()
        self.assertEqual(relay.stats, {"ws": 0, "cf": 0, "direct": 0, "rejected": 0, "pooled": 0})
        # The route is unusable either way; it is re-probed later.
        self.assertEqual(relay.ws_state[2], "blocked")

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


class ProcessTests(unittest.TestCase):
    def test_sigterm_does_not_wait_for_open_clients(self):
        import signal
        import subprocess
        import tempfile
        import time
        port = free_port()
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "relay.pid"
            process = subprocess.Popen(
                [sys.executable, str(ROOT / "tools" / "router" / "telegram_ws_relay.py"),
                 "--listen", f"127.0.0.1:{port}", "--pidfile", str(pidfile),
                 "--log", str(Path(directory) / "relay.log")],
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        client = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.1)
                with client:
                    client.sendall(b"partial header")  # Telegram keeps its connections open
                    time.sleep(0.3)
                    process.send_signal(signal.SIGTERM)
                    self.assertEqual(process.wait(timeout=5), 0)
                self.assertFalse(pidfile.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


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

    def test_describe_names_timeouts(self):
        self.assertEqual(RELAY.describe(asyncio.TimeoutError()), "timeout")
        self.assertEqual(RELAY.describe(ConnectionResetError()), "ConnectionResetError")
        self.assertEqual(RELAY.describe(OSError(101, "Network unreachable")), "[Errno 101] Network unreachable")

    def test_self_test_reports_every_data_center(self):
        relay = RELAY.Relay(use_tls=False, ws_port=free_port(), address_override="127.0.0.1",
                            fallback_port=free_port(), connect_timeout=1, cf_domains=["cf.example.test"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = asyncio.run(RELAY.self_test(relay))
        lines = out.getvalue().splitlines()
        self.assertEqual(code, 1)
        self.assertEqual([line.split(":")[0] for line in lines], ["DC1", "DC2", "DC3", "DC4", "DC5"])
        self.assertNotIn("WebSocket", lines[0])  # DC1 has no fixed WebSocket address
        self.assertIn("Cloudflare failed (kws1.cf.example.test via 127.0.0.1:", lines[0])
        self.assertIn("WebSocket failed (kws2.web.telegram.org via 127.0.0.1:", lines[1])
        self.assertIn("TCP 127.0.0.1:", lines[0])

    def test_cloudflare_domains(self):
        self.assertEqual(len(RELAY.CF_DEFAULT_DOMAINS), 20)
        self.assertTrue(all(RELAY.valid_domain(d) and d.endswith(".co.uk") for d in RELAY.CF_DEFAULT_DOMAINS))
        self.assertEqual(RELAY.decode_cf_domain("own.example.org"), "own.example.org")
        self.assertFalse(RELAY.valid_domain("bad domain"))
        self.assertFalse(RELAY.valid_domain("x"))

    def test_own_domains_file_replaces_the_defaults(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text("# mine\nTg.Example.org\nbad domain\ntg.example.org  # twice\nsecond.example.net\n",
                            encoding="utf-8")
            self.assertEqual(RELAY.read_domains_file(path), ["tg.example.org", "second.example.net"])
            self.assertEqual(RELAY.read_domains_file(Path(directory) / "missing"), [])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                RELAY.main(["--print-cf-domains", "--cf-domains-file", str(path)])
            self.assertEqual(out.getvalue().split(), ["tg.example.org", "second.example.net"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                RELAY.main(["--print-cf-domains", "--cf-domains-file", str(Path(directory) / "missing")])
            self.assertEqual(out.getvalue().split(), RELAY.CF_DEFAULT_DOMAINS)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                RELAY.main(["--print-cf-domains", "--no-cf"])
            self.assertEqual(out.getvalue(), "")

    def test_refresh_replaces_domains_only_with_a_usable_list(self):
        relay = RELAY.Relay(use_tls=False, cf_domains=["old.example.org"])

        async def run_once(fetched):
            original = RELAY.fetch_cf_domains
            RELAY.fetch_cf_domains = lambda: fetched
            try:
                task = asyncio.ensure_future(RELAY.refresh_cf_domains(relay, interval=60))
                await asyncio.sleep(0.2)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            finally:
                RELAY.fetch_cf_domains = original

        asyncio.run(run_once(["a.example.org", "b.example.org"]))
        self.assertEqual(relay.cf_domains, ["old.example.org"])
        asyncio.run(run_once(["a.example.org", "b.example.org", "c.example.org"]))
        self.assertEqual(relay.cf_domains, ["a.example.org", "b.example.org", "c.example.org"])

    def test_cf_order_prefers_the_fastest_domain(self):
        relay = RELAY.Relay(use_tls=False, cf_domains=[f"d{n}.example.org" for n in range(6)])
        relay.note_rtt("d4.example.org", 0.3)
        relay.note_rtt("d1.example.org", 0.1)
        order = relay.cf_order(2)
        self.assertEqual(order[:2], ["d1.example.org", "d4.example.org"])
        self.assertEqual(len(order), RELAY.CF_ATTEMPTS)
        relay.note_rtt("d1.example.org", 1.0)  # 0.7 * 0.1 + 0.3 * 1.0 = 0.37
        self.assertEqual(relay.cf_order(2)[:2], ["d4.example.org", "d1.example.org"])
        relay.mark_failed(("cf", "d4.example.org"))
        self.assertNotIn("d4.example.org", relay.cf_order(2))

    def test_blocked_websocket_is_probed_less_and_less_often(self):
        relay = RELAY.Relay(use_tls=False)
        delays = []
        for _ in range(9):
            relay.ws_failed(2)
            delays.append(round(relay.ws_next_probe[2] - time.monotonic()))
        self.assertEqual(delays[:4], [300, 600, 1200, 2400])
        self.assertEqual(delays[-1], 6 * 3600)
        relay.ws_worked(2)
        self.assertEqual(relay.ws_state[2], "ok")
        relay.ws_failed(2)
        self.assertEqual(round(relay.ws_next_probe[2] - time.monotonic()), 300)

    def test_listen_validation(self):
        self.assertEqual(RELAY.parse_listen("127.0.0.1:18443"), ("127.0.0.1", 18443))
        for bad in ("8.8.8.8:1", "127.0.0.1:0", "127.0.0.1:x", "18443"):
            with self.subTest(bad=bad), self.assertRaises(RELAY.argparse.ArgumentTypeError):
                RELAY.parse_listen(bad)


if __name__ == "__main__":
    unittest.main()

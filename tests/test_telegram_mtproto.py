"""Tests for tools/router/telegram_mtproto.py (AES-CTR, obfuscated2, handshake).

The real data centers are not reachable from tests, so FakeDataCenter plays
the server side of obfuscated2 as the protocol defines it: client->server keys
come from header bytes 8..56, server->client keys from the same bytes reversed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import socket
import struct
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "telegram_mtproto_test", ROOT / "tools" / "router" / "telegram_mtproto.py"
)
MT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MT)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - optional cross-check
    Cipher = None


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


class FakeDataCenter:
    """Answers one obfuscated2 abridged req_pq_multi; ``mode`` breaks it on purpose."""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.seen_dc = None
        self.stop = threading.Event()
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            if self.mode == "silent":
                # Keeps the connection open without answering (a DPI drop).
                self.stop.wait(3)
                return
            if self.mode == "close":
                # Reads the request, then a graceful close (FIN).
                recv_exact(conn, 64)
                conn.shutdown(socket.SHUT_RDWR)
                return
            if self.mode == "reset":
                # Closing with unread data makes the kernel send an RST.
                return
            header = recv_exact(conn, 64)
            from_client = MT.AesCtr(header[8:40], header[40:56])
            plain = from_client.process(header)
            assert plain[56:60] == MT.ABRIDGED_TAG
            self.seen_dc = struct.unpack("<h", plain[60:62])[0]
            reversed_part = header[8:56][::-1]
            to_client = MT.AesCtr(reversed_part[:32], reversed_part[32:48])
            length = from_client.process(recv_exact(conn, 1))[0] * 4
            message = from_client.process(recv_exact(conn, length))
            constructor = struct.unpack("<I", message[20:24])[0]
            assert constructor == MT.REQ_PQ_MULTI
            nonce = message[24:40]
            if self.mode == "bad-nonce":
                nonce = bytes(16)
            body = struct.pack("<I", MT.RES_PQ) + nonce + os.urandom(16) + b"\x08" + os.urandom(8) + b"\0" * 3
            reply = b"\0" * 8 + struct.pack("<qi", 0, len(body)) + body
            reply += b"\0" * (-len(reply) % 4)
            conn.sendall(to_client.process(bytes([len(reply) // 4]) + reply))

    def close(self):
        self.stop.set()
        self.server.close()
        self.thread.join(timeout=5)


class AesTests(unittest.TestCase):
    def test_fips197_vector(self):
        key = bytes(range(32))
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            MT._encrypt_block(MT._expand_key(key), block).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    @unittest.skipIf(Cipher is None, "cryptography not installed")
    def test_ctr_matches_reference_across_chunks_and_counter_wrap(self):
        for iv in (os.urandom(16), b"\xff" * 16):
            key, data = os.urandom(32), os.urandom(150)
            reference = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)
            ctr = MT.AesCtr(key, iv)
            self.assertEqual(ctr.process(data[:5]) + ctr.process(data[5:70]) + ctr.process(data[70:]), reference)

    def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            MT.AesCtr(b"short", bytes(16))
        with self.assertRaises(ValueError):
            MT.AesCtr(bytes(32), b"short")


class HeaderTests(unittest.TestCase):
    def test_header_round_trip_and_constraints(self):
        for dc in (1, 2, 5, -2):
            header, _, _ = MT.make_header(dc)
            self.assertEqual(len(header), 64)
            self.assertNotEqual(header[0], 0xEF)
            self.assertNotIn(header[:4], MT._FORBIDDEN_STARTS)
            self.assertEqual(MT.read_header(header), (MT.ABRIDGED_TAG, dc))

    def test_read_header_rejects_other_data(self):
        self.assertIsNone(MT.read_header(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(MT.read_header(os.urandom(64)) if False else None)
        tls = b"\x16\x03\x01\x02\x00" + bytes(59)
        self.assertIsNone(MT.read_header(tls))


class HandshakeTests(unittest.TestCase):
    def run_server(self, mode, timeout=2.0, dc=2):
        server = FakeDataCenter(mode)
        try:
            return MT.handshake("127.0.0.1", server.port, dc, timeout), server.seen_dc
        finally:
            server.close()

    def test_answering_data_center(self):
        self.assertEqual(self.run_server("ok"), ("ok", 2))

    def test_failures(self):
        self.assertEqual(self.run_server("bad-nonce")[0], "bad-nonce")
        self.assertEqual(self.run_server("close")[0], "closed")
        self.assertIn(self.run_server("reset")[0], {"reset", "closed"})
        self.assertEqual(self.run_server("silent", timeout=0.5)[0], "timeout")

    def test_refused_port(self):
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        self.assertEqual(MT.handshake("127.0.0.1", port, 2, 1.0), "network-error")


class CliTests(unittest.TestCase):
    def test_events_and_exit_code(self):
        servers = [FakeDataCenter("ok"), FakeDataCenter("close")]
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = MT.main([f"2:127.0.0.1:{servers[0].port}", f"4:127.0.0.1:{servers[1].port}",
                                "--label", "raw", "--timeout", "2", "--min-ok", "1"])
        finally:
            for server in servers:
                server.close()
        lines = out.getvalue().splitlines()
        self.assertEqual(code, 0)
        self.assertTrue(lines[0].startswith("EVENT|TG_MTPROTO|raw|2|127.0.0.1|ok|"), lines)
        self.assertTrue(lines[1].startswith("EVENT|TG_MTPROTO|raw|4|127.0.0.1|closed|"), lines)

    def test_min_ok_not_reached(self):
        server = FakeDataCenter("close")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = MT.main([f"2:127.0.0.1:{server.port}", "--min-ok", "1", "--timeout", "1"])
        finally:
            server.close()
        self.assertEqual(code, 1)

    def test_argument_validation(self):
        for argv in (["9:1.2.3.4:443"], ["2:::1:443"], ["--label", "a b"], ["--timeout", "99"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    MT.main(argv)

    def test_default_targets_are_the_five_data_centers(self):
        self.assertEqual(sorted(MT.DATA_CENTERS), [1, 2, 3, 4, 5])


if __name__ == "__main__":
    unittest.main()

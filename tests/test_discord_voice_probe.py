import contextlib
import importlib.util
import io
import socket
import struct
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "discord_voice_probe_test", ROOT / "tools" / "router" / "discord_voice_probe.py"
)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class FakeVoiceServer:
    """UDP server on 127.0.0.1 that answers like a voice server (or not)."""

    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop.set()
        self.thread.join(2)
        self.sock.close()

    def serve(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            self.requests.append(data)
            if self.mode == "silent":
                continue
            packet_type, length, ssrc = struct.unpack(">HHI", data[:8])
            if self.mode == "wrong-ssrc":
                ssrc ^= 1
            if self.mode == "garbage":
                self.sock.sendto(b"\x00\x01", peer)
                continue
            address = b"203.0.113.7".ljust(64, b"\0")
            reply = struct.pack(">HHI", 0x0002, 70, ssrc) + address + struct.pack(">H", peer[1])
            self.sock.sendto(reply, peer)


class DiscoveryPacketTests(unittest.TestCase):
    def test_request_layout(self):
        packet = PROBE.discovery_request(0x01020304)
        self.assertEqual(len(packet), 74)
        self.assertEqual(packet[:8], bytes.fromhex("0001004601020304"))
        self.assertEqual(packet[8:], bytes(66))

    def test_response_check(self):
        good = struct.pack(">HHI", 2, 70, 7) + bytes(66)
        self.assertTrue(PROBE.is_discovery_response(good, 7))
        self.assertFalse(PROBE.is_discovery_response(good, 8))
        self.assertFalse(PROBE.is_discovery_response(struct.pack(">HHI", 1, 70, 7), 7))
        self.assertFalse(PROBE.is_discovery_response(struct.pack(">HHI", 2, 69, 7), 7))
        self.assertFalse(PROBE.is_discovery_response(b"\x00\x02", 7))


class ProbeTests(unittest.TestCase):
    def run_probe(self, mode, **kwargs):
        with FakeVoiceServer(mode) as server:
            result = PROBE.probe("127.0.0.1", server.port, interval=0.01, timeout=0.5, **kwargs)
        return result, server

    def test_answering_server(self):
        (sent, received, valid), server = self.run_probe("answer", count=3)
        self.assertEqual((sent, received, valid), (3, 3, 3))
        self.assertTrue(all(len(request) == 74 for request in server.requests))

    def test_silent_server(self):
        (sent, received, valid), _server = self.run_probe("silent", count=2)
        self.assertEqual((sent, received, valid), (2, 0, 0))

    def test_replies_that_are_not_ours_are_not_valid(self):
        for mode in ("wrong-ssrc", "garbage"):
            with self.subTest(mode=mode):
                (sent, received, valid), _server = self.run_probe(mode, count=2)
                self.assertEqual((sent, received, valid), (2, 2, 0))

    def test_closed_port(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        sent, received, valid = PROBE.probe("127.0.0.1", port, count=1, interval=0, timeout=0.3)
        self.assertEqual((received, valid), (0, 0))
        self.assertEqual(sent, 1)


class CliTests(unittest.TestCase):
    def test_main_prints_event_and_exit_code(self):
        with FakeVoiceServer("answer") as server:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = PROBE.main(["127.0.0.1", str(server.port), "--label", "raw",
                                   "--count", "1", "--interval", "0", "--timeout", "0.5"])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().strip(), "EVENT|VOICE_PROBE|raw|1|1|1")
        with FakeVoiceServer("silent") as server:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = PROBE.main(["127.0.0.1", str(server.port), "--label", "c-1",
                                   "--count", "1", "--interval", "0", "--timeout", "0.3"])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue().strip(), "EVENT|VOICE_PROBE|c-1|1|0|0")

    def test_argument_validation(self):
        for argv in (
            ["::1", "50000"],
            ["discord.media", "50000"],
            ["1.2.3.4", "0"],
            ["1.2.3.4", "50000", "--count", "11"],
            ["1.2.3.4", "50000", "--label", "a|b"],
            ["1.2.3.4", "50000", "--timeout", "0"],
        ):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    PROBE.parse_args(argv)


if __name__ == "__main__":
    unittest.main()

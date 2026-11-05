from __future__ import annotations

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("discord_ws_probe_test", ROOT / "tools/router/discord_ws_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class WebSocketResponseTests(unittest.TestCase):
    def test_valid_upgrade_requires_matching_accept(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        accept = base64.b64encode(hashlib.sha1((key + PROBE.GUID).encode()).digest()).decode()
        header = ("HTTP/1.1 101 Switching Protocols\r\n"
                  "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
        self.assertTrue(PROBE.response_ok(header, key))
        self.assertFalse(PROBE.response_ok(header, "different-key"))
        self.assertFalse(PROBE.response_ok(header.replace(b"101", b"403", 1), key))


if __name__ == "__main__":
    unittest.main()

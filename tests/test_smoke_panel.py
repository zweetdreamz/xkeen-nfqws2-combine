"""Read-only smoke CLI against a real, loopback-only mock HTTP server."""
import copy
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

import panel_mock_server


@unittest.skipUnless(os.name == "posix", "POSIX shell tool")
class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.responses = copy.deepcopy(panel_mock_server.RESPONSES)
        for attribute, value in (("RESPONSES", self.responses), ("STATS", {}), ("DELAYS", {}), ("SEQUENCES", {})):
            patcher = mock.patch.object(panel_mock_server, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), panel_mock_server.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def run_smoke(self, *args):
        tool = Path(__file__).resolve().parents[1] / "tools/dev/smoke-panel.sh"
        return subprocess.run([*os.environ.get("TEST_SHELL", "sh").split(), str(tool), "--host", "127.0.0.1",
                               "--port", str(self.server.server_port), "--rounds", "1", "--parallel", "4", *args],
                              text=True, capture_output=True, timeout=20)

    def test_success_and_read_only_request_set(self):
        result = self.run_smoke("--local")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("requests max_bytes p50_seconds max_seconds failures", result.stdout)
        self.assertEqual(result.stdout.splitlines()[1].split()[0], "7")
        self.assertEqual(set(panel_mock_server.STATS), {"GET /api/route/status", "GET /api/tuner/status",
                                                       "GET /api/diagnostics/status"})

    def test_size_limit_and_invalid_json_shape_fail(self):
        self.responses["/api/route/status"] = {"ok": True, "output": "x" * 3000}
        result = self.run_smoke("--local")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("exceeds limit 2048", result.stderr)
        self.responses["/api/route/status"] = {"not_ok": True}
        result = self.run_smoke("--local")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing ok", result.stderr)

    def test_consent_and_dry_run_send_nothing(self):
        result = self.run_smoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to touch the router without --yes-router", result.stderr)
        self.assertEqual(panel_mock_server.STATS, {})
        result = self.run_smoke("--dry-run")
        self.assertEqual(result.returncode, 0)
        self.assertIn("GET", result.stdout)
        self.assertEqual(panel_mock_server.STATS, {})

    def test_local_flag_rejects_remote_host_and_unreachable_returns_two(self):
        result = self.run_smoke("--local", "--host", "192.168.2.1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(panel_mock_server.STATS, {})
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            result = self.run_smoke("--local", "--port", str(reserved.getsockname()[1]))
        self.assertEqual(result.returncode, 2, result.stderr)


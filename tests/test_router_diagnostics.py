from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools" / "router" / "xkeen_diagnostics.py"
    spec = importlib.util.spec_from_file_location("xkeen_diagnostics_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RouterDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_flowseal_standard_targets_are_bounded_and_cover_services(self):
        targets = dict(self.module.STANDARD_TARGETS)
        self.assertEqual(len(targets), 19)
        self.assertEqual(targets["DiscordMain"], "https://discord.com")
        self.assertEqual(targets["YouTubeWeb"], "https://www.youtube.com")
        self.assertEqual(targets["CloudflareDNS1111"], "PING:1.1.1.1")
        self.assertEqual(targets["DiscordAPI"], "https://discord.com/api/v10/gateway")
        self.assertEqual(targets["YouTube204"], "https://www.youtube.com/generate_204")
        self.assertEqual(targets["GooglevideoMapping"], "https://redirector.googlevideo.com/report_mapping")

    def test_route_consistency_detects_leftover_zapret_in_direct_mode(self):
        text = "# Active routes: Discord=direct, YouTube=zapret.\n--hostlist=/opt/etc/nfqws2/lists/youtube.list"
        tags = {"discord-direct", "youtube-direct"}
        checks = self.module.route_consistency(text, tags, "discord.com\n")
        by_name = {item["name"]: item["status"] for item in checks}
        self.assertEqual(by_name["Discord TCP route"], "error")
        self.assertEqual(by_name["Discord Voice route"], "ok")
        self.assertEqual(by_name["YouTube route"], "ok")
        self.assertTrue(all(item["status"] == "ok" for item in self.module.route_consistency(text, tags, "")))
        checks = self.module.route_consistency(text, {"discord-direct"}, "")
        self.assertEqual(checks[0]["status"], "error")

    def test_route_consistency_checks_discord_voice_separately(self):
        text = (
            "# Active routes: DiscordTCP=vless, DiscordVoice=zapret, YouTube=vless.\n"
            "NFQWS_ARGS_UDP=\"--filter-udp=443 --filter-l7=stun,discord\""
        )
        by_name = {
            item["name"]: item["status"]
            for item in self.module.route_consistency(text, {"discord-direct"}, "")
        }
        self.assertEqual(by_name["Discord TCP route"], "ok")
        self.assertEqual(by_name["Discord Voice route"], "ok")
        by_name = {
            item["name"]: item["status"]
            for item in self.module.route_consistency(text, set(), "")
        }
        self.assertEqual(by_name["Discord Voice route"], "error")

    def test_dpi_suite_is_provider_diverse_and_bounded(self):
        self.assertEqual(len(self.module.DPI_TARGETS), 12)
        providers = {provider for _identifier, provider, _host in self.module.DPI_TARGETS}
        self.assertGreaterEqual(len(providers), 10)
        for identifier, _provider, host in self.module.DPI_TARGETS:
            self.assertRegex(identifier, r"^[A-Z0-9.-]+$")
            self.assertRegex(host, r"^[a-z0-9.-]+$")

    def test_dpi_marker_and_block_classification(self):
        parsed = self.module.parse_dpi_marker(
            "noise\n__XKDPI__000|65536|0|6.001|203.0.113.10"
        )
        self.assertEqual(parsed[1:3], (65536, 0))
        self.assertEqual(
            self.module.classify_dpi(28, parsed, "timeout", 6),
            "likely_blocked",
        )
        okay = self.module.parse_dpi_marker(
            "__XKDPI__403|65536|120|0.421|203.0.113.10"
        )
        self.assertEqual(self.module.classify_dpi(0, okay, "", 6), "ok")

    def test_summary_separates_warning_and_error(self):
        results = [
            {"name": "one", "status": "ok"},
            {"name": "two", "status": "warn"},
            {"name": "three", "status": "error"},
        ]
        summary = self.module.summary("health", results)
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["warn"], 1)
        self.assertEqual(summary["error"], 1)

    def test_atomic_state_is_private_and_valid_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            self.module.atomic_json(path, {"ok": True, "text": "проверка"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["text"], "проверка")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_windows_helper_is_recoverable(self):
        helper = (
            ROOT / "tools" / "windows" / "reset-discord-cache.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Rename-Item", helper)
        self.assertIn(".xkeen-backup-", helper)
        self.assertNotIn("Remove-Item", helper)

    def test_dns_private_answer_prevents_http_probe(self):
        with mock.patch.object(self.module, "resolve_public", return_value=(False, "private DNS")):
            with mock.patch.object(self.module, "curl_probe") as curl:
                result = self.module.standard_target("DiscordMain", "https://discord.com")
                self.assertEqual(result["dns"]["status"], "error")
                curl.assert_not_called()

    def test_tls_handshake_failure_is_not_unsupported(self):
        self.assertEqual(self.module.classify_dpi(35, None, "SSL handshake failed", 6), "fail")
        self.assertEqual(self.module.classify_dpi(4, None, "TLS1.3 not supported", 6), "unsupported")

    def test_standard_probe_captures_tls_response_without_restart(self):
        captured = []

        def fake_run(command, timeout):
            captured.append(command)
            return {"ok": True, "code": 0, "output": "__XKRES__403|0.15|1.1.1.1"}

        with mock.patch.object(self.module, "run", side_effect=fake_run):
            result = self.module.curl_probe("https://discord.com", "TLS1.2", ["--tlsv1.2", "--tls-max", "1.2"], 5)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["http_code"], "403")
        self.assertEqual(len(captured), 1)
        self.assertIn("--max-time", captured[0])
        self.assertNotIn("--insecure", captured[0])

    def test_dpi_payload_is_removed_after_probe_failure(self):
        class Writer:
            def write(self, **_changes):
                pass

        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(self.module, "JOB_DIR", Path(temporary)):
                with mock.patch.object(self.module, "DPI_TARGETS", (("ONE", "test", "example.com"),)):
                    with mock.patch.object(self.module, "dpi_target", side_effect=RuntimeError("fixture failure")):
                        results = self.module.run_dpi(Writer())
                        self.assertIn("fixture failure", results[0]["error"])
                        self.assertEqual(list(Path(temporary).glob("payload-*.bin")), [])


if __name__ == "__main__":
    unittest.main()

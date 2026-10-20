from __future__ import annotations

import dataclasses
import importlib.util
import json
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_tuner():
    path = ROOT / "tools" / "windows" / "zapret_tuner.py"
    spec = importlib.util.spec_from_file_location("panel_test_tuner", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_panel_namespace():
    installer = (
        ROOT / "tools" / "router" / "xkeen_control_script.sh"
    ).read_text(encoding="utf-8")
    source = installer.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF\n", 1)[0]
    namespace = {"__name__": "panel_import_test"}
    exec(compile(source, "app.py", "exec"), namespace)
    return namespace


class PanelImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tuner = load_tuner()
        cls.panel = load_panel_namespace()
        cls.source = cls.tuner.SourceFile(
            "general (ALT11).bat",
            "",
            "fixture-sha",
            "https://example.invalid/general-alt11.bat",
        )

    def report_for(self, service):
        candidate = self.tuner.known_candidate(service, [self.source])
        report = {
            "report_format": 1,
            "created_utc": "2026-07-23T00:00:00Z",
            "repository": "fixture/repository",
            "ref": "main",
            "commit": "abc123",
            "search_seed": 123456,
            "service": service,
            "found": dataclasses.asdict(candidate),
        }
        return json.loads(json.dumps(report))

    def test_accepts_all_tuner_service_families(self):
        for service in ("youtube", "discord-tcp", "discord-voice"):
            with self.subTest(service=service):
                profile = self.panel["validate_report"](self.report_for(service))
                self.assertEqual(profile["service"], service)
                self.assertEqual(profile["format"], 1)
                self.assertEqual(profile["report"]["search_seed"], 123456)

    def test_panel_imports_sys_for_background_tuner_launch(self):
        self.assertIs(self.panel["sys"], sys)

    def test_route_switch_is_allowlisted_and_backgrounded(self):
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            self.panel["start_diagnostic_job"]("standard")
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            self.panel["start_diagnostic_job"]("dpi")
        self.assertEqual(
            self.panel["validate_route"]("discord", "vpn"),
            ("discord", "vpn"),
        )
        with self.assertRaises(ValueError):
            self.panel["validate_route"]("discord", "custom")
        installer = (
            ROOT / "tools" / "router" / "xkeen_control_script.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('"/api/route/status"', installer)
        self.assertIn('"--route-job"', installer)
        self.assertIn("timeout=900", installer)
        self.assertIn("start_new_session=True", installer)

    def test_command_timeout_terminates_the_process_group(self):
        result = self.panel["run_command"](
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout=0.05,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertIn("TERM", result["output"])

    def test_command_does_not_wait_for_descendant_holding_output(self):
        started = time.monotonic()
        result = self.panel["run_command"](
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-c',"
                    "'import time; time.sleep(8)']); print('parent-done')"
                ),
            ],
            timeout=4,
        )
        elapsed = time.monotonic() - started
        self.assertTrue(result["ok"], result)
        self.assertIn("parent-done", result["output"])
        # MIPS Python startup can exceed a second under router load. Still
        # finish well before the descendant closes inherited output at 8s.
        self.assertLess(elapsed, 4)

    def test_route_history_keeps_snapshot_and_orders_by_date(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_history = self.panel["ROUTE_HISTORY_DIR"]
            old_snapshots = self.panel["SNAPSHOT_DIR"]
            self.panel["ROUTE_HISTORY_DIR"] = root / "history"
            self.panel["SNAPSHOT_DIR"] = root / "snapshots"
            try:
                snapshot = self.panel["SNAPSHOT_DIR"] / "20260815-010203-42"
                snapshot.mkdir(parents=True)
                (snapshot / "STATE.tsv").write_text("PURPOSE\tpre-apply\n", encoding="utf-8")
                (snapshot / "MANIFEST").write_text("fixture\n", encoding="utf-8")
                first = {
                    "job_id": "1111111111111111",
                    "operation": "switch",
                    "status": "completed",
                    "created_utc": "2026-08-15T01:00:00Z",
                    "snapshot": str(snapshot),
                }
                second = {
                    "job_id": "2222222222222222",
                    "operation": "switch",
                    "status": "completed",
                    "created_utc": "2026-08-15T02:00:00Z",
                    "snapshot": str(snapshot),
                }
                self.panel["write_history"](first)
                self.panel["write_history"](second)
                history = self.panel["route_history"]()
                self.assertEqual(history[0]["job_id"], second["job_id"])
                self.assertTrue(history[0]["rollback_available"])
                parsed = self.panel["parse_snapshot_from_output"](
                    f"Snapshot created: {snapshot}\nApply complete."
                )
                self.assertEqual(parsed, str(snapshot))
            finally:
                self.panel["ROUTE_HISTORY_DIR"] = old_history
                self.panel["SNAPSHOT_DIR"] = old_snapshots

    def test_dated_profile_version_is_valid_and_detected_as_active(self):
        profile = self.panel["validate_report"](self.report_for("youtube"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_imported = self.panel["IMPORTED_PROFILE_DIR"]
            old_versions = self.panel["PROFILE_VERSION_DIR"]
            self.panel["IMPORTED_PROFILE_DIR"] = root / "imported"
            self.panel["PROFILE_VERSION_DIR"] = root / "versions"
            try:
                self.panel["IMPORTED_PROFILE_DIR"].mkdir()
                active = self.panel["IMPORTED_PROFILE_DIR"] / "youtube.json"
                active.write_text(json.dumps(profile), encoding="utf-8")
                directory = self.panel["PROFILE_VERSION_DIR"] / "youtube"
                directory.mkdir(parents=True)
                version_id = (
                    f"20260815T020304Z-{profile['candidate_id']}-applied-123"
                )
                (directory / f"{version_id}.json").write_text(
                    json.dumps(profile),
                    encoding="utf-8",
                )
                versions = self.panel["profile_versions"]()
                self.assertEqual(len(versions), 1)
                self.assertEqual(versions[0]["created_utc"], "2026-08-15T02:03:04Z")
                self.assertTrue(versions[0]["active"])
                path, restored = self.panel["profile_version_path"](
                    "youtube",
                    version_id,
                )
                self.assertEqual(path.name, f"{version_id}.json")
                self.assertEqual(restored["candidate_id"], profile["candidate_id"])
                collision_id = version_id + "-1"
                (directory / f"{collision_id}.json").write_text(
                    json.dumps(profile),
                    encoding="utf-8",
                )
                collision_path, _restored = self.panel["profile_version_path"](
                    "youtube",
                    collision_id,
                )
                self.assertEqual(collision_path.name, f"{collision_id}.json")
            finally:
                self.panel["IMPORTED_PROFILE_DIR"] = old_imported
                self.panel["PROFILE_VERSION_DIR"] = old_versions

    def test_route_progress_stages_and_new_api_are_present(self):
        stage = self.panel["route_stage"](
            "Snapshot created: /fixture\nPatching Xray routing: /fixture\n"
            "Restarting XKeen...\nRestarting nfqws2 only\nStarted NFQWS2 service",
            "switch",
        )
        self.assertEqual(stage, ("verify", "Проверка служб", 94))
        installer = (
            ROOT / "tools" / "router" / "xkeen_control_script.sh"
        ).read_text(encoding="utf-8")
        for endpoint in (
            '"/api/history"',
            '"/api/profile-versions"',
            '"/api/updates/check"',
            '"/api/checks/config"',
            '"/api/diagnostics/status"',
            '"/api/diagnostics/cancel"',
        ):
            self.assertIn(endpoint, installer)
        self.assertIn("--rollback-snapshot", installer)
        self.assertIn("tracked=d.progress!==undefined||!!d.operation", installer)
        self.assertIn('data-tab="diagnostics"', installer)
        self.assertIn('data-diag-kind="standard"', installer)
        self.assertIn('data-diag-kind="dpi"', installer)
        self.assertIn("reset-discord-cache.ps1", installer)

    def test_rejects_candidate_tampering(self):
        report = self.report_for("youtube")
        report["found"]["args"][-1] = (
            "--lua-desync=fake:blob=youtube_quic:repeats=99"
        )
        with self.assertRaisesRegex(ValueError, "candidate_id"):
            self.panel["validate_report"](report)

    def test_old_router_network_reports_are_hidden_but_health_is_kept(self):
        for kind in ("standard", "dpi", "health"):
            saved = {"kind": kind, "status": "completed", "progress": 100,
                     "results": [{"name": "old"}], "finished_utc": "2026-10-20T12:00:00Z"}
            with mock.patch.dict(self.panel, {
                "safe_json_file": lambda _path: saved,
                "diagnostic_active": lambda: False,
            }):
                state = self.panel["diagnostic_status"]()
            if kind == "health":
                self.assertEqual(state["results"], saved["results"])
                self.assertEqual(state["finished_utc"], saved["finished_utc"])
            else:
                self.assertEqual(state["status"], "idle")
                self.assertEqual(state["results"], [])
                self.assertNotIn("summary", state)

    def test_rejects_cross_service_hostlist(self):
        report = self.report_for("discord-tcp")
        report["found"]["args"][2] = (
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list"
        )
        with self.assertRaises(ValueError):
            self.panel["validate_report"](report)

    def test_flowseal_download_noop_and_failed_update_preserves_cache(self):
        latest = "c" * 40
        source = self.tuner.SourceFile("general (ALT).bat", "@echo off\n", "d" * 40,
                                      "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/" + latest + "/general.bat")
        metadata = {"sha": latest, "commit": {"committer": {"date": "2026-10-20T00:00:00Z"}}}
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "sources.json"
            with mock.patch.dict(self.panel, {"FLOWSEAL_SOURCE_CACHE": cache,
                    "FLOWSEAL_UPDATE_STATE": Path(directory) / "update.json",
                    "flowseal_source_module": lambda: self.tuner}):
                with mock.patch.object(self.panel["urllib"].request, "urlopen",
                        side_effect=lambda *_a, **_k: io.BytesIO(json.dumps(metadata).encode())):
                    with mock.patch.object(self.tuner, "fetch_sources", return_value=([source], latest)) as fetch:
                        first = self.panel["check_flowseal_update"]()
                        self.assertEqual(first["status"], "downloaded")
                        second = self.panel["check_flowseal_update"]()
                        self.assertEqual(second["status"], "up_to_date")
                        fetch.assert_called_once_with("Flowseal/zapret-discord-youtube", latest)
                    saved = cache.read_bytes()
                    metadata["sha"] = "e" * 40
                    with mock.patch.object(self.tuner, "fetch_sources", side_effect=OSError("offline")):
                        with self.assertRaises(OSError):
                            self.panel["check_flowseal_update"]()
                    self.assertEqual(cache.read_bytes(), saved)
                    self.assertEqual(self.panel["cached_flowseal_update"]()["status"], "error")


if __name__ == "__main__":
    unittest.main()

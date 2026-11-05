"""Tests of the diagnostic job of the panel: job files, state, start guards and launch."""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

from panel_fixtures import PanelUnitCase


class DiagnosticJobTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        diagnostics = self.root / "diagnostics"
        self.patch(
            DIAGNOSTIC_JOB_DIR=diagnostics,
            DIAGNOSTIC_STATE=diagnostics / "state.json",
            DIAGNOSTIC_PID=diagnostics / "panel-launch.pid",
            DIAGNOSTIC_LOG=diagnostics / "process.log",
        )
        self.diagnostics = diagnostics

    def test_cancel_jobs_without_active_process(self):
        with self.assertRaisesRegex(RuntimeError, "активной диагностики нет"):
            self.ns["cancel_diagnostic_job"]()

    def test_clear_previous_diagnostic_job(self):
        self.diagnostics.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        self.ns["DIAGNOSTIC_STATE"].symlink_to(outside)
        self.ns["DIAGNOSTIC_LOG"].write_text("x", encoding="utf-8")
        (self.diagnostics / "payload-12.bin").write_bytes(b"x")
        (self.diagnostics / "payload-x.bin").write_bytes(b"x")
        (self.diagnostics / "payload-7.bin").symlink_to(outside)
        self.ns["clear_previous_diagnostic_job"]()
        self.assertEqual(
            sorted(path.name for path in self.diagnostics.iterdir()),
            ["payload-7.bin", "payload-x.bin"],
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.ns["DIAGNOSTIC_PID"].mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге диагностики"):
            self.ns["clear_previous_diagnostic_job"]()

    def test_diagnostic_status_marks_stale_health_job_as_error(self):
        self.diagnostics.mkdir()
        self.ns["DIAGNOSTIC_STATE"].write_text(
            json.dumps({"job_id": "a" * 16, "kind": "health", "status": "running", "results": [{"name": "x"}]}),
            encoding="utf-8",
        )
        status = self.ns["diagnostic_status"]()
        self.assertEqual(status["status"], "error")
        self.assertEqual(status["error"], "процесс диагностики завершился неожиданно")
        self.assertFalse(status["active"])
        self.assertEqual(json.loads(self.ns["DIAGNOSTIC_STATE"].read_text())["status"], "running")
        # The fixture is an owned panel job, not a tool run by hand.
        (self.diagnostics / "job.id").write_text("a" * 16)
        self.ns["reconcile_diagnostic_job"]()
        saved = json.loads(self.ns["DIAGNOSTIC_STATE"].read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "error")
        self.ns["DIAGNOSTIC_STATE"].write_text("[]", encoding="utf-8")
        status = self.ns["diagnostic_status"]()
        self.assertEqual(status["status"], "error")
        self.assertIn("state:", status["error"])

    def test_start_diagnostic_job_guards(self):
        start = self.ns["start_diagnostic_job"]
        idle = {"tuner_active": lambda: False, "diagnostic_active": lambda: False, "route_active": lambda: False}
        for name, message in (
            ("diagnostic_active", "диагностика уже выполняется"),
            ("tuner_active", "сначала завершите автоподбор"),
            ("route_active", "сначала завершите переключение маршрута"),
        ):
            with self.subTest(active=name):
                with self.patched(**{**idle, name: lambda: True}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        start("health")
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            start("unknown")

    def test_start_diagnostic_job_launches_worker(self):
        process = mock.Mock(pid=999)
        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            DIAGNOSTICS=self.root / "xkeen_diagnostics.py",
        )
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen:
            state = self.ns["start_diagnostic_job"]("health")
        command = popen.call_args.args[0]
        self.assertEqual(command[:4], [sys.executable, str(self.root / "xkeen_diagnostics.py"), "--kind", "health"])
        self.assertEqual(command[4:], ["--job-id", state["job_id"]])
        self.assertEqual(state["pid"], 999)
        self.assertEqual(self.ns["DIAGNOSTIC_PID"].read_text(encoding="ascii"), "999\n")
        saved = json.loads(self.ns["DIAGNOSTIC_STATE"].read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "queued")
        self.assertEqual(saved["kind"], "health")


if __name__ == "__main__":
    unittest.main()

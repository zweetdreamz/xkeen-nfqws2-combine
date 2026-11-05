"""Tests of the stored state of the scheduled check (kdn.web.domain.automation): missing and unreadable state."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

from panel_fixtures import PanelUnitCase


class AutomationStateTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        self.state_file = self.root / "automation-state.json"
        self.patch(AUTOMATION_STATE=self.state_file)

    def test_missing_state_is_idle_without_error(self):
        self.assertEqual(self.ns["automation_state"](), {"status": "idle", "history": []})

    def test_unreadable_state_is_idle_with_error_class_and_message(self):
        for content, error_class in (
            ("", "ValueError"),
            ("{broken", "JSONDecodeError"),
            ("[]", "ValueError"),
            (b"\xff\xfe{}", "UnicodeDecodeError"),
        ):
            with self.subTest(content=content):
                if isinstance(content, bytes):
                    self.state_file.write_bytes(content)
                else:
                    self.state_file.write_text(content, encoding="utf-8")
                state = self.ns["automation_state"]()
                self.assertEqual((state["status"], state["history"]), ("idle", []))
                self.assertRegex(state["state_error"], rf"^{error_class}: .+")

    def test_state_read_failure_is_reported(self):
        with self.patched(safe_json_file=mock.Mock(side_effect=PermissionError("denied"))):
            state = self.ns["automation_state"]()
        self.assertEqual(state, {"status": "idle", "history": [], "state_error": "PermissionError: denied"})

    def test_save_overwrites_broken_state_without_the_error_marker(self):
        self.state_file.write_text("{broken", encoding="utf-8")
        self.ns["automation_write"](phase="checking")
        self.assertEqual(
            json.loads(self.state_file.read_text(encoding="utf-8")),
            {"status": "idle", "history": [], "phase": "checking"},
        )
        self.assertNotIn("state_error", self.ns["automation_state"]())

    def test_startup_recovery_reports_unreadable_state_on_logger(self):
        self.state_file.write_text("{broken", encoding="utf-8")
        stderr = io.StringIO()
        logger = mock.Mock()
        logger.warning.side_effect = lambda message, *args: stderr.write((message % args) + "\n")
        with mock.patch.object(self.ns.module("automation").logsetup, "panel_logger", return_value=logger):
            self.ns["start_automation_recovery"]()
        self.assertRegex(stderr.getvalue(), r"^automation recovery state unreadable: JSONDecodeError: .+\n$")
        self.assertEqual(self.state_file.read_text(encoding="utf-8"), "{broken")

    def test_startup_recovery_is_silent_for_readable_state(self):
        for content in (None, json.dumps({"status": "idle", "history": []})):
            with self.subTest(state=content):
                if content is not None:
                    self.state_file.write_text(content, encoding="utf-8")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.ns["start_automation_recovery"]()
                self.assertEqual(stderr.getvalue(), "")

    def test_status_reports_state_error(self):
        self.patch(AUTOMATION_CONFIG=self.root / "automation-config.json")
        self.state_file.write_text("", encoding="utf-8")
        status = self.ns["automation_status"]()
        self.assertTrue(status["ok"])
        self.assertEqual(status["state"]["status"], "idle")
        self.assertIn("ValueError", status["state"]["state_error"])


if __name__ == "__main__":
    unittest.main()

"""Diagnostic views and cancellation do not write the external tool's state."""
import subprocess
import sys
from unittest import mock

from panel_job_view_harness import OwnedJobCase


class DiagnosticViewTests(OwnedJobCase):
    family_name = "diagnostic"

    def test_read_only_view_and_owned_reconcile(self):
        self.check_owned_view_and_reconcile()

    def test_early_exit_while_starting_is_not_lost(self):
        self.check_early_exit_is_reconciled_while_starting()

    def test_cancel_marker_never_rewrites_tool_state(self):
        self.check_cancel_marker_and_terminal_state("completed")

    def test_manual_tool_is_not_settled(self):
        self.check_manual_tool_is_never_settled()

    def test_starting_and_legacy_marker(self):
        self.check_starting_and_legacy_marker(self.mod.refusals.DIAGNOSTIC_START)

    def test_real_reaper_and_live_reconcile(self):
        self.spawn_real(callback=self.reconcile)
        self.assertFalse(self.reconcile())
        self.cancel()
        self.until(lambda: self.store.read_state()["status"] == "error")

    def test_command_initial_state_and_project_lock_skip(self):
        def launched(argv, **kwargs):
            state = self.store.read_state()
            self.assertEqual((state["kind"], state["status"], state["results"], state["progress"]), ("health", "queued", [], 0))
            return mock.Mock(pid=4321)

        with mock.patch.object(self.jobs.COORDINATOR, "_project_lock", side_effect=AssertionError("project lock")), \
                mock.patch.object(subprocess, "Popen", side_effect=launched) as popen:
            state = self.start()
        self.assertEqual(popen.call_args.args[0], [sys.executable, str(self.cfg.DIAGNOSTICS), "--kind", "health", "--job-id", state["job_id"]])
        self.assertEqual(state["pid"], 4321)

    def test_spawn_failure_and_empty_cancel(self):
        with self.assertRaisesRegex(RuntimeError, "активной диагностики нет"):
            self.cancel()
        with mock.patch.object(subprocess, "Popen", side_effect=OSError("failed")):
            with self.assertRaisesRegex(OSError, "failed"):
                self.start()
        self.assertEqual(self.store.read_state()["status"], "error")

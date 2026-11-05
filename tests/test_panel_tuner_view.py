"""Tuner ownership, cancellation, early exits, admission and argv compatibility."""
import subprocess
import sys
from unittest import mock

from panel_job_view_harness import OwnedJobCase


class TunerViewTests(OwnedJobCase):
    family_name = "tuner"

    def test_read_only_view_and_owned_reconcile(self):
        self.check_owned_view_and_reconcile()

    def test_early_exit_while_starting_is_not_lost(self):
        self.check_early_exit_is_reconciled_while_starting()

    def test_cancel_marker_never_rewrites_tool_state(self):
        self.check_cancel_marker_and_terminal_state("cancelled")
        self.store.prepare(self.spec(status="queued"))
        self.assertFalse((self.family.directory() / "cancel.request").exists())

    def test_manual_tool_is_not_settled(self):
        self.check_manual_tool_is_never_settled()

    def test_starting_and_legacy_cancel_marker(self):
        self.check_starting_and_legacy_marker(self.mod.refusals.TUNER_START)

    def test_dead_queued_state_keeps_short_process_log_tail(self):
        self.store.prepare(self.spec(status="queued"))
        self.family.log().write_text("old\nTraceback:\nNameError: fixture\n")
        view = self.read_view()
        self.assertIn("process.log: old | Traceback: | NameError: fixture", view["error"])
        self.assertTrue(self.reconcile())
        self.assertEqual(self.store.read_state()["error"], view["error"])

    def test_real_reaper_settles_dead_job_but_not_live_or_terminal(self):
        self.spawn_real(callback=self.reconcile)
        self.assertFalse(self.reconcile())
        self.cancel()
        self.until(lambda: self.store.read_state()["status"] == "error")
        self.store.update_state(self.job_id, status="found")
        self.assertFalse(self.reconcile())

    def test_start_queued_state_command_baseline_and_voice_flags(self):
        for service, baseline in (("youtube", True), ("discord-voice", False)):
            with self.subTest(service=service):
                settings = {"service": service, "mix_level": "safe", "max_candidates": 4, "search_seed": 5,
                            "client_ip": "192.168.2.60" if service == "discord-voice" else "",
                            "source_file": "general (ALT3).bat", "voice_auto": service == "discord-voice"}

                def launched(argv, **kwargs):
                    self.assertEqual(self.store.read_state()["status"], "queued")
                    self.assertEqual(self.store.job_id(), self.job_id)
                    self.assertFalse(self.store.read_state()["needs_voice_verdict"])
                    return mock.Mock(pid=4321)

                with mock.patch.object(self.mod.secrets, "token_hex", return_value=self.job_id), \
                        mock.patch.object(self.mod, "learned_voice_endpoint", return_value={"ip": "1.1.1.1", "port": 50000}), \
                        mock.patch.object(subprocess, "Popen", side_effect=launched) as popen:
                    self.assertEqual(self.mod.start_tuner_job(settings, baseline_only=baseline), 4321)
                expected = [sys.executable, str(self.cfg.AUTOTUNER), "--service", service, "--job-id", self.job_id,
                            "--mix-level", "safe", "--max-candidates", "4", "--search-seed", "5", "--http-timeout", "6",
                            "--voice-duration", "25"]
                if settings["client_ip"]:
                    expected += ["--client-ip", settings["client_ip"]]
                expected += ["--source-file", "general (ALT3).bat"]
                expected += ["--baseline-only"] if baseline else ["--voice-auto"]
                self.assertEqual(popen.call_args.args[0], expected)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_status_is_read_outside_lock_and_idle_is_rechecked(self):
        flags = {"busy": False}

        def status():
            self.assertFalse(self.jobs.JOB_START_LOCK.locked())
            flags["busy"] = True
            return {"ok": True, "youtube_route": "zapret"}

        self.patch(read_status_fields=status, route_active=lambda: flags["busy"])
        with mock.patch.object(self.store, "spawn") as spawn:
            with self.assertRaisesRegex(RuntimeError, "сначала завершите переключение маршрута"):
                self.start()
            spawn.assert_not_called()

    def test_holder_bypasses_own_hold_but_not_other_jobs(self):
        self.jobs.COORDINATOR.add_hold("automation", lambda: True, "held")
        self.addCleanup(lambda: self.jobs.COORDINATOR._holds.pop("automation", None))
        with self.assertRaisesRegex(RuntimeError, "held"):
            self.start()
        with mock.patch.object(subprocess, "Popen", return_value=mock.Mock(pid=4321)):
            self.assertEqual(self.start(holder="automation"), 4321)
        with self.patched(route_active=lambda: True), self.assertRaisesRegex(RuntimeError, "сначала завершите переключение маршрута"):
            self.start(holder="automation")

    def test_empty_cancel_is_old_error_and_spawn_failure_is_recorded(self):
        with self.assertRaisesRegex(RuntimeError, "активного подбора нет"):
            self.cancel()
        with mock.patch.object(subprocess, "Popen", side_effect=OSError("failed")):
            with self.assertRaisesRegex(OSError, "failed"):
                self.start()
        self.assertEqual(self.store.read_state()["status"], "error")

"""Tests of the automation of the panel (kdn.web.domain.automation): the run lock, the cancel flag and the schedule.

The behaviour of the schedule endpoints and of a whole slot is pinned in test_panel_endpoints.py and
test_panel_import.py; this file holds the lifecycle of the run lock and what moved with the split of the panel
into modules. The lock is a plain threading.Lock: a slot or a recovery takes it in one thread and the thread it
starts releases it.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import panel_harness


BUSY = {"tuner_active": lambda: True, "route_active": lambda: False, "diagnostic_active": lambda: False}
FREE = {"tuner_active": lambda: False, "route_active": lambda: False, "diagnostic_active": lambda: False}


class PanelAutomationTests(panel_harness.PanelTestCase):
    ns_name = "panel_automation_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.patch(AUTOMATION_CONFIG=self.root / "config.json", AUTOMATION_STATE=self.root / "state.json")
        self.lock = self.ns["AUTOMATION_RUN_LOCK"]
        self.cancel = self.ns["AUTOMATION_CANCEL"]
        self.addCleanup(self.cancel.clear)
        self.addCleanup(self.release_lock)
        self.config = {**self.ns["default_automation_config"](), "enabled": True}
        self.ns.module("automation").CONFIG.write(self.config)
        clock = mock.patch.object(self.ns.module("automation"), "datetime")
        clock.start().now.return_value = datetime(2026, 11, 6, 3, 0, tzinfo=self.ns["AUTOMATION_ZONE"])
        self.addCleanup(clock.stop)

    def release_lock(self):
        if self.lock.locked():
            self.lock.release()

    def state(self):
        return self.ns["automation_state"]()

    def test_launch_releases_the_run_lock_when_the_router_is_busy(self):
        self.patch(**BUSY)
        self.assertFalse(self.ns["launch_automation_slot"]("2026-11-06T03:00+0300", self.config))
        self.assertFalse(self.lock.locked())
        self.assertEqual(self.state()["status"], "skipped")
        self.assertEqual(self.state()["last_slot"], "2026-11-06T03:00+0300")

    def test_launch_remembers_a_slot_missed_while_a_run_holds_the_lock(self):
        self.lock.acquire()
        self.assertFalse(self.ns["launch_automation_slot"]("2026-11-06T03:00+0300", self.config))
        self.assertTrue(self.lock.locked())
        self.assertEqual(self.state()["last_slot"], "2026-11-06T03:00+0300")

    def test_launch_hands_the_run_lock_to_the_slot_thread(self):
        seen, finished = [], threading.Event()

        def slot(slot_id, _config):
            seen.append((slot_id, self.lock.locked()))
            self.lock.release()
            finished.set()

        self.patch(run_automation_slot=slot, **FREE)
        self.assertTrue(self.ns["launch_automation_slot"]("2026-11-06T03:00+0300", self.config))
        self.assertTrue(finished.wait(10))
        self.assertEqual(seen, [("2026-11-06T03:00+0300", True)])
        self.assertFalse(self.lock.locked())
        self.assertEqual(self.state()["status"], "running")

    def test_slot_clears_the_cancel_flag_and_releases_the_lock(self):
        self.patch(check_flowseal_update=mock.Mock(side_effect=RuntimeError("boom")))
        for cancelled, status in ((True, "cancelled"), (False, "error")):
            with self.subTest(cancelled=cancelled):
                self.lock.acquire()
                if cancelled:
                    self.cancel.set()
                self.ns["run_automation_slot"]("slot-4", self.config)
                self.assertEqual(self.state()["status"], status)
                self.assertEqual(self.state()["error"], "boom")
                self.assertFalse(self.cancel.is_set())
                self.assertFalse(self.lock.locked())

    def test_note_keeps_the_last_80_events_of_500_characters(self):
        for index in range(85):
            self.ns["automation_note"](f"event {index}")
        self.ns["automation_note"]("x" * 600)
        events = self.state()["events"]
        self.assertEqual(len(events), 80)
        self.assertEqual(events[0]["message"], "event 6")
        self.assertEqual(events[-1]["message"], "x" * 500)

    def test_schedule_takes_one_to_six_times(self):
        self.config["times"] = [f"0{hour}:00" for hour in range(6)]
        self.assertEqual(self.ns["validate_automation_config"](self.config)["times"], self.config["times"])
        self.config["times"].append("06:00")
        with self.assertRaisesRegex(ValueError, "от 1 до 6"):
            self.ns["validate_automation_config"](self.config)
        self.config["times"] = []
        with self.assertRaisesRegex(ValueError, "от 1 до 6"):
            self.ns["validate_automation_config"](self.config)

    def test_recovery_hands_the_run_lock_to_the_recovery_thread(self):
        recover, thread = mock.Mock(), mock.Mock()
        self.patch(recover_automation_transaction=recover)
        self.ns["save_automation_state"]({"status": "running", "transaction": {"service": "youtube"}})
        with mock.patch.object(self.ns["threading"], "Thread", thread):
            self.ns["start_automation_recovery"]()
        thread.assert_called_once_with(target=recover, daemon=True, name="zapret-automation-recovery")
        thread.return_value.start.assert_called_once_with()
        self.assertTrue(self.lock.locked())
        self.assertEqual(self.state()["status"], "recovering")

    def test_recovery_is_not_started_after_a_failed_recovery(self):
        thread = mock.Mock()
        self.ns["save_automation_state"]({"status": "recovery-failed", "transaction": {"service": "youtube"}})
        with mock.patch.object(self.ns["threading"], "Thread", thread):
            self.ns["start_automation_recovery"]()
        thread.assert_not_called()
        self.assertFalse(self.lock.locked())
        self.assertEqual(self.state()["status"], "recovery-failed")

    def test_scheduler_pauses_15_seconds_between_passes(self):
        sleep = mock.Mock(side_effect=StopIteration)
        self.patch(automation_config=lambda: {**self.config, "enabled": False}, automation_state=lambda: {})
        with mock.patch.object(self.ns["time"], "sleep", sleep), self.assertRaises(StopIteration):
            self.ns["automation_loop"]()
        sleep.assert_called_once_with(15)


if __name__ == "__main__":
    unittest.main()

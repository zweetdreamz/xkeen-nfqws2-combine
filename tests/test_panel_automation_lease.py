"""Automation's lease excludes manual starts and cancellation waits for restoration."""
from unittest import mock

import panel_harness


class LeaseTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.domain.automation",)

    def setUp(self):
        self.fresh_root()
        self.auto = self.ns.module("automation")
        self.jobs = self.ns.module("jobfiles")
        self.auto.AUTOMATION_CANCEL.clear()
        self.addCleanup(self.auto.AUTOMATION_CANCEL.clear)

    def test_hold_is_dynamic_and_blocks_manual_starts(self):
        self.assertIsNone(self.jobs.COORDINATOR.held("automation"))
        with self.auto.AUTOMATION_RUN_LOCK:
            self.assertEqual(self.jobs.COORDINATOR.held("automation"), self.auto.refusals.AUTOMATION_BUSY)
            with self.assertRaisesRegex(RuntimeError, "идёт проверка по расписанию"):
                self.jobs.COORDINATOR.ensure_idle(self.auto.refusals.ROUTE_CHANGE)
            self.jobs.COORDINATOR.ensure_idle(self.auto.refusals.TUNER_START, holder="automation")

    def test_slot_sees_quick_operation_start_without_family(self):
        with self.jobs.COORDINATOR.exclusive(self.auto.refusals.ROUTE_CHANGE), mock.patch.object(self.auto.threading, "Thread") as thread:
            self.assertFalse(self.auto.launch_automation_slot("test", self.auto.default_automation_config()))
            thread.assert_not_called()
        self.assertEqual(self.auto.automation_state()["status"], "skipped")

    def test_cancel_waits_for_exit_and_grace_is_bounded(self):
        self.auto.AUTOMATION_CANCEL.set()
        for failure in (None, OSError("signal denied"), RuntimeError("lost pidfile")):
            events = []
            states = iter([True, True, False])

            def cancel(failure=failure, events=events):
                events.append("cancel")
                if failure is not None:
                    raise failure

            with self.subTest(failure=failure), \
                    mock.patch.object(self.jobs, "tuner_process_alive", side_effect=lambda pid, states=states: next(states)), \
                    mock.patch.object(self.auto.tuner_jobs, "cancel_tuner_job", side_effect=cancel), \
                    mock.patch.object(self.auto.time, "sleep", side_effect=lambda sec, events=events: events.append("wait")):
                with self.assertRaisesRegex(RuntimeError, "задание остановлено пользователем"):
                    self.auto.wait_automation_tuner(123, 10)
            self.assertEqual(events, ["cancel", "wait"])

    def test_deadline_also_cancels_and_waits(self):
        states = iter([True, True, False])
        events = []
        with mock.patch.object(self.jobs, "tuner_process_alive", side_effect=lambda pid: next(states)), \
                mock.patch.object(self.auto.time, "monotonic", return_value=0), \
                mock.patch.object(self.auto.time, "sleep", side_effect=lambda seconds: events.append("wait")), \
                mock.patch.object(self.auto.tuner_jobs, "cancel_tuner_job", side_effect=lambda: events.append("cancel")):
            with self.assertRaisesRegex(RuntimeError, "подбор превысил лимит времени"):
                self.auto.wait_automation_tuner(123, 0)
        self.assertEqual(events, ["cancel", "wait"])

    def test_cancel_grace_is_bounded(self):
        self.auto.AUTOMATION_CANCEL.set()
        with mock.patch.object(self.jobs, "tuner_process_alive", return_value=True), \
                mock.patch.object(self.auto.tuner_jobs, "cancel_tuner_job"), \
                mock.patch.object(self.auto.time, "monotonic", side_effect=[0, 0, 151]):
            with self.assertRaisesRegex(RuntimeError, "подбор не завершился после остановки"):
                self.auto.wait_automation_tuner(123, 10)

    def test_recovery_nonblocking_and_scheduler_warning_uses_logger(self):
        self.auto.save_automation_state({"status": "running", "transaction": {"service": "youtube"}})
        with self.auto.AUTOMATION_RUN_LOCK, mock.patch.object(self.auto.threading, "Thread") as thread:
            self.auto.start_automation_recovery(blocking=False)
            thread.assert_not_called()
        with mock.patch.object(self.auto, "automation_state", side_effect=OSError("fixture")), \
                mock.patch.object(self.auto.time, "sleep", side_effect=StopIteration), \
                mock.patch.object(self.auto.logsetup, "panel_logger") as logger:
            with self.assertRaises(StopIteration):
                self.auto.automation_loop()
            logger.return_value.warning.assert_called_once()

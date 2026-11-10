"""Local regressions for scheduled jobs and shared subprocess output ownership."""
from datetime import datetime
from pathlib import Path
import sys
import time
from unittest import mock

import panel_harness


class AutomationLaunchTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.domain.automation",)

    def setUp(self):
        self.fresh_root()
        self.auto = self.ns.module("automation")
        self.config = {**self.auto.default_automation_config(), "enabled": True}
        self.auto.CONFIG.write(self.config)
        self.slot = "2026-11-06T03:00+0300"
        clock = mock.patch.object(self.auto, "datetime")
        clock.start().now.return_value = datetime(2026, 11, 6, 3, 0, tzinfo=self.auto.AUTOMATION_ZONE)
        self.addCleanup(clock.stop)
        self.addCleanup(self.release)

    def release(self):
        if self.auto.AUTOMATION_RUN_LOCK.locked():
            self.auto.AUTOMATION_RUN_LOCK.release()

    def test_recovery_finishing_between_scheduler_reads_does_not_launch(self):
        auto = self.auto
        auto.save_automation_state({"status": "error", "transaction": {"schema": 2, "operation_id": "fixture"}})
        launched = []

        class Thread:
            def __init__(self, *, target, args=(), **kwargs):
                self.target, self.args = target, args

            def start(self):
                if self.target is auto.run_automation_slot:
                    launched.append(self.args)

        class Clock:
            @staticmethod
            def now(zone):
                if auto.AUTOMATION_RUN_LOCK.locked():
                    auto.recover_automation_transaction()
                return datetime(2026, 11, 6, 3, 0, tzinfo=zone)

        with mock.patch.object(auto.threading, "Thread", Thread), \
                mock.patch.object(auto, "datetime", Clock), \
                mock.patch.object(auto, "automation_rollback_import", side_effect=RuntimeError("не совпал с исходным")), \
                mock.patch.object(auto.time, "sleep", side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                auto.automation_loop()
        self.assertEqual(launched, [])
        state = auto.automation_state()
        self.assertEqual(state["status"], "recovery-failed")
        self.assertEqual(state["transaction"]["operation_id"], "fixture")
        self.assertFalse(auto.automation_config()["enabled"])
        self.assertFalse(auto.AUTOMATION_RUN_LOCK.locked())

    def test_launch_does_not_replace_pending_transaction(self):
        state = {"status": "error", "transaction": {"operation_id": "pending"}}
        self.auto.save_automation_state(state)
        with mock.patch.object(self.auto.threading, "Thread"):
            self.assertFalse(self.auto.launch_automation_slot(self.slot, self.config))
        self.assertEqual(self.auto.automation_state(), state)
        self.assertFalse(self.auto.AUTOMATION_RUN_LOCK.locked())

    def test_launch_rechecks_disabled_schedule(self):
        self.auto.CONFIG.write({**self.config, "enabled": False})
        with mock.patch.object(self.auto.threading, "Thread"):
            self.assertFalse(self.auto.launch_automation_slot(self.slot, self.config))
        self.assertEqual(self.auto.automation_state()["status"], "idle")
        self.assertFalse(self.auto.AUTOMATION_RUN_LOCK.locked())


    def test_launch_keeps_recovery_failed_latch_with_enabled_config(self):
        state = {"status": "recovery-failed", "error": "restore failed"}
        self.auto.save_automation_state(state)
        with mock.patch.object(self.auto.threading, "Thread"):
            self.assertFalse(self.auto.launch_automation_slot(self.slot, self.config))
        self.assertEqual(self.auto.automation_state(), state)
        self.assertFalse(self.auto.AUTOMATION_RUN_LOCK.locked())

    def test_launch_rechecks_slot_time_and_duplicate_consumption(self):
        for times, last_slot, requested in (
            (["04:00"], "", self.slot),
            (["03:00"], self.slot, self.slot),
            (["03:00"], "", "2026-11-05T03:00+0300"),
        ):
            with self.subTest(times=times, last_slot=last_slot, requested=requested):
                self.auto.CONFIG.write({**self.config, "times": times})
                state = {"status": "completed", "last_slot": last_slot}
                self.auto.save_automation_state(state)
                with mock.patch.object(self.auto.threading, "Thread"):
                    self.assertFalse(self.auto.launch_automation_slot(requested, self.config))
                self.assertEqual(self.auto.automation_state(), state)
                self.assertFalse(self.auto.AUTOMATION_RUN_LOCK.locked())


class RouteOutputTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.domain.route_jobs",)

    def test_progress_read_cannot_rewind_child_stdout(self):
        root = self.fresh_root()
        routes = self.ns.module("route_jobs")
        log = routes.cfg.ROUTE_APPLY_LOG
        log.parent.mkdir(parents=True, exist_ok=True)
        trigger, ack = root / "trigger", root / "ack"
        snapshot = routes.cfg.SNAPSHOT_DIR / "fixture-snapshot"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").touch()
        (snapshot / "MANIFEST").touch()
        child = """
import os, pathlib, sys, time
trigger, ack, snapshot = map(pathlib.Path, sys.argv[1:])
os.write(1, ('Snapshot created: ' + str(snapshot) + '\\n').encode())
while not trigger.exists():
    time.sleep(.001)
os.write(1, b'CHILD-WRITE\\n')
ack.touch()
"""
        original_open = Path.open

        class ControlledReader:
            def __init__(self, raw):
                self.raw = raw
                self.first = True

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.raw.close()

            def __getattr__(self, name):
                return getattr(self.raw, name)

            def read(self, *args):
                if self.first:
                    self.first = False
                    trigger.touch()
                    deadline = time.monotonic() + 5
                    while not ack.exists():
                        assert time.monotonic() < deadline
                        time.sleep(.001)
                return self.raw.read(*args)

        def controlled_open(path, *args, **kwargs):
            raw = original_open(path, *args, **kwargs)
            return ControlledReader(raw) if path == log and args in (("w+b",), ("rb",)) else raw

        with mock.patch.object(Path, "open", controlled_open):
            result = routes.run_route_command(
                [sys.executable, "-c", child, str(trigger), str(ack), str(snapshot)],
                "fixture", "switch", timeout=8,
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["output"], "Snapshot created: " + str(snapshot) + "\nCHILD-WRITE")
        self.assertEqual(routes.engine.parse_snapshot_from_output(result["output"]), str(snapshot))

"""Tests of the fail-safe of the automation: the schedule file under a lock and the state that must stay readable.

An unreadable automation-state.json blocks the nightly scheduler and the enabling of the schedule until the file is
fixed or removed (the user's decision for the recovery-failed latch, variant B). The schedule file
(automation-config.json) is read, changed and written under one lock, so the disabling after a recovery and the
save of the schedule lose no change of each other.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import panel_fixtures
import panel_harness


MOSCOW_NOW = datetime(2026, 10, 28, 3, 0, tzinfo=timezone(timedelta(hours=3)))
SLOT = "2026-10-28T03:00+0300"
STATE_UNREADABLE = (
    "состояние расписания повреждено (automation-state.json): сначала исправьте или удалите файл "
    "(копия непустого файла — automation-state.json.corrupt) и повторите"
)
RECOVERY_FAILED = "после неудачного отката сначала проверьте nfqws2 и выполните ручное восстановление"
NOTE_PREFIX = "Не удалось выключить расписание после прерывания: "
# Every kind of file that does not read as a JSON object: broken text, empty, a list, not UTF-8.
UNREADABLE_STATES = (b"{broken", b"", b"[]", b"\xff\xfe{}")


class Clock:
    @staticmethod
    def now(_zone):
        return MOSCOW_NOW


class ProbeLock:
    """A lock that sets ``contended`` when a thread comes to take it while it is held: an interleaving point."""

    def __init__(self, contended):
        self.lock = threading.Lock()
        self.contended = contended

    def __enter__(self):
        if self.lock.locked():
            self.contended.set()
        self.lock.acquire()
        return self

    def __exit__(self, *_exc):
        self.lock.release()

    def acquire(self, *args, **kwargs):
        if self.lock.locked():
            self.contended.set()
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        self.lock.release()

    def locked(self):
        return self.lock.locked()


class AutomationFailsafeTests(panel_harness.PanelTestCase):
    ns_name = "panel_automation_failsafe_test"
    modules = ("kdn.web.domain.automation",)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config_file = self.root / "automation-config.json"
        self.state_file = self.root / "automation-state.json"
        self.launch = mock.Mock(return_value=True)
        # A slot that does start must not run the real checks.
        self.patch(AUTOMATION_CONFIG=self.config_file, AUTOMATION_STATE=self.state_file, run_automation_slot=mock.Mock())
        self.run_lock = self.ns["AUTOMATION_RUN_LOCK"]
        self.addCleanup(self.release_run_lock)
        self.addCleanup(self.ns["AUTOMATION_CANCEL"].clear)
        self.config = {**self.ns["default_automation_config"](), "enabled": True, "times": ["03:00"]}
        self.counter = 0

    def release_run_lock(self):
        if self.run_lock.locked():
            self.run_lock.release()

    def write_config(self, config=None):
        self.config_file.write_text(json.dumps(self.config if config is None else config), encoding="utf-8")

    def stored_config(self):
        return json.loads(self.config_file.read_text(encoding="utf-8"))

    def break_state(self, content=b"{broken"):
        """Point the panel at a new, unreadable state file (every call a file of its own) and return its path."""
        self.counter += 1
        path = self.root / f"state-{self.counter}" / "automation-state.json"
        path.parent.mkdir()
        path.write_bytes(content)
        self.patch(AUTOMATION_STATE=path)
        return path

    @staticmethod
    def untouched(path):
        info = path.stat()
        return path.read_bytes(), info.st_mtime_ns

    def run_loop(self, ticks=1, after_pass=None, **patches):
        """Run ``ticks`` passes of the scheduler at 03:00 Moscow time; return what it wrote to stderr."""
        passes = []

        def sleep(_seconds):
            passes.append(1)
            if len(passes) >= ticks:
                raise StopIteration
            if after_pass is not None:
                after_pass(len(passes))

        stderr = io.StringIO()
        logger = mock.Mock()
        logger.warning.side_effect = lambda message, *args: stderr.write((message % args) + "\n")
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.patched(datetime=Clock, launch_automation_slot=self.launch, **patches))
            stack.enter_context(mock.patch.object(self.ns["time"], "sleep", sleep))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            stack.enter_context(mock.patch.object(self.ns.module("automation").logsetup, "panel_logger", return_value=logger))
            stack.enter_context(self.assertRaises(StopIteration))
            self.ns["automation_loop"]()
        return stderr.getvalue()

    # The scheduler.

    def test_scheduler_tick_does_not_launch_while_the_state_is_unreadable(self):
        self.write_config()
        for content in UNREADABLE_STATES:
            with self.subTest(content=content):
                path = self.break_state(content)
                before = self.untouched(path)
                self.launch.reset_mock()
                stderr = self.run_loop(ticks=2)
                self.launch.assert_not_called()
                self.assertEqual(self.untouched(path), before)
                self.assertEqual(stderr.count("\n"), 1, stderr)
                self.assertIn("state unreadable", stderr)

    def test_scheduler_resumes_after_the_state_file_is_removed_or_fixed(self):
        self.write_config()
        launched_while_broken = []
        repairs = {
            "removed": Path.unlink,
            "fixed": lambda path: path.write_text('{"status": "idle", "history": []}', encoding="utf-8"),
        }
        for name, repair in repairs.items():
            with self.subTest(repair=name):
                path = self.break_state()
                self.launch.reset_mock()
                launched_while_broken.clear()

                def after_pass(_count, path=path, repair=repair):
                    launched_while_broken.append(self.launch.call_count)
                    repair(path)

                self.run_loop(ticks=2, after_pass=after_pass)
                self.assertEqual(launched_while_broken, [0])
                self.launch.assert_called_once_with(SLOT, self.ns["automation_config"]())

    def test_scheduler_does_not_start_recovery_for_an_unreadable_state(self):
        self.write_config()
        state = {"status": "idle", "history": [], "transaction": {"service": "youtube"},
                 "state_error": "ValueError: unreadable"}
        recovery = mock.Mock()
        self.run_loop(ticks=2, automation_state=lambda: state, start_automation_recovery=recovery)
        recovery.assert_not_called()
        self.launch.assert_not_called()

    def test_unreadable_state_is_copied_to_corrupt_once_and_not_overwritten(self):
        self.write_config()
        path = self.break_state(b"{broken")
        corrupt = path.with_name(path.name + ".corrupt")
        store = self.ns["STATE"]

        def after_pass(count):
            self.assertEqual(corrupt.read_bytes(), b"{broken")
            if count == 2:
                path.write_bytes(b"[]")  # still unreadable, but another error: a new line, no new copy

        with mock.patch.object(store, "preserve", wraps=store.preserve) as preserve:
            stderr = self.run_loop(ticks=4, after_pass=after_pass)
        preserve.assert_called_once_with()
        self.assertEqual(corrupt.read_bytes(), b"{broken")
        self.assertEqual(path.read_bytes(), b"[]")
        # Two ticks with the first error and two with the second: one line for each of the errors.
        self.assertEqual(stderr.count("\n"), 2, stderr)
        self.launch.assert_not_called()

    def test_an_empty_file_that_turns_into_garbage_gets_its_copy_on_the_new_error(self):
        self.write_config()
        path = self.break_state(b"")
        corrupt = path.with_name(path.name + ".corrupt")

        def after_pass(count):
            self.assertFalse(corrupt.exists())
            path.write_bytes(b"[]")

        self.run_loop(ticks=2, after_pass=after_pass)
        self.assertEqual(corrupt.read_bytes(), b"[]")

    def test_a_failed_copy_is_retried_on_each_new_error_until_one_is_made(self):
        self.write_config()
        path = self.break_state(b"{broken")
        errors = [b"[]", b"\xff\xfe{}"]

        def after_pass(count):
            path.write_bytes(errors[count - 1])

        store = self.ns["STATE"]
        with mock.patch.object(store, "preserve", side_effect=[False, True]) as preserve:
            stderr = self.run_loop(ticks=3, after_pass=after_pass)
        # Three errors: the first copy failed, the second succeeded, the third needs none.
        self.assertEqual(preserve.call_count, 2)
        self.assertEqual(stderr.count("\n"), 3, stderr)

    def test_scheduler_reports_an_error_again_after_the_file_was_fixed_and_broke_again(self):
        self.write_config()
        path = self.break_state()
        broken = [b'{"status": "idle", "history": []}', b"{broken", b"{broken"]

        def after_pass(count):
            path.write_bytes(broken[count - 1])

        stderr = self.run_loop(ticks=4, after_pass=after_pass)
        self.assertEqual(stderr.count("\n"), 2, stderr)

    def test_startup_recovery_and_the_scheduler_report_one_error_once(self):
        path = self.break_state()
        stderr = io.StringIO()
        logger = mock.Mock()
        logger.warning.side_effect = lambda message, *args: stderr.write((message % args) + "\n")
        with mock.patch.object(self.ns.module("automation").logsetup, "panel_logger", return_value=logger):
            self.ns["start_automation_recovery"]()
        self.assertEqual(stderr.getvalue().count("\n"), 1, stderr.getvalue())
        self.assertEqual(self.run_loop(), "")
        self.assertEqual(path.read_bytes(), b"{broken")

    def test_startup_recovery_keeps_a_copy_of_an_unreadable_state(self):
        path = self.break_state()
        with contextlib.redirect_stderr(io.StringIO()):
            self.ns["start_automation_recovery"]()
        self.assertEqual(path.read_bytes(), b"{broken")
        self.assertEqual(path.with_name(path.name + ".corrupt").read_bytes(), b"{broken")

    # A slot.

    def test_launch_returns_false_before_any_write_when_the_state_is_unreadable(self):
        for held in (False, True):
            with self.subTest(run_lock_held=held):
                path = self.break_state()
                before = self.untouched(path)
                if held:
                    self.run_lock.acquire()
                try:
                    self.assertFalse(self.ns["launch_automation_slot"](SLOT, self.config))
                finally:
                    self.release_run_lock()
                self.assertEqual(self.untouched(path), before)
                self.assertEqual(sorted(entry.name for entry in path.parent.iterdir()), ["automation-state.json"])
                self.assertFalse(self.run_lock.locked())
                self.ns["run_automation_slot"].assert_not_called()

    # The schedule.

    def test_enabling_is_refused_while_the_state_is_unreadable_and_disabling_is_allowed(self):
        path = self.break_state()
        before = self.untouched(path)
        with self.assertRaises(ValueError) as refused:
            self.ns["save_automation_config"](self.config)
        self.assertEqual(str(refused.exception), STATE_UNREADABLE)
        self.assertEqual(self.ns["STATE_UNREADABLE"], STATE_UNREADABLE)
        self.assertFalse(self.config_file.exists())
        disabled = {**self.config, "enabled": False, "times": ["04:30", "02:15"]}
        status = self.ns["save_automation_config"](disabled)
        self.assertTrue(status["ok"])
        self.assertFalse(status["config"]["enabled"])
        self.assertEqual(self.stored_config(), self.ns["validate_automation_config"](disabled))
        self.assertEqual(self.stored_config()["times"], ["02:15", "04:30"])
        self.assertEqual(self.untouched(path), before)

    def test_enabling_works_again_once_the_state_file_is_removed(self):
        path = self.break_state()
        with self.assertRaises(ValueError):
            self.ns["save_automation_config"](self.config)
        path.unlink()
        status = self.ns["save_automation_config"](self.config)
        self.assertTrue(status["config"]["enabled"])
        self.assertTrue(self.stored_config()["enabled"])

    def test_enabling_is_still_refused_after_recovery_failed(self):
        self.ns["save_automation_state"]({"status": "recovery-failed"})
        with self.assertRaises(ValueError) as refused:
            self.ns["save_automation_config"](self.config)
        self.assertEqual(str(refused.exception), RECOVERY_FAILED)
        self.assertNotEqual(RECOVERY_FAILED, STATE_UNREADABLE)
        self.assertFalse(self.config_file.exists())
        status = self.ns["save_automation_config"]({**self.config, "enabled": False})
        self.assertFalse(status["config"]["enabled"])

    def test_save_validates_before_it_stores_and_returns_the_status(self):
        with self.assertRaisesRegex(ValueError, "неверный формат расписания"):
            self.ns["save_automation_config"]({"enabled": True})
        self.assertFalse(self.config_file.exists())
        status = self.ns["save_automation_config"](self.config)
        self.assertEqual(status["config"], self.stored_config())
        self.assertEqual(status["state"], {"status": "idle", "history": []})
        self.assertIsNotNone(status["next_run"])
        self.assertEqual(
            self.config_file.read_text(encoding="utf-8"),
            json.dumps(self.stored_config(), ensure_ascii=False, indent=2) + "\n",
        )

    def test_status_reports_the_blocker_without_writing(self):
        self.write_config()
        path = self.break_state()
        before = panel_fixtures.tree_digest(self.root)
        status = self.ns["automation_status"]()
        self.assertEqual(panel_fixtures.tree_digest(self.root), before)
        self.assertEqual(status["state"]["error"], STATE_UNREADABLE)
        self.assertRegex(status["state"]["state_error"], r"^JSONDecodeError: .+")
        self.assertEqual(path.read_bytes(), b"{broken")

    def test_status_of_a_readable_state_has_no_blocker(self):
        self.ns["save_automation_state"]({"status": "completed", "active": False})
        state = self.ns["automation_status"]()["state"]
        self.assertNotIn("error", state)
        self.assertNotIn("state_error", state)

    def test_state_blocker_is_the_message_for_an_unreadable_state_only(self):
        blocker = self.ns["state_blocker"]
        self.assertEqual(blocker({"status": "idle", "state_error": "ValueError: x"}), STATE_UNREADABLE)
        self.assertEqual(blocker({"status": "idle"}), "")
        self.assertEqual(blocker({"status": "recovery-failed"}), "")

    # The schedule file under its lock.

    def test_disable_turns_the_schedule_off_and_keeps_the_rest(self):
        self.config["times"] = ["04:30", "03:00"]
        self.write_config()
        self.ns["disable_automation_after_recovery"]()
        stored = self.stored_config()
        self.assertEqual(stored, {**self.ns["validate_automation_config"](self.config), "enabled": False})
        self.assertEqual(stored["times"], ["03:00", "04:30"])
        self.assertEqual(
            self.config_file.read_text(encoding="utf-8"), json.dumps(stored, ensure_ascii=False, indent=2) + "\n"
        )
        self.assertNotIn("events", self.ns["automation_state"]())

    def test_disable_leaves_a_disabled_or_a_missing_schedule_alone(self):
        self.ns["disable_automation_after_recovery"]()
        self.assertFalse(self.config_file.exists())
        self.write_config({**self.config, "enabled": False})
        before = self.untouched(self.config_file)
        self.ns["disable_automation_after_recovery"]()
        self.assertEqual(self.untouched(self.config_file), before)
        self.assertNotIn("events", self.ns["automation_state"]())

    def test_disable_with_an_unreadable_config_notes_the_failure(self):
        for content in (b"{broken", b"", b"[]", json.dumps({**self.config, "version": 2}).encode()):
            with self.subTest(content=content):
                self.config_file.write_bytes(content)
                self.ns["disable_automation_after_recovery"]()
                self.assertEqual(self.config_file.read_bytes(), content)
                self.assertFalse(self.config_file.with_name("automation-config.json.corrupt").exists())
                self.assertTrue(self.ns["automation_state"]()["events"][-1]["message"].startswith(NOTE_PREFIX))

    def test_disable_after_recovery_waits_for_the_config_lock(self):
        self.write_config()
        lock = self.ns["AUTOMATION_CONFIG_LOCK"]
        thread = threading.Thread(target=self.ns["disable_automation_after_recovery"], daemon=True)
        with lock:
            thread.start()
            thread.join(0.2)
            self.assertTrue(thread.is_alive(), "the disabling did not wait for the schedule lock")
            self.assertTrue(self.stored_config()["enabled"])
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.stored_config()["enabled"])

    def test_save_waits_for_the_config_lock(self):
        lock = self.ns["AUTOMATION_CONFIG_LOCK"]
        thread = threading.Thread(target=self.ns["save_automation_config"], args=(self.config,), daemon=True)
        with lock:
            thread.start()
            thread.join(0.2)
            self.assertTrue(thread.is_alive(), "the save did not wait for the schedule lock")
            self.assertFalse(self.config_file.exists())
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertTrue(self.stored_config()["enabled"])

    def test_save_and_disable_lose_no_change(self):
        self.write_config()
        arrived = threading.Event()
        self.patch(AUTOMATION_CONFIG_LOCK=ProbeLock(arrived))
        fsutil = self.ns.module("common.fsutil")
        real_read = fsutil.safe_json_file
        read_done, resume = threading.Event(), threading.Event()
        stops = []

        def read_then_wait(path, *args, **kwargs):
            data = real_read(path, *args, **kwargs)
            if threading.current_thread() is disable and path == self.config_file and not stops:
                # The disabling has read the stored schedule and is about to write it back changed.
                stops.append(path)
                read_done.set()
                resume.wait(10)
            return data

        saved = {**self.config, "enabled": False, "times": ["04:30"]}

        def save():
            try:
                self.ns["save_automation_config"](saved)
            finally:
                arrived.set()  # the save is through, or it came to the lock the disabling holds

        disable = threading.Thread(target=self.ns["disable_automation_after_recovery"], daemon=True)
        save_thread = threading.Thread(target=save, daemon=True)
        with mock.patch.object(fsutil, "safe_json_file", read_then_wait):
            disable.start()
            self.assertTrue(read_done.wait(10))
            save_thread.start()
            self.assertTrue(arrived.wait(10))
            resume.set()
            for thread in (disable, save_thread):
                thread.join(10)
                self.assertFalse(thread.is_alive())
        self.assertEqual(self.stored_config(), self.ns["validate_automation_config"](saved))

    def test_enabling_checks_the_state_after_it_has_the_config_lock(self):
        arrived = threading.Event()
        probe = ProbeLock(arrived)
        self.patch(AUTOMATION_CONFIG_LOCK=probe)
        refusals = []

        def enable():
            try:
                self.ns["save_automation_config"](self.config)
            except ValueError as exc:
                refusals.append(str(exc))

        thread = threading.Thread(target=enable, daemon=True)
        with probe:
            thread.start()
            self.assertTrue(arrived.wait(10))
            # The recovery fails while the save waits for the lock; its disabling takes the lock next.
            self.ns["save_automation_state"]({"status": "recovery-failed"})
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(refusals, [RECOVERY_FAILED])
        self.assertFalse(self.config_file.exists())

    def test_save_over_a_corrupt_config_keeps_a_copy(self):
        self.config_file.write_bytes(b"{broken")
        self.ns["save_automation_config"](self.config)
        self.assertEqual(self.config_file.with_name("automation-config.json.corrupt").read_bytes(), b"{broken")
        self.assertEqual(self.stored_config(), self.ns["validate_automation_config"](self.config))


class StatePreserveTests(panel_harness.PanelTestCase):
    ns_name = "panel_state_preserve_test"
    modules = ("kdn.web.infra.statestore",)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "state.json"
        self.corrupt = self.root / "state.json.corrupt"
        self.lock = threading.Lock()
        self.store = self.ns.module("infra.statestore").StateStore(
            lambda: self.path, lambda: self.lock, lambda: {"status": "idle", "history": []}
        )
        self.limit = self.ns.module("common.fsutil").MAX_JSON_BYTES

    def clean(self):
        for entry in (self.path, self.corrupt):
            entry.unlink(missing_ok=True)

    def test_preserve_copies_unreadable_files_only(self):
        target = self.root / "target.json"
        target.write_bytes(b"{broken")

        def symlink():
            self.path.symlink_to(target)

        cases = {
            "missing": lambda: None,
            "readable": lambda: self.path.write_text('{"status": "idle"}', encoding="utf-8"),
            "empty": lambda: self.path.write_bytes(b""),
            "symlink": symlink,
            "oversized": lambda: self.path.write_bytes(b" " * (self.limit + 1)),
        }
        for name, make in cases.items():
            with self.subTest(file=name):
                self.clean()
                make()
                self.assertIs(self.store.preserve(), False)
                self.assertFalse(self.corrupt.exists())
        self.assertEqual(target.read_bytes(), b"{broken")

    def test_preserve_copies_every_kind_of_unreadable_file_byte_for_byte(self):
        for content in UNREADABLE_STATES:
            if not content:
                continue
            with self.subTest(content=content):
                self.clean()
                self.path.write_bytes(content)
                self.assertIs(self.store.preserve(), True)
                self.assertEqual(self.corrupt.read_bytes(), content)
                self.assertEqual(self.path.read_bytes(), content)

    def test_preserve_replaces_the_earlier_copy_but_not_by_an_empty_file(self):
        self.corrupt.write_bytes(b"older")
        self.path.write_bytes(b"{newer")
        self.assertIs(self.store.preserve(), True)
        self.assertEqual(self.corrupt.read_bytes(), b"{newer")
        self.path.write_bytes(b"")
        self.assertIs(self.store.preserve(), False)
        self.assertEqual(self.corrupt.read_bytes(), b"{newer")

    def test_preserve_does_not_touch_the_state_file(self):
        self.path.write_bytes(b"{broken")
        before = (self.path.read_bytes(), self.path.stat().st_mtime_ns)
        self.store.preserve()
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_preserve_waits_for_the_store_lock(self):
        self.path.write_bytes(b"{broken")
        results = []
        thread = threading.Thread(target=lambda: results.append(self.store.preserve()), daemon=True)
        with self.lock:
            thread.start()
            thread.join(0.2)
            self.assertTrue(thread.is_alive(), "preserve did not wait for the store lock")
            self.assertFalse(self.corrupt.exists())
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, [True])
        self.assertEqual(self.corrupt.read_bytes(), b"{broken")

    def test_a_failed_copy_is_reported_as_not_made(self):
        self.path.write_bytes(b"{broken")
        stderr = io.StringIO()
        with (
            mock.patch.object(self.ns.module("infra.statestore"), "_replace_file", side_effect=OSError("disk full")),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertIs(self.store.preserve(), False)
        self.assertIn("disk full", stderr.getvalue())
        self.assertFalse(self.corrupt.exists())


if __name__ == "__main__":
    unittest.main()

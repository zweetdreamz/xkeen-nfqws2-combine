"""Tests of the automation state store (kdn.web.infra.statestore) and of the automation state around it.

The store is the one place that reads and writes automation-state.json: every read-modify-write of the file runs
under one lock, a broken file is kept as ``<name>.corrupt`` before it is overwritten, and a GET of the status
never writes. The interleavings here are forced with hooks, not left to the scheduler: a thread test that passes
only on a lucky schedule pins nothing.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import threading
import unittest
from unittest import mock

import panel_harness


BROKEN_STATES = (
    ("", "ValueError"),
    ("{broken", "JSONDecodeError"),
    ("[]", "ValueError"),
    (b"\xff\xfe{}", "UnicodeDecodeError"),
)
DEFAULT_STATE = {"status": "idle", "history": []}


def write_any(path, content):
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


class HookLock:
    """A lock that runs a one-shot callback just before it is taken: an interleaving point for a test."""

    def __init__(self):
        self.lock = threading.Lock()
        self.before_acquire = None

    def fire(self):
        callback, self.before_acquire = self.before_acquire, None
        if callback is not None:
            callback()

    def __enter__(self):
        self.fire()
        self.lock.acquire()
        return self

    def __exit__(self, *_exc):
        self.lock.release()

    def acquire(self, *args, **kwargs):
        self.fire()
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        self.lock.release()

    def locked(self):
        return self.lock.locked()


class StateStoreTests(panel_harness.PanelTestCase):
    ns_name = "panel_statestore_test"

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

    def saved(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def stderr_of(self, call):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            call()
        return stderr.getvalue()

    def opens_of_the_state_file(self, call):
        """Run ``call`` and return how often the state file was opened for reading by path."""
        with mock.patch.object(os, "open", wraps=os.open) as opened:
            call()
        return [entry for entry in opened.call_args_list if entry.args[0] == self.path]

    def blocked_until_the_lock_is_free(self, call):
        """Run ``call`` in a thread while the test holds the store lock; return its result once the lock is free."""
        results = []
        thread = threading.Thread(target=lambda: results.append(call()), daemon=True)
        self.lock.acquire()
        try:
            thread.start()
            thread.join(0.2)
            self.assertTrue(thread.is_alive(), "the call did not wait for the store lock")
            self.assertFalse(self.path.exists())
        finally:
            self.lock.release()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        return results[0]

    def test_read_defaults_and_reports_corruption(self):
        first = self.store.read()
        self.assertEqual(first, DEFAULT_STATE)
        first["history"].append("leak")
        self.assertEqual(self.store.read(), DEFAULT_STATE, "the default is built anew on every read")
        for content, error_class in BROKEN_STATES:
            with self.subTest(content=content):
                write_any(self.path, content)
                state = self.store.read()
                self.assertEqual((state["status"], state["history"]), ("idle", []))
                self.assertRegex(state["state_error"], rf"^{error_class}: .+")
        fsutil = self.ns.module("common.fsutil")
        with mock.patch.object(fsutil, "safe_json_file", side_effect=PermissionError("denied")):
            self.assertEqual(self.store.read(), {**DEFAULT_STATE, "state_error": "PermissionError: denied"})

    def test_read_does_not_take_the_lock(self):
        self.store.write({"status": "idle", "history": [], "phase": "x"})
        results = []
        thread = threading.Thread(target=lambda: results.append(self.store.read()), daemon=True)
        with self.lock:
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "read waited for the store lock")
        self.assertEqual(results[0]["phase"], "x")

    def test_write_drops_state_error(self):
        self.store.write({"status": "running", "state_error": "ValueError: stale", "note": "кириллица"})
        text = self.path.read_text(encoding="utf-8")
        self.assertEqual(
            text, json.dumps({"status": "running", "note": "кириллица"}, ensure_ascii=False, indent=2) + "\n"
        )
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("state_error", self.store.read())

    def test_durable_write_syncs_new_file_mode_before_replace_then_parent_directories(self):
        events = []
        real_chmod, real_fsync, real_replace = os.fchmod, os.fsync, os.replace
        def chmod(fd, mode):
            events.append('mode')
            return real_chmod(fd, mode)
        def fsync(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertFalse(self.path.exists(), 'file fsync must precede publication')
                events.append('file')
            else:
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                self.assertEqual(self.saved(), DEFAULT_STATE)
                events.append('directory')
            return real_fsync(fd)
        def replace(source, target):
            self.assertEqual(events, ['mode', 'file'])
            events.append('replace')
            return real_replace(source, target)
        with (mock.patch.object(os, 'fchmod', chmod), mock.patch.object(os, 'fsync', fsync),
              mock.patch.object(os, 'replace', replace)):
            self.store.write(DEFAULT_STATE)
        self.assertEqual(events, ['mode', 'file', 'replace', 'directory', 'directory'])

    def test_write_over_a_readable_or_missing_file_makes_no_copy(self):
        self.store.write({"status": "idle", "history": []})
        self.store.write({"status": "idle", "history": [], "phase": "x"})
        self.assertEqual(sorted(entry.name for entry in self.root.iterdir()), ["state.json"])

    def test_write_over_corrupt_file_keeps_a_corrupt_copy_once(self):
        broken = b"\xff\xfe{broken"
        self.path.write_bytes(broken)
        self.store.write({"status": "idle", "history": []})
        self.assertEqual(self.corrupt.read_bytes(), broken)
        self.assertEqual(self.corrupt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.saved(), DEFAULT_STATE)
        self.store.write({"status": "idle", "history": [], "phase": "x"})
        self.assertEqual(self.corrupt.read_bytes(), broken)
        self.assertEqual(sorted(entry.name for entry in self.root.iterdir()), ["state.json", "state.json.corrupt"])

    def test_every_kind_of_unreadable_file_is_copied_byte_for_byte(self):
        # An empty file is unreadable too, but has nothing to copy: see the test below.
        for content, _error_class in (state for state in BROKEN_STATES if state[0]):
            with self.subTest(content=content):
                write_any(self.path, content)
                self.store.write({"status": "idle", "history": []})
                expected = content if isinstance(content, bytes) else content.encode("utf-8")
                self.assertEqual(self.corrupt.read_bytes(), expected)

    def test_an_empty_file_is_not_copied_and_keeps_the_earlier_copy(self):
        # A zero-byte state holds nothing to keep; copying it would only wipe the copy of an earlier, real break.
        self.path.write_bytes(b"")
        self.assertEqual(self.stderr_of(lambda: self.store.write({"status": "idle", "history": []})), "")
        self.assertFalse(self.corrupt.exists())
        self.assertEqual(self.saved(), DEFAULT_STATE)
        earlier = b"{earlier break"
        self.path.write_bytes(earlier)
        self.store.write({"status": "idle", "history": []})
        self.assertEqual(self.corrupt.read_bytes(), earlier)
        self.path.write_bytes(b"")
        self.assertRegex(self.store.read()["state_error"], r"^ValueError: .+")
        self.store.update(phase="x")
        self.assertEqual(self.corrupt.read_bytes(), earlier)
        self.assertEqual(self.saved(), {**DEFAULT_STATE, "phase": "x"})

    def test_a_newer_corrupt_file_replaces_the_older_copy(self):
        self.path.write_text("{first", encoding="utf-8")
        self.store.write({"status": "idle", "history": []})
        self.path.write_text("{second", encoding="utf-8")
        self.store.write({"status": "idle", "history": []})
        self.assertEqual(self.corrupt.read_text(encoding="utf-8"), "{second")

    def test_symlinked_state_is_not_copied(self):
        target = self.root / "target.json"
        target.write_text("{broken", encoding="utf-8")
        self.path.symlink_to(target)
        self.assertEqual(self.opens_of_the_state_file(lambda: self.store.write({"status": "idle", "history": []})), [])
        self.assertFalse(self.corrupt.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "{broken")
        self.assertFalse(self.path.is_symlink())
        self.assertEqual(self.saved(), DEFAULT_STATE)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_a_special_file_is_neither_opened_nor_copied(self):
        os.mkfifo(self.path)
        self.assertEqual(self.opens_of_the_state_file(lambda: self.store.write({"status": "idle", "history": []})), [])
        self.assertFalse(self.corrupt.exists())
        self.assertEqual(self.saved(), DEFAULT_STATE)

    def test_an_oversized_file_is_not_copied(self):
        maximum = self.ns.module("common.fsutil").MAX_JSON_BYTES
        self.path.write_bytes(b"{" * (maximum + 1))
        self.assertEqual(self.opens_of_the_state_file(lambda: self.store.write({"status": "idle", "history": []})), [])
        self.assertFalse(self.corrupt.exists())
        self.path.write_bytes(b"{" * maximum)
        self.store.write({"status": "idle", "history": []})
        self.assertEqual(len(self.corrupt.read_bytes()), maximum)

    def test_a_failed_copy_does_not_block_the_write(self):
        self.corrupt.mkdir()
        self.path.write_text("{broken", encoding="utf-8")
        message = self.stderr_of(lambda: self.store.write({"status": "idle", "history": [], "phase": "x"}))
        self.assertEqual(message.count("\n"), 1)
        self.assertIn("state.json", message)
        self.assertEqual(self.saved()["phase"], "x")
        self.assertTrue(self.corrupt.is_dir())
        self.assertEqual(sorted(entry.name for entry in self.root.iterdir()), ["state.json", "state.json.corrupt"])

    def test_update_merges_changes_into_the_stored_state(self):
        self.assertEqual(self.store.update(phase="a", count=1), {**DEFAULT_STATE, "phase": "a", "count": 1})
        self.assertEqual(self.store.update(count=2), {**DEFAULT_STATE, "phase": "a", "count": 2})
        self.assertEqual(self.saved(), {**DEFAULT_STATE, "phase": "a", "count": 2})

    def test_update_over_corrupt_file_keeps_the_copy_and_drops_the_error(self):
        self.path.write_text("{broken", encoding="utf-8")
        state = self.store.update(phase="a")
        self.assertIn("state_error", state)
        self.assertEqual(self.saved(), {**DEFAULT_STATE, "phase": "a"})
        self.assertEqual(self.corrupt.read_text(encoding="utf-8"), "{broken")

    def test_mutate_writes_the_changed_state_and_returns_it(self):
        def change(state):
            state["phase"] = "b"

        self.assertEqual(self.store.mutate(change), {**DEFAULT_STATE, "phase": "b"})
        self.assertEqual(self.saved(), {**DEFAULT_STATE, "phase": "b"})
        self.assertEqual(self.store.mutate(lambda _state: True)["phase"], "b")

    def test_mutate_false_skips_the_write(self):
        self.store.write({"status": "idle", "history": []})
        os.utime(self.path, ns=(10**9, 10**9))
        before = (self.path.read_bytes(), self.path.stat().st_mtime_ns)

        def decline(state):
            state["phase"] = "never saved"
            return False

        self.assertEqual(self.store.mutate(decline)["phase"], "never saved")
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), before)

    def test_mutate_false_over_a_missing_file_creates_nothing(self):
        self.store.mutate(lambda _state: False)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_update_waits_for_the_store_lock(self):
        state = self.blocked_until_the_lock_is_free(lambda: self.store.update(phase="x"))
        self.assertEqual(state["phase"], "x")
        self.assertEqual(self.saved()["phase"], "x")

    def test_mutate_waits_for_the_store_lock(self):
        state = self.blocked_until_the_lock_is_free(lambda: self.store.mutate(lambda state: state.update(phase="y")))
        self.assertEqual(state["phase"], "y")
        self.assertEqual(self.saved()["phase"], "y")

    def test_write_waits_for_the_store_lock(self):
        self.blocked_until_the_lock_is_free(lambda: self.store.write({"status": "idle", "history": []}))
        self.assertEqual(self.saved(), DEFAULT_STATE)

    def test_mutate_reads_the_file_after_it_has_the_lock(self):
        # Another writer lands while this one waits for the lock: its change is what mutate starts from.
        self.lock = HookLock()
        self.lock.before_acquire = lambda: self.path.write_text(
            json.dumps({**DEFAULT_STATE, "other": 1}), encoding="utf-8"
        )
        self.store.mutate(lambda state: state.update(mine=2))
        self.assertEqual(self.saved(), {**DEFAULT_STATE, "other": 1, "mine": 2})

    def test_store_resolves_path_and_lock_on_every_call(self):
        self.store.update(phase="first")
        self.path = self.root / "other.json"
        self.lock = HookLock()
        self.assertEqual(self.store.read(), DEFAULT_STATE)
        self.store.update(phase="second")
        self.assertEqual(self.saved()["phase"], "second")
        self.assertEqual(json.loads((self.root / "state.json").read_text(encoding="utf-8"))["phase"], "first")


class StateStoreAutomationTests(panel_harness.PanelTestCase):
    ns_name = "panel_statestore_automation_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_file = self.root / "state.json"
        self.patch(AUTOMATION_CONFIG=self.root / "config.json", AUTOMATION_STATE=self.state_file)
        self.run_lock = self.ns["AUTOMATION_RUN_LOCK"]
        self.state_lock = self.ns["AUTOMATION_STATE_LOCK"]
        self.cancel = self.ns["AUTOMATION_CANCEL"]
        self.addCleanup(self.cancel.clear)
        self.addCleanup(self.release_run_lock)

    def release_run_lock(self):
        if self.run_lock.locked():
            self.run_lock.release()

    def fast_switching(self):
        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        self.addCleanup(sys.setswitchinterval, interval)

    def stored(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def seed(self, **state):
        self.ns["save_automation_state"](state)

    def run_threads(self, *targets):
        threads = [threading.Thread(target=target, daemon=True) for target in targets]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
            self.assertFalse(thread.is_alive())

    def test_wrappers_keep_their_contract(self):
        self.assertEqual(self.ns["automation_state"](), DEFAULT_STATE)
        written = self.ns["automation_write"](phase="checking")
        self.assertEqual(written, {**DEFAULT_STATE, "phase": "checking"})
        self.assertIsNone(self.ns["automation_note"]("hello"))
        state = self.ns["automation_state"]()
        self.assertEqual([event["message"] for event in state["events"]], ["hello"])
        self.assertEqual(state["phase"], "checking")

    def test_store_follows_the_patched_path_and_lock(self):
        lock = HookLock()
        fired = []
        lock.before_acquire = lambda: fired.append(True)
        self.patch(AUTOMATION_STATE=self.root / "elsewhere.json", AUTOMATION_STATE_LOCK=lock)
        self.ns["automation_write"](phase="x")
        self.assertEqual(fired, [True])
        self.assertTrue((self.root / "elsewhere.json").is_file())
        self.assertFalse(self.state_file.exists())

    def test_concurrent_notes_lose_no_event(self):
        self.fast_switching()

        def notes(worker):
            for index in range(15):
                self.ns["automation_note"](f"worker {worker} note {index}")

        self.run_threads(*(lambda worker=worker: notes(worker) for worker in range(4)))
        events = self.ns["automation_state"]()["events"]
        self.assertEqual(len(events), 60)
        self.assertEqual(
            {event["message"] for event in events},
            {f"worker {worker} note {index}" for worker in range(4) for index in range(15)},
        )

    def test_concurrent_note_and_write_keep_both(self):
        self.fast_switching()

        def notes():
            for index in range(20):
                self.ns["automation_note"](f"note {index}")

        def writes():
            for index in range(20):
                self.ns["automation_write"](counter=index)

        self.run_threads(notes, writes)
        state = self.ns["automation_state"]()
        self.assertEqual(len(state["events"]), 20)
        self.assertEqual(state["counter"], 19)

    def test_status_reads_under_lock_but_only_startup_persists_interruption(self):
        self.seed(status="running", active=True, last_slot="slot")
        results = []
        thread = threading.Thread(target=lambda: results.append(self.ns["automation_status"]()), daemon=True)
        with self.state_lock:
            thread.start()
            thread.join(0.2)
            self.assertTrue(thread.is_alive(), "automation_status wrote without the state lock")
            self.assertEqual(self.stored()["status"], "running")
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["state"]["status"], "interrupted")
        self.assertFalse(results[0]["state"]["active"])
        self.assertEqual(self.stored()["status"], "running")
        self.assertNotIn("error", self.stored())
        self.ns["start_automation_recovery"]()
        self.assertEqual(self.stored()["status"], "interrupted")
        self.assertEqual(self.stored()["last_slot"], "slot")
        self.assertIn("панель перезапустилась", self.stored()["error"])

    def test_status_does_not_overwrite_a_run_that_just_finished(self):
        self.seed(status="running", active=True)
        read = self.ns["automation_state"]
        finished = []

        def stale_read():
            state = read()
            if not finished:
                # The run ends (its final state is written, the run lock is free) right after this read.
                finished.append(True)
                self.ns["automation_write"](status="completed", active=False)
            return state

        self.patch(automation_state=stale_read)
        status = self.ns["automation_status"]()
        self.assertEqual(finished, [True])
        self.assertEqual(status["state"]["status"], "completed")
        self.assertEqual(self.stored()["status"], "completed")
        self.assertNotIn("error", self.stored())

    def test_status_does_not_interrupt_a_run_that_started_after_the_read(self):
        self.seed(status="running", active=True, last_slot="old")
        lock = HookLock()
        self.patch(AUTOMATION_STATE_LOCK=lock)

        def new_slot_starts():
            # A new slot takes the run lock and records its own running state while the request waits for the lock.
            self.run_lock.acquire()
            self.state_file.write_text(json.dumps({**self.stored(), "last_slot": "new"}), encoding="utf-8")

        lock.before_acquire = new_slot_starts
        status = self.ns["automation_status"]()
        self.assertEqual((status["state"]["status"], status["state"]["last_slot"]), ("running", "new"))
        self.assertEqual((self.stored()["status"], self.stored()["last_slot"]), ("running", "new"))
        self.assertNotIn("error", self.stored())

    def test_status_leaves_a_live_run_alone(self):
        self.seed(status="running", active=True)
        os.utime(self.state_file, ns=(10**9, 10**9))
        before = (self.state_file.read_bytes(), self.state_file.stat().st_mtime_ns)
        self.run_lock.acquire()
        status = self.ns["automation_status"]()
        self.assertEqual(status["state"]["status"], "running")
        self.assertTrue(status["active"])
        self.assertEqual((self.state_file.read_bytes(), self.state_file.stat().st_mtime_ns), before)

    def test_idle_status_does_not_write(self):
        status = self.ns["automation_status"]()
        self.assertEqual(status["state"], DEFAULT_STATE)
        self.assertEqual(list(self.root.iterdir()), [])
        for state in ({"status": "completed", "active": False}, {"status": "error", "phase": "failed"}):
            with self.subTest(state=state):
                self.seed(**state)
                os.utime(self.state_file, ns=(10**9, 10**9))
                before = (self.state_file.read_bytes(), self.state_file.stat().st_mtime_ns)
                self.ns["automation_status"]()
                self.assertEqual((self.state_file.read_bytes(), self.state_file.stat().st_mtime_ns), before)

    def test_status_of_an_idle_state_does_not_wait_for_the_lock(self):
        self.seed(status="completed", active=False)
        results = []
        thread = threading.Thread(target=lambda: results.append(self.ns["automation_status"]()), daemon=True)
        with self.state_lock:
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "a status that has nothing to write waited for the state lock")
        self.assertEqual(results[0]["state"]["status"], "completed")

    def test_status_of_a_corrupt_file_neither_rewrites_nor_copies_it(self):
        self.state_file.write_text("{broken", encoding="utf-8")
        status = self.ns["automation_status"]()
        self.assertIn("state_error", status["state"])
        self.assertEqual(self.state_file.read_text(encoding="utf-8"), "{broken")
        self.assertEqual(sorted(entry.name for entry in self.root.iterdir()), ["state.json"])

    def test_first_write_over_a_corrupt_file_keeps_a_copy(self):
        self.state_file.write_bytes(b"\xff\xfe{")
        self.ns["automation_note"]("x")
        self.assertEqual((self.root / "state.json.corrupt").read_bytes(), b"\xff\xfe{")
        self.assertEqual([event["message"] for event in self.stored()["events"]], ["x"])
        self.assertNotIn("state_error", self.stored())

    def test_startup_reports_corrupt_state_once(self):
        self.state_file.write_text("{broken", encoding="utf-8")
        stderr = io.StringIO()
        sleep = mock.Mock(side_effect=StopIteration)
        logger = mock.Mock()
        logger.warning.side_effect = lambda message, *args: stderr.write((message % args) + "\n")
        with mock.patch.object(self.ns.module("automation").logsetup, "panel_logger", return_value=logger):
            self.ns["start_automation_recovery"]()
            # The scheduler's first pass reads the same broken file and stays quiet about it.
            with mock.patch.object(self.ns["time"], "sleep", sleep), self.assertRaises(StopIteration):
                self.ns["automation_loop"]()
        self.assertEqual(stderr.getvalue().count("state unreadable"), 1)
        self.assertRegex(stderr.getvalue(), r"^automation recovery state unreadable: JSONDecodeError: .+\n$")
        self.assertEqual(self.state_file.read_text(encoding="utf-8"), "{broken")
        self.assertEqual((self.root / "state.json.corrupt").read_text(encoding="utf-8"), "{broken")

    def test_startup_is_quiet_about_a_readable_state(self):
        self.seed(status="idle", history=[])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.ns["start_automation_recovery"]()
        self.assertEqual(stderr.getvalue(), "")


class AutomationSlotStateTests(panel_harness.PanelTestCase):
    """The read-modify-writes of run_automation_slot, each with another writer landing right before the lock."""

    ns_name = "panel_statestore_slot_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_file = self.root / "state.json"
        result = self.root / "result.json"
        result.write_text("{}", encoding="utf-8")
        self.hook = HookLock()
        self.patch(AUTOMATION_STATE=self.state_file, TUNER_RESULT=result, AUTOMATION_STATE_LOCK=self.hook)
        self.run_lock = self.ns["AUTOMATION_RUN_LOCK"]
        self.cancel = self.ns["AUTOMATION_CANCEL"]
        self.addCleanup(self.cancel.clear)
        self.addCleanup(self.release_run_lock)
        self.config = self.ns["default_automation_config"]()
        self.config["services"]["discord-tcp"]["enabled"] = False

    def release_run_lock(self):
        if self.run_lock.locked():
            self.run_lock.release()

    def stored(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def store_raw(self, **changes):
        """Change the file as another writer does just before it takes the lock."""
        state = self.stored()
        state.update(changes)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def run_slot(self):
        self.run_lock.acquire()
        self.ns["run_automation_slot"]("slot", self.config)

    def fail_on_flowseal_check(self):
        self.patch(check_flowseal_update=mock.Mock(side_effect=RuntimeError("boom")))

    def test_failed_slot_with_a_pending_transaction_needs_recovery(self):
        self.ns["save_automation_state"]({"status": "running", "transaction": {"service": "youtube"}})
        self.fail_on_flowseal_check()
        self.run_slot()
        state = self.stored()
        self.assertEqual((state["status"], state["phase"], state["error"]), ("error", "recovery-needed", "boom"))
        self.assertEqual(state["transaction"], {"service": "youtube"})
        self.assertFalse(self.run_lock.locked())

    def test_failed_slot_without_a_transaction_is_just_failed(self):
        self.ns["save_automation_state"]({"status": "running", "transaction": None})
        self.fail_on_flowseal_check()
        self.run_slot()
        state = self.stored()
        self.assertEqual((state["status"], state["phase"]), ("error", "failed"))

    def test_failed_slot_decides_on_recovery_from_the_state_it_writes_over(self):
        self.ns["save_automation_state"]({"status": "running", "transaction": {"service": "youtube"}})
        self.fail_on_flowseal_check()
        note = self.ns["automation_note"]

        def noting(message):
            note(message)
            if message.startswith("Ошибка"):
                # The transaction is resolved by another writer after the failure is noted, before the final write.
                self.hook.before_acquire = lambda: self.store_raw(transaction=None)

        self.patch(automation_note=noting)
        self.run_slot()
        state = self.stored()
        self.assertEqual((state["status"], state["phase"]), ("error", "failed"))
        self.assertIsNone(state["transaction"])

    def prepare_applying_slot(self):
        pointers = ["old-pointer", "new-pointer"]
        recorded, applied_context = [], []
        locked_at_read = []
        checks = iter([("unhealthy", {}), ("healthy", {"baseline_quic_replies": 1})])

        def apply_profile(_profile, *, operation_context):
            self.assertEqual(operation_context, self.stored()["transaction"])
            applied_context.append(dict(operation_context))
            # Another writer extends the transaction after the profile is applied, before the pointer is stored.
            self.hook.before_acquire = lambda: self.store_raw(
                transaction={**self.stored()["transaction"], "marker": "kept"}
            )
            return {"ok": True}

        def import_pointer_value():
            locked_at_read.append(self.hook.locked())
            return pointers.pop(0)

        def config_health():
            recorded.append(self.stored()["transaction"])
            return {"all_ok": True}

        self.patch(
            check_flowseal_update=lambda: {"downloaded_commit": "a" * 40},
            run_command=lambda *_args, **_kwargs: {"ok": True},
            current_routes_fast=lambda: {"youtube": "zapret"},
            automation_check_service=lambda *_args: next(checks),
            start_tuner_job=lambda *_args, **_kwargs: 123,
            wait_automation_tuner=lambda *_args: {"status": "found", "result_available": True},
            validate_report=lambda _report: {"service": "youtube", "candidate_id": "c" * 12},
            nfqws_config_hash=lambda: "b" * 64,
            import_pointer_value=import_pointer_value,
            IMPORTED_PROFILE_DIR=self.root / "imported",
            apply_profile=apply_profile,
            config_health=config_health,
        )
        return recorded, locked_at_read, applied_context

    def test_applied_pointer_is_stored_on_the_transaction_as_it_is_then(self):
        recorded, locked_at_read, applied_context = self.prepare_applying_slot()
        self.run_slot()
        self.assertEqual(locked_at_read, [False, False], "the engine is asked for the pointer outside the state lock")
        self.assertEqual(len(recorded), 1)
        self.assertEqual(len(applied_context), 1)
        initial = applied_context[0]
        self.assertRegex(initial['operation_id'], r'^[0-9a-f]{32}$')
        self.assertEqual(initial, {'schema': 2, 'operation_id': initial['operation_id'],
            'project': str(self.ns['ENGINE'].absolute()), 'service': 'youtube', 'candidate_id': 'c' * 12,
            'before_hash': 'b' * 64, 'before_pointer': 'old-pointer', 'before_descriptor': None, 'phase': 'applying'})
        self.assertEqual(recorded[0], dict(initial, marker='kept', applied_pointer='new-pointer'))
        state = self.stored()
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["results"], {"youtube": "applied-quic-unverified", "discord-tcp": "disabled"})
        self.assertIsNone(state["transaction"])
        self.assertFalse(self.run_lock.locked())


if __name__ == "__main__":
    unittest.main()

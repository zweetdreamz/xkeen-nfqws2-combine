"""Unit tests of kdn.common.lock: the one project lock of the engine and the router tools.

The module is imported directly and patched only with mock.patch.object on
the module object. Every lock lives in a TemporaryDirectory; nothing touches
/opt. The last classes run the lock of the other users (autotune job, VPN node
manager) in child processes: they are still the old mkdir + pid-file code and
must keep working against a lock written by the new one, and the new one
against theirs.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from kdn.common import lock


ROUTER_DIR = Path(lock.__file__).resolve().parents[2]
LOCK_LOGICAL = "opt/tmp/keenetic-discord-nfqws2.lock"
CHILD_ENV = {**os.environ, "PYTHONPATH": str(ROUTER_DIR)}


class LockTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.path = self.root / LOCK_LOGICAL

    @property
    def pid_file(self):
        return self.path / "pid"

    def live_process(self):
        process = subprocess.Popen(["sleep", "60"])
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        process.kill()
        process.wait()

    @staticmethod
    def dead_pid():
        process = subprocess.Popen(["true"])
        process.wait()
        return process.pid

    def make_lock_dir(self, pid_text=None):
        self.path.mkdir(parents=True, mode=0o700)
        if pid_text is not None:
            self.pid_file.write_text(pid_text, encoding="ascii")

    def delayed(self, delay, action):
        timer = threading.Timer(delay, action)
        timer.start()
        self.addCleanup(timer.join)
        self.addCleanup(timer.cancel)


class AcquireReleaseTests(LockTestCase):
    def test_acquire_writes_pid_and_release_removes_lock(self):
        project_lock = lock.ProjectLock(self.path)
        self.assertFalse(project_lock.held)
        project_lock.acquire()
        self.assertTrue(project_lock.held)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
        self.assertEqual(self.pid_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(self.path), ["pid"])
        project_lock.release()
        self.assertFalse(project_lock.held)
        self.assertFalse(self.path.exists())

    def test_context_manager_releases_on_error(self):
        with self.assertRaisesRegex(ValueError, "boom"):
            with lock.ProjectLock(self.path) as project_lock:
                self.assertTrue(project_lock.held)
                self.assertTrue(self.path.is_dir())
                raise ValueError("boom")
        self.assertFalse(self.path.exists())
        with lock.ProjectLock(self.path) as project_lock:
            self.assertTrue(project_lock.held)
        self.assertFalse(self.path.exists())

    def test_failed_pid_publication_leaves_no_lock_behind(self):
        project_lock = lock.ProjectLock(self.path)
        with mock.patch.object(lock.os, "link", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                project_lock.acquire()
        self.assertFalse(project_lock.held)
        self.assertFalse(self.path.exists())

    def test_filesystem_without_hard_links_falls_back_to_replace(self):
        with mock.patch.object(lock.os, "link", side_effect=OSError(errno.EPERM, "no hard links")):
            with lock.ProjectLock(self.path) as project_lock:
                self.assertTrue(project_lock.held)
                self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
                self.assertEqual(os.listdir(self.path), ["pid"])

    def test_release_without_acquire_and_twice_is_a_no_op(self):
        project_lock = lock.ProjectLock(self.path)
        project_lock.release()
        project_lock.acquire()
        project_lock.release()
        project_lock.release()
        self.assertFalse(self.path.exists())

    def test_release_by_non_owner_keeps_lock(self):
        holder = self.live_process()
        project_lock = lock.ProjectLock(self.path)
        project_lock.acquire()
        # Someone else took the lock over (a stale-lock cleanup that was too hasty).
        self.pid_file.write_text(f"{holder.pid}\n", encoding="ascii")
        project_lock.release()
        self.assertFalse(project_lock.held)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{holder.pid}\n")

    def test_release_with_a_foreign_file_leaves_the_directory(self):
        project_lock = lock.ProjectLock(self.path)
        project_lock.acquire()
        (self.path / "other").write_text("x", encoding="ascii")
        project_lock.release()
        self.assertFalse(self.pid_file.exists())
        self.assertTrue((self.path / "other").exists())

    def test_second_acquire_in_the_same_process_is_busy(self):
        first = lock.ProjectLock(self.path)
        first.acquire()
        self.addCleanup(first.release)
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, os.getpid())
        self.assertIn(f"PID {os.getpid()}", str(caught.exception))
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_lock_busy_is_a_runtime_error(self):
        self.assertTrue(issubclass(lock.LockBusy, RuntimeError))
        self.assertIsNone(lock.LockBusy("x").pid)
        self.assertEqual(lock.LockBusy("x", 7).pid, 7)

    def test_pid_file_is_never_seen_incomplete(self):
        stop = threading.Event()
        seen = []

        def watch():
            while not stop.is_set():
                try:
                    text = self.pid_file.read_text(encoding="ascii")
                except OSError:
                    continue
                if not re.fullmatch(r"\d+\n", text):
                    seen.append(text)

        watcher = threading.Thread(target=watch)
        watcher.start()
        try:
            for _ in range(300):
                with lock.ProjectLock(self.path):
                    pass
        finally:
            stop.set()
            watcher.join()
        self.assertEqual(seen, [])


class HolderTests(LockTestCase):
    def test_live_holder_is_busy(self):
        holder = self.live_process()
        self.make_lock_dir(f"{holder.pid}\n")
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=0.2).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)
        self.assertIn(f"(PID {holder.pid})", str(caught.exception))
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{holder.pid}\n")

    def test_permission_error_counts_as_alive(self):
        self.make_lock_dir("4000000\n")
        with mock.patch.object(lock.proc, "process_alive", return_value=True) as alive:
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        alive.assert_called_with(4000000)
        self.assertEqual(caught.exception.pid, 4000000)
        self.assertTrue(self.pid_file.exists())

    def test_kill_zero_permission_error_means_alive_through_proc(self):
        self.make_lock_dir("4000000\n")
        with mock.patch.object(lock.proc.os, "kill", side_effect=PermissionError):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
            self.assertTrue(lock.inspect_lock(self.path).alive)
        self.assertEqual(caught.exception.pid, 4000000)

    def test_dead_holder_is_taken_over(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")
        project_lock = lock.ProjectLock(self.path)
        started = time.monotonic()
        project_lock.acquire()
        self.assertLess(time.monotonic() - started, 1.0, "a dead pid must not be waited for")
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        project_lock.release()
        self.assertFalse(self.path.exists())

    def test_crashed_new_protocol_holder_is_taken_over(self):
        holder = hold_in_child(self, "from kdn.common import lock\nlock.ProjectLock(sys.argv[1]).acquire()\n")
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{holder.pid}\n")
        with self.assertRaises(lock.LockBusy):
            lock.ProjectLock(self.path, pid_wait=0).acquire()
        holder.kill()
        holder.wait()
        with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
            self.assertTrue(project_lock.held)
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_garbage_pid_is_treated_as_no_pid(self):
        for text in ("garbage", "", "0\n", "1\n", "-5\n"):
            with self.subTest(text=text):
                self.make_lock_dir(text)
                with lock.ProjectLock(self.path, pid_wait=0):
                    self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
                self.assertFalse(self.path.exists())

    def test_stale_lock_with_extra_files_is_refused(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        (self.path / "other").write_text("x", encoding="ascii")
        with self.assertRaisesRegex(lock.LockBusy, "stale lock directory is not empty") as caught:
            lock.ProjectLock(self.path).acquire()
        self.assertIn(str(self.path), str(caught.exception))
        self.assertIsNone(caught.exception.pid)
        self.assertTrue((self.path / "other").exists())

    def test_leftover_temporary_pid_of_a_dead_writer_is_cleaned(self):
        self.make_lock_dir()
        (self.path / f"pid.tmp-{self.dead_pid()}").write_text("1234\n", encoding="ascii")
        with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
            self.assertTrue(project_lock.held)
            self.assertEqual(os.listdir(self.path), ["pid"])

    def test_temporary_pid_of_a_live_writer_blocks_the_takeover(self):
        # A holder frozen between "create the file" and "publish it" must not lose its lock.
        writer = self.live_process()
        self.make_lock_dir()
        (self.path / f"pid.tmp-{writer.pid}").write_text(f"{writer.pid}\n", encoding="ascii")
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, writer.pid)
        self.assertNotIn("not empty", str(caught.exception))
        self.assertTrue((self.path / f"pid.tmp-{writer.pid}").exists())

    def test_leftover_files_with_a_foreign_name_are_not_ours_to_delete(self):
        self.make_lock_dir()
        for name in ("pid.tmp-x", "pid.stale-", "pid.old"):
            (self.path / name).write_text("x", encoding="ascii")
        with self.assertRaisesRegex(lock.LockBusy, "stale lock directory is not empty"):
            lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(sorted(os.listdir(self.path)), ["pid.old", "pid.stale-", "pid.tmp-x"])


class PidWaitTests(LockTestCase):
    def test_pidless_lock_is_busy_while_holder_writes_pid(self):
        holder = self.live_process()
        self.make_lock_dir()
        self.delayed(0.3, lambda: self.pid_file.write_text(f"{holder.pid}\n", encoding="ascii"))
        started = time.monotonic()
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=1.0).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)
        self.assertGreaterEqual(time.monotonic() - started, 0.25)
        self.assertLess(time.monotonic() - started, 0.9, "the wait ends as soon as the pid shows up")
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{holder.pid}\n")

    def test_pidless_lock_older_than_wait_is_stale(self):
        self.make_lock_dir()
        started = time.monotonic()
        with lock.ProjectLock(self.path, pid_wait=0.2) as project_lock:
            self.assertGreaterEqual(time.monotonic() - started, 0.2)
            self.assertTrue(project_lock.held)
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_zero_wait_takes_a_pidless_lock_at_once(self):
        self.make_lock_dir()
        started = time.monotonic()
        with lock.ProjectLock(self.path, pid_wait=0):
            self.assertLess(time.monotonic() - started, 0.1)

    def test_default_wait_and_poll(self):
        self.assertEqual(lock.DEFAULT_PID_WAIT, 2.0)
        project_lock = lock.ProjectLock(self.path)
        self.assertEqual((project_lock.pid_wait, project_lock.poll), (2.0, 0.1))

    def test_lock_that_vanishes_while_waiting_is_acquired_at_once(self):
        self.make_lock_dir()
        self.delayed(0.2, self.path.rmdir)
        started = time.monotonic()
        with lock.ProjectLock(self.path, pid_wait=3.0) as project_lock:
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertTrue(project_lock.held)
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_dead_pid_that_shows_up_while_waiting_ends_the_wait(self):
        dead = self.dead_pid()
        self.make_lock_dir()
        self.delayed(0.2, lambda: self.pid_file.write_text(f"{dead}\n", encoding="ascii"))
        started = time.monotonic()
        with lock.ProjectLock(self.path, pid_wait=3.0):
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_pid_that_appears_after_the_wait_but_before_the_removal_is_respected(self):
        holder = self.live_process()
        self.make_lock_dir()
        reads = iter([None, holder.pid])
        with mock.patch.object(lock.proc, "read_job_pid", side_effect=lambda _path: next(reads)):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)
        self.assertTrue(self.path.is_dir())

    def test_pid_that_changes_after_a_dead_one_was_seen_is_respected(self):
        holder = self.live_process()
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")
        real_alive = lock.proc.process_alive

        def alive(pid):
            if pid == dead:
                # Another process takes the stale lock over right after we looked at it.
                self.pid_file.write_text(f"{holder.pid}\n", encoding="ascii")
                return False
            return real_alive(pid)

        with mock.patch.object(lock.proc, "process_alive", side_effect=alive):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{holder.pid}\n")

    def test_pid_that_disappears_after_a_dead_one_was_seen_is_busy(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")

        def alive(pid):
            self.assertEqual(pid, dead)
            self.pid_file.unlink()
            return False

        with mock.patch.object(lock.proc, "process_alive", side_effect=alive):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertIsNone(caught.exception.pid)
        self.assertEqual(str(caught.exception), "another project operation is active")
        self.assertTrue(self.path.is_dir())

    def test_lock_removed_after_a_dead_pid_was_seen_is_acquired(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")

        def alive(pid):
            self.assertEqual(pid, dead)
            self.pid_file.unlink()
            self.path.rmdir()
            return False

        with mock.patch.object(lock.proc, "process_alive", side_effect=alive):
            with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                self.assertTrue(project_lock.held)
                self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_stale_lock_that_vanishes_during_the_cleanup_is_acquired(self):
        self.make_lock_dir()
        writer = self.dead_pid()
        leftover = self.path / f"pid.tmp-{writer}"
        leftover.write_text("1234\n", encoding="ascii")

        def alive(pid):
            self.assertEqual(pid, writer)
            leftover.unlink()
            self.path.rmdir()
            return False

        with mock.patch.object(lock.proc, "process_alive", side_effect=alive):
            with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                self.assertTrue(project_lock.held)

    def test_lock_that_keeps_changing_hands_gives_up(self):
        self.make_lock_dir()
        with mock.patch.object(lock.ProjectLock, "_settle", return_value=lock._VANISHED):
            with self.assertRaisesRegex(lock.LockBusy, "keeps changing hands"):
                lock.ProjectLock(self.path).acquire()


class TakeoverRaceTests(LockTestCase):
    """Interleavings of two contenders, forced by hooks at the step between the steps."""

    @staticmethod
    def hook(project_lock, name, before, nth=1):
        """Run `before` once, right before the nth call of the method `name` of `project_lock`."""
        original = getattr(project_lock, name)
        calls = []

        def hooked(*args):
            calls.append(name)
            if len(calls) == nth:
                before()
            return original(*args)

        setattr(project_lock, name, hooked)

    def test_contender_that_lost_the_stale_takeover_gives_way(self):
        # C saw the dead pid; before C takes the stale lock over, B completes a whole takeover and holds the lock.
        self.make_lock_dir(f"{self.dead_pid()}\n")
        owner = self.live_process()
        first = lock.ProjectLock(self.path, pid_wait=0)
        second = lock.ProjectLock(self.path, pid_wait=0)

        def first_takes_over():
            with mock.patch.object(lock.os, "getpid", return_value=owner.pid):
                first.acquire()

        self.hook(second, "_take_over", first_takes_over)
        with self.assertRaises(lock.LockBusy) as caught:
            second.acquire()
        self.assertEqual(caught.exception.pid, owner.pid)
        self.assertTrue(first.held)
        self.assertFalse(second.held)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{owner.pid}\n")
        self.assertEqual(os.listdir(self.path), ["pid"])

    def test_suspended_publisher_does_not_overwrite_the_pid_of_the_new_owner(self):
        # B made the directory and was suspended; C found it stale, replaced it and holds the lock.
        suspended_pid = self.live_process().pid
        suspended = lock.ProjectLock(self.path, pid_wait=0)
        new_owner = lock.ProjectLock(self.path, pid_wait=0)
        original = suspended._publish_pid

        def resumed():
            new_owner.acquire()
            with mock.patch.object(lock.os, "getpid", return_value=suspended_pid):
                return original()

        suspended._publish_pid = resumed
        with self.assertRaises(lock.LockBusy) as caught:
            suspended.acquire()
        self.assertEqual(caught.exception.pid, os.getpid())
        self.assertTrue(new_owner.held)
        self.assertFalse(suspended.held)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
        self.assertEqual(os.listdir(self.path), ["pid"])

    def test_directory_removed_before_the_pid_is_published_is_retried(self):
        project_lock = lock.ProjectLock(self.path, pid_wait=0)
        self.hook(project_lock, "_publish_pid", self.path.rmdir)
        project_lock.acquire()
        self.assertTrue(project_lock.held)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
        self.assertEqual(os.listdir(self.path), ["pid"])

    def test_fresh_acquirer_that_wins_the_mkdir_after_the_removal_keeps_the_lock(self):
        # C removed the stale directory; before C makes its own, a fresh acquirer makes one and publishes.
        self.make_lock_dir(f"{self.dead_pid()}\n")
        winner = lock.ProjectLock(self.path, pid_wait=0)
        taker = lock.ProjectLock(self.path, pid_wait=0)
        self.hook(taker, "_create", winner.acquire, nth=2)
        with self.assertRaises(lock.LockBusy) as caught:
            taker.acquire()
        self.assertEqual(caught.exception.pid, os.getpid())
        self.assertTrue(winner.held)
        self.assertFalse(taker.held)
        self.assertEqual(os.listdir(self.path), ["pid"])
        winner.release()
        self.assertFalse(self.path.exists())

    def open_fails_once_in_a_removed_directory(self, number, recreated):
        real_open = os.open
        failed = []

        def vanishing_open(path, *args, **kwargs):
            if not failed and Path(path).name.startswith("pid.tmp-"):
                failed.append(path)
                self.path.rmdir()
                if recreated:
                    self.path.mkdir(mode=0o700)
                raise OSError(number, "taken over")
            return real_open(path, *args, **kwargs)

        return mock.patch.object(lock.os, "open", vanishing_open), failed

    def test_publication_that_fails_in_a_removed_directory_is_retried(self):
        # Another contender removed the directory under us (and maybe made a new one): Linux says ENOENT,
        # macOS may say EINVAL for it.
        cases = ((errno.ENOENT, False), (errno.EINVAL, False), (errno.EINVAL, True), (errno.EIO, False))
        for number, recreated in cases:
            with self.subTest(errno=errno.errorcode[number], recreated=recreated):
                patch, failed = self.open_fails_once_in_a_removed_directory(number, recreated)
                with patch, lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                    self.assertTrue(project_lock.held)
                    self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
                self.assertEqual(len(failed), 1)

    def test_pid_that_appears_before_the_takeover_is_respected(self):
        owner = self.live_process()
        self.make_lock_dir()
        project_lock = lock.ProjectLock(self.path, pid_wait=0)
        self.hook(
            project_lock,
            "_take_over",
            lambda: self.pid_file.write_text(f"{owner.pid}\n", encoding="ascii"),
        )
        with self.assertRaises(lock.LockBusy) as caught:
            project_lock.acquire()
        self.assertEqual(caught.exception.pid, owner.pid)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{owner.pid}\n")
        self.assertEqual(os.listdir(self.path), ["pid"])

    def test_other_stale_pid_that_replaced_the_seen_one_is_taken_over_next_round(self):
        other_dead = self.dead_pid()
        self.make_lock_dir(f"{self.dead_pid()}\n")
        project_lock = lock.ProjectLock(self.path, pid_wait=0)
        self.hook(
            project_lock,
            "_take_over",
            lambda: self.pid_file.write_text(f"{other_dead}\n", encoding="ascii"),
        )
        with project_lock:
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_pid_that_is_reused_while_the_takeover_waits_is_respected(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")
        answers = iter([False, True])
        with mock.patch.object(lock.proc, "process_alive", side_effect=lambda _pid: next(answers)):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, dead)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{dead}\n")

    def test_taker_in_flight_during_the_removal_is_busy_with_its_pid(self):
        owner = self.live_process()
        self.make_lock_dir()
        project_lock = lock.ProjectLock(self.path, pid_wait=0)
        self.hook(
            project_lock,
            "_take_over",
            lambda: (self.path / f"pid.tmp-{owner.pid}").write_text(f"{owner.pid}\n", encoding="ascii"),
        )
        with self.assertRaises(lock.LockBusy) as caught:
            project_lock.acquire()
        self.assertEqual(caught.exception.pid, owner.pid)
        self.assertNotIn("not empty", str(caught.exception))
        self.assertTrue((self.path / f"pid.tmp-{owner.pid}").exists())

    def plant_during_the_removal(self, text):
        planted = []

        def leftovers(_self):
            if not planted:
                planted.append(self.pid_file.write_text(text, encoding="ascii"))
            return iter(())

        return mock.patch.object(lock.ProjectLock, "_leftovers", leftovers)

    def test_pid_published_while_the_directory_is_removed_is_busy(self):
        owner = self.live_process()
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with self.plant_during_the_removal(f"{owner.pid}\n"):
            with self.assertRaises(lock.LockBusy) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.pid, owner.pid)
        self.assertNotIn("not empty", str(caught.exception))
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{owner.pid}\n")

    def test_stale_pid_planted_while_the_directory_is_removed_is_retried(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with self.plant_during_the_removal(f"{self.dead_pid()}\n"):
            with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                self.assertTrue(project_lock.held)
                self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")


class ReleaseDuringTakeoverTests(LockTestCase):
    """B takes a lock over that C saw stale and releases it at any moment of C's own takeover: nothing stays."""

    CHANGES = ("rename", "link", "unlink", "rmdir", "mkdir")

    def scenario(self, release_after):
        """B releases right after the `release_after`-th change C makes to the files (0: before C looks again)."""
        self.make_lock_dir(f"{self.dead_pid()}\n")
        first = lock.ProjectLock(self.path, pid_wait=0)
        second = lock.ProjectLock(self.path, pid_wait=0)
        state = {"counting": False, "changes": 0}

        def watched(name):
            real = getattr(os, name)

            def change(*args, **kwargs):
                result = real(*args, **kwargs)
                if state["counting"]:
                    state["changes"] += 1
                    if state["changes"] == release_after:
                        state["counting"] = False
                        first.release()
                        state["counting"] = True
                return result

            return change

        def first_takes_over_after_second_looked():
            state["counting"] = False
            first.acquire()
            if release_after == 0:
                first.release()
            state["counting"] = True

        TakeoverRaceTests.hook(second, "_take_over", first_takes_over_after_second_looked)
        with contextlib.ExitStack() as stack:
            for name in self.CHANGES:
                stack.enter_context(mock.patch.object(os, name, watched(name)))
            state["counting"] = True
            try:
                second.acquire()
            except lock.LockBusy:
                pass
            finally:
                state["counting"] = False
        return first, second

    def test_release_at_any_moment_leaves_no_lock_behind(self):
        for release_after in range(0, 9):
            with self.subTest(release_after=release_after), tempfile.TemporaryDirectory() as root:
                self.path = Path(root) / LOCK_LOGICAL
                first, second = self.scenario(release_after)
                self.assertFalse(first.held and second.held, "two owners")
                first.release()
                second.release()
                self.assertFalse(
                    self.path.exists(),
                    f"a lock is left behind: {lock.inspect_lock(self.path)}",
                )

    def test_the_lock_is_free_for_a_third_process_after_the_release(self):
        first, second = self.scenario(1)
        first.release()
        second.release()
        with mock.patch.object(lock.os, "getpid", return_value=self.live_process().pid):
            with lock.ProjectLock(self.path, pid_wait=0) as third:
                self.assertTrue(third.held)


HANG_IN_TAKEOVER = """
from kdn.common import lock

def hang(_self):
    print('held', flush=True)
    sys.stdin.read()
    return True

lock.ProjectLock._remove_directory = hang
lock.ProjectLock(sys.argv[1], pid_wait=0).acquire()
"""


class TakeoverMutexTests(LockTestCase):
    """The flock on `<lock>.takeover` that serializes the takers of a stale lock."""

    @property
    def mutex_file(self):
        return self.path.with_name(self.path.name + ".takeover")

    def probe_mutex(self):
        """True if the takeover mutex is free: a flock taken here and dropped at once."""
        descriptor = os.open(self.mutex_file, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        finally:
            os.close(descriptor)
        return True

    def test_fresh_acquire_does_not_need_the_mutex(self):
        with lock.ProjectLock(self.path):
            pass
        self.assertFalse(self.mutex_file.exists())

    def test_mutex_file_is_a_permanent_private_sibling_of_the_directory(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with lock.ProjectLock(self.path, pid_wait=0):
            self.assertEqual(os.listdir(self.path), ["pid"])
            self.assertEqual(self.mutex_file.parent, self.path.parent)
            self.assertEqual(self.mutex_file.name, "keenetic-discord-nfqws2.lock.takeover")
            self.assertEqual(self.mutex_file.stat().st_mode & 0o777, 0o600)
            inode = self.mutex_file.stat().st_ino
        self.assertFalse(self.path.exists())
        self.assertEqual(self.mutex_file.stat().st_ino, inode, "the mutex file is never deleted")
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with lock.ProjectLock(self.path, pid_wait=0):
            self.assertEqual(self.mutex_file.stat().st_ino, inode)

    def test_mutex_is_free_again_after_a_takeover_and_after_a_refusal(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with lock.ProjectLock(self.path, pid_wait=0):
            self.assertTrue(self.probe_mutex())
        self.make_lock_dir(f"{self.dead_pid()}\n")
        (self.path / "other").write_text("x", encoding="ascii")
        with self.assertRaisesRegex(lock.LockBusy, "not empty"):
            lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertTrue(self.probe_mutex())

    def test_mutex_is_held_until_the_new_pid_is_published(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        project_lock = lock.ProjectLock(self.path, pid_wait=0)
        seen = []
        TakeoverRaceTests.hook(project_lock, "_publish_pid", lambda: seen.append(self.probe_mutex()))
        with project_lock:
            self.assertEqual(seen, [False])

    def test_second_taker_waits_for_the_mutex_of_the_first(self):
        owner = self.live_process()
        self.make_lock_dir(f"{self.dead_pid()}\n")
        first = lock.ProjectLock(self.path, pid_wait=0)
        second = lock.ProjectLock(self.path, pid_wait=0, poll=0.001)
        waiting = threading.Event()
        real_flock = fcntl.flock
        outcome = []

        def flock(descriptor, operation):
            try:
                return real_flock(descriptor, operation)
            except BlockingIOError:
                waiting.set()
                raise

        def second_takes_over():
            try:
                second.acquire()
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=second_takes_over)

        def second_arrives_while_the_first_is_taking_over():
            thread.start()
            self.assertTrue(waiting.wait(5), "the second taker did not wait for the first one")

        self.addCleanup(thread.join)
        TakeoverRaceTests.hook(first, "_remove_directory", second_arrives_while_the_first_is_taking_over)
        with (
            mock.patch.object(lock, "_MIN_MUTEX_WAIT", 30),
            mock.patch.object(lock.fcntl, "flock", flock),
            mock.patch.object(lock.os, "getpid", return_value=owner.pid),
        ):
            first.acquire()
        thread.join(10)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], lock.LockBusy)
        self.assertEqual(outcome[0].pid, owner.pid)
        self.assertTrue(first.held)
        self.assertFalse(second.held)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{owner.pid}\n")

    def test_taker_gives_up_when_the_mutex_stays_taken(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")
        descriptor = os.open(self.mutex_file, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        with mock.patch.object(lock, "_MIN_MUTEX_WAIT", 0.1):
            for pid_wait, at_least in ((0, 0.1), (0.3, 0.3)):
                with self.subTest(pid_wait=pid_wait):
                    started = time.monotonic()
                    with self.assertRaisesRegex(lock.LockBusy, "a stale lock is being taken over") as caught:
                        lock.ProjectLock(self.path, pid_wait=pid_wait, poll=0.01).acquire()
                    self.assertGreaterEqual(time.monotonic() - started, at_least)
                    self.assertLess(time.monotonic() - started, at_least + 1.0)
                    self.assertIsNone(caught.exception.pid)
                    self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{dead}\n")

    def test_mutex_of_a_killed_taker_does_not_block_later_takeovers(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        holder = hold_in_child(self, HANG_IN_TAKEOVER)
        self.assertFalse(self.probe_mutex(), "the child holds the mutex")
        self.assertFalse(self.pid_file.exists(), "the child has removed the stale pid")
        with mock.patch.object(lock, "_MIN_MUTEX_WAIT", 0.2):
            with self.assertRaisesRegex(lock.LockBusy, "a stale lock is being taken over"):
                lock.ProjectLock(self.path, pid_wait=0, poll=0.01).acquire()
        holder.kill()
        holder.wait()
        started = time.monotonic()
        with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
            self.assertTrue(project_lock.held)
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_filesystem_without_flock_takes_a_stale_lock_over_without_the_mutex(self):
        for number in (errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS, errno.EINVAL):
            with self.subTest(errno=errno.errorcode[number]):
                self.make_lock_dir(f"{self.dead_pid()}\n")
                with mock.patch.object(lock.fcntl, "flock", side_effect=OSError(number, "no flock")) as flock:
                    with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                        self.assertTrue(project_lock.held)
                        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")
                self.assertEqual(flock.call_count, 1, "tried once, then went on without the mutex")
                self.assertFalse(self.path.exists())

    def test_other_flock_errors_are_raised_and_leave_the_lock_alone(self):
        dead = self.dead_pid()
        self.make_lock_dir(f"{dead}\n")
        with mock.patch.object(lock.fcntl, "flock", side_effect=OSError(errno.EIO, "disk")):
            with self.assertRaises(OSError) as caught:
                lock.ProjectLock(self.path, pid_wait=0).acquire()
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{dead}\n")

    def test_stale_lock_is_taken_over_on_a_filesystem_without_hard_links(self):
        self.make_lock_dir(f"{self.dead_pid()}\n")
        with mock.patch.object(lock.os, "link", side_effect=OSError(errno.EPERM, "no hard links")):
            with lock.ProjectLock(self.path, pid_wait=0) as project_lock:
                self.assertTrue(project_lock.held)
                self.assertEqual(os.listdir(self.path), ["pid"])


class InspectTests(LockTestCase):
    def test_inspect_lock_states(self):
        self.assertEqual(lock.inspect_lock(self.path), lock.LockState(False, None, False))
        self.assertFalse(self.path.parent.exists(), "inspecting creates nothing")

        self.make_lock_dir()
        started = time.monotonic()
        self.assertEqual(lock.inspect_lock(self.path), lock.LockState(True, None, False))
        self.assertLess(time.monotonic() - started, 0.1, "inspecting never waits")

        holder = self.live_process()
        self.pid_file.write_text(f"{holder.pid}\n", encoding="ascii")
        self.assertEqual(lock.inspect_lock(self.path), lock.LockState(True, holder.pid, True))

        dead = self.dead_pid()
        self.pid_file.write_text(f"{dead}\n", encoding="ascii")
        self.assertEqual(lock.inspect_lock(self.path), lock.LockState(True, dead, False))
        self.assertTrue(self.pid_file.exists(), "inspecting removes nothing")

        self.pid_file.write_text("garbage", encoding="ascii")
        self.assertEqual(lock.inspect_lock(self.path), lock.LockState(True, None, False))

    def test_inspect_lock_accepts_a_string_path(self):
        self.make_lock_dir()
        self.assertTrue(lock.inspect_lock(str(self.path)).exists)

    def test_lock_state_is_frozen(self):
        state = lock.LockState(True, 5, True)
        with self.assertRaises(AttributeError):
            state.pid = 6


HOLD_TAIL = "print('held', flush=True)\nsys.stdin.read()\n"
STRESS_WORKER = """
import os, sys, time
from kdn.common import lock

path, marker, rounds = sys.argv[1], sys.argv[2], int(sys.argv[3])
violations = 0
mine = lock.ProjectLock(path, poll=0.005)
for _ in range(rounds):
    while True:
        try:
            mine.acquire()
            break
        except lock.LockBusy:
            time.sleep(0.002)
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        violations += 1
    else:
        os.close(descriptor)
        time.sleep(0.001)
        os.unlink(marker)
    mine.release()
print(violations)
"""

STALE_WORKER = """
import collections, json, os, sys, time
from kdn.common import lock

path, marker, rounds = sys.argv[1], sys.argv[2], int(sys.argv[3])
mine = lock.ProjectLock(path, pid_wait=0.2, poll=0.002)
violations = 0
refusals = collections.Counter()
done = 0
while done < rounds:
    try:
        mine.acquire()
    except lock.LockBusy as error:
        if not str(error).startswith("another project operation is active"):
            refusals[str(error).split(":")[0]] += 1
        time.sleep(0.0005)
        continue
    except BaseException as error:
        refusals["unexpected " + type(error).__name__ + ": " + str(error)] += 1
        time.sleep(0.0005)
        continue
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        violations += 1
    else:
        os.close(descriptor)
        time.sleep(0.0003)
        os.unlink(marker)
    done += 1
    mine.release()
print(json.dumps({"violations": violations, "refusals": refusals}))
"""
# A holder that crashes over and over: it makes the directory and leaves it with a dead pid.
STALE_PLANTER = """
import os, sys, time
from pathlib import Path

path = Path(sys.argv[1])
dead = [int(pid) for pid in sys.argv[2].split(",")]
planted = 0
while True:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        time.sleep(0.0002)
        continue
    (path / "pid").write_text(f"{dead[planted % len(dead)]}\\n", encoding="ascii")
    planted += 1
    time.sleep(0.003)
"""


def hold_in_child(test, source, *extra):
    """Child python that runs `source` (argv[1] is the lock path) and then waits on stdin."""
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys\n" + source + HOLD_TAIL, str(test.path), *extra],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=CHILD_ENV,
    )
    test.addCleanup(stop_child, process)
    line = process.stdout.readline()
    test.assertEqual(line.strip(), "held", line + (process.stdout.read() if process.poll() is not None else ""))
    return process


def stop_child(process):
    if process.poll() is None:
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    process.stdout.close()


def run_child(source, *args):
    result = subprocess.run(
        [sys.executable, "-c", "import sys\n" + source, *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
        env=CHILD_ENV,
        check=False,
    )
    return result.stdout.strip() + result.stderr.strip()


class ConcurrencyTests(LockTestCase):
    def test_contenders_never_share_the_lock(self):
        marker = self.root / "critical-section"
        workers = [
            subprocess.Popen(
                [sys.executable, "-c", STRESS_WORKER, str(self.path), str(marker), "40"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=CHILD_ENV,
            )
            for _ in range(4)
        ]
        outputs = []
        for worker in workers:
            try:
                outputs.append(worker.communicate(timeout=120)[0].strip())
            finally:
                if worker.poll() is None:
                    self.reap(worker)
        self.assertEqual(outputs, ["0"] * 4)
        self.assertFalse(self.path.exists())

    def test_contenders_never_share_a_lock_that_keeps_going_stale(self):
        marker = self.root / "critical-section"
        self.path.parent.mkdir(parents=True)
        dead = ",".join(str(self.dead_pid()) for _ in range(30))
        planter = subprocess.Popen(
            [sys.executable, "-c", STALE_PLANTER, str(self.path), dead],
            stderr=subprocess.PIPE,
            text=True,
            env=CHILD_ENV,
        )
        self.addCleanup(self.reap_planter, planter)
        workers = [
            subprocess.Popen(
                [sys.executable, "-c", STALE_WORKER, str(self.path), str(marker), "40"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=CHILD_ENV,
            )
            for _ in range(4)
        ]
        results = []
        for worker in workers:
            try:
                output = worker.communicate(timeout=120)[0].strip()
            finally:
                if worker.poll() is None:
                    self.reap(worker)
            results.append(json.loads(output))
        self.assertEqual(results, [{"violations": 0, "refusals": {}}] * 4)

    def reap_planter(self, planter):
        planter.kill()
        _, errors = planter.communicate()
        self.assertNotIn("Traceback", errors)


AUTOTUNE_HOLD = """
sys.path.insert(0, sys.argv[2])
import zapret_autotune_job as job
job.TEST_ROOT = sys.argv[3]
held = job.acquire_project_lock()
"""
AUTOTUNE_TAKE = """
import os
sys.path.insert(0, sys.argv[1])
import zapret_autotune_job as job
job.TEST_ROOT = sys.argv[2]
try:
    held = job.acquire_project_lock()
except RuntimeError as error:
    print('busy:', error)
else:
    print('acquired', job.read_pid(held / 'pid') == os.getpid())
    job.release_project_lock(held)
"""
VPN_SETUP = """
from pathlib import Path
sys.path.insert(0, sys.argv[{router}])
from vpn_node_manager import VpnNodeManager
base = Path(sys.argv[{base}])
manager = VpnNodeManager(
    xray_dir=base / 'xray', state_file=base / 'vpn-nodes.json', backup_dir=base / 'backups',
    lock_dir=Path(sys.argv[{lock}]),
)
manager._require_supported_xkeen = lambda: None  # this child tests lock ownership only
"""
VPN_HOLD = VPN_SETUP.format(router=2, base=3, lock=1) + """
def hold(name):
    print('held', flush=True)
    sys.stdin.read()
    return {'ok': True}

manager._activate_locked = hold
manager.activate('node')
"""
VPN_TAKE = VPN_SETUP.format(router=1, base=2, lock=3) + """
try:
    manager.activate('node')
except RuntimeError as error:
    print('busy:', error)
else:
    print('acquired')
"""


class LegacyUsersTests(LockTestCase):
    """Interop with job/tool entrypoints, including the manager on shared ProjectLock."""

    def setUp(self):
        super().setUp()
        self.path.parent.mkdir(parents=True)

    def test_autotune_job_respects_a_new_lock(self):
        with lock.ProjectLock(self.path):
            out = run_child(AUTOTUNE_TAKE, ROUTER_DIR, self.root)
        self.assertEqual(out, f"busy: another project operation is active (PID {os.getpid()})")

    def test_new_lock_respects_the_autotune_job(self):
        holder = hold_in_child(self, AUTOTUNE_HOLD, ROUTER_DIR, self.root)
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=0.2).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)

    def test_autotune_job_takes_over_the_lock_of_a_crashed_new_holder(self):
        holder = hold_in_child(self, "from kdn.common import lock\nlock.ProjectLock(sys.argv[1]).acquire()\n")
        holder.kill()
        holder.wait()
        self.assertEqual(run_child(AUTOTUNE_TAKE, ROUTER_DIR, self.root), "acquired True")
        self.assertFalse(self.path.exists())

    def test_new_lock_takes_over_the_lock_of_a_crashed_autotune_job(self):
        holder = hold_in_child(self, AUTOTUNE_HOLD, ROUTER_DIR, self.root)
        holder.kill()
        holder.wait()
        with lock.ProjectLock(self.path):
            self.assertEqual(self.pid_file.read_text(encoding="ascii"), f"{os.getpid()}\n")

    def test_vpn_manager_respects_a_new_lock(self):
        with lock.ProjectLock(self.path):
            out = run_child(VPN_TAKE, ROUTER_DIR, self.root, self.path)
        self.assertEqual(out, f"busy: another project operation is active (PID {os.getpid()})")

    def test_new_lock_respects_the_vpn_manager(self):
        holder = hold_in_child(self, VPN_HOLD, ROUTER_DIR, self.root)
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=0.2).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)

    def test_vpn_manager_releases_a_lock_the_new_code_can_take(self):
        holder = hold_in_child(self, VPN_HOLD, ROUTER_DIR, self.root)
        holder.stdin.close()
        holder.wait(timeout=10)
        self.assertFalse(self.path.exists())
        with lock.ProjectLock(self.path):
            pass

    def test_new_lock_waits_for_a_pid_the_vpn_manager_writes_late(self):
        # The VPN manager makes the directory and writes the pid in a second step.
        holder = self.live_process()
        self.make_lock_dir()
        self.delayed(0.3, lambda: self.pid_file.write_text(f"{holder.pid}\n", encoding="ascii"))
        with self.assertRaises(lock.LockBusy) as caught:
            lock.ProjectLock(self.path, pid_wait=1.5).acquire()
        self.assertEqual(caught.exception.pid, holder.pid)


if __name__ == "__main__":
    unittest.main()

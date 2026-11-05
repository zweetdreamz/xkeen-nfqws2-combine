"""Unit tests of kdn.jobs.coordinator: the one place that decides "the router is busy".

The module is imported directly and patched only with mock.patch.object on module objects. The probes are
lambdas over flags, the project lock is a real directory in a TemporaryDirectory. Races are forced with events
and barriers (a wait timeout only bounds a hang, nothing is synchronised by sleeping); the lock-order tests use
real locks and would hang or time out if the coordinator ever waited for a lock.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from kdn.common import errors
from kdn.common import lock
from kdn.jobs import coordinator


# Upper bound for a thread to finish or an event to be set; reached only when something hangs.
WAIT = 10.0
FAMILIES = ("route", "tuner", "diagnostic")


class Task(threading.Thread):
    """A thread that keeps what its function returned or raised and re-raises it in finish()."""

    def __init__(self, function):
        super().__init__(daemon=True)
        self._function = function
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self._function()
        except Exception as exc:
            self.error = exc

    def finish(self):
        self.join(WAIT)
        if self.is_alive():
            raise AssertionError("the thread did not finish: a deadlock or a wait that never ends")
        if self.error is not None:
            raise self.error
        return self.result


class RecordingLock:
    """A start lock that records how it was asked for and refuses to be waited for."""

    def __init__(self):
        self._lock = threading.Lock()
        self.acquires = []

    def acquire(self, blocking=True, timeout=-1):
        self.acquires.append((blocking, timeout))
        if blocking:
            raise AssertionError("the coordinator must never wait for the start lock")
        return self._lock.acquire(blocking=False)

    def __enter__(self):
        self.acquire()

    def __exit__(self, *_exc_info):
        self.release()

    def release(self):
        self._lock.release()

    def locked(self):
        return self._lock.locked()


class CoordinatorCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.project_lock_path = Path(self._tmp.name) / "opt" / "tmp" / "project.lock"
        self.busy = dict.fromkeys(FAMILIES, False)
        self.probe_calls = []
        self.start_lock = threading.Lock()
        self.coordinator = self.make_coordinator()
        self.refusals = coordinator.Refusals(route="route busy", tuner="tuner busy", diagnostic="diagnostic busy")

    def probe(self, name):
        def probe():
            self.probe_calls.append(name)
            return self.busy[name]

        return probe

    def make_coordinator(self, *, start_lock=None, probes=None, project_lock=None):
        return coordinator.Coordinator(
            start_lock=self.start_lock if start_lock is None else start_lock,
            probes={name: self.probe(name) for name in FAMILIES} if probes is None else probes,
            project_lock=(lambda: self.project_lock_path) if project_lock is None else project_lock,
        )

    def thread(self, function):
        task = Task(function)
        self.addCleanup(task.join, WAIT)
        task.start()
        return task

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

    def make_project_lock(self, pid_text=None):
        self.project_lock_path.mkdir(parents=True, mode=0o700)
        if pid_text is not None:
            (self.project_lock_path / lock.PID_FILE).write_text(pid_text, encoding="ascii")

    def lock_tree(self):
        """Names, mtimes and contents of everything under the project lock path."""
        if not self.project_lock_path.exists():
            return None
        return sorted(
            (str(path), path.stat().st_mtime_ns, path.read_bytes() if path.is_file() else None)
            for path in [self.project_lock_path, *self.project_lock_path.rglob("*")]
        )

    def assert_start_lock_free(self):
        self.assertFalse(self.start_lock.locked())
        self.assertIsNone(self.coordinator.starting())
        self.assertFalse(self.coordinator.start_in_progress())


class ConstantsTests(unittest.TestCase):
    def test_the_texts_are_the_ones_of_the_panel(self):
        self.assertEqual(coordinator.STARTING, "другое задание уже запускается; повторите через несколько секунд")
        self.assertEqual(coordinator.PROJECT_BUSY, "проект занят другой операцией (PID {pid}); повторите позже")

    def test_refusals_default_to_the_shared_texts_and_are_frozen(self):
        refusals = coordinator.Refusals(route="a", tuner="b", diagnostic="c")
        self.assertEqual(
            (refusals.route, refusals.tuner, refusals.diagnostic, refusals.starting, refusals.project),
            ("a", "b", "c", coordinator.STARTING, coordinator.PROJECT_BUSY),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            refusals.route = "other"
        with self.assertRaises(TypeError):
            coordinator.Refusals(route="a", tuner="b")

    def test_busy_is_the_typed_error_that_maps_to_409(self):
        self.assertTrue(issubclass(errors.Busy, RuntimeError))
        self.assertEqual(errors.Busy.status, 409)


class ConstructionTests(CoordinatorCase):
    def test_probes_must_name_exactly_the_three_families(self):
        for probes in (
            {"route": bool, "tuner": bool},
            {"route": bool, "tuner": bool, "diagnostic": bool, "extra": bool},
            {},
        ):
            with self.subTest(probes=sorted(probes)):
                with self.assertRaises(ValueError):
                    self.make_coordinator(probes=probes)

    def test_an_unknown_family_is_refused_before_the_start_lock_is_taken(self):
        for family in ("diagnostics", "vpn", ""):
            with self.subTest(family=family):
                with self.assertRaises(ValueError):
                    with self.coordinator.exclusive(self.refusals, family=family):
                        self.fail("the body must not run")
                self.assert_start_lock_free()


class ExclusiveTests(CoordinatorCase):
    def test_idle_exclusive_runs_the_body_and_releases_the_lock(self):
        ran = []
        with self.coordinator.exclusive(self.refusals, family="route"):
            ran.append(self.start_lock.locked())
        self.assertEqual(ran, [True])
        self.assert_start_lock_free()

    def test_busy_family_raises_its_own_message(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                self.busy[family] = True
                for attempt in (
                    lambda: self.coordinator.ensure_idle(self.refusals),
                    lambda: self.coordinator.exclusive(self.refusals).__enter__(),
                ):
                    with self.assertRaises(errors.Busy) as raised:
                        attempt()
                    self.assertEqual(str(raised.exception), f"{family} busy")
                    self.assertIsInstance(raised.exception, RuntimeError)
                self.busy[family] = False

    def test_a_refusal_by_a_busy_family_releases_the_lock_and_clears_starting(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                self.busy[family] = True
                with self.assertRaises(errors.Busy):
                    with self.coordinator.exclusive(self.refusals, family="tuner"):
                        self.fail("the body must not run")
                self.assert_start_lock_free()
                self.busy[family] = False

    def test_an_empty_refusal_text_still_refuses(self):
        refusals = coordinator.Refusals(route="", tuner="", diagnostic="")
        self.busy["tuner"] = True
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(refusals)
        self.assertEqual(str(raised.exception), "")

    def test_second_start_is_refused_with_the_starting_message(self):
        inside, release = threading.Event(), threading.Event()

        def hold():
            with self.coordinator.exclusive(self.refusals, family="route"):
                inside.set()
                self.assertTrue(release.wait(WAIT))

        holder = self.thread(hold)
        self.assertTrue(inside.wait(WAIT))
        try:
            with self.assertRaises(errors.Busy) as raised:
                with self.coordinator.exclusive(self.refusals, family="tuner"):
                    self.fail("the body must not run")
            self.assertEqual(str(raised.exception), coordinator.STARTING)
        finally:
            release.set()
        holder.finish()
        self.assert_start_lock_free()

    def test_the_refusal_uses_the_starting_text_of_the_given_refusals(self):
        refusals = dataclasses.replace(self.refusals, starting="сначала дождитесь запуска")
        self.start_lock.acquire()
        self.addCleanup(self.start_lock.release)
        with self.assertRaises(errors.Busy) as raised:
            with self.coordinator.exclusive(refusals):
                self.fail("the body must not run")
        self.assertEqual(str(raised.exception), "сначала дождитесь запуска")

    def test_a_refused_start_leaves_the_running_one_untouched(self):
        with self.coordinator.exclusive(self.refusals, family="route"):
            with self.assertRaises(errors.Busy):
                with self.coordinator.exclusive(self.refusals, family="tuner"):
                    self.fail("the body must not run")
            # The refused attempt neither released the lock of the first nor reset what it announced.
            self.assertTrue(self.start_lock.locked())
            self.assertEqual(self.coordinator.starting(), "route")
        self.assert_start_lock_free()

    def test_exclusive_is_not_reentrant_for_the_same_thread_either(self):
        with self.coordinator.exclusive(self.refusals):
            with self.assertRaises(errors.Busy) as raised:
                with self.coordinator.exclusive(self.refusals):
                    self.fail("the body must not run")
            self.assertEqual(str(raised.exception), coordinator.STARTING)
        self.assert_start_lock_free()

    def test_start_lock_is_released_after_an_error_in_the_body(self):
        with self.assertRaises(KeyError):
            with self.coordinator.exclusive(self.refusals, family="diagnostic"):
                raise KeyError("body")
        self.assert_start_lock_free()
        with self.coordinator.exclusive(self.refusals):
            pass

    def test_a_failing_probe_releases_the_lock_and_clears_starting(self):
        def broken():
            raise OSError("probe failed")

        coord = self.make_coordinator(probes={"route": broken, "tuner": bool, "diagnostic": bool})
        with self.assertRaises(OSError):
            with coord.exclusive(self.refusals, family="route"):
                self.fail("the body must not run")
        self.assertFalse(self.start_lock.locked())
        self.assertIsNone(coord.starting())

    def test_the_injected_start_lock_is_the_one_used(self):
        self.start_lock.acquire()
        self.addCleanup(self.start_lock.release)
        with self.assertRaises(errors.Busy) as raised:
            with self.coordinator.exclusive(self.refusals):
                self.fail("the body must not run")
        self.assertEqual(str(raised.exception), coordinator.STARTING)
        recording = RecordingLock()
        coord = self.make_coordinator(start_lock=recording)
        with coord.exclusive(self.refusals):
            self.assertTrue(recording.locked())
        self.assertEqual(recording.acquires, [(False, -1)])
        self.assertFalse(recording.locked())

    def test_starting_names_the_family_only_inside_the_block(self):
        for family in (*FAMILIES, None):
            with self.subTest(family=family):
                self.assertIsNone(self.coordinator.starting())
                with self.coordinator.exclusive(self.refusals, family=family):
                    self.assertEqual(self.coordinator.starting(), family)
                self.assertIsNone(self.coordinator.starting())
                with self.assertRaises(KeyError):
                    with self.coordinator.exclusive(self.refusals, family=family):
                        raise KeyError("body")
                self.assertIsNone(self.coordinator.starting())

    def test_starting_is_set_before_the_idle_check(self):
        seen = []
        probes = {
            name: (lambda name=name: seen.append((name, self.coordinator.starting())) or False) for name in FAMILIES
        }
        self.coordinator = self.make_coordinator(probes=probes)
        with self.coordinator.exclusive(self.refusals, family="tuner"):
            pass
        self.assertEqual(seen, [(name, "tuner") for name in FAMILIES])
        seen.clear()
        # A plain early check announces nothing.
        self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(seen, [(name, None) for name in FAMILIES])

    def test_a_poll_during_the_idle_check_of_a_start_sees_it_starting(self):
        # The status view of a family asks starting() from another thread while the start is still checking.
        in_probe, release = threading.Event(), threading.Event()

        def probe():
            in_probe.set()
            self.assertTrue(release.wait(WAIT))
            return False

        coord = self.make_coordinator(probes={"route": probe, "tuner": bool, "diagnostic": bool})

        def start():
            with coord.exclusive(self.refusals, family="route"):
                pass

        starter = self.thread(start)
        self.assertTrue(in_probe.wait(WAIT))
        try:
            self.assertEqual(coord.starting(), "route")
            self.assertTrue(coord.start_in_progress())
        finally:
            release.set()
        starter.finish()
        self.assertIsNone(coord.starting())

    def test_start_in_progress_follows_the_start_lock(self):
        self.assertFalse(self.coordinator.start_in_progress())
        with self.coordinator.exclusive(self.refusals, family="route"):
            self.assertTrue(self.coordinator.start_in_progress())
        self.assertFalse(self.coordinator.start_in_progress())
        self.start_lock.acquire()
        self.assertTrue(self.coordinator.start_in_progress())
        self.start_lock.release()
        self.assertFalse(self.coordinator.start_in_progress())

    def test_start_in_progress_is_true_for_a_block_without_a_family(self):
        # The automation window: a quick operation (no family) is between its checks and its write, starting()
        # is empty but the scheduler must still see the start.
        inside, release = threading.Event(), threading.Event()

        def quick_operation():
            with self.coordinator.exclusive(self.refusals):
                inside.set()
                self.assertTrue(release.wait(WAIT))

        worker = self.thread(quick_operation)
        self.assertTrue(inside.wait(WAIT))
        try:
            self.assertIsNone(self.coordinator.starting())
            self.assertTrue(self.coordinator.start_in_progress())
        finally:
            release.set()
        worker.finish()
        self.assertFalse(self.coordinator.start_in_progress())


class IdleCheckTests(CoordinatorCase):
    def test_hold_blocks_everyone_but_its_holder(self):
        self.coordinator.add_hold("automation", lambda: True, "идёт проверка по расписанию")
        for attempt in (
            lambda: self.coordinator.ensure_idle(self.refusals),
            lambda: self.coordinator.ensure_idle(self.refusals, holder="someone-else"),
            lambda: self.coordinator.exclusive(self.refusals).__enter__(),
        ):
            with self.assertRaises(errors.Busy) as raised:
                attempt()
            self.assertEqual(str(raised.exception), "идёт проверка по расписанию")
        self.assertFalse(self.start_lock.locked())
        self.coordinator.ensure_idle(self.refusals, holder="automation")
        with self.coordinator.exclusive(self.refusals, family="tuner", holder="automation"):
            self.assertEqual(self.coordinator.starting(), "tuner")

    def test_a_holder_is_not_excused_from_the_other_holds(self):
        self.coordinator.add_hold("automation", lambda: True, "автоматизация")
        self.coordinator.add_hold("maintenance", lambda: True, "обслуживание")
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(self.refusals, holder="automation")
        self.assertEqual(str(raised.exception), "обслуживание")

    def test_a_hold_that_is_not_held_does_not_refuse(self):
        self.coordinator.add_hold("automation", lambda: False, "автоматизация")
        self.coordinator.ensure_idle(self.refusals)

    def test_hold_is_checked_before_the_families_and_the_project_lock(self):
        self.coordinator.add_hold("automation", lambda: True, "автоматизация")
        self.busy.update(dict.fromkeys(FAMILIES, True))
        self.make_project_lock(f"{self.live_process().pid}\n")
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), "автоматизация")
        self.assertEqual(self.probe_calls, [])

    def test_holds_are_checked_in_the_order_they_were_registered(self):
        self.coordinator.add_hold("first", lambda: True, "первое")
        self.coordinator.add_hold("second", lambda: True, "второе")
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), "первое")

    def test_registering_a_name_again_replaces_the_hold(self):
        self.coordinator.add_hold("automation", lambda: True, "старое")
        self.coordinator.add_hold("automation", lambda: True, "новое")
        self.assertEqual(self.coordinator.held("automation"), "новое")

    def test_held_returns_the_message_or_none(self):
        state = {"held": False}
        self.coordinator.add_hold("automation", lambda: state["held"], "автоматизация")
        self.assertIsNone(self.coordinator.held("automation"))
        state["held"] = True
        self.assertEqual(self.coordinator.held("automation"), "автоматизация")
        self.assertIsNone(self.coordinator.held("unknown"))
        state["held"] = False
        self.assertIsNone(self.coordinator.held("automation"))

    def test_ensure_idle_does_not_take_the_start_lock(self):
        recording = RecordingLock()
        coord = self.make_coordinator(start_lock=recording)
        coord.ensure_idle(self.refusals)
        self.assertEqual(recording.acquires, [])
        self.assertFalse(recording.locked())

    def test_ensure_idle_ignores_a_start_in_progress(self):
        # It is the early check of an HTTP handler; the start itself is refused by exclusive(), not by this.
        inside, release = threading.Event(), threading.Event()

        def start():
            with self.coordinator.exclusive(self.refusals, family="route"):
                inside.set()
                self.assertTrue(release.wait(WAIT))

        starter = self.thread(start)
        self.assertTrue(inside.wait(WAIT))
        try:
            self.coordinator.ensure_idle(self.refusals)
            self.assertIsNone(self.coordinator.active())
        finally:
            release.set()
        starter.finish()

    def test_probes_are_called_at_check_time_not_at_construction(self):
        coord = self.make_coordinator()
        self.assertEqual(self.probe_calls, [])
        self.busy["diagnostic"] = True
        with self.assertRaises(errors.Busy):
            coord.ensure_idle(self.refusals)
        self.busy["diagnostic"] = False
        coord.ensure_idle(self.refusals)
        self.busy["route"] = True
        with self.assertRaises(errors.Busy):
            coord.ensure_idle(self.refusals)

    def test_families_are_checked_in_the_fixed_order_whatever_the_dictionary_order(self):
        reversed_probes = {name: self.probe(name) for name in reversed(FAMILIES)}
        coord = self.make_coordinator(probes=reversed_probes)
        self.busy.update(dict.fromkeys(FAMILIES, True))
        with self.assertRaises(errors.Busy) as raised:
            coord.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), "route busy")
        self.assertEqual(self.probe_calls, ["route"])
        self.probe_calls.clear()
        self.busy["route"] = False
        with self.assertRaises(errors.Busy) as raised:
            coord.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), "tuner busy")
        self.assertEqual(self.probe_calls, ["route", "tuner"])

    def test_active_returns_the_first_busy_family_in_fixed_order(self):
        reversed_probes = {name: self.probe(name) for name in reversed(FAMILIES)}
        coord = self.make_coordinator(probes=reversed_probes)
        self.assertIsNone(coord.active())
        for busy, expected in (
            ({"route", "tuner", "diagnostic"}, "route"),
            ({"route", "diagnostic"}, "route"),
            ({"tuner", "diagnostic"}, "tuner"),
            ({"diagnostic"}, "diagnostic"),
            ({"tuner"}, "tuner"),
            (set(), None),
        ):
            with self.subTest(busy=sorted(busy)):
                self.busy.update({name: name in busy for name in FAMILIES})
                self.assertEqual(coord.active(), expected)

    def test_active_ignores_holds_and_the_project_lock(self):
        self.coordinator.add_hold("automation", lambda: True, "автоматизация")
        self.make_project_lock(f"{self.live_process().pid}\n")
        self.assertIsNone(self.coordinator.active())


class ProjectLockTests(CoordinatorCase):
    def test_live_project_lock_of_an_unknown_process_refuses_with_its_pid(self):
        pid = self.live_process().pid
        self.make_project_lock(f"{pid}\n")
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), f"проект занят другой операцией (PID {pid}); повторите позже")
        with self.assertRaises(errors.Busy) as raised:
            with self.coordinator.exclusive(self.refusals, family="route"):
                self.fail("the body must not run")
        self.assertEqual(str(raised.exception), f"проект занят другой операцией (PID {pid}); повторите позже")
        self.assert_start_lock_free()

    def test_the_project_text_of_the_given_refusals_is_used(self):
        pid = self.live_process().pid
        self.make_project_lock(f"{pid}\n")
        refusals = dataclasses.replace(self.refusals, project="занято процессом {pid}")
        with self.assertRaises(errors.Busy) as raised:
            self.coordinator.ensure_idle(refusals)
        self.assertEqual(str(raised.exception), f"занято процессом {pid}")

    def test_stale_project_lock_is_ignored(self):
        self.make_project_lock(f"{self.dead_pid()}\n")
        self.coordinator.ensure_idle(self.refusals)
        with self.coordinator.exclusive(self.refusals, family="route"):
            pass

    def test_missing_project_lock_is_ignored(self):
        self.assertFalse(self.project_lock_path.exists())
        self.coordinator.ensure_idle(self.refusals)

    def test_a_lock_without_a_valid_pid_is_ignored(self):
        for text in (None, "", "garbage\n"):
            with self.subTest(pid_file=text):
                self.make_project_lock(text)
                self.coordinator.ensure_idle(self.refusals)
                (self.project_lock_path / lock.PID_FILE).unlink(missing_ok=True)
                self.project_lock_path.rmdir()

    def test_refusals_without_project_skip_the_lock(self):
        self.make_project_lock(f"{self.live_process().pid}\n")
        refusals = dataclasses.replace(self.refusals, project=None)
        with mock.patch.object(lock, "inspect_lock", side_effect=AssertionError("must not be inspected")):
            self.coordinator.ensure_idle(refusals)
            with self.coordinator.exclusive(refusals):
                pass

    def test_a_missing_path_skips_the_lock(self):
        coord = self.make_coordinator(project_lock=lambda: None)
        with mock.patch.object(lock, "inspect_lock", side_effect=AssertionError("must not be inspected")):
            coord.ensure_idle(self.refusals)

    def test_the_path_is_asked_at_check_time(self):
        elsewhere = Path(self._tmp.name) / "elsewhere.lock"
        path = {"value": elsewhere}
        coord = self.make_coordinator(project_lock=lambda: path["value"])
        self.make_project_lock(f"{self.live_process().pid}\n")
        coord.ensure_idle(self.refusals)
        path["value"] = self.project_lock_path
        with self.assertRaises(errors.Busy):
            coord.ensure_idle(self.refusals)

    def test_a_known_job_is_reported_before_the_project_lock(self):
        self.make_project_lock(f"{self.live_process().pid}\n")
        self.busy["tuner"] = True
        with mock.patch.object(lock, "inspect_lock", side_effect=AssertionError("must not be inspected")):
            with self.assertRaises(errors.Busy) as raised:
                self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(str(raised.exception), "tuner busy")

    def test_the_project_lock_is_inspected_once_per_check_and_only_read(self):
        pid = self.live_process().pid
        self.make_project_lock(f"{pid}\n")
        before = self.lock_tree()
        with (
            mock.patch.object(lock, "inspect_lock", wraps=lock.inspect_lock) as inspect,
            mock.patch.object(lock, "ProjectLock", side_effect=AssertionError("the panel never takes the lock")),
            mock.patch.object(lock.time, "sleep", side_effect=AssertionError("the check never waits")),
        ):
            for attempt in (
                lambda: self.coordinator.ensure_idle(self.refusals),
                lambda: self.coordinator.exclusive(self.refusals).__enter__(),
            ):
                with self.assertRaises(errors.Busy):
                    attempt()
            self.assertEqual(inspect.call_args_list, [mock.call(self.project_lock_path)] * 2)
        self.assertEqual(self.lock_tree(), before)

    def test_a_lock_being_taken_right_now_does_not_make_the_check_wait(self):
        # mkdir done, pid not published yet: ProjectLock.acquire would poll for it, the check just looks.
        self.make_project_lock()
        before = self.lock_tree()
        with mock.patch.object(lock.time, "sleep", side_effect=AssertionError("the check never waits")):
            self.coordinator.ensure_idle(self.refusals)
        self.assertEqual(self.lock_tree(), before)

    def test_an_idle_check_leaves_no_lock_behind(self):
        self.coordinator.ensure_idle(self.refusals)
        with self.coordinator.exclusive(self.refusals, family="route"):
            self.assertFalse(self.project_lock_path.exists())
        self.assertFalse(self.project_lock_path.exists())
        self.assertFalse(self.project_lock_path.parent.exists())


class ConcurrencyTests(CoordinatorCase):
    def test_concurrent_exclusive_admits_one_at_a_time(self):
        count = 16
        barrier = threading.Barrier(count)
        all_others_refused = threading.Event()
        guard = threading.Lock()
        counts = {"inside": 0, "max_inside": 0, "admitted": 0, "refused": 0}

        def attempt():
            barrier.wait(WAIT)
            try:
                with self.coordinator.exclusive(self.refusals, family="route"):
                    with guard:
                        counts["inside"] += 1
                        counts["admitted"] += 1
                        counts["max_inside"] = max(counts["max_inside"], counts["inside"])
                    # Stay inside until the other fifteen have all been turned away.
                    self.assertTrue(all_others_refused.wait(WAIT))
                    with guard:
                        counts["inside"] -= 1
            except errors.Busy as exc:
                self.assertEqual(str(exc), coordinator.STARTING)
                with guard:
                    counts["refused"] += 1
                    if counts["refused"] == count - 1:
                        all_others_refused.set()

        for task in [self.thread(attempt) for _ in range(count)]:
            task.finish()
        self.assertEqual(counts, {"inside": 0, "max_inside": 1, "admitted": 1, "refused": count - 1})
        self.assert_start_lock_free()

    def test_repeated_attempts_never_overlap(self):
        threads, rounds = 8, 300
        barrier = threading.Barrier(threads)
        inside = []
        outcomes = []

        def hammer():
            barrier.wait(WAIT)
            for _ in range(rounds):
                try:
                    with self.coordinator.exclusive(self.refusals, family="route"):
                        self.assertEqual(inside, [])
                        inside.append(threading.get_ident())
                        self.assertEqual(self.coordinator.starting(), "route")
                        inside.pop()
                except errors.Busy:
                    outcomes.append("refused")
                else:
                    outcomes.append("admitted")

        for task in [self.thread(hammer) for _ in range(threads)]:
            task.finish()
        self.assertEqual(len(outcomes), threads * rounds)
        self.assertIn("admitted", outcomes)
        self.assert_start_lock_free()


class LockOrderTests(CoordinatorCase):
    """The coordinator only ever tries its lock and only reads the others, so it cannot close a cycle.

    JOB_START_LOCK is the start lock, AUTOMATION_RUN_LOCK is a hold read through locked(), VPN_STORE_LOCK is
    taken by the body of a quick operation after exclusive() (start lock -> VPN store lock), the slot takes its
    run lock before it asks for the start lock (run lock -> start lock). Whichever order a thread meets them in,
    nobody waits for the start lock, so the worst case is a Busy, never a deadlock.
    """

    def setUp(self):
        super().setUp()
        self.run_lock = threading.Lock()
        self.vpn_lock = threading.RLock()
        self.coordinator.add_hold("automation", self.run_lock.locked, "автоматизация")

    def test_the_start_lock_is_only_ever_tried_never_waited_for(self):
        recording = RecordingLock()
        coord = self.make_coordinator(start_lock=recording)
        coord.add_hold("automation", self.run_lock.locked, "автоматизация")
        with coord.exclusive(self.refusals, family="route"):
            with self.assertRaises(errors.Busy):
                with coord.exclusive(self.refusals):
                    self.fail("the body must not run")
        self.busy["tuner"] = True
        with self.assertRaises(errors.Busy):
            with coord.exclusive(self.refusals):
                self.fail("the body must not run")
        self.busy["tuner"] = False
        self.make_project_lock(f"{self.live_process().pid}\n")
        with self.assertRaises(errors.Busy):
            with coord.exclusive(self.refusals):
                self.fail("the body must not run")
        (self.project_lock_path / lock.PID_FILE).unlink()
        self.project_lock_path.rmdir()
        self.run_lock.acquire()
        with self.assertRaises(errors.Busy):
            with coord.exclusive(self.refusals):
                self.fail("the body must not run")
        with coord.exclusive(self.refusals, holder="automation"):
            pass
        self.run_lock.release()
        for check in (coord.active, coord.starting, coord.start_in_progress, lambda: coord.held("automation")):
            check()
        self.assertTrue(recording.acquires)
        self.assertEqual({blocking for blocking, _timeout in recording.acquires}, {False})

    def test_a_start_holding_the_start_lock_and_a_thread_holding_the_vpn_lock_cannot_deadlock(self):
        # A: exclusive() (start lock), then wants the VPN store lock. B: holds the VPN store lock, then asks for
        # the start lock. With a waiting acquire both would wait for each other for ever.
        a_inside, b_has_vpn, b_refused = threading.Event(), threading.Event(), threading.Event()
        outcome = {}

        def quick_operation():
            with self.coordinator.exclusive(self.refusals):
                a_inside.set()
                self.assertTrue(b_has_vpn.wait(WAIT))
                outcome["a_got_vpn"] = self.vpn_lock.acquire(timeout=WAIT / 5)
                if outcome["a_got_vpn"]:
                    self.vpn_lock.release()

        def other_thread():
            with self.vpn_lock:
                b_has_vpn.set()
                self.assertTrue(a_inside.wait(WAIT))
                try:
                    with self.coordinator.exclusive(self.refusals):
                        outcome["b_refused"] = False
                except errors.Busy as exc:
                    outcome["b_refused"] = str(exc) == coordinator.STARTING
                b_refused.set()

        a, b = self.thread(quick_operation), self.thread(other_thread)
        a.finish()
        b.finish()
        self.assertTrue(b_refused.is_set())
        self.assertEqual(outcome, {"b_refused": True, "a_got_vpn": True})
        self.assert_start_lock_free()

    def test_the_vpn_lock_taken_inside_the_block_is_free_for_the_next_start(self):
        with self.coordinator.exclusive(self.refusals):
            with self.vpn_lock:
                pass
        with self.vpn_lock:
            with self.coordinator.exclusive(self.refusals):
                pass
        self.assert_start_lock_free()

    def test_a_manual_start_during_a_scheduled_run_is_refused_not_blocked(self):
        slot_running, release_slot = threading.Event(), threading.Event()

        def scheduled_slot():
            self.assertTrue(self.run_lock.acquire(blocking=False))
            try:
                slot_running.set()
                self.assertTrue(release_slot.wait(WAIT))
            finally:
                self.run_lock.release()

        slot = self.thread(scheduled_slot)
        self.assertTrue(slot_running.wait(WAIT))
        try:
            self.assertFalse(self.start_lock.locked())
            with self.assertRaises(errors.Busy) as raised:
                with self.coordinator.exclusive(self.refusals, family="route"):
                    self.fail("the body must not run")
            self.assertEqual(str(raised.exception), "автоматизация")
            self.assert_start_lock_free()
        finally:
            release_slot.set()
        slot.finish()
        with self.coordinator.exclusive(self.refusals, family="route"):
            pass

    def test_the_slot_takes_the_run_lock_then_the_start_lock_and_its_own_start_passes_its_hold(self):
        slot_inside, release_slot = threading.Event(), threading.Event()
        outcome = {}

        def scheduled_slot():
            self.assertTrue(self.run_lock.acquire(blocking=False))
            try:
                self.coordinator.ensure_idle(self.refusals, holder="automation")
                with self.coordinator.exclusive(self.refusals, family="tuner", holder="automation"):
                    outcome["starting"] = self.coordinator.starting()
                    slot_inside.set()
                    self.assertTrue(release_slot.wait(WAIT))
            finally:
                self.run_lock.release()

        slot = self.thread(scheduled_slot)
        self.assertTrue(slot_inside.wait(WAIT))
        try:
            with self.assertRaises(errors.Busy) as raised:
                with self.coordinator.exclusive(self.refusals):
                    self.fail("the body must not run")
            self.assertEqual(str(raised.exception), coordinator.STARTING)
            with self.assertRaises(errors.Busy) as raised:
                self.coordinator.ensure_idle(self.refusals)
            self.assertEqual(str(raised.exception), "автоматизация")
        finally:
            release_slot.set()
        slot.finish()
        self.assertEqual(outcome, {"starting": "tuner"})
        self.assert_start_lock_free()
        self.assertFalse(self.run_lock.locked())

    def test_a_slot_check_during_a_quick_operation_sees_the_start_and_never_waits_for_it(self):
        # The window of the scheduler: the quick operation passed its checks and has no family, the slot takes
        # its run lock now. ensure_idle() is satisfied, start_in_progress() tells the slot to skip.
        inside, release = threading.Event(), threading.Event()

        def quick_operation():
            with self.coordinator.exclusive(self.refusals):
                inside.set()
                self.assertTrue(release.wait(WAIT))

        quick = self.thread(quick_operation)
        self.assertTrue(inside.wait(WAIT))
        seen = {}

        def scheduled_slot():
            self.assertTrue(self.run_lock.acquire(blocking=False))
            try:
                self.coordinator.ensure_idle(self.refusals, holder="automation")
                seen["start_in_progress"] = self.coordinator.start_in_progress()
                seen["starting"] = self.coordinator.starting()
            finally:
                self.run_lock.release()

        try:
            self.thread(scheduled_slot).finish()
        finally:
            release.set()
        quick.finish()
        self.assertEqual(seen, {"start_in_progress": True, "starting": None})

    def test_a_start_that_began_before_the_run_lock_was_taken_finishes_undisturbed(self):
        # exclusive() is entered, then the slot takes the run lock: the start in progress is not re-checked
        # against the hold and the slot never blocks on it.
        inside, slot_took_lock, finished = threading.Event(), threading.Event(), threading.Event()

        def manual_start():
            with self.coordinator.exclusive(self.refusals, family="route"):
                inside.set()
                self.assertTrue(slot_took_lock.wait(WAIT))
            finished.set()

        starter = self.thread(manual_start)
        self.assertTrue(inside.wait(WAIT))
        self.assertTrue(self.run_lock.acquire(blocking=False))
        try:
            slot_took_lock.set()
            starter.finish()
        finally:
            self.run_lock.release()
        self.assertTrue(finished.is_set())
        self.assert_start_lock_free()


if __name__ == "__main__":
    unittest.main()

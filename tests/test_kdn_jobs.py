"""Unit tests of kdn.jobs: the job families, the store of their files and processes, and data compatibility.

The modules are imported directly and patched only with mock.patch.object on the module object. Every job
directory lives in a TemporaryDirectory; processes are real short scripts (a sleeper, a waiter), nothing touches
/opt. The last class runs the writers that fill job directories today (the phase-2 panel, the autotune and the
diagnostics tools) and reads, settles and clears what they leave through the store.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from kdn.common import fsutil, proc
from kdn.jobs import jobspec, jobstore

import panel_harness


REPO = Path(__file__).resolve().parents[1]
ROUTER_DIR = REPO / "tools" / "router"

SLEEPER = "import time\ntime.sleep(120)\n"
# Starts a grandchild in the same process group and writes its pid to the file named by argv[1].
GROUP_LEADER = (
    "import subprocess, sys, time\n"
    "child = subprocess.Popen(['sleep', '120'])\n"
    "open(sys.argv[1], 'w').write(str(child.pid))\n"
    "time.sleep(120)\n"
)
# Runs until the file named by argv[1] appears.
WAITER = "import os, sys, time\nwhile not os.path.exists(sys.argv[1]):\n    time.sleep(0.02)\n"
REPORTER = (
    "import os\n"
    "print(os.getcwd())\n"
    "print(os.environ.get('MARK'))\n"
    "print(os.environ.get('PATH'))\n"
    "print(os.environ.get('PYTHONUNBUFFERED'))\n"
)


def wait_for(predicate, timeout=10.0):
    """Poll an outside state (a process, a file) until it holds; False after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def kill_group(pid):
    with contextlib.suppress(OSError):
        os.killpg(pid, signal.SIGKILL)


def kill_process(pid):
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


class StoreTestCase(unittest.TestCase):
    """A family in a temporary directory, shaped like the route family of the router."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "job"
        self.script = self.root / "worker.py"
        self.script.write_text(SLEEPER, encoding="utf-8")
        self.family = self.make_family()
        self.store = jobstore.JobStore(self.family)

    def make_family(self, **overrides):
        directory = self.directory
        values = {
            "name": "route",
            "directory": lambda: directory,
            "state": lambda: directory / "state.json",
            "pid": lambda: directory / "worker.pid",
            "log": lambda: directory / "process.log",
            "files": lambda: (
                directory / "state.json",
                directory / "worker.pid",
                directory / "process.log",
                directory / "apply.log",
            ),
            "marker": lambda: (os.fsencode(str(self.script)),),
        }
        values.update(overrides)
        return jobspec.JobFamily(**values)

    def spec(self, job_id, **overrides):
        values = {
            "family": self.family.name,
            "kind": "switch",
            "job_id": job_id,
            "argv": [sys.executable, str(self.script)],
            "initial": {"job_id": job_id, "status": "queued"},
        }
        values.update(overrides)
        return jobspec.JobSpec(**values)

    def state_bytes(self):
        return (self.directory / "state.json").read_bytes()

    def start_worker(self, job_id="A", **overrides):
        """Prepare a job and spawn the script of `self.script` for it; returns (pid, exited event)."""
        exited = threading.Event()
        spec = self.spec(job_id, **overrides)
        self.store.prepare(spec)
        pid = self.store.spawn(spec, on_exit=exited.set)
        self.addCleanup(kill_group, pid)
        return pid, exited

    @staticmethod
    def dead_pid():
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait()
        return finished.pid

    def write_script(self, text):
        self.script.write_text(text, encoding="utf-8")


class SpecTests(StoreTestCase):
    def test_family_paths_are_resolved_on_every_call(self):
        one, two = self.root / "one", self.root / "two"
        for directory, pid in ((one, 4242), (two, 4343)):
            directory.mkdir()
            (directory / "worker.pid").write_text(f"{pid}\n", encoding="ascii")
        current = [one]
        store = jobstore.JobStore(
            self.make_family(
                directory=lambda: current[0],
                state=lambda: current[0] / "state.json",
                pid=lambda: current[0] / "worker.pid",
            )
        )
        self.assertEqual(store.pid(), 4242)
        current[0] = two
        self.assertEqual(store.pid(), 4343)
        store.write_state({"job_id": "x"})
        self.assertFalse((one / "state.json").exists())
        self.assertEqual(json.loads((two / "state.json").read_text(encoding="utf-8")), {"job_id": "x"})

    def test_file_names_of_the_markers(self):
        self.assertEqual(jobspec.CANCEL_REQUEST_NAME, "cancel.request")
        self.assertEqual(jobspec.JOB_ID_NAME, "job.id")

    def test_family_defaults_and_immutability(self):
        self.assertEqual(self.family.place, "каталоге задания")
        self.assertIsNone(self.family.extra)
        self.assertIs(self.family.tool_owned, False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.family.name = "other"
        flagged = self.make_family(tool_owned=True, place="каталоге диагностики")
        self.assertEqual((flagged.tool_owned, flagged.place), (True, "каталоге диагностики"))

    def test_job_spec_defaults_are_independent(self):
        first = jobspec.JobSpec(family="route", kind="switch", job_id="a", argv=["x"])
        second = jobspec.JobSpec(family="route", kind="switch", job_id="b", argv=["y"])
        self.assertEqual((first.cwd, first.env, first.initial), (None, {}, {}))
        self.assertIsNot(first.env, second.env)
        self.assertIsNot(first.initial, second.initial)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.kind = "other"

    def test_a_spec_of_another_family_is_refused(self):
        stranger = self.spec("A", family="tuner")
        with self.assertRaisesRegex(ValueError, "tuner"):
            self.store.prepare(stranger)
        with self.assertRaisesRegex(ValueError, "tuner"):
            self.store.spawn(stranger)
        self.assertFalse(self.directory.exists())

    def test_a_spec_without_a_job_id_is_refused(self):
        with self.assertRaisesRegex(ValueError, "идентификатора"):
            self.store.prepare(self.spec(""))
        with self.assertRaisesRegex(ValueError, "идентификатора"):
            self.store.spawn(self.spec(""))
        self.assertFalse(self.directory.exists())


class AliveTests(StoreTestCase):
    def test_alive_needs_every_marker_as_a_whole_argument(self):
        marker = (b"--route-job", b"/p/app.py")
        store = jobstore.JobStore(self.make_family(marker=lambda: marker))
        cases = (
            ([b"python3", b"/p/app.py", b"--route-job"], True),
            ([b"python3", b"/p/app.py", b"--route-job", b"id", b"switch", b""], True),
            ([b"python3", b"/p/app.py"], False),
            ([b"python3", b"--route-job"], False),
            ([b"python3", b"/p/app.py.bak", b"--route-job"], False),
            ([b"python3", b"x--route-job", b"/p/app.py"], False),
            ([b"python3", b"/p/app.py --route-job"], False),
            ([], False),
            (None, False),
        )
        for command, expected in cases:
            with self.subTest(command=command), mock.patch.object(proc, "job_command", return_value=command):
                self.assertIs(store.alive(4242), expected)

    def test_a_single_marker_and_an_empty_marker(self):
        single = jobstore.JobStore(self.make_family(marker=lambda: (b"/p/tuner.py",)))
        empty = jobstore.JobStore(self.make_family(marker=lambda: ()))
        with mock.patch.object(proc, "job_command", return_value=[b"python3", b"/p/tuner.py", b"--job-id", b"x"]):
            self.assertIs(single.alive(4242), True)
            # A family without a marker recognises no process: any live process would pass for the job.
            self.assertIs(empty.alive(4242), False)

    def test_markers_are_read_on_every_call(self):
        current = [(b"/p/one.py",)]
        store = jobstore.JobStore(self.make_family(marker=lambda: current[0]))
        with mock.patch.object(proc, "job_command", return_value=[b"python3", b"/p/two.py"]):
            self.assertIs(store.alive(1234), False)
            current[0] = (b"/p/two.py",)
            self.assertIs(store.alive(1234), True)

    def test_active_follows_the_pid_file(self):
        pid_file = self.directory / "worker.pid"
        self.assertIsNone(self.store.pid())
        self.assertIs(self.store.active(), False)
        self.directory.mkdir()
        for content in ("garbage\n", "", "1\n", "0\n", "-5\n", f"{self.dead_pid()}\n"):
            with self.subTest(content=content):
                pid_file.write_text(content, encoding="ascii")
                self.assertIs(self.store.active(), False)
        stranger = subprocess.Popen(["sleep", "120"])
        self.addCleanup(stranger.wait)
        self.addCleanup(stranger.kill)
        pid_file.write_text(f"{stranger.pid}\n", encoding="ascii")
        self.assertEqual(self.store.pid(), stranger.pid)
        # Alive, but not a process of this family: its argv lacks the marker.
        self.assertIs(self.store.active(), False)
        pid, _exited = self.start_worker()
        self.assertEqual(self.store.pid(), pid)
        self.assertIs(self.store.alive(pid), True)
        self.assertIs(self.store.active(), True)
        kill_group(pid)
        self.assertTrue(wait_for(lambda: not self.store.active()))


class StateTests(StoreTestCase):
    def test_state_round_trip_keeps_non_ascii_and_ends_with_newline(self):
        state = {"job_id": "a", "text": "Ошибка переключения 漢 😀", "nested": {"routes": ["x", "y"]}}
        self.store.write_state(state)
        raw = self.state_bytes()
        self.assertEqual(raw, (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        self.assertIn("Ошибка переключения".encode("utf-8"), raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(self.store.read_state(), state)
        self.assertEqual(stat.S_IMODE((self.directory / "state.json").stat().st_mode), 0o600)
        self.assertEqual([path.name for path in self.directory.iterdir()], ["state.json"])

    def test_read_state_raises_what_the_file_reader_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.store.read_state()
        self.directory.mkdir()
        path = self.directory / "state.json"
        for content in ("", "nope", "[]", "[1]", '"text"'):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.store.read_state()
        outside = self.root / "outside.json"
        outside.write_text('{"job_id": "x"}', encoding="utf-8")
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.store.read_state()
        path.unlink()
        path.write_text('{"x": "' + "y" * fsutil.MAX_JSON_BYTES + '"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.read_state()

    def test_update_state_changes_only_its_own_job(self):
        self.assertIs(self.store.update_state("A", status="running"), False)
        self.assertFalse(self.directory.exists())
        self.store.write_state({"job_id": "A", "status": "queued", "keep": 1})
        self.assertIs(self.store.update_state("A", status="running", progress=10), True)
        self.assertEqual(self.store.read_state(), {"job_id": "A", "status": "running", "keep": 1, "progress": 10})
        before = self.state_bytes()
        for job_id in ("B", "", None):
            with self.subTest(job_id=job_id):
                self.assertIs(self.store.update_state(job_id, status="failed"), False)
                self.assertEqual(self.state_bytes(), before)
        (self.directory / "state.json").write_text("not json", encoding="utf-8")
        self.assertIs(self.store.update_state("A", status="failed"), False)
        self.assertEqual(self.state_bytes(), b"not json")

    def test_update_state_without_a_job_id_in_the_state_changes_nothing(self):
        self.store.write_state({"status": "queued"})
        before = self.state_bytes()
        self.assertIs(self.store.update_state(None, status="failed"), False)
        self.assertIs(self.store.settle(None, status="failed"), False)
        self.assertEqual(self.state_bytes(), before)

    def test_concurrent_updates_lose_nothing(self):
        self.store.write_state({"job_id": "A"})
        threads_count, rounds = 8, 25
        errors = []

        def work(number):
            try:
                for index in range(rounds):
                    self.assertIs(self.store.update_state("A", **{f"k{number}_{index}": index}), True)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(number,)) for number in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        state = self.store.read_state()
        expected = {f"k{number}_{index}": index for number in range(threads_count) for index in range(rounds)}
        self.assertEqual(state, {"job_id": "A", **expected})

    def test_settle_refuses_a_live_job_and_changes_a_dead_one(self):
        pid, _exited = self.start_worker("A")
        before = self.state_bytes()
        with self.assertRaisesRegex(RuntimeError, "задание ещё выполняется"):
            self.store.settle("A", status="failed")
        self.assertEqual(self.state_bytes(), before)
        # A state of another job is not this settle's business, live process or not.
        self.assertIs(self.store.settle("B", status="failed"), False)
        self.assertEqual(self.state_bytes(), before)
        kill_group(pid)
        self.assertTrue(wait_for(lambda: not self.store.active()))
        self.assertIs(self.store.settle("A", status="failed", error="завершился"), True)
        self.assertEqual(self.store.read_state(), {"job_id": "A", "status": "failed", "error": "завершился"})

    def test_settle_of_a_missing_or_unreadable_state_is_false(self):
        self.assertIs(self.store.settle("A", status="failed"), False)
        self.directory.mkdir()
        (self.directory / "state.json").write_text("[]", encoding="utf-8")
        self.assertIs(self.store.settle("A", status="failed"), False)
        self.assertEqual(self.state_bytes(), b"[]")

    def test_settle_checks_liveness_by_the_pid_file_of_the_family(self):
        self.store.write_state({"job_id": "A", "status": "running"})
        (self.directory / "worker.pid").write_text("4242\n", encoding="ascii")
        with mock.patch.object(proc, "job_command", return_value=[b"python3", os.fsencode(str(self.script))]):
            with self.assertRaises(RuntimeError):
                self.store.settle("A", status="failed")
        with mock.patch.object(proc, "job_command", return_value=[b"python3", b"/some/other.py"]):
            self.assertIs(self.store.settle("A", status="failed"), True)

    def test_tool_owned_settle_needs_the_panels_job_id(self):
        store = jobstore.JobStore(self.make_family(name="tuner", tool_owned=True))
        # A tool started by hand over SSH writes the same state.json, but the panel has no job.id for it.
        store.write_state({"job_id": "T1", "status": "running"})
        before = self.state_bytes()
        self.assertIs(store.settle("T1", status="error"), False)
        self.assertEqual(self.state_bytes(), before)
        (self.directory / "job.id").write_text("T0\n", encoding="ascii")
        self.assertIs(store.settle("T1", status="error"), False)
        self.assertEqual(self.state_bytes(), before)
        (self.directory / "job.id").write_text("T1\n", encoding="ascii")
        self.assertIs(store.settle("T1", status="error", error="x"), True)
        self.assertEqual(store.read_state(), {"job_id": "T1", "status": "error", "error": "x"})

    def test_a_job_prepared_by_the_panel_can_be_settled_when_the_tool_is_gone(self):
        store = jobstore.JobStore(self.make_family(name="tuner", tool_owned=True))
        store.prepare(self.spec("T2", family="tuner"))
        self.assertIs(store.settle("T2", status="error", error="процесс завершился"), True)
        self.assertEqual(store.read_state()["status"], "error")

    def test_tool_owned_job_id_must_be_a_regular_file(self):
        store = jobstore.JobStore(self.make_family(name="tuner", tool_owned=True))
        store.write_state({"job_id": "T1", "status": "running"})
        outside = self.root / "outside.id"
        outside.write_text("T1\n", encoding="ascii")
        (self.directory / "job.id").symlink_to(outside)
        self.assertEqual(store.job_id(), "")
        self.assertIs(store.settle("T1", status="error"), False)

    def test_route_family_settles_a_job_without_job_id(self):
        # The job a phase-2 panel left: state and pid file, no job.id.
        self.store.write_state({"job_id": "R1", "status": "running"})
        self.assertFalse((self.directory / "job.id").exists())
        self.assertIs(self.store.settle("R1", status="failed"), True)
        self.assertEqual(self.store.read_state()["status"], "failed")


class ClearTests(StoreTestCase):
    def payload_extra(self):
        """The extra paths of the diagnostics family: payload-<N>.bin files."""
        return [path for path in self.directory.glob("payload-*.bin") if re.fullmatch(r"payload-\d+\.bin", path.name)]

    def test_clear_removes_files_extras_the_job_id_and_the_cancel_marker(self):
        store = jobstore.JobStore(self.make_family(extra=self.payload_extra))
        self.directory.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        (self.directory / "state.json").symlink_to(outside)
        for name in ("worker.pid", "process.log", "apply.log", "job.id", "cancel.request", "payload-12.bin"):
            (self.directory / name).write_text("x", encoding="utf-8")
        (self.directory / "payload-x.bin").write_bytes(b"x")
        (self.directory / "payload-7.bin").symlink_to(outside)
        (self.directory / "other.txt").write_text("x", encoding="utf-8")
        store.clear()
        self.assertEqual(
            sorted(path.name for path in self.directory.iterdir()),
            ["other.txt", "payload-7.bin", "payload-x.bin"],
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_clear_refuses_an_unusual_object(self):
        self.directory.mkdir()
        (self.directory / "apply.log").mkdir()
        with self.assertRaises(RuntimeError) as caught:
            self.store.clear()
        self.assertEqual(str(caught.exception), f"необычный объект в каталоге задания: {self.directory / 'apply.log'}")
        flagged = jobstore.JobStore(self.make_family(place="каталоге диагностики"))
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге диагностики"):
            flagged.clear()

    def test_clear_refuses_a_directory_in_place_of_the_job_id_and_of_the_marker(self):
        for name in ("job.id", "cancel.request"):
            with self.subTest(name=name):
                self.directory.mkdir()
                (self.directory / name).mkdir()
                with self.assertRaisesRegex(RuntimeError, "необычный объект"):
                    self.store.clear()
                (self.directory / name).rmdir()
                self.directory.rmdir()

    def test_clear_creates_the_directory_with_mode_700(self):
        self.store.clear()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.directory.chmod(0o755)
        self.store.clear()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_clear_files_removes_regular_files_and_links_only(self):
        self.directory.mkdir()
        target = self.root / "target.txt"
        target.write_text("keep\n", encoding="utf-8")
        regular, link, missing = self.directory / "a", self.directory / "b", self.directory / "c"
        regular.write_text("x", encoding="utf-8")
        link.symlink_to(target)
        jobstore.clear_files(self.directory, [regular, link, missing], "каталоге задания")
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")
        (self.directory / "d").mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге: "):
            jobstore.clear_files(self.directory, [self.directory / "d"], "каталоге")


class PrepareTests(StoreTestCase):
    def test_prepare_clears_then_writes_the_job_id_and_the_initial_state(self):
        self.directory.mkdir()
        for name in ("state.json", "worker.pid", "process.log", "apply.log", "cancel.request", "job.id", "keep.txt"):
            (self.directory / name).write_text("old", encoding="utf-8")
        spec = self.spec("A", initial={"job_id": "A", "status": "queued", "text": "Ошибка"})
        self.store.prepare(spec)
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["job.id", "keep.txt", "state.json"])
        self.assertEqual(self.store.job_id(), "A")
        self.assertEqual(self.state_bytes(), (json.dumps(spec.initial, ensure_ascii=False, indent=2) + "\n").encode())
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

    def test_prepare_with_an_empty_initial_state_writes_no_state(self):
        self.store.prepare(self.spec("A", initial={}))
        self.assertEqual([path.name for path in self.directory.iterdir()], ["job.id"])
        self.assertEqual(self.store.job_id(), "A")

    def test_prepare_refuses_an_unusual_object_before_writing_anything(self):
        self.directory.mkdir()
        (self.directory / "apply.log").mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект"):
            self.store.prepare(self.spec("A"))
        self.assertFalse((self.directory / "job.id").exists())
        self.assertFalse((self.directory / "state.json").exists())

    def test_job_id_of_a_missing_empty_or_odd_file_is_empty(self):
        self.assertEqual(self.store.job_id(), "")
        self.directory.mkdir()
        path = self.directory / "job.id"
        for content in (b"", b"\n", b"  \n", b"\xff\xfe"):
            with self.subTest(content=content):
                path.write_bytes(content)
                self.assertEqual(self.store.job_id(), "")
        path.write_bytes(b"A" * 5000)
        self.assertLessEqual(len(self.store.job_id()), 256)


class RaceTests(StoreTestCase):
    """Forced interleavings of a reconcile (settle) and a new launch (prepare) on one store."""

    def pausing_reader(self, thread_name, read_done, proceed):
        """A safe_json_file that makes the named thread wait after its first read of the state."""
        real = fsutil.safe_json_file
        state_path = self.directory / "state.json"

        def read(path, *args, **kwargs):
            data = real(path, *args, **kwargs)
            if threading.current_thread().name == thread_name and path == state_path and not read_done.is_set():
                read_done.set()
                proceed.wait(10)
            return data

        return read

    def test_every_writer_waits_for_a_running_settle(self):
        operations = {
            "prepare": lambda: self.store.prepare(self.spec("B")),
            "clear": self.store.clear,
            "write_state": lambda: self.store.write_state({"job_id": "B", "status": "queued"}),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                self.store.prepare(self.spec("A"))
                read_done, proceed, finished = threading.Event(), threading.Event(), threading.Event()
                result = {}

                def settle(result=result):
                    result["settle"] = self.store.settle("A", status="failed", error="A died")

                def run(operation=operation, finished=finished):
                    operation()
                    finished.set()

                settler = threading.Thread(target=settle, name="settler")
                writer = threading.Thread(target=run, name="writer")
                with mock.patch.object(fsutil, "safe_json_file", self.pausing_reader("settler", read_done, proceed)):
                    settler.start()
                    self.assertTrue(read_done.wait(10))
                    writer.start()
                    # The settle read state A and has not written yet: the other writer must wait for it.
                    self.assertFalse(finished.wait(0.3))
                    proceed.set()
                    settler.join(10)
                    writer.join(10)
                self.assertIs(result["settle"], True)
                self.assertTrue(finished.is_set())
                if name == "clear":
                    # The settle wrote first, the clear removed it: nothing of A is left to come back.
                    self.assertFalse((self.directory / "state.json").exists())
                    self.assertFalse((self.directory / "job.id").exists())
                else:
                    self.assertEqual(self.store.read_state(), {"job_id": "B", "status": "queued"})
                if name == "prepare":
                    self.assertEqual(self.store.job_id(), "B")
                self.store.clear()

    def test_settle_waits_for_a_running_prepare(self):
        self.store.prepare(self.spec("A"))
        mid_prepare, resume, settled = threading.Event(), threading.Event(), threading.Event()
        result = {}
        real = fsutil.atomic_text

        def writing(path, text, *args, **kwargs):
            real(path, text, *args, **kwargs)
            if threading.current_thread().name == "preparer" and path.name == "job.id":
                mid_prepare.set()
                resume.wait(10)

        def settle():
            result["settle"] = self.store.settle("A", status="failed")
            settled.set()

        preparer = threading.Thread(target=lambda: self.store.prepare(self.spec("B")), name="preparer")
        settler = threading.Thread(target=settle, name="settler")
        with mock.patch.object(fsutil, "atomic_text", writing):
            preparer.start()
            self.assertTrue(mid_prepare.wait(10))
            # B is half prepared: the old files are gone, its state is not written yet.
            settler.start()
            self.assertFalse(settled.wait(0.3))
            resume.set()
            preparer.join(10)
            settler.join(10)
        self.assertIs(result["settle"], False)
        self.assertEqual(self.store.read_state(), {"job_id": "B", "status": "queued"})

    def test_settle_after_a_new_prepare_does_not_overwrite_the_new_job(self):
        self.store.prepare(self.spec("A"))
        # The reconcile read state A, then the launch of B ran, then the reconcile writes.
        seen = self.store.read_state()
        self.store.prepare(self.spec("B", initial={"job_id": "B", "status": "queued", "fresh": True}))
        before = self.state_bytes()
        self.assertIs(self.store.settle(seen["job_id"], status="failed", error="A died"), False)
        self.assertIs(self.store.update_state(seen["job_id"], status="failed"), False)
        self.assertEqual(self.state_bytes(), before)
        self.assertEqual(self.store.job_id(), "B")

    def test_a_job_started_between_the_pid_check_and_the_write_is_not_settled(self):
        # settle(B) arrives while B's spawn has written the pid file already: B is live, not dead.
        pid, _exited = self.start_worker("B")
        before = self.state_bytes()
        with self.assertRaisesRegex(RuntimeError, "задание ещё выполняется"):
            self.store.settle("B", status="failed")
        self.assertEqual(self.state_bytes(), before)
        kill_group(pid)

    def test_prepare_write_clear_and_settle_hammer_leaves_a_whole_job(self):
        real = fsutil.safe_json_file

        def slow_read(*args, **kwargs):
            # Hands the CPU over right after a read: the window between a read and its write gets wide.
            data = real(*args, **kwargs)
            time.sleep(0.001)
            return data

        with mock.patch.object(fsutil, "safe_json_file", slow_read):
            for round_number in range(5):
                self.hammer_round([f"job{round_number:02d}{index:02d}" for index in range(6)])

    def hammer_round(self, ids):
        """One thread launches the jobs in turn; others settle and update every id of the round meanwhile."""
        done = threading.Event()
        errors = []

        def whole(job_id):
            # Once prepare(job_id) returned, the files belong to that job and nobody else's write may land.
            self.assertEqual(self.store.read_state(), {"job_id": job_id, "who": job_id, "n": job_id})
            self.assertEqual(self.store.job_id(), job_id)

        def launch_all():
            try:
                for index, job_id in enumerate(ids):
                    if index == 3:
                        self.store.clear()
                    self.store.prepare(self.spec(job_id, initial={"job_id": job_id, "who": job_id, "n": job_id}))
                    whole(job_id)
                    for _ in range(3):
                        # Lets a stale write that is still on its way land.
                        time.sleep(0.002)
                        whole(job_id)
            except BaseException as exc:
                errors.append(exc)
            finally:
                done.set()

        def settle_all():
            try:
                while not done.is_set():
                    for job_id in ids:
                        self.store.settle(job_id, who=job_id, n=job_id)
                        self.store.update_state(job_id, who=job_id)
                        # Outside the lock: the launcher gets its turn.
                        time.sleep(0.002)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=launch_all)] + [threading.Thread(target=settle_all) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])



class SpawnTests(StoreTestCase):
    def test_spawn_starts_a_session_leader_and_writes_the_pid(self):
        pid, _exited = self.start_worker("A")
        self.assertEqual(os.getsid(pid), pid)
        self.assertNotEqual(os.getsid(pid), os.getsid(0))
        self.assertEqual((self.directory / "worker.pid").read_text(encoding="ascii"), f"{pid}\n")
        self.assertEqual(self.store.pid(), pid)
        self.assertIs(self.store.active(), True)
        self.assertTrue((self.directory / "process.log").is_file())

    def test_spawn_returns_the_pid_of_the_process_it_started(self):
        process = mock.Mock(pid=4321)
        process.wait.return_value = mock.Mock()
        self.store.prepare(self.spec("A"))
        with mock.patch.object(jobstore.subprocess, "Popen", return_value=process) as popen:
            self.assertEqual(self.store.spawn(self.spec("A")), 4321)
        self.assertEqual((self.directory / "worker.pid").read_text(encoding="ascii"), "4321\n")
        self.assertIs(popen.call_args.kwargs["start_new_session"], True)
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.STDOUT)
        self.assertEqual(popen.call_args.args[0], [sys.executable, str(self.script)])

    def test_spawn_passes_cwd_env_and_unbuffered_and_logs_the_output(self):
        self.write_script(REPORTER)
        cwd = self.root / "cwd"
        cwd.mkdir()
        _pid, exited = self.start_worker("A", cwd=cwd, env={"MARK": "marked"})
        self.assertTrue(exited.wait(20))
        lines = (self.directory / "process.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines, [str(cwd.resolve()), "marked", proc.ROUTER_PATH, "1"])

    def test_the_log_is_appended_to_not_truncated(self):
        self.write_script(REPORTER)
        self.directory.mkdir()
        (self.directory / "process.log").write_text("earlier line\n", encoding="utf-8")
        spec = self.spec("A", initial={})
        exited = threading.Event()
        self.store.spawn(spec, on_exit=exited.set)
        self.assertTrue(exited.wait(20))
        text = (self.directory / "process.log").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("earlier line\n"))
        self.assertGreater(len(text.splitlines()), 1)

    def test_spawn_reaper_calls_on_exit_after_the_process_ends(self):
        finish = self.root / "finish"
        self.write_script(WAITER)
        seen = {}
        exited = threading.Event()

        def on_exit():
            seen["pid_file"] = self.store.pid()
            seen["active"] = self.store.active()
            exited.set()

        spec = self.spec("A", argv=[sys.executable, str(self.script), str(finish)])
        self.store.prepare(spec)
        pid = self.store.spawn(spec, on_exit=on_exit)
        self.addCleanup(kill_group, pid)
        self.assertFalse(exited.is_set())
        self.assertIs(self.store.active(), True)
        finish.write_text("go", encoding="ascii")
        self.assertTrue(exited.wait(20))
        self.assertEqual(seen, {"pid_file": pid, "active": False})

    def test_the_reaper_can_settle_the_dead_job_through_the_store(self):
        result = {}
        settled = threading.Event()

        def on_exit():
            result["settle"] = self.store.settle("A", status="failed", error="died")
            settled.set()

        spec = self.spec("A")
        self.store.prepare(spec)
        pid = self.store.spawn(spec, on_exit=on_exit)
        self.addCleanup(kill_group, pid)
        kill_group(pid)
        self.assertTrue(settled.wait(20))
        # The reaper runs after the process was waited for, so the store sees it as gone.
        self.assertIs(result["settle"], True)
        self.assertEqual(self.store.read_state(), {"job_id": "A", "status": "failed", "error": "died"})

    def test_spawn_without_on_exit_still_reaps(self):
        finish = self.root / "finish"
        self.write_script(WAITER)
        spec = self.spec("A", argv=[sys.executable, str(self.script), str(finish)])
        self.store.prepare(spec)
        thread_type = threading.Thread
        reapers = []

        def tracked_thread(*args, **kwargs):
            thread = thread_type(*args, **kwargs)
            reapers.append(thread)
            return thread

        with mock.patch.object(jobstore.threading, 'Thread', side_effect=tracked_thread):
            pid = self.store.spawn(spec)
        self.addCleanup(kill_group, pid)
        finish.write_text("go", encoding="ascii")
        self.assertTrue(wait_for(lambda: not self.store.active()))
        self.assertEqual(len(reapers), 1)
        reapers[0].join(timeout=10)
        self.assertFalse(reapers[0].is_alive())
        # Reaped: no zombie is left for the pid.
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_reaper_ignores_a_wait_that_returns_no_exit_status(self):
        # Popen stubs of the panel tests return a Mock from wait(): no real process ended, no reconcile.
        process = mock.Mock(pid=4321)
        on_exit = mock.Mock()
        self.store.prepare(self.spec("A"))
        with mock.patch.object(jobstore.subprocess, "Popen", return_value=process), \
                mock.patch.object(jobstore.threading, "Thread", SyncThread):
            self.store.spawn(self.spec("A"), on_exit=on_exit)
        process.wait.assert_called_once_with()
        on_exit.assert_not_called()

    def test_reaper_calls_on_exit_for_a_real_exit_status_including_failure(self):
        for code in (0, 1, -9):
            with self.subTest(code=code):
                process = mock.Mock(pid=4321)
                process.wait.return_value = code
                on_exit = mock.Mock()
                self.store.prepare(self.spec("A"))
                with mock.patch.object(jobstore.subprocess, "Popen", return_value=process), \
                        mock.patch.object(jobstore.threading, "Thread", SyncThread):
                    self.store.spawn(self.spec("A"), on_exit=on_exit)
                on_exit.assert_called_once_with()

    def test_on_exit_error_does_not_break_the_reaper(self):
        process = mock.Mock(pid=4321)
        process.wait.return_value = 0
        self.store.prepare(self.spec("A"))
        errors = io.StringIO()

        def on_exit():
            raise ValueError("on_exit blew up")

        with mock.patch.object(jobstore.subprocess, "Popen", return_value=process), \
                mock.patch.object(jobstore.threading, "Thread", SyncThread), \
                contextlib.redirect_stderr(errors):
            self.store.spawn(self.spec("A"), on_exit=on_exit)
        self.assertIn("ValueError", errors.getvalue())
        self.assertIn("on_exit blew up", errors.getvalue())

    def test_the_reaper_is_a_daemon_thread(self):
        process = mock.Mock(pid=4321)
        process.wait.return_value = mock.Mock()
        self.store.prepare(self.spec("A"))
        with mock.patch.object(jobstore.subprocess, "Popen", return_value=process), \
                mock.patch.object(jobstore.threading, "Thread", SyncThread):
            self.store.spawn(self.spec("A"))
        self.assertIs(SyncThread.last_daemon, True)

    def test_spawn_failure_raises_and_leaves_no_pid_file(self):
        self.store.prepare(self.spec("A"))
        spec = self.spec("A", argv=[str(self.root / "no-such-binary")])
        with self.assertRaises(OSError):
            self.store.spawn(spec, on_exit=mock.Mock())
        self.assertFalse((self.directory / "worker.pid").exists())
        self.assertIsNone(self.store.pid())

    def test_spawn_failure_does_not_call_on_exit(self):
        on_exit = mock.Mock()
        self.store.prepare(self.spec("A"))
        with self.assertRaises(OSError):
            self.store.spawn(self.spec("A", argv=[str(self.root / "no-such-binary")]), on_exit=on_exit)
        on_exit.assert_not_called()

    def test_pid_write_failure_stops_the_started_worker(self):
        finish = self.root / "finish"
        self.write_script(WAITER)
        spec = self.spec("A", argv=[sys.executable, str(self.script), str(finish)])
        self.store.prepare(spec)
        started = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            started.append(process)
            return process

        with mock.patch.object(jobstore.subprocess, "Popen", side_effect=start), \
                mock.patch.object(jobstore.fsutil, "atomic_text", side_effect=OSError("pid write failed")):
            with self.assertRaisesRegex(OSError, "pid write failed"):
                self.store.spawn(spec)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())
        self.assertFalse((self.directory / "worker.pid").exists())

    def test_reaper_start_failure_stops_the_worker_and_removes_its_pid(self):
        finish = self.root / "finish"
        self.write_script(WAITER)
        spec = self.spec("A", argv=[sys.executable, str(self.script), str(finish)])
        self.store.prepare(spec)
        started = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            started.append(process)
            return process

        with mock.patch.object(jobstore.subprocess, "Popen", side_effect=start), \
                mock.patch.object(jobstore.threading, "Thread") as thread:
            thread.return_value.start.side_effect = OSError("reaper could not start")
            with self.assertRaisesRegex(OSError, "reaper could not start"):
                self.store.spawn(spec)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())
        self.assertFalse((self.directory / "worker.pid").exists())

    def test_spawn_holds_the_store_lock_until_the_pid_file_is_written(self):
        # A settle must never see the window between the process start and the pid file as "no process".
        self.store.prepare(self.spec("A"))
        inside, resume, settled = threading.Event(), threading.Event(), threading.Event()
        result = {}
        real = fsutil.atomic_text

        def writing(path, text, *args, **kwargs):
            if threading.current_thread().name == "spawner" and path.name == "worker.pid":
                inside.set()
                resume.wait(10)
            real(path, text, *args, **kwargs)

        def settle():
            try:
                result["settle"] = self.store.settle("A", status="failed")
            except RuntimeError as exc:
                result["settle"] = str(exc)
            settled.set()

        spawner = threading.Thread(target=lambda: result.update(pid=self.store.spawn(self.spec("A"))), name="spawner")
        settler = threading.Thread(target=settle, name="settler")
        with mock.patch.object(fsutil, "atomic_text", writing):
            spawner.start()
            self.assertTrue(inside.wait(10))
            settler.start()
            self.assertFalse(settled.wait(0.3))
            resume.set()
            spawner.join(10)
            settler.join(10)
        self.addCleanup(kill_group, result["pid"])
        self.assertEqual(result["settle"], "задание ещё выполняется")
        self.assertEqual(self.store.read_state(), {"job_id": "A", "status": "queued"})


class SyncThread:
    """threading.Thread whose start() runs the target at once, in the caller's thread."""

    last_daemon = None

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        SyncThread.last_daemon = daemon
        self.target, self.args, self.kwargs = target, args, kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)


class CancelTests(StoreTestCase):
    def test_request_cancel_writes_the_marker_and_ends_the_group_without_touching_state(self):
        marker_path = self.directory / "cancel.request"
        pids = self.root / "grandchild.pid"
        self.write_script(GROUP_LEADER)
        pid, exited = self.start_worker("A", argv=[sys.executable, str(self.script), str(pids)])
        self.assertTrue(wait_for(lambda: pids.exists() and pids.read_text(encoding="ascii").isdigit()))
        grandchild = int(pids.read_text(encoding="ascii"))
        self.addCleanup(kill_process, grandchild)
        before = self.state_bytes()
        self.assertIs(self.store.cancel_requested(), False)
        self.assertEqual(self.store.request_cancel("нет задания"), pid)
        self.assertTrue(exited.wait(20))
        self.assertTrue(wait_for(lambda: not proc.process_alive(grandchild)), "the whole group must end")
        self.assertEqual(self.state_bytes(), before)
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        self.assertEqual(set(marker), {"job_id", "pid", "requested_utc"})
        self.assertEqual((marker["job_id"], marker["pid"]), ("A", pid))
        self.assertRegex(marker["requested_utc"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(stat.S_IMODE(marker_path.stat().st_mode), 0o600)
        self.assertIs(self.store.cancel_requested(), True)

    def test_request_cancel_without_a_job_raises_the_given_message(self):
        with self.assertRaises(RuntimeError) as caught:
            self.store.request_cancel("активного подбора нет")
        self.assertEqual(str(caught.exception), "активного подбора нет")
        self.directory.mkdir()
        (self.directory / "worker.pid").write_text(f"{self.dead_pid()}\n", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "^активного подбора нет$"):
            self.store.request_cancel("активного подбора нет")
        self.assertFalse((self.directory / "cancel.request").exists())

    def test_request_cancel_leaves_a_process_that_is_not_ours_alone(self):
        stranger = subprocess.Popen(["sleep", "120"], start_new_session=True)
        self.addCleanup(stranger.wait)
        self.addCleanup(kill_group, stranger.pid)
        self.directory.mkdir()
        (self.directory / "worker.pid").write_text(f"{stranger.pid}\n", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "^нет задания$"):
            self.store.request_cancel("нет задания")
        self.assertIsNone(stranger.poll())
        self.assertFalse((self.directory / "cancel.request").exists())

    def test_the_marker_of_a_job_without_a_job_id_never_shows_a_cancellation(self):
        # A job of the phase-2 panel has no job.id: the marker records an empty id and is ignored.
        self.directory.mkdir()
        self.store.write_state({"job_id": "A", "status": "running"})
        spec = self.spec("A")
        exited = threading.Event()
        pid = self.store.spawn(spec, on_exit=exited.set)
        self.addCleanup(kill_group, pid)
        self.assertEqual(self.store.request_cancel("нет"), pid)
        self.assertTrue(exited.wait(20))
        self.assertEqual(json.loads((self.directory / "cancel.request").read_text(encoding="utf-8"))["job_id"], "")
        self.assertIs(self.store.cancel_requested(), False)

    def test_request_cancel_raises_the_os_error_of_the_signal(self):
        self.start_worker("A")
        with mock.patch.object(os, "killpg", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                self.store.request_cancel("нет")
        self.assertTrue((self.directory / "cancel.request").is_file())

    def test_cancel_requested_ignores_symlinks_directories_a_marker_of_another_job_and_a_stale_pid(self):
        self.directory.mkdir()
        marker = self.directory / "cancel.request"
        (self.directory / "job.id").write_text("J1\n", encoding="ascii")
        (self.directory / "worker.pid").write_text("4242\n", encoding="ascii")
        good = {"job_id": "J1", "pid": 4242, "requested_utc": "2026-10-28T00:00:00Z"}
        outside = self.root / "outside.json"
        outside.write_text(json.dumps(good), encoding="utf-8")

        def write(data):
            marker.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")

        self.assertIs(self.store.cancel_requested(), False)  # no marker
        write(good)
        self.assertIs(self.store.cancel_requested(), True)
        cases = {
            "another job": {**good, "job_id": "J0"},
            "stale pid": {**good, "pid": 4243},
            "pid as text": {**good, "pid": "4242"},
            "no job id": {"pid": 4242},
            "no pid": {"job_id": "J1"},
            "empty job id": {**good, "job_id": ""},
            "not an object": "[]",
            "not json": "nope",
            "empty": "",
        }
        for name, content in cases.items():
            with self.subTest(marker=name):
                write(content)
                self.assertIs(self.store.cancel_requested(), False)
        marker.unlink()
        marker.symlink_to(outside)
        with self.subTest(marker="symlink"):
            self.assertIs(self.store.cancel_requested(), False)
        marker.unlink()
        marker.mkdir()
        with self.subTest(marker="directory"):
            self.assertIs(self.store.cancel_requested(), False)
        marker.rmdir()
        write(good)
        (self.directory / "job.id").write_text("", encoding="ascii")
        with self.subTest(job_id="empty"):
            self.assertIs(self.store.cancel_requested(), False)
        (self.directory / "job.id").unlink()
        with self.subTest(job_id="missing"):
            self.assertIs(self.store.cancel_requested(), False)
        (self.directory / "job.id").write_text("J1\n", encoding="ascii")
        (self.directory / "worker.pid").unlink()
        with self.subTest(pid="missing"):
            self.assertIs(self.store.cancel_requested(), False)

    def test_clear_forgets_the_cancellation(self):
        _pid, exited = self.start_worker("A")
        self.store.request_cancel("нет")
        self.assertTrue(exited.wait(20))
        self.assertIs(self.store.cancel_requested(), True)
        self.store.clear()
        self.assertIs(self.store.cancel_requested(), False)
        self.assertFalse((self.directory / "cancel.request").exists())




def load_tool(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROUTER_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


JOB_ID = "0123456789abcdef"
ROUTES = {"discord-tcp": "direct", "discord-voice": "direct", "youtube": "zapret", "telegram": "unmanaged"}
CREATED = {"created_at": 1793191995, "created_utc": "2026-10-28T12:53:15Z"}
TUNER_SETTINGS = {"service": "youtube", "mix_level": "safe", "max_candidates": 8, "client_ip": "", "search_seed": 1}
VOLATILE = frozenset({"created_at", "created_utc", "started_utc", "finished_utc", "updated_utc"})
# state.json of a route switch that the phase-2 worker finished (start_route_job, then run_route_job), as written.
PHASE_TWO_COMPLETED_ROUTE_STATE = """{
  "ok": true,
  "job_id": "0123456789abcdef",
  "operation": "switch",
  "status": "completed",
  "stage": "completed",
  "stage_label": "Готово",
  "progress": 100,
  "active": false,
  "service": "discord",
  "mode": "vpn",
  "before_routes": {
    "discord-tcp": "direct",
    "discord-voice": "direct",
    "youtube": "zapret",
    "telegram": "unmanaged"
  },
  "requested_routes": {
    "discord-tcp": "vless",
    "discord-voice": "vless",
    "youtube": "zapret",
    "telegram": "unmanaged"
  },
  "created_at": 1793191995,
  "created_utc": "2026-10-28T12:53:15Z",
  "output": "Snapshot created: /opt/backups/s1\\nГотово\\n",
  "started_utc": "2026-10-28T12:53:15Z",
  "result_ok": true,
  "code": 0,
  "snapshot": "/opt/backups/s1",
  "after_routes": {
    "discord-tcp": "direct",
    "discord-voice": "direct",
    "youtube": "zapret",
    "telegram": "unmanaged"
  },
  "finished_utc": "2026-10-28T12:53:16Z"
}
"""


class PhaseTwoDataTests(panel_harness.PanelTestCase):
    """What the writers of today leave in the job directories reads, settles and clears through the stores.

    The panel's launchers are written out below as `phase_two_*_launch` (their files, command line and Popen
    arguments as the phase-2 panel produced them); the three `*_emulation_matches_the_panel` tests hold them to
    the live panel code until the panel writes through the stores. The StateWriter classes of the autotune and
    diagnostics tools are the real ones. The child processes are real: the argv the panel launched is exactly
    what runs, so the liveness marker is checked against /proc, not against a hand-written command line.
    """

    modules = ("kdn.web.domain.route_jobs", "kdn.web.domain.tuner_jobs", "kdn.web.domain.diagnostic_jobs")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.autotune = load_tool("kdn_jobs_compat_autotune", "zapret_autotune_job.py")
        cls.diagnostics = load_tool("kdn_jobs_compat_diagnostics", "xkeen_diagnostics.py")

    def setUp(self):
        self.cfg = self.ns.module("kdn.web.infra.config")
        self.reset_root()
        self.patch(PROJECT_DIR=self.root / "project", ENTRY=self.script, AUTOTUNER=self.script, DIAGNOSTICS=self.script)

    def reset_root(self):
        self.root = self.fresh_root()
        (self.root / "project").mkdir()
        self.script = self.root / "worker.py"
        self.script.write_text(SLEEPER, encoding="utf-8")

    # Families as the jobfiles of task 10a builds them: paths and markers read from the configuration per call.
    def route_store(self):
        cfg = self.cfg
        return jobstore.JobStore(jobspec.JobFamily(
            name="route",
            directory=lambda: cfg.ROUTE_JOB_DIR,
            state=lambda: cfg.ROUTE_STATE,
            pid=lambda: cfg.ROUTE_PID,
            log=lambda: cfg.ROUTE_LOG,
            files=lambda: (
                cfg.ROUTE_STATE, cfg.ROUTE_PID, cfg.ROUTE_LOG, cfg.ROUTE_APPLY_LOG, cfg.ROUTE_JOB_DIR / "payload.json",
            ),
            marker=lambda: (b"--route-job", os.fsencode(str(cfg.ENTRY))),
        ))

    def tuner_store(self):
        cfg = self.cfg
        names = ("state.json", "events.log", "result-report.json", "runner.sh", "verdict.txt", "panel-launch.pid",
                 "process.log")
        return jobstore.JobStore(jobspec.JobFamily(
            name="tuner",
            directory=lambda: cfg.TUNER_JOB_DIR,
            state=lambda: cfg.TUNER_STATE,
            pid=lambda: cfg.TUNER_PID,
            log=lambda: cfg.TUNER_JOB_DIR / "process.log",
            files=lambda: [cfg.TUNER_JOB_DIR / name for name in names],
            marker=lambda: (os.fsencode(str(cfg.AUTOTUNER)),),
            tool_owned=True,
        ))

    def diagnostic_store(self):
        cfg = self.cfg

        def payloads():
            return [
                path for path in cfg.DIAGNOSTIC_JOB_DIR.glob("payload-*.bin")
                if re.fullmatch(r"payload-\d+\.bin", path.name)
            ]

        return jobstore.JobStore(jobspec.JobFamily(
            name="diagnostic",
            directory=lambda: cfg.DIAGNOSTIC_JOB_DIR,
            state=lambda: cfg.DIAGNOSTIC_STATE,
            pid=lambda: cfg.DIAGNOSTIC_PID,
            log=lambda: cfg.DIAGNOSTIC_LOG,
            files=lambda: (cfg.DIAGNOSTIC_STATE, cfg.DIAGNOSTIC_PID, cfg.DIAGNOSTIC_LOG),
            marker=lambda: (os.fsencode(str(cfg.DIAGNOSTICS)),),
            place="каталоге диагностики",
            extra=payloads,
            tool_owned=True,
        ))

    # The phase-2 launchers: files, command and Popen arguments; `popen` is the real Popen unless a test stubs it.
    def phase_two_route_launch(self, popen=subprocess.Popen, job_id=JOB_ID):
        cfg = self.cfg
        state = {
            "ok": True, "job_id": job_id, "operation": "switch", "status": "queued", "stage": "queued",
            "stage_label": "В очереди", "progress": 0, "active": True, "service": "discord", "mode": "vpn",
            "before_routes": dict(ROUTES),
            "requested_routes": {**ROUTES, "discord-tcp": "vless", "discord-voice": "vless"},
            **CREATED, "output": "",
        }
        cfg.ROUTE_JOB_DIR.mkdir(parents=True, exist_ok=True)
        cfg.ROUTE_JOB_DIR.chmod(0o700)
        fsutil.atomic_text(cfg.ROUTE_STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        command = [sys.executable, str(cfg.ENTRY), "--route-job", job_id, "switch", "discord", "vpn"]
        environment = proc.command_env()
        environment["PYTHONUNBUFFERED"] = "1"
        environment["XKEEN_PROJECT_DIR"] = str(cfg.PROJECT_DIR)
        with cfg.ROUTE_LOG.open("ab", buffering=0) as output:
            process = popen(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, cwd=cfg.PROJECT_DIR,
                env=environment, start_new_session=True,
            )
        fsutil.atomic_text(cfg.ROUTE_PID, f"{process.pid}\n")
        return process.pid, command

    def phase_two_tuner_launch(self, popen=subprocess.Popen, job_id=JOB_ID):
        # The launcher writes no state: the tool creates state.json itself, so only the pid file and the log exist.
        cfg = self.cfg
        cfg.TUNER_JOB_DIR.mkdir(parents=True, exist_ok=True)
        cfg.TUNER_JOB_DIR.chmod(0o700)
        command = [
            sys.executable, str(cfg.AUTOTUNER), "--service", "youtube", "--job-id", job_id, "--mix-level", "safe",
            "--max-candidates", "8", "--search-seed", "1", "--http-timeout", "6", "--voice-duration", "25",
        ]
        environment = proc.command_env()
        environment["PYTHONUNBUFFERED"] = "1"
        with (cfg.TUNER_JOB_DIR / "process.log").open("ab", buffering=0) as output:
            process = popen(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, cwd=cfg.PROJECT_DIR,
                env=environment, start_new_session=True,
            )
        fsutil.atomic_text(cfg.TUNER_PID, f"{process.pid}\n")
        return process.pid, command

    def phase_two_diagnostic_launch(self, popen=subprocess.Popen, job_id=JOB_ID):
        cfg = self.cfg
        cfg.DIAGNOSTIC_JOB_DIR.mkdir(parents=True, exist_ok=True)
        cfg.DIAGNOSTIC_JOB_DIR.chmod(0o700)
        initial = {
            "ok": True, "job_id": job_id, "kind": "health", "status": "queued", "active": True, "progress": 0,
            "created_utc": CREATED["created_utc"], "results": [],
        }
        fsutil.atomic_text(cfg.DIAGNOSTIC_STATE, json.dumps(initial, ensure_ascii=False, indent=2) + "\n")
        command = [sys.executable, str(cfg.DIAGNOSTICS), "--kind", "health", "--job-id", job_id]
        environment = proc.command_env()
        environment["PYTHONUNBUFFERED"] = "1"
        with cfg.DIAGNOSTIC_LOG.open("ab", buffering=0) as output:
            process = popen(
                command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, cwd=cfg.PROJECT_DIR,
                env=environment, start_new_session=True,
            )
        fsutil.atomic_text(cfg.DIAGNOSTIC_PID, f"{process.pid}\n")
        return process.pid, command

    def launch(self, emulation):
        pid, command = emulation()
        self.addCleanup(kill_group, pid)
        return pid, command

    # The real writers of the tools, with the initial state of their main().
    def run_tuner_writer(self, job_id, pid, **changes):
        writer = self.autotune.StateWriter(
            self.cfg.TUNER_JOB_DIR,
            {
                "format": 1, "job_id": job_id, "service": "youtube", "status": "preparing",
                "created_utc": self.autotune.utc_now(), "pid": pid, "mix_level": "safe", "max_candidates": 8,
                "search_seed": 1, "source_file": None, "needs_voice_verdict": False, "result_available": False,
            },
        )
        writer.write(status="running", **changes)
        return writer

    def run_diagnostic_writer(self, job_id):
        with mock.patch.object(self.diagnostics, "STATE_PATH", self.cfg.DIAGNOSTIC_STATE):
            writer = self.diagnostics.StateWriter(
                {"ok": True, "job_id": job_id, "kind": "health", "status": "running", "active": True, "progress": 2,
                 "created_utc": self.diagnostics.utc_now(), "source": {"flowseal_commit": "x"}, "results": []},
            )
            writer.write(progress=40, results=[{"name": "Проверка", "ok": True}])
            return writer

    @staticmethod
    def wait_dead(store):
        return wait_for(lambda: not store.active())

    def prepared_job(self, store, family, kind, job_id=JOB_ID, initial=None):
        """Prepare and spawn a job of the new store with a sleeper; returns (pid, exited event)."""
        spec = jobspec.JobSpec(
            family=family, kind=kind, job_id=job_id, argv=[sys.executable, str(self.script)],
            initial={"job_id": job_id, "status": "queued"} if initial is None else initial,
        )
        exited = threading.Event()
        store.prepare(spec)
        pid = store.spawn(spec, on_exit=exited.set)
        self.addCleanup(kill_group, pid)
        return pid, exited

    # Route.

    def test_route_worker_of_the_phase_two_panel_is_live_and_cannot_be_settled(self):
        store = self.route_store()
        pid, argv = self.launch(self.phase_two_route_launch)
        self.assertEqual(argv[1:4], [str(self.script), "--route-job", JOB_ID])
        self.assertEqual(store.pid(), pid)
        self.assertIs(store.alive(pid), True)
        self.assertIs(store.active(), True)
        self.assertEqual(store.read_state()["job_id"], JOB_ID)
        with self.assertRaisesRegex(RuntimeError, "задание ещё выполняется"):
            store.settle(JOB_ID, status="failed")
        self.assertEqual(store.read_state()["status"], "queued")

    def test_the_worker_command_line_of_the_phase_two_panel_matches_the_marker_in_proc(self):
        store = self.route_store()
        pid, argv = self.launch(self.phase_two_route_launch)
        command = proc.job_command(pid)
        self.assertEqual(command[: len(argv)], [os.fsencode(part) for part in argv])
        self.assertIs(store.alive(pid), True)
        # The same argv under another entry file is not this panel's worker.
        with mock.patch.object(proc, "job_command", return_value=[b"python3", b"/elsewhere/app.py", b"--route-job"]):
            self.assertIs(store.alive(pid), False)
        with mock.patch.object(proc, "job_command", return_value=[b"python3", os.fsencode(str(self.script))]):
            self.assertIs(store.alive(pid), False)

    def test_route_job_whose_worker_died_is_settled_and_keeps_the_phase_two_keys(self):
        store = self.route_store()
        pid, _argv = self.launch(self.phase_two_route_launch)
        written = store.read_state()
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        self.assertIs(store.settle(JOB_ID, status="failed", result_ok=False, active=False, error="x"), True)
        self.assertEqual(
            store.read_state(), {**written, "status": "failed", "result_ok": False, "active": False, "error": "x"}
        )
        self.assertEqual(list(store.read_state())[: len(written)], list(written))

    def test_completed_route_state_of_the_phase_two_worker_round_trips_byte_for_byte(self):
        store = self.route_store()
        self.cfg.ROUTE_JOB_DIR.mkdir(parents=True)
        self.cfg.ROUTE_STATE.write_text(PHASE_TWO_COMPLETED_ROUTE_STATE, encoding="utf-8")
        self.cfg.ROUTE_PID.write_text(f"{self.dead_pid()}\n", encoding="ascii")
        finished = store.read_state()
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["output"], "Snapshot created: /opt/backups/s1\nГотово\n")
        store.write_state(finished)
        self.assertEqual(self.cfg.ROUTE_STATE.read_text(encoding="utf-8"), PHASE_TWO_COMPLETED_ROUTE_STATE)
        # The caller decides on the status; the store lets a dead job's finished state be touched as before.
        self.assertIs(store.settle(JOB_ID, note="seen"), True)
        self.assertEqual(store.read_state(), {**finished, "note": "seen"})

    @staticmethod
    def dead_pid():
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait()
        return finished.pid

    def test_clear_removes_the_route_files_of_the_phase_two_panel_and_only_those(self):
        store = self.route_store()
        pid, _argv = self.launch(self.phase_two_route_launch)
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        self.cfg.ROUTE_APPLY_LOG.write_text("Snapshot created: /x\n", encoding="utf-8")
        (self.cfg.ROUTE_JOB_DIR / "other.txt").write_text("keep", encoding="utf-8")
        store.clear()
        self.assertEqual([path.name for path in self.cfg.ROUTE_JOB_DIR.iterdir()], ["other.txt"])

    def test_prepare_over_a_phase_two_route_directory_replaces_the_old_job(self):
        store = self.route_store()
        pid, _argv = self.launch(self.phase_two_route_launch)
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        self.cfg.ROUTE_APPLY_LOG.write_text("old log\n", encoding="utf-8")
        spec = jobspec.JobSpec(
            family="route", kind="xkeen", job_id="fedcba9876543210", argv=[sys.executable, str(self.script)],
            initial={"ok": True, "job_id": "fedcba9876543210", "status": "queued"},
        )
        store.prepare(spec)
        self.assertEqual(sorted(path.name for path in self.cfg.ROUTE_JOB_DIR.iterdir()), ["job.id", "state.json"])
        self.assertEqual(store.read_state()["job_id"], "fedcba9876543210")
        self.assertIsNone(store.pid())

    # Tuner.

    def test_tuner_job_of_the_phase_two_panel_is_live_for_the_marker_and_follows_the_tool_state(self):
        store = self.tuner_store()
        pid, command = self.launch(self.phase_two_tuner_launch)
        self.assertEqual(command[1], str(self.script))
        self.assertEqual(store.pid(), pid)
        self.assertIs(store.active(), True)
        # The launcher writes no state: the tool does, as its first act.
        with self.assertRaises(FileNotFoundError):
            store.read_state()
        self.run_tuner_writer(JOB_ID, pid)
        state = store.read_state()
        self.assertEqual((state["job_id"], state["status"], state["pid"]), (JOB_ID, "running", pid))
        with self.assertRaisesRegex(RuntimeError, "задание ещё выполняется"):
            store.settle(JOB_ID, status="error")

    def test_a_dead_tuner_job_of_the_phase_two_panel_is_not_settled_on_disk(self):
        store = self.tuner_store()
        pid, _command = self.launch(self.phase_two_tuner_launch)
        self.run_tuner_writer(JOB_ID, pid)
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        before = self.cfg.TUNER_STATE.read_bytes()
        self.assertEqual(store.job_id(), "")
        self.assertIs(store.settle(JOB_ID, status="error", error="x"), False)
        self.assertEqual(self.cfg.TUNER_STATE.read_bytes(), before)

    def test_a_tuner_run_by_hand_is_not_settled(self):
        store = self.tuner_store()
        self.run_tuner_writer(JOB_ID, 4242)
        before = self.cfg.TUNER_STATE.read_bytes()
        self.assertIs(store.active(), False)
        self.assertIs(store.settle(JOB_ID, status="error", error="x"), False)
        self.assertEqual(self.cfg.TUNER_STATE.read_bytes(), before)

    def test_tuner_job_prepared_by_the_new_store_is_settled_after_the_tool_overwrote_the_state(self):
        store = self.tuner_store()
        pid, exited = self.prepared_job(
            store, "tuner", "tuner", initial={"format": 1, "job_id": JOB_ID, "service": "youtube", "status": "queued"}
        )
        self.assertEqual(store.pid(), pid)
        self.assertEqual(self.cfg.TUNER_PID.read_text(encoding="ascii"), f"{pid}\n")
        # The tool replaces the panel's initial state with its own, then dies without finishing.
        self.run_tuner_writer(JOB_ID, pid, candidate_count=3)
        tool_state = store.read_state()
        self.assertNotIn("queued", json.dumps(tool_state))
        kill_group(pid)
        self.assertTrue(exited.wait(20))
        message = "процесс подбора завершился неожиданно"
        self.assertIs(store.settle(JOB_ID, status="error", error=message), True)
        settled = store.read_state()
        self.assertEqual(settled, {**tool_state, "status": "error", "error": message})
        self.assertEqual(settled["candidate_count"], 3)

    def test_the_cancel_marker_of_a_tuner_job_is_not_honoured_by_a_job_of_the_old_panel(self):
        store = self.tuner_store()
        pid, exited = self.prepared_job(store, "tuner", "tuner", initial={"job_id": JOB_ID, "status": "running"})
        store.request_cancel("нет")
        self.assertTrue(exited.wait(20))
        self.assertIs(store.cancel_requested(), True)
        marker = (self.cfg.TUNER_JOB_DIR / "cancel.request").read_bytes()
        # The panel is rolled back: its clear removes the seven files it knows and leaves job.id and the marker,
        # its launcher then starts another job.
        for name in ("state.json", "events.log", "result-report.json", "runner.sh", "verdict.txt",
                     "panel-launch.pid", "process.log"):
            (self.cfg.TUNER_JOB_DIR / name).unlink(missing_ok=True)
        self.assertEqual(sorted(path.name for path in self.cfg.TUNER_JOB_DIR.iterdir()), ["cancel.request", "job.id"])
        new_pid, _command = self.launch(self.phase_two_tuner_launch)
        self.assertNotEqual(new_pid, pid)
        self.run_tuner_writer("fedcba9876543210", new_pid)
        self.assertEqual((self.cfg.TUNER_JOB_DIR / "cancel.request").read_bytes(), marker)
        self.assertIs(store.active(), True)
        self.assertIs(store.cancel_requested(), False)
        kill_group(new_pid)
        self.assertTrue(self.wait_dead(store))
        self.assertIs(store.settle("fedcba9876543210", status="error"), False)

    def test_cancelling_a_live_tuner_job_leaves_the_tool_state_alone(self):
        store = self.tuner_store()
        pid, exited = self.prepared_job(store, "tuner", "tuner")
        self.run_tuner_writer(JOB_ID, pid)
        before = self.cfg.TUNER_STATE.read_bytes()
        self.assertEqual(store.request_cancel("активного подбора нет"), pid)
        self.assertTrue(exited.wait(20))
        self.assertEqual(self.cfg.TUNER_STATE.read_bytes(), before)
        self.assertIs(store.cancel_requested(), True)

    # Diagnostics.

    def test_diagnostic_job_of_the_phase_two_panel_is_live_and_its_state_reads(self):
        store = self.diagnostic_store()
        pid, command = self.launch(self.phase_two_diagnostic_launch)
        self.assertEqual(command[1:4], [str(self.script), "--kind", "health"])
        self.assertEqual(store.pid(), pid)
        self.assertIs(store.active(), True)
        self.assertEqual(store.read_state()["status"], "queued")
        self.run_diagnostic_writer(JOB_ID)
        read = store.read_state()
        self.assertEqual((read["job_id"], read["status"], read["progress"]), (JOB_ID, "running", 40))
        self.assertEqual(read["results"], [{"name": "Проверка", "ok": True}])
        with self.assertRaisesRegex(RuntimeError, "задание ещё выполняется"):
            store.settle(JOB_ID, status="error")

    def test_a_dead_diagnostic_job_of_the_phase_two_panel_is_not_settled_on_disk(self):
        store = self.diagnostic_store()
        pid, _command = self.launch(self.phase_two_diagnostic_launch)
        self.run_diagnostic_writer(JOB_ID)
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        before = self.cfg.DIAGNOSTIC_STATE.read_bytes()
        self.assertIs(store.settle(JOB_ID, status="error", error="x"), False)
        self.assertEqual(self.cfg.DIAGNOSTIC_STATE.read_bytes(), before)

    def test_the_cancelling_state_of_the_old_cancel_is_settled_for_a_job_of_the_new_panel(self):
        store = self.diagnostic_store()
        pid, exited = self.prepared_job(
            store, "diagnostic", "health",
            initial={"ok": True, "job_id": JOB_ID, "kind": "health", "status": "queued", "active": True},
        )
        writer = self.run_diagnostic_writer(JOB_ID)
        # What the phase-2 cancel did: the state says "cancelling" before the group gets TERM.
        with mock.patch.object(self.diagnostics, "STATE_PATH", self.cfg.DIAGNOSTIC_STATE):
            writer.write(status="cancelling", active=True)
        kill_group(pid)
        self.assertTrue(exited.wait(20))
        self.assertEqual(store.read_state()["status"], "cancelling")
        self.assertIs(store.settle(JOB_ID, status="error", active=False, error="x"), True)
        self.assertEqual(store.read_state()["status"], "error")

    def test_clear_removes_regular_payloads_of_the_diagnostics_tool_only(self):
        store = self.diagnostic_store()
        pid, _command = self.launch(self.phase_two_diagnostic_launch)
        kill_group(pid)
        self.assertTrue(self.wait_dead(store))
        directory = self.cfg.DIAGNOSTIC_JOB_DIR
        outside = self.root / "outside.bin"
        outside.write_bytes(b"keep")
        # The tool names its DPI payload payload-<pid>.bin.
        (directory / "payload-4242.bin").write_bytes(b"x")
        (directory / "payload-x.bin").write_bytes(b"x")
        (directory / "payload-7.bin").symlink_to(outside)
        store.clear()
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["payload-7.bin", "payload-x.bin"])
        self.assertEqual(outside.read_bytes(), b"keep")

    # The helper both generations share.

    def test_clear_files_behaves_like_the_phase_two_clear_job_files(self):
        scenarios = {
            "files and a link": lambda path: self.build(path, files=("a", "b"), links=("c",), other=("keep",)),
            "missing directory": lambda directory: None,
            "wide directory": lambda directory: self.build(directory, files=("a",), mode=0o755),
            "directory in place of a file": lambda directory: self.build(directory, files=("a",), dirs=("b",)),
        }
        for name, build in scenarios.items():
            with self.subTest(scenario=name):
                results = []
                for index, clear in enumerate((self.ns["clear_job_files"], jobstore.clear_files)):
                    base = self.root / f"{name.replace(' ', '-')}-{index}"
                    base.mkdir()
                    directory = base / "job"
                    build(directory)
                    paths = [directory / "a", directory / "b", directory / "c"]
                    try:
                        clear(directory, paths, "каталоге диагностики")
                        outcome = "cleared"
                    except RuntimeError as exc:
                        outcome = str(exc).replace(str(directory), "<dir>")
                    listing = sorted(path.name for path in directory.iterdir())
                    results.append((outcome, listing, stat.S_IMODE(directory.stat().st_mode)))
                self.assertEqual(results[0], results[1])

    @staticmethod
    def build(directory, files=(), links=(), dirs=(), other=(), mode=None):
        directory.mkdir()
        target = directory.parent / "target.txt"
        target.write_text("keep\n", encoding="utf-8")
        for name in files:
            (directory / name).write_text("x", encoding="utf-8")
        for name in links:
            (directory / name).symlink_to(target)
        for name in dirs:
            (directory / name).mkdir()
        for name in other:
            (directory / name).write_text("x", encoding="utf-8")
        if mode is not None:
            directory.chmod(mode)

    # The written-out launchers equal the live panel (until the panel writes through the stores).

    def skip_once_the_panel_writes_through_the_stores(self):
        if hasattr(self.ns.module("kdn.web.infra.jobfiles"), "ROUTE_STORE"):
            self.skipTest("the panel writes through the stores: the phase-2 launchers are gone")

    @staticmethod
    def normalized(path):
        if path.suffix != ".json":
            return path.read_text(encoding="utf-8")
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data), {key: "<volatile>" if key in VOLATILE else value for key, value in data.items()}

    def shape(self, directory, call):
        command, kwargs = call
        return {
            "command": command,
            "flags": {key: value for key, value in kwargs.items() if key not in ("stdout", "env")},
            "stdout": str(kwargs["stdout"].name),
            "env": {key: kwargs["env"].get(key) for key in ("PATH", "PYTHONUNBUFFERED", "XKEEN_PROJECT_DIR")},
            "files": {path.name: self.normalized(path) for path in sorted(directory.iterdir())},
            "mode": stat.S_IMODE(directory.stat().st_mode),
        }

    def compare_with_the_panel(self, directory_of, live_launch, emulation):
        self.skip_once_the_panel_writes_through_the_stores()
        calls = []

        def stub(command, **kwargs):
            calls.append((command, kwargs))
            return mock.Mock(pid=4321)

        with mock.patch.object(self.ns["secrets"], "token_hex", return_value=JOB_ID), \
                mock.patch.object(self.ns["subprocess"], "Popen", side_effect=stub), \
                mock.patch.object(self.ns["threading"], "Thread"):
            live_launch()
        live = self.shape(directory_of(), calls[-1])
        self.reset_root()
        emulation(popen=stub)
        written = self.shape(directory_of(), calls[-1])
        self.assertEqual(len(calls), 2)
        self.assertEqual(written, live)

    def test_route_emulation_matches_the_panel(self):
        self.skip_once_the_panel_writes_through_the_stores()
        self.patch(current_routes_fast=lambda: dict(ROUTES))
        self.compare_with_the_panel(
            lambda: self.cfg.ROUTE_JOB_DIR,
            lambda: self.ns["start_route_job"]("discord", "vpn"),
            self.phase_two_route_launch,
        )

    def test_tuner_emulation_matches_the_panel(self):
        self.skip_once_the_panel_writes_through_the_stores()
        self.patch(read_status=lambda: {"ok": True, "code": 0, "output": "youtube_route=zapret\n"})
        self.compare_with_the_panel(
            lambda: self.cfg.TUNER_JOB_DIR,
            lambda: self.ns["start_tuner_job"](dict(TUNER_SETTINGS)),
            self.phase_two_tuner_launch,
        )

    def test_diagnostic_emulation_matches_the_panel(self):
        self.skip_once_the_panel_writes_through_the_stores()
        self.compare_with_the_panel(
            lambda: self.cfg.DIAGNOSTIC_JOB_DIR,
            lambda: self.ns["start_diagnostic_job"]("health"),
            self.phase_two_diagnostic_launch,
        )

    def test_the_completed_route_literal_is_what_the_phase_two_worker_writes(self):
        self.skip_once_the_panel_writes_through_the_stores()
        self.patch(
            current_routes_fast=lambda: dict(ROUTES),
            run_route_command=lambda *_a, **_k: {
                "ok": True, "code": 0, "output": "Snapshot created: /opt/backups/s1\nГотово\n",
            },
        )
        with mock.patch.object(self.ns["secrets"], "token_hex", return_value=JOB_ID), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)), \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.ns["start_route_job"]("discord", "vpn")
        self.assertEqual(self.ns["run_route_job"](JOB_ID, "switch", "discord", "vpn"), 0)
        live = json.loads(self.cfg.ROUTE_STATE.read_text(encoding="utf-8"))
        literal = json.loads(PHASE_TWO_COMPLETED_ROUTE_STATE)

        def stable(data):
            return {key: value for key, value in data.items() if key not in VOLATILE | {"snapshot"}}

        self.assertEqual(stable(live), stable(literal))
        self.assertEqual(list(live), list(literal))


if __name__ == "__main__":
    unittest.main()

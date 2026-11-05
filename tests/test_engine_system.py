"""Tests of kdn.engine.system: external commands, processes and packages of the engine, ported from the script.

``run`` is the one place where the engine starts a program: the caller's environment, stdin and stderr closed
(or merged), the child in the caller's process group and registered with lifecycle, a timeout that kills the
child's own pid and nothing else. The ports of ``have``, ``process_running``, ``package_version``,
``nfqws_pid_is_service`` / ``nfqws_service_pid`` and the xray lookup of ``xray_test_config`` are checked against
the real functions of apply-discord-nfqws2.sh (extracted by engine_shell) under dash and busybox ash, on mock
binaries on ``PATH`` and on a fake ``/proc`` tree; the awk of ``package_version`` runs under the awk of the test
stand and under busybox awk, and the port follows the field separators of each.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from unittest import mock

import engine_shell
import test_engine_structure
from kdn.engine import config, confvalues, lifecycle, system


ROOT = Path(__file__).resolve().parents[1]
ROUTER_DIR = ROOT / "tools" / "router"
BASE_PATH = "/usr/bin:/bin"
HAS_BUSYBOX = shutil.which("busybox") is not None
HAS_PROC = os.path.isdir("/proc/self")
SHELLS = [("dash", (shutil.which("dash") or "dash",))]
if HAS_BUSYBOX:
    SHELLS.append(("busybox ash", (shutil.which("busybox"), "sh")))
# Default-FS separators of mawk (the awk of the test stand) and of busybox awk (the awk of the router).
MAWK_SEPARATORS = " \t\n"
BUSYBOX_SEPARATORS = " \t\n\v\f\r"
HUGE = "9" * 5000


def arabic_digits(number):
    """A number written with ARABIC-INDIC DIGIT characters: ``str.isdigit()`` and ``int()`` accept them."""
    return "".join(chr(0x660 + int(digit)) for digit in str(number))


def is_dead(pid):
    """True when the pid is gone or only a zombie that nobody reaped."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b") ", 1)[1][:1] == b"Z"
    except OSError:
        return False


def wait_until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return condition()


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = self.enterContext(tempfile.TemporaryDirectory(prefix="engine-system-"))

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write(self, path, data, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data if isinstance(data, bytes) else data.encode("utf-8", "surrogateescape"))
        os.chmod(path, mode)
        return path

    def tool(self, directory, name, body):
        """An executable shell script ``directory/name``; the directory is created."""
        return self.write(os.path.join(directory, name), "#!/bin/sh\n" + textwrap.dedent(body).lstrip("\n"), 0o755)

    def env(self, *directories, **extra):
        return {"PATH": ":".join([*directories, BASE_PATH]), **extra}


def spawn_engine(source, *args):
    """A Python process that imports kdn.engine, in a session of its own (so a killpg reaches only it)."""
    env = {name: value for name, value in os.environ.items() if not name.startswith(("KDN_ENGINE", "PYTHON"))}
    env["PYTHONPATH"] = str(ROUTER_DIR)
    return subprocess.Popen(
        [sys.executable, "-P", "-c", textwrap.dedent(source), *args],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=True,
    )


class RunTests(TempDirTestCase):
    def test_run_uses_the_callers_path_and_closes_stdin(self):
        directory = self.path("bin")
        self.tool(
            directory, "kdn-probe-tool", 'echo "marker ${KDN_CALLER:-unset} ${KDN_PARENT_ONLY:-unset}"; cat; echo done'
        )
        with mock.patch.dict(os.environ, {"KDN_PARENT_ONLY": "leak"}), self.stdin_that_never_ends():
            done = system.run(["kdn-probe-tool"], self.env(directory, KDN_CALLER="yes"), 10)
        self.assertEqual((done.stdout, done.returncode, done.timed_out), ("marker yes unset\ndone\n", 0, False))
        self.assertNotIn(directory, os.environ.get("PATH", ""))

    @contextlib.contextmanager
    def stdin_that_never_ends(self):
        """File descriptor 0 of this process is an open pipe nobody writes to: a child that inherits it blocks."""
        read_end, write_end = os.pipe()
        saved = os.dup(0)
        os.dup2(read_end, 0)
        try:
            yield
        finally:
            os.dup2(saved, 0)
            for descriptor in (saved, read_end, write_end):
                os.close(descriptor)

    def test_run_sends_stderr_to_devnull_unless_it_is_merged(self):
        directory = self.path("bin")
        self.tool(directory, "noisy", "echo noise >&2; echo quiet")
        read_end, write_end = os.pipe()
        saved = os.dup(2)
        os.dup2(write_end, 2)
        try:
            done = system.run(["noisy"], self.env(directory), 10)
        finally:
            os.dup2(saved, 2)
            os.close(saved)
            os.close(write_end)
        with os.fdopen(read_end, "rb") as handle:
            leaked = handle.read()
        self.assertEqual((done.stdout, leaked), ("quiet\n", b""))

    def test_run_does_not_search_the_callers_own_path(self):
        directory = self.path("bin")
        self.tool(directory, "kdn-probe-tool", "echo here")
        with mock.patch.dict(os.environ, {"PATH": directory + ":" + BASE_PATH}):
            done = system.run(["kdn-probe-tool"], {"PATH": BASE_PATH}, 10)
        self.assertEqual((done.returncode, done.stdout), (127, ""))

    def test_children_stay_in_the_callers_process_group(self):
        seen = []
        register = lifecycle.register_child

        def record(process):
            seen.append((process.pid, os.getpgid(process.pid), os.getsid(process.pid)))
            register(process)

        with mock.patch.object(lifecycle, "register_child", record):
            done = system.run(["sleep", "0.3"], self.env(), 10)
        self.assertEqual(done.returncode, 0)
        pid, group, session = seen[0]
        self.assertEqual(group, os.getpgid(0))
        self.assertEqual(session, os.getsid(0))
        self.assertNotEqual(group, pid)

    def test_run_registers_the_child_while_it_runs(self):
        events = []
        register, unregister = lifecycle.register_child, lifecycle.unregister_child

        def on_register(process):
            events.append(("register", process, process.poll() is None))
            register(process)

        def on_unregister(process):
            events.append(("unregister", process, process.poll() is None))
            unregister(process)

        with (
            mock.patch.object(lifecycle, "register_child", on_register),
            mock.patch.object(lifecycle, "unregister_child", on_unregister),
        ):
            system.run(["sleep", "0.2"], self.env(), 10)
        self.assertEqual([event[0] for event in events], ["register", "unregister"])
        self.assertIs(events[0][1], events[1][1])
        self.assertEqual([events[0][2], events[1][2]], [True, False])

    def test_run_unregisters_a_child_that_timed_out(self):
        unregistered = []
        unregister = lifecycle.unregister_child
        with (
            mock.patch.object(system, "KILL_GRACE", 0.5),
            mock.patch.object(
                lifecycle, "unregister_child", lambda process: (unregistered.append(process), unregister(process))
            ),
        ):
            done = system.run(["sleep", "30"], self.env(), 0.2)
        self.assertTrue(done.timed_out)
        self.assertEqual(len(unregistered), 1)
        self.assertIsNotNone(unregistered[0].poll())

    def test_run_kills_and_unregisters_the_child_when_it_is_interrupted(self):
        started = []
        register = lifecycle.register_child
        unregistered = []
        unregister = lifecycle.unregister_child
        with (
            mock.patch.object(
                lifecycle, "register_child", lambda process: (started.append(process), register(process))
            ),
            mock.patch.object(
                lifecycle, "unregister_child", lambda process: (unregistered.append(process), unregister(process))
            ),
            mock.patch.object(subprocess.Popen, "communicate", side_effect=KeyboardInterrupt),
            mock.patch.object(system, "KILL_GRACE", 0.5),
            self.assertRaises(KeyboardInterrupt),
        ):
            system.run(["sleep", "30"], self.env(), 10)
        self.assertEqual(len(started), 1)
        self.assertEqual(unregistered, started)
        self.assertIsNotNone(started[0].poll())
        self.assertTrue(is_dead(started[0].pid))

    def test_stop_leaves_a_child_that_is_already_gone_alone(self):
        process = subprocess.Popen(["true"])
        process.wait()
        with mock.patch.object(process, "terminate") as terminate, mock.patch.object(process, "kill") as kill:
            system._stop(process)
        terminate.assert_not_called()
        kill.assert_not_called()

    def test_stop_survives_a_child_that_cannot_be_signalled(self):
        refuses = mock.Mock(poll=mock.Mock(return_value=None), terminate=mock.Mock(side_effect=PermissionError))
        system._stop(refuses)
        refuses.kill.assert_not_called()
        stuck = mock.Mock(
            poll=mock.Mock(return_value=None),
            wait=mock.Mock(side_effect=subprocess.TimeoutExpired("x", 1)),
            kill=mock.Mock(side_effect=PermissionError),
        )
        system._stop(stuck)
        stuck.terminate.assert_called_once_with()
        stuck.kill.assert_called_once_with()

    def test_completed_has_a_readable_repr(self):
        done = system.Completed(3, "out", True)
        self.assertEqual(repr(done), "Completed(returncode=3, stdout='out', timed_out=True)")
        self.assertFalse(hasattr(done, "__dict__"))

    def test_run_missing_binary_is_127(self):
        done = system.run(["kdn-no-such-binary", "--flag"], self.env(), 10)
        self.assertEqual((done.returncode, done.stdout, done.timed_out), (127, "", False))
        done = system.run([self.path("absent", "tool")], self.env(), 10)
        self.assertEqual((done.returncode, done.stdout, done.timed_out), (127, "", False))

    def test_run_file_without_the_execute_bit_is_126(self):
        path = self.write(self.path("bin", "plain"), "#!/bin/sh\necho no\n", 0o644)
        done = system.run([path], self.env(), 10)
        self.assertEqual((done.returncode, done.stdout, done.timed_out), (126, "", False))

    def test_run_merges_stderr_on_request(self):
        directory = self.path("bin")
        self.tool(directory, "both", "echo out1; echo err1 >&2; echo out2")
        env = self.env(directory)
        self.assertEqual(system.run(["both"], env, 10).stdout, "out1\nout2\n")
        self.assertEqual(system.run(["both"], env, 10, merge_stderr=True).stdout, "out1\nerr1\nout2\n")

    def test_run_returns_the_exit_status_and_keeps_the_bytes(self):
        directory = self.path("bin")
        self.tool(directory, "odd", r"printf 'a\r\nb\377\n\302\240c'; exit 3")
        done = system.run(["odd"], self.env(directory), 10)
        self.assertEqual((done.returncode, done.stdout, done.timed_out), (3, "a\r\nb\udcff\n\u00a0c", False))

    def test_run_reports_death_by_a_signal_as_128_plus_the_signal(self):
        done = system.run(["sh", "-c", "kill -TERM $$"], self.env(), 10)
        self.assertEqual((done.returncode, done.timed_out), (143, False))

    def test_run_without_a_timeout_waits_for_the_child(self):
        self.assertEqual(system.run(["sh", "-c", "sleep 0.2; echo late"], self.env(), None).stdout, "late\n")

    def test_run_timeout_marks_the_result_and_keeps_the_partial_output(self):
        started = time.monotonic()
        done = system.run(["sh", "-c", "echo first; exec sleep 30"], self.env(), 0.5)
        self.assertTrue(done.timed_out)
        self.assertEqual(done.returncode, 124)
        self.assertEqual(done.stdout, "first\n")
        self.assertLess(time.monotonic() - started, 5)

    def test_run_timeout_ends_a_child_that_ignores_term_with_kill(self):
        pidfile = self.path("pid")
        script = 'trap "" TERM; echo $$ > "$1"; echo ready; while :; do sleep 0.05; done'
        started = time.monotonic()
        with mock.patch.object(system, "KILL_GRACE", 0.4):
            done = system.run(["sh", "-c", script, "sh", pidfile], self.env(), 0.4)
        elapsed = time.monotonic() - started
        self.assertEqual((done.timed_out, done.returncode, done.stdout), (True, 124, "ready\n"))
        self.assertGreaterEqual(elapsed, 0.75)
        self.assertLess(elapsed, 5)
        self.assertTrue(is_dead(int(Path(pidfile).read_text())))

    def test_a_grandchild_holding_the_pipe_after_the_child_exited_keeps_the_childs_status(self):
        pidfile = self.path("grandchild")
        script = 'sleep 20 & echo $! > "$1"; echo partial; exit 5'
        started = time.monotonic()
        with mock.patch.object(system, "DRAIN_WAIT", 0.3):
            done = system.run(["sh", "-c", script, "sh", pidfile], self.env(), 0.4)
        grandchild = int(Path(pidfile).read_text())
        self.addCleanup(lambda: os.kill(grandchild, signal.SIGKILL) if not is_dead(grandchild) else None)
        self.assertEqual((done.timed_out, done.returncode, done.stdout), (False, 5, "partial\n"))
        self.assertLess(time.monotonic() - started, 5)

    def test_run_timeout_does_not_wait_for_a_grandchild_that_holds_the_pipe(self):
        pidfile = self.path("grandchild")
        script = 'sleep 20 & echo $! > "$1"; echo started; wait'
        started = time.monotonic()
        with mock.patch.object(system, "DRAIN_WAIT", 0.3):
            done = system.run(["sh", "-c", script, "sh", pidfile], self.env(), 0.4)
        grandchild = int(Path(pidfile).read_text())
        self.addCleanup(lambda: os.kill(grandchild, signal.SIGKILL) if not is_dead(grandchild) else None)
        self.assertEqual((done.timed_out, done.returncode, done.stdout), (True, 124, "started\n"))
        self.assertLess(time.monotonic() - started, 5)

    def test_run_timeout_kills_the_child_not_the_callers_group(self):
        pidfile = self.path("pid")
        engine = spawn_engine(
            """
            import os, subprocess, sys, time
            from kdn.engine import system
            bystander = subprocess.Popen(["sleep", "30"])
            started = time.monotonic()
            done = system.run(["sh", "-c", 'echo $$ > "$1"; exec sleep 30', "sh", sys.argv[1]], os.environ, 0.5)
            print(done.timed_out, done.returncode, time.monotonic() - started < 5, bystander.poll() is None, flush=True)
            bystander.kill()
            bystander.wait()
            """,
            pidfile,
        )
        self.addCleanup(engine.kill)
        out, err = engine.communicate(timeout=30)
        self.assertEqual(out.split(), ["True", "124", "True", "True"], err)
        self.assertTrue(wait_until(lambda: is_dead(int(Path(pidfile).read_text()))))

    def run_engine_with_a_child(self, handlers, signal_group, timeout="120", closes_stdout=False):
        """An engine process in a session of its own runs ``sleep`` through system.run and gets a TERM.

        ``closes_stdout``: the child gives up the pipe at once and keeps running, so that run() is in its wait
        for the exit and not in its read of the output. Returns the exit status, the pid of the child, the
        stderr and the seconds from the signal to the exit.
        """
        pidfile = self.path(f"child-{timeout}-{handlers}-{signal_group}-{closes_stdout}.pid")
        engine = spawn_engine(
            """
            import os, sys
            from kdn.engine import lifecycle, system
            if sys.argv[2] == "handlers":
                lifecycle.install_signal_handlers()
            timeout = None if sys.argv[3] == "none" else float(sys.argv[3])
            redirect = ">/dev/null" if sys.argv[4] == "closed" else ""
            script = 'echo $$ > "$1"; exec sleep 60 ' + redirect
            system.run(["sh", "-c", script, "sh", sys.argv[1]], os.environ, timeout)
            """,
            pidfile,
            "handlers" if handlers else "plain",
            timeout,
            "closed" if closes_stdout else "open",
        )
        self.addCleanup(engine.kill)
        self.assertTrue(wait_until(lambda: os.path.exists(pidfile) and Path(pidfile).read_text().endswith("\n")))
        child = int(Path(pidfile).read_text())
        self.addCleanup(lambda: None if is_dead(child) else os.kill(child, signal.SIGKILL))
        self.assertEqual(os.getpgid(child), engine.pid, "the child must share the process group of the engine")
        self.assertEqual(os.getsid(child), engine.pid)
        signalled = time.monotonic()
        if signal_group:
            os.killpg(engine.pid, signal.SIGTERM)
        else:
            os.kill(engine.pid, signal.SIGTERM)
        _, err = engine.communicate(timeout=30)
        return engine.returncode, child, err, time.monotonic() - signalled

    def test_killpg_of_the_callers_group_reaches_the_child(self):
        code, child, err, _ = self.run_engine_with_a_child(handlers=False, signal_group=True)
        self.assertEqual(code, -signal.SIGTERM, err)
        self.assertTrue(wait_until(lambda: is_dead(child)))

    def test_killpg_with_the_handlers_installed_exits_130_and_leaves_no_child(self):
        code, child, err, _ = self.run_engine_with_a_child(handlers=True, signal_group=True)
        self.assertEqual(code, 130, err)
        self.assertTrue(wait_until(lambda: is_dead(child)))

    def test_term_to_the_engine_alone_kills_the_registered_child(self):
        code, child, err, _ = self.run_engine_with_a_child(handlers=True, signal_group=False)
        self.assertEqual(code, 130, err)
        self.assertTrue(wait_until(lambda: is_dead(child)), "the registered child must not outlive the engine")

    def test_term_between_spawn_and_registration_leaves_no_child(self):
        pidfile = self.path('spawn-window.pid')
        engine = spawn_engine(
            """
            import os, signal, subprocess, sys
            from pathlib import Path
            from kdn.engine import lifecycle, system
            lifecycle.install_signal_handlers()
            original = subprocess.Popen
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs)
                Path(sys.argv[1]).write_text(str(child.pid))
                os.kill(os.getpid(), signal.SIGTERM)
                return child
            subprocess.Popen = spawn
            system.run(['sleep', '60'], os.environ, 120)
            """, pidfile,
        )
        self.addCleanup(engine.kill)
        # Avoid waiting on the leaked child's inherited stdout in the red case.
        engine.wait(timeout=15)
        child = int(Path(pidfile).read_text())
        self.addCleanup(lambda: os.kill(child, signal.SIGKILL) if not is_dead(child) else None)
        self.assertEqual(engine.returncode, 130)
        self.assertTrue(wait_until(lambda: is_dead(child), timeout=2),
                        'spawned child must be registered before deferred TERM is handled')
        engine.communicate(timeout=5)

    def test_sigterm_during_a_run_exits_130_at_once_with_or_without_a_timeout(self):
        # An untimed Popen.wait() holds the wait lock in the main thread, the handler cannot reap the child it
        # killed and the exit takes about 2 * KILL grace (4 s); every wait of run() is timed. The wait is reached
        # when the child has closed the pipe and still runs.
        for timeout in ("none", "120"):
            for closes_stdout in (False, True):
                with self.subTest(timeout=timeout, closes_stdout=closes_stdout):
                    self.check_sigterm_is_quick(timeout, closes_stdout)

    def check_sigterm_is_quick(self, timeout, closes_stdout):
        code, child, err, elapsed = self.run_engine_with_a_child(
            handlers=True, signal_group=False, timeout=timeout, closes_stdout=closes_stdout
        )
        self.assertEqual(code, 130, err)
        self.assertLess(elapsed, 1.0, "the exit after SIGTERM must not wait for a grace period")
        self.assertTrue(is_dead(child))

    def test_a_run_without_a_timeout_waits_in_slices(self):
        calls = []
        communicate = subprocess.Popen.communicate

        def record(process, *args, **kwargs):
            calls.append(kwargs.get("timeout", args[1] if len(args) > 1 else None))
            return communicate(process, *args, **kwargs)

        with (
            mock.patch.object(system, "SLICE", 0.1),
            mock.patch.object(subprocess.Popen, "communicate", record),
        ):
            done = system.run(["sh", "-c", "sleep 0.35; echo late"], self.env(), None)
        self.assertEqual(done.stdout, "late\n")
        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(set(calls), {0.1})

    def test_no_wait_of_run_is_untimed(self):
        waited = []
        wait, communicate = subprocess.Popen.wait, subprocess.Popen.communicate

        def record_wait(process, timeout=None):
            waited.append(("wait", timeout))
            return wait(process, timeout=timeout)

        def record_communicate(process, input=None, timeout=None):
            waited.append(("communicate", timeout))
            return communicate(process, input, timeout)

        with (
            mock.patch.object(subprocess.Popen, "wait", record_wait),
            mock.patch.object(subprocess.Popen, "communicate", record_communicate),
            mock.patch.object(system, "KILL_GRACE", 0.3),
        ):
            system.run(["true"], self.env(), None)
            system.run(["true"], self.env(), 10)
            system.run(["sleep", "30"], self.env(), 0.2)
            system.run(["sh", "-c", 'trap "" TERM; while :; do sleep 0.05; done'], self.env(), 0.2)
        self.assertTrue(waited)
        self.assertEqual([call for call in waited if call[1] is None], [])


class ImportBudgetTests(unittest.TestCase):
    def test_system_loads_none_of_the_slow_modules(self):
        _, baseline = test_engine_structure.importtime_modules(["-c", "pass"])
        result, names = test_engine_structure.importtime_modules(["-c", "import kdn.engine.system"])
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace")[-2000:])
        self.assertIn("kdn.engine.system", names)
        # enum comes with re, json and subprocess (R11); the rest of rule 9 holds.
        slow = test_engine_structure.FORBIDDEN_MODULES - {"enum"}
        loaded = {test_engine_structure.top_level(name) for name in names - baseline}
        self.assertEqual(sorted(loaded & slow), [])

    def test_only_system_and_bounded_validation_runner_import_subprocess(self):
        found = []
        for path in test_engine_structure.engine_files():
            for _, module, _, _, _ in test_engine_structure.imports_of(test_engine_structure.parse(path)):
                if test_engine_structure.top_level(module) == "subprocess":
                    found.append(path.name)
        self.assertEqual(sorted(set(found)), ["nfqws_process.py", "system.py"])


class HaveTests(TempDirTestCase):
    def test_have_finds_an_executable_file_on_the_callers_path(self):
        first, second = self.path("one"), self.path("two")
        self.tool(first, "alpha", "exit 0")
        self.tool(second, "beta", "exit 0")
        self.assertTrue(system.have("alpha", {"PATH": f"{first}:{second}"}))
        self.assertTrue(system.have("beta", {"PATH": f"{first}:{second}"}))
        self.assertFalse(system.have("beta", {"PATH": first}))
        self.assertFalse(system.have("alpha", {"PATH": ""}))
        self.assertFalse(system.have("missing", {"PATH": f"{first}:{second}"}))

    def test_have_skips_what_a_shell_would_not_run(self):
        directory = self.path("bin")
        self.write(os.path.join(directory, "plain"), "#!/bin/sh\n", 0o644)
        os.makedirs(os.path.join(directory, "adir"))
        os.symlink("nowhere", os.path.join(directory, "dangling"))
        self.tool(directory, "real", "exit 0")
        os.symlink("real", os.path.join(directory, "link"))
        for name, expected in (("plain", False), ("adir", False), ("dangling", False), ("link", True), ("real", True)):
            with self.subTest(name=name):
                self.assertEqual(system.have(name, {"PATH": directory}), expected)

    def test_an_empty_path_entry_is_the_current_directory(self):
        self.tool(self.path("cwd"), "local-tool", "exit 0")
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.path("cwd"))
        for value in (":/nonexistent", "/nonexistent:", "/nonexistent::/other", ""):
            with self.subTest(path=value):
                self.assertTrue(system.have("local-tool", {"PATH": value}))
        self.assertFalse(system.have("local-tool", {"PATH": "/nonexistent"}))

    def test_a_name_with_a_slash_is_tested_as_a_path_and_a_missing_path_is_the_default_one(self):
        path = self.tool(self.path("bin"), "tool", "exit 0")
        self.assertTrue(system.have(path, {"PATH": ""}))
        self.assertFalse(system.have(self.path("bin", "nothing"), {"PATH": BASE_PATH}))
        self.assertTrue(system.have("sh", {}))

    def test_have_matches_command_v_of_every_shell(self):
        first, second = self.path("one"), self.path("two")
        self.tool(first, "alpha", "exit 0")
        self.tool(second, "alpha", "exit 0")
        self.tool(second, "beta", "exit 0")
        self.write(os.path.join(first, "plain"), "#!/bin/sh\n", 0o644)
        self.write(os.path.join(second, "plain"), "#!/bin/sh\n", 0o755)
        os.makedirs(os.path.join(first, "adir"))
        os.symlink("alpha", os.path.join(first, "link"))
        os.symlink("nowhere", os.path.join(first, "dangling"))
        self.tool(self.tmp, "cwdtool", "exit 0")
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.tmp)
        paths = [
            f"{first}:{second}",
            first,
            second,
            f"{second}:{first}",
            f":{second}",
            f"{second}::{first}",
            f"{second}:",
            "",
        ]
        names = ["alpha", "beta", "adir", "link", "dangling", "missing", "cwdtool", "./one/alpha", "one/alpha", "plain"]
        for label, shell in SHELLS:
            for value in paths:
                for name in names:
                    # busybox ash accepts a regular file without the execute bit, dash and the port do not;
                    # that case is pinned against dash only.
                    if label == "busybox ash" and name == "plain" and value in (first, f"{first}:{second}"):
                        continue
                    with self.subTest(shell=label, path=value, name=name):
                        env = {"PATH": value}
                        result = engine_shell.run_function("have", name, env=env, shell=shell)
                        self.assertEqual(system.have(name, env), result.returncode == 0, result)


class ProcessRunningTests(TempDirTestCase):
    def mocks(self, pidof=None, pgrep=None):
        """A fresh directory of a pidof and a pgrep that log their argv and exit with a status (None: absent)."""
        self.mock_count = getattr(self, "mock_count", 0) + 1
        directory = self.path("mocks", str(self.mock_count))
        os.makedirs(directory)
        log = os.path.join(directory, "calls.log")
        for name, status in (("pidof", pidof), ("pgrep", pgrep)):
            if status is not None:
                self.tool(directory, name, f'echo "{name} $*" >> "{log}"\nexit {status}')
        return directory, log

    def calls(self, log):
        return Path(log).read_text().splitlines() if os.path.exists(log) else []

    def test_process_running_pidof_then_pgrep(self):
        for pidof, pgrep, expected, calls in (
            (0, 0, True, ["pidof xray"]),
            (0, 1, True, ["pidof xray"]),
            (1, 0, True, ["pidof xray", "pgrep -x xray"]),
            (1, 1, False, ["pidof xray", "pgrep -x xray"]),
            (None, 0, True, ["pgrep -x xray"]),
            (1, None, False, ["pidof xray"]),
            (None, 1, False, ["pgrep -x xray"]),
            (None, None, False, []),
        ):
            with self.subTest(pidof=pidof, pgrep=pgrep):
                directory, log = self.mocks(pidof, pgrep)
                self.assertEqual(system.process_running("xray", {"PATH": directory}), expected)
                self.assertEqual(self.calls(log), calls)

    def test_process_running_treats_a_pidof_that_hangs_as_a_failure(self):
        directory = self.path("mocks")
        self.tool(directory, "pidof", "exec sleep 30")
        self.tool(directory, "pgrep", "exit 0")
        started = time.monotonic()
        with mock.patch.object(system, "KILL_GRACE", 0.3):
            self.assertTrue(system.process_running("xray", self.env(directory), timeout=0.3))
        self.assertLess(time.monotonic() - started, 5)

    def test_process_running_matches_the_script_function(self):
        for label, shell in SHELLS:
            for pidof in (None, 0, 1):
                for pgrep in (None, 0, 1):
                    with self.subTest(shell=label, pidof=pidof, pgrep=pgrep):
                        directory, _ = self.mocks(pidof, pgrep)
                        env = {"PATH": directory + ":/nonexistent"}
                        result = engine_shell.run_function(
                            "process_running", "xray", defs=["have", "set -eu"], env=env, shell=shell
                        )
                        self.assertEqual(system.process_running("xray", env), result.returncode == 0, result)

    def test_the_default_timeouts_come_from_config_and_follow_its_scale(self):
        seen = []
        with mock.patch.object(
            system, "run", lambda argv, environ, timeout, **kwargs: seen.append(timeout) or system.Completed(1, "")
        ):
            env = {
                "PATH": os.path.dirname(self.tool(self.path("m"), "pidof", "exit 1")),
                "KDN_ENGINE_TIMEOUT_SCALE": "3",
            }
            system.process_running("xray", env)
            system.package_version("jq", env)
            system.package_present("jq", env, timeout=7)
        self.assertEqual(seen, [config.timeout("process", env), config.timeout("opkg", env), 7])
        self.assertEqual(seen[:2], [15, 60])


OPKG_OUTPUTS = {
    "installed": "Package: x\nVersion: 1.2-3\nStatus: install user installed\nArchitecture: mipsel\n",
    "status before version": "Package: x\nStatus: install ok installed\nVersion: 2.0\n",
    "not installed": "Package: x\nVersion: 1.2\nStatus: install ok not-installed\n",
    "deinstall": "Package: x\nVersion: 1.2\nStatus: deinstall ok config-files\n",
    "no version": "Package: x\nStatus: install user installed\n",
    "last version wins": "Version: 1\nVersion: 2\nStatus: install ok installed\n",
    "extra fields": "Version: 1.0 extra words\nStatus: install ok installed\n",
    "empty version": "Version:\nStatus: install ok installed\n",
    "no space after the colon": "Version:1.0\nStatus: install ok installed\n",
    "leading space": " Version: 1.0\nStatus: install ok installed\n",
    "status without a space": "Version: 1.0\nStatus:installed\n",
    "status installed only": "Version: 1.0\nStatus: installed\n",
    "not installed with a space": "Version: 1.0\nStatus: not installed\n",
    "status text before installed": "Version: 1.0\nStatus:x installed y\n",
    "lower case status": "Version: 1.0\nstatus: install ok installed\n",
    "empty": "",
    "no final newline": "Version: 1.0\nStatus: install ok installed",
    "crlf": "Version: 1.0\r\nStatus: install ok installed\r\n",
    "lone cr": "Version: 1.0\rStatus: install ok installed\n",
    "tab": "Version:\t1.0\nStatus: install ok installed\n",
    "vertical tab and form feed": "Version:\x0b1.0\x0c2\nStatus: install ok installed\n",
    "nbsp": "Version: \u00a01.0\nStatus: install ok installed\n",
    "nbsp separator": "Version:\u00a01.0\nStatus: install ok installed\n",
    "invalid utf-8": "Version: 1.\udcff0\nStatus: install ok installed\n",
    "version in the middle": "Package: x\nDescription: Version: 9\nVersion: 1.0\nStatus: install ok installed\n",
    "version prefix": "Versions: 5\nStatus: install ok installed\n",
    "blank lines": "\n\nVersion: 3\n\nStatus: install ok installed\n\n",
}


class PackageTests(TempDirTestCase):
    def opkg(self, output=None, name="opkg", exit_status=0):
        directory = self.path("opkg-bin")
        fixture = self.path("opkg.out")
        self.write(fixture, "" if output is None else output)
        self.tool(directory, name, f'echo "$*" >> "{self.path("opkg.calls")}"\ncat "{fixture}"\nexit {exit_status}')
        return directory

    def test_package_version_parses_opkg_status(self):
        for label in (
            "installed",
            "status before version",
            "not installed",
            "deinstall",
            "no version",
            "last version wins",
        ):
            with self.subTest(case=label):
                directory = self.opkg(OPKG_OUTPUTS[label])
                expected = {"installed": "1.2-3", "status before version": "2.0", "last version wins": "2"}.get(
                    label, ""
                )
                self.assertEqual(system.package_version("nfqws2-keenetic", self.env(directory)), expected)
                self.assertEqual(system.package_present("nfqws2-keenetic", self.env(directory)), expected != "")
        self.assertIn("status nfqws2-keenetic", Path(self.path("opkg.calls")).read_text().splitlines())

    def test_package_version_follows_the_router_awk_by_default(self):
        # busybox awk splits fields on every isspace character (R9): a CR or a VT ends the version.
        for text, expected in (
            ("Version: 1.0\r\nStatus: install ok installed\r\n", "1.0"),
            ("Version:\x0b1.0\x0c2\nStatus: install ok installed\n", "1.0"),
            ("Version:\u00a01.0\nStatus: install ok installed\n", ""),
        ):
            with self.subTest(text=text):
                self.assertEqual(system.package_version("pkg", self.env(self.opkg(text))), expected)

    def test_a_missing_opkg_is_no_package(self):
        env = {"PATH": self.path("nothing")}
        self.assertEqual(system.package_version("jq", env), "")
        self.assertFalse(system.package_present("jq", env))

    def test_a_failing_opkg_is_read_as_it_printed(self):
        directory = self.opkg("Version: 1\nStatus: install ok installed\n", exit_status=1)
        self.assertEqual(system.package_version("jq", self.env(directory)), "1")

    def test_opkg_stderr_is_not_read(self):
        directory = self.path("bin")
        self.tool(directory, "opkg", 'echo "Version: 9" >&2; echo "Status: install ok installed" >&2')
        self.assertEqual(system.package_version("jq", self.env(directory)), "")

    def test_a_timed_out_opkg_is_no_package(self):
        directory = self.path("bin")
        self.tool(directory, "opkg", "echo 'Version: 1'; echo 'Status: install ok installed'; exec sleep 30")
        with mock.patch.object(system, "KILL_GRACE", 0.3):
            self.assertEqual(system.package_version("jq", self.env(directory), timeout=0.4), "")

    def differential(self, awk, separators):
        for label, text in OPKG_OUTPUTS.items():
            directory = self.opkg(text)
            env = {"PATH": directory + ":" + BASE_PATH}
            with self.subTest(awk=awk, case=label):
                result = engine_shell.run_function(
                    "package_version", "pkg", defs=["set -eu"], env=env, awk=awk, shell=SHELLS[0][1]
                )
                with mock.patch.object(confvalues, "AWK_FIELD_SEPARATORS", separators):
                    self.assertEqual(system.package_version("pkg", env), result.stdout.rstrip("\n"), result)
                    self.assertEqual(system.package_present("pkg", env), result.stdout.rstrip("\n") != "")
                self.assertEqual(result.returncode, 0)

    def test_package_version_matches_the_script_function_under_the_system_awk(self):
        self.differential("system", MAWK_SEPARATORS)

    @unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
    def test_package_version_matches_the_script_function_under_busybox_awk(self):
        self.differential("busybox", BUSYBOX_SEPARATORS)

    def test_package_version_matches_the_script_function_without_opkg(self):
        env = self.env(self.path("none"))
        result = engine_shell.run_function("package_version", "pkg", defs=["set -eu"], env=env, shell=SHELLS[0][1])
        self.assertEqual((result.stdout, result.returncode), ("", 0))
        self.assertEqual(system.package_version("pkg", env), "")


class FindXrayTests(TempDirTestCase):
    def paths(self, default):
        return types.SimpleNamespace(xray_default_bin=default)

    def test_find_xray_prefers_path_over_the_default(self):
        on_path = self.tool(self.path("bin"), "xray", "exit 0")
        default = self.tool(self.path("opt", "sbin"), "xray", "exit 0")
        found = system.find_xray(self.paths(default), {"PATH": self.path("bin")})
        self.assertEqual(found, Path(on_path))
        self.assertIsInstance(found, Path)

    def test_find_xray_falls_back_to_the_default_location(self):
        default = self.tool(self.path("opt", "sbin"), "xray", "exit 0")
        self.assertEqual(system.find_xray(self.paths(default), {"PATH": self.path("bin")}), Path(default))
        self.assertEqual(system.find_xray(self.paths(default), {"PATH": ""}), Path(default))

    def test_find_xray_is_none_when_nothing_is_executable(self):
        plain = self.write(self.path("opt", "sbin", "xray"), "#!/bin/sh\n", 0o644)
        self.write(self.path("bin", "xray"), "#!/bin/sh\n", 0o644)
        self.assertIsNone(system.find_xray(self.paths(plain), {"PATH": self.path("bin")}))
        self.assertIsNone(system.find_xray(self.paths(self.path("absent", "xray")), {"PATH": self.path("bin")}))

    def test_a_non_executable_xray_on_path_is_skipped_for_a_later_one(self):
        self.write(self.path("one", "xray"), "#!/bin/sh\n", 0o644)
        later = self.tool(self.path("two"), "xray", "exit 0")
        self.assertEqual(
            system.find_xray(self.paths(self.path("absent")), {"PATH": f"{self.path('one')}:{self.path('two')}"}),
            Path(later),
        )

    def test_a_non_executable_default_is_not_used_when_path_has_none(self):
        # The script tests [ -x ] of the one it picked: a hit on PATH is never replaced by the default.
        plain_default = self.write(self.path("opt", "sbin", "xray"), "#!/bin/sh\n", 0o644)
        self.assertIsNone(system.find_xray(self.paths(plain_default), {"PATH": self.path("none")}))

    def test_find_xray_matches_the_lookup_in_xray_test_config(self):
        lines = engine_shell.extract_function("xray_test_config").splitlines()
        lookup = lines[1:4]
        self.assertTrue(lookup[0].lstrip().startswith('xray_test_bin="$(command -v xray'), lookup)
        self.assertTrue(lookup[1].lstrip().startswith('[ -n "$xray_test_bin" ]'), lookup)
        self.assertTrue(lookup[2].lstrip().startswith('[ -x "$xray_test_bin" ]'), lookup)
        script = "\n".join(
            [
                lookup[0],
                lookup[1].replace('"$(root_path /opt/sbin/xray)"', '"$DEFAULT_XRAY"'),
                'if [ -x "$xray_test_bin" ]; then echo "$xray_test_bin"; else echo none; fi',
            ]
        )
        self.assertIn("DEFAULT_XRAY", script)
        on_path_dir, other_dir = self.path("bin"), self.path("other")
        self.tool(on_path_dir, "xray", "exit 0")
        default = self.tool(self.path("opt", "sbin"), "xray", "exit 0")
        plain_dir = self.path("plain")
        self.write(os.path.join(plain_dir, "xray"), "#!/bin/sh\n", 0o644)
        plain_default = self.write(self.path("opt", "plain", "xray"), "#!/bin/sh\n", 0o644)
        cases = [
            (on_path_dir, default),
            (other_dir, default),
            (plain_dir, default),
            (f"{plain_dir}:{on_path_dir}", default),
            (other_dir, plain_default),
            (other_dir, self.path("absent")),
        ]
        label, shell = SHELLS[0]
        for path_value, default_value in cases:
            with self.subTest(path=path_value, default=default_value):
                env = {"PATH": path_value, "DEFAULT_XRAY": default_value}
                shell_result = engine_shell.run_sh("set -eu\n" + script, env=env, shell=shell).stdout.strip()
                found = system.find_xray(self.paths(default_value), env)
                self.assertEqual("none" if found is None else str(found), shell_result)


class IsRouterTests(TempDirTestCase):
    def test_is_router(self):
        ndmc = self.tool(self.path("bin"), "ndmc", "exit 0")
        plain = self.write(self.path("bin", "plain-ndmc"), "x", 0o644)
        etc = self.path("opt", "etc")
        os.makedirs(etc)
        paths = types.SimpleNamespace()
        for ndmc_path, etc_path, test_root, expected in (
            (ndmc, etc, "", True),
            (ndmc, etc, None, True),
            (plain, etc, "", False),
            (self.path("absent"), etc, "", False),
            (ndmc, self.path("absent"), "", False),
            (ndmc, ndmc, "", False),
            (self.path("absent"), self.path("absent"), "/some/root", True),
            (plain, self.path("absent"), "/some/root", True),
        ):
            with (
                self.subTest(ndmc=ndmc_path, etc=etc_path, test_root=test_root),
                mock.patch.object(system, "NDMC", ndmc_path),
                mock.patch.object(system, "OPT_ETC", etc_path),
            ):
                self.assertIs(system.is_router(paths, test_root), expected)

    def test_is_router_matches_the_script_function(self):
        text = engine_shell.extract_function("is_router")
        self.assertEqual((text.count("/bin/ndmc"), text.count("/opt/etc")), (1, 1))
        fake = text.replace("/bin/ndmc", "$FAKE_NDMC").replace("/opt/etc", "$FAKE_ETC")
        ndmc = self.tool(self.path("bin"), "ndmc", "exit 0")
        plain = self.write(self.path("bin", "plain-ndmc"), "x", 0o644)
        etc = self.path("opt", "etc")
        os.makedirs(etc)
        for ndmc_path, etc_path, test_root in (
            (ndmc, etc, ""),
            (plain, etc, ""),
            (self.path("bin"), etc, ""),
            (ndmc, self.path("absent"), ""),
            (ndmc, ndmc, ""),
            (self.path("absent"), etc, ""),
            (self.path("absent"), self.path("absent"), "/some/root"),
        ):
            for label, shell in SHELLS:
                with self.subTest(shell=label, ndmc=ndmc_path, etc=etc_path, test_root=test_root):
                    result = engine_shell.run_function(
                        "is_router",
                        defs=[fake],
                        variables={"TEST_ROOT": test_root, "FAKE_NDMC": ndmc_path, "FAKE_ETC": etc_path},
                        shell=shell,
                    )
                    with (
                        mock.patch.object(system, "NDMC", ndmc_path),
                        mock.patch.object(system, "OPT_ETC", etc_path),
                    ):
                        self.assertEqual(system.is_router(types.SimpleNamespace(), test_root), result.returncode == 0)


# (label, /proc/<pid>/cmdline bytes) for a live pid; the expected qnum of nfqws2.conf is varied by the tests.
CMDLINES = [
    ("service", b"nfqws2\0--qnum=300\0"),
    ("full path", b"/opt/usr/bin/nfqws2\0--user=nobody\0--qnum=300\0--filter-tcp=443\0"),
    ("other queue", b"nfqws2\0--qnum=301\0"),
    ("first qnum wins", b"nfqws2\0--qnum=999\0--qnum=300\0"),
    ("empty first qnum", b"nfqws2\0--qnum=\0--qnum=999\0"),
    ("no qnum", b"nfqws2\0--filter-tcp=443\0"),
    ("qnum as a substring", b"nfqws2\0x--qnum=999\0"),
    ("qnum inside an argument with a space", b"nfqws2\0a --qnum=999\0"),
    ("qnum after a newline", b"nfqws2\0x\n--qnum=301\0"),
    ("dry run", b"nfqws2\0--dry-run\0--qnum=300\0"),
    ("dry run last", b"nfqws2\0--qnum=300\0--dry-run\0"),
    ("dry run first", b"--dry-run\0nfqws2\0"),
    ("dry run is a prefix", b"nfqws2\0--dry-run=1\0"),
    ("dry run is a suffix", b"nfqws2\0--no--dry-run\0"),
    ("dry run inside one argument", b"nfqws2\0x --dry-run y\0"),
    ("dry run then a newline", b"nfqws2\0--dry-run\n"),
    ("dry run with a newline inside", b"nfqws2\0--dry-run\nx\0"),
    ("intercept off", b"nfqws2\0--intercept=0\0"),
    ("intercept on", b"nfqws2\0--intercept=1\0"),
    ("intercept 01", b"nfqws2\0--intercept=01\0"),
    ("intercept off inside one argument", b"nfqws2\0a --intercept=0 b\0"),
    ("other program", b"sleep\0--qnum=300\0"),
    ("zombie", b""),
    ("only separators", b"\0\0"),
    ("upper case", b"NFQWS2\0"),
    ("name inside a word", b"xnfqws2y\0--qnum=300\0"),
    ("name in the last argument", b"sh\0-c\0nfqws2\0"),
    ("no final separator", b"nfqws2\0--qnum=300"),
    ("setproctitle style", b"nfqws2: worker --qnum=300"),
    ("invalid utf-8", b"nfqws2\0\xff\xfe\0--qnum=300\0"),
    ("tab separated", b"nfqws2\t--dry-run\0"),
    ("trailing newlines", b"nfqws2\0--qnum=300\n\n"),
    ("qnum with a trailing cr", b"nfqws2\0--qnum=300\r\0"),
    ("glob characters", b"nfqws2\0*\0?\0[a-z]\0--qnum=300\0"),
]


class PidTestCase(TempDirTestCase):
    """A live pid, a dead pid, a fake /proc tree and a pidfile of a fixture root."""

    def setUp(self):
        super().setUp()
        self.proc = self.path("proc")
        os.makedirs(self.proc)
        self.enterContext(mock.patch.object(system, "PROC_ROOT", self.proc))
        self.live = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL)
        self.addCleanup(self.live.wait)
        self.addCleanup(self.live.kill)
        done = subprocess.Popen(["true"])
        done.wait()
        self.dead = done.pid
        self.pidfile = self.path("run", "nfqws2.pid")
        self.paths = types.SimpleNamespace(nfqws_pidfile=self.pidfile)

    def fake_proc(self, pid, cmdline):
        entry = os.path.join(self.proc, str(pid))
        os.makedirs(entry, exist_ok=True)
        if cmdline is not None:
            self.write(os.path.join(entry, "cmdline"), cmdline)

    def write_pidfile(self, data):
        self.write(self.pidfile, data)

    def service_pid(self, expected=None, test_root="/fixture", environ=None, **kwargs):
        reader = None if expected is None else (lambda key: expected if key == "NFQUEUE_NUM" else "?")
        return system.nfqws_service_pid(self.paths, environ or self.env(), test_root, reader, **kwargs)


class NfqwsServiceUnitTests(PidTestCase):
    def test_nfqws_service_pid_cases(self):
        live = self.live.pid
        self.fake_proc(live, b"nfqws2\0--qnum=300\0")
        self.write_pidfile(f"{live}\n")
        self.assertEqual(self.service_pid(), live)
        self.assertEqual(self.service_pid("300"), live)
        self.assertTrue(system.nfqws_running(self.paths, self.env(), "/fixture", None))

        self.fake_proc(live, b"sleep\0--qnum=300\0")
        self.assertIsNone(self.service_pid())
        self.assertFalse(system.nfqws_running(self.paths, self.env(), "/fixture", None))

        self.fake_proc(live, b"nfqws2\0--dry-run\0--qnum=300\0")
        self.assertIsNone(self.service_pid())
        self.fake_proc(live, b"nfqws2\0--dry-run=1\0")
        self.assertEqual(self.service_pid(), live)
        self.fake_proc(live, b"nfqws2\0--no--dry-run\0")
        self.assertEqual(self.service_pid(), live)
        self.fake_proc(live, b"nfqws2\0--intercept=0\0")
        self.assertIsNone(self.service_pid())

    def test_another_qnum_is_a_test_instance_unless_nfqws_conf_says_so(self):
        live = self.live.pid
        self.fake_proc(live, b"nfqws2\0--qnum=301\0")
        self.write_pidfile(str(live))
        self.assertIsNone(self.service_pid())
        self.assertIsNone(self.service_pid("300"))
        self.assertEqual(self.service_pid("301"), live)
        self.assertIsNone(self.service_pid(""), "an empty NFQUEUE_NUM falls back to 300")
        self.fake_proc(live, b"nfqws2\0--qnum=300\0")
        self.assertEqual(self.service_pid(""), live)
        self.assertEqual(self.service_pid(None), live)

    def test_a_missing_proc_entry_counts_as_a_service(self):
        live = self.live.pid
        self.write_pidfile(str(live))
        self.assertEqual(self.service_pid(), live)
        self.fake_proc(live, None)
        self.assertIsNone(self.service_pid(), "a /proc entry without a readable cmdline is not nfqws2")

    def test_an_unreadable_pidfile_is_not_a_service(self):
        self.write_pidfile(str(self.live.pid))
        with mock.patch("builtins.open", side_effect=PermissionError):
            self.assertIsNone(self.service_pid())

    def test_a_dead_pid_or_a_missing_pidfile_is_not_a_service(self):
        self.assertIsNone(self.service_pid())
        self.write_pidfile(str(self.dead))
        self.assertIsNone(self.service_pid())
        os.unlink(self.pidfile)
        os.makedirs(self.pidfile)
        self.assertIsNone(self.service_pid(), "a directory is not a pidfile")

    def test_kill_zero_that_is_refused_is_not_a_service(self):
        live = self.live.pid
        self.write_pidfile(str(live))
        self.assertEqual(self.service_pid(), live)
        for error in (PermissionError(1, "denied"), ProcessLookupError(3, "gone"), OverflowError("big")):
            with self.subTest(error=type(error).__name__), mock.patch.object(os, "kill", side_effect=error) as kill:
                self.assertIsNone(self.service_pid())
                kill.assert_called_once_with(live, 0)

    def test_the_pid_is_only_digits_of_the_first_line(self):
        live = self.live.pid
        for data, expected in (
            (f"{live}", live),
            (f"{live}\n", live),
            (f"{live}\n{self.dead}\n", live),
            (f"{live}\r\n", None),
            (f" {live}", None),
            (f"{live} ", None),
            (f"+{live}", None),
            (f"-{live}", None),
            (f"{live}x", None),
            ("", None),
            ("\n", None),
            (f"\n{live}\n", None),
            ("abc", None),
            ("\u0663", None),
            ("\u00b2", None),
            (arabic_digits(live), None),
            (f"{live}\0".encode(), live),
            (f"{live}\0\n".encode(), live),
        ):
            with self.subTest(data=data):
                self.write_pidfile(data)
                self.assertEqual(self.service_pid(), expected)

    def test_pid_zero_and_leading_zeros_follow_the_shell(self):
        live = self.live.pid
        self.write_pidfile("0")
        self.assertEqual(self.service_pid(), 0, "kill -0 0 succeeds and /proc/0 does not exist")
        self.assertTrue(system.nfqws_running(self.paths, self.env(), "/fixture", None), "pid 0 is still a service")
        self.fake_proc(live, b"sleep\0")
        self.write_pidfile(f"00{live}")
        self.assertEqual(self.service_pid(), live, "/proc/00<pid> does not exist, so nothing contradicts the pidfile")
        self.write_pidfile(str(live))
        self.assertIsNone(self.service_pid(), "the cmdline of /proc/<pid> is not nfqws2")

    def test_huge_digit_strings_are_not_a_service(self):
        for digits in ("9" * 20, "2147483648", "4294967297", "4294967296", "18446744073709551617", HUGE):
            with self.subTest(digits=digits[:30]):
                self.write_pidfile(digits)
                self.assertIsNone(self.service_pid())

    def test_pidof_is_not_used_in_a_fixture_root(self):
        directory = self.path("mocks")
        log = self.path("pidof.log")
        self.tool(directory, "pidof", f'echo "$*" >> "{log}"\necho {self.live.pid}')
        self.fake_proc(self.live.pid, b"nfqws2\0--qnum=300\0")
        self.assertIsNone(self.service_pid(test_root="/fixture", environ=self.env(directory)))
        self.assertFalse(os.path.exists(log))
        self.write_pidfile(str(self.live.pid))
        self.assertEqual(self.service_pid(test_root="/fixture", environ=self.env(directory)), self.live.pid)
        self.assertFalse(os.path.exists(log))

    def test_pidof_is_the_fallback_outside_a_fixture_root(self):
        directory = self.path("mocks")
        log = self.path("pidof.log")
        live = self.live.pid
        other = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL)
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        self.fake_proc(live, b"nfqws2\0--qnum=300\0")
        self.fake_proc(other.pid, b"nfqws2\0--dry-run\0")
        listing = f"{HUGE}\t{self.dead}\t{other.pid}\n{live} {self.dead}\n"
        self.tool(directory, "pidof", f'echo "$*" >> "{log}"\nprintf "%s" "{listing}"\nexit 0')
        environ = self.env(directory)
        self.assertEqual(self.service_pid(test_root="", environ=environ), live, "the first pid that is a service")
        self.assertEqual(Path(log).read_text(), "nfqws2\n")
        # A good pidfile wins and pidof is not asked.
        os.unlink(log)
        self.write_pidfile(str(live))
        self.assertEqual(self.service_pid(test_root="", environ=environ), live)
        self.assertFalse(os.path.exists(log))
        # A pidfile that is not a service falls through to pidof.
        self.write_pidfile(str(other.pid))
        self.assertEqual(self.service_pid(test_root=None, environ=environ), live)
        self.assertEqual(Path(log).read_text(), "nfqws2\n")

    def test_nothing_is_found_without_pidof_or_with_a_pidof_that_fails(self):
        self.assertIsNone(self.service_pid(test_root="", environ={"PATH": self.path("none")}))
        directory = self.path("mocks")
        self.tool(directory, "pidof", "exit 1")
        self.assertIsNone(self.service_pid(test_root="", environ=self.env(directory)))
        # A pidof that hangs after it printed a service pid is not believed.
        self.write_pidfile("")
        self.fake_proc(self.live.pid, b"nfqws2\0--qnum=300\0")
        self.tool(directory, "pidof", f"echo {self.live.pid}; exec sleep 30")
        with mock.patch.object(system, "KILL_GRACE", 0.3):
            self.assertIsNone(self.service_pid(test_root="", environ=self.env(directory), timeout=0.3))

    def test_the_expected_qnum_is_read_from_nfqws_conf_only_when_needed(self):
        live = self.live.pid
        self.write_pidfile(str(live))
        asked = []

        def reader(key):
            asked.append(key)
            return "300"

        for cmdline, expected_calls in (
            (b"sleep\0", []),
            (b"nfqws2\0--dry-run\0", []),
            (b"nfqws2\0--qnum=300\0", ["NFQUEUE_NUM"]),
            (b"nfqws2\0", ["NFQUEUE_NUM"]),
        ):
            asked.clear()
            self.fake_proc(live, cmdline)
            system.nfqws_service_pid(self.paths, self.env(), "/fixture", reader)
            self.assertEqual(asked, expected_calls, cmdline)


@unittest.skipUnless(HAS_PROC, "needs a real /proc")
class NfqwsServiceRealProcTests(TempDirTestCase):
    """The real /proc of Linux: the cmdline of a live process, a zombie and a recycled pid."""

    def start(self, *arguments):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", *arguments], stdin=subprocess.DEVNULL
        )
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        expected = b'\0' + b'\0'.join(os.fsencode(value) for value in arguments) + b'\0'

        def ready():
            try:
                return process.poll() is None and expected in Path(f'/proc/{process.pid}/cmdline').read_bytes()
            except OSError:
                return False

        self.assertTrue(wait_until(ready), f'child cmdline not ready, rc={process.poll()}')
        return process

    def lookup(self, process):
        pidfile = self.write(self.path("nfqws2.pid"), f"{process.pid}\n")
        paths = types.SimpleNamespace(nfqws_pidfile=pidfile)
        return system.nfqws_service_pid(paths, {"PATH": BASE_PATH}, "/fixture", lambda key: "300")

    def test_a_live_nfqws2_is_the_service(self):
        # The interpreter is started with the arguments of nfqws2 after "-c <code>": they land in the cmdline.
        process = self.start("nfqws2", "--qnum=300")
        self.assertIn(b"\0nfqws2\0--qnum=300\0", Path(f"/proc/{process.pid}/cmdline").read_bytes())
        self.assertEqual(self.lookup(process), process.pid)

    def test_test_instances_and_strangers_are_not_the_service(self):
        for arguments in (("nfqws2", "--dry-run"), ("nfqws2", "--qnum=301"), ("nfqws2", "--intercept=0"), ("other",)):
            with self.subTest(arguments=arguments):
                self.assertIsNone(self.lookup(self.start(*arguments)))

    def test_a_zombie_is_not_the_service(self):
        process = subprocess.Popen(["true"])
        self.addCleanup(process.wait)
        self.assertTrue(wait_until(lambda: is_dead(process.pid) and os.path.exists(f"/proc/{process.pid}")))
        self.assertEqual(Path(f"/proc/{process.pid}/cmdline").read_bytes(), b"")
        self.assertIsNone(self.lookup(process))


class NfqwsServiceDifferentialTests(PidTestCase):
    """The port against nfqws_service_pid / nfqws_pid_is_service of the script, on a fake /proc."""

    def setUp(self):
        super().setUp()
        original = engine_shell.extract_function("nfqws_pid_is_service")
        self.assertEqual(original.count('"/proc/'), 2)
        self.is_service = original.replace('"/proc/', '"$PROC_ROOT/')
        self.stub = 'nfqws_value() { printf "%s\\n" "$EXPECTED_QNUM"; }'

    def shell(self, shell, test_root, expected, environ):
        result = engine_shell.run_function(
            "nfqws_service_pid",
            defs=["set -eu", "have", self.is_service, self.stub],
            variables={
                "TEST_ROOT": test_root,
                "NFQWS_PIDFILE": self.pidfile,
                "PROC_ROOT": self.proc,
                "EXPECTED_QNUM": "" if expected is None else expected,
            },
            env=environ,
            shell=shell,
        )
        return result

    def compare(self, label, shell, test_root="/fixture", expected=None, environ=None, note=""):
        environ = environ or self.env()
        result = self.shell(shell, test_root, expected, environ)
        found = self.service_pid(expected, test_root, environ)
        context = f"{label} {note}: shell rc={result.returncode} out={result.stdout!r} err={result.stderr!r}"
        if found is None:
            self.assertNotEqual(result.returncode, 0, context)
            self.assertEqual(result.stdout, "", context)
        else:
            self.assertEqual(result.returncode, 0, context)
            self.assertEqual(int(result.stdout), found, context)

    def test_cmdlines_and_expected_queues(self):
        live = self.live.pid
        self.write_pidfile(f"{live}\n")
        for label, shell in SHELLS:
            for name, cmdline in CMDLINES:
                for expected in (None, "300", "301", "999", "300\r"):
                    self.fake_proc(live, cmdline)
                    self.compare(label, shell, expected=expected, note=f"{name!r} expecting {expected!r} {cmdline!r}")

    def test_a_missing_proc_entry_and_an_unreadable_cmdline(self):
        live = self.live.pid
        self.write_pidfile(str(live))
        for label, shell in SHELLS:
            self.compare(label, shell, note="no /proc entry")
            self.fake_proc(live, None)
            self.compare(label, shell, note="a /proc entry without a cmdline")
            shutil.rmtree(os.path.join(self.proc, str(live)))

    def test_pidfile_contents(self):
        live = self.live.pid
        self.fake_proc(live, b"nfqws2\0--qnum=300\0")
        corpus = [
            f"{live}",
            f"{live}\n",
            f"{live}\n{self.dead}\n",
            f"{live}\r\n",
            f" {live}",
            f"{live} ",
            f"\t{live}",
            f"+{live}",
            f"-{live}",
            f"{live}x",
            f"0{live}",
            f"00{live}",
            f"{live}0",
            str(self.dead),
            "0",
            "00",
            "1",
            "",
            "\n",
            f"\n{live}\n",
            "abc",
            "\u0663",
            "\u00b2",
            arabic_digits(live),
            f"{live}\0".encode(),
            f"1\0{live}".encode(),
            b"\xff",
            "9" * 20,
            "2147483647",
            "2147483648",
            "4294967296",
            "4294967297",
            "4294967297" + "0" * 30,
            HUGE,
        ]
        for label, shell in SHELLS:
            for data in corpus:
                self.write_pidfile(data)
                self.compare(label, shell, note=f"pidfile {data!r:.60}")

    def test_pidfile_that_is_not_a_regular_file(self):
        for label, shell in SHELLS:
            self.compare(label, shell, note="no pidfile")
            os.makedirs(self.pidfile)
            self.compare(label, shell, note="a directory")
            os.rmdir(self.pidfile)
            os.symlink(self.path("target"), self.pidfile)
            self.compare(label, shell, note="a dangling link")
            self.write(self.path("target"), f"{self.live.pid}\n")
            self.fake_proc(self.live.pid, b"nfqws2\0")
            self.compare(label, shell, note="a link to a pidfile")
            os.unlink(self.pidfile)
            os.unlink(self.path("target"))

    def test_the_pidof_fallback(self):
        live = self.live.pid
        directory = self.path("mocks")
        self.fake_proc(live, b"nfqws2\0--qnum=300\0")
        listings = (
            f"{live}\n",
            f"{self.dead} {live}\n",
            f"{self.dead}\t{live}\n",
            f"{live} {self.dead}\n",
            f"{self.dead}\n",
            "\n",
            "",
            f"{HUGE} {live}\n",
            f"abc {live}\n",
            f"*{live}\n",
        )
        for label, shell in SHELLS:
            for listing in listings:
                for pidfile in (None, f"{self.dead}", f"{live}"):
                    if pidfile is None:
                        if os.path.exists(self.pidfile):
                            os.unlink(self.pidfile)
                    else:
                        self.write_pidfile(pidfile)
                    self.tool(directory, "pidof", f"printf '%s' '{listing}'\nexit 0")
                    self.compare(
                        label,
                        shell,
                        test_root="",
                        environ=self.env(directory),
                        note=f"pidof {listing!r} pidfile {pidfile!r}",
                    )
            os.unlink(self.path("mocks", "pidof"))
            tools = self.path("sed-and-tr")
            os.makedirs(tools, exist_ok=True)
            for name in ("sed", "tr"):
                if not os.path.lexists(os.path.join(tools, name)):
                    os.symlink(shutil.which(name), os.path.join(tools, name))
            self.compare(label, shell, test_root="", environ={"PATH": tools}, note="no pidof")
            self.compare(label, shell, test_root="/fixture", environ=self.env(directory), note="fixture root")


if __name__ == "__main__":
    unittest.main()

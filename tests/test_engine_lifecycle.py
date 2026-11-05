"""Tests of kdn.engine.lifecycle and of the entry point: children, cleanups and signals.

The signal tests run the module in a child interpreter, because a signal handler, the exit code 130 and SIGPIPE
belong to a whole process; the unit tests of the registries run in the process of pytest and leave nothing behind.
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from kdn.engine import __main__ as entry
from kdn.engine import cli, lifecycle


ROUTER_DIR = Path(lifecycle.__file__).resolve().parents[2]
CHILD_ENV = {
    **{name: value for name, value in os.environ.items() if not name.startswith("KDN_ENGINE")},
    "PYTHONPATH": str(ROUTER_DIR),
}
WATCHDOG = 40

# A child engine: one registered child that sleeps, one cleanup that removes a directory; the pid goes to stdout
# from inside the try, so that the signal the test sends on seeing it cannot land before the finally is armed.
ENGINE = """
import os, signal, subprocess, sys, time
from kdn.engine import lifecycle
for name in ("SIGTERM", "SIGHUP", "SIGINT"):
    signal.signal(getattr(signal, name), signal.SIG_DFL)
lifecycle.install_signal_handlers()
workdir = sys.argv[1]
lifecycle.add_cleanup(lambda: os.rmdir(workdir))
child = subprocess.Popen(["sleep", "60"])
lifecycle.register_child(child)
try:
    print(child.pid, flush=True)
    time.sleep(30)
finally:
    lifecycle.run_cleanups()
"""

# A child engine started with HUP and INT ignored by its parent (nohup, a background job): reports which
# of TERM, HUP and INT are ignored after the install, then waits for a signal.
ENGINE_INHERITING = """
import signal, time
from kdn.engine import lifecycle
lifecycle.install_signal_handlers()
names = ("SIGTERM", "SIGHUP", "SIGINT")
print([signal.getsignal(getattr(signal, name)) == signal.SIG_IGN for name in names], flush=True)
time.sleep(30)
"""
# POSIX sh ignores a signal for the process that it execs: this is how nohup and "cmd &" start a program.
IGNORING_LAUNCH = ["sh", "-c", 'trap "" HUP INT; exec "$@"', "sh"]
HAS_PROC = Path("/proc/self/status").exists()


def ignored_signals(pid):
    """Numbers of the signals the process ignores (SigIgn of /proc/<pid>/status)."""
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("SigIgn:"):
            mask = int(line.split()[1], 16)
            return {number for number in range(1, 65) if mask >> (number - 1) & 1}
    raise AssertionError("no SigIgn line")


def pid_is_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class ChildProcessCase(unittest.TestCase):
    def spawn(self, code, *args, **kwargs):
        process = subprocess.Popen(
            [sys.executable, "-P", "-c", code, *args], env=CHILD_ENV, stdout=subprocess.PIPE, **kwargs
        )
        watchdog = threading.Timer(WATCHDOG, process.kill)
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.addCleanup(process.stdout.close)
        return process

    def kill_later(self, pid):
        def kill():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        self.addCleanup(kill)


class SignalTests(ChildProcessCase):
    def run_engine(self, signum):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "work"
            workdir.mkdir()
            process = self.spawn(ENGINE, str(workdir))
            line = process.stdout.readline()
            self.assertTrue(line.strip().isdigit(), line)
            grandchild = int(line)
            self.kill_later(grandchild)
            self.assertFalse(pid_is_gone(grandchild))
            process.send_signal(signum)
            self.assertEqual(process.wait(timeout=20), 130)
            return grandchild, workdir.exists()

    def test_sigterm_kills_registered_children_runs_cleanups_and_exits_130(self):
        grandchild, workdir_left = self.run_engine(signal.SIGTERM)
        self.assertTrue(pid_is_gone(grandchild), "the registered child outlived the engine")
        self.assertFalse(workdir_left, "the cleanup did not run")

    def test_sighup_and_sigint_do_the_same(self):
        for signum in (signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=signal.Signals(signum).name):
                grandchild, workdir_left = self.run_engine(signum)
                self.assertTrue(pid_is_gone(grandchild), "the registered child outlived the engine")
                self.assertFalse(workdir_left, "the cleanup did not run")

    def test_sigpipe_is_the_default_action(self):
        code = (
            "import sys\n"
            "from kdn.engine import lifecycle\n"
            "lifecycle.install_signal_handlers()\n"
            "sys.stdin.readline()\n"
            "sys.stdout.write('x' * 100)\n"
            "sys.stdout.flush()\n"
            "sys.exit(0)\n"
        )
        process = self.spawn(code, stdin=subprocess.PIPE)
        process.stdout.close()
        process.stdin.write(b"go\n")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=20), -signal.SIGPIPE)

    def test_without_the_handlers_a_closed_pipe_is_an_exception(self):
        code = (
            "import os, sys\n"
            "sys.stdin.readline()\n"
            "try:\n"
            "    sys.stdout.write('x' * 100)\n"
            "    sys.stdout.flush()\n"
            "except BrokenPipeError:\n"
            "    os._exit(42)\n"
        )
        process = self.spawn(code, stdin=subprocess.PIPE)
        process.stdout.close()
        process.stdin.write(b"go\n")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=20), 42)

    def test_the_handlers_are_installed_by_the_function_only(self):
        code = (
            "import signal\n"
            "from kdn.engine import lifecycle\n"
            "for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):\n"
            "    signal.signal(s, signal.SIG_DFL)\n"
            "before = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGPIPE)]\n"
            "lifecycle.install_signal_handlers()\n"
            "after = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGPIPE)]\n"
            "changed = [a is not b for a, b in zip(before[:3], after[:3])]\n"
            "print(before[3] == signal.SIG_IGN, changed, after[3] == signal.SIG_DFL)\n"
        )
        process = self.spawn(code)
        output = process.stdout.read().decode("ascii").strip()
        self.assertEqual(process.wait(timeout=20), 0)
        self.assertEqual(output, "True [True, True, True] True")

    def spawn_ignoring(self, argv, **kwargs):
        """Start argv through a shell that ignores HUP and INT, so that the child inherits SIG_IGN for both."""
        process = subprocess.Popen(
            [*IGNORING_LAUNCH, *argv], env=kwargs.pop("env", CHILD_ENV), stdout=subprocess.PIPE, **kwargs
        )
        watchdog = threading.Timer(WATCHDOG, process.kill)
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.addCleanup(process.stdout.close)
        return process

    def test_ignored_hup_and_int_are_kept_and_a_term_still_exits_130(self):
        process = self.spawn_ignoring([sys.executable, "-P", "-c", ENGINE_INHERITING])
        self.assertEqual(process.stdout.readline().strip(), b"[False, True, True]")
        process.send_signal(signal.SIGHUP)
        process.send_signal(signal.SIGINT)
        time.sleep(0.5)
        self.assertIsNone(process.poll(), "an inherited SIG_IGN was replaced by the handler")
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=20), 130)

    @unittest.skipUnless(HAS_PROC, "needs /proc")
    def test_the_shell_engine_inherits_the_ignored_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "shell-engine.sh"
            script.write_text("echo ready\nread line\nexit 0\n", encoding="ascii")
            env = {**CHILD_ENV, "KDN_ENGINE_SCRIPT": str(script)}
            process = self.spawn_ignoring(
                [sys.executable, "-P", "-m", "kdn.engine", "--help"], env=env, stdin=subprocess.PIPE
            )
            self.addCleanup(process.stdin.close)
            self.assertEqual(process.stdout.readline(), b"ready\n")
            ignored = ignored_signals(process.pid)
            process.stdin.close()
            self.assertEqual(process.wait(timeout=20), 0)
        self.assertLessEqual({signal.SIGHUP, signal.SIGINT}, ignored)
        self.assertNotIn(signal.SIGTERM, ignored)
        self.assertNotIn(signal.SIGPIPE, ignored, "SIGPIPE must be the default action in the shell engine too")


class RegistryTests(unittest.TestCase):
    def tearDown(self):
        lifecycle.run_cleanups()

    def test_cleanups_run_in_reverse_order_and_survive_errors(self):
        calls = []

        def broken():
            calls.append(2)
            raise RuntimeError("cleanup failed")

        lifecycle.add_cleanup(lambda: calls.append(1))
        lifecycle.add_cleanup(broken)
        lifecycle.add_cleanup(lambda: calls.append(3))
        lifecycle.run_cleanups()
        self.assertEqual(calls, [3, 2, 1])
        lifecycle.run_cleanups()
        self.assertEqual(calls, [3, 2, 1], "a cleanup runs once")

    def test_a_cleanup_added_by_a_cleanup_runs_too(self):
        calls = []
        lifecycle.add_cleanup(lambda: (calls.append("outer"), lifecycle.add_cleanup(lambda: calls.append("inner"))))
        lifecycle.run_cleanups()
        self.assertEqual(calls, ["outer", "inner"])

    def sleeper(self, script="exec sleep 60"):
        process = subprocess.Popen(["sh", "-c", script], stdout=subprocess.PIPE)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        return process

    def test_terminate_children_terminates_every_registered_child(self):
        first, second = self.sleeper(), self.sleeper()
        for process in (first, second):
            lifecycle.register_child(process)
            self.addCleanup(lifecycle.unregister_child, process)
        lifecycle.terminate_children()
        self.assertEqual((first.poll(), second.poll()), (-signal.SIGTERM, -signal.SIGTERM))

    def test_terminate_children_kills_a_child_that_ignores_term(self):
        process = self.sleeper("trap '' TERM; echo ready; exec sleep 60")
        self.assertEqual(process.stdout.readline(), b"ready\n")
        lifecycle.register_child(process)
        self.addCleanup(lifecycle.unregister_child, process)
        started = time.monotonic()
        lifecycle.terminate_children(grace=0.3)
        self.assertEqual(process.poll(), -signal.SIGKILL)
        self.assertLess(time.monotonic() - started, 10)

    def test_terminate_children_waits_for_a_child_that_exits_within_the_grace(self):
        process = self.sleeper("trap 'exit 3' TERM; echo ready; while :; do sleep 0.05; done")
        self.assertEqual(process.stdout.readline(), b"ready\n")
        lifecycle.register_child(process)
        self.addCleanup(lifecycle.unregister_child, process)
        lifecycle.terminate_children(grace=5)
        self.assertEqual(process.poll(), 3)

    def test_unregistered_children_are_left_alone(self):
        kept, released = self.sleeper(), self.sleeper()
        lifecycle.register_child(kept)
        lifecycle.register_child(released)
        lifecycle.unregister_child(released)
        self.addCleanup(lifecycle.unregister_child, kept)
        lifecycle.terminate_children()
        self.assertEqual(kept.poll(), -signal.SIGTERM)
        self.assertIsNone(released.poll())
        lifecycle.unregister_child(released)

    def test_terminate_children_ignores_children_that_already_exited(self):
        process = subprocess.Popen(["true"])
        process.wait()
        lifecycle.register_child(process)
        self.addCleanup(lifecycle.unregister_child, process)
        lifecycle.terminate_children(grace=0.1)
        self.assertEqual(process.returncode, 0)
        lifecycle.terminate_children(grace=0.1)

    def test_terminate_children_without_children_returns_at_once(self):
        started = time.monotonic()
        lifecycle.terminate_children()
        self.assertLess(time.monotonic() - started, 1)


class EntryPointTests(unittest.TestCase):
    def tearDown(self):
        lifecycle.run_cleanups()

    def test_main_installs_the_handlers_runs_the_mode_then_the_cleanups(self):
        order = []
        lifecycle.add_cleanup(lambda: order.append("cleanup"))
        with (
            mock.patch.object(lifecycle, "install_signal_handlers", lambda: order.append("handlers")),
            mock.patch.object(cli, "main", lambda: order.append("mode") or 3),
        ):
            with self.assertRaises(SystemExit) as raised:
                entry.main()
        self.assertEqual(raised.exception.code, 3)
        self.assertEqual(order, ["handlers", "mode", "cleanup"])

    def test_main_runs_the_cleanups_when_the_mode_fails_or_the_process_is_told_to_exit(self):
        for error in (RuntimeError("bug"), SystemExit(130)):
            with self.subTest(error=repr(error)):
                calls = []
                lifecycle.add_cleanup(lambda calls=calls: calls.append("cleanup"))
                with (
                    mock.patch.object(lifecycle, "install_signal_handlers"),
                    mock.patch.object(cli, "main", side_effect=error),
                ):
                    with self.assertRaises(type(error)):
                        entry.main()
                self.assertEqual(calls, ["cleanup"])

    def test_importing_the_entry_point_runs_nothing(self):
        code = (
            "import signal\n"
            "before = signal.getsignal(signal.SIGTERM)\n"
            "from kdn.engine import __main__\n"
            "print(signal.getsignal(signal.SIGTERM) is before)\n"
        )
        result = subprocess.run(
            [sys.executable, "-P", "-c", code], env=CHILD_ENV, capture_output=True, text=True, check=False, timeout=60
        )
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "True"), result.stderr)


if __name__ == "__main__":
    unittest.main()

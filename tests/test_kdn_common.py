"""Unit tests of kdn.common: the code the panel and the router tools share.

The modules are imported directly and patched only with mock.patch.object on
the module object. Every file operation stays inside a TemporaryDirectory;
no test touches /opt or the network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from kdn.common import fsutil, jsonc, paths, proc, timeutil


ALLOWED = {"KD_ALLOW_TEST_ROOT": "1"}


class PathsTests(unittest.TestCase):
    def test_root_path_without_test_root(self):
        self.assertEqual(paths.root_path("/opt/x", environ={}), Path("/opt/x"))

    def test_root_path_under_allowed_test_root(self):
        environ = {"KD_TEST_ROOT": "/t/r", **ALLOWED}
        self.assertEqual(paths.root_path("/opt/x", environ=environ), Path("/t/r/opt/x"))
        self.assertEqual(paths.test_root(environ), "/t/r")

    def test_empty_test_root_is_no_test_root(self):
        self.assertEqual(paths.test_root({"KD_TEST_ROOT": ""}), "")
        self.assertEqual(paths.root_path("/opt/x", environ={"KD_TEST_ROOT": ""}), Path("/opt/x"))

    def test_test_root_requires_permission(self):
        environments = [{"KD_TEST_ROOT": "/t/r"}]
        # Only the exact value "1" grants permission, like the engine's [ "$KD_ALLOW_TEST_ROOT" != "1" ].
        for value in ("0", "", "true", "2", "yes", " 1"):
            environments.append({"KD_TEST_ROOT": "/t/r", "KD_ALLOW_TEST_ROOT": value})
        for environ in environments:
            with self.subTest(environ=environ):
                with self.assertRaises(RuntimeError) as caught:
                    paths.test_root(environ)
                self.assertEqual(str(caught.exception), "KD_TEST_ROOT is reserved for isolated repository tests.")
                with self.assertRaisesRegex(RuntimeError, "reserved for isolated repository tests"):
                    paths.root_path("/opt/x", environ=environ)

    def test_test_root_reads_process_environment_by_default(self):
        with mock.patch.dict(os.environ, {"KD_TEST_ROOT": "/t/env", **ALLOWED}):
            self.assertEqual(paths.root_path("/opt/x"), Path("/t/env/opt/x"))
        with mock.patch.dict(os.environ, {"KD_TEST_ROOT": "/t/env"}):
            os.environ.pop("KD_ALLOW_TEST_ROOT", None)
            with self.assertRaises(RuntimeError):
                paths.test_root()

    def test_root_path_needs_absolute_logical_path(self):
        for logical in ("opt/x", "", "./opt/x"):
            with self.subTest(logical=logical):
                with self.assertRaises(ValueError):
                    paths.root_path(logical, environ={})

    def test_project_dir_env_and_default(self):
        self.assertEqual(paths.project_dir({"XKEEN_PROJECT_DIR": "rel/project"}), Path("rel/project"))
        self.assertEqual(paths.project_dir({}), paths.root_path(paths.DEFAULT_PROJECT_DIR, environ={}))
        self.assertEqual(paths.project_dir({}), Path("/opt/root/keenetic-discord-nfqws2"))
        environ = {"KD_TEST_ROOT": "/t/r", **ALLOWED}
        self.assertEqual(paths.project_dir(environ), Path("/t/r/opt/root/keenetic-discord-nfqws2"))
        # A configured directory is used as is, the test root does not move it.
        self.assertEqual(paths.project_dir({**environ, "XKEEN_PROJECT_DIR": "/srv/p"}), Path("/srv/p"))

    def test_constants(self):
        self.assertEqual(paths.TEST_ROOT_ENV, "KD_TEST_ROOT")
        self.assertEqual(paths.ALLOW_TEST_ROOT_ENV, "KD_ALLOW_TEST_ROOT")
        self.assertEqual(paths.PROJECT_DIR_ENV, "XKEEN_PROJECT_DIR")
        self.assertEqual(paths.DEFAULT_PROJECT_DIR, "/opt/root/keenetic-discord-nfqws2")


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)


class FsutilTests(TempDirTestCase):
    def test_atomic_text_replaces_with_mode_and_leaves_no_temp(self):
        target = self.root / "data.txt"
        target.write_text("old", encoding="utf-8")
        os.chmod(target, 0o644)
        fsutil.atomic_text(target, "новый текст\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "новый текст\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["data.txt"])
        fsutil.atomic_text(target, "shared", mode=0o644)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_atomic_text_stages_the_temp_file_next_to_the_target(self):
        target = self.root / "data.txt"
        with mock.patch.object(fsutil.os, "replace", wraps=os.replace) as replace:
            fsutil.atomic_text(target, "x")
        replace.assert_called_once()
        source, destination = replace.call_args.args
        self.assertEqual(Path(source).parent, target.parent)  # os.replace stays on one filesystem
        self.assertTrue(Path(source).name.startswith(".data.txt."))
        self.assertEqual(Path(destination), target)

    def test_atomic_text_creates_parent_directories(self):
        target = self.root / "a" / "b" / "data.txt"
        fsutil.atomic_text(target, "x")
        self.assertEqual(target.read_text(encoding="utf-8"), "x")

    def test_atomic_text_removes_temp_and_keeps_target_on_failure(self):
        target = self.root / "data.txt"
        target.write_text("old", encoding="utf-8")
        with mock.patch.object(fsutil.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                fsutil.atomic_text(target, "new")
        self.assertEqual(target.read_text(encoding="utf-8"), "old")
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["data.txt"])

    def test_safe_json_file_reads_an_object(self):
        target = self.root / "report.json"
        target.write_text('{"a": [1, 2]}', encoding="utf-8")
        self.assertEqual(fsutil.safe_json_file(target), {"a": [1, 2]})
        self.assertEqual(fsutil.MAX_JSON_BYTES, 512 * 1024)

    def test_safe_json_file_rejects_with_panel_messages(self):
        real = self.root / "real.json"
        real.write_text('{"a": 1}', encoding="utf-8")
        link = self.root / "link.json"
        link.symlink_to(real)
        directory = self.root / "dir.json"
        directory.mkdir()
        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        big = self.root / "big.json"
        big.write_text('{"a": "' + "x" * 64 + '"}', encoding="utf-8")
        array = self.root / "array.json"
        array.write_text("[]", encoding="utf-8")
        cases = [
            (link, {}, "необычный тип файла"),
            (directory, {}, "необычный тип файла"),
            (empty, {}, "некорректный размер файла"),
            (big, {"maximum": 16}, "некорректный размер файла"),
            (array, {}, "ожидается JSON-объект"),
        ]
        for path, kwargs, message in cases:
            with self.subTest(path=path.name):
                with self.assertRaises(ValueError) as caught:
                    fsutil.safe_json_file(path, **kwargs)
                self.assertEqual(str(caught.exception), f"{message}: {path}")
        # The limit is inclusive: a file of exactly `maximum` bytes is accepted.
        self.assertEqual(fsutil.safe_json_file(real, maximum=len(real.read_bytes())), {"a": 1})

    def test_safe_json_file_comments_flag(self):
        target = self.root / "xray.json"
        target.write_text('{"a": 1 /* c */} // x', encoding="utf-8")
        self.assertEqual(fsutil.safe_json_file(target, comments=True), {"a": 1})
        with self.assertRaises(json.JSONDecodeError):
            fsutil.safe_json_file(target)


class JsoncTests(unittest.TestCase):
    def test_strip_json_comments_keeps_strings(self):
        for text in ('{"a": "// not"}', '{"a": "/* not */"}', '{"a": "a\\"/*b"}', '{"a": "end\\\\"} '):
            with self.subTest(text=text):
                self.assertEqual(jsonc.strip_json_comments(text), text)

    def test_strip_json_comments_removes_comments(self):
        self.assertEqual(jsonc.strip_json_comments("a // c\nb"), "a \nb")
        self.assertEqual(jsonc.strip_json_comments("a/*x*/b"), "a b")
        self.assertEqual(jsonc.strip_json_comments("a/* x\ny */b"), "a b")
        self.assertEqual(jsonc.strip_json_comments('{"a": 1} // tail'), '{"a": 1} ')

    def test_strip_json_comments_cuts_an_unclosed_block(self):
        self.assertEqual(jsonc.strip_json_comments('{"a": 1} /* never closed'), '{"a": 1}  ')
        self.assertEqual(jsonc.strip_json_comments('{"a": 1} // no newline'), '{"a": 1} ')


class RunCommandTests(unittest.TestCase):
    def test_run_command_codes_and_env(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("XKEEN_FOREGROUND", None)
        ok = proc.run_command(["sh", "-c", "echo hello"], 10)
        self.assertEqual(ok, {"ok": True, "code": 0, "output": "hello"})
        failed = proc.run_command(["sh", "-c", "echo bad >&2; exit 3"], 10)
        self.assertEqual(failed, {"ok": False, "code": 3, "output": "bad"})
        missing = proc.run_command(["/nonexistent/kdn-binary"], 10)
        self.assertFalse(missing["ok"])
        self.assertEqual(missing["code"], 127)
        self.assertIn("/nonexistent/kdn-binary", missing["output"])
        seen = proc.run_command(["sh", "-c", 'printf "%s|%s" "${XKEEN_FOREGROUND-unset}" "$PATH"'], 10)
        self.assertEqual(seen["output"], f"unset|{proc.ROUTER_PATH}")
        seen = proc.run_command(
            ["sh", "-c", 'printf "%s|%s" "${XKEEN_FOREGROUND-unset}" "$PATH"'],
            10,
            env={"XKEEN_FOREGROUND": "1"},
        )
        self.assertEqual(seen["output"], f"1|{proc.ROUTER_PATH}")

    def test_run_command_env_argument_wins_over_the_pinned_path(self):
        result = proc.run_command(["/bin/sh", "-c", 'printf "%s" "$PATH"'], 10, env={"PATH": "/x"})
        self.assertEqual(result, {"ok": True, "code": 0, "output": "/x"})

    def test_run_command_decodes_output_with_replacement(self):
        script = "import sys; sys.stdout.buffer.write(b'ok\\xff\\xfe')"
        result = proc.run_command([sys.executable, "-c", script], 10)
        self.assertEqual(result, {"ok": True, "code": 0, "output": "ok\ufffd\ufffd"})

    def test_run_command_timeout_without_output_has_only_the_notice(self):
        result = proc.run_command(["sleep", "60"], 1)
        self.assertEqual(result["code"], 124)
        self.assertEqual(result["output"], "Команда превысила таймаут; отправлен TERM для штатного отката.")

    def test_command_env_pins_path_and_keeps_the_rest(self):
        with mock.patch.dict(os.environ, {"PATH": "/somewhere/else", "KDN_COMMON_PROBE": "1"}):
            env = proc.command_env()
        self.assertEqual(env["PATH"], proc.ROUTER_PATH)
        self.assertEqual(env["KDN_COMMON_PROBE"], "1")
        self.assertEqual(proc.ROUTER_PATH, "/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin")

    def test_run_command_timeout_stops_the_group(self):
        started = time.monotonic()
        result = proc.run_command(["sh", "-c", "sleep 60 & echo $!; wait"], 1)
        self.assertLess(time.monotonic() - started, 30)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertTrue(
            result["output"].startswith("Команда превысила таймаут; отправлен TERM для штатного отката.\n"),
            result["output"],
        )
        grandchild = int(result["output"].splitlines()[-1])
        deadline = time.monotonic() + 5
        while proc.process_alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(proc.process_alive(grandchild))

    def test_run_command_grace_comes_from_the_timeout(self):
        graces = []
        for timeout, expected in ((1, 10), (30, 15), (60, 30), (400, 120)):
            with self.subTest(timeout=timeout):
                graces.clear()
                with (
                    mock.patch.object(proc.subprocess, "Popen", _HangingProcess),
                    mock.patch.object(proc, "stop_process_group", side_effect=lambda _p, grace: graces.append(grace)),
                ):
                    result = proc.run_command(["never-started"], timeout)
                self.assertEqual(result["code"], 124)
                self.assertEqual(graces, [expected])

    def test_stop_process_group_terminates_a_cooperative_group(self):
        process = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(process.kill)
        started = time.monotonic()
        proc.stop_process_group(process, 10)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(process.returncode, -signal.SIGTERM)

    def test_stop_process_group_kills_after_grace(self):
        process = subprocess.Popen(
            ["sh", "-c", "trap '' TERM; sleep 30 & echo $!; wait"],
            stdout=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.kill)
        grandchild = int(process.stdout.readline())  # printed after the trap is installed
        self.addCleanup(_kill_quietly, grandchild)
        started = time.monotonic()
        proc.stop_process_group(process, 0.3)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.3)
        self.assertLess(elapsed, 5)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        # KILL goes to the whole group, not only to the leader: no TERM-ignoring member survives.
        deadline = time.monotonic() + 5
        while proc.process_alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(proc.process_alive(grandchild))

    def test_stop_process_group_falls_back_to_the_process_itself(self):
        process = mock.Mock(spec=["pid", "terminate", "kill", "wait"])
        process.pid = 2**22 + 12345  # no such process group
        process.wait.side_effect = [subprocess.TimeoutExpired("x", 1), None]
        with mock.patch.object(proc.os, "killpg", side_effect=ProcessLookupError):
            proc.stop_process_group(process, 1)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)


def _kill_quietly(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


class _HangingProcess:
    """Popen stand-in whose wait() always times out."""

    def __init__(self, *_args, **_kwargs):
        self.pid = 1
        self.returncode = None

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired("never-started", timeout)


class ProcessInspectionTests(TempDirTestCase):
    def write_stat(self, pid, state):
        directory = self.root / str(pid)
        directory.mkdir(exist_ok=True)
        (directory / "stat").write_text(f"{pid} (sh) {state} 1 1 1 0 -1\n", encoding="ascii")

    def test_process_alive_states(self):
        self.assertTrue(proc.process_alive(os.getpid()))
        child = subprocess.Popen(["true"])
        child.wait()
        self.assertFalse(proc.process_alive(child.pid))

        self.write_stat(123, "Z")
        with mock.patch.object(proc.os, "kill") as kill:
            self.assertFalse(proc.process_alive(123, self.root))
            kill.assert_called_once_with(123, 0)
            self.write_stat(123, "S")
            self.assertTrue(proc.process_alive(123, self.root))
        with mock.patch.object(proc.os, "kill", side_effect=PermissionError):
            self.assertTrue(proc.process_alive(123, self.root))
            self.assertTrue(proc.process_alive(321, self.root))
        with mock.patch.object(proc.os, "kill", side_effect=ProcessLookupError):
            self.assertFalse(proc.process_alive(123, self.root))

    def test_process_alive_unreadable_stat_counts_as_alive(self):
        with mock.patch.object(proc.os, "kill"):
            self.assertTrue(proc.process_alive(404, self.root))  # no stat file
            (self.root / "5").mkdir()
            (self.root / "5" / "stat").write_bytes(b"5 (\xff\xfe) S 1\n")  # not ASCII
            self.assertTrue(proc.process_alive(5, self.root))
            (self.root / "6").mkdir()
            (self.root / "6" / "stat").write_text("6\n", encoding="ascii")  # too short
            self.assertTrue(proc.process_alive(6, self.root))

    def test_process_alive_reads_the_module_proc_root(self):
        self.write_stat(77, "Z")
        with mock.patch.object(proc.os, "kill"), mock.patch.object(proc, "PROC_ROOT", self.root):
            self.assertFalse(proc.process_alive(77))
        self.assertEqual(proc.PROC_ROOT, Path("/proc"))

    def test_read_job_pid_and_job_command(self):
        pidfile = self.root / "worker.pid"
        for raw, expected in (("123\n", 123), ("1", None), ("0", None), ("x", None), ("-5", None), ("", None)):
            with self.subTest(raw=raw):
                pidfile.write_text(raw, encoding="ascii")
                self.assertEqual(proc.read_job_pid(pidfile), expected)
        pidfile.write_bytes(b"\xff\xfe")
        self.assertIsNone(proc.read_job_pid(pidfile))
        self.assertIsNone(proc.read_job_pid(self.root / "missing.pid"))

        pid = os.getpid()
        directory = self.root / str(pid)
        directory.mkdir()
        (directory / "cmdline").write_bytes(b"a\0b\0")
        self.assertEqual(proc.job_command(pid, self.root), [b"a", b"b", b""])
        self.assertIsNone(proc.job_command(pid, self.root / "nowhere"))
        self.write_stat(pid, "Z")
        self.assertIsNone(proc.job_command(pid, self.root))
        with mock.patch.object(proc.os, "kill", side_effect=ProcessLookupError):
            self.assertIsNone(proc.job_command(pid, self.root))


class TimeutilTests(unittest.TestCase):
    def test_utc_now_format(self):
        self.assertRegex(timeutil.utc_now(), re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"))

    def test_utc_now_is_gmt(self):
        with mock.patch.object(timeutil.time, "gmtime", return_value=time.gmtime(86400 * 365)):
            self.assertEqual(timeutil.utc_now(), "1971-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()

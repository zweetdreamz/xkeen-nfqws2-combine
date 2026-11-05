"""Tests of the frame of kdn.engine: the mode table of cli, the hand-over to the shell engine (legacy), the Console
that keeps the order of two streams, and the plain classes of findings.

Only preflight (and status JSON until task 19) hands the run to the shell. The text modes are native. The tests never replace the
process of pytest: the context carries the execve, and the tests give it a double.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from kdn.engine import checks, cli, config, console, findings, legacy, plan, preflight, profiles, snapshots, status


ROUTER_DIR = Path(cli.__file__).resolve().parents[2]
ROOT = ROUTER_DIR.parents[1]
SCRIPT = ROOT / "apply-discord-nfqws2.sh"
MODE_TABLE = ROOT / "tests" / "fixtures" / "engine" / "mode-table.tsv"
SIX_MODES = {
    "status": status,
    "check-config": checks,
    "print-nfqws-profiles": profiles,
    "show-snapshots": snapshots,
    "preflight": preflight,
    "print-plan": plan,
}
SIX_FLAGS = {
    "status": "--status",
    "check-config": "--check-config",
    "print-nfqws-profiles": "--print-nfqws-profiles",
    "show-snapshots": "--show-snapshots",
    "preflight": "--preflight",
    "print-plan": "--print-plan",
}
# What the shell dispatcher puts around the Python engine and the legacy shell must not see.
DISPATCHER_ENV = {
    "PATH": "/usr/bin:/bin",
    "PYTHONPATH": "/project/tools/router:/user/lib",
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8:surrogateescape",
    "KDN_ENGINE": "python",
    "KDN_ENGINE_SCRIPT": "/project/apply-discord-nfqws2.sh",
    "KDN_ENGINE_SCRIPT_DIR": "/project",
    "KDN_ENGINE_ADDED_PYTHONPATH": "/project/tools/router",
    "KDN_ENGINE_ADDED_ENV": "PYTHONUTF8 PYTHONIOENCODING",
    "UNRELATED": "kept",
}


def load_mode_table():
    """(line, mode, argv) of every row of mode-table.tsv; @empty@ is an argument that is an empty string."""
    rows = []
    for number, line in enumerate(MODE_TABLE.read_bytes().decode("utf-8").split("\n"), 1):
        if not line:
            continue
        mode, _, tokens = line.partition("\t")
        argv = [("" if token == "@empty@" else token) for token in tokens.split(" ")] if tokens else []
        rows.append((number, mode, argv))
    # Internal recovery adapters are native-only; retain the frozen legacy table.
    rows.extend((
        (0, 'prune-import-snapshots', ['--prune-import-snapshots', '--yes-router']),
        (0, 'setup-route-checker', ['--setup-route-checker', '--yes-router']),
        (0, '?', ['--focused-operation-context']),
        (0, '?', ['--recover-import-source']),
        (0, 'rollback-import', ['--rollback-import', '--focused-operation-context', '{}',
                                 '--recover-import-source', '/synthetic/source', '--yes-router']),
    ))
    return rows


def child_environ(**extra):
    env = {name: value for name, value in os.environ.items() if not name.startswith("KDN_ENGINE")}
    for name in ("PYTHONUTF8", "PYTHONIOENCODING"):
        env.pop(name, None)
    env["PYTHONPATH"] = str(ROUTER_DIR)
    env.update(extra)
    return env


class FakeExec:
    """execve double: records the calls and returns, as the real one never does."""

    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def __call__(self, path, args, env):
        self.calls.append((path, list(args), dict(env)))
        if self.error is not None:
            raise self.error


class Streams:
    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def console(self):
        return console.Console(self.stdout, self.stderr)


def make_context(argv, environ=None, execve=None, streams=None):
    streams = Streams() if streams is None else streams
    return cli.Context(
        list(argv),
        dict(DISPATCHER_ENV if environ is None else environ),
        streams.console(),
        execve=FakeExec() if execve is None else execve,
    )


class ModeTableTests(unittest.TestCase):
    def test_mode_table(self):
        rows = load_mode_table()
        self.assertGreaterEqual(len(rows), 54)
        for number, mode, argv in rows:
            with self.subTest(line=number, mode=mode, argv=argv):
                self.assertEqual(cli.mode_of(argv), mode)

    def test_the_table_covers_every_mode_and_every_option_with_a_value(self):
        rows = load_mode_table()
        self.assertEqual({mode for _, mode, _ in rows}, {*SIX_MODES, *cli.MUTATION_MODES, "help", "?"})
        missing = [
            option
            for option in cli.VALUE_OPTIONS
            if not any(mode == "?" and argv == [option] for _, mode, argv in rows)
        ]
        self.assertEqual(missing, [])
        self.assertEqual(len(cli.VALUE_OPTIONS), 15)

    def test_mode_of_does_not_modify_the_arguments(self):
        argv = ["--status", "--yes-router"]
        cli.mode_of(argv)
        self.assertEqual(argv, ["--status", "--yes-router"])

    def test_the_last_mode_wins_and_a_value_is_not_a_mode(self):
        self.assertEqual(cli.mode_of(["--preflight", "--print-plan"]), "print-plan")
        self.assertEqual(cli.mode_of(["--core", "--status"]), "help")
        self.assertEqual(cli.mode_of(["--core", "--status", "--status"]), "status")
        self.assertEqual(cli.mode_of(["--rollback-snapshot", "--help", "--check-config"]), "check-config")

    def test_modes_has_the_six_modules(self):
        self.assertEqual(cli.MODES, SIX_MODES)
        for module in cli.MODES.values():
            self.assertTrue(callable(module.run))


class LegacyHandOverTests(unittest.TestCase):
    def setUp(self):
        # Unit dispatch checks are not target-version integration tests.
        patcher = mock.patch.object(cli.xkeen, 'require', return_value='2.1.1')
        patcher.start()
        self.addCleanup(patcher.stop)
    def test_live_preflight_uses_shared_native_preparation_without_confirmation(self):
        streams, execve = Streams(), FakeExec()
        with mock.patch.object(cli, '_run_mutation', return_value=0) as native:
            self.assertEqual(cli.main(['--preflight'], environ={}, stdout=streams.stdout,
                                      stderr=streams.stderr, execve=execve), 0)
        native.assert_called_once()
        self.assertEqual(native.call_args.args[0].options.mode, 'preflight')
        self.assertFalse(native.call_args.args[0].options.confirmed)
        self.assertEqual(execve.calls, [])

    def test_mutation_modes_reach_native_dispatch_once_without_legacy_exec(self):
        for number, mode, argv in load_mode_table():
            if mode not in cli.MUTATION_MODES:
                continue
            with self.subTest(line=number, mode=mode, argv=argv):
                execve = FakeExec()
                streams = Streams()
                with mock.patch.object(cli, '_run_mutation', return_value=7) as native:
                    result = cli.main(argv, environ=dict(DISPATCHER_ENV), stdout=streams.stdout,
                                      stderr=streams.stderr, execve=execve)
                self.assertEqual(result, 7)
                native.assert_called_once()
                self.assertEqual(native.call_args.args[0].options.mode, mode)
                self.assertEqual(native.call_args.args[0].argv, argv)
                self.assertEqual(execve.calls, [])

    def test_unported_modes_fall_back_to_legacy(self):
        for number, mode, argv in load_mode_table():
            if mode in cli.MODES or mode in cli.MUTATION_MODES:
                continue
            with self.subTest(line=number, mode=mode, argv=argv):
                execve = FakeExec()
                streams = Streams()
                code = cli.main(
                    argv,
                    environ=dict(DISPATCHER_ENV),
                    stdout=streams.stdout,
                    stderr=streams.stderr,
                    execve=execve,
                )
                if mode == '?':
                    with self.assertRaises(cli.options.ArgError) as caught:
                        cli.options.parse_args(argv)
                    self.assertEqual(code, 2)
                    self.assertEqual(execve.calls, [])
                    self.assertEqual((streams.stdout.getvalue(), streams.stderr.getvalue()),
                                     ('', caught.exception.message + '\n'))
                    continue
                self.assertEqual(code, 0)
                self.assertEqual(len(execve.calls), 1)
                path, args, env = execve.calls[0]
                self.assertEqual(args, [path, "/project/apply-discord-nfqws2.sh", *argv])
                self.assertEqual(env["KDN_ENGINE"], "legacy")
                self.assertEqual((streams.stdout.getvalue(), streams.stderr.getvalue()), ("", ""))

    def test_apply_with_confirmation_reaches_native_once_without_shell(self):
        execve = FakeExec()
        with mock.patch.object(cli, '_run_mutation', return_value=0) as native:
            result = cli.main(["--apply", "--yes-router"], environ=dict(DISPATCHER_ENV),
                              stdout=io.StringIO(), stderr=io.StringIO(), execve=execve)
        self.assertEqual(result, 0)
        self.assertEqual(execve.calls, [])
        native.assert_called_once()
        self.assertEqual(native.call_args.args[0].options.mode, 'apply')

    def test_every_stub_falls_back_with_the_original_argv(self):
        for name, module in SIX_MODES.items():
            argv = [SIX_FLAGS[name], "--yes-router", "", "--core", "xray"]
            with self.subTest(mode=name):
                execve = FakeExec()
                streams = Streams()
                ctx = make_context(argv, execve=execve, streams=streams)
                if name == 'status':
                    ctx.paths = config.EnginePaths.from_environ({})
                    with mock.patch.object(status.system, 'is_router', return_value=False):
                        self.assertEqual(module.run(ctx), 1)
                    self.assertEqual(execve.calls, [])
                    self.assertEqual((streams.stdout.getvalue(), streams.stderr.getvalue()),
                                     ('', 'ERROR: this does not look like a Keenetic Entware environment.\n'))
                    continue
                if name in ('print-plan', 'print-nfqws-profiles', 'check-config'):
                    ctx.paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': '/fixture/root', 'KD_ALLOW_TEST_ROOT': '1'})
                    ctx.options = cli.options.parse_args([SIX_FLAGS[name]])
                    ctx.resolved = cli.options.resolve(ctx.options, None)
                    rc = module.run(ctx)
                    self.assertEqual(execve.calls, [])
                    if name == 'print-plan':
                        self.assertEqual((rc, streams.stdout.getvalue(), streams.stderr.getvalue()), (0, plan.render(ctx.resolved), ''))
                    elif name == 'check-config':
                        self.assertEqual((rc, streams.stdout.getvalue(), streams.stderr.getvalue()),
                                         (2, 'CHECK|error|read|cannot read /fixture/root/opt/etc/nfqws2/nfqws2.conf\n', ''))
                    else:
                        self.assertEqual((rc, streams.stdout.getvalue(), streams.stderr.getvalue()),
                                         (2, '', 'ERROR: nfqws2 config not found: /fixture/root/opt/etc/nfqws2/nfqws2.conf\n'))
                    continue
                if name == 'show-snapshots':
                    ctx.paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': '/fixture/root', 'KD_ALLOW_TEST_ROOT': '1'})
                    self.assertEqual(module.run(ctx), 0)
                    self.assertEqual(execve.calls, [])
                    self.assertEqual(streams.stdout.getvalue(),
                                     'State directory: /fixture/root/opt/etc/keenetic-discord-nfqws2\n'
                                     'Baseline: not created\nLatest pre-apply: not created\n')
                    self.assertEqual(streams.stderr.getvalue(), '')
                    continue
                with mock.patch.object(preflight, 'needs_legacy', return_value=True):
                    module.run(ctx)
                self.assertEqual(len(execve.calls), 1)
                path, args, env = execve.calls[0]
                self.assertEqual(args, [path, "/project/apply-discord-nfqws2.sh", *argv])
                self.assertEqual(env["KDN_ENGINE"], "legacy")
                self.assertEqual((streams.stdout.getvalue(), streams.stderr.getvalue()), ("", ""))

    def test_every_stub_is_reached_through_main(self):
        for name, flag in SIX_FLAGS.items():
            with self.subTest(mode=name):
                execve = FakeExec()
                out, err = io.StringIO(), io.StringIO()
                if name == 'status':
                    report = status.StatusReport()
                    report.fields['project'] = 'fixture'
                    report.warnings.append('WARNING: fixture')
                    with mock.patch.object(status, 'collect', return_value=report) as collect:
                        code = cli.main([flag], environ=dict(DISPATCHER_ENV), stdout=out, stderr=err, execve=execve)
                    collect.assert_called_once()
                    self.assertEqual((code, out.getvalue(), err.getvalue()), (0, 'project=fixture\n', 'WARNING: fixture\n'))
                    self.assertEqual(execve.calls, [])
                    continue
                with mock.patch.object(preflight, 'needs_legacy', return_value=True):
                    code = cli.main(
                        [flag],
                        environ=dict(DISPATCHER_ENV, KD_TEST_ROOT='/fixture/root', KD_ALLOW_TEST_ROOT='1'),
                        stdout=out,
                        stderr=err,
                        execve=execve,
                    )
                self.assertEqual(code, 2 if name in ('check-config', 'print-nfqws-profiles') else 0)
                if name in ('print-plan', 'print-nfqws-profiles', 'check-config'):
                    self.assertEqual(execve.calls, [])
                    if name == 'print-plan':
                        self.assertEqual(out.getvalue(), plan.render(cli.options.resolve(cli.options.parse_args([flag]), None)))
                        self.assertEqual(err.getvalue(), '')
                    elif name == 'check-config':
                        self.assertEqual((out.getvalue(), err.getvalue()), ('CHECK|error|read|cannot read /fixture/root/opt/etc/nfqws2/nfqws2.conf\n', ''))
                    else:
                        self.assertEqual((out.getvalue(), err.getvalue()), ('', 'ERROR: nfqws2 config not found: /fixture/root/opt/etc/nfqws2/nfqws2.conf\n'))
                    continue
                if name == 'show-snapshots':
                    self.assertEqual(execve.calls, [])
                    self.assertEqual(out.getvalue(), 'State directory: /fixture/root/opt/etc/keenetic-discord-nfqws2\n'
                                     'Baseline: not created\nLatest pre-apply: not created\n')
                    self.assertEqual(err.getvalue(), '')
                    continue
                self.assertEqual([call[1][2:] for call in execve.calls], [[flag]])

    def test_fallback_command_prefers_the_script_from_the_environment(self):
        _, args, _ = legacy.fallback_command(
            {"KDN_ENGINE_SCRIPT": "/a/apply.sh", "KDN_ENGINE_SCRIPT_DIR": "/b"}, ["--status"]
        )
        self.assertEqual(args[1:], ["/a/apply.sh", "--status"])
        _, args, _ = legacy.fallback_command({"KDN_ENGINE_SCRIPT_DIR": "/b"}, [])
        self.assertEqual(args[1:], ["/b/apply-discord-nfqws2.sh"])
        _, args, _ = legacy.fallback_command({"KDN_ENGINE_SCRIPT": "", "KDN_ENGINE_SCRIPT_DIR": ""}, ["--apply"])
        self.assertEqual(Path(args[1]).resolve(), SCRIPT.resolve())
        self.assertEqual(args[2:], ["--apply"])
        self.assertTrue(SCRIPT.is_file())

    def test_fallback_command_runs_the_shell_the_panel_runs(self):
        path, args, _ = legacy.fallback_command({"PATH": "/nonexistent"}, [])
        self.assertEqual((path, args[0]), ("/bin/sh", "/bin/sh"))

    def test_fallback_command_finds_sh_on_the_path_when_bin_sh_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            shell = Path(tmp) / "sh"
            shell.write_text("#!/bin/sh\n", encoding="ascii")
            shell.chmod(0o755)
            with mock.patch.object(legacy, "SHELL", str(Path(tmp) / "no-such-sh")):
                path, args, _ = legacy.fallback_command({"PATH": f":/nonexistent:{tmp}"}, [])
                self.assertEqual((path, args[0]), (str(shell), str(shell)))
                path, _, _ = legacy.fallback_command({"PATH": "/nonexistent"}, [])
                self.assertEqual(path, str(Path(tmp) / "no-such-sh"))

    def test_fallback_command_strips_what_the_dispatcher_added(self):
        environ = dict(DISPATCHER_ENV)
        _, _, env = legacy.fallback_command(environ, ["--status"])
        self.assertEqual(
            env,
            {"PATH": "/usr/bin:/bin", "PYTHONPATH": "/user/lib", "KDN_ENGINE": "legacy", "UNRELATED": "kept"},
        )
        self.assertEqual(environ, DISPATCHER_ENV)

    def test_fallback_command_removes_a_pythonpath_that_held_only_the_added_directory(self):
        environ = {**DISPATCHER_ENV, "PYTHONPATH": "/project/tools/router"}
        _, _, env = legacy.fallback_command(environ, [])
        self.assertNotIn("PYTHONPATH", env)

    def test_fallback_command_keeps_what_the_user_set(self):
        environ = {
            "PYTHONPATH": "/user/lib:/project/tools/router",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "latin-1",
            "KDN_ENGINE_ADDED_PYTHONPATH": "/project/tools/router",
            "KDN_ENGINE_ADDED_ENV": "PYTHONIOENCODING",
        }
        _, _, env = legacy.fallback_command(environ, [])
        # The added directory is stripped only from the front, and only the names the dispatcher listed.
        self.assertEqual(env["PYTHONPATH"], "/user/lib:/project/tools/router")
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertNotIn("PYTHONIOENCODING", env)
        _, _, env = legacy.fallback_command({"PYTHONPATH": "/user/lib", "PYTHONUTF8": "1"}, [])
        self.assertEqual((env["PYTHONPATH"], env["PYTHONUTF8"]), ("/user/lib", "1"))

    def test_fallback_command_knows_comma_separated_added_names(self):
        environ = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "x", "KDN_ENGINE_ADDED_ENV": "PYTHONUTF8,PYTHONIOENCODING"}
        _, _, env = legacy.fallback_command(environ, [])
        self.assertEqual(env, {"KDN_ENGINE": "legacy"})

    def test_exec_legacy_flushes_the_streams_before_the_exec(self):
        order = []

        class Recorder(io.StringIO):
            def __init__(self, name):
                super().__init__()
                self.name = name

            def flush(self):
                order.append(f"flush {self.name}")

        ctx = cli.Context(
            ["--apply"],
            dict(DISPATCHER_ENV),
            console.Console(Recorder("stdout"), Recorder("stderr")),
            execve=lambda path, args, env: order.append("exec"),
        )
        legacy.exec_legacy(ctx)
        self.assertEqual(order[-1], "exec")
        self.assertEqual(sorted(order[:-1]), ["flush stderr", "flush stdout"])

    def test_exec_legacy_reports_a_shell_that_cannot_start(self):
        streams = Streams()
        execve = FakeExec(error=OSError(2, "No such file or directory"))
        code = legacy.exec_legacy(make_context(["--apply"], execve=execve, streams=streams))
        self.assertEqual(code, 127)
        self.assertEqual(streams.stdout.getvalue(), "")
        self.assertEqual(
            streams.stderr.getvalue(), "ERROR: cannot start the shell engine: [Errno 2] No such file or directory\n"
        )

    def test_python_m_kdn_engine_reaches_the_shell_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = child_environ(KD_TEST_ROOT=tmp, KD_ALLOW_TEST_ROOT="1", KDN_ENGINE_SCRIPT_DIR=str(ROOT))
            from target_fixture import version_executable
            binary = version_executable(Path(tmp) / 'bin/xkeen')
            env['PATH'] = str(binary.parent) + os.pathsep + env.get('PATH', os.defpath)
            result = subprocess.run(
                [sys.executable, "-P", "-m", "kdn.engine", "--apply"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("this mode changes router state", result.stderr)
        self.assertEqual(result.stdout, "STAGE|preflight\nRESULT|failed\n")

    def test_the_shell_engine_gets_the_arguments_and_exit_codes_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = child_environ(KD_TEST_ROOT=tmp, KD_ALLOW_TEST_ROOT="1", KDN_ENGINE_SCRIPT_DIR=str(ROOT))
            for argv, message in (
                (["--bogus"], "ERROR: unknown argument: --bogus"),
                ([""], "ERROR: unknown argument: \n"),
                (["--core"], "ERROR: --core requires auto, xray, or mihomo."),
            ):
                with self.subTest(argv=argv):
                    result = subprocess.run(
                        [sys.executable, "-P", "-m", "kdn.engine", *argv],
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=60,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)

    def test_the_test_root_guard_of_the_shell_engine_is_not_bypassed(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = child_environ(KD_TEST_ROOT=tmp, KDN_ENGINE_SCRIPT_DIR=str(ROOT))
            env.pop("KD_ALLOW_TEST_ROOT", None)
            result = subprocess.run(
                [sys.executable, "-P", "-m", "kdn.engine", "--status"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("ERROR: KD_TEST_ROOT is reserved for isolated repository tests.", result.stderr)


class MainTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(cli.xkeen, 'require', return_value='2.1.1')
        patcher.start()
        self.addCleanup(patcher.stop)
    def test_main_returns_the_code_of_the_mode_and_flushes(self):
        def run(ctx):
            ctx.console.out("line")
            ctx.console.err("warning")
            return 7

        streams = Streams()
        with mock.patch.dict(cli.MODES, {"status": types.SimpleNamespace(run=run)}):
            code = cli.main(["--status"], environ={}, stdout=streams.stdout, stderr=streams.stderr)
        self.assertEqual(code, 7)
        self.assertEqual((streams.stdout.getvalue(), streams.stderr.getvalue()), ("line\n", "warning\n"))

    def test_the_mode_gets_the_context_of_the_run(self):
        seen = []
        execve = FakeExec()
        with mock.patch.object(cli, '_run_mutation', side_effect=lambda ctx: seen.append(ctx) or 0):
            cli.main(
                ["--preflight", "--core", "xray"],
                environ={"A": "1"},
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                execve=execve,
            )
        (ctx,) = seen
        self.assertEqual(ctx.argv, ["--preflight", "--core", "xray"])
        self.assertEqual(ctx.environ, {"A": "1"})
        self.assertIs(ctx.execve, execve)
        self.assertEqual(ctx.paths, config.EnginePaths.from_environ({"A": "1"}))
        self.assertEqual(ctx.options, cli.options.parse_args(ctx.argv))
        self.assertEqual(ctx.resolved.core_requested, 'xray')
        self.assertEqual(ctx.resolved.routes_summary(), 'Discord TCP=zapret, Discord Voice=zapret, YouTube=vless, Telegram=unmanaged')
        self.assertEqual(execve.calls, [])

    def test_main_defaults_to_the_process_argv_environment_and_streams(self):
        streams = Streams()
        execve = FakeExec()
        with (
            mock.patch.object(sys, "argv", ["engine", "--apply", "--yes-router"]),
            mock.patch.dict(os.environ, {"KDN_ENGINE_SCRIPT": "/x/apply.sh"}),
            mock.patch.object(console.Console, "process", return_value=streams.console()),
            mock.patch.object(cli, '_run_mutation', return_value=0) as native,
        ):
            cli.main(execve=execve)
            observed_script = native.call_args.args[0].environ['KDN_ENGINE_SCRIPT']
        native.assert_called_once()
        self.assertEqual(native.call_args.args[0].argv, ["--apply", "--yes-router"])
        self.assertEqual(observed_script, '/x/apply.sh')
        self.assertEqual(execve.calls, [])

    def test_context_defaults(self):
        ctx = cli.Context(["--status"], {"A": "1"}, console.Console(io.StringIO(), io.StringIO()))
        self.assertEqual((ctx.argv, ctx.environ), (["--status"], {"A": "1"}))
        self.assertEqual((ctx.paths, ctx.options, ctx.resolved), (None, None, None))
        self.assertIs(ctx.execve, os.execve)

    def test_context_is_a_plain_slots_class(self):
        ctx = cli.Context([], {}, console.Console(io.StringIO(), io.StringIO()))
        self.assertFalse(hasattr(ctx, "__dict__"))
        with self.assertRaises(AttributeError):
            ctx.surprise = 1
        ctx.options = "set later by the argument parser"
        self.assertEqual(ctx.options, "set later by the argument parser")


class ConsoleTests(unittest.TestCase):
    def test_out_and_err_end_with_a_newline_unless_told_otherwise(self):
        streams = Streams()
        output = streams.console()
        output.out()
        output.out("a")
        output.out("b", end="")
        output.err()
        output.err("c")
        output.err("d", end="")
        self.assertEqual(streams.stdout.getvalue(), "\na\nb")
        self.assertEqual(streams.stderr.getvalue(), "\nc\nd")

    def test_writing_to_one_stream_flushes_the_other_first(self):
        events = []

        class Recorder(io.StringIO):
            def __init__(self, name):
                super().__init__()
                self.name = name

            def write(self, text):
                events.append(f"write {self.name} {text!r}")
                return super().write(text)

            def flush(self):
                events.append(f"flush {self.name}")

        output = console.Console(Recorder("stdout"), Recorder("stderr"))
        output.out("1")
        output.err("2")
        self.assertEqual(
            events,
            ["flush stderr", "write stdout '1\\n'", "flush stdout", "write stderr '2\\n'"],
        )
        events.clear()
        output.flush()
        self.assertEqual(sorted(events), ["flush stderr", "flush stdout"])

    def test_console_keeps_the_order_between_streams(self):
        code = (
            "from kdn.engine import console\n"
            "c = console.Console.process()\n"
            "c.out('1'); c.err('2'); c.out('3'); c.err('4', end=''); c.out('5'); c.err('6')\n"
            "c.flush()\n"
        )
        result = subprocess.run(
            [sys.executable, "-P", "-c", code],
            env=child_environ(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.stdout, b"1\n2\n3\n45\n6\n")

    def test_console_writes_undecodable_bytes_back(self):
        code = (
            "from kdn.engine import console\n"
            "c = console.Console.process()\n"
            "c.out('a\\udcffb')\n"
            "c.err('c\\udcfed')\n"
        )
        result = subprocess.run(
            [sys.executable, "-P", "-c", code],
            env=child_environ(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"a\xffb\n")
        self.assertEqual(result.stderr, b"c\xfed\n")

    def test_console_writes_utf8_whatever_the_locale(self):
        code = "from kdn.engine import console\nconsole.Console.process().out('\\u0436\\u00e9')\n"
        result = subprocess.run(
            [sys.executable, "-P", "-c", code],
            env=child_environ(LC_ALL="C", PYTHONUTF8="0"),
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "жé\n".encode())

    def test_surrogateescape_streams_round_trip_through_a_buffer(self):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="utf-8", errors="surrogateescape", newline="")
        console.Console(stream, io.StringIO()).out("x\udcff\r", end="")
        stream.flush()
        self.assertEqual(buffer.getvalue(), b"x\xff\r")


class FindingsTests(unittest.TestCase):
    def test_finding_is_a_value(self):
        finding = findings.Finding("err", "ERROR: x")
        self.assertEqual((finding.stream, finding.text), ("err", "ERROR: x"))
        self.assertEqual(finding, findings.Finding("err", "ERROR: x"))
        self.assertNotEqual(finding, findings.Finding("out", "ERROR: x"))
        self.assertNotEqual(finding, ("err", "ERROR: x"))
        self.assertEqual(len({finding, findings.Finding("err", "ERROR: x")}), 1)
        self.assertEqual(repr(finding), "Finding('err', 'ERROR: x')")
        self.assertFalse(hasattr(finding, "__dict__"))

    def test_state_defaults(self):
        state = findings.State()
        self.assertEqual(
            (state.errors, state.findings, state.detected_core, state.direct_mark),
            (0, [], "", ""),
        )
        self.assertEqual((state.proxy_outbound, state.wan, state.ipv6), ("", "", ""))
        self.assertFalse(hasattr(state, "__dict__"))
        with self.assertRaises(AttributeError):
            state.surprise = 1

    def test_states_do_not_share_the_findings_list(self):
        first, second = findings.State(), findings.State()
        first.findings.append(findings.Finding("err", "x"))
        self.assertEqual(second.findings, [])

    def test_state_takes_every_field_and_compares_by_value(self):
        shared = [findings.Finding("out", "y")]
        state = findings.State(2, shared, "xray", "255", "vless", "eth3", "on")
        self.assertIs(state.findings, shared)
        self.assertEqual(
            (state.errors, state.detected_core, state.direct_mark, state.proxy_outbound, state.wan, state.ipv6),
            (2, "xray", "255", "vless", "eth3", "on"),
        )
        self.assertEqual(state, findings.State(2, [findings.Finding("out", "y")], "xray", "255", "vless", "eth3", "on"))
        self.assertNotEqual(state, findings.State())
        self.assertIn("detected_core='xray'", repr(state))


if __name__ == "__main__":
    unittest.main()

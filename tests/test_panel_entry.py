"""Tests of the panel entry points and of the configuration they import, run as on the router.

The installed shim and the script runs of tools/router/kdn/web/app.py are the only checks of sys.path and of
the imports at start-up: the other panel tests import the package in-process. Every script run uses cwd="/",
an empty project directory and a free loopback port, writes no bytecode and stops at the missing project
scripts. kdn.web.infra.config reads its paths once at import, so it is probed in a child process too. The
sys.path bootstrap and ENTRY are also checked on a panel generation.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import panel_harness


ROOT = Path(__file__).resolve().parents[1]
ROUTER_DIR = ROOT / "tools" / "router"
APP = ROUTER_DIR / "kdn" / "web" / "app.py"
INSTALLER = ROUTER_DIR / "xkeen_control_script.sh"
MISSING = "Project scripts are missing"
JOB_ID = "0123456789abcdef"
# The five scripts of the project main() requires, in the order of its message.
PROJECT_SCRIPTS = ("ENGINE", "SERVICE_SWITCH", "VPN_MANAGER_SCRIPT", "AUTOTUNER", "DIAGNOSTICS")
DEFAULT_PROJECT_DIR = "/opt/root/keenetic-discord-nfqws2"
# Settings of the test process the router has not: the entry must find its package on its own.
DROPPED_ENV = ("PYTHONPATH", "PYTHONSAFEPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "KD_TEST_ROOT", "KD_ALLOW_TEST_ROOT")
# Runs app.py as the shim does and prints the ENTRY the configuration got from it.
ENTRY_PROBE = (
    "import runpy, sys; runpy.run_path(sys.argv[1], run_name='probe'); "
    "from kdn.web.infra import config; print(config.ENTRY)"
)
# Prints every path of the configuration as read at import.
CONFIG_PROBE = (
    "import json, pathlib; from kdn.web.infra import config; "
    "print(json.dumps({name: str(value) for name, value in vars(config).items() "
    "if isinstance(value, pathlib.PurePath)}))"
)


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class OrderedStdout(io.StringIO):
    """stdout that notes in ``calls`` where a line of output begins: its order against the startup steps is observable."""

    def __init__(self, calls):
        super().__init__()
        self.calls = calls

    def write(self, text):
        written = self.getvalue()
        if text and (not written or written.endswith("\n")):
            self.calls.append("print")
        return super().write(text)


def child_env(*, test_root=None, **values):
    """Environment of a child process: without the test process settings and XKEEN_PROJECT_DIR, plus values."""
    env = {key: value for key, value in os.environ.items() if key not in (*DROPPED_ENV, "XKEEN_PROJECT_DIR")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if test_root is not None:
        env.update(KD_TEST_ROOT=str(test_root), KD_ALLOW_TEST_ROOT="1")
    env.update(values)
    return env


class PanelEntryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.port = free_port()

    def run_python(self, script, *args, project, test_root=None):
        env = child_env(
            test_root=test_root,
            XKEEN_PROJECT_DIR=str(project),
            XKEEN_WEB_BIND="127.0.0.1",
            XKEEN_WEB_PORT=str(self.port),
        )
        return subprocess.run(
            [sys.executable, str(script), *args],
            env=env,
            cwd="/",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def run_probe(self, code, *args, env, cwd="/"):
        return subprocess.run(
            [sys.executable, "-c", code, *args],
            env=env,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def config_paths(self, **env):
        result = self.run_probe(CONFIG_PROBE, env=child_env(PYTHONPATH=str(ROUTER_DIR), **env), cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {name: Path(value) for name, value in json.loads(result.stdout).items()}

    def assertReachesMain(self, result, project):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(MISSING, result.stderr)
        self.assertIn(str(project / "apply-discord-nfqws2.sh"), result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_real_shim_reaches_main(self):
        from target_fixture import installer_environment
        web = self.root / "web"
        project = self.root / "project"
        installed = subprocess.run(
            ["sh", str(INSTALLER)],
            env=installer_environment({**os.environ, "XKEEN_WEB_DIR": str(web)}, self.root),
            cwd="/",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(installed.returncode, 0, installed.stderr)
        shutil.copytree(
            ROUTER_DIR / "kdn",
            project / "tools" / "router" / "kdn",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        self.assertReachesMain(self.run_python(web / "app.py", project=project), project)

    def test_entry_runs_as_a_script(self):
        project = self.root / "project"
        project.mkdir()
        self.assertReachesMain(self.run_python(APP, project=project), project)

    def test_route_worker_runs_as_a_script(self):
        project = self.root / "project"
        project.mkdir()
        router = self.root / "router"
        router.mkdir()
        result = self.run_python(APP, "--route-job", JOB_ID, "bogus", "-", "-", project=project, test_root=router)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_entry_is_the_running_file(self):
        tools = ROOT / "tools"
        link = self.root / "web"
        link.symlink_to(APP.parent, target_is_directory=True)
        runs = (
            (str(APP), "/", {}),
            (os.path.relpath(APP, tools), str(tools), {}),
            # The package comes from the real tree, the file runs through the link: ENTRY is the path that runs,
            # not the fallback the configuration derives from its own location.
            (str(link / "app.py"), "/", {"PYTHONPATH": str(ROUTER_DIR)}),
        )
        for path, cwd, extra in runs:
            with self.subTest(path=path):
                result = self.run_probe(ENTRY_PROBE, path, env=child_env(test_root=self.root, **extra), cwd=cwd)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(Path(cwd, path).absolute()))

    def test_config_refuses_test_root_without_permission(self):
        env = child_env(PYTHONPATH=str(ROUTER_DIR), KD_TEST_ROOT=str(self.root))
        result = self.run_probe("import kdn.web.infra.config", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved for isolated repository tests", result.stderr)

    def test_config_paths_follow_the_test_root(self):
        on_router = self.config_paths()
        self.assertEqual(on_router["NFQWS_CONFIG"], Path("/opt/etc/nfqws2/nfqws2.conf"))
        self.assertEqual(on_router["PROJECT_DIR"], Path(DEFAULT_PROJECT_DIR))
        self.assertEqual(on_router["IMPORT_STAGING_DIR"], Path("/opt/tmp"))
        under_root = self.config_paths(test_root=self.root)
        self.assertEqual(under_root["NFQWS_CONFIG"], self.root / "opt/etc/nfqws2/nfqws2.conf")
        self.assertEqual(under_root["PROJECT_DIR"], self.root / DEFAULT_PROJECT_DIR.lstrip("/"))
        self.assertEqual(under_root["IMPORT_STAGING_DIR"], self.root / "opt/tmp")
        for name in ("NFQWS_CONFIG", "PROJECT_DIR", "IMPORT_STAGING_DIR"):
            with self.subTest(name=name):
                self.assertTrue(under_root[name].is_relative_to(self.root), under_root[name])

    def test_config_paths_are_absolute_for_a_relative_project_dir(self):
        # The tuner and diagnostics workers run with cwd=PROJECT_DIR: a relative path would be resolved twice.
        paths = self.config_paths(test_root=self.root, XKEEN_PROJECT_DIR="relative/project")
        project = Path(os.path.realpath(self.root)) / "relative" / "project"
        self.assertEqual(paths["PROJECT_DIR"], project)
        self.assertEqual(paths["ENGINE"], project / "apply-discord-nfqws2.sh")
        self.assertEqual(paths["DIAGNOSTICS"], project / "tools" / "router" / "xkeen_diagnostics.py")
        self.assertEqual([name for name, path in paths.items() if not path.is_absolute()], [])

    def test_config_empty_project_dir_means_the_default(self):
        self.assertEqual(self.config_paths(XKEEN_PROJECT_DIR="")["PROJECT_DIR"], Path(DEFAULT_PROJECT_DIR))
        under_root = self.config_paths(test_root=self.root, XKEEN_PROJECT_DIR="")
        self.assertEqual(under_root["PROJECT_DIR"], self.root / DEFAULT_PROJECT_DIR.lstrip("/"))


class PanelEntryGenerationTests(panel_harness.PanelTestCase):
    ns_name = "panel_entry_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def package_path(self, path, app_file):
        return self.ns.module("app")._package_path(path, app_file)

    def test_package_path_replaces_script_dir_with_router_dir(self):
        web, router, app = str(APP.parent), str(ROUTER_DIR), str(APP)
        given = [web, "/x"]
        self.assertEqual(self.package_path(given, app), [router, "/x"])
        self.assertEqual(given, [web, "/x"])
        self.assertEqual(self.package_path([web, router, "/x"], app), [router, "/x"])
        link = self.root / "web-link"
        link.symlink_to(APP.parent, target_is_directory=True)
        self.assertEqual(self.package_path([str(link), "/x"], app), [router, "/x"])
        with contextlib.chdir(APP.parent):
            self.assertEqual(self.package_path(["", "/x"], app), [router, "/x"])

    def test_package_path_puts_router_dir_first(self):
        # tools/router already on sys.path, but behind another entry (PYTHONPATH, an in-process import): it moves
        # to the front, so an earlier directory with another kdn package cannot shadow it.
        web, router, app = str(APP.parent), str(ROUTER_DIR), str(APP)
        self.assertEqual(self.package_path([web, "/x", router], app), [router, "/x"])
        self.assertEqual(self.package_path(["/x", router, "/y"], app), [router, "/x", "/y"])
        self.assertEqual(self.package_path(["/x", router, "/y", router], app), [router, "/x", "/y"])
        self.assertEqual(self.package_path([router, "/x"], app), [router, "/x"])

    def test_package_path_skips_dir_without_package(self):
        copy = self.root / "tools" / "router" / "kdn" / "web" / "app.py"
        copy.parent.mkdir(parents=True)
        shutil.copyfile(APP, copy)
        self.assertEqual(self.package_path(["/x", "/y"], str(copy)), ["/x", "/y"])

    def project_scripts(self, *, missing=()):
        """Paths for the five project scripts under the test root; those named in missing are not created."""
        directory = Path(tempfile.mkdtemp(dir=self.root))
        paths = {}
        for name in PROJECT_SCRIPTS:
            paths[name] = directory / name.lower()
            if name not in missing:
                paths[name].write_text("", encoding="utf-8")
        return paths

    def run_main(self, argv, *, scripts, reconcile_error=None):
        """Runs main(argv) with the startup parts replaced; returns the calls in order, stdout, Thread, loop, server.

        The calls are the banner line and the startup steps, in the order they happen.
        """
        calls = []
        recovery = mock.Mock(side_effect=lambda: calls.append("recovery"))
        loop = mock.Mock(name="automation_loop")
        server = mock.Mock()
        server.return_value.serve_forever.side_effect = lambda: calls.append("serve")
        thread = mock.Mock()
        thread.return_value.start.side_effect = lambda: calls.append("scheduler")
        def reconcile():
            calls.append("reconcile")
            if reconcile_error is not None:
                raise reconcile_error

        self.logger = mock.Mock()
        self.patch(start_automation_recovery=recovery, automation_loop=loop, reconcile_jobs=reconcile,
                   configure_logging=lambda *args, **kwargs: calls.append("logging") or self.logger,
                   redirect_std_streams=lambda logger: calls.append("redirect"), panel_logger=lambda: self.logger, **scripts)
        with (
            mock.patch.object(self.ns.module("server"), "PanelServer", server),
            mock.patch.object(self.ns["threading"], "Thread", thread),
            contextlib.redirect_stdout(OrderedStdout(calls)) as output,
        ):
            self.ns["main"](argv)
        return calls, output.getvalue(), thread, loop, server

    def test_main_dispatches_route_job(self):
        run_route_job = mock.Mock(return_value=7)
        self.patch(run_job=run_route_job)
        self.assertEqual(self.ns["main"](["app.py", "--route-job", "id", "switch", "a", "b"]), 7)
        run_route_job.assert_called_once_with("id", "switch", "a", "b")

    def test_main_reads_sys_argv_by_default(self):
        run_route_job = mock.Mock(return_value=0)
        self.patch(run_job=run_route_job)
        with mock.patch.object(sys, "argv", ["app.py", "--route-job", "id", "vpn-node", "node", "-"]):
            self.assertEqual(self.ns["main"](), 0)
        run_route_job.assert_called_once_with("id", "vpn-node", "node", "-")

    def test_main_refuses_without_project_scripts(self):
        for missing in PROJECT_SCRIPTS:
            with self.subTest(missing=missing):
                scripts = self.project_scripts(missing=(missing,))
                recovery, server = mock.Mock(), mock.Mock()
                self.patch(start_automation_recovery=recovery, **scripts)
                with mock.patch.object(self.ns.module("server"), "PanelServer", server):
                    with self.assertRaises(SystemExit) as raised:
                        self.ns["main"](["app.py"])
                listed = [str(scripts[name]) for name in PROJECT_SCRIPTS]
                self.assertEqual(
                    raised.exception.code,
                    f"Project scripts are missing. Expected {', '.join(listed[:-1])} and {listed[-1]}",
                )
                recovery.assert_not_called()
                server.assert_not_called()

    def test_main_starts_recovery_then_scheduler_then_server(self):
        scripts = self.project_scripts()
        calls, output, thread, loop, server = self.run_main(["app.py"], scripts=scripts)
        self.assertEqual(calls, ["logging", "redirect", "print", "reconcile", "recovery", "scheduler", "scheduler", "scheduler", "scheduler", "serve"])
        self.assertEqual(output, f"XKeen Control: http://{self.ns['BIND_HOST']}:{self.ns['PORT']}\n")
        self.assertEqual(thread.call_args_list, [mock.call(target=loop, daemon=True, name="zapret-automation"),
                                               mock.call(target=self.ns["reconcile_loop"], daemon=True, name="xkeen-job-reconcile"),
                                               mock.call(target=self.ns.module('domain.vpn_monitor').loop, daemon=True, name='vpn-node-monitor'),
                                               mock.call(target=self.ns.module('domain.notifications').notification_loop, daemon=True, name='notification-delivery')])
        server.assert_called_once_with((self.ns["BIND_HOST"], self.ns["PORT"]), self.ns["Handler"],
            max_threads=self.ns["MAX_HTTP_THREADS"], max_connections=self.ns["MAX_HTTP_CONNECTIONS"],
            first_line_timeout=self.ns["HTTP_FIRST_LINE_TIMEOUT"])

    def test_main_survives_a_reconcile_error(self):
        for error in (RuntimeError("fixture"), OSError("fixture")):
            with self.subTest(error=error):
                calls, *_rest = self.run_main(["app.py"], scripts=self.project_scripts(), reconcile_error=error)
                self.assertEqual(calls[-1], "serve")
                self.logger.exception.assert_called_once_with("startup reconciliation failed")

    def test_bind_failure_launches_no_recovery_or_scheduler(self):
        self.patch(configure_logging=mock.Mock(), redirect_std_streams=mock.Mock(),
                   start_automation_recovery=mock.Mock(), reconcile_jobs=mock.Mock(), **self.project_scripts())
        with mock.patch.object(self.ns.module("server"), "PanelServer", side_effect=OSError("address busy")), \
                mock.patch.object(self.ns["threading"], "Thread") as thread, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "address busy"):
                self.ns["main"](["app.py"])
            thread.assert_not_called()
        self.ns["start_automation_recovery"].assert_not_called()
        self.ns["reconcile_jobs"].assert_not_called()

    def test_main_serves_for_any_other_argument_list(self):
        # Only exactly six arguments with --route-job make a worker; every other list starts the server.
        scripts = self.project_scripts()
        for argv in (
            ["app.py", "--route-job", "id", "switch", "a"],
            ["app.py", "--route-job", "id", "switch", "a", "b", "c"],
            ["app.py", "--other", "id", "switch", "a", "b"],
            ["app.py", "--route-job"],
        ):
            with self.subTest(argv=argv):
                run_route_job = mock.Mock()
                self.patch(run_job=run_route_job)
                calls, _output, _thread, _loop, _server = self.run_main(argv, scripts=scripts)
                self.assertEqual(calls, ["logging", "redirect", "print", "reconcile", "recovery", "scheduler", "scheduler", "scheduler", "scheduler", "serve"])
                run_route_job.assert_not_called()

    def test_route_liveness_accepts_worker_of_previous_version(self):
        # The monolith spawned its route worker with the absolute path the shim ran:
        # PROJECT/tools/router/kdn/web/app.py.
        previous = Path(os.path.join(ROOT, "tools", "router", "kdn", "web", "app.py")).absolute()
        self.assertEqual(self.ns["ENTRY"], previous)
        entry = os.fsencode(str(previous))
        for command, alive in (
            ([b"python3", entry, b"--route-job", b"x"], True),
            ([b"python3", os.fsencode(str(self.root / "app.py")), b"--route-job", b"x"], False),
            ([b"python3", entry, b"--tuner-job", b"x"], False),
        ):
            with self.subTest(command=command), self.patched(job_command=lambda _pid, command=command: command):
                self.assertIs(self.ns["route_process_alive"](1), alive)

    def test_main_survives_an_unwritable_log_file(self):
        path = self.root / "log-is-a-directory"
        path.mkdir()
        self.patch(LOG_FILE=path, start_automation_recovery=mock.Mock(), reconcile_jobs=mock.Mock(), **self.project_scripts())
        module = self.ns.module("logsetup")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), mock.patch.object(self.ns["threading"], "Thread"), \
                mock.patch.object(self.ns.module("server"), "PanelServer") as server:
            try:
                self.ns["main"](["app.py"])
            finally:
                module.restore_std_streams()
            server.return_value.serve_forever.assert_called_once()
        self.assertIn("unavailable", stderr.getvalue())
        logger = module.panel_logger()
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


class NewWorkerScriptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.state_dir = self.root / "opt/tmp/xkeen-route-switch"
        self.state_dir.mkdir(parents=True)
        from target_fixture import version_executable
        version_executable(self.root / 'opt/sbin/xkeen')
        init = self.root / 'opt/etc/init.d/S05xkeen'
        init.parent.mkdir(parents=True)
        init.write_text('#!/bin/sh\nexit 0\n')
        init.chmod(0o700)

    def worker(self, operation, subject, data=None):
        state = {"job_id": JOB_ID, "operation": operation, "status": "queued", "_history_enabled": False}
        (self.state_dir / "state.json").write_text(json.dumps(state))
        payload = self.state_dir / "payload.json"
        if data is not None:
            payload.write_text(json.dumps({"job_id": JOB_ID, "data": data}))
        result = subprocess.run([sys.executable, str(APP), "--route-job", JOB_ID, operation, subject, "-"],
            env=child_env(test_root=self.root, XKEEN_PROJECT_DIR=str(self.project)), cwd="/", capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads((self.state_dir / "state.json").read_text())
        self.assertEqual((state["status"], state["result_ok"]), ("completed", True))
        self.assertFalse(payload.exists())
        return state

    def test_xkeen_script_mode_imports_table_and_runs_only_the_stub(self):
        xkeen = self.root / "opt/sbin/xkeen"
        xkeen.parent.mkdir(parents=True, exist_ok=True)
        xkeen.write_text("#!/bin/sh\n[ \"$1\" = -v ] && echo 'XKeen 2.1.1'\nexit 0\n")
        xkeen.chmod(0o755)
        xray = self.root / "xray"
        shutil.copy2("/usr/bin/sleep", xray)
        process = subprocess.Popen([str(xray), "30"])
        self.addCleanup(process.wait)
        self.addCleanup(process.terminate)
        state = self.worker("xkeen", "start")
        self.assertNotIn("health", state["result"])

    def test_apply_script_mode_leaves_no_payload_or_staged_profile(self):
        engine = self.project / "apply-discord-nfqws2.sh"
        engine.write_text("#!/bin/sh\nexit 0\n")
        state = self.worker("apply-profile", "import", {"service": "youtube", "candidate_id": "fixture"})
        self.assertIn("health", state["result"])
        self.assertFalse(list((self.root / "opt/tmp").glob("xkeen-profile-*.json")))


if __name__ == "__main__":
    unittest.main()

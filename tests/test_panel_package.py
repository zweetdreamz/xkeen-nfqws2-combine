"""The panel is the kdn.web module; the installer writes only a shim that runs it."""

from __future__ import annotations

import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import panel_harness


INSTALLER = panel_harness.ROOT / "tools" / "router" / "xkeen_control_script.sh"
SHIM = (
    "import os\n"
    "import runpy\n"
    'project = os.environ.get("XKEEN_PROJECT_DIR", "/opt/root/keenetic-discord-nfqws2")\n'
    'runpy.run_path(os.path.join(project, "tools", "router", "kdn", "web", "app.py"), run_name="__main__")\n'
)


class PanelPackageTests(panel_harness.PanelTestCase):
    ns_name = "panel_package_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_shim_runs_module_from_project_dir(self):
        stub = self.root / "project" / "tools" / "router" / "kdn" / "web" / "app.py"
        stub.parent.mkdir(parents=True)
        stub.write_text(
            "import sys\nprint('name', __name__)\nprint('file', __file__)\nprint('argv', sys.argv[1:])\n",
            encoding="utf-8",
        )
        shim = self.root / "app.py"
        shim.write_text(SHIM, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(shim), "--route-job", "x", "y", "z", "w"],
            env={**os.environ, "XKEEN_PROJECT_DIR": str(self.root / "project")},
            cwd="/",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("name __main__", result.stdout)
        self.assertIn(f"file {stub}", result.stdout)
        self.assertIn("argv ['--route-job', 'x', 'y', 'z', 'w']", result.stdout)

    def test_missing_asset_raises_clear_error(self):
        copy = self.root / "app.py"
        shutil.copyfile(panel_harness.APP, copy)
        # Asset ownership moved from the entry to read_routes; test that real
        # loader against an absent assets directory rather than the bootstrap.
        module = self.ns.module("read_routes")
        with mock.patch.object(module, "__file__", str(copy)), self.assertRaisesRegex(RuntimeError, "asset missing: index.html"):
            module._load_asset("index.html")

    def test_html_comes_from_the_asset_file(self):
        page = (panel_harness.APP.with_name("assets") / "index.html").read_text(encoding="utf-8")
        self.assertEqual(self.ns["HTML"], page)
        self.assertIn("__SERVICE_CONFIG_SECTION__", page)

    def test_route_worker_command_uses_module_file(self):
        job_dir = self.root / "route-job"
        job_id = "0123456789abcdef"
        state = {"job_id": job_id, "operation": "switch", "status": "queued"}
        with self.patched(
            ROUTE_JOB_DIR=job_dir,
            ROUTE_STATE=job_dir / "state.json",
            ROUTE_PID=job_dir / "worker.pid",
            ROUTE_LOG=job_dir / "process.log",
            ROUTE_APPLY_LOG=job_dir / "apply.log",
            ROUTE_HISTORY_DIR=self.root / "history",
        ):
            with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen:
                self.ns["launch_route_worker"](state, ["switch", "discord", "vpn"])
        self.assertEqual(
            popen.call_args.args[0],
            [sys.executable, str(panel_harness.APP), "--route-job", job_id, "switch", "discord", "vpn"],
        )

    def test_route_worker_entry_is_absolute_for_relative_module_file(self):
        # runpy.run_path keeps a relative __file__ when XKEEN_PROJECT_DIR is relative, while the worker
        # is spawned with cwd=PROJECT_DIR: a relative script path would be resolved there and not found.
        relative = os.path.relpath(panel_harness.APP)
        # The real app.py, run from the relative path as the shim runs it, sets ENTRY of this generation;
        # the patch puts the generation's own ENTRY back after the test.
        self.patch(ENTRY=self.ns["ENTRY"])
        runpy.run_path(relative, run_name="panel_package_test")
        job_dir = self.root / "route-job"
        state = {"job_id": "0123456789abcdef", "operation": "switch", "status": "queued"}
        with self.patched(
            PROJECT_DIR=self.root,
            ROUTE_JOB_DIR=job_dir,
            ROUTE_STATE=job_dir / "state.json",
            ROUTE_PID=job_dir / "worker.pid",
            ROUTE_LOG=job_dir / "process.log",
            ROUTE_APPLY_LOG=job_dir / "apply.log",
            ROUTE_HISTORY_DIR=self.root / "history",
        ):
            with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen:
                self.ns["launch_route_worker"](state, ["switch", "discord", "vpn"])
            argv = popen.call_args.args[0]
            entry = argv[1]
            self.assertEqual(entry, str(Path.cwd() / relative))
            self.assertTrue(Path(os.path.join(popen.call_args.kwargs["cwd"], entry)).is_file())
            argv_bytes = [os.fsencode(part) for part in argv]
            with self.patched(job_command=lambda _pid: argv_bytes):
                self.assertTrue(self.ns["route_process_alive"](4321))

    def test_installer_writes_shim_only(self):
        from target_fixture import installer_environment
        result = subprocess.run(
            ["sh", str(INSTALLER)],
            env=installer_environment({**os.environ, "XKEEN_WEB_DIR": str(self.root)}, self.root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        app = self.root / "app.py"
        self.assertEqual(app.read_text(encoding="utf-8"), SHIM)
        self.assertEqual(stat.S_IMODE(app.stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), [".installer-bin", "app.py"])
        self.assertIn(f"  {app}", result.stdout)


if __name__ == "__main__":
    unittest.main()

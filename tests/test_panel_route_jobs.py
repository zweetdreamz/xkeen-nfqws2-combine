"""Tests of the route jobs of the panel (kdn.web.domain.route_jobs): the job state and history, the snapshots
the jobs take, the worker process and the route command.

The VPN node manager the jobs run (kdn.web.domain.vpn) is here too. The HTTP endpoints are pinned in
test_panel_http.py and test_panel_endpoints.py.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from panel_fixtures import PanelUnitCase
import panel_harness


JOB_ID = "0123456789abcdef"
SLEEPER = [sys.executable, "-c", "import time; time.sleep(30)"]


class PanelRouteJobsTests(panel_harness.PanelTestCase):
    ns_name = "panel_route_jobs_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.job_dir = self.root / "route-job"
        self.job_dir.mkdir()
        self.patch(
            PROJECT_DIR=self.root / "project",
            ROUTE_JOB_DIR=self.job_dir,
            ROUTE_STATE=self.job_dir / "state.json",
            ROUTE_PID=self.job_dir / "worker.pid",
            ROUTE_LOG=self.job_dir / "process.log",
            ROUTE_APPLY_LOG=self.job_dir / "apply.log",
            ROUTE_HISTORY_DIR=self.root / "history",
        )
        (self.root / "project").mkdir()

    def test_route_command_timeout_stops_the_process_group(self):
        self.patch(update_route_state=lambda *_args, **_changes: True)
        started = time.monotonic()
        result = self.ns["run_route_command"](SLEEPER, JOB_ID, "switch", timeout=0)
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertTrue(result["output"].startswith("Команда превысила таймаут"))

    def test_route_command_timeout_uses_the_shared_stop_with_120_seconds(self):
        # The route command stops its group exactly as the other panel commands do: TERM, 120 s, KILL.
        calls = []
        real_stop = self.ns["stop_process_group"]

        def spy(process, grace):
            calls.append((process, grace))
            real_stop(process, grace)

        self.patch(update_route_state=lambda *_args, **_changes: True, stop_process_group=spy)
        result = self.ns["run_route_command"](SLEEPER, JOB_ID, "switch", timeout=0)
        self.assertEqual(result["code"], 124)
        self.assertEqual([grace for _process, grace in calls], [120])
        self.assertIsNotNone(calls[0][0].returncode)

    def test_route_worker_gets_an_absolute_project_dir(self):
        # The worker runs with cwd=PROJECT_DIR: a relative XKEEN_PROJECT_DIR of the panel would be resolved twice.
        state = {"job_id": JOB_ID, "operation": "switch", "status": "queued"}
        project_dir = self.ns["PROJECT_DIR"]
        self.assertTrue(project_dir.is_absolute())
        with mock.patch.dict(os.environ, {"XKEEN_PROJECT_DIR": "relative/project"}):
            with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen:
                self.ns["launch_route_worker"](state, ["switch", "discord", "vpn"])
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["XKEEN_PROJECT_DIR"], str(project_dir))
        self.assertEqual(popen.call_args.kwargs["cwd"], project_dir)
        self.assertEqual(environment["PYTHONUNBUFFERED"], "1")

    def test_vpn_manager_loads_the_script_once_and_caches_it_on_the_vpn_module(self):
        script = self.root / "vpn_node_manager.py"
        script.write_text("class VpnNodeManager:\n    pass\n", encoding="utf-8")
        self.patch(VPN_MANAGER_SCRIPT=script, VPN_MODULE=None)
        first = self.ns["vpn_manager"]()
        module = self.ns["VPN_MODULE"]
        self.assertIsNotNone(module)
        self.assertIsInstance(first, module.VpnNodeManager)
        # The second call reuses the loaded module; the cache is the attribute of the module that owns vpn_manager.
        self.assertIsInstance(self.ns["vpn_manager"](), module.VpnNodeManager)
        self.assertIs(self.ns["VPN_MODULE"], module)
        owner, _name = self.ns.owner("vpn_manager")
        self.assertIs(vars(owner)["VPN_MODULE"], module)

    def test_vpn_jobs_do_not_start_while_another_job_runs(self):
        # Both VPN jobs are route jobs: they refuse to start beside a tuner, a diagnostic or a route job.
        self.patch(tuner_active=lambda: True, read_status=lambda: self.fail("the engine must not be asked"))
        for start, arguments in ((self.ns["start_vpn_node_job"], ("vless_2",)), (self.ns["start_vpn_recovery_job"], ())):
            with self.subTest(start=start.__name__), self.assertRaisesRegex(RuntimeError, "во время подбора"):
                start(*arguments)


class PanelRouteWorkerTests(panel_harness.PanelTestCase):
    """The route worker as a real process: the entry file run as a script, as the router runs it."""

    ns_name = "panel_route_worker_test"

    def test_worker_runs_a_switch_job_when_the_project_dir_is_relative(self):
        # The panel started with a relative XKEEN_PROJECT_DIR; the worker runs with cwd=PROJECT_DIR and must still
        # find the engine scripts and the job files: the panel hands it the absolute directory.
        root = self.fresh_root()
        project_dir = self.ns["PROJECT_DIR"]
        project_dir.mkdir(parents=True)
        (project_dir / "set-service-route.sh").write_text('echo "route $1 -> $2"\n', encoding="utf-8")
        environment = {
            "KD_TEST_ROOT": str(root),
            "KD_ALLOW_TEST_ROOT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "XKEEN_PROJECT_DIR": os.path.relpath(project_dir, root),
        }
        with mock.patch.dict(os.environ, environment), contextlib.chdir(root):
            job_id = self.ns["start_route_job"]("youtube", "direct")["job_id"]
        deadline = time.monotonic() + 60
        state = self.ns["safe_json_file"](self.ns["ROUTE_STATE"])
        while state["status"] not in ("completed", "failed") and time.monotonic() < deadline:
            time.sleep(0.2)
            state = self.ns["safe_json_file"](self.ns["ROUTE_STATE"])
        log = self.ns["ROUTE_LOG"].read_text(encoding="utf-8", errors="replace")
        self.assertEqual(state["job_id"], job_id, log)
        self.assertEqual((state["status"], state.get("code")), ("completed", 0), log)
        self.assertEqual(state["output"], "route youtube -> direct")


class SnapshotTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        self.snapshots = self.root / "snapshots"
        self.snapshots.mkdir()
        self.patch(SNAPSHOT_DIR=self.snapshots)

    def make_snapshot(self, parent, name, manifest=True, state=True):
        path = parent / name
        path.mkdir(parents=True)
        if state:
            (path / "STATE.tsv").write_text("PURPOSE\tpre-apply\n", encoding="utf-8")
        if manifest:
            (path / "MANIFEST").write_text("fixture\n", encoding="utf-8")
        return path

    def test_safe_snapshot_accepts_valid_directory(self):
        path = self.make_snapshot(self.snapshots, "20260815-010203-42")
        self.assertTrue(self.ns["safe_snapshot"](path))

    def test_safe_snapshot_rejections(self):
        safe = self.ns["safe_snapshot"]
        valid = self.make_snapshot(self.snapshots, "valid-1")
        link = self.snapshots / "link-1"
        link.symlink_to(valid, target_is_directory=True)
        self.assertFalse(safe(link))

        elsewhere = self.make_snapshot(self.root / "elsewhere", "valid-2")
        self.assertFalse(safe(elsewhere))
        nested = self.make_snapshot(valid, "nested-3")
        self.assertFalse(safe(nested))

        self.assertFalse(safe(self.make_snapshot(self.snapshots, "no-manifest", manifest=False)))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "no-state", state=False)))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "bad_name")))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "bad.name")))
        self.assertFalse(safe(self.snapshots / "missing"))

        regular = self.snapshots / "regular-file"
        regular.write_text("x", encoding="utf-8")
        self.assertFalse(safe(regular))

        (valid / "MANIFEST").unlink()
        (valid / "MANIFEST").mkdir()
        self.assertFalse(safe(valid))

    def test_safe_snapshot_missing_snapshot_dir(self):
        path = self.make_snapshot(self.snapshots, "valid-1")
        self.patch(SNAPSHOT_DIR=self.root / "absent")
        self.assertFalse(self.ns["safe_snapshot"](path))

    def test_parse_snapshot_from_output(self):
        parse = self.ns["parse_snapshot_from_output"]
        snapshot = self.make_snapshot(self.snapshots, "20260815-010203-42")
        self.assertEqual(parse(f"Snapshot created: {snapshot}\nApply complete."), str(snapshot))
        self.assertEqual(
            parse(f"log\nRescue snapshot of current state: {snapshot}\nRestore complete: x"),
            str(snapshot),
        )
        self.assertEqual(parse(f"Snapshot created: {snapshot}/STATE.tsv"), str(snapshot))

    def test_parse_snapshot_from_output_rejections(self):
        parse = self.ns["parse_snapshot_from_output"]
        outside = self.make_snapshot(self.root / "other", "20260815-010203-42")
        self.assertEqual(parse(f"Snapshot created: {outside}"), "")
        self.assertEqual(parse("Apply complete."), "")
        self.assertEqual(parse(""), "")
        self.assertEqual(parse(f"Snapshot: {self.snapshots}/20260815-010203-42"), "")
        self.assertEqual(parse(f"Snapshot created: {self.snapshots}/missing-1"), "")
        broken = self.make_snapshot(self.snapshots, "broken-1", manifest=False)
        self.assertEqual(parse(f"Snapshot created: {broken}"), "")
        self.assertEqual(parse(f"Snapshot created: {self.snapshots}/../etc"), "")


class RouteJobTests(PanelUnitCase):
    JOB_ID = "0123456789abcdef"

    def setUp(self):
        super().setUp()
        job_dir = self.root / "route-job"
        self.patch(
            ROUTE_JOB_DIR=job_dir,
            ROUTE_STATE=job_dir / "state.json",
            ROUTE_PID=job_dir / "worker.pid",
            ROUTE_LOG=job_dir / "process.log",
            ROUTE_APPLY_LOG=job_dir / "apply.log",
            ROUTE_HISTORY_DIR=self.root / "history",
            SNAPSHOT_DIR=self.root / "snapshots",
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            ENTRY=self.root / "app.py",
        )
        self.job_dir = job_dir

    def write_state(self, state):
        self.job_dir.mkdir(parents=True, exist_ok=True)
        self.ns["ROUTE_STATE"].write_text(json.dumps(state), encoding="utf-8")

    def read_state(self):
        return json.loads(self.ns["ROUTE_STATE"].read_text(encoding="utf-8"))

    def test_update_route_state(self):
        update = self.ns["update_route_state"]
        self.assertFalse(update(self.JOB_ID, status="running"))
        self.write_state({"job_id": "ffffffffffffffff", "status": "queued"})
        self.assertFalse(update(self.JOB_ID, status="running"))
        self.assertEqual(self.read_state(), {"job_id": "ffffffffffffffff", "status": "queued"})
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        self.assertTrue(update(self.JOB_ID, status="running", progress=10))
        self.assertEqual(self.read_state(), {"job_id": self.JOB_ID, "status": "running", "progress": 10})
        self.ns["ROUTE_STATE"].write_text("{broken", encoding="utf-8")
        self.assertFalse(update(self.JOB_ID, status="running"))

    def test_history_write_update_and_read(self):
        entry = {"job_id": self.JOB_ID, "status": "running", "created_utc": "2026-08-15T00:00:00Z"}
        self.ns["write_history"](entry)
        path = self.root / "history" / f"{self.JOB_ID}.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), entry)
        self.assertEqual((self.root / "history").stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.ns["update_history"](self.JOB_ID, status="completed"))
        self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["status"], "completed")
        self.assertFalse(self.ns["update_history"]("ffffffffffffffff", status="x"))
        self.assertFalse(self.ns["update_history"]("not-a-job", status="x"))
        with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
            self.ns["write_history"]({"job_id": "../x"})

    def test_history_id_mismatch(self):
        other = "ffffffffffffffff"
        history = self.root / "history"
        history.mkdir()
        (history / f"{other}.json").write_text(json.dumps({"job_id": self.JOB_ID}), encoding="utf-8")
        self.assertFalse(self.ns["update_history"](other, status="x"))
        with self.assertRaisesRegex(ValueError, "ID записи истории не совпадает"):
            self.ns["read_history_item"](other)

    def test_route_history_reports_corrupt_entries(self):
        history = self.root / "history"
        history.mkdir()
        (history / "aaaaaaaaaaaaaaaa.json").write_text(
            json.dumps({"job_id": "aaaaaaaaaaaaaaaa", "created_utc": "2026-08-15T01:00:00Z", "snapshot": ""}),
            encoding="utf-8",
        )
        (history / "bbbbbbbbbbbbbbbb.json").write_text(json.dumps({"job_id": "cccccccccccccccc"}), encoding="utf-8")
        (history / "dddddddddddddddd.json").write_text("{broken", encoding="utf-8")
        (history / "ignored.json").write_text("{}", encoding="utf-8")
        items = {item["job_id"]: item for item in self.ns["route_history"]()}
        self.assertEqual(set(items), {"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "dddddddddddddddd"})
        self.assertFalse(items["aaaaaaaaaaaaaaaa"]["rollback_available"])
        for job_id in ("bbbbbbbbbbbbbbbb", "dddddddddddddddd"):
            self.assertEqual(items[job_id]["status"], "error")
            self.assertFalse(items[job_id]["rollback_available"])
            self.assertIn("история повреждена", items[job_id]["error"])
        self.assertIn("ID файла не совпадает", items["bbbbbbbbbbbbbbbb"]["error"])

    def test_route_history_keeps_newest_entries_beyond_200_files(self):
        history = self.root / "history"
        history.mkdir()
        for index in range(210):
            job_id = f"{index:016x}"
            path = history / f"{job_id}.json"
            path.write_text(
                json.dumps({"job_id": job_id, "created_utc": f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z"}),
                encoding="utf-8",
            )
            os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))

        self.patch(ROUTE_HISTORY_DIR=history)
        # The bounded enumeration is still arbitrary order; sorting must happen
        # before the UI read limit, even when its input starts with old records.
        with mock.patch.object(self.ns.module('kdn.web.domain.history').fsutil, 'bounded_files',
                               return_value=sorted(history.glob('*.json'))):
            items = self.ns["route_history"]()
        self.assertEqual(len(items), self.ns["MAX_HISTORY_ITEMS"])
        self.assertEqual(items[0]["job_id"], f"{209:016x}")
        self.assertEqual(items[-1]["job_id"], f"{210 - self.ns['MAX_HISTORY_ITEMS']:016x}")

    def test_route_history_missing_directory(self):
        self.assertEqual(self.ns["route_history"](), [])

    def test_route_status_idle_without_state(self):
        status = self.ns["route_status"]()
        self.assertEqual(
            status,
            {"ok": True, "status": "idle", "active": False, "output": ""},
        )

    def test_route_status_marks_stale_running_job_failed(self):
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running"})
        self.write_state({"job_id": self.JOB_ID, "status": "running", "progress": 45})
        self.ns["ROUTE_APPLY_LOG"].write_text("line 1\n" + "x" * 1500 + "\n", encoding="utf-8")
        status = self.ns["route_status"]()
        self.assertTrue(status["ok"])
        self.assertFalse(status["active"])
        self.assertEqual(status["status"], "failed")
        self.assertIs(status["result_ok"], False)
        self.assertEqual(status["error"], "процесс переключения завершился неожиданно")
        self.assertNotIn("log_tail", status)
        self.assertEqual(self.read_state()["status"], "running")
        self.ns["reconcile_route_job"]()
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(history["status"], "failed")
        self.assertIs(history["result_ok"], False)
        self.assertEqual(history["error"], "процесс переключения завершился неожиданно")
        self.assertIn("finished_utc", history)

    def test_route_status_keeps_existing_error_and_ignores_pid_of_other_process(self):
        self.write_state({"job_id": self.JOB_ID, "status": "queued", "error": "boom"})
        self.ns["ROUTE_PID"].write_text(f"{os.getpid()}\n", encoding="ascii")
        status = self.ns["route_status"]()
        self.assertFalse(status["active"])
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["error"], "boom")

    def test_route_status_completed_and_corrupt_state(self):
        self.write_state({"job_id": self.JOB_ID, "status": "completed", "ok": False})
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "completed")
        self.assertTrue(status["ok"])
        self.ns["ROUTE_STATE"].write_text("[]", encoding="utf-8")
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "error")
        self.assertIn("state:", status["error"])
        link_target = self.root / "outside.log"
        link_target.write_text("secret\n", encoding="utf-8")
        self.ns["ROUTE_APPLY_LOG"].symlink_to(link_target)
        self.assertNotIn("log_tail", self.ns["route_status"]())
        self.assertEqual(self.ns["route_apply_log"](), "")

    def test_clear_previous_route_job_removes_files_and_symlinks(self):
        self.job_dir.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        self.ns["ROUTE_STATE"].symlink_to(outside)
        self.ns["ROUTE_PID"].write_text("123\n", encoding="ascii")
        self.ns["ROUTE_APPLY_LOG"].symlink_to(self.root / "dangling")
        keep = self.job_dir / "unrelated.txt"
        keep.write_text("x", encoding="utf-8")
        self.ns["clear_previous_route_job"]()
        for name in ("ROUTE_STATE", "ROUTE_PID", "ROUTE_LOG", "ROUTE_APPLY_LOG"):
            self.assertFalse(os.path.lexists(self.ns[name]), name)
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.assertTrue(keep.exists())
        self.assertEqual(self.job_dir.stat().st_mode & 0o777, 0o700)

    def test_clear_previous_route_job_creates_directory(self):
        self.ns["clear_previous_route_job"]()
        self.assertTrue(self.job_dir.is_dir())

    def test_clear_previous_route_job_refuses_directory(self):
        self.job_dir.mkdir()
        self.ns["ROUTE_LOG"].mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге задания"):
            self.ns["clear_previous_route_job"]()
        self.assertTrue(self.ns["ROUTE_LOG"].is_dir())

    def test_ensure_route_job_available(self):
        ensure = lambda: self.ns["COORDINATOR"].ensure_idle(self.ns["ROUTE_CHANGE"])
        idle = {"tuner_active": lambda: False, "diagnostic_active": lambda: False, "route_active": lambda: False}
        with self.patched(**idle):
            ensure()
        for name, message in (
            ("tuner_active", "во время подбора"),
            ("diagnostic_active", "во время диагностики"),
            ("route_active", "уже выполняется"),
        ):
            with self.subTest(active=name):
                with self.patched(**{**idle, name: lambda: True}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        ensure()

    def test_start_route_job_builds_state(self):
        captured = []

        def fake_launch(state, worker_args):
            captured.append((dict(state), list(worker_args)))
            return state

        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            current_routes_fast=lambda: {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
            launch_route_worker=fake_launch,
        )
        state = self.ns["start_route_job"]("discord-voice", "vpn")
        self.assertRegex(state["job_id"], r"^[0-9a-f]{16}$")
        self.assertEqual(state["operation"], "switch")
        self.assertEqual(state["status"], "queued")
        self.assertEqual(
            state["before_routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
        )
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "zapret", "discord-voice": "vless", "youtube": "direct"},
        )
        self.assertEqual(captured[0][1], ["switch", "discord-voice", "vpn"])
        state = self.ns["start_route_job"]("youtube", "zapret")
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "zapret"},
        )
        # The "discord" shorthand switches both Discord routes.
        state = self.ns["start_route_job"]("discord", "direct")
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "direct", "discord-voice": "direct", "youtube": "direct"},
        )
        with self.assertRaises(ValueError):
            self.ns["start_route_job"]("discord-tcp", "custom")
        self.assertEqual(len(captured), 3)

    def test_start_history_rollback_validation(self):
        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            launch_route_worker=lambda state, args: (state, args),
        )
        rollback = self.ns["start_history_rollback"]
        with self.assertRaises(FileNotFoundError):
            rollback(self.JOB_ID)
        with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
            rollback("bad")
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running"})
        with self.assertRaisesRegex(ValueError, "только для завершённой или прерванной операции"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "failed"})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "completed", "snapshot": ""})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "completed", "snapshot": 5})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["write_history"](
            {
                "job_id": self.JOB_ID,
                "status": "completed",
                "snapshot": str(snapshot),
                "before_routes": {"discord": "direct", "youtube": "direct"},
            }
        )
        state, args = rollback(self.JOB_ID)
        self.assertEqual(state["operation"], "rollback")
        self.assertEqual(state["rollback_of"], self.JOB_ID)
        self.assertEqual(state["target_snapshot"], str(snapshot))
        self.assertEqual(state["requested_routes"], {"discord": "direct", "youtube": "direct"})
        self.assertEqual(args, ["rollback", self.JOB_ID, str(snapshot)])
        # D10: an interrupted (failed) operation with its snapshot can be rolled back.
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "failed", "snapshot": str(snapshot)})
        state, args = rollback(self.JOB_ID)
        self.assertEqual(args, ["rollback", self.JOB_ID, str(snapshot)])

    def test_route_status_keeps_snapshot_of_a_job_that_died(self):
        # D10: the worker died after "Snapshot created:"; the snapshot is kept,
        # the failure is recorded once and rollback becomes available.
        snapshot = self.root / "snapshots" / "20261022-001904-29825"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running", "created_utc": "2026-10-22T00:19:00Z"})
        self.write_state({"job_id": self.JOB_ID, "status": "running", "progress": 65})
        self.ns["ROUTE_APPLY_LOG"].write_text(
            f"Snapshot created: {snapshot}\nPatching Xray routing: x\nRestarting XKeen...\n", encoding="utf-8",
        )
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["snapshot"], str(snapshot))
        self.assertEqual(self.read_state()["status"], "running")
        self.ns["reconcile_route_job"]()
        state = self.read_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["snapshot"], str(snapshot))
        self.assertFalse(state["active"])
        [item] = self.ns["route_history"]()
        self.assertEqual(item["status"], "failed")
        self.assertEqual(item["snapshot"], str(snapshot))
        self.assertTrue(item["rollback_available"])
        self.assertIn("Snapshot created:", item["output_tail"])
        finished = item["finished_utc"]
        with self.patched(utc_now=lambda: "2099-01-01T00:00:00Z"):
            self.assertEqual(self.ns["route_status"]()["finished_utc"], finished)
        self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["finished_utc"], finished)

    def test_route_status_does_not_fail_a_job_that_is_being_started(self):
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        with self.ns["JOB_START_LOCK"]:
            self.assertEqual(self.ns["route_status"]()["status"], "queued")
        self.assertEqual(self.read_state()["status"], "queued")
        self.assertEqual(self.ns["route_status"]()["status"], "failed")

    def test_launch_route_worker_writes_state_history_and_pid(self):
        process = mock.Mock(pid=4321)
        state = {
            "ok": True,
            "job_id": self.JOB_ID,
            "operation": "switch",
            "status": "queued",
            "stage_label": "В очереди",
            "progress": 0,
            "active": True,
            "output": "",
            "created_utc": "2026-08-15T00:00:00Z",
        }
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen:
            result = self.ns["launch_route_worker"](dict(state), ["switch", "discord", "vpn"])
        command = popen.call_args.args[0]
        self.assertEqual(
            command,
            [sys.executable, str(self.root / "app.py"), "--route-job", self.JOB_ID, "switch", "discord", "vpn"],
        )
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(result["pid"], 4321)
        self.assertEqual(self.ns["ROUTE_PID"].read_text(encoding="ascii"), "4321\n")
        self.assertEqual(self.read_state()["status"], "queued")
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(
            history,
            {
                "job_id": self.JOB_ID,
                "operation": "switch",
                "status": "queued",
                "created_utc": "2026-08-15T00:00:00Z",
            },
        )

    def dead_pid(self):
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait()
        return finished.pid

    def make_snapshot(self, name):
        snapshot = self.root / "snapshots" / name
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        return snapshot

    def test_new_route_job_marks_previous_dead_job_failed_first(self):
        # The previous worker died and nobody polled the status: starting the
        # next job must record the failure and keep the snapshot before the
        # job files are cleared.
        snapshot = self.make_snapshot("20261028-000000-1")
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running", "created_utc": "2026-10-28T00:00:00Z"})
        self.write_state({"job_id": self.JOB_ID, "status": "running", "progress": 65})
        self.ns["ROUTE_PID"].write_text(f"{self.dead_pid()}\n", encoding="ascii")
        self.ns["ROUTE_APPLY_LOG"].write_text(f"Snapshot created: {snapshot}\nRestarting XKeen...\n", encoding="utf-8")
        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            current_routes_fast=lambda: {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
        )
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)):
            new_state = self.ns["start_route_job"]("youtube", "zapret")
        items = {item["job_id"]: item for item in self.ns["route_history"]()}
        old = items[self.JOB_ID]
        self.assertEqual(old["status"], "failed")
        self.assertEqual(old["snapshot"], str(snapshot))
        self.assertTrue(old["rollback_available"])
        self.assertIn("Snapshot created:", old["output_tail"])
        self.assertEqual(items[new_state["job_id"]]["status"], "queued")
        self.assertEqual(self.read_state()["job_id"], new_state["job_id"])

    def test_reconcile_route_job_leaves_other_states_alone(self):
        reconcile = self.ns["reconcile_route_job"]
        self.assertIsNone(reconcile())
        for status in ("completed", "failed", "idle"):
            with self.subTest(status=status):
                self.write_state({"job_id": self.JOB_ID, "status": status})
                self.assertIsNone(reconcile())
                self.assertEqual(self.read_state(), {"job_id": self.JOB_ID, "status": status})
        self.ns["ROUTE_STATE"].write_text("{broken", encoding="utf-8")
        self.assertIsNone(reconcile())
        self.assertEqual(self.ns["ROUTE_STATE"].read_text(encoding="utf-8"), "{broken")

    def test_reconcile_route_job_marks_dead_queued_job_once(self):
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "queued"})
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        self.ns["reconcile_route_job"]()
        failed = self.read_state()
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["status"], "failed")
        with self.patched(utc_now=lambda: "2099-01-01T00:00:00Z"):
            self.ns["reconcile_route_job"]()
        self.assertEqual(self.read_state(), failed)

    def test_reconcile_route_job_waits_for_a_job_being_started(self):
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        with self.ns["JOB_START_LOCK"]:
            self.ns["reconcile_route_job"]()
            self.assertEqual(self.read_state()["status"], "queued")
            self.ns["reconcile_route_job"](holds_start_lock=True)
        self.assertEqual(self.read_state()["status"], "failed")

    def test_launch_route_worker_records_spawn_failure(self):
        state = {"job_id": self.JOB_ID, "status": "queued"}
        with mock.patch.object(self.ns["subprocess"], "Popen", side_effect=OSError("no exec")):
            with self.assertRaisesRegex(OSError, "no exec"):
                self.ns["launch_route_worker"](dict(state), ["switch", "discord", "vpn"])
        saved = self.read_state()
        self.assertEqual(saved["status"], "failed")
        self.assertIs(saved["active"], False)
        self.assertEqual(saved["error"], "no exec")
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(history["status"], "failed")
        self.assertFalse(self.ns["ROUTE_PID"].exists())

    def test_run_route_job_rejects_bad_arguments(self):
        for operation, subject, target in (
            ("bogus", "discord", "vpn"),
            ("switch", "discord", "custom"),
            ("rollback", "bad-id", "/x"),
            ("rollback", "ffffffffffffffff", str(self.root / "snapshots" / "missing")),
        ):
            with self.subTest(operation=operation, subject=subject, target=target):
                self.ns["write_history"]({"job_id": self.JOB_ID, "status": "queued"})
                self.write_state({"job_id": self.JOB_ID, "status": "queued"})
                with self.patched(run_route_command=mock.Mock(side_effect=AssertionError)):
                    code = self.ns["run_route_job"](self.JOB_ID, operation, subject, target)
                self.assertEqual(code, 2)
                state = self.read_state()
                self.assertEqual(state["status"], "failed")
                self.assertEqual(state["stage"], "failed")
                self.assertEqual(state["stage_label"], "Ошибка запуска")
                self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["status"], "failed")

    def test_run_route_job_stops_when_state_belongs_to_other_job(self):
        self.write_state({"job_id": "ffffffffffffffff", "status": "queued"})
        runner = mock.Mock(side_effect=AssertionError("must not run"))
        with self.patched(run_route_command=runner):
            self.assertEqual(self.ns["run_route_job"](self.JOB_ID, "switch", "discord", "vpn"), 2)
        runner.assert_not_called()

    def test_run_route_job_switch_success_and_failure(self):
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["NFQWS_CONFIG"].write_text("# Active routes: Discord=vless, YouTube=direct.\n", encoding="utf-8")
        for ok, code, status, label in ((True, 0, "completed", "Готово"), (False, 3, "failed", "Ошибка и откат")):
            with self.subTest(ok=ok):
                self.ns["write_history"]({"job_id": self.JOB_ID, "status": "queued"})
                self.write_state({"job_id": self.JOB_ID, "status": "queued"})
                runner = mock.Mock(return_value={"ok": ok, "code": code, "output": f"Snapshot created: {snapshot}\ndone"})
                with self.patched(run_route_command=runner):
                    result = self.ns["run_route_job"](self.JOB_ID, "switch", "discord", "vpn")
                self.assertEqual(result, code)
                command, job_id, operation = runner.call_args.args
                self.assertEqual(command[0], "/bin/sh")
                self.assertEqual(command[2:], ["discord", "vpn", "--core", "auto", "--yes-router"])
                self.assertEqual((job_id, operation), (self.JOB_ID, "switch"))
                state = self.read_state()
                self.assertEqual(state["status"], status)
                self.assertEqual(state["stage_label"], label)
                self.assertEqual(state["progress"], 100)
                self.assertEqual(state["snapshot"], str(snapshot))
                self.assertEqual(
                    state["after_routes"],
                    {"discord-tcp": "vless", "discord-voice": "vless", "youtube": "direct", "telegram": "unmanaged"},
                )
                self.assertIn("started_utc", state)
                history = self.ns["read_history_item"](self.JOB_ID)
                self.assertEqual(history["status"], status)
                self.assertEqual(history["code"], code)
                self.assertTrue(history["output_tail"].endswith("done"))

    def test_run_route_command_tracks_stage_and_exit_code(self):
        self.job_dir.mkdir()
        self.write_state({"job_id": self.JOB_ID, "status": "running"})
        script = (
            "import sys, time; print('Snapshot created: /fixture', flush=True); "
            "time.sleep(1.5); print('done'); sys.exit(3)"
        )
        result = self.ns["run_route_command"]([sys.executable, "-c", script], self.JOB_ID, "switch")
        self.assertEqual(result, {"ok": False, "code": 3, "output": "Snapshot created: /fixture\ndone"})
        state = self.read_state()
        self.assertEqual((state["stage"], state["progress"]), ("snapshot", 25))
        self.assertEqual(
            self.ns["ROUTE_APPLY_LOG"].read_text(encoding="utf-8").strip(),
            "Snapshot created: /fixture\ndone",
        )

    def test_run_route_command_timeout_terminates_process(self):
        self.job_dir.mkdir()
        result = self.ns["run_route_command"](
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
            self.JOB_ID,
            "switch",
            timeout=0,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertTrue(result["output"].startswith("Команда превысила таймаут"))
        self.assertIn("started", result["output"])

    def test_run_route_job_rollback_command(self):
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        runner = mock.Mock(return_value={"ok": True, "code": 0, "output": ""})
        with self.patched(run_route_command=runner):
            self.assertEqual(self.ns["run_route_job"](self.JOB_ID, "rollback", "ffffffffffffffff", str(snapshot)), 0)
        command = runner.call_args.args[0]
        self.assertEqual(command[2:], ["--rollback-snapshot", str(snapshot), "--yes-router"])
        self.assertEqual(self.read_state()["snapshot"], "")


if __name__ == "__main__":
    unittest.main()

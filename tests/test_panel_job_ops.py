"""New operations run only in the worker, with generation-safe payload cleanup."""
import threading
from types import SimpleNamespace
from unittest import mock

import panel_harness


class WorkerTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.domain.job_ops",)

    def setUp(self):
        self.root = self.fresh_root()
        self.ops = self.ns.module("job_ops")
        self.jobs = self.ns.module("jobfiles")
        self.route = self.ns.module("route_jobs")
        self.cfg = self.ns.module("config")
        self.spec = self.ns.module("kdn.jobs.jobspec")
        self.job_id = "a" * 16
        self.patch(current_routes_fast=lambda: {}, config_health=lambda: {"ok": True, "all_ok": True})

    def prepare(self, operation="xkeen", data=None, job_id=None):
        job_id = job_id or self.job_id
        self.jobs.ROUTE_STORE.prepare(self.spec.JobSpec("route", operation, job_id, [],
            initial={"job_id": job_id, "operation": operation, "status": "queued", "_history_enabled": False}))
        if data is not None:
            self.route.stage_payload(job_id, data)

    def result(self):
        return self.route.route_result(self.job_id)

    def test_xkeen_expected_liveness_and_no_history(self):
        for action in ("start", "restart", "stop"):
            with self.subTest(action=action):
                self.prepare()
                with mock.patch.object(self.ops.engine, "run_xkeen_action", return_value={"ok": True, "code": 0, "output": "done"}) as command:
                    self.assertEqual(self.ops.run_job(self.job_id, "xkeen", action, "-"), 0)
                    command.assert_called_once_with([str(self.cfg.XKEEN_INIT), action] + ([] if action == "stop" else ["on"]), xray_expected=action != "stop")
                self.assertEqual(self.result()["status"], "completed")
                self.assertNotIn("health", self.result()["result"])
                self.assertFalse(self.cfg.ROUTE_HISTORY_DIR.exists())

    def test_apply_success_failure_and_exception_clean_payload(self):
        for outcome in ({"ok": True, "code": 0, "output": "applied"}, {"ok": False, "code": 3, "output": "failed"}, OSError("fixture")):
            with self.subTest(outcome=outcome):
                self.prepare("apply-profile", {"service": "youtube"})
                patch = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": dict(outcome)}
                with mock.patch.object(self.ops.engine, "apply_profile", **patch) as apply:
                    code = self.ops.run_job(self.job_id, "apply-profile", "import", "-")
                    apply.assert_called_once_with({"service": "youtube"})
                self.assertFalse(self.jobs.route_payload_path().exists())
                self.assertEqual(self.result()["status"], "completed" if code == 0 else "failed")
                self.assertEqual("health" in self.result()["result"], code == 0)

    def test_clear_rollback_and_failed_vpn_probe_are_completed_results(self):
        for operation, subject, name in (("import-clear", "youtube", "clear_imported_profile"),
                                         ("import-rollback", "-", "rollback_import")):
            self.prepare(operation)
            with mock.patch.object(self.ops.engine, name, return_value={"ok": True, "code": 0, "output": ""}):
                self.assertEqual(self.ops.run_job(self.job_id, operation, subject, "-"), 0)
                self.assertIn("health", self.result()["result"])
        manager = SimpleNamespace(check=lambda name: {"ok": True, "health": {"ok": False, "detail": "offline"}},
                                  add=lambda name, source: {"node": {"id": name}})
        with mock.patch.object(self.ops.vpn, "vpn_manager", return_value=manager):
            self.prepare("vpn-check")
            self.assertEqual(self.ops.run_job(self.job_id, "vpn-check", "node1", "-"), 0)
            self.assertFalse(self.result()["health"]["ok"])
            self.assertEqual(self.result()["status"], "completed")
            self.prepare("vpn-add", {"name": "node1", "source": "fixture"})
            self.assertEqual(self.ops.run_job(self.job_id, "vpn-add", "node1", "-"), 0)
            self.assertEqual(self.result()["node"], {"id": "node1"})
            self.assertFalse(self.jobs.route_payload_path().exists())

    def test_unicode_name_stays_in_private_payload_not_worker_subject(self):
        manager = SimpleNamespace(add=mock.Mock(return_value={'node': {'id': 'node_123'}}))
        with mock.patch.object(self.ops.vpn, 'vpn_manager', return_value=manager):
            self.prepare('vpn-add', {'name': 'Европа', 'source': 'fixture'})
            self.assertEqual(self.ops.run_job(self.job_id, 'vpn-add', 'new-node', '-'), 0)
            manager.add.assert_called_once_with('Европа', 'fixture')
            self.assertFalse(self.jobs.route_payload_path().exists())

    def test_missing_foreign_payload_bad_args_and_old_operations(self):
        self.prepare("apply-profile")
        self.assertEqual(self.ops.run_job(self.job_id, "apply-profile", "import", "-"), 2)
        self.prepare("apply-profile", {"new": True}, job_id="b" * 16)
        self.assertEqual(self.ops.run_job(self.job_id, "apply-profile", "import", "-"), 2)
        self.assertTrue(self.jobs.route_payload_path().exists())
        self.assertEqual(self.jobs.ROUTE_STORE.read_state()["job_id"], "b" * 16)
        for operation, subject in (("xkeen", "invalid"), ("import-clear", "invalid"), ("vpn-check", "bad;id")):
            self.prepare(operation)
            with mock.patch.object(self.route, "begin_route_job") as begin:
                self.assertEqual(self.ops.run_job(self.job_id, operation, subject, "-"), 2)
                begin.assert_not_called()
        with mock.patch.object(self.route, "run_route_job", return_value=7) as old:
            self.assertEqual(self.ops.run_job(self.job_id, "switch", "youtube", "direct"), 7)
            old.assert_called_once_with(self.job_id, "switch", "youtube", "direct")

    def test_post_check_failure_is_metadata_not_lost_success(self):
        with mock.patch.object(self.ops.health, "config_health", side_effect=ValueError("broken")):
            result = self.ops.with_post_checks({"ok": True, "output": "changed"})
            self.assertTrue(result["ok"])
            self.assertEqual(result["health_error"], "ValueError: broken")

    def test_reconciliation_payload_starting_and_loop_error(self):
        self.prepare(data={"secret": "fixture"})
        with self.jobs.JOB_START_LOCK:
            self.assertEqual(self.ops.reconcile_jobs(), [])
            self.assertTrue(self.jobs.route_payload_path().exists())
        self.assertIn("route", self.ops.reconcile_jobs())
        self.assertFalse(self.jobs.route_payload_path().exists())
        stop = threading.Event()
        calls = []

        def reconcile():
            calls.append(1)
            if len(calls) == 1:
                raise OSError("temporary")
            stop.set()

        with mock.patch.object(self.ops, "reconcile_jobs", side_effect=reconcile), \
                mock.patch.object(self.ops.logsetup, "panel_logger") as logger:
            self.ops.reconcile_loop(stop, interval=0.001)
            logger.return_value.exception.assert_called_once()
        self.assertEqual(len(calls), 2)

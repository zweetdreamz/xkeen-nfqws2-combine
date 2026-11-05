"""Job routes preserve admission order, result queries and read-only GET views."""
import json
from unittest import mock

import panel_harness


class JobRouteTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.api.job_routes",)

    def setUp(self):
        self.root = self.fresh_root()
        self.api = self.ns.module("job_routes")
        self.router = self.api.router.Router(self.api.JOB_ROUTES)
        self.cfg = self.ns.module("config")

    def dispatch(self, method, path, body=None, query=None):
        return self.router.dispatch(self.api.router.Request(method, path, body=body, query=query or {}))

    def test_choices_query_and_status_are_read_only(self):
        for path in ("/api/route/nope/vpn", "/api/route/youtube/nope"):
            self.assertEqual(self.dispatch("POST", path).status, 404)
        with mock.patch.object(self.api.route_jobs, "route_result", return_value={"ok": True, "output": "full"}) as result:
            self.assertEqual(self.dispatch("GET", "/api/route/result", query={"job_id": "A"}).status, 200)
            result.assert_called_once_with("A")
        self.assertEqual(self.dispatch("GET", "/api/route/result", query={"job_id": "unknown"}).status, 404)
        for path in (self.cfg.ROUTE_STATE, self.cfg.TUNER_STATE, self.cfg.DIAGNOSTIC_STATE, self.cfg.AUTOMATION_STATE):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"job_id":"aaaaaaaaaaaaaaaa","status":"running","kind":"health"}')
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        for route in self.api.JOB_ROUTES:
            if route.method == "GET":
                self.assertEqual(self.dispatch("GET", route.pattern).status, 200)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_busy_before_validation_and_verdict_bad_body_is_400(self):
        self.cfg.AUTOTUNER.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.AUTOTUNER.touch()
        with self.patched(route_active=lambda: True):
            answer = self.dispatch("POST", "/api/tuner/start", body=None)
            self.assertEqual((answer.status, json.loads(answer.body)["error"]), (409, "сначала завершите переключение маршрута"))
        self.assertEqual(self.dispatch("POST", "/api/tuner/verdict", body={"works": "yes"}).status, 400)

    def test_starts_are_only_domain_calls(self):
        for path, module, name, args in (("/api/route/youtube/direct", self.api.route_jobs, "start_route_job", ("youtube", "direct")),
                                        ("/api/history/rollback/A", self.api.route_jobs, "start_history_rollback", ("A",)),
                                        ("/api/vpn-nodes/activate/node1", self.api.vpn, "start_vpn_node_job", ("node1",)),
                                        ("/api/vpn-nodes/recover", self.api.vpn, "start_vpn_recovery_job", ())):
            with self.subTest(path=path), mock.patch.object(module, name, return_value={"ok": True, "job_id": "A"}) as start:
                self.assertEqual(self.dispatch("POST", path).status, 202)
                start.assert_called_once_with(*args)

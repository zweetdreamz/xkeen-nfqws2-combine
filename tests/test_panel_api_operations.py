"""HTTP operation routes enqueue only, preserving validation/busy precedence."""
import json
from unittest import mock

import panel_harness


class OperationRouteTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.api.operation_routes",)

    def setUp(self):
        self.fresh_root()
        self.api = self.ns.module("operation_routes")
        self.router = self.api.router.Router(self.api.OPERATION_ROUTES)

    def post(self, path, body=None):
        return self.router.dispatch(self.api.router.Request("POST", path, body=body))

    def test_route_arguments_and_202(self):
        cases = [("/api/xkeen/restart", "start_xkeen_job", ("restart",)),
                 ("/api/import/clear/youtube", "start_import_clear_job", ("youtube",)),
                 ("/api/import/rollback", "start_import_rollback_job", ()),
                 ("/api/profiles/apply/youtube/v1", "start_version_apply_job", ("youtube", "v1")),
                 ("/api/tuner/apply", "start_tuner_apply_job", ()),
                 ("/api/vpn-nodes/check/node1", "start_vpn_check_job", ("node1",))]
        for path, name, args in cases:
            with self.subTest(path=path), mock.patch.object(self.api.operations, name, return_value={"ok": True, "job_id": "A"}) as start:
                answer = self.post(path)
                self.assertEqual((answer.status, json.loads(answer.body)), (202, {"ok": True, "job_id": "A"}))
                start.assert_called_once_with(*args)
        for path in ("/api/xkeen/nope", "/api/import/clear/nope"):
            self.assertEqual(self.post(path).status, 404)
        self.assertTrue(all(route.automation_blocks for route in self.api.OPERATION_ROUTES))

    def test_precedence_and_vpn_body_validation(self):
        with self.patched(tuner_active=lambda: True):
            self.assertEqual(self.post("/api/tuner/apply").status, 409)
            self.assertEqual(self.post("/api/profiles/apply/youtube/bad").status, 409)
            with mock.patch.object(self.api.validation, "validate_report", side_effect=ValueError("bad")):
                self.assertEqual(self.post("/api/import/apply").status, 400)
        for body in (None, {}, {"name": 5, "source": "x"}, {"name": "n", "source": "x" * 32769}):
            self.assertEqual(self.post("/api/vpn-nodes/add", body).status, 400)
        with mock.patch.object(self.api.operations, "start_vpn_add_job", return_value={"ok": True}) as start:
            self.assertEqual(self.post("/api/vpn-nodes/add", {"name": "node1", "source": "fixture"}).status, 202)
            start.assert_called_once_with("node1", "fixture")

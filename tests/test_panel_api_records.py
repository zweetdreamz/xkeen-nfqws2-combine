"""Record routes: transport-independent mappings and actual schedule safety checks."""
import json
from unittest import mock

import panel_harness
from test_panel_api_server import ServerCase


class RecordTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.api.record_routes",)

    def setUp(self):
        self.fresh_root()
        self.records = self.ns.module("kdn.web.api.record_routes")
        self.router = self.records.router.Router(self.records.RECORD_ROUTES)

    def post(self, path, body=None):
        return self.router.dispatch(self.records.router.Request("POST", path, body={} if body is None else body))

    def error(self, answer, code, text):
        self.assertEqual((answer.status, json.loads(answer.body)), (code, {"ok": False, "error": text}))

    def test_record_arguments_success_and_error_tables(self):
        r = self.records
        cases = [("/api/history/delete/" + "a" * 16, r.history, "delete_history_record", ("a" * 16,)),
                 ("/api/profile-versions/delete/youtube/v1", r.profiles, "delete_profile_version", ("youtube", "v1")),
                 ("/api/vpn-nodes/delete/node1", r.vpn, "remove_node", ("node1",)),
                 ("/api/vpn-nodes/sync-current", r.vpn, "sync_current", ())]
        for path, module, name, arguments in cases:
            with self.subTest(path=path), mock.patch.object(module, name, return_value={"ok": True, "value": "same"}) as call:
                self.assertEqual(json.loads(self.post(path).body), {"ok": True, "value": "same"})
                call.assert_called_once_with(*arguments)
            for kind, code in ((RuntimeError, 409), (ValueError, 400), (OSError, 400)):
                with self.subTest(path=path, kind=kind), mock.patch.object(module, name, side_effect=kind("old text")):
                    self.error(self.post(path), code, "old text")
        self.assertTrue(all(route.method == "POST" for route in r.RECORD_ROUTES))

    def test_vpn_update_route_and_strict_body(self):
        r = self.records
        with mock.patch.object(r.vpn, 'update_node', return_value={'ok': True, 'node': {'id': 'reserve'}}) as update:
            answer = self.post('/api/vpn-nodes/update/reserve', {'name': 'Европа'})
            self.assertEqual(answer.status, 200)
            update.assert_called_once_with('reserve', {'name': 'Европа'})
        with mock.patch.object(r.vpn, 'vpn_manager') as manager:
            for body in ({}, {'source': None}, {'password': 'SECRET'}, []):
                with self.subTest(body=body):
                    answer = self.post('/api/vpn-nodes/update/reserve', body)
                    self.assertEqual(answer.status, 400)
                    self.assertNotIn('SECRET', answer.body.decode())
            manager.assert_not_called()

    def test_update_errors_and_import_validation_mapping(self):
        r = self.records
        for kind in (OSError, RuntimeError, ValueError):
            with self.subTest(kind=kind), mock.patch.object(r.flowseal, "check_flowseal_update", side_effect=kind("upstream")):
                self.error(self.post("/api/updates/check"), 502, "upstream")
        with mock.patch.object(r.validation, "validate_report", return_value={"candidate_id": "A"}) as validate:
            answer = self.post("/api/import/validate", {"report": True})
            self.assertEqual(json.loads(answer.body), {"ok": True, "profile": {"candidate_id": "A"}})
            validate.assert_called_once_with({"report": True})
        with mock.patch.object(r.validation, "validate_report", side_effect=ValueError("invalid report")):
            self.error(self.post("/api/import/validate"), 400, "invalid report")

    def test_automation_save_fail_closed_disable_and_recovery_failed(self):
        r = self.records
        cfg = self.ns.module("config")
        cfg.AUTOMATION_STATE.parent.mkdir(parents=True, exist_ok=True)
        cfg.AUTOMATION_STATE.write_text("{broken")
        config = r.automation.default_automation_config()
        self.error(self.post("/api/automation/save", {**config, "enabled": True}), 400, r.automation.STATE_UNREADABLE)
        self.assertEqual(cfg.AUTOMATION_STATE.read_text(), "{broken")
        self.assertFalse(cfg.AUTOMATION_CONFIG.exists())
        disabled = self.post("/api/automation/save", config)
        self.assertEqual(disabled.status, 200)
        self.assertFalse(json.loads(disabled.body)["config"]["enabled"])
        r.automation.save_automation_state({"status": "recovery-failed"})
        self.error(self.post("/api/automation/save", {**config, "enabled": True}), 400,
                   "после неудачного отката сначала проверьте nfqws2 и выполните ручное восстановление")
        r.automation.save_automation_state({"status": "idle"})
        answer = self.post("/api/automation/save", config)
        self.assertTrue({"ok", "config", "state", "active", "next_run", "timezone"} <= json.loads(answer.body).keys())

    def test_automation_cancel_codes(self):
        r = self.records
        self.error(self.post("/api/automation/cancel"), 409, "задание расписания не выполняется")
        with r.automation.AUTOMATION_RUN_LOCK:
            r.automation.save_automation_state({"status": "running", "phase": "recovering"})
            self.error(self.post("/api/automation/cancel"), 409, "автоматическое восстановление нельзя остановить")
            r.automation.save_automation_state({"status": "running", "phase": "checking"})
            answer = self.post("/api/automation/cancel")
            self.assertEqual((answer.status, json.loads(answer.body)), (202, {"ok": True, "status": "cancelling"}))
            self.assertTrue(r.automation.AUTOMATION_CANCEL.is_set())

    def test_real_record_refusals_and_no_engine_mutation(self):
        r = self.records
        with self.patched(route_active=lambda: True):
            self.error(self.post("/api/history/delete/" + "a" * 16), 409, "нельзя удалять историю во время выполняющегося задания")
            self.error(self.post("/api/vpn-nodes/delete/node1"), 409, "переключение маршрута уже выполняется")
        engine = self.ns.module("engine")
        proc = self.ns.module("kdn.common.proc")
        with mock.patch.object(proc, "run_command", side_effect=AssertionError("router command")), \
                mock.patch.object(engine, "apply_profile", side_effect=AssertionError("router mutation")):
            config = r.automation.default_automation_config()
            self.assertEqual(self.post("/api/automation/save", config).status, 200)
            with mock.patch.object(r.validation, "validate_report", return_value={"candidate_id": "A"}):
                self.assertEqual(self.post("/api/import/validate").status, 200)


class HoldTransportTests(ServerCase):
    modules = ("kdn.web.api.record_routes", "kdn.web.api.server")

    def test_only_automation_cancel_bypasses_the_hold(self):
        records = self.ns.module("kdn.web.api.record_routes")
        with records.automation.AUTOMATION_RUN_LOCK, self.serving(*records.RECORD_ROUTES, held=lambda name: "held schedule") as server:
            self.assertEqual(self.post(server, path="/api/automation/cancel")[0], 202)
            for path in ("/api/automation/save", "/api/updates/check", "/api/history/delete/" + "a" * 16):
                with self.subTest(path=path):
                    status, _, body = self.post(server, path=path)
                    self.assertEqual((status, json.loads(body)["error"]), (409, "held schedule"))

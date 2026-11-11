"""Tests of the HTTP layer of the panel (kdn.web.app.Handler): a real server on 127.0.0.1, router commands forbidden."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from panel_fixtures import DIAGNOSTICS_MODULE, make_report
import panel_harness


class HttpLayerTests(panel_harness.PanelTestCase):
    ns_name = "panel_http_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        cls.root = root

        def forbidden(*_args, **_kwargs):
            raise AssertionError("router command must not run in tests")

        cls.patch_class(
            BIND_HOST="127.0.0.1",
            run_command=forbidden,
            apply_profile=forbidden,
            PROJECT_DIR=root / "project",
            ENGINE=root / "project" / "apply-discord-nfqws2.sh",
            SERVICE_SWITCH=root / "project" / "set-service-route.sh",
            AUTOTUNER=root / "project" / "zapret_autotune_job.py",
            DIAGNOSTICS=root / "project" / "xkeen_diagnostics.py",
            DISCORD_CACHE_HELPER=root / "project" / "reset-discord-cache.ps1",
            BROWSER_DIAGNOSTICS=root / "project" / "browser-diagnostics.js",
            XKEEN=str(root / "xkeen"),
            IMPORTED_PROFILE_DIR=root / "imported",
            PROFILE_VERSION_DIR=root / "versions",
            NFQWS_CONFIG=root / "nfqws2.conf",
            DISCORD_LIST=root / "user.list",
            XRAY_CONFIG_DIR=root / "xray",
            IMPORT_ROLLBACK_POINTER=root / "rollback.ptr",
            TUNER_JOB_DIR=root / "tuner",
            TUNER_STATE=root / "tuner" / "state.json",
            TUNER_RESULT=root / "tuner" / "result-report.json",
            TUNER_VERDICT=root / "tuner" / "verdict.txt",
            TUNER_PID=root / "tuner" / "panel-launch.pid",
            DIAGNOSTIC_JOB_DIR=root / "diagnostics",
            DIAGNOSTIC_STATE=root / "diagnostics" / "state.json",
            DIAGNOSTIC_PID=root / "diagnostics" / "panel-launch.pid",
            DIAGNOSTIC_LOG=root / "diagnostics" / "process.log",
            ROUTE_JOB_DIR=root / "route",
            ROUTE_STATE=root / "route" / "state.json",
            ROUTE_PID=root / "route" / "worker.pid",
            ROUTE_LOG=root / "route" / "process.log",
            ROUTE_APPLY_LOG=root / "route" / "apply.log",
            ROUTE_HISTORY_DIR=root / "history",
            SNAPSHOT_DIR=root / "snapshots",
            FLOWSEAL_UPDATE_STATE=root / "flowseal-update.json",
            FLOWSEAL_SOURCE_CACHE=root / "flowseal-sources.json",
            ENTRY=root / "app.py",
        )
        handler = cls.ns["Handler"]
        quiet = mock.patch.object(handler, "log_message", lambda *_args: None)
        quiet.start()
        cls.addClassCleanup(quiet.stop)
        cls.server = cls.ns["ThreadingHTTPServer"](("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        cls.patch_class(PORT=cls.port)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            return response, data
        finally:
            connection.close()

    def post(self, path, payload=None, *, raw=None, headers=None):
        body = raw if raw is not None else json.dumps({} if payload is None else payload).encode("utf-8")
        merged = {"X-XKeen-Control": "1", "Content-Type": "application/json"}
        merged.update(headers or {})
        return self.request("POST", path, body=body, headers=merged)

    def assertJsonError(self, response, data, status, fragment):
        self.assertEqual(response.status, status, data)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        payload = json.loads(data.decode("utf-8"))
        self.assertIs(payload["ok"], False)
        self.assertIn(fragment, payload["error"])
        return payload

    def operation(self, path, payload=None):
        """Assert real HTTP 202, run the captured worker locally, then GET its full result.

        Preserve the old command/timeout/health assertions without pretending
        the HTTP thread still executes the operation or returns its outcome.
        """
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen:
            response, data = self.post(path, payload)
        self.assertEqual(response.status, 202, data)
        queued = json.loads(data)
        args = popen.call_args.args[0][3:]
        self.assertEqual(args[0], queued["job_id"])
        self.ns["run_job"](*args)
        result_response, result_data = self.request("GET", "/api/route/result?job_id=" + queued["job_id"])
        self.assertEqual(result_response.status, 200, result_data)
        result = json.loads(result_data)
        completed = {"ok": result["result_ok"], "code": result["code"], "output": result["output"], **result.get("result", {})}
        return response, json.dumps(completed).encode()

    def test_get_root_returns_html_with_security_headers(self):
        response, data = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(int(response.getheader("Content-Length")), len(data))
        self.assertTrue(data.startswith(b"<!doctype html>"))
        page = data.decode("utf-8")
        self.assertIn('id="service-configs"', page)
        self.assertEqual(page.count('<details class="service-config"'), 4)
        self.assertNotIn("__SERVICE_CONFIG_", page)
        self.assertIn('data-tab="automation"', page)
        self.assertIn('id="automationSaveStatus"', page)
        self.assertRegex(
            page,
            r'<input(?=[^>]*\bid="autoEnabled")(?=[^>]*\btype="checkbox")'
            r'(?=[^>]*\brole="switch")[^>]*>',
        )
        self.assertIn('Сохранено. Расписание выключено.', page)

    def test_automation_api_starts_disabled_and_validates_saved_schedule(self):
        with self.patched(
            AUTOMATION_CONFIG=self.root / "automation-config.json",
            AUTOMATION_STATE=self.root / "automation-state.json",
        ):
            response, data = self.request("GET", "/api/automation")
            self.assertEqual(response.status, 200)
            default = json.loads(data)
            self.assertFalse(default["config"]["enabled"])
            config = default["config"]
            config["times"] = ["03:00", "15:00"]
            response, data = self.post("/api/automation/save", config)
            self.assertEqual(response.status, 200, data)
            self.assertEqual(json.loads(data)["config"]["times"], ["03:00", "15:00"])
            config["times"] = ["25:00"]
            response, data = self.post("/api/automation/save", config)
            self.assertJsonError(response, data, 400, "ЧЧ:ММ")
            config["times"] = ["03:00"]
            config["enabled"] = True
            self.ns["save_automation_state"]({"status": "recovery-failed", "transaction": {"service": "youtube"}})
            response, data = self.post("/api/automation/save", config)
            self.assertJsonError(response, data, 400, "ручное восстановление")

    def test_empty_automation_state_is_reported_not_fatal(self):
        state_file = self.root / "automation-state-empty.json"
        state_file.write_text("", encoding="utf-8")
        with self.patched(
            AUTOMATION_CONFIG=self.root / "automation-config-empty.json",
            AUTOMATION_STATE=state_file,
        ):
            response, data = self.request("GET", "/api/automation")
            self.assertEqual(response.status, 200, data)
            state = json.loads(data)["state"]
            self.assertEqual(state["status"], "idle")
            self.assertIn("ValueError", state["state_error"])
            self.ns["automation_note"]("x")
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual([event["message"] for event in saved["events"]], ["x"])
            response, data = self.request("GET", "/api/automation")
            self.assertEqual(response.status, 200, data)
            self.assertNotIn("state_error", json.loads(data)["state"])

    def test_automation_blocks_other_post_actions_while_running(self):
        lock = threading.Lock()
        lock.acquire()
        try:
            with self.patched(AUTOMATION_RUN_LOCK=lock):
                response, data = self.post("/api/xkeen/stop")
                self.assertJsonError(response, data, 409, "проверка по расписанию")
        finally:
            lock.release()

    def test_unknown_get_is_404(self):
        response, data = self.request("GET", "/api/nope")
        self.assertJsonError(response, data, 404, "unknown endpoint")
        response, data = self.request("GET", "/?x=1")
        self.assertEqual(response.status, 200)  # split_target now separates query from the route
        self.assertIn(b"<!doctype html>", data)

    def test_get_rejects_client_outside_lan(self):
        with self.patched(private_client=lambda _address: False):
            response, data = self.request("GET", "/")
        self.assertJsonError(response, data, 403, "client is outside LAN")

    def test_get_status_without_engine_is_500(self):
        response, data = self.request("GET", "/api/status")
        self.assertJsonError(response, data, 500, "project script not found")

    def test_get_download_missing_helper_is_404(self):
        response, data = self.request("GET", "/tools/reset-discord-cache.ps1")
        self.assertEqual(response.status, 404)
        self.assertIs(json.loads(data)["ok"], False)

    def test_get_download_helper(self):
        helper = self.root / "helper.ps1"
        helper.write_text("Write-Host 'ok'\n", encoding="utf-8")
        with self.patched(DISCORD_CACHE_HELPER=helper):
            response, data = self.request("GET", "/tools/reset-discord-cache.ps1")
        self.assertEqual(response.status, 200)
        self.assertEqual(
            response.getheader("Content-Disposition"),
            'attachment; filename="reset-discord-cache.ps1"',
        )
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(data, "Write-Host 'ok'\n".encode("utf-8-sig"))

    def test_get_read_only_endpoints(self):
        response, data = self.request("GET", "/api/history")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(data), {"ok": True, "items": []})
        response, data = self.request("GET", "/api/profile-versions")
        self.assertEqual(json.loads(data), {"ok": True, "versions": []})
        response, data = self.request("GET", "/api/imported")
        payload = json.loads(data)
        self.assertFalse(payload["rollback_available"])
        self.assertEqual([item["service"] for item in payload["profiles"]], ["youtube", "discord-tcp", "discord-voice"])
        response, data = self.request("GET", "/api/route/status")
        self.assertEqual(json.loads(data)["status"], "idle")
        response, data = self.request("GET", "/api/tuner/status")
        self.assertEqual(json.loads(data)["status"], "idle")
        response, data = self.request("GET", "/api/diagnostics/status")
        self.assertEqual(json.loads(data)["status"], "idle")

    def test_post_without_control_header_is_403(self):
        response, data = self.request(
            "POST",
            "/api/import/validate",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertJsonError(response, data, 403, "control header missing")
        response, data = self.post("/api/import/validate", headers={"X-XKeen-Control": "yes"})
        self.assertJsonError(response, data, 403, "control header missing")

    def test_post_with_wrong_host_is_403(self):
        for host in ("evil.example", f"127.0.0.1:{self.port + 1}", "localhost", f"localhost:{self.port}"):
            with self.subTest(host=host):
                response, data = self.post("/api/import/validate", headers={"Host": host})
                self.assertJsonError(response, data, 403, "unexpected Host header")

    def test_post_with_bare_bind_host_passes_host_check(self):
        response, data = self.post("/api/nope", headers={"Host": "127.0.0.1"})
        self.assertJsonError(response, data, 404, "unknown action")

    def test_post_with_foreign_origin_is_403(self):
        for origin in ("http://evil.example", f"http://127.0.0.1:{self.port + 1}", "null"):
            with self.subTest(origin=origin):
                response, data = self.post("/api/import/validate", headers={"Origin": origin})
                self.assertJsonError(response, data, 403, "cross-origin request denied")

    def test_post_with_same_origin_is_accepted(self):
        response, data = self.post(
            "/api/import/validate",
            make_report("youtube"),
            headers={"Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(response.status, 200, data)
        payload = json.loads(data)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["profile"]["service"], "youtube")

    def test_post_rejects_client_outside_lan(self):
        with self.patched(private_client=lambda _address: False):
            response, data = self.post("/api/import/validate")
        self.assertJsonError(response, data, 403, "client is outside LAN")

    def test_post_with_wrong_content_type_is_400(self):
        for content_type in ("text/plain", "application/x-www-form-urlencoded", "application/json-patch+json"):
            with self.subTest(content_type=content_type):
                response, data = self.post("/api/import/validate", headers={"Content-Type": content_type})
                self.assertJsonError(response, data, 400, "ожидается Content-Type: application/json")

    def test_post_content_type_parameters_and_case_are_accepted(self):
        response, data = self.post(
            "/api/import/validate",
            make_report("discord-tcp"),
            headers={"Content-Type": "Application/JSON; charset=utf-8"},
        )
        self.assertEqual(response.status, 200, data)

    def test_post_with_bad_content_length_is_400(self):
        for length in ("abc", "-1", "1.5", ""):
            with self.subTest(length=length):
                response, data = self.post("/api/import/validate", raw=b"{}", headers={"Content-Length": length})
                self.assertJsonError(response, data, 400, "некорректный Content-Length")

    def test_post_with_oversized_content_length_is_400(self):
        response, data = self.post(
            "/api/import/validate",
            raw=b"{}",
            headers={"Content-Length": str(512 * 1024 + 1)},
        )
        self.assertJsonError(response, data, 400, "JSON превышает 512 КиБ")

    def test_post_with_invalid_json_is_400(self):
        for raw in (b"{bad", b"", b"\xff\xfe", b"{\"a\": 1}}"):
            with self.subTest(raw=raw):
                response, data = self.post("/api/import/validate", raw=raw)
                self.assertJsonError(response, data, 400, "некорректный JSON")

    def test_unexpected_handler_errors_return_json_500(self):
        def boom(*_args, **_kwargs):
            raise AttributeError("unexpected")

        with self.patched(tuner_status=boom, tuner_sources=boom):
            for path in ("/api/tuner/status", "/api/tuner/sources"):
                with self.subTest(path=path):
                    response, data = self.request("GET", path)
                    self.assertJsonError(response, data, 500, "внутренняя ошибка панели")
        # The server keeps serving after the failure.
        response, _data = self.request("GET", "/")
        self.assertEqual(response.status, 200)

    def test_post_with_deeply_nested_json_is_400(self):
        raw = (b"[" * 100000) + (b"]" * 100000)
        response, data = self.post("/api/import/validate", raw=raw)
        self.assertJsonError(response, data, 400, "некорректный JSON")

    def test_unknown_post_is_404(self):
        for path in ("/api/nope", "/", "/api/import/clear/whatsapp", "/api/route/discord"):
            with self.subTest(path=path):
                response, data = self.post(path)
                self.assertJsonError(response, data, 404, "unknown action")

    def test_route_post_with_unknown_mode_or_service_is_404(self):
        starter = mock.Mock(side_effect=AssertionError("must not start"))
        with self.patched(start_route_job=starter):
            for path in ("/api/route/discord/custom", "/api/route/discord/vless", "/api/route/whatsapp/vpn"):
                with self.subTest(path=path):
                    response, data = self.post(path)
                    self.assertJsonError(response, data, 404, "unknown action")
        starter.assert_not_called()

    def test_route_post_starts_job_and_maps_errors(self):
        starter = mock.Mock(return_value={"ok": True, "job_id": "0123456789abcdef", "status": "queued"})
        with self.patched(start_route_job=starter):
            response, data = self.post("/api/route/youtube/vpn")
        self.assertEqual(response.status, 202, data)
        self.assertEqual(json.loads(data)["job_id"], "0123456789abcdef")
        starter.assert_called_once_with("youtube", "vpn")
        for exc, status in ((RuntimeError("busy"), 409), (ValueError("bad"), 400), (OSError("io"), 400)):
            with self.subTest(exc=exc):
                with self.patched(start_route_job=mock.Mock(side_effect=exc)):
                    response, data = self.post("/api/route/discord/direct")
                self.assertJsonError(response, data, status, str(exc))

    def test_route_post_rejects_telegram_zapret(self):
        response, data = self.post("/api/route/telegram/zapret")
        self.assertJsonError(response, data, 400, "Zapret для Telegram удалён")

    def test_import_validate_rejects_invalid_report(self):
        response, data = self.post("/api/import/validate", {"report_format": 2})
        self.assertJsonError(response, data, 400, "неподдерживаемая версия отчёта")
        response, data = self.post("/api/import/validate", [1, 2])
        self.assertJsonError(response, data, 400, "корень отчёта")

    def test_import_apply_is_blocked_while_jobs_run(self):
        report = make_report("discord-tcp")
        for name in ("tuner_active", "route_active", "diagnostic_active"):
            with self.subTest(active=name):
                with self.patched(**{name: lambda: True}):
                    response, data = self.post("/api/import/apply", report)
                self.assertJsonError(response, data, 409, "профиль нельзя применять")

    def test_diagnostic_targets_come_from_the_shared_module(self):
        with self.patched(DIAGNOSTICS=DIAGNOSTICS_MODULE, DIAGNOSTICS_MODULES={}):
            response, data = self.request("GET", "/api/diagnostics/targets")
            self.assertEqual(response.status, 200)
            payload = json.loads(data)
            self.assertIn({"name": "DiscordMain", "url": "https://discord.com"}, payload["standard"])
            self.assertEqual(len(payload["dpi"]), 12)
            # Loaded once and reused by the post-apply check.
            self.assertEqual(list(self.ns["DIAGNOSTICS_MODULES"]), [str(DIAGNOSTICS_MODULE)])

    def test_successful_nfqws2_changes_return_the_post_apply_check(self):
        # D3: import, clear, rollback, version and tuner apply run the check, errors do not.
        health = {"ok": True, "checks": [{"name": "fixture", "ok": False, "status": "error", "detail": "x"}], "all_ok": False}
        calls = []

        def command(ok):
            return lambda *_args, **_kwargs: {"ok": ok, "code": 0 if ok else 1, "output": "engine"}

        def checked():
            calls.append(1)
            return health

        report = make_report("discord-tcp")
        # The cases below create the tuner and version directories: take them away again, the files first.
        versions = self.ns["PROFILE_VERSION_DIR"] / "discord-tcp"
        for directory in (self.ns["PROFILE_VERSION_DIR"], versions, self.ns["TUNER_STATE"].parent):
            if not directory.exists():
                self.addCleanup(directory.rmdir)
        # The tuner apply reads the found result, the version apply reads a stored version.
        self.ns["TUNER_STATE"].parent.mkdir(exist_ok=True)
        self.ns["TUNER_STATE"].write_text(json.dumps({"status": "found", "result_available": True}), encoding="utf-8")
        self.ns["TUNER_RESULT"].write_text(json.dumps(report), encoding="utf-8")
        profile = self.ns["validate_report"](report)
        version_id = f"20260815T020304Z-{profile['candidate_id']}-applied-123"
        versions.mkdir(parents=True, exist_ok=True)
        (versions / f"{version_id}.json").write_text(json.dumps(profile), encoding="utf-8")
        for fixture in (self.ns["TUNER_STATE"], self.ns["TUNER_RESULT"], versions / f"{version_id}.json"):
            self.addCleanup(fixture.unlink, missing_ok=True)
        cases = (
            ("/api/import/apply", report, "apply_profile"),
            ("/api/import/clear/youtube", {}, "run_command"),
            ("/api/import/rollback", {}, "run_command"),
            ("/api/tuner/apply", {}, "apply_profile"),
            (f"/api/profiles/apply/discord-tcp/{version_id}", {}, "apply_profile"),
        )
        for ok in (True, False):
            for path, body, runner in cases:
                with self.subTest(path=path, ok=ok), self.patched(**{
                    runner: command(ok), "config_health": checked,
                    "tuner_active": lambda: False, "route_active": lambda: False, "diagnostic_active": lambda: False,
                }):
                    calls.clear()
                    response, data = self.operation(path, body)
                    payload = json.loads(data)
                    self.assertEqual(response.status, 202)
                    if ok:
                        self.assertEqual(payload["health"], health)
                        self.assertEqual(calls, [1])
                    else:
                        self.assertNotIn("health", payload)
                        self.assertEqual(calls, [])
        # A failing check does not turn a completed change into an error.
        with self.patched(
            apply_profile=command(True), config_health=lambda: 1 / 0,
            tuner_active=lambda: False, route_active=lambda: False, diagnostic_active=lambda: False,
        ):
            response, data = self.operation("/api/import/apply", report)
        self.assertEqual(response.status, 202)
        self.assertIn("ZeroDivisionError", json.loads(data)["health_error"])

    def test_import_clear_and_rollback_run_their_own_engine_function(self):
        # The test above stubs run_command, which cannot tell the clear and the rollback command apart: here the
        # route must call its own engine function once, with the service of the path, and answer with its payload.
        health = {"ok": True, "checks": [], "all_ok": True}
        idle = {"tuner_active": lambda: False, "route_active": lambda: False, "diagnostic_active": lambda: False}
        routes = [(f"/api/import/clear/{service}", "clear_imported_profile", "rollback_import", (service,))
                  for service in self.ns["SERVICES"]]
        routes.append(("/api/import/rollback", "rollback_import", "clear_imported_profile", ()))
        for path, called, other, args in routes:
            for ok in (True, False):
                with self.subTest(path=path, ok=ok):
                    answer = {"ok": ok, "code": 0 if ok else 1, "output": "engine"}
                    function = mock.Mock(return_value=dict(answer))
                    unused = mock.Mock(side_effect=AssertionError(f"{other} must not run"))
                    with self.patched(**{called: function, other: unused, "config_health": lambda: health, **idle}):
                        response, data = self.operation(path)
                    self.assertEqual(response.status, 202, data)
                    function.assert_called_once_with(*args)
                    unused.assert_not_called()
                    self.assertEqual(json.loads(data), {**answer, "health": health} if ok else answer)

    def test_tuner_start_hands_the_validated_request_to_start_tuner_job(self):
        started = mock.Mock(return_value=4321)
        body = {"service": "youtube", "mix_level": "off", "max_candidates": 8, "search_seed": 7}
        with self.patched(AUTOTUNER=Path(__file__), start_tuner_job=started, route_active=lambda: False,
                          diagnostic_active=lambda: False,
                          tuner_status=lambda: {"ok": True, "status": "queued", "active": False}):
            response, data = self.post("/api/tuner/start", body)
        self.assertEqual(response.status, 202, data)
        started.assert_called_once_with({
            "service": "youtube", "mix_level": "off", "max_candidates": 8, "client_ip": "", "search_seed": 7,
            "source_file": None, "voice_auto": False, "voice_traffic": False,
        })
        self.assertEqual(json.loads(data), {"ok": True, "status": "queued", "active": True, "service": "youtube"})

    def test_tuner_verdict_body_validation(self):
        for body in ({}, {"works": "yes"}, {"works": True, "extra": 1}, [True]):
            with self.subTest(body=body):
                response, data = self.post("/api/tuner/verdict", body)
                self.assertJsonError(response, data, 400, "bool-параметр works")
        response, data = self.post("/api/tuner/verdict", {"works": True})
        self.assertEqual(response.status, 409, data)

    def test_tuner_start_without_autotuner_is_500(self):
        response, data = self.post("/api/tuner/start", {"service": "youtube"})
        self.assertJsonError(response, data, 500, "autotuner not found")

    def test_diagnostics_start_without_script_is_500(self):
        response, data = self.post("/api/diagnostics/start/health")
        self.assertJsonError(response, data, 500, "diagnostics not found")

    def test_cancel_endpoints_without_active_jobs_are_409(self):
        response, data = self.post("/api/tuner/cancel")
        self.assertJsonError(response, data, 409, "активного подбора нет")
        response, data = self.post("/api/diagnostics/cancel")
        self.assertJsonError(response, data, 409, "активной диагностики нет")

    def test_history_rollback_with_bad_id_is_400(self):
        response, data = self.post("/api/history/rollback/not-an-id")
        self.assertJsonError(response, data, 400, "некорректный ID операции")

    def test_profile_apply_with_bad_version_is_400(self):
        response, data = self.post("/api/profiles/apply/youtube/bad-version")
        self.assertJsonError(response, data, 400, "некорректный ID версии")

    def xkeen_action(self, action, answers):
        """POST /api/xkeen/<action> with run_command answering from `answers` (command -> result)."""
        calls = []

        def fake_run_command(command, timeout, *, env=None):
            calls.append({"command": list(command), "timeout": timeout, "env": env})
            return answers[tuple(command)]

        with self.patched(run_command=fake_run_command):
            response, data = self.operation(f"/api/xkeen/{action}")
        return calls, response, json.loads(data)

    def test_xkeen_restart_runs_in_foreground_and_checks_xray(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        ok = {"ok": True, "code": 0, "output": "restarted"}
        calls, response, payload = self.xkeen_action(
            "restart", {(xkeen, "restart", "on"): ok, ("pidof", "xray"): {"ok": True, "code": 0, "output": "200"}})
        self.assertEqual(response.status, 202, payload)
        self.assertEqual([call["command"] for call in calls], [[xkeen, "restart", "on"], ["pidof", "xray"]])
        self.assertGreaterEqual(calls[0]["timeout"], 150)
        self.assertEqual(calls[0]["env"], None)
        self.assertIs(payload["ok"], True)
        self.assertEqual((payload["code"], payload["output"]), (0, "restarted"))

    def test_xkeen_start_and_restart_fail_when_xray_is_not_running(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        for action in ("start", "restart"):
            with self.subTest(action=action):
                calls, response, payload = self.xkeen_action(
                    action, {tuple([xkeen, action] + ([] if action == "stop" else ["on"])): {"ok": True, "code": 0, "output": "done"},
                             ("pidof", "xray"): {"ok": False, "code": 1, "output": ""}})
                self.assertEqual(response.status, 202, payload)
                self.assertIs(payload["ok"], False)
                self.assertEqual(payload["code"], 0)
                self.assertIn("Xray не запущен", payload["output"])
                self.assertTrue(payload["output"].startswith("done"))
                self.assertEqual([call["command"] for call in calls], [[xkeen, action] + ([] if action == "stop" else ["on"]), ["pidof", "xray"]])

    def test_xkeen_stop_fails_when_xray_still_running(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        calls, response, payload = self.xkeen_action(
            "stop", {(xkeen, "stop"): {"ok": True, "code": 0, "output": "stopped"},
                     ("pidof", "xray"): {"ok": True, "code": 0, "output": "200"}})
        self.assertEqual(response.status, 202, payload)
        self.assertIs(payload["ok"], False)
        self.assertIn("Xray всё ещё запущен", payload["output"])
        self.assertEqual(calls[0]["env"], None)

    def test_xkeen_stop_succeeds_when_xray_is_gone(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        calls, response, payload = self.xkeen_action(
            "stop", {(xkeen, "stop"): {"ok": True, "code": 0, "output": "stopped"},
                     ("pidof", "xray"): {"ok": False, "code": 1, "output": ""}})
        self.assertEqual(response.status, 202, payload)
        self.assertEqual(payload, {"ok": True, "code": 0, "output": "stopped"})

    def test_xkeen_failed_command_skips_the_xray_check(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        calls, response, payload = self.xkeen_action(
            "restart", {(xkeen, "restart", "on"): {"ok": False, "code": 124, "output": "timeout"}})
        self.assertEqual(response.status, 202, payload)
        self.assertEqual(payload, {"ok": False, "code": 124, "output": "timeout"})
        self.assertEqual([call["command"] for call in calls], [[xkeen, "restart", "on"]])

    def test_xkeen_actions_are_blocked_while_jobs_run(self):
        for name in ("tuner_active", "route_active", "diagnostic_active"):
            with self.subTest(active=name):
                with self.patched(**{name: lambda: True}):
                    response, data = self.post("/api/xkeen/restart")
                self.assertJsonError(response, data, 409, "XKeen нельзя менять")


if __name__ == "__main__":
    unittest.main()

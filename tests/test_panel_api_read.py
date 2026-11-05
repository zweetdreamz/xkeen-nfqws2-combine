"""Read routes tested without the app entry or any router-changing command."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest import mock

import panel_harness


class ReadTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.api.read_routes",)

    def setUp(self):
        self.read = self.ns.module("kdn.web.api.read_routes")
        self.read.readcache.invalidate()
        self.router = self.read.router.Router(self.read.READ_ROUTES)
        self.patch(BROWSER_DIAGNOSTICS=panel_harness.ROOT / "tools/router/browser-diagnostics.js")

    def get(self, path):
        return self.router.dispatch(self.read.router.Request("GET", path))

    def payload(self, path):
        return json.loads(self.get(path).body)

    def test_status_cache_checks_target_on_hits_and_post_invalidates(self):
        from kdn.common import xkeen
        with tempfile.NamedTemporaryFile() as source, \
                mock.patch.object(self.read.cfg, 'ENGINE', Path(source.name)), \
                mock.patch.object(self.read.engine, 'read_status_fields', return_value={'ok': True, 'youtube_route': 'zapret'}) as load:
            self.assertEqual(self.get('/api/status').status, 200)
            self.assertEqual(self.get('/api/status').status, 200)
            self.assertEqual(load.call_count, 1)
            with mock.patch.object(self.read.engine, 'require_supported_target', side_effect=xkeen.UnsupportedXKeen()):
                response = self.get('/api/status')
            self.assertEqual(response.status, 409)
            self.assertEqual(json.loads(response.body)['error_code'], 'unsupported_xkeen')
            self.get('/api/status')
            load.return_value = {'ok': True, 'youtube_route': 'vless'}
            routes = self.read.READ_ROUTES + (self.read.router.Route('POST', '/test-mutation',
                lambda request: self.read.router.json_response(200, {'ok': True})),)
            self.read.router.Router(routes).dispatch(self.read.router.Request('POST', '/test-mutation'))
            self.assertEqual(self.payload('/api/status')['youtube_route'], 'vless')
            self.assertEqual(load.call_count, 3)

    def test_page_and_browser_asset(self):
        profiles = {"services": {"discord-tcp": {"route": "zapret", "profiles": [
            {"label": "<test>", "args": ["--test=<x>"]}], "note": ""}}}
        with mock.patch.object(self.read.profiles, "current_service_configs", return_value=profiles):
            page = self.get("/")
        self.assertEqual(page.status, 200)
        self.assertIn("text/html", page.content_type)
        self.assertNotIn(b"__SERVICE_CONFIG_SECTION__", page.body)
        self.assertIn(b"&lt;test&gt;", page.body)
        self.assertIn(b"--test=&lt;x&gt;", page.body)
        with mock.patch.object(self.read.profiles, "current_service_configs", side_effect=OSError("unavailable")):
            self.assertIn(b"unavailable", self.get("/").body)
        script = self.get("/assets/browser-diagnostics.js")
        self.assertEqual(script.body, self.read.cfg.BROWSER_DIAGNOSTICS.read_text(encoding="utf-8").encode())
        self.assertEqual(script.content_type, "application/javascript; charset=utf-8")

    def test_download_and_failures(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "helper.ps1"
            with mock.patch.object(self.read.cfg, "DISCORD_CACHE_HELPER", path):
                self.assertEqual(self.get("/tools/reset-discord-cache.ps1").status, 404)
                path.write_text("hello", encoding="utf-8-sig")
                result = self.get("/tools/reset-discord-cache.ps1")
                self.assertEqual(result.body, b"\xef\xbb\xbfhello")
                self.assertEqual(result.headers["Content-Disposition"], 'attachment; filename="reset-discord-cache.ps1"')
                with mock.patch.object(self.read.cfg, "MAX_REPORT_BYTES", 2):
                    self.assertEqual(self.get("/tools/reset-discord-cache.ps1").status, 404)
                path.unlink()
                path.symlink_to(Path(root) / "elsewhere")
                self.assertEqual(self.get("/tools/reset-discord-cache.ps1").status, 404)

    def test_status_and_heavy_flags(self):
        with mock.patch.object(self.read.cfg, "ENGINE", Path("/no-such-test-engine")):
            self.assertIn("project script not found:", self.payload("/api/status")["error"])
            self.assertEqual(self.get("/api/status").status, 500)
        with tempfile.NamedTemporaryFile() as engine, mock.patch.object(self.read.cfg, "ENGINE", Path(engine.name)):
            for ok in (True, False):
                self.read.readcache.invalidate()  # independent producer outcomes, not a cache hit
                value = {"ok": ok, "code": 0 if ok else 1, "output": "data", "youtube_route": "zapret"}
                with mock.patch.object(self.read.engine, "read_status_fields", return_value=value):
                    response = self.get("/api/status")
                    self.assertEqual((response.status, json.loads(response.body)), (200 if ok else 500, value))
        self.assertEqual({r.pattern for r in self.read.READ_ROUTES if r.heavy}, {"/api/status", "/api/checks/config"})
        self.assertTrue(all(r.method == "GET" for r in self.read.READ_ROUTES))
        self.assertEqual(len(self.read.READ_ROUTES), 15)

    def test_domain_wrappers(self):
        cases = [("/api/tuner/sources", self.read.flowseal, "tuner_sources", {"ok": True, "sources": []}, None),
                 ("/api/updates", self.read.flowseal, "cached_flowseal_update", {"ok": True, "status": "ready"}, None),
                 ("/api/checks/config", self.read.health, "config_health", {"ok": True, "checks": []}, None),
                 ("/api/tuner/voice-endpoint", self.read.tuner_jobs, "learned_voice_endpoint", {"ip": "1.2.3.4"}, "endpoint"),
                 ("/api/history", self.read.history, "route_history", [{"job_id": "A"}], "items"),
                 ("/api/profile-versions", self.read.profiles, "profile_versions", [{"id": "A"}], "versions")]
        for path, module, name, data, wrapper in cases:
            with self.subTest(path=path), mock.patch.object(module, name, return_value=data):
                self.assertEqual(self.payload(path), {"ok": True, wrapper: data} if wrapper else data)
        with mock.patch.object(self.read.profiles, "imported_profiles", return_value=[{"service": "youtube"}]):
            self.assertEqual(self.payload("/api/imported"), {"ok": True, "profiles": [{"service": "youtube"}],
                                                            "rollback_available": False})
        module = SimpleNamespace(STANDARD_TARGETS=[("secure", "https://host"), ("plain", "http://host")],
                                 DPI_TARGETS=[("ID", "Provider", "host")])
        with mock.patch.object(self.read.toolmods, "diagnostics_module", return_value=module):
            self.assertEqual(self.payload("/api/diagnostics/targets"), {"ok": True,
                             "standard": [{"name": "secure", "url": "https://host"}],
                             "dpi": [{"name": "Provider · ID", "url": "https://host"}]})

    def test_specific_error_tables_and_unhandled_errors(self):
        for path, module, name, kinds in [
            ("/api/service-configs", self.read.profiles, "current_service_configs", (OSError, ValueError, RuntimeError)),
            ("/api/vpn-nodes", self.read.vpn, "nodes_status", (OSError, RuntimeError, ValueError, TypeError)),
            ("/api/history", self.read.history, "route_history", (OSError, ValueError)),
            ("/api/profile-versions", self.read.profiles, "profile_versions", (OSError, ValueError)),
        ]:
            for kind in kinds:
                with self.subTest(path=path, kind=kind), mock.patch.object(module, name, side_effect=kind("broken")):
                    result = self.get(path)
                    self.assertEqual((result.status, json.loads(result.body)), (500, {"ok": False, "error": "broken"}))
        with mock.patch.object(self.read.history, "route_history", side_effect=TypeError("propagate")):
            with self.assertRaisesRegex(TypeError, "propagate"):
                self.get("/api/history")

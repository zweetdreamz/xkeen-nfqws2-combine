"""Whole-table HTTP checks, including every legacy route and GET filesystem purity."""
import json
import concurrent.futures
import dataclasses
import subprocess
import threading
from unittest import mock

from test_panel_api_server import ServerCase


class TableTests(ServerCase):
    modules = ("kdn.web.app",)

    def setUp(self):
        super().setUp()
        self.root = self.fresh_root()
        self.table = self.ns.module("table")
        self.jobs = self.ns.module("jobfiles")

    def test_every_old_route_is_in_the_table(self):
        gets = ["/", "/tools/reset-discord-cache.ps1", "/assets/browser-diagnostics.js", "/api/diagnostics/targets",
                "/api/status", "/api/service-configs", "/api/vpn-nodes", "/api/imported", "/api/tuner/status",
                "/api/tuner/sources", "/api/tuner/voice-endpoint", "/api/route/status", "/api/diagnostics/status",
                "/api/history", "/api/profile-versions", "/api/updates", "/api/automation", "/api/checks/config"]
        posts = ["/api/automation/save", "/api/automation/cancel", "/api/diagnostics/start/health", "/api/diagnostics/cancel",
                 "/api/tuner/start", "/api/tuner/cancel", "/api/tuner/verdict", "/api/tuner/apply", "/api/xkeen/start",
                 "/api/xkeen/stop", "/api/xkeen/restart", "/api/route/youtube/vpn", "/api/vpn-nodes/add",
                 "/api/vpn-nodes/check/node1", "/api/vpn-nodes/delete/node1", "/api/vpn-nodes/sync-current",
                 "/api/vpn-nodes/recover", "/api/vpn-nodes/activate/node1", "/api/history/delete/A",
                 "/api/profile-versions/delete/youtube/v1", "/api/history/rollback/A", "/api/profiles/apply/youtube/v1",
                 "/api/updates/check", "/api/import/validate", "/api/import/apply", "/api/import/clear/youtube", "/api/import/rollback"]
        self.assertEqual(len(gets) + len(posts), 45)
        for method, paths in (("GET", gets), ("POST", posts)):
            for path in paths:
                with self.subTest(method=method, path=path):
                    self.assertIsNotNone(self.table.ROUTER.match(method, path))
        self.assertIsNotNone(self.table.ROUTER.match("GET", "/api/route/result"))

    def test_all_gets_are_views_and_foreign_host_is_refused(self):
        for path in (self.cfg.ROUTE_STATE, self.cfg.TUNER_STATE, self.cfg.DIAGNOSTIC_STATE, self.cfg.AUTOMATION_STATE):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"job_id":"aaaaaaaaaaaaaaaa","status":"running","kind":"health","operation":"switch"}')
        def digest():
            return {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with self.serving(handler=self.table.Handler, max_threads=4, max_connections=32, first_line_timeout=1) as server:
            for corrupt in (False, True):
                if corrupt:
                    self.cfg.AUTOMATION_STATE.write_text("{broken")
                for route in self.table.ROUTER.routes:
                    if route.method != "GET":
                        continue
                    with self.subTest(path=route.pattern, corrupt=corrupt):
                        before = digest()
                        status, _headers, _body = self.request(server, path=route.pattern)
                        self.assertIn(status, (200, 404, 500))
                        self.assertEqual(before, digest())
                        self.assertEqual(self.request(server, path=route.pattern, headers={"Host": "foreign"})[0], 403)

    def test_new_xkeen_job_is_visible_to_deploy_busy_poll(self):
        command = [b"python3", str(self.cfg.ENTRY).encode(), b"--route-job"]
        self.patch(job_command=lambda pid: command if pid == 4321 else None)
        with self.serving(handler=self.table.Handler, max_threads=4, max_connections=32, first_line_timeout=1) as server, \
                mock.patch.object(subprocess, "Popen", return_value=mock.Mock(pid=4321)):
            status, _, body = self.post(server, path="/api/xkeen/restart")
            self.assertEqual(status, 202, body)
            status, _, body = self.request(server, path="/api/route/status")
            self.assertEqual(status, 200)
            self.assertIs(json.loads(body)["active"], True)
            self.assertEqual(self.cfg.ROUTE_PID.read_text().strip(), "4321")

    def test_table_heavy_routes_share_two_slots(self):
        entered, release = threading.Event(), threading.Event()
        lock = threading.Lock()
        active = peak = 0

        def slow(request):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                if active == 2:
                    entered.set()
            release.wait(3)
            with lock:
                active -= 1
            return self.routes.json_response(200, {"ok": True})

        routes = [dataclasses.replace(route, handler=slow) if route.heavy else route for route in self.table.ROUTER.routes]
        with self.serving(*routes, max_threads=8, max_connections=32, first_line_timeout=1) as server, \
                concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(self.request, server, path="/api/status" if n % 2 else "/api/checks/config") for n in range(6)]
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.request(server, path="/api/history")[0], 200)
            finally:
                release.set()
            self.assertTrue(all(f.result(timeout=4)[0] == 200 for f in futures))
        self.assertEqual(peak, 2)

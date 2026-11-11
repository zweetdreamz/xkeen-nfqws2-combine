"""Smoke tests of the panel HTTP endpoints: the real Handler on 127.0.0.1:0 and the contract the page relies on.

These characterize today's HTTP layer (tests/panel_contract.py holds the fields the page reads). Every test starts
from an empty test root of the panel generation (``fresh_root()``), under which all router paths of the panel lie;
``run_command``, the VPN manager (a real VpnNodeManager over temporary files with the probe stubbed) and the worker
processes (``subprocess.Popen``) are stubs, so nothing touches the router, /opt or the network beyond 127.0.0.1.
tests/test_panel_contract.py requires every key of FRONTEND_CONTRACT to be checked here with a literal key.
"""

from __future__ import annotations

import http.client
import json
import signal
import threading
import unittest
from unittest import mock

from panel_contract import FRONTEND_CONDITIONAL, FRONTEND_CONTRACT, missing_fields
import panel_harness
from panel_fixtures import make_report
from tools.router.vpn_node_manager import VpnNodeManager
from tools.router import vpn_node_manager as node_module

ROOT = panel_harness.ROOT
UUID = "00000000-0000-4000-8000-000000000000"
JSON_TYPE = "application/json; charset=utf-8"
STATUS_OUTPUT = (
    "discord_route=mixed\ndiscord_tcp_route=zapret\ndiscord_voice_route=direct\nyoutube_route=vless\n"
    "telegram_route=unmanaged\nxkeen_runtime=running\nnfqws_runtime=running\ndetected_core=xray\nscript_version=6.4"
)
ROUTES_HEADER = "# Active routes: DiscordTCP=zapret, DiscordVoice=direct, YouTube=vless, Telegram=unmanaged.\n"
GOOD_PROBE = {"ok": True, "checked_utc": "2026-10-20T10:00:00Z", "latency_ms": 120, "http_code": 204, "target": "example.invalid"}
BAD_PROBE = {"ok": False, "checked_utc": "2026-10-20T10:00:00Z", "detail": "HTTPS через эту ноду не ответил"}
OK = {"ok": True, "code": 0, "output": ""}
FAILED = {"ok": False, "code": 1, "output": ""}


def vpn_outbound(address="vpn.example"):
    return {"tag": "vless-reality", "protocol": "vless",
            "settings": {"address": address, "port": 443, "id": UUID, "encryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverName": "example.com", "fingerprint": "chrome",
                                                   "publicKey": "key", "shortId": "", "spiderX": "/"}}}


class Commands:
    """run_command stand-in: answers by command, records every call, fails on a command nobody expected."""

    def __init__(self, answers):
        self.answers = {tuple(command): answer for command, answer in answers.items()}
        self.calls = []

    def __call__(self, command, timeout, *, env=None):
        self.calls.append({"command": list(command), "timeout": timeout, "env": env})
        if tuple(command) not in self.answers:
            raise AssertionError(f"unexpected router command: {command}")
        return dict(self.answers[tuple(command)])


class PanelEndpointCase(panel_harness.PanelTestCase):
    ns_name = "panel_endpoints_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        handler = cls.ns["Handler"]
        quiet = mock.patch.object(handler, "log_message", lambda *_args: None)
        quiet.start()
        cls.addClassCleanup(quiet.stop)
        cls.server = cls.ns["ThreadingHTTPServer"](("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        # Every router path of the panel lies under this root; only what the tests run or serve for real is set apart.
        root = self.fresh_root()
        self.root = root

        def forbidden(*_args, **_kwargs):
            raise AssertionError("router command must not run in this test")

        self.engine = root / "project" / "apply-discord-nfqws2.sh"
        self.patch(
            BIND_HOST="127.0.0.1",
            PORT=self.port,
            run_command=forbidden,
            apply_profile=forbidden,
            PROJECT_DIR=ROOT,
            ENGINE=self.engine,
            SERVICE_SWITCH=root / "project" / "set-service-route.sh",
            AUTOTUNER=root / "project" / "zapret_autotune_job.py",
            DIAGNOSTICS=ROOT / "tools" / "router" / "xkeen_diagnostics.py",
            BROWSER_DIAGNOSTICS=ROOT / "tools" / "router" / "browser-diagnostics.js",
            XKEEN=str(root / "xkeen"),
        )
        self.addCleanup(self.ns["AUTOMATION_CANCEL"].clear)
        # P3.22 routes enqueue jobs now. Old synchronous-contract cases stay
        # RED until P3.23, but must never launch real router-command workers.
        worker = mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321))
        worker.start()
        self.addCleanup(worker.stop)

    # --- requests -------------------------------------------------------------------------------------------

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response, response.read()
        finally:
            connection.close()

    def get(self, path, status=200):
        response, data = self.request("GET", path)
        self.assertEqual(response.status, status, data)
        self.assertEqual(response.getheader("Content-Type"), JSON_TYPE)
        return json.loads(data)

    def post(self, path, payload=None, status=200, headers=None):
        merged = {"X-XKeen-Control": "1", "Content-Type": "application/json", **(headers or {})}
        response, data = self.request("POST", path, body=json.dumps({} if payload is None else payload).encode(),
                                      headers=merged)
        self.assertEqual(response.status, status, data)
        self.assertEqual(response.getheader("Content-Type"), JSON_TYPE)
        return json.loads(data)

    def assertContract(self, key, payload, also=()):
        self.assertEqual(missing_fields(key, payload, also), [], f"{key}: {payload}")

    def operation(self, path, body=None):
        worker = self.fake_workers()
        started = self.post(path, body, status=202)
        slim = self.get("/api/route/status")
        self.assertNotIn("log_tail", slim)
        self.assertLessEqual(len(json.dumps(slim, ensure_ascii=False).encode()), 2048)
        self.ns["run_job"](*worker.call_args.args[0][3:])
        result = self.get("/api/route/result?job_id=" + started["job_id"])
        self.assertContract("GET /api/route/result", result)
        return started, result

    def assertPage(self, key, response, data):
        """The contract of an HTML answer: the page itself (the deploy tool's panel_ready check), no JSON fields."""
        self.assertEqual(FRONTEND_CONTRACT[key], set())
        self.assertEqual(response.status, 200, data)
        self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
        self.assertTrue(data.startswith(b"<!doctype html>"))

    def assertElements(self, key, items, also=()):
        self.assertTrue(items, f"{key}: no elements to check")
        for item in items:
            self.assertContract(key, item, also)

    # --- fixtures -------------------------------------------------------------------------------------------

    def write(self, name, text):
        """Write the file the panel reads under its configuration name, creating the directories above it."""
        path = self.ns[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def router(self, answers):
        # Replacing the command producer starts a fresh contract scenario.
        self.ns.module('infra.readcache').invalidate()
        commands = Commands(answers)
        self.patch(run_command=commands)
        return commands

    def write_engine(self):
        self.engine.parent.mkdir(parents=True, exist_ok=True)
        self.engine.write_text("#!/bin/sh\n", encoding="utf-8")

    def status_command(self, output=STATUS_OUTPUT):
        report = {'schema': 1, 'text': output, 'fields': {}, 'warnings': [], 'lock': {'exists': False, 'pid': None, 'alive': False},
                  'snapshots': None, 'xkeen_output': None, 'xkeen': None, 'xray': None}
        return {("/bin/sh", str(self.engine), "--status", "--json"): {"ok": True, "code": 0, "output": json.dumps(report, indent=2)}}

    def vpn_manager(self, probes=(GOOD_PROBE,)):
        """A real VpnNodeManager over temporary files, installed as the panel's vpn_manager()."""
        xray_dir = self.root / "xray"
        xray_dir.mkdir()
        (xray_dir / "04_outbounds.json").write_text(
            json.dumps({"outbounds": [vpn_outbound(), {"tag": "direct", "protocol": "freedom"}]}), encoding="utf-8")
        manager = VpnNodeManager(xray_dir=xray_dir, state_file=self.root / "vpn-nodes.json",
                                 backup_dir=self.root / "vpn-backups", lock_dir=self.root / "project.lock")
        target = mock.patch.object(manager, "_require_supported_xkeen")
        target.start()
        self.addCleanup(target.stop)
        probe = mock.patch.object(manager, "probe", side_effect=list(probes) + [probes[-1]] * 8)
        probe.start()
        self.addCleanup(probe.stop)
        self.patch(vpn_manager=lambda: manager, VPN_MODULE=node_module)
        return manager

    def fake_workers(self):
        """subprocess.Popen as seen by the panel: a worker that has already gone away. Returns the mock."""
        process = mock.Mock()
        process.pid = 999999
        patcher = mock.patch.object(self.ns["subprocess"], "Popen", return_value=process)
        popen = patcher.start()
        self.addCleanup(patcher.stop)
        return popen

    def history_record(self, job_id="0123456789abcdef", **fields):
        directory = self.ns["ROUTE_HISTORY_DIR"]
        directory.mkdir(parents=True, exist_ok=True)
        record = {"job_id": job_id, "operation": "switch", "status": "completed", "service": "youtube",
                  "created_utc": "2026-10-20T10:00:00Z", **fields}
        (directory / f"{job_id}.json").write_text(json.dumps(record), encoding="utf-8")
        return record

    def snapshot(self, name="20261020-100000"):
        directory = self.ns["SNAPSHOT_DIR"] / name
        directory.mkdir(parents=True)
        (directory / "STATE.tsv").write_text("state\n", encoding="utf-8")
        (directory / "MANIFEST").write_text("manifest\n", encoding="utf-8")
        return directory

    def profile_version(self, service="youtube", stamp="20261020T100000Z", reason="replaced"):
        profile = self.ns["validate_report"](make_report(service))
        version_id = f"{stamp}-{profile['candidate_id']}-{reason}-1"
        directory = self.ns["PROFILE_VERSION_DIR"] / service
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{version_id}.json").write_text(json.dumps(profile), encoding="utf-8")
        return version_id

    def flowseal_cache(self, commit="a" * 40):
        module = self.ns["flowseal_source_module"]()
        source = module.SourceFile("general.bat", "@echo off", "d" * 40, "https://example.invalid/general.bat")
        module.save_source_cache(self.ns["FLOWSEAL_SOURCE_CACHE"], [source], commit)


class GetEndpointTests(PanelEndpointCase):
    def test_home_dns_read_switch_and_confirmation(self):
        status={'ok':True,'supported':True,'mode':'vless','interface':'Home','detail':'','pending':False,'recovery_mode':None,'host_overrides':0}
        self.patch(read_dns_mode=mock.Mock(return_value=status))
        self.assertContract('GET /api/dns',self.get('/api/dns'))
        started=mock.Mock(return_value={'ok':True,'job_id':'0123456789abcdef'})
        self.patch(start_dns_switch=started)
        self.assertContract('POST /api/dns/<mode>',self.post('/api/dns/doh',{'confirm':True},status=202))
        started.assert_called_once_with('doh')
        self.post('/api/dns/doh',{},status=400)
        self.post('/api/dns/doh',{'confirm':1},status=400)
        started.assert_called_once()
    def test_notification_settings_tokens_and_test_queue(self):
        status=self.get('/api/notifications')
        self.assertContract('GET /api/notifications',status)
        self.assertElements('GET /api/notifications#choices[]',status['choices'])
        topic=self.post('/api/notifications/topic',{})
        self.assertContract('POST /api/notifications/topic',topic)
        saved=self.post('/api/notifications/save',{'enabled':True,'topic':topic['topic'],'token':'SECRET-TOKEN'})
        self.assertContract('POST /api/notifications/save',saved)
        self.assertNotIn('SECRET-TOKEN',json.dumps(saved))
        self.assertTrue(saved['token_set'])
        self.assertContract('POST /api/notifications/test',self.post('/api/notifications/test',{},status=202))
        self.post('/api/notifications/save',{'enabled':True,'topic':'bad/topic'},status=400)

    def test_inspection_and_monitor_reads_are_cached(self):
        self.assertContract('GET /api/inspection/status', self.get('/api/inspection/status'))
        self.assertContract('GET /api/vpn-monitor', self.get('/api/vpn-monitor'))

    def test_root_is_the_html_page(self):
        response, data = self.request("GET", "/")
        self.assertPage("GET /", response, data)

    def test_status_parses_the_engine_output(self):
        self.write_engine()
        commands = self.router(self.status_command())
        payload = self.get("/api/status")
        self.assertContract("GET /api/status", payload)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(
            {key: payload[key] for key in ("discord_tcp_route", "discord_voice_route", "youtube_route", "telegram_route",
                                           "xkeen_runtime")},
            {"discord_tcp_route": "zapret", "discord_voice_route": "direct", "youtube_route": "vless",
             "telegram_route": "unmanaged", "xkeen_runtime": "running"})
        self.assertEqual(payload["output"], STATUS_OUTPUT)
        self.assertEqual(commands.calls, [{"command": ["/bin/sh", str(self.engine), "--status", "--json"], "timeout": 40, "env": None}])

    def test_status_falls_back_to_installed_legacy_engine(self):
        self.write_engine()
        commands = self.router({('/bin/sh', str(self.engine), '--status', '--json'): {'ok': False, 'code': 2, 'output': 'unknown argument: --json'},
                                ('/bin/sh', str(self.engine), '--status'): {'ok': True, 'code': 0, 'output': STATUS_OUTPUT}})
        payload = self.get('/api/status')
        self.assertEqual(payload['output'], STATUS_OUTPUT)
        self.assertEqual(payload['youtube_route'], 'vless')
        self.assertEqual([call['command'][2:] for call in commands.calls], [['--status', '--json'], ['--status']])

    def test_status_warning_json_preserves_existing_http_contract(self):
        self.write_engine()
        output = 'WARNING: preserved\n' + json.dumps({'schema': 1, 'text': STATUS_OUTPUT + '\n', 'warnings': ['WARNING: preserved']}, indent=2)
        commands = self.router({('/bin/sh', str(self.engine), '--status', '--json'): {'ok': True, 'code': 0, 'output': output}})
        payload = self.get('/api/status')
        self.assertContract('GET /api/status', payload)
        self.assertEqual(payload['output'], 'WARNING: preserved\n' + STATUS_OUTPUT)
        self.assertEqual(payload['xkeen_runtime'], 'running')
        self.assertNotIn('schema', payload)
        self.assertEqual(len(commands.calls), 1)

    def test_status_timeout_is_not_retried(self):
        self.write_engine()
        commands = self.router({('/bin/sh', str(self.engine), '--status', '--json'): {'ok': False, 'code': 124, 'output': 'timeout'}})
        payload = self.get('/api/status', status=500)
        self.assertEqual((payload['ok'], payload['code'], payload['output']), (False, 124, 'timeout'))
        self.assertEqual(len(commands.calls), 1)

    def test_service_configs_report_each_route(self):
        self.write("NFQWS_CONFIG", ROUTES_HEADER)
        payload = self.get("/api/service-configs")
        self.assertContract("*", payload)
        self.assertEqual(list(payload["services"]), ["discord-tcp", "discord-voice", "youtube", "telegram"])
        self.assertEqual({name: entry["route"] for name, entry in payload["services"].items()},
                         {"discord-tcp": "zapret", "discord-voice": "direct", "youtube": "vless", "telegram": "unmanaged"})
        for name, entry in payload["services"].items():
            with self.subTest(service=name):
                self.assertEqual(sorted(entry), ["note", "profiles", "route"])
        self.assertIn("Напрямую", payload["services"]["discord-voice"]["note"])

    def test_vpn_nodes_lists_the_registry(self):
        manager = self.vpn_manager(probes=(GOOD_PROBE, BAD_PROBE))
        manager.add("vless_2", json.dumps(vpn_outbound("other.example")))
        manager.add("vless_3", json.dumps(vpn_outbound("third.example")))
        payload = self.get("/api/vpn-nodes")
        self.assertContract("GET /api/vpn-nodes", payload)
        self.assertIs(payload["ok"], True)
        self.assertEqual((payload["active"], payload["canonical_tag"], payload["drift"], payload["recovery_needed"]),
                         ("current", "vless-reality", False, False))
        self.assertEqual([node["id"] for node in payload["nodes"]], ["current", "vless_2", "vless_3"])
        self.assertEqual([node["active"] for node in payload["nodes"]], [True, False, False])
        self.assertEqual(payload["nodes"][1]["endpoint"], "other.example:443")
        self.assertNotIn(UUID, json.dumps(payload))
        self.assertElements("GET /api/vpn-nodes#nodes[]", payload["nodes"])
        self.assertIsNone(payload["nodes"][0]["health"])
        self.assertIsNone(payload['nodes'][1]['health'])
        self.assertIsNone(payload['nodes'][2]['health'])

    def test_updates_before_and_after_a_download(self):
        payload = self.get("/api/updates")
        self.assertContract("GET /api/updates", payload)
        self.assertEqual(payload, {"ok": True, "status": "never_downloaded"})
        self.flowseal_cache()
        payload = self.get("/api/updates")
        self.assertContract("GET /api/updates", payload, also=("downloaded_commit", "source_count"))
        self.assertEqual((payload["status"], payload["downloaded_commit"], payload["source_count"]),
                         ("downloaded", "a" * 40, 1))

    def test_tuner_sources_list_the_cached_bat_files(self):
        self.flowseal_cache()
        payload = self.get("/api/tuner/sources")
        self.assertContract("GET /api/tuner/sources", payload)
        self.assertEqual((payload["status"], payload["commit"]), ("ready", "a" * 40))
        self.assertElements("GET /api/tuner/sources#sources[]", payload["sources"])
        self.assertEqual([item["name"] for item in payload["sources"]], ["general.bat"])
        self.assertIsInstance(payload["sources"][0]["services"], list)

    def test_voice_endpoint_is_null_or_the_learned_server(self):
        payload = self.get("/api/tuner/voice-endpoint")
        self.assertContract("GET /api/tuner/voice-endpoint", payload)
        self.assertEqual(payload, {"ok": True, "endpoint": None})
        learned = {"ip": "162.159.130.234", "port": 50007, "learned_utc": "2026-10-20T10:00:00Z"}
        self.write("VOICE_ENDPOINT_FILE", json.dumps(learned))
        payload = self.get("/api/tuner/voice-endpoint")
        self.assertContract("GET /api/tuner/voice-endpoint#endpoint", payload["endpoint"])
        self.assertEqual(payload, {"ok": True, "endpoint": learned})

    def test_checks_config_runs_the_live_checks(self):
        self.router({
            ("pidof", "xray"): OK,
            ("pidof", "nfqws2"): FAILED,
        })
        payload = self.get("/api/checks/config")
        self.assertContract("GET /api/checks/config", payload)
        self.assertIs(payload["ok"], True)
        self.assertIs(payload["all_ok"], False)
        self.assertEqual(sorted(payload["routes"]), ["discord-tcp", "discord-voice", "telegram", "youtube"])
        self.assertElements("GET /api/checks/config#checks[]", payload["checks"])
        by_name = {check["name"]: check for check in payload["checks"]}
        self.assertEqual((by_name["Xray"]["ok"], by_name["Xray"]["status"]), (True, "ok"))
        self.assertEqual((by_name["nfqws2"]["ok"], by_name["nfqws2"]["status"]), (False, "error"))

    def test_browser_diagnostics_script_is_served_as_javascript(self):
        response, data = self.request("GET", "/assets/browser-diagnostics.js")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/javascript; charset=utf-8")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertEqual(data, (ROOT / "tools" / "router" / "browser-diagnostics.js").read_bytes())

    def test_discord_cache_helper_is_served_as_a_download(self):
        helper = self.root / "reset-discord-cache.ps1"
        helper.write_text("Write-Host 'reset'\n", encoding="utf-8")
        self.patch(DISCORD_CACHE_HELPER=helper)
        response, data = self.request("GET", "/tools/reset-discord-cache.ps1")
        self.assertEqual(response.status, 200, data)
        self.assertEqual(response.getheader("Content-Type"), "text/plain; charset=utf-8")
        self.assertEqual(response.getheader("Content-Disposition"), 'attachment; filename="reset-discord-cache.ps1"')
        self.assertEqual(data, b"\xef\xbb\xbfWrite-Host 'reset'\n")

    def test_automation_active_means_a_run_holds_the_lock(self):
        payload = self.get("/api/automation")
        self.assertContract("GET /api/automation", payload)
        self.assertContract("GET /api/automation#config", payload["config"])
        self.assertEqual((payload["active"], payload["config"]["enabled"], payload["next_run"]), (False, False, None))
        # An enabled schedule is not an active run.
        config = {**self.ns["default_automation_config"](), "enabled": True}
        self.write("AUTOMATION_CONFIG", json.dumps(config))
        payload = self.get("/api/automation")
        self.assertContract("GET /api/automation", payload)
        self.assertEqual((payload["active"], payload["config"]["enabled"]), (False, True))
        self.assertIsInstance(payload["next_run"], str)
        lock = threading.Lock()
        lock.acquire()
        try:
            self.patch(AUTOMATION_RUN_LOCK=lock)
            payload = self.get("/api/automation")
        finally:
            lock.release()
        self.assertContract("GET /api/automation", payload)
        self.assertIs(payload["active"], True)

    def test_automation_running_and_completed_states_meet_nested_contract(self):
        lock = threading.Lock()
        self.patch(AUTOMATION_RUN_LOCK=lock)
        for status in ("running", "completed"):
            if status == "running":
                lock.acquire()
            self.write("AUTOMATION_STATE", json.dumps({"status": status, "phase": "checking",
                       "current_service": "youtube", "events": [{"at": "2026-10-29T03:00:00Z", "message": "test"}],
                       "error": ""}))
            try:
                payload = self.get("/api/automation")
                self.assertContract("GET /api/automation#state", payload["state"],
                                    also=tuple(FRONTEND_CONDITIONAL["GET /api/automation#state"]))
                for scenario in payload["config"]["services"].values():
                    self.assertContract("GET /api/automation#config.services[]", scenario)
            finally:
                if lock.locked():
                    lock.release()

    def test_full_tuner_status_and_history_conditional_fields(self):
        state = {"status": "found", "service": "discord-voice", "error": "", "current_candidate": 2,
                 "candidate_count": 8, "source_file": "general.bat", "commit": "abcdef",
                 "last_probe_detail": {"phase": "candidate", "round": 2, "role": "web", "http_code": "200",
                                       "status": "ok", "seconds": 0.2, "bytes": 1024},
                 "baseline_result": {"verdict": "fail", "successes": 0, "total": 3},
                 "last_suite_result": {"candidate": 2, "phase": "candidate", "verdict": "pass"},
                 "voice_traffic_baseline": "attempts", "last_voice_traffic": {"candidate": 2, "state": "connected"},
                 "voice_auto_mode": "auto", "last_voice_auto": {"candidate": 2, "result": "pass"},
                 "voice_unconfirmed": True, "voice_calibration": {"active": {"valid": 1}},
                 "found": {"candidate_id": "A", "family": "fake", "source_name": "general.bat", "args": []}}
        self.write("TUNER_STATE", json.dumps(state))
        self.assertContract("GET /api/tuner/status", self.get("/api/tuner/status"),
                            also=tuple(FRONTEND_CONDITIONAL["GET /api/tuner/status"]))
        item = {"job_id": "a" * 16, "operation": "vpn-node", "created_utc": "2026-10-29T03:00:00Z",
                "status": "failed", "service": "vpn", "before_routes": {}, "after_routes": {},
                "requested_routes": {}, "outbound_tag": "vless_2", "output_tail": "example",
                "finished_utc": "2026-10-29T03:01:00Z", "error": "test", "snapshot": ""}
        directory = self.ns["ROUTE_HISTORY_DIR"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (item["job_id"] + ".json")).write_text(json.dumps(item))
        payload = self.get("/api/history")
        self.assertContract("GET /api/history#items[]", payload["items"][0],
                            also=tuple(FRONTEND_CONDITIONAL["GET /api/history#items[]"]))

    def test_idle_job_and_list_endpoints_meet_the_contract(self):
        route = self.get("/api/route/status")
        tuner = self.get("/api/tuner/status")
        diagnostics = self.get("/api/diagnostics/status")
        history = self.get("/api/history")
        imported = self.get("/api/imported")
        versions = self.get("/api/profile-versions")
        sources = self.get("/api/tuner/sources")
        targets = self.get("/api/diagnostics/targets")
        with self.subTest(key="GET /api/route/status"):
            self.assertContract("GET /api/route/status", route)
        with self.subTest(key="GET /api/tuner/status"):
            self.assertContract("GET /api/tuner/status", tuner)
        with self.subTest(key="GET /api/diagnostics/status"):
            self.assertContract("GET /api/diagnostics/status", diagnostics)
        with self.subTest(key="GET /api/history"):
            self.assertContract("GET /api/history", history)
        with self.subTest(key="GET /api/imported"):
            self.assertContract("GET /api/imported", imported)
        with self.subTest(key="GET /api/profile-versions"):
            self.assertContract("GET /api/profile-versions", versions)
        with self.subTest(key="GET /api/tuner/sources"):
            self.assertContract("GET /api/tuner/sources", sources)
        with self.subTest(key="GET /api/diagnostics/targets"):
            self.assertContract("GET /api/diagnostics/targets", targets)
        for payload in (route, tuner, diagnostics, history, imported, versions, sources, targets):
            self.assertIs(payload["ok"], True)
        self.assertEqual({"GET /api/route/status": route["status"], "GET /api/tuner/status": tuner["status"],
                          "GET /api/diagnostics/status": diagnostics["status"]},
                         {"GET /api/route/status": "idle", "GET /api/tuner/status": "idle",
                          "GET /api/diagnostics/status": "idle"})
        self.assertElements("GET /api/imported#profiles[]", imported["profiles"])
        self.assertElements("GET /api/diagnostics/targets#standard[]", targets["standard"])
        self.assertElements("GET /api/diagnostics/targets#dpi[]", targets["dpi"])

    def test_active_is_a_boolean_in_every_job_status(self):
        for activity in (False, True):
            with self.subTest(active=activity), self.patched(
                route_active=mock.Mock(return_value=activity), tuner_active=mock.Mock(return_value=activity),
                diagnostic_active=mock.Mock(return_value=activity),
            ):
                route = self.get("/api/route/status")
                tuner = self.get("/api/tuner/status")
                diagnostics = self.get("/api/diagnostics/status")
                self.assertContract("GET /api/route/status", route)
                self.assertContract("GET /api/tuner/status", tuner)
                self.assertContract("GET /api/diagnostics/status", diagnostics)
                self.assertIs(route["active"], activity, "GET /api/route/status")
                self.assertIs(tuner["active"], activity, "GET /api/tuner/status")
                self.assertIs(diagnostics["active"], activity, "GET /api/diagnostics/status")

    def test_profile_versions_list_a_saved_version(self):
        version_id = self.profile_version()
        payload = self.get("/api/profile-versions")
        self.assertContract("GET /api/profile-versions", payload)
        self.assertElements("GET /api/profile-versions#versions[]", payload["versions"])
        self.assertEqual([(item["id"], item["service"], item["reason"], item["active"]) for item in payload["versions"]],
                         [(version_id, "youtube", "replaced", False)])


class JobFlowTests(PanelEndpointCase):
    """A job is started with a POST; its state then shows up in the status and history answers."""

    def test_route_post_answer_status_and_history_carry_the_job_fields(self):
        popen = self.fake_workers()
        started = self.post("/api/route/youtube/vpn", status=202)
        self.assertContract("POST /api/route/<svc>/<mode>", started)
        job_id = started["job_id"]
        self.assertRegex(job_id, r"^[0-9a-f]{16}$")
        self.assertContract("GET /api/route/status", started, also=("job_id", "stage", "stage_label", "progress", "operation", "service"))
        self.assertEqual((started["status"], started["operation"], started["service"], started["mode"], started["active"]),
                         ("queued", "switch", "youtube", "vpn", True))
        command = popen.call_args.args[0]
        self.assertEqual(command[2:], ["--route-job", job_id, "switch", "youtube", "vpn"])
        # Polling is read-only; the reaper/startup reconciliation persists it.
        status = self.get("/api/route/status")
        self.assertContract("GET /api/route/status", status, also=tuple(FRONTEND_CONDITIONAL["GET /api/route/status"]))
        self.assertEqual((status["job_id"], status["status"], status["stage"], status["active"], status["operation"],
                          status["service"]), (job_id, "failed", "failed", False, "switch", "youtube"))
        self.assertIn("неожиданно", status["error"])
        self.assertEqual(self.ns["safe_json_file"](self.ns["ROUTE_STATE"])["status"], "queued")
        self.ns["reconcile_route_job"]()
        history = self.get("/api/history")
        self.assertContract("GET /api/history", history)
        self.assertEqual([item["job_id"] for item in history["items"]], [job_id])
        self.assertElements("GET /api/history#items[]", history["items"], also=("snapshot",))
        self.assertEqual((history["items"][0]["status"], history["items"][0]["rollback_available"]), ("failed", False))

    def test_history_rollback_starts_a_job_from_a_saved_snapshot(self):
        snapshot = self.snapshot()
        self.history_record(snapshot=str(snapshot), before_routes={"youtube": "direct"})
        item = self.get("/api/history")["items"][0]
        self.assertIs(item["rollback_available"], True)
        popen = self.fake_workers()
        started = self.post("/api/history/rollback/0123456789abcdef", status=202)
        self.assertContract("POST /api/history/rollback/<id>", started)
        self.assertEqual((started["operation"], started["rollback_of"], started["status"]),
                         ("rollback", "0123456789abcdef", "queued"))
        self.assertEqual(popen.call_args.args[0][2:], ["--route-job", started["job_id"], "rollback",
                                                      "0123456789abcdef", str(snapshot)])

    def test_history_rollback_of_a_dead_unpolled_job_reconciles_it_first(self):
        # The worker died while nobody polled the status: its history entry still says "running".
        snapshot = self.snapshot()
        self.history_record(status="running", before_routes={"youtube": "direct"})
        self.write("ROUTE_STATE", json.dumps({"job_id": "0123456789abcdef", "status": "running"}))
        self.write("ROUTE_APPLY_LOG", f"Snapshot created: {snapshot}\n")
        popen = self.fake_workers()
        started = self.post("/api/history/rollback/0123456789abcdef", status=202)
        self.assertContract("POST /api/history/rollback/<id>", started)
        self.assertEqual((started["operation"], started["rollback_of"]), ("rollback", "0123456789abcdef"))
        self.assertEqual(popen.call_args.args[0][2:], ["--route-job", started["job_id"], "rollback",
                                                      "0123456789abcdef", str(snapshot)])
        items = {item["job_id"]: item for item in self.get("/api/history")["items"]}
        self.assertEqual((items["0123456789abcdef"]["status"], items["0123456789abcdef"]["snapshot"]),
                         ("failed", str(snapshot)))
        self.assertEqual(items[started["job_id"]]["status"], "queued")

    def test_diagnostics_start_health_queues_a_job(self):
        popen = self.fake_workers()
        started = self.post("/api/diagnostics/start/health", status=202)
        self.assertContract("POST /api/diagnostics/start/health", started)
        self.assertEqual((started["kind"], started["status"], started["active"], started["progress"], started["results"]),
                         ("health", "queued", True, 0, []))
        self.assertEqual(popen.call_args.args[0][2:], ["--kind", "health", "--job-id", started["job_id"]])
        status = self.get("/api/diagnostics/status")
        self.assertContract("GET /api/diagnostics/status", status, also=("job_id", "kind", "error"))
        self.assertEqual((status["job_id"], status["kind"], status["status"], status["active"]),
                         (started["job_id"], "health", "error", False))

    def test_vpn_node_activate_and_recover_start_route_jobs(self):
        manager = self.vpn_manager()
        manager.add("vless_2", json.dumps(vpn_outbound("other.example")))
        self.router(self.status_command())
        popen = self.fake_workers()
        started = self.post("/api/vpn-nodes/activate/vless_2", status=202)
        self.assertContract("POST /api/vpn-nodes/activate/<n>", started)
        self.assertEqual((started["operation"], started["service"], started["outbound_tag"]), ("vpn-node", "vpn", "vless_2"))
        self.assertEqual(popen.call_args.args[0][2:], ["--route-job", started["job_id"], "vpn-node", "vless_2", "-"])
        manager.transaction_file.write_text("{}", encoding="utf-8")
        self.assertIs(self.get("/api/vpn-nodes")["recovery_needed"], True)
        started = self.post("/api/vpn-nodes/recover", status=202)
        self.assertContract("POST /api/vpn-nodes/recover", started)
        self.assertEqual((started["operation"], started["mode"]), ("vpn-recover", "recover"))
        self.assertEqual(popen.call_args.args[0][2:], ["--route-job", started["job_id"], "vpn-recover", "-", "-"])


class PostEndpointTests(PanelEndpointCase):
    def test_checker_actions_and_explicit_ip_policy_contracts(self):
        checks = self.ns.module('domain.inspection')
        monitor = self.ns.module('domain.vpn_monitor')
        operations = self.ns.module('domain.operations')
        state = {'ok': True, 'config': {}, 'state': {}, 'identity': {}, 'expected': {}, 'verdict': 'unknown', 'active': False}
        with mock.patch.object(checks, 'start', return_value={'ok': True, 'job_id': '0123456789abcdef', 'kind': 'vpn', 'status': 'running', 'active': True}):
            self.assertContract('POST /api/inspection/check/<kind>', self.post('/api/inspection/check/vpn', {}, status=202))
        with mock.patch.object(operations, 'start_inspection_setup', return_value={'ok': True, 'job_id': '0123456789abcdef'}):
            self.post('/api/inspection/setup', {}, status=400)
            self.assertContract('POST /api/inspection/setup', self.post('/api/inspection/setup', {'confirm': True}, status=202))
        with mock.patch.object(monitor, 'save', return_value=state):
            self.assertContract('POST /api/vpn-monitor/save', self.post('/api/vpn-monitor/save', {'identity': {}, 'changes': {}}))
        with mock.patch.object(monitor, 'approve_vpn_monitor_ips', return_value=state):
            self.assertContract('POST /api/vpn-monitor/approve', self.post('/api/vpn-monitor/approve', {'identity': {}, 'observation_id': 'shown', 'families': ['ipv4']}))
        self.post('/api/vpn-monitor/approve', {'families': ['ipv4']}, status=400)

    def test_import_apply_clear_rollback_and_version_result_contracts(self):
        healthy = {"ok": True, "all_ok": True, "checks": []}
        command = {"ok": True, "code": 0, "output": "applied"}
        self.patch(apply_profile=lambda *a: dict(command), clear_imported_profile=lambda *a: dict(command),
                   rollback_import=lambda: dict(command), config_health=lambda: healthy)
        started, result = self.operation("/api/import/apply", make_report("youtube"))
        self.assertContract("POST /api/import/apply", started)
        self.assertContract("GET /api/route/result", result, also=("health", "code", "snapshot"))
        started, _ = self.operation("/api/import/clear/youtube")
        self.assertContract("POST /api/import/clear/<service>", started)
        started, _ = self.operation("/api/import/rollback")
        self.assertContract("POST /api/import/rollback", started)
        version = self.profile_version()
        started, _ = self.operation("/api/profiles/apply/youtube/" + version)
        self.assertContract("POST /api/profiles/apply/<service>/<version_id>", started)

    def test_vpn_node_add_check_delete_and_sync_current(self):
        manager = self.vpn_manager(probes=(GOOD_PROBE, BAD_PROBE))
        added = self.post("/api/vpn-nodes/add", {"name": "vless_2", "source": json.dumps(vpn_outbound("other.example"))})
        self.assertContract("POST /api/vpn-nodes/add", added)
        self.assertContract("GET /api/route/result#node", added["node"])
        self.assertContract("GET /api/vpn-nodes#nodes[]", added["node"])
        self.assertIsNone(added['node']['health'])
        self.assertEqual((added["node"]["id"], added["node"]["active"]), ("vless_2", False))
        self.assertIn("vless_2", manager.load()["nodes"])
        from kdn import vpn_ping
        with mock.patch.object(vpn_ping,'run',side_effect=lambda selected,_binary:{key:{'ok':True,'latency_ms':25,'latency_kind':'http_keepalive','http_code':204} for key in selected}) as ping:
            answer=self.post('/api/vpn-nodes/ping/vless_2')
            self.assertContract('POST /api/vpn-nodes/ping/<id>',answer)
            self.assertEqual(answer['ping']['latency_ms'],25)
            batch=self.post('/api/vpn-nodes/ping')
            self.assertContract('POST /api/vpn-nodes/ping',batch)
            self.assertEqual(len(batch['results']),2)
            self.assertEqual(ping.call_count,2)
        started, checked = self.operation("/api/vpn-nodes/check/vless_2")
        self.assertContract("POST /api/vpn-nodes/check/<id>", started)
        self.assertContract("GET /api/route/result", checked, also=("health",))
        self.assertEqual(checked["status"], "completed")
        self.assertIs(checked["health"]["ok"], True)
        self.assertContract('GET /api/vpn-nodes#nodes[].health',checked['health'],also=('latency_ms','http_code'))
        _, checked = self.operation('/api/vpn-nodes/check/vless_2')
        self.assertIs(checked['health']['ok'], False)
        self.assertEqual(self.post("/api/vpn-nodes/sync-current"), {"ok": True})
        self.assertIsNone(manager.load()["nodes"]["current"]["health"])
        self.assertEqual(self.post("/api/vpn-nodes/delete/vless_2"), {"ok": True})
        self.assertEqual(list(manager.load()["nodes"]), ["current"])

    def test_history_delete_moves_the_record_to_the_trash(self):
        snapshot = self.snapshot()
        self.history_record(snapshot=str(snapshot))
        payload = self.post("/api/history/delete/0123456789abcdef")
        self.assertEqual(payload, {"ok": True, "snapshot_preserved": True})
        self.assertEqual(self.get("/api/history")["items"], [])
        self.assertTrue(snapshot.is_dir())
        self.assertEqual(len(list((self.ns["RECORD_TRASH_DIR"] / "history").glob("*.json"))), 1)

    def test_profile_version_delete_moves_the_file_to_the_trash(self):
        version_id = self.profile_version()
        payload = self.post(f"/api/profile-versions/delete/youtube/{version_id}")
        self.assertEqual(payload, {"ok": True, "archived": True})
        self.assertEqual(self.get("/api/profile-versions")["versions"], [])
        self.assertEqual(len(list((self.ns["RECORD_TRASH_DIR"] / "versions" / "youtube").glob("*.json"))), 1)

    def test_updates_check_up_to_date_when_the_commit_is_cached(self):
        self.flowseal_cache()
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"sha": "a" * 40, "commit": {"committer": {"date": "2026-10-20T09:00:00Z"}}}).encode()
        with mock.patch.object(self.ns["urllib"].request, "urlopen", return_value=response) as urlopen:
            payload = self.post("/api/updates/check")
        self.assertContract("POST /api/updates/check", payload)
        self.assertEqual((payload["status"], payload["source_count"], payload["downloaded_commit"], payload["latest_date"]),
                         ("up_to_date", 1, "a" * 40, "2026-10-20T09:00:00Z"))
        self.assertIn("api.github.com/repos/", urlopen.call_args.args[0].full_url)
        self.assertEqual(self.get("/api/updates")["status"], "up_to_date")

    def test_tuner_apply_applies_the_found_profile_and_attaches_the_check(self):
        self.write("TUNER_STATE", json.dumps({"status": "found", "result_available": True}))
        self.write("TUNER_RESULT", json.dumps(make_report("youtube")))
        applied = []

        def apply_profile(profile):
            applied.append(profile["service"])
            return {"ok": True, "code": 0, "output": "engine applied"}

        self.patch(apply_profile=apply_profile)
        self.router({("pidof", "xray"): OK, ("pidof", "nfqws2"): OK})
        started, payload = self.operation("/api/tuner/apply")
        self.assertContract("POST /api/tuner/apply", started)
        self.assertContract("GET /api/route/result", payload, also=("health",))
        self.assertEqual((applied, payload["output"]), (["youtube"], "engine applied"))
        self.assertContract("GET /api/checks/config", payload["health"])

    def test_automation_cancel_asks_a_running_job_to_stop(self):
        lock = threading.Lock()
        lock.acquire()
        try:
            self.patch(AUTOMATION_RUN_LOCK=lock)
            payload = self.post("/api/automation/cancel", status=202)
        finally:
            lock.release()
        self.assertEqual(payload, {"ok": True, "status": "cancelling"})
        self.assertTrue(self.ns["AUTOMATION_CANCEL"].is_set())

    def test_diagnostics_cancel_signals_the_running_job(self):
        self.write("DIAGNOSTIC_STATE", json.dumps(
            {"job_id": "0123456789abcdef", "kind": "health", "status": "running", "active": True}))
        store = self.ns.module("jobfiles").DIAGNOSTIC_STORE
        (self.ns["DIAGNOSTIC_JOB_DIR"] / "job.id").write_text("0123456789abcdef")
        before = self.ns["DIAGNOSTIC_STATE"].read_bytes()
        with mock.patch.object(store, "pid", return_value=4242), mock.patch.object(store, "alive", return_value=True), \
                mock.patch.object(self.ns["os"], "killpg") as killpg:
            payload = self.post("/api/diagnostics/cancel", status=202)
        killpg.assert_called_once_with(4242, signal.SIGTERM)
        self.assertContract("GET /api/diagnostics/status", payload)
        self.assertEqual((payload["ok"], payload["status"], payload["active"]), (True, "cancelling", True))
        self.assertEqual(self.ns["DIAGNOSTIC_STATE"].read_bytes(), before)
        self.assertTrue((self.ns["DIAGNOSTIC_JOB_DIR"] / "cancel.request").is_file())

    def test_xkeen_actions_run_xkeen_then_check_xray(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        for action, xray_running in (("start", True), ("stop", False), ("restart", True)):
            with self.subTest(action=action):
                commands = self.router({
                    tuple([xkeen, action] + ([] if action == "stop" else ["on"])): {"ok": True, "code": 0, "output": f"{action} done"},
                    ("pidof", "xray"): OK if xray_running else FAILED,
                })
                started, payload = self.operation(f"/api/xkeen/{action}")
                self.assertContract("POST /api/xkeen/<action>", started)
                self.assertEqual((payload["result_ok"], payload["code"], payload["output"]), (True, 0, f"{action} done"))
                self.assertEqual(commands.calls, [
                    {"command": [xkeen, action] + ([] if action == "stop" else ["on"]), "timeout": 150, "env": None},
                    {"command": ["pidof", "xray"], "timeout": 5, "env": None},
                ])

    def test_xkeen_action_that_leaves_xray_in_the_wrong_state_fails_with_a_note(self):
        started = "Xray не запущен после команды XKeen"
        stopped = "Xray всё ещё запущен после остановки XKeen"
        for action, xray_running, note in (("start", False, started), ("restart", False, started), ("stop", True, stopped)):
            with self.subTest(action=action):
                self.router({
                    tuple([str(self.ns["XKEEN_INIT"]), action] + ([] if action == "stop" else ["on"])): {"ok": True, "code": 0, "output": f"{action} done"},
                    ("pidof", "xray"): OK if xray_running else FAILED,
                })
                _started, payload = self.operation(f"/api/xkeen/{action}")
                self.assertEqual((payload["result_ok"], payload["code"], payload["output"]), (False, 0, f"{action} done\n{note}"))
                self.assertEqual(missing_fields("*", payload), [])


class ErrorAnswerTests(PanelEndpointCase):
    """Every JSON answer with ok: false says why in error or output (index.html readJson shows them).

    One test per failing request, generated from ERROR_CASES below; each starts from a fresh environment.
    """

    def offline(self):
        patcher = mock.patch.object(self.ns["urllib"].request, "urlopen", side_effect=OSError("offline"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_xkeen_start_fails(self):
        self.router({(str(self.ns["XKEEN_INIT"]), "start", "on"): {"ok": False, "code": 3, "output": "no xkeen"}})
        started, result = self.operation("/api/xkeen/start")
        self.assertContract("POST /api/xkeen/<action>", started)
        self.assertContract("GET /api/route/result", result, also=("error", "code"))
        self.assertIs(result["ok"], True)  # result fetch succeeded, operation did not
        self.assertIs(result["result_ok"], False)
        self.assertEqual((result["code"], result["output"]), (3, "no xkeen"))

    def test_a_request_without_the_control_header_is_refused_with_an_error(self):
        response, data = self.request("POST", "/api/xkeen/start", body=b"{}", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 403)
        answer = json.loads(data)
        self.assertIs(answer["ok"], False)
        self.assertEqual(missing_fields("*", answer), [])


def _engine_fails(case):
    case.write_engine()
    case.router({("/bin/sh", str(case.engine), "--status", "--json"): {"ok": False, "code": 2, "output": "engine failed"},
                 ("/bin/sh", str(case.engine), "--status"): {"ok": False, "code": 2, "output": "engine failed"}})


def _registry_damaged(case):
    case.vpn_manager()
    (case.root / "vpn-nodes.json").write_text("{", encoding="utf-8")


def _xray_config_missing(case):
    case.vpn_manager()
    (case.root / "xray" / "04_outbounds.json").unlink()


# name -> (status, method, path, body, setup(case))
ERROR_CASES = {
    "unknown_get": (404, "GET", "/api/nope", None, None),
    "discord_cache_helper_missing": (404, "GET", "/tools/reset-discord-cache.ps1", None, None),
    "status_without_the_engine": (500, "GET", "/api/status", None, None),
    "status_when_the_engine_fails": (500, "GET", "/api/status", None, _engine_fails),
    "service_configs_without_nfqws2_conf": (500, "GET", "/api/service-configs", None, None),
    "vpn_nodes_with_a_damaged_registry": (500, "GET", "/api/vpn-nodes", None, _registry_damaged),
    "unknown_post": (404, "POST", "/api/nope", None, None),
    "vpn_add_with_a_wrong_body": (400, "POST", "/api/vpn-nodes/add", [1], lambda case: case.vpn_manager()),
    "vpn_check_of_an_unknown_node": (400, "POST", "/api/vpn-nodes/check/nope", None, lambda case: case.vpn_manager()),
    "vpn_delete_of_the_active_node": (400, "POST", "/api/vpn-nodes/delete/current", None, lambda case: case.vpn_manager()),
    "vpn_sync_current_without_the_xray_config": (400, "POST", "/api/vpn-nodes/sync-current", None, _xray_config_missing),
    "vpn_recover_without_a_transaction": (400, "POST", "/api/vpn-nodes/recover", None, lambda case: case.vpn_manager()),
    "vpn_activate_with_a_bad_name": (400, "POST", "/api/vpn-nodes/activate/1x", None, None),
    "history_delete_with_a_bad_id": (400, "POST", "/api/history/delete/not-an-id", None, None),
    "history_rollback_of_an_unknown_record": (400, "POST", "/api/history/rollback/0123456789abcdef", None, None),
    "profile_version_delete_of_a_missing_file": (
        400, "POST", "/api/profile-versions/delete/youtube/20261020T100000Z-aaaaaaaaaaaa-replaced-1", None, None),
    "updates_check_without_network": (502, "POST", "/api/updates/check", None, lambda case: case.offline()),
    "tuner_apply_without_a_result": (400, "POST", "/api/tuner/apply", None, None),
    "automation_cancel_without_a_run": (409, "POST", "/api/automation/cancel", None, None),
    "diagnostics_start_without_the_script": (
        500, "POST", "/api/diagnostics/start/health", None, lambda case: case.patch(DIAGNOSTICS=case.root / "missing.py")),
    "diagnostics_start_of_a_browser_only_kind": (400, "POST", "/api/diagnostics/start/standard", None, None),
    "diagnostics_cancel_without_a_run": (409, "POST", "/api/diagnostics/cancel", None, None),
    "route_switch_during_a_tuner_run": (
        409, "POST", "/api/route/youtube/vpn", None, lambda case: case.patch(tuner_active=lambda: True)),
}


def _error_case_test(status, method, path, body, setup):
    def test(self):
        if setup:
            setup(self)
        answer = self.get(path, status) if method == "GET" else self.post(path, body, status)
        self.assertIs(answer["ok"], False, answer)
        self.assertEqual(missing_fields("*", answer), [], answer)

    return test


for _name, _spec in ERROR_CASES.items():
    setattr(ErrorAnswerTests, f"test_{_name}", _error_case_test(*_spec))


if __name__ == "__main__":
    unittest.main()

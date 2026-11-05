"""Serve the panel page with canned API answers for browser UI tests.

Usage: python3 tests/panel_mock_server.py PORT

The page is tools/router/kdn/web/assets/index.html. GET answers come from
RESPONSES; a test can replace any of them with
POST /__mock/set {"path": ..., "body": ...}. Every other POST succeeds, and
starting a job (route switch, VPN node activate or recover, history rollback)
is answered with JOB_ANSWER, as the panel does; POST /__mock/set
{"method": "POST", "path": ..., "status": 500, "body": ...} changes a POST
answer. {"path": ..., "delay": seconds} slows an answer down.
GET /__mock/stats returns the request count and the most requests in flight
at once, per "METHOD path"; {"reset_stats": true} clears them. The canned
answers carry the fields of tests/panel_contract.py (tests/test_panel_contract.py
checks it). Nothing here touches the router or the network beyond 127.0.0.1.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HTML = (REPO / "tools/router/kdn/web/assets/index.html").read_bytes()
BROWSER_JS = (REPO / "tools/router/browser-diagnostics.js").read_bytes()
INSPECTION_JS = (REPO / 'tools/router/kdn/web/assets/inspection.js').read_bytes()

RESPONSES: dict[str, dict] = {
    '/api/dns': {'ok':True,'supported':True,'mode':'vless','interface':'Home','detail':'','pending':False,'recovery_mode':None,'host_overrides':0},
    '/api/notifications': {'ok':True,'enabled':False,'topic':'kdn-'+48*'a','token_set':True,
                           'events':['vpn-check-failed'],'choices':[{'id':'vpn-check-failed','title':'VPN: проверка не проходит'},
                                                                     {'id':'night-failed','title':'Ночная проверка: ошибка'}],
                           'url':'','pending':0,'last_delivery':None,'error':''},
    '/api/inspection/status': {'ok': True, 'status': 'idle', 'active': False, 'results': {}},
    '/api/vpn-monitor': {'ok': True, 'active': False, 'identity': {}, 'expected': {}, 'verdict': 'unknown',
                         'config': {'enabled': False, 'interval_minutes': 5, 'families': ['ipv4', 'ipv6'], 'nodes': {}, 'version': 1},
                         'state': {'history': []}, 'detail': '', 'next_check': None},
    "/api/status": {
        "ok": True,
        "discord_route": "mixed",
        "discord_tcp_route": "zapret",
        "discord_voice_route": "direct",
        "youtube_route": "vless",
        "telegram_route": "unmanaged",
        "xkeen_runtime": "running",
    },
    "/api/imported": {"ok": True, "rollback_available": False, "profiles": []},
    "/api/profile-versions": {"ok": True, "versions": []},
    "/api/history": {"ok": True, "items": []},
    "/api/updates": {"ok": True, "status": "never_downloaded"},
    "/api/tuner/sources": {"ok": True, "status": "never_downloaded", "commit": "", "sources": []},
    "/api/tuner/status": {"ok": True, "status": "idle", "active": False, "log_tail": [], "result_available": False},
    "/api/tuner/voice-endpoint": {"ok": True, "endpoint": None},
    "/api/diagnostics/status": {"ok": True, "status": "idle", "active": False, "progress": 0, "results": []},
    "/api/route/status": {"ok": True, "status": "idle", "active": False, "output": ""},
    "/api/route/result": {"ok": True, "job_id": "0123456789abcdef", "status": "completed", "active": False,
                          "result_ok": True, "code": 0, "output": "mock"},
    "/api/checks/config": {"ok": True, "checks": []},
    "/api/vpn-nodes": {"ok": True, "active": "current", "nodes": [], "drift": False, "warning": "",
                       "canonical_tag": "vless-reality", "recovery_needed": False},
    "/api/automation": {"ok": True, "active": False, "next_run": None,
                        "config": {"enabled": False, "times": ["03:00"], "services": {
                            service: {"enabled": True, "mix_level": "safe", "max_candidates": 32, "source_file": ""}
                            for service in ("youtube", "discord-tcp")}},
                        "state": {"status": "idle", "history": []}},
    "/api/diagnostics/targets": {"ok": True, "standard": [], "dpi": []},
}
POST_RESPONSES: dict[str, tuple[int, dict]] = {}
JOB_START = re.compile(r"/api/(?:route/[a-z-]+/[a-z]+|vpn-nodes/(?:activate/[^/]+|recover|add|check/[^/]+)|history/rollback/[0-9a-f]{16}|xkeen/(?:start|stop|restart)|import/(?:apply|rollback|clear/[^/]+)|tuner/apply|profiles/apply/[^/]+/[^/]+)")
JOB_ANSWER = {
    "ok": True, "job_id": "0123456789abcdef", "operation": "switch", "status": "queued", "stage": "queued",
    "stage_label": "В очереди", "progress": 0, "active": True, "service": "youtube", "output": "",
}
DELAYS: dict[str, float] = {}
SEQUENCES: dict[str, list] = {}
STATS: dict[str, dict[str, int]] = {}
STATS_LOCK = threading.Lock()


def post_answer(path: str) -> tuple[int, dict]:
    if path in POST_RESPONSES:
        return POST_RESPONSES[path]
    if path in ('/api/dns/vless','/api/dns/doh'):return 202,JOB_ANSWER
    if path=='/api/notifications/save':return 200,RESPONSES['/api/notifications']
    if path=='/api/notifications/test':return 202,{'ok':True,'queued':True}
    if path=='/api/notifications/topic':return 200,{'ok':True,'topic':'kdn-'+48*'b'}
    if path in ('/api/vpn-monitor/save', '/api/vpn-monitor/approve'):
        return 200, RESPONSES['/api/vpn-monitor']
    if path.startswith('/api/inspection/check/'):
        return 202, {'ok': True, 'job_id': '0123456789abcdef', 'kind': path.rsplit('/', 1)[1], 'status': 'running', 'active': True}
    if path == '/api/inspection/setup':
        return 202, JOB_ANSWER
    if JOB_START.fullmatch(path):
        operation = ("xkeen" if path.startswith("/api/xkeen/") else "vpn-add" if path == "/api/vpn-nodes/add"
                     else "vpn-check" if "/vpn-nodes/check/" in path else "import-clear" if "/import/clear/" in path
                     else "import-rollback" if path == "/api/import/rollback" else "apply-profile" if path.endswith("/apply") or "/profiles/apply/" in path
                     else "vpn-node" if "/vpn-nodes/activate/" in path else "vpn-recover" if path.endswith("/recover") else "switch")
        return 202, {**JOB_ANSWER, "operation": operation}
    return 200, {"ok": True, "output": "mock"}


def track(key: str, change: int) -> None:
    with STATS_LOCK:
        entry = STATS.setdefault(key, {"count": 0, "in_flight": 0, "max_in_flight": 0})
        if change > 0:
            entry["count"] += 1
        entry["in_flight"] += change
        entry["max_in_flight"] = max(entry["max_in_flight"], entry["in_flight"])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def answer(self, method: str, path: str, code: int, payload: dict) -> None:
        key = f"{method} {path}"
        track(key, 1)
        try:
            time.sleep(DELAYS.get(path, 0))
            self.reply(code, json.dumps(payload).encode(), "application/json")
        finally:
            track(key, -1)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.reply(200, HTML, "text/html; charset=utf-8")
        elif path == "/assets/browser-diagnostics.js":
            self.reply(200, BROWSER_JS, "application/javascript")
        elif path == '/assets/inspection.js':
            self.reply(200, INSPECTION_JS, 'application/javascript')
        elif path == "/__mock/stats":
            with STATS_LOCK:
                body = json.dumps(STATS).encode()
            self.reply(200, body, "application/json")
        elif path in RESPONSES:
            with STATS_LOCK:
                sequence = SEQUENCES.get(path)
                value = sequence.pop(0) if sequence and len(sequence) > 1 else sequence[0] if sequence else RESPONSES[path]
            if isinstance(value, dict) and "body" in value and "status" in value:
                self.answer("GET", path, value["status"], value["body"])
            else:
                self.answer("GET", path, 200, value)
        else:
            self.reply(404, b'{"ok":false,"error":"not found"}', "application/json")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/__mock/set":
            change = json.loads(body)
            if change.get("reset_stats"):
                with STATS_LOCK:
                    STATS.clear()
            elif "delay" in change:
                DELAYS[change["path"]] = float(change["delay"])
            elif "sequence" in change:
                SEQUENCES[change["path"]] = list(change["sequence"])
            elif change.get("method") == "POST":
                POST_RESPONSES[change["path"]] = (int(change.get("status", 200)), change["body"])
            else:
                RESPONSES[change["path"]] = change["body"]
                SEQUENCES.pop(change["path"], None)
            self.reply(200, b'{"ok":true}', "application/json")
            return
        code, payload = post_answer(self.path)
        self.answer("POST", self.path, code, payload)


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ready {port}", flush=True)
    server.serve_forever()

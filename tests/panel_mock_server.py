"""Serve the panel page with canned API answers for browser UI tests.

Usage: python3 tests/panel_mock_server.py PORT

The page is extracted from tools/router/xkeen_control_script.sh. GET
answers come from RESPONSES; a test can replace any of them with
POST /__mock/set {"path": ..., "body": ...}. Every other POST succeeds
unless POST /__mock/set {"method": "POST", "path": ..., "status": 500,
"body": ...} changes it. {"path": ..., "delay": seconds} slows an answer
down. GET /__mock/stats returns the request count and the most requests in
flight at once, per "METHOD path"; {"reset_stats": true} clears them.
Nothing here touches the router or the
network beyond 127.0.0.1.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel_loader import panel_source  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
NAMESPACE: dict = {"__name__": "panel_mock"}
exec(compile(panel_source(), "panel_app.py", "exec"), NAMESPACE)
HTML = NAMESPACE["HTML"].encode("utf-8")
BROWSER_JS = (REPO / "tools/router/browser-diagnostics.js").read_bytes()

RESPONSES: dict[str, dict] = {
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
    "/api/tuner/status": {"ok": True, "status": "idle", "active": False},
    "/api/tuner/voice-endpoint": {"ok": True, "endpoint": None},
    "/api/diagnostics/status": {"ok": True, "status": "idle", "active": False},
    "/api/route/status": {"ok": True, "status": "idle", "active": False},
    "/api/checks/config": {"ok": True, "checks": []},
}
POST_RESPONSES: dict[str, tuple[int, dict]] = {}
DELAYS: dict[str, float] = {}
STATS: dict[str, dict[str, int]] = {}
STATS_LOCK = threading.Lock()


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
        elif path == "/__mock/stats":
            with STATS_LOCK:
                body = json.dumps(STATS).encode()
            self.reply(200, body, "application/json")
        elif path in RESPONSES:
            self.answer("GET", path, 200, RESPONSES[path])
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
            elif change.get("method") == "POST":
                POST_RESPONSES[change["path"]] = (int(change.get("status", 200)), change["body"])
            else:
                RESPONSES[change["path"]] = change["body"]
            self.reply(200, b'{"ok":true}', "application/json")
            return
        code, payload = POST_RESPONSES.get(self.path, (200, {"ok": True, "output": "mock"}))
        self.answer("POST", self.path, code, payload)


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ready {port}", flush=True)
    server.serve_forever()

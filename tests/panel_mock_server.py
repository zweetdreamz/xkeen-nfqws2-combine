"""Serve the panel page with canned API answers for browser UI tests.

Usage: python3 tests/panel_mock_server.py PORT

The page is extracted from tools/router/xkeen_control_script.sh. GET
answers come from RESPONSES; a test can replace any of them with
POST /__mock/set {"path": ..., "body": ...}. Every other POST succeeds.
Nothing here touches the router or the network beyond 127.0.0.1.
"""

from __future__ import annotations

import json
import sys
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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.reply(200, HTML, "text/html; charset=utf-8")
        elif path == "/assets/browser-diagnostics.js":
            self.reply(200, BROWSER_JS, "application/javascript")
        elif path in RESPONSES:
            self.reply(200, json.dumps(RESPONSES[path]).encode(), "application/json")
        else:
            self.reply(404, b'{"ok":false,"error":"not found"}', "application/json")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/__mock/set":
            change = json.loads(body)
            RESPONSES[change["path"]] = change["body"]
            self.reply(200, b'{"ok":true}', "application/json")
            return
        self.reply(200, b'{"ok":true,"output":"mock"}', "application/json")


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ready {port}", flush=True)
    server.serve_forever()

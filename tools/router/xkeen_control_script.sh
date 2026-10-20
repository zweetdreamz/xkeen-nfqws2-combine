#!/bin/sh
set -eu

# Installs only the local web application file. It does not change routing,
# XKeen, nfqws2 or startup settings while this installer is running.

APP_DIR="${XKEEN_WEB_DIR:-/opt/xkeen-web}"
mkdir -p "$APP_DIR"

cat > "$APP_DIR/app.py" <<'PYEOF'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


PORT = int(os.environ.get("XKEEN_WEB_PORT", "8088"))
BIND_HOST = os.environ.get("XKEEN_WEB_BIND", "192.168.2.1")
PROJECT_DIR = Path(
    os.environ.get("XKEEN_PROJECT_DIR", "/opt/root/keenetic-discord-nfqws2")
)
ENGINE = PROJECT_DIR / "apply-discord-nfqws2.sh"
SERVICE_SWITCH = PROJECT_DIR / "set-service-route.sh"
AUTOTUNER = PROJECT_DIR / "tools" / "router" / "zapret_autotune_job.py"
DIAGNOSTICS = PROJECT_DIR / "tools" / "router" / "xkeen_diagnostics.py"
DISCORD_CACHE_HELPER = PROJECT_DIR / "tools" / "windows" / "reset-discord-cache.ps1"
BROWSER_DIAGNOSTICS = PROJECT_DIR / "tools" / "router" / "browser-diagnostics.js"
XKEEN = shutil.which("xkeen") or "/opt/sbin/xkeen"
IMPORTED_PROFILE_DIR = Path("/opt/etc/nfqws2/imported-profiles")
PROFILE_VERSION_DIR = Path("/opt/etc/nfqws2/profile-versions")
NFQWS_CONFIG = Path("/opt/etc/nfqws2/nfqws2.conf")
DISCORD_LIST = Path("/opt/etc/nfqws2/lists/user.list")
XRAY_ROUTING = Path("/opt/etc/xray/configs/05_routing.json")
IMPORT_ROLLBACK_POINTER = Path(
    "/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr"
)
TUNER_JOB_DIR = Path("/opt/tmp/xkeen-zapret-tuner")
TUNER_STATE = TUNER_JOB_DIR / "state.json"
TUNER_RESULT = TUNER_JOB_DIR / "result-report.json"
TUNER_VERDICT = TUNER_JOB_DIR / "verdict.txt"
TUNER_PID = TUNER_JOB_DIR / "panel-launch.pid"
DIAGNOSTIC_JOB_DIR = Path("/opt/tmp/xkeen-diagnostics")
DIAGNOSTIC_STATE = DIAGNOSTIC_JOB_DIR / "state.json"
DIAGNOSTIC_PID = DIAGNOSTIC_JOB_DIR / "panel-launch.pid"
DIAGNOSTIC_LOG = DIAGNOSTIC_JOB_DIR / "process.log"
ROUTE_JOB_DIR = Path("/opt/tmp/xkeen-route-switch")
ROUTE_STATE = ROUTE_JOB_DIR / "state.json"
ROUTE_PID = ROUTE_JOB_DIR / "worker.pid"
ROUTE_LOG = ROUTE_JOB_DIR / "process.log"
ROUTE_APPLY_LOG = ROUTE_JOB_DIR / "apply.log"
# Held while any background job (route, tuner, diagnostics) is being started,
# from its "nothing else is running" checks until its PID file is written.
JOB_START_LOCK = threading.Lock()
ROUTE_HISTORY_DIR = Path("/opt/etc/xkeen-web/history")
SNAPSHOT_DIR = Path("/opt/etc/keenetic-discord-nfqws2/snapshots")
FLOWSEAL_UPDATE_STATE = Path("/opt/etc/xkeen-web/flowseal-update.json")
FLOWSEAL_SOURCE_CACHE = Path("/opt/etc/xkeen-web/flowseal-sources.json")
FLOWSEAL_UPDATE_LOCK = threading.Lock()
FLOWSEAL_REPOSITORY = "Flowseal/zapret-discord-youtube"
FLOWSEAL_REF = "main"
MAX_REPORT_BYTES = 512 * 1024
MAX_HISTORY_ITEMS = 50
SERVICES = ("youtube", "discord-tcp", "discord-voice")
ROUTE_SERVICES = ("discord-tcp", "discord-voice", "youtube")
# "discord" is accepted as a shorthand that switches Discord TCP and Voice together.
ROUTE_REQUEST_SERVICES = ROUTE_SERVICES + ("discord",)
ROUTE_VALUES = {"direct", "zapret", "vless"}
STATUS_ROUTE_KEYS = {
    "discord-tcp": "discord_tcp_route",
    "discord-voice": "discord_voice_route",
    "youtube": "youtube_route",
}
# Same pattern as zapret_tuner.SOURCE_NAME_RE: one Flowseal general*.bat file.
SOURCE_FILE_NAME = re.compile(r"general[A-Za-z0-9 ()_.-]*\.bat", re.IGNORECASE)
SAFE_TOKEN = re.compile(r"^--[a-z0-9-]+=[A-Za-z0-9_@/.,:+<>=!-]+$")
SAFE_OPTIONS = {
    "filter-tcp",
    "filter-udp",
    "filter-l7",
    "hostlist",
    "out-range",
    "payload",
    "lua-desync",
}
SAFE_LUA = {"fake", "multisplit", "multidisorder", "fakedsplit", "hostfakesplit"}


HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f4f5f7" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0e1116" media="(prefers-color-scheme: dark)">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%234f5bd5'/%3E%3Cpath d='M9 22h9a3.5 3.5 0 0 0 0-7h-4a3.5 3.5 0 0 1 0-7h9' fill='none' stroke='white' stroke-width='2.4' stroke-linecap='round'/%3E%3C/svg%3E">
<title>XKeen Control</title>
<style>
:root{color-scheme:light dark;
--bg:#f4f5f7;--surface:#fff;--surface-2:#f7f8fa;--sunken:#eef0f4;--line:#e3e6ec;--line-strong:#cfd4dd;
--text:#141a26;--muted:#5f6879;--faint:#8a93a3;
--accent:#4f5bd5;--accent-strong:#3f49b8;--accent-soft:#eceefd;--on-accent:#fff;
--green:#0f8a5f;--green-soft:#e6f5ee;--red:#d1343f;--red-soft:#fdecee;--amber:#a85b00;--amber-soft:#fff4e0;
--direct:#1f6fd1;--zapret:#0f8a5f;--vpn:#7a4fd6;
--shadow:0 1px 2px rgba(16,24,40,.05),0 4px 16px rgba(16,24,40,.05);--ring:0 0 0 3px rgba(79,91,213,.28);
--radius:16px;--radius-sm:10px;--mono:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{
--bg:#0e1116;--surface:#161a21;--surface-2:#1b2029;--sunken:#11151b;--line:#272d38;--line-strong:#363d4a;
--text:#e7eaf0;--muted:#a0a8b7;--faint:#757e8e;
--accent:#8e97ff;--accent-strong:#a9b0ff;--accent-soft:#232848;--on-accent:#0e1116;
--green:#3fcf8e;--green-soft:#15291f;--red:#ff6b74;--red-soft:#2e1619;--amber:#f4b740;--amber-soft:#2b2210;
--direct:#5aa4ff;--zapret:#3fcf8e;--vpn:#b294ff;
--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25);--ring:0 0 0 3px rgba(142,151,255,.35)}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
.i{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.page{width:min(1080px,calc(100% - 32px));margin:0 auto;padding:0 0 48px}
header{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:28px 0 18px}
.brand{display:flex;align-items:center;gap:14px;min-width:0}
.logo{display:grid;place-items:center;width:46px;height:46px;flex:none;border-radius:13px;background:linear-gradient(135deg,#5b67e8,#3f49b8);color:#fff;box-shadow:0 6px 18px rgba(79,91,213,.35)}
.logo .i{width:24px;height:24px;stroke-width:2.2}
h1{margin:0;font-size:clamp(22px,4vw,28px);line-height:1.15;letter-spacing:-.02em;font-weight:720}
.subtitle,.hint,.muted{color:var(--muted)}.subtitle{font-size:14px}
.status{display:inline-flex;align-items:center;gap:9px;padding:7px 14px 7px 12px;border:1px solid var(--line);border-radius:999px;background:var(--surface);box-shadow:var(--shadow);font-size:14px;font-weight:600;white-space:nowrap}
.dot{position:relative;width:9px;height:9px;border-radius:50%;background:var(--amber);color:var(--amber)}
.dot.ok{background:var(--green);color:var(--green)}.dot.bad{background:var(--red);color:var(--red)}
.dot.ok::after{content:"";position:absolute;inset:-4px;border-radius:50%;border:2px solid currentColor;opacity:0;animation:pulse 2.4s ease-out infinite}
@keyframes pulse{0%{transform:scale(.6);opacity:.55}100%{transform:scale(1.5);opacity:0}}
.tabs{position:sticky;top:0;z-index:5;display:flex;gap:4px;margin:0 -4px;padding:6px 4px;overflow-x:auto;scrollbar-width:none;background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:saturate(1.4) blur(10px);-webkit-backdrop-filter:saturate(1.4) blur(10px)}
.tabs::-webkit-scrollbar{display:none}
.tabs .tab{display:inline-flex;align-items:center;gap:8px;padding:9px 14px;border:1px solid transparent;border-radius:11px;background:transparent;color:var(--muted);font-weight:600;white-space:nowrap;box-shadow:none}
.tabs .tab:hover{background:var(--surface);color:var(--text);border-color:var(--line);transform:none}
.tabs .tab.active{background:var(--surface);color:var(--accent);border-color:var(--line);box-shadow:var(--shadow)}
.tab-page{display:none}.tab-page.active{display:block;animation:fade .18s ease-out}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.card{border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow);padding:22px;margin-top:16px}
.card h2{margin:0 0 4px;font-size:18px;line-height:1.3;letter-spacing:-.01em;font-weight:680}
.hint{margin:0 0 16px;font-size:14px}
button{appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);padding:10px 16px;background:var(--surface);color:var(--text);font:inherit;font-size:14px;font-weight:600;line-height:1.3;cursor:pointer;transition:background .15s,border-color .15s,color .15s,box-shadow .15s,transform .15s}
button:hover{background:var(--surface-2);border-color:var(--faint)}
button:active{transform:translateY(1px)}
button:focus-visible,a:focus-visible,select:focus-visible,input:focus-visible{outline:none;box-shadow:var(--ring);border-color:var(--accent)}
button:disabled{opacity:.5;cursor:not-allowed;transform:none}
.apply{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}.apply:hover{background:var(--accent-strong);border-color:var(--accent-strong)}
.cancel,.stop{color:var(--red)}.cancel:hover,.stop:hover{background:var(--red-soft);border-color:var(--red)}
.rollback,.restart{color:var(--amber)}.rollback:hover,.restart:hover{background:var(--amber-soft);border-color:var(--amber)}
.start{color:var(--green)}.start:hover{background:var(--green-soft);border-color:var(--green)}
.clear{padding:7px 12px;font-size:13px;border-color:var(--line);color:var(--muted)}.clear:hover{color:var(--text)}
.xkeen-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.xkeen-actions button{padding:12px 16px}
.services{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.service,.profile{border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--surface-2)}
.service-head,.profile-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}
.service h3,.profile h3{margin:0;font-size:16px;font-weight:680}
.service-title{display:flex;align-items:center;gap:10px}
.service-icon{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;color:#fff;font-weight:800;font-size:15px}
.service[data-service^=discord] .service-icon{background:#5865f2}.service[data-service=discord-voice] .service-icon{background:#3ba55d}
.service-scope{color:var(--muted);font-size:12px;line-height:1.3}.service[data-service=youtube] .service-icon{background:#ff2d2d}
.current{display:inline-flex;align-items:center;padding:3px 10px;border-radius:999px;background:var(--sunken);color:var(--muted);font:600 11px/1.6 var(--mono);letter-spacing:.04em}
.service:has(.mode.active[data-mode=direct]) .current{background:color-mix(in srgb,var(--direct) 14%,transparent);color:var(--direct)}
.service:has(.mode.active[data-mode=zapret]) .current{background:color-mix(in srgb,var(--zapret) 14%,transparent);color:var(--zapret)}
.service:has(.mode.active[data-mode=vpn]) .current{background:color-mix(in srgb,var(--vpn) 14%,transparent);color:var(--vpn)}
.modes{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;padding:4px;border-radius:12px;background:var(--sunken);border:1px solid var(--line)}
.mode{--mode:var(--accent);padding:9px 8px;border:1px solid transparent;border-radius:9px;background:transparent;color:var(--muted);box-shadow:none}
.mode[data-mode=direct]{--mode:var(--direct)}.mode[data-mode=zapret]{--mode:var(--zapret)}.mode[data-mode=vpn]{--mode:var(--vpn)}
.mode::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--mode);opacity:.55}
.mode:hover{background:var(--surface);color:var(--text);border-color:transparent}
.mode.active{background:var(--surface);color:var(--mode);border-color:color-mix(in srgb,var(--mode) 45%,transparent);box-shadow:var(--shadow)}
.mode.active::before{opacity:1;box-shadow:0 0 0 3px color-mix(in srgb,var(--mode) 22%,transparent)}
.legend{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:14px;color:var(--muted);font-size:13px}
.legend>div{padding:10px 12px;border-radius:10px;background:var(--surface-2);border:1px solid var(--line)}
.legend b{display:flex;align-items:center;gap:7px;color:var(--text);margin-bottom:2px;font-size:13px}
.legend b::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--c)}
.legend>div:nth-child(1){--c:var(--direct)}.legend>div:nth-child(2){--c:var(--zapret)}.legend>div:nth-child(3){--c:var(--vpn)}
.warning{display:flex;gap:10px;align-items:flex-start;margin-top:14px;padding:11px 14px;border-radius:12px;border:1px solid color-mix(in srgb,var(--amber) 30%,transparent);background:var(--amber-soft);color:var(--text);font-size:13px;line-height:1.5}
.warning::before{content:"!";display:grid;place-items:center;flex:none;width:18px;height:18px;margin-top:1px;border-radius:50%;background:var(--amber);color:var(--surface);font-weight:800;font-size:12px}
.upload{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}
input[type=file]{width:100%;padding:12px;border:1.5px dashed var(--line-strong);border-radius:12px;background:var(--surface-2);color:var(--muted);font:inherit;font-size:14px;cursor:pointer}
input[type=file]:hover{border-color:var(--accent)}
input[type=file]::file-selector-button{margin-right:12px;padding:7px 12px;border:1px solid var(--line-strong);border-radius:8px;background:var(--surface);color:var(--text);font:inherit;font-weight:600;cursor:pointer}
.candidate{display:none}.candidate.visible{display:block;margin-top:16px}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px;margin:14px 0;padding:14px 16px;border-radius:12px;background:var(--surface-2);border:1px solid var(--line)}
.meta div{min-width:0;overflow-wrap:anywhere}.meta b{display:block;color:var(--faint);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.profiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.profile{display:flex;flex-direction:column;padding:14px}
.profile h3{font-size:15px}.profile .family{flex:1;min-height:40px;margin-top:4px;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.profile button{width:100%;padding:8px;margin-top:10px;font-size:13px;color:var(--red)}
.tuner-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.field{display:grid;gap:6px;align-content:start}.field-hint{color:var(--faint);font-size:12px}.field label{color:var(--muted);font-size:13px;font-weight:600}
.field select,.field input{width:100%;padding:10px 12px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:var(--surface);color:var(--text);font:inherit;font-size:14px}
.field select:hover,.field input:hover{border-color:var(--faint)}
.tuner-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
.verdict{display:none;margin-top:14px;padding:16px;border:1px solid color-mix(in srgb,var(--amber) 40%,transparent);border-radius:13px;background:var(--amber-soft)}
.verdict.visible{display:block}.verdict b{display:block;margin-bottom:2px}.verdict-actions{display:flex;gap:10px;margin-top:12px}
.progress-line{display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px 12px;margin:12px 0;color:var(--muted);font-size:13px;font-variant-numeric:tabular-nums}
.found-card{display:none;border-color:color-mix(in srgb,var(--green) 40%,var(--line))}.found-card.visible{display:block}
.found-card h2{color:var(--green)}
.console-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.console-head h2{margin:0}
pre{min-height:120px;max-height:340px;overflow:auto;margin:0;padding:14px 16px;border:1px solid #1f2633;border-radius:12px;background:#0b0e14;color:#c9f4dd;white-space:pre-wrap;overflow-wrap:anywhere;font:12.5px/1.65 var(--mono)}
.args{min-height:80px;max-height:260px;color:#cdd6ff}
.route-progress{display:none;margin-top:16px;padding:14px 16px;border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);border-radius:13px;background:var(--accent-soft)}
.route-progress.visible{display:block}
.route-progress-head{display:flex;justify-content:space-between;gap:12px;font-size:14px;font-variant-numeric:tabular-nums}
.bar{height:6px;margin-top:10px;border-radius:99px;background:color-mix(in srgb,var(--accent) 16%,transparent);overflow:hidden}
.bar span{display:block;height:100%;width:0;border-radius:inherit;background:linear-gradient(90deg,var(--accent),var(--green));transition:width .35s ease}
.history-list,.version-list,.check-list,.diagnostic-list{display:grid;gap:10px}
.history-item,.version-item,.check-item,.diagnostic-item,.update-box{padding:14px 16px;border:1px solid var(--line);border-radius:13px;background:var(--surface-2)}
.history-head,.version-head,.check-head,.diagnostic-head,.update-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.history-head>b,.version-head>b,.diagnostic-head>b{font-size:14px;font-weight:650}
.history-head>span,.version-head>span,.diagnostic-head>span{flex:none;padding:2px 9px;border-radius:999px;background:var(--sunken);color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.history-head>span.good,.version-head>span.good,.diagnostic-head>span.good{background:var(--green-soft);color:var(--green)}
.history-head>span.bad,.version-head>span.bad,.diagnostic-head>span.bad{background:var(--red-soft);color:var(--red)}
.diagnostic-item.warn .diagnostic-head>span{background:var(--amber-soft);color:var(--amber)}
.history-item button,.version-item button{margin-top:10px;padding:6px 12px;font-size:13px}
.history-routes,.version-meta,.check-detail,.diagnostic-detail{color:var(--muted);font-size:13px;margin-top:4px;overflow-wrap:anywhere}
.good{color:var(--green)}.bad{color:var(--red)}
.diagnostic-item.bad,.check-item.bad{color:var(--text)}
.card>.profile-head:last-child{margin-bottom:0}.card>.profile-head:last-child .hint{margin-bottom:0}
#postApplyStatus.good,#postApplyStatus.bad{margin:0 0 4px;font-size:14px;font-weight:600}
.toolbar{display:flex;flex-wrap:wrap;gap:10px}
.check-item,.diagnostic-item{position:relative;padding-left:18px;overflow:hidden}
.check-item::before,.diagnostic-item::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--red)}
.check-item.ok::before,.diagnostic-item.ok::before{background:var(--green)}.check-item.manual::before,.diagnostic-item.warn::before{background:var(--amber)}
.updates-grid,.diagnostic-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.mono{font:12px var(--mono);overflow-wrap:anywhere}
.empty{color:var(--faint);padding:14px;border:1px dashed var(--line);border-radius:12px;text-align:center;font-size:14px}
.update-box .empty{border:0;padding:0;text-align:left}
.download{display:inline-flex;align-items:center;gap:8px;text-decoration:none;border:1px solid var(--line-strong);border-radius:var(--radius-sm);padding:10px 16px;background:var(--surface);color:var(--accent);font-weight:600;font-size:14px;transition:background .15s,border-color .15s}
.download:hover{background:var(--accent-soft);border-color:var(--accent)}
.protocols{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.protocol{padding:2px 8px;border:1px solid var(--line);border-radius:999px;background:var(--surface);font:11px/1.7 var(--mono)}
.protocol.ok{color:var(--green);border-color:color-mix(in srgb,var(--green) 40%,transparent)}
.protocol.warn{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 40%,transparent)}
.protocol.bad{color:var(--red);border-color:color-mix(in srgb,var(--red) 40%,transparent)}
.section-head{display:flex;align-items:center;gap:10px;margin-bottom:4px}.section-head h2{margin:0}
.section-head .i{color:var(--accent)}
#tunerVerification{margin:12px 0 0}
footer{margin-top:28px;color:var(--faint);font-size:12px;text-align:center}
@media(max-width:980px){.services{grid-template-columns:1fr}.service .modes{max-width:460px}}
@media(max-width:760px){header{align-items:flex-start;flex-direction:column;padding-top:20px}.services,.profiles,.tuner-grid,.updates-grid,.diagnostic-grid,.legend,.meta{grid-template-columns:1fr}.card{padding:18px}.profile-head{flex-wrap:wrap}}
@media(max-width:480px){.page{width:calc(100% - 24px)}.xkeen-actions,.upload{grid-template-columns:1fr}.tabs{display:grid;grid-template-columns:1fr 1fr}.tabs .tab{justify-content:center;padding:8px 10px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<symbol id="i-route" viewBox="0 0 24 24"><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><path d="M8 19h7.5a3.5 3.5 0 0 0 0-7h-7a3.5 3.5 0 0 1 0-7H16"/></symbol>
<symbol id="i-pulse" viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></symbol>
<symbol id="i-spark" viewBox="0 0 24 24"><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M19 15.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z"/></symbol>
<symbol id="i-upload" viewBox="0 0 24 24"><path d="M12 15V4"/><path d="M7 9l5-5 5 5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></symbol>
<symbol id="i-stop" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/></symbol>
<symbol id="i-restart" viewBox="0 0 24 24"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v5h-5"/></symbol>
<symbol id="i-history" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 2.64-6.36"/><path d="M3 4v5h5"/><path d="M12 7.5V12l3 2"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/></symbol>
<symbol id="i-terminal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M7.5 9.5l3 2.5-3 2.5"/><path d="M13 15h4"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/></symbol>
<symbol id="i-layers" viewBox="0 0 24 24"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></symbol>
</svg>
<main class="page">
<header><div class="brand"><div class="logo"><svg class="i"><use href="#i-route"/></svg></div><div><h1>XKeen Control</h1><div class="subtitle">Маршруты сервисов и профили nfqws2</div></div></div><div class="status" role="status" aria-live="polite"><span id="dot" class="dot"></span><span id="statusText">проверка…</span></div></header>
<nav class="tabs" aria-label="Разделы"><button class="tab active" data-tab="control"><svg class="i"><use href="#i-route"/></svg>Управление</button><button class="tab" data-tab="diagnostics"><svg class="i"><use href="#i-pulse"/></svg>Диагностика</button><button class="tab" data-tab="autotune"><svg class="i"><use href="#i-spark"/></svg>Автоподбор</button><button class="tab" data-tab="import"><svg class="i"><use href="#i-upload"/></svg>Импорт профиля</button></nav>

<div id="control" class="tab-page active">
  <section class="card"><div class="section-head"><svg class="i"><use href="#i-power"/></svg><h2>XKeen</h2></div><p class="hint">Запуск и остановка proxy-клиента.</p><div class="xkeen-actions"><button class="start" data-action="start"><svg class="i"><use href="#i-play"/></svg>Включить</button><button class="stop" data-action="stop"><svg class="i"><use href="#i-stop"/></svg>Выключить</button><button class="restart" data-action="restart"><svg class="i"><use href="#i-restart"/></svg>Перезапустить</button></div></section>
  <section class="card"><div class="section-head"><svg class="i"><use href="#i-route"/></svg><h2>Маршруты сервисов</h2></div><p class="hint">Меняется только выбранный сервис; режимы остальных сохраняются.</p><div class="services">
    <article class="service" data-service="discord-tcp"><div class="service-head"><div class="service-title"><span class="service-icon" aria-hidden="true">D</span><div><h3>Discord TCP</h3><div class="service-scope">Сайт, API, CDN, QUIC</div></div></div><span class="current">—</span></div><div class="modes"><button class="mode" data-mode="direct">Direct</button><button class="mode" data-mode="zapret">Zapret</button><button class="mode" data-mode="vpn">VPN</button></div></article>
    <article class="service" data-service="discord-voice"><div class="service-head"><div class="service-title"><span class="service-icon" aria-hidden="true">V</span><div><h3>Discord Voice</h3><div class="service-scope">Голос и STUN по UDP</div></div></div><span class="current">—</span></div><div class="modes"><button class="mode" data-mode="direct">Direct</button><button class="mode" data-mode="zapret">Zapret</button><button class="mode" data-mode="vpn">VPN</button></div></article>
    <article class="service" data-service="youtube"><div class="service-head"><div class="service-title"><span class="service-icon" aria-hidden="true">Y</span><div><h3>YouTube</h3><div class="service-scope">Сайт, видео, QUIC</div></div></div><span class="current">—</span></div><div class="modes"><button class="mode" data-mode="direct">Direct</button><button class="mode" data-mode="zapret">Zapret</button><button class="mode" data-mode="vpn">VPN</button></div></article>
  </div><div class="legend"><div><b>Direct</b>Напрямую через WAN, без nfqws2.</div><div><b>Zapret</b>Через WAN с обработкой nfqws2.</div><div><b>VPN</b>Через существующий VLESS outbound Xray.</div></div><div class="warning">Смена маршрута выполняет полный транзакционный apply и перезапускает службы, включая Xkeen.</div><div id="routeProgress" class="route-progress" role="status" aria-live="polite"><div class="route-progress-head"><b id="routeStage">Подготовка</b><span id="routePercent">0%</span></div><div class="bar"><span id="routeBar"></span></div></div></section>
  <section class="card"><div class="profile-head"><div><div class="section-head"><svg class="i"><use href="#i-check"/></svg><h2>Проверка после применения</h2></div><div id="postApplyStatus" class="hint">После переключения здесь появится краткий статус служб и конфигов.</div></div><button id="openDiagnostics" class="clear">Открыть диагностику</button></div></section>
  <section class="card"><div class="profile-head"><div><div class="section-head"><svg class="i"><use href="#i-history"/></svg><h2>История и откат</h2></div><div class="hint">Для каждой смены сохраняются режимы, результат и pre-apply snapshot.</div></div><button id="refreshHistory" class="clear">Обновить</button></div><div id="history" class="history-list"><div class="empty">История пуста.</div></div></section>
</div>

<div id="diagnostics" class="tab-page">
  <section class="card"><div class="section-head"><svg class="i"><use href="#i-pulse"/></svg><h2>Диагностика Flowseal для роутера</h2></div><p class="hint">Адаптация Run Diagnostics и Run Tests: ничего не применяет, не меняет firewall и не перезапускает Xkeen/nfqws2.</p>
    <div class="toolbar"><button class="diag-start apply" data-diag-kind="health">Проверить роутер</button><button class="diag-start" data-diag-kind="standard">Standard tests</button><button class="diag-start" data-diag-kind="dpi">DPI 16–20 КБ</button><button id="cancelDiagnostic" class="cancel" disabled>Остановить тест</button></div>
    <div id="diagnosticProgress" class="route-progress" role="status" aria-live="polite"><div class="route-progress-head"><b id="diagnosticStatus">Задание не запускалось</b><span id="diagnosticPercent">0%</span></div><div class="bar"><span id="diagnosticBar"></span></div></div>
    <div class="warning">Standard tests и DPI выполняются из этого браузера по текущим маршрутам устройства. Собственный VPN/прокси компьютера тоже влияет на путь. Ping и выбор TLS-версии браузеру недоступны. DPI: HTTPS GET и POST 64 КиБ на 12 узлов, до 768 КиБ отправки. CORS скрывает HTTP-код и объём передачи; таймаут или ошибка могут быть вызваны сервером, перенаправлением или политикой браузера и не доказывают DPI-блокировку. При закрытии страницы тест остановится.</div>
  </section>
  <section class="card"><div class="profile-head"><div><h2>Результаты</h2><div id="diagnosticSummary" class="hint">Пока нет результатов.</div></div></div><div id="diagnosticResults" class="diagnostic-list"><div class="empty">Запустите один из тестов выше.</div></div></section>
  <section class="card"><h2>Проверить в приложении</h2><p class="hint">Discord Voice/UDP: переподключитесь к голосовому каналу и проверьте звук в обе стороны. YouTube QUIC/HTTP3: запустите видео в клиенте с HTTP3; обычный HTTPS-тест не подтверждает QUIC или воспроизведение.</p></section>
  <section class="card"><h2>Кэш Discord на Windows</h2><p class="hint">Роутер не имеет доступа к файлам компьютера. Helper закрывает Discord и переименовывает Cache, Code Cache и GPUCache в резервные каталоги — ничего безвозвратно не удаляется.</p><a class="download" href="/tools/reset-discord-cache.ps1" download><svg class="i"><use href="#i-download"/></svg>Скачать Windows-helper</a></section>
</div>

<div id="autotune" class="tab-page">
  <section class="card"><div class="profile-head"><div><h2>Обновления Flowseal</h2><div class="hint">Новые стратегии скачиваются для следующего подбора. Рабочие профили остаются прежними.</div></div><button id="checkUpdates">Проверить обновление</button></div><div id="updateInfo" class="update-box"><div class="empty">Обновления ещё не проверялись.</div></div></section>
  <section class="card">
    <div class="section-head"><svg class="i"><use href="#i-spark"/></svg><h2>Автоподбор стратегий</h2></div>
    <p class="hint">Актуальные general*.bat временно проверяются на роутере. Меняется только проверяемый профиль; остальные TCP/QUIC/UDP-профили сохраняются. Для TCP выполняются baseline и два прохода кандидата с проверкой API/CDN. Voice требует подтверждения звука.</p>
    <div class="tuner-grid">
      <div class="field"><label for="tunerService">Сервис</label><select id="tunerService"><option value="youtube">YouTube</option><option value="discord-tcp">Discord TCP</option><option value="discord-voice">Discord Voice</option></select></div>
      <div class="field"><label for="tunerSource">BAT-файл Flowseal</label><select id="tunerSource"><option value="">Все файлы и встроенный профиль</option></select><div id="tunerSourceHint" class="field-hint">Выберите файл, чтобы проверить только его конфиг. Список появится после «Проверить обновление».</div></div>
      <div class="field"><label for="tunerMix">Глубина перебора</label><select id="tunerMix"><option value="safe">Safe — по одному параметру</option><option value="extended">Extended — плюс сочетания</option><option value="off">Только прямой перевод BAT</option></select></div>
      <div class="field"><label for="tunerMax">Максимум кандидатов</label><input id="tunerMax" type="number" min="1" max="64" value="32"></div>
      <div class="field"><label for="tunerSeed">Seed (пусто = новый случайный)</label><input id="tunerSeed" inputmode="numeric" pattern="[0-9]*" placeholder="например, 1732459012"></div>
      <div class="field" id="clientIpField" hidden><label for="tunerClientIp">LAN IPv4 компьютера с Discord</label><input id="tunerClientIp" inputmode="decimal" placeholder="192.168.2.60"></div>
    </div>
    <div class="tuner-actions"><button id="startTuner" class="apply"><svg class="i"><use href="#i-play"/></svg>Начать подбор</button><button id="cancelTuner" class="cancel" disabled>Остановить и восстановить nfqws2</button></div>
    <div class="warning">Safe отдельно меняет repeats, out-range, TCP pos/seq и QUIC repeats. Extended добавляет ограниченные сочетания и смешивание BAT-компонентов. Пустой seed даёт новый порядок и подмножество кандидатов; сохранённый seed точно повторяет поиск. Подбор временно перезапускает только nfqws2; Xkeen не вызывается. Сервис должен заранее находиться в режиме Zapret.</div>
  </section>
  <section class="card">
    <div class="profile-head"><div><h2>Ход подбора</h2><div id="tunerStatus" class="hint">Задание не запускалось</div></div><span id="tunerCommit" class="current"></span></div>
    <div class="progress-line"><span id="tunerProgress">—</span><span id="tunerProbe"></span></div>
    <pre id="tunerLog"></pre>
    <div id="tunerVerification" class="hint"></div>
    <div id="voiceVerdict" class="verdict" role="alert"><b>Проверьте Discord Voice</b><div>Переподключитесь к голосовому каналу и подтвердите, появился ли звук в обе стороны.</div><div class="verdict-actions"><button id="voiceYes" class="apply">Да, работает</button><button id="voiceNo" class="cancel">Нет</button></div></div>
  </section>
  <section id="tunerFound" class="card found-card">
    <div class="section-head"><svg class="i good"><use href="#i-check"/></svg><h2>Найден проходной профиль</h2></div>
    <div class="meta"><div><b>ID</b><span id="tunerFoundId"></span></div><div><b>Семейство</b><span id="tunerFoundFamily"></span></div><div><b>Источник</b><span id="tunerFoundSource"></span></div></div>
    <pre id="tunerFoundArgs" class="args"></pre>
    <div class="tuner-actions"><button id="applyTunerResult" class="apply">Применить найденный профиль</button></div>
    <div class="warning">Это отдельное подтверждённое действие: создаётся focused snapshot и перезапускается только nfqws2.</div>
  </section>
</div>

<div id="import" class="tab-page">
  <section class="card"><div class="section-head"><svg class="i"><use href="#i-upload"/></svg><h2>Отчёт Windows-тюнера</h2></div><p class="hint">Выберите JSON-отчёт с найденным кандидатом. Сначала он проверяется, применение доступно только для сервиса в режиме Zapret.</p><div class="upload"><input id="reportFile" type="file" accept="application/json,.json"><button id="validate">Проверить</button></div>
    <div id="candidate" class="candidate"><div class="meta"><div><b>Сервис</b><span id="candidateService"></span></div><div><b>ID кандидата</b><span id="candidateId"></span></div><div><b>BAT-источник</b><span id="candidateSource"></span></div><div><b>Семейство</b><span id="candidateFamily"></span></div></div><pre id="candidateArgs" class="args"></pre><p class="warning">Применение создаёт отдельный snapshot, меняет только nfqws2 и перезапускает только nfqws2. Xkeen не останавливается и не перезапускается.</p><button id="applyImport" class="apply">Применить профиль nfqws2</button></div>
  </section>
  <section class="card"><div class="profile-head"><div><div class="section-head"><svg class="i"><use href="#i-layers"/></svg><h2>Постоянные профили</h2></div><div class="hint">Они сохраняются при следующих обычных apply.</div></div><button id="rollbackImport" class="rollback">Откатить последнее изменение</button></div><div id="profiles" class="profiles"></div></section>
  <section class="card"><div class="profile-head"><div><h2>Версии профилей по дате</h2><div class="hint">Каждый импорт и заменяемый профиль сохраняются отдельно.</div></div><button id="refreshVersions" class="clear">Обновить</button></div><div id="profileVersions" class="version-list"><div class="empty">Сохранённых версий пока нет.</div></div></section>
</div>

<section class="card"><div class="console-head"><div class="section-head"><svg class="i"><use href="#i-terminal"/></svg><h2>Журнал</h2></div><button class="clear" id="clear">Очистить</button></div><pre id="log" aria-live="polite"></pre></section>
<footer>XKeen + nfqws2 · локальная панель, доступна только из LAN</footer>
</main>
<script src="/assets/browser-diagnostics.js"></script>
<script>
const logEl=document.getElementById("log"),dot=document.getElementById("dot"),statusText=document.getElementById("statusText");
const controlHeaders={"X-XKeen-Control":"1","Content-Type":"application/json"};
const label={direct:"DIRECT",zapret:"ZAPRET",vless:"VPN",vpn:"VPN",unknown:"НЕИЗВЕСТНО"};
const serviceLabel={youtube:"YouTube",discord:"Discord",rollback:"Откат","discord-tcp":"Discord TCP","discord-voice":"Discord Voice"};
const activeTunerStates=new Set(["preparing","running","voice_window","awaiting_voice","cancelling"]);
let selectedReport=null,validatedDescriptor=null,tunerPoll=null,routeWatch=null,diagnosticWatch=null;
function stamp(){return new Date().toLocaleTimeString("ru-RU",{hour12:false})}
function log(text,replace=false){const line="["+stamp()+"] "+text;logEl.textContent=replace?line:(logEl.textContent?logEl.textContent+"\n"+line:line);logEl.scrollTop=logEl.scrollHeight}
let tunerRunning=false,diagnosticRunning=false;
function busy(value){document.querySelectorAll("button:not(.tab)").forEach(b=>b.disabled=value);if(!value){tunerControls(tunerRunning);diagnosticControls(diagnosticRunning)}}
function modeForUi(value){return value==="vless"?"vpn":value}
function updateService(service,value){const box=document.querySelector('[data-service="'+service+'"]');box.querySelector(".current").textContent=label[value]||value;box.querySelectorAll(".mode").forEach(b=>b.classList.toggle("active",b.dataset.mode===modeForUi(value)))}
function fmtDate(value){if(!value)return "—";const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString("ru-RU",{hour12:false})}
function routeName(value){return label[value]||value||"?"}
function routesText(routes){if(!routes)return "—";if(routes.discord&&!routes["discord-tcp"])return "Discord "+routeName(routes.discord)+" · YouTube "+routeName(routes.youtube);return "Discord TCP "+routeName(routes["discord-tcp"])+" · Voice "+routeName(routes["discord-voice"])+" · YouTube "+routeName(routes.youtube)}
function setRouteProgress(d){const box=document.getElementById("routeProgress"),progress=Math.max(0,Math.min(100,Number(d.progress||0))),tracked=d.progress!==undefined||!!d.operation;box.classList.toggle("visible",!!d.active||(tracked&&["completed","failed"].includes(d.status)));document.getElementById("routeStage").textContent=d.stage_label||d.status||"Подготовка";document.getElementById("routePercent").textContent=progress+"%";document.getElementById("routeBar").style.width=progress+"%"}
async function readJson(response){const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.output||data.error||("HTTP "+response.status));return data}
async function api(path,options={}){return readJson(await fetch(path,{cache:"no-store",...options}))}
async function refresh(){try{const d=await api("/api/status");updateService("discord-tcp",d.discord_tcp_route||"unknown");updateService("discord-voice",d.discord_voice_route||"unknown");updateService("youtube",d.youtube_route||"unknown");const running=d.xkeen_runtime==="running";dot.className="dot "+(running?"ok":"bad");statusText.textContent=running?"XKeen работает":"XKeen остановлен"}catch(e){dot.className="dot bad";statusText.textContent="ошибка статуса";log("status: "+e)}}
async function refreshProfiles(){const root=document.getElementById("profiles");try{const d=await api("/api/imported");root.textContent="";d.profiles.forEach(p=>{const box=document.createElement("article");box.className="profile";const h=document.createElement("h3");h.textContent=serviceLabel[p.service];const family=document.createElement("div");family.className="family";family.textContent=p.installed?(p.family+" · "+p.candidate_id+" · "+fmtDate(p.installed_utc)):(p.error||"Встроенный профиль");box.append(h,family);if(p.installed){const b=document.createElement("button");b.textContent="Вернуть встроенный";b.addEventListener("click",()=>clearImport(p.service));box.append(b)}root.append(box)});document.getElementById("rollbackImport").disabled=!d.rollback_available}catch(e){root.textContent="Ошибка: "+e;log("профили: "+e)}}
async function xkeenAction(action){busy(true);log("xkeen -"+action,true);try{const d=await api("/api/xkeen/"+action,{method:"POST",headers:controlHeaders,body:"{}"});log(d.output||"готово")}catch(e){log("ошибка: "+e)}finally{busy(false);await refresh();await refreshProfiles()}}
function delay(ms){return new Promise(resolve=>setTimeout(resolve,ms))}
function watchRouteJob(jobId,name){if(routeWatch)return routeWatch;routeWatch=(async()=>{busy(true);let lastStage="",connectionLost=false;const deadline=Date.now()+16*60*1000;try{while(Date.now()<deadline){let d;try{d=await api("/api/route/status");if(connectionLost){log("связь с панелью восстановлена");connectionLost=false}}catch(e){if(!connectionLost){log("перезапуск сети прервал связь; продолжаю ждать результат");connectionLost=true}await delay(2000);continue}if(jobId&&d.job_id&&d.job_id!==jobId)throw new Error("состояние задания изменилось");setRouteProgress(d);if(d.stage!==lastStage){lastStage=d.stage;log((name||serviceLabel[d.service]||"Маршрут")+": "+(d.stage_label||d.status))}if(d.active){await delay(1500);continue}if(d.status==="completed"){log(d.output||"операция завершена");await runPostChecks(d.operation==="switch"?d.service:"all",false);return d}throw new Error(d.output||d.error||"переключение завершилось с ошибкой")}throw new Error("превышено время ожидания; задание продолжает работать на роутере")}finally{routeWatch=null;busy(false);await refresh();await refreshProfiles();await refreshHistory();await refreshVersions()}})();return routeWatch}
async function routeAction(service,mode){const name=serviceLabel[service]||service;if(!confirm(name+": переключить в "+label[mode]+"?\n\nЭто перезапустит Xkeen и nfqws2."))return;busy(true);log(name+" → "+label[mode],true);try{const d=await api("/api/route/"+service+"/"+mode,{method:"POST",headers:controlHeaders,body:"{}"});log("задание принято; можно закрыть страницу — оно продолжится на роутере");await watchRouteJob(d.job_id,name)}catch(e){log("ошибка: "+e);busy(false);await refresh();await refreshProfiles()}}
async function resumeRouteJob(){try{const d=await api("/api/route/status");setRouteProgress(d);if(d.active){log("найдена выполняющаяся операция с маршрутами");await watchRouteJob(d.job_id,serviceLabel[d.service]||"Маршрут")}}catch(e){log("статус переключения: "+e)}}
async function rollbackHistory(jobId){if(!confirm("Вернуть состояние до выбранной операции?\n\nСначала будет создан rescue snapshot текущего состояния."))return;busy(true);log("откат операции "+jobId,true);try{const d=await api("/api/history/rollback/"+jobId,{method:"POST",headers:controlHeaders,body:"{}"});await watchRouteJob(d.job_id,"Откат")}catch(e){log("ошибка отката: "+e);busy(false);await refreshHistory()}}
async function refreshHistory(){const root=document.getElementById("history");try{const d=await api("/api/history");root.textContent="";if(!d.items.length){root.innerHTML='<div class="empty">История пуста.</div>';return}d.items.forEach(item=>{const box=document.createElement("article");box.className="history-item";const head=document.createElement("div");head.className="history-head";const title=document.createElement("b");title.textContent=(item.operation==="rollback"?"Откат":"Переключение")+" · "+fmtDate(item.created_utc);const state=document.createElement("span");state.className=item.status==="completed"?"good":"bad";state.textContent=item.status||"unknown";head.append(title,state);const routes=document.createElement("div");routes.className="history-routes";routes.textContent=routesText(item.before_routes)+" → "+routesText(item.after_routes||item.requested_routes);box.append(head,routes);if(item.snapshot){const snap=document.createElement("div");snap.className="history-routes mono";snap.textContent=item.snapshot.split("/").pop();box.append(snap)}if(item.rollback_available){const b=document.createElement("button");b.className="rollback";b.textContent="Вернуть состояние до операции";b.addEventListener("click",()=>rollbackHistory(item.job_id));box.append(b)}root.append(box)})}catch(e){root.textContent="Ошибка истории: "+e}}
async function runPostChecks(){const root=document.getElementById("postApplyStatus");root.textContent="Проверяю службы и конфиги…";try{const config=await api("/api/checks/config");const failed=config.checks.filter(item=>item.ok!==true);root.textContent=failed.length?"Проверка не пройдена: "+failed.map(item=>item.name+" — "+item.detail).join("; "):"Конфиги и службы: OK";root.className=failed.length?"bad":"good"}catch(e){root.textContent="Ошибка проверки: "+e;root.className="bad"}}
function diagnosticControls(active){diagnosticRunning=active;document.querySelectorAll(".diag-start").forEach(b=>b.disabled=active);document.getElementById("cancelDiagnostic").disabled=!active}
function diagnosticToken(check){const token=document.createElement("span"),status=check.status||"error";token.className="protocol "+(status==="ok"?"ok":["unsupported","timeout","likely_blocked"].includes(status)?"warn":"bad");const suffix=check.http_code&&check.http_code!=="000"?" "+check.http_code:"";token.textContent=(check.protocol||"Ping")+": "+status.toUpperCase()+suffix+(check.uploaded!==undefined?" · ↑"+check.uploaded+" ↓"+check.downloaded+" B":"");token.title=check.detail||"";return token}
function renderDiagnostic(d){const active=!!d.active,status=d.status||"idle",progress=Math.max(0,Math.min(100,Number(d.progress||0))),progressBox=document.getElementById("diagnosticProgress");diagnosticControls(active);progressBox.classList.toggle("visible",active||["completed","error","cancelled"].includes(status));document.getElementById("diagnosticStatus").textContent=({idle:"Задание не запускалось",running:"Выполняется…",completed:"Готово",error:"Ошибка",cancelled:"Остановлено",cancelling:"Останавливается…"})[status]||status;document.getElementById("diagnosticPercent").textContent=progress+"%";document.getElementById("diagnosticBar").style.width=progress+"%";const sum=d.summary||{},summary=document.getElementById("diagnosticSummary");summary.textContent=d.error?d.error:(status==="completed"?"OK: "+(sum.ok||0)+" · предупреждений: "+((sum.warn||0)+(sum.unsupported||0)+(sum.likely_blocked||0))+" · ошибок: "+(sum.error||0):(active?"Результаты появляются по мере выполнения.":"Пока нет результатов."));const root=document.getElementById("diagnosticResults");root.textContent="";const results=d.results||[];if(!results.length){root.innerHTML='<div class="empty">Результатов пока нет.</div>';return}results.forEach(item=>{const box=document.createElement("article"),head=document.createElement("div"),title=document.createElement("b"),state=document.createElement("span"),detail=document.createElement("div"),protocols=document.createElement("div");head.className="diagnostic-head";detail.className="diagnostic-detail";protocols.className="protocols";const checks=item.checks||(item.kind==="ping"?[item.ping||{}]:[]);const statuses=checks.map(x=>x.status);let level=statuses.includes("error")||statuses.includes("fail")||item.error?"bad":statuses.includes("likely_blocked")||statuses.includes("unsupported")||statuses.includes("timeout")||item.status==="warn"?"warn":"ok";if(d.kind==="health")level=item.status==="ok"?"ok":item.status==="warn"?"warn":"bad";box.className="diagnostic-item "+level;title.textContent=item.name||([item.provider,item.id].filter(Boolean).join(" · "))||"Проверка";state.className=level==="ok"?"good":level==="warn"?"":"bad";state.textContent=level==="ok"?"OK":level==="warn"?"ВНИМАНИЕ":"ОШИБКА";head.append(title,state);detail.textContent=item.detail||item.target||item.host||item.error||"";box.append(head,detail);if(item.dns){const dns=document.createElement("span");dns.className="protocol "+(item.dns.status==="ok"?"ok":"bad");dns.textContent="DNS: "+item.dns.status.toUpperCase();dns.title=item.dns.detail||"";protocols.append(dns)}checks.forEach(check=>protocols.append(diagnosticToken(check)));if(protocols.childNodes.length)box.append(protocols);root.append(box)})}
async function refreshDiagnostic(){try{const d=await api("/api/diagnostics/status");if(browserDiagnosticRun)return;renderDiagnostic(d);if(d.kind==="health"&&d.status==="completed"&&!d.active){document.getElementById("diagnosticStatus").textContent="Сохранённая проверка роутера · "+fmtDate(d.finished_utc||d.created_utc)}if(d.active&&!diagnosticWatch){diagnosticWatch=watchDiagnostic(d.job_id);try{await diagnosticWatch}catch(e){log("диагностика: "+e)}finally{diagnosticWatch=null}}}catch(e){if(!browserDiagnosticRun)document.getElementById("diagnosticSummary").textContent="Ошибка статуса: "+e}}
async function watchDiagnostic(jobId){const deadline=Date.now()+12*60*1000;while(Date.now()<deadline){const d=await api("/api/diagnostics/status");if(d.job_id&&d.job_id!==jobId)throw new Error("ID диагностического задания изменился");renderDiagnostic(d);if(d.active){await delay(1200);continue}if(d.status==="completed")return d;throw new Error(d.error||"диагностика завершилась: "+d.status)}throw new Error("превышено время ожидания диагностики")}
async function startDiagnostic(kind){if(kind!=="health"){await runBrowserDiagnostic(kind);return}if(browserDiagnosticRun||diagnosticWatch)return;diagnosticControls(true);log("проверка роутера",true);try{const d=await api("/api/diagnostics/start/health",{method:"POST",headers:controlHeaders,body:"{}"});renderDiagnostic(d);diagnosticWatch=watchDiagnostic(d.job_id);await diagnosticWatch;log("проверка роутера завершена")}catch(e){log("ошибка диагностики: "+e)}finally{diagnosticWatch=null;await refreshDiagnostic()}}
async function cancelDiagnostic(){if(browserDiagnosticRun){browserDiagnosticRun.controller.abort();return}try{renderDiagnostic(await api("/api/diagnostics/cancel",{method:"POST",headers:controlHeaders,body:"{}"}))}catch(e){log("ошибка остановки диагностики: "+e)}}
async function validateReport(){const file=document.getElementById("reportFile").files[0];if(!file){log("выберите JSON-отчёт");return}try{selectedReport=JSON.parse(await file.text());const d=await api("/api/import/validate",{method:"POST",headers:controlHeaders,body:JSON.stringify(selectedReport)});validatedDescriptor=d.profile;document.getElementById("candidateService").textContent=serviceLabel[d.profile.service];document.getElementById("candidateId").textContent=d.profile.candidate_id;document.getElementById("candidateSource").textContent=d.profile.source_name;document.getElementById("candidateFamily").textContent=d.profile.family;document.getElementById("candidateArgs").textContent=d.profile.args.join("\n");document.getElementById("candidate").classList.add("visible");log("отчёт проверен: "+d.profile.service+" / "+d.profile.candidate_id,true)}catch(e){selectedReport=null;validatedDescriptor=null;document.getElementById("candidate").classList.remove("visible");log("отчёт отклонён: "+e,true)}}
async function applyImport(){if(!selectedReport||!validatedDescriptor)return;if(!confirm("Применить "+serviceLabel[validatedDescriptor.service]+" / "+validatedDescriptor.candidate_id+"?\n\nБудет перезапущен только nfqws2. Xkeen останется запущен без перезапуска."))return;busy(true);log("применение профиля "+validatedDescriptor.candidate_id,true);try{const d=await api("/api/import/apply",{method:"POST",headers:controlHeaders,body:JSON.stringify(selectedReport)});log(d.output||"профиль применён")}catch(e){log("ошибка применения: "+e)}finally{busy(false);await refresh();await refreshProfiles();await refreshVersions()}}
async function clearImport(service){if(!confirm("Вернуть встроенный профиль для "+serviceLabel[service]+"?\n\nБудет перезапущен только nfqws2."))return;busy(true);log("встроенный профиль: "+service,true);try{const d=await api("/api/import/clear/"+service,{method:"POST",headers:controlHeaders,body:"{}"});log(d.output||"готово")}catch(e){log("ошибка: "+e)}finally{busy(false);await refreshProfiles();await refreshVersions()}}
async function rollbackImport(){if(!confirm("Откатить последнее применение/удаление профиля?\n\nБудет перезапущен только nfqws2."))return;busy(true);log("откат профиля nfqws2",true);try{const d=await api("/api/import/rollback",{method:"POST",headers:controlHeaders,body:"{}"});log(d.output||"готово")}catch(e){log("ошибка отката: "+e)}finally{busy(false);await refreshProfiles();await refreshVersions()}}
async function refreshVersions(){const root=document.getElementById("profileVersions");try{const d=await api("/api/profile-versions");root.textContent="";if(!d.versions.length){root.innerHTML='<div class="empty">Сохранённых версий пока нет. Текущий профиль попадёт сюда при следующем импорте или замене.</div>';return}d.versions.forEach(v=>{const box=document.createElement("article");box.className="version-item";const head=document.createElement("div");head.className="version-head";const title=document.createElement("b");title.textContent=serviceLabel[v.service]+" · "+fmtDate(v.created_utc);const state=document.createElement("span");state.className=v.active?"good":"muted";state.textContent=v.active?"АКТИВЕН":v.reason;head.append(title,state);const meta=document.createElement("div");meta.className="version-meta";meta.textContent=v.family+" · "+v.candidate_id+(v.commit?" · "+v.commit.slice(0,12):"");box.append(head,meta);if(!v.active){const b=document.createElement("button");b.className="apply";b.textContent="Применить эту версию";b.addEventListener("click",()=>applyVersion(v.service,v.id));box.append(b)}root.append(box)})}catch(e){root.textContent="Ошибка версий: "+e}}
async function applyVersion(service,id){if(!confirm("Применить версию "+serviceLabel[service]+" от выбранной даты?\n\nБудет создан focused snapshot и перезапущен только nfqws2."))return;busy(true);log("применение версии "+id,true);try{const d=await api("/api/profiles/apply/"+service+"/"+id,{method:"POST",headers:controlHeaders,body:"{}"});log(d.output||"версия применена")}catch(e){log("ошибка версии: "+e)}finally{busy(false);await refreshProfiles();await refreshVersions()}}
function renderUpdate(d){const root=document.getElementById("updateInfo");root.textContent="";const title=document.createElement("b");title.className=d.status==="error"?"bad":"good";title.textContent=d.status==="up_to_date"?"Актуально":d.status==="downloaded"?"Новые стратегии скачаны":d.status==="error"?"Не удалось обновить":"Нажмите «Проверить обновление»";root.append(title);const detail=document.createElement("div");detail.className="version-meta";detail.textContent=d.error||((d.downloaded_commit?"Версия "+d.downloaded_commit.slice(0,12)+" · файлов: "+d.source_count:"")+(d.checked_utc?" · проверено "+fmtDate(d.checked_utc):""));root.append(detail)}
async function refreshUpdates(){try{renderUpdate(await api("/api/updates"))}catch(e){document.getElementById("updateInfo").textContent="Ошибка: "+e}}
async function checkUpdates(){const button=document.getElementById("checkUpdates");button.disabled=true;button.textContent="Проверяю и скачиваю…";try{const d=await api("/api/updates/check",{method:"POST",headers:controlHeaders,body:"{}"});renderUpdate(d);log(d.status==="up_to_date"?"Flowseal: актуально":"Flowseal: скачаны новые стратегии ("+d.source_count+" файлов)");await refreshTunerSources()}catch(e){renderUpdate({status:"error",error:String(e)});log("ошибка обновления Flowseal: "+e)}finally{button.disabled=false;button.textContent="Проверить обновление"}}
let tunerSourceList=[];
function renderTunerSources(){const select=document.getElementById("tunerSource"),service=document.getElementById("tunerService").value,previous=select.value;select.textContent="";const all=document.createElement("option");all.value="";all.textContent="Все файлы и встроенный профиль";select.append(all);tunerSourceList.forEach(item=>{const option=document.createElement("option"),supported=(item.services||[]).includes(service);option.value=item.name;option.textContent=item.name+(supported?"":" — нет профиля для "+serviceLabel[service]);option.disabled=!supported;select.append(option)});const keep=tunerSourceList.find(item=>item.name===previous&&(item.services||[]).includes(service));select.value=keep?previous:""}
async function refreshTunerSources(){const hint=document.getElementById("tunerSourceHint");try{const d=await api("/api/tuner/sources");tunerSourceList=d.sources||[];renderTunerSources();hint.textContent=d.status==="ready"?"Только выбранный файл: его профили без встроенного; Safe/Extended добавляют вариации параметров этого файла. Commit "+d.commit.slice(0,12)+".":d.status==="error"?"Список файлов недоступен: "+d.error:"Список файлов появится после «Проверить обновление»."}catch(e){hint.textContent="Список файлов недоступен: "+e}}
function tunerServiceChanged(){document.getElementById("clientIpField").hidden=document.getElementById("tunerService").value!=="discord-voice";renderTunerSources()}
function tunerControls(active){tunerRunning=active;document.getElementById("startTuner").disabled=active;document.getElementById("cancelTuner").disabled=!active;document.querySelectorAll("[data-action],.mode").forEach(b=>b.disabled=active)}
function tunerStateLabel(state){return ({idle:"Задание не запускалось",preparing:"Получение и разбор стратегий…",running:"Проверка кандидатов…",voice_window:"Окно проверки Discord Voice…",awaiting_voice:"Ожидается ваш ответ",cancelling:"Остановка и восстановление nfqws2…",found:"Найден проходной профиль",none:"Проходной профиль не найден",cancelled:"Подбор остановлен, nfqws2 восстановлен",error:"Ошибка подбора"})[state]||state}
function renderTuner(d){
  const state=d.status||"idle",active=!!d.active||activeTunerStates.has(state);tunerControls(active);
  document.getElementById("tunerStatus").textContent=tunerStateLabel(state)+(d.error?": "+d.error:"");
  document.getElementById("tunerCommit").textContent=[d.source_file||"",d.commit?d.commit.slice(0,12):"",d.search_seed===undefined?"":("seed "+d.search_seed)].filter(Boolean).join(" · ");
  document.getElementById("tunerProgress").textContent=d.candidate_count?("кандидат "+(d.current_candidate||0)+" из "+d.candidate_count):"—";
  const probe=d.last_probe_detail;document.getElementById("tunerProbe").textContent=probe?([probe.phase,"проход "+probe.round,probe.role,probe.http_code,probe.status,probe.seconds+" с",probe.bytes+" B"].join(" · ")):"";
  const base=d.baseline_result,suite=d.last_suite_result;document.getElementById("tunerVerification").textContent=(base?"Исходный профиль: "+base.verdict+" ("+base.successes+"/"+base.total+"). ":"")+(suite?"Кандидат "+suite.candidate+": "+suite.phase+" · "+suite.verdict+". ":"")+(d.service==="discord-voice"?"Voice: требуется подтверждение звука; UDP-пакеты сами по себе не доказывают качество голоса.":"Победитель должен пройти два HTTP-прохода. QUIC и воспроизведение видео не подтверждаются.");
  document.getElementById("tunerLog").textContent=(d.log_tail||[]).join("\n");
  document.getElementById("voiceVerdict").classList.toggle("visible",state==="awaiting_voice");
  const found=d.found;document.getElementById("tunerFound").classList.toggle("visible",state==="found"&&!!found);
  if(found){document.getElementById("tunerFoundId").textContent=found.candidate_id;document.getElementById("tunerFoundFamily").textContent=found.family;document.getElementById("tunerFoundSource").textContent=found.source_name;document.getElementById("tunerFoundArgs").textContent=(found.args||[]).join("\n")}
  if(active&&!tunerPoll)tunerPoll=setInterval(refreshTuner,1800);if(!active&&tunerPoll){clearInterval(tunerPoll);tunerPoll=null}
}
async function refreshTuner(){try{renderTuner(await api("/api/tuner/status"))}catch(e){document.getElementById("tunerStatus").textContent="Ошибка статуса: "+e}}
async function startTuner(){
  const service=document.getElementById("tunerService").value,max=Number(document.getElementById("tunerMax").value),mix=document.getElementById("tunerMix").value,clientIp=document.getElementById("tunerClientIp").value.trim(),searchSeed=document.getElementById("tunerSeed").value.trim(),sourceFile=document.getElementById("tunerSource").value;
  if(service==="discord-voice"&&!clientIp){log("для Discord Voice укажите LAN IPv4 компьютера");return}
  if(!confirm("Начать подбор для "+serviceLabel[service]+(sourceFile?" из "+sourceFile:"")+"?\n\nТолько nfqws2 будет временно перезапускаться. Xkeen останется без изменений."))return;
  document.getElementById("tunerFound").classList.remove("visible");tunerControls(true);log("автоподбор: "+service,true);
  try{const d=await api("/api/tuner/start",{method:"POST",headers:controlHeaders,body:JSON.stringify({service:service,mix_level:mix,max_candidates:max,client_ip:clientIp,search_seed:searchSeed,source_file:sourceFile})});renderTuner(d)}
  catch(e){log("не удалось начать подбор: "+e);tunerControls(false)}
}
async function cancelTuner(){if(!confirm("Остановить подбор? Временный процесс будет завершён, штатный nfqws2 восстановлен."))return;try{renderTuner(await api("/api/tuner/cancel",{method:"POST",headers:controlHeaders,body:"{}"}))}catch(e){log("ошибка остановки: "+e)}}
async function voiceVerdict(works){try{renderTuner(await api("/api/tuner/verdict",{method:"POST",headers:controlHeaders,body:JSON.stringify({works:works})}))}catch(e){log("ошибка ответа Voice: "+e)}}
async function applyTunerResult(){if(!confirm("Применить найденный профиль постоянно?\n\nБудет перезапущен только nfqws2; перед изменением создаётся focused snapshot."))return;busy(true);try{const d=await api("/api/tuner/apply",{method:"POST",headers:controlHeaders,body:"{}"});log(d.output||"найденный профиль применён",true)}catch(e){log("ошибка применения: "+e,true)}finally{busy(false);await refresh();await refreshProfiles();await refreshVersions();await refreshTuner()}}
document.querySelectorAll(".tab").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x===b));document.querySelectorAll(".tab-page").forEach(x=>x.classList.toggle("active",x.id===b.dataset.tab))}));
document.querySelectorAll("[data-action]").forEach(b=>b.addEventListener("click",()=>xkeenAction(b.dataset.action)));document.querySelectorAll(".service").forEach(box=>box.querySelectorAll(".mode").forEach(b=>b.addEventListener("click",()=>routeAction(box.dataset.service,b.dataset.mode))));
document.getElementById("validate").addEventListener("click",validateReport);document.getElementById("applyImport").addEventListener("click",applyImport);document.getElementById("rollbackImport").addEventListener("click",rollbackImport);document.getElementById("clear").addEventListener("click",()=>log("журнал очищен",true));
document.getElementById("tunerService").addEventListener("change",tunerServiceChanged);document.getElementById("startTuner").addEventListener("click",startTuner);document.getElementById("cancelTuner").addEventListener("click",cancelTuner);document.getElementById("voiceYes").addEventListener("click",()=>voiceVerdict(true));document.getElementById("voiceNo").addEventListener("click",()=>voiceVerdict(false));document.getElementById("applyTunerResult").addEventListener("click",applyTunerResult);
document.getElementById("refreshHistory").addEventListener("click",refreshHistory);document.getElementById("refreshVersions").addEventListener("click",refreshVersions);document.getElementById("checkUpdates").addEventListener("click",checkUpdates);
document.getElementById("openDiagnostics").addEventListener("click",()=>document.querySelector('.tab[data-tab="diagnostics"]').click());
document.querySelectorAll(".diag-start").forEach(b=>b.addEventListener("click",()=>startDiagnostic(b.dataset.diagKind)));document.getElementById("cancelDiagnostic").addEventListener("click",cancelDiagnostic);
log("панель готова",true);tunerServiceChanged();refresh();refreshProfiles();refreshVersions();refreshHistory();refreshUpdates();refreshTunerSources();refreshTuner();refreshDiagnostic();resumeRouteJob();
</script></body></html>"""


def command_env():
    env = os.environ.copy()
    env["PATH"] = "/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
    return env


def run_command(command, timeout):
    try:
        with tempfile.TemporaryFile(mode="w+b") as capture:
            process = subprocess.Popen(
                command,
                stdout=capture,
                stderr=subprocess.STDOUT,
                env=command_env(),
                start_new_session=True,
            )
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, AttributeError):
                    process.terminate()
                try:
                    process.wait(timeout=min(120, max(10, timeout // 2)))
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, AttributeError):
                        process.kill()
                    process.wait()
            capture.flush()
            capture.seek(0)
            output = capture.read().decode("utf-8", errors="replace").strip()
        if timed_out:
            return {
                "ok": False,
                "code": 124,
                "output": f"Команда превысила таймаут; отправлен TERM для штатного отката.\n{output}".strip(),
            }
        return {
            "ok": process.returncode == 0,
            "code": process.returncode,
            "output": output,
        }
    except OSError as exc:
        return {"ok": False, "code": 127, "output": str(exc)}


def parse_status(text):
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {
            "discord_route",
            "discord_tcp_route",
            "discord_voice_route",
            "youtube_route",
            "xkeen_runtime",
            "nfqws_runtime",
            "script_version",
        }:
            result[key] = value
    return result


def private_client(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def bounded_text(value, field, maximum, *, allow_empty=True):
    if not isinstance(value, str) or len(value) > maximum or "\n" in value or "\r" in value:
        raise ValueError(f"некорректное поле {field}")
    if not allow_empty and not value:
        raise ValueError(f"пустое поле {field}")
    return value


def voice_ports_allowed(value):
    for item in value.split(","):
        parts = item.split("-", 1)
        if not all(part.isdigit() for part in parts):
            return False
        left = int(parts[0])
        right = int(parts[-1])
        if left > right:
            return False
        allowed = (
            (left == right == 443)
            or (3478 <= left <= right <= 3481)
            or (left == right == 5349)
            or (19294 <= left <= right <= 19344)
            or (50000 <= left <= right <= 65535)
        )
        if not allowed:
            return False
    return bool(value)


def validate_candidate(candidate, report):
    if not isinstance(candidate, dict):
        raise ValueError("в отчёте нет найденного кандидата")
    service = candidate.get("service")
    if service not in SERVICES:
        raise ValueError("неподдерживаемый сервис")
    source_name = bounded_text(candidate.get("source_name"), "source_name", 160, allow_empty=False)
    source_sha = bounded_text(candidate.get("source_sha"), "source_sha", 128)
    source_url = bounded_text(candidate.get("source_url"), "source_url", 500)
    family = bounded_text(candidate.get("family"), "family", 240, allow_empty=False)
    candidate_id = bounded_text(candidate.get("candidate_id"), "candidate_id", 12, allow_empty=False)
    if not re.fullmatch(r"[0-9a-f]{12}", candidate_id):
        raise ValueError("некорректный candidate_id")
    rank = candidate.get("rank")
    if isinstance(rank, bool) or not isinstance(rank, int) or not 0 <= rank <= 100000:
        raise ValueError("некорректный rank")
    notes = candidate.get("notes")
    if not isinstance(notes, list) or len(notes) > 20:
        raise ValueError("некорректные notes")
    notes = [bounded_text(item, "notes", 500) for item in notes]
    args = candidate.get("args")
    if not isinstance(args, list) or not 1 <= len(args) <= 40:
        raise ValueError("некорректный список args")
    for token in args:
        bounded_text(token, "args", 600, allow_empty=False)
        if token == "--new":
            continue
        if not SAFE_TOKEN.fullmatch(token):
            raise ValueError(f"небезопасный токен: {token}")
        name, value = token[2:].split("=", 1)
        if name not in SAFE_OPTIONS:
            raise ValueError(f"неподдерживаемая опция: --{name}")
        if name == "lua-desync" and value.split(":", 1)[0] not in SAFE_LUA:
            raise ValueError("неподдерживаемая Lua-стратегия")

    def values(prefix):
        return [token[len(prefix):] for token in args if token.startswith(prefix)]

    if service == "youtube":
        required = {
            "--filter-tcp=443",
            "--filter-udp=443",
            "--filter-l7=tls",
            "--filter-l7=quic",
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
            "--payload=tls_client_hello",
            "--payload=quic_initial",
        }
        if args.count("--new") != 1 or not required.issubset(args):
            raise ValueError("неполный YouTube TCP/QUIC профиль")
        if set(values("--filter-tcp=")) != {"443"} or set(values("--filter-udp=")) != {"443"}:
            raise ValueError("YouTube профиль выходит за TCP/UDP 443")
        if set(values("--filter-l7=")) - {"tls", "quic"}:
            raise ValueError("лишний L7-фильтр YouTube")
        if set(values("--hostlist=")) != {"/opt/etc/nfqws2/lists/youtube.list"}:
            raise ValueError("лишний hostlist YouTube")
        if any("discord" in token or "user.list" in token for token in args):
            raise ValueError("YouTube профиль пересекается с Discord")
    elif service == "discord-tcp":
        required = {
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist=/opt/etc/nfqws2/lists/user.list",
            "--payload=tls_client_hello",
        }
        if "--new" in args or not required.issubset(args):
            raise ValueError("неполный Discord TCP профиль")
        if set(values("--filter-tcp=")) != {"443"} or values("--filter-udp="):
            raise ValueError("Discord TCP профиль выходит за TCP 443")
        if set(values("--filter-l7=")) != {"tls"}:
            raise ValueError("лишний L7-фильтр Discord TCP")
        if set(values("--hostlist=")) != {"/opt/etc/nfqws2/lists/user.list"}:
            raise ValueError("лишний hostlist Discord TCP")
        if any("youtube" in token or "discord_udp" in token for token in args):
            raise ValueError("Discord TCP профиль пересекается с другим семейством")
    else:
        udp = values("--filter-udp=")
        lua = values("--lua-desync=")
        if (
            "--new" in args
            or len(udp) != 1
            or not voice_ports_allowed(udp[0])
            or values("--filter-tcp=")
            or values("--hostlist=")
            or set(values("--filter-l7=")) != {"stun,discord"}
            or set(values("--payload=")) != {"stun,discord_ip_discovery"}
            or len(lua) != 1
            or not re.fullmatch(r"fake:blob=discord_udp:repeats=([1-9]|[1-9][0-9])", lua[0])
        ):
            raise ValueError("Discord Voice профиль выходит за безопасные UDP-границы")

    serialized = "\n".join((service, source_name, family, *args))
    expected_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]
    if candidate_id != expected_id:
        raise ValueError("candidate_id не соответствует содержимому")
    report_meta = {
        "repository": bounded_text(report.get("repository", ""), "repository", 200),
        "ref": bounded_text(report.get("ref", ""), "ref", 200),
        "commit": bounded_text(report.get("commit", ""), "commit", 128),
        "created_utc": bounded_text(report.get("created_utc", ""), "created_utc", 80),
    }
    search_seed = report.get("search_seed")
    if search_seed is not None and (
        isinstance(search_seed, bool)
        or not isinstance(search_seed, int)
        or not 0 <= search_seed <= 4294967295
    ):
        raise ValueError("некорректный search_seed")
    report_meta["search_seed"] = search_seed
    return {
        "format": 1,
        "service": service,
        "candidate_id": candidate_id,
        "source_name": source_name,
        "source_sha": source_sha,
        "source_url": source_url,
        "family": family,
        "args": args,
        "notes": notes,
        "rank": rank,
        "report": report_meta,
    }


def validate_report(report):
    if not isinstance(report, dict):
        raise ValueError("корень отчёта должен быть JSON-объектом")
    if report.get("report_format", 1) != 1:
        raise ValueError("неподдерживаемая версия отчёта")
    candidate = report.get("found")
    profile = validate_candidate(candidate, report)
    if report.get("service") != profile["service"]:
        raise ValueError("сервис отчёта не совпадает с кандидатом")
    return profile


def imported_profiles():
    result = []
    for service in SERVICES:
        path = IMPORTED_PROFILE_DIR / f"{service}.json"
        item = {"service": service, "installed": False}
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError("необычный тип файла")
            if info.st_size > MAX_REPORT_BYTES:
                raise ValueError("файл слишком велик")
            data = json.loads(path.read_text(encoding="utf-8"))
            profile = validate_candidate(data, data.get("report", {}))
            if profile["service"] != service or data.get("format") != 1:
                raise ValueError("неверный сервис")
            item.update(
                installed=True,
                candidate_id=profile["candidate_id"],
                family=profile["family"],
                source_name=profile["source_name"],
                commit=profile["report"].get("commit", ""),
                created_utc=profile["report"].get("created_utc", ""),
                installed_utc=time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(info.st_mtime),
                ),
            )
        except FileNotFoundError:
            pass
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            item["error"] = f"Некорректный профиль: {exc}"
        result.append(item)
    return result


def atomic_text(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def safe_json_file(path, maximum=MAX_REPORT_BYTES):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"необычный тип файла: {path}")
    if not 0 < info.st_size <= maximum:
        raise ValueError(f"некорректный размер файла: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"ожидается JSON-объект: {path}")
    return data


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_active_routes(text):
    """Read the "# Active routes:" line written by apply-discord-nfqws2.sh.

    Returns {"discord-tcp", "discord-voice", "youtube"} -> route, or None when
    the line is missing or malformed. The legacy line "Discord=X, YouTube=Y."
    written before the TCP/Voice split applies X to both Discord routes.
    """
    match = re.search(r"^# Active routes: (.+)\.$", text, re.MULTILINE)
    if not match:
        return None
    values = {}
    for pair in match.group(1).split(", "):
        key, separator, value = pair.partition("=")
        if not separator or value not in ROUTE_VALUES:
            return None
        values[key] = value
    if set(values) == {"DiscordTCP", "DiscordVoice", "YouTube"}:
        return {
            "discord-tcp": values["DiscordTCP"],
            "discord-voice": values["DiscordVoice"],
            "youtube": values["YouTube"],
        }
    if set(values) == {"Discord", "YouTube"}:
        return {
            "discord-tcp": values["Discord"],
            "discord-voice": values["Discord"],
            "youtube": values["YouTube"],
        }
    return None


def current_routes_fast():
    unknown = {service: "unknown" for service in ROUTE_SERVICES}
    try:
        text = NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return unknown
    return parse_active_routes(text) or unknown


def safe_snapshot(path):
    try:
        resolved_parent = path.parent.resolve(strict=True)
        expected_parent = SNAPSHOT_DIR.resolve(strict=True)
        info = path.lstat()
    except OSError:
        return False
    return (
        resolved_parent == expected_parent
        and re.fullmatch(r"[0-9A-Za-z-]+", path.name) is not None
        and stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and (path / "STATE.tsv").is_file()
        and (path / "MANIFEST").is_file()
    )


def history_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{16}", job_id):
        raise ValueError("некорректный ID операции")
    return ROUTE_HISTORY_DIR / f"{job_id}.json"


def write_history(entry):
    path = history_path(entry.get("job_id"))
    ROUTE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ROUTE_HISTORY_DIR, 0o700)
    atomic_text(path, json.dumps(entry, ensure_ascii=False, indent=2) + "\n")


def update_history(job_id, **changes):
    try:
        entry = safe_json_file(history_path(job_id))
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return False
    if entry.get("job_id") != job_id:
        return False
    entry.update(changes)
    write_history(entry)
    return True


def route_history():
    items = []
    def modified(path):
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    try:
        # Newest files first, so the 200-file read limit drops old entries.
        paths = sorted(ROUTE_HISTORY_DIR.glob("*.json"), key=modified, reverse=True)
    except OSError:
        paths = []
    for path in paths[:200]:
        if not re.fullmatch(r"[0-9a-f]{16}\.json", path.name):
            continue
        try:
            item = safe_json_file(path)
            if item.get("job_id") != path.stem:
                raise ValueError("ID файла не совпадает")
            snapshot_value = item.get("snapshot", "")
            snapshot_path = Path(snapshot_value) if isinstance(snapshot_value, str) else Path("")
            item["rollback_available"] = bool(snapshot_value and safe_snapshot(snapshot_path))
            items.append(item)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            items.append(
                {
                    "job_id": path.stem,
                    "status": "error",
                    "error": f"история повреждена: {exc}",
                    "rollback_available": False,
                }
            )
    items.sort(key=lambda item: item.get("created_utc", ""), reverse=True)
    return items[:MAX_HISTORY_ITEMS]


def parse_snapshot_from_output(output):
    pattern = re.compile(
        r"(?:Snapshot created|Rescue snapshot of current state): "
        + re.escape(str(SNAPSHOT_DIR))
        + r"[\\/]([0-9A-Za-z-]+)"
    )
    match = pattern.search(output)
    if not match:
        return ""
    candidate = SNAPSHOT_DIR / match.group(1)
    return str(candidate) if safe_snapshot(candidate) else ""


def profile_versions():
    active = {
        item["service"]: item.get("candidate_id")
        for item in imported_profiles()
        if item.get("installed")
    }
    result = []
    pattern = re.compile(
        r"^(\d{8}T\d{6}Z)-([0-9a-f]{12})-"
        r"(applied|replaced|cleared)-(\d+)(?:-(\d+))?\.json$"
    )
    for service in SERVICES:
        directory = PROFILE_VERSION_DIR / service
        try:
            paths = sorted(directory.glob("*.json"), reverse=True)
        except OSError:
            continue
        for path in paths[:50]:
            match = pattern.fullmatch(path.name)
            if not match:
                continue
            try:
                data = safe_json_file(path)
                profile = validate_candidate(data, data.get("report", {}))
                if profile["service"] != service or profile["candidate_id"] != match.group(2):
                    raise ValueError("метаданные версии не совпадают")
                stamp = match.group(1)
                created = (
                    f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T"
                    f"{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"
                )
                result.append(
                    {
                        "id": path.name[:-5],
                        "service": service,
                        "candidate_id": profile["candidate_id"],
                        "family": profile["family"],
                        "source_name": profile["source_name"],
                        "commit": profile["report"].get("commit", ""),
                        "created_utc": created,
                        "reason": match.group(3),
                        "active": active.get(service) == profile["candidate_id"],
                    }
                )
            except (OSError, ValueError, json.JSONDecodeError):
                continue
    result.sort(key=lambda item: item["created_utc"], reverse=True)
    return result[:100]


def profile_version_path(service, version_id):
    if service not in SERVICES:
        raise ValueError("неподдерживаемый сервис")
    if not re.fullmatch(
        r"\d{8}T\d{6}Z-[0-9a-f]{12}-(applied|replaced|cleared)-\d+(?:-\d+)?",
        version_id,
    ):
        raise ValueError("некорректный ID версии")
    path = PROFILE_VERSION_DIR / service / f"{version_id}.json"
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("необычный файл версии")
    data = safe_json_file(path)
    profile = validate_candidate(data, data.get("report", {}))
    if profile["service"] != service:
        raise ValueError("сервис версии не совпадает")
    return path, profile


def flowseal_source_module():
    name = "xkeen_flowseal_sources"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, PROJECT_DIR / "tools/windows/zapret_tuner.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None)
            raise
    return sys.modules[name]


def cached_flowseal_update():
    try:
        sources, commit = flowseal_source_module().read_source_cache(FLOWSEAL_SOURCE_CACHE)
        try:
            payload = safe_json_file(FLOWSEAL_UPDATE_STATE)
        except (OSError, ValueError):
            payload = {}
        payload.update(ok=True, repository=FLOWSEAL_REPOSITORY, downloaded_commit=commit, source_count=len(sources))
        if payload.get("status") not in {"downloaded", "up_to_date", "error"}:
            payload["status"] = "downloaded"
        return payload
    except FileNotFoundError:
        return {"ok": True, "status": "never_downloaded"}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"ok": True, "status": "error", "error": str(exc)}


def check_flowseal_update():
    with FLOWSEAL_UPDATE_LOCK:
        try:
            return download_flowseal_update()
        except (OSError, RuntimeError, ValueError) as exc:
            atomic_text(FLOWSEAL_UPDATE_STATE, json.dumps({
                "ok": True, "status": "error", "error": str(exc)[:1000],
                "checked_utc": utc_now(),
            }, ensure_ascii=False) + "\n")
            raise


def download_flowseal_update():
    url = f"https://api.github.com/repos/{FLOWSEAL_REPOSITORY}/commits/{FLOWSEAL_REF}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "keenetic-zapret-panel/6.4",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read(1024 * 1024).decode("utf-8"))
    latest = data.get("sha", "") if isinstance(data, dict) else ""
    if not isinstance(latest, str) or not re.fullmatch(r"[0-9a-f]{40}", latest):
        raise RuntimeError("GitHub не вернул корректный commit")
    authored = data.get("commit", {}).get("committer", {}).get("date", "")
    module = flowseal_source_module()
    sources, cached_commit = [], ""
    try:
        sources, cached_commit = module.read_source_cache(FLOWSEAL_SOURCE_CACHE)
    except (OSError, RuntimeError, ValueError):
        pass
    changed = cached_commit != latest
    if changed:
        sources, fetched_commit = module.fetch_sources(FLOWSEAL_REPOSITORY, latest)
        if fetched_commit != latest:
            raise RuntimeError("скачанный commit не совпал с запрошенным")
        # Validate and atomically replace only after every source is downloaded.
        module.save_source_cache(FLOWSEAL_SOURCE_CACHE, sources, latest)
    payload = {
        "ok": True, "status": "downloaded" if changed else "up_to_date",
        "repository": FLOWSEAL_REPOSITORY, "latest_commit": latest,
        "downloaded_commit": latest, "source_count": len(sources),
        "latest_date": bounded_text(authored, "latest_date", 80),
        "checked_utc": utc_now(),
    }
    atomic_text(FLOWSEAL_UPDATE_STATE, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return payload


def config_health():
    routes = current_routes_fast()
    checks = []

    def add(name, passed, detail):
        checks.append({"name": name, "ok": bool(passed), "detail": detail})

    xray_running = bool(run_command(["pidof", "xray"], timeout=5)["ok"])
    nfqws_running = bool(run_command(["pidof", "nfqws2"], timeout=5)["ok"])
    add("Xray", xray_running, "процесс запущен" if xray_running else "процесс не найден")
    add("nfqws2", nfqws_running, "процесс запущен" if nfqws_running else "процесс не найден")
    try:
        nfqws_text = NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        nfqws_text = ""
        add("nfqws2 config", False, str(exc))
    try:
        routing = safe_json_file(XRAY_ROUTING)
        rules = routing.get("routing", {}).get("rules", [])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        rules = []
        add("Xray routing", False, str(exc))

    def outbound_present(tag):
        return any(isinstance(rule, dict) and rule.get("outboundTag") == tag for rule in rules)

    youtube = routes["youtube"]
    youtube_hostlist = "--hostlist=/opt/etc/nfqws2/lists/youtube.list" in nfqws_text
    add(
        "YouTube route",
        youtube in {"direct", "zapret", "vless"}
        and (youtube == "vless" or outbound_present("youtube-direct"))
        and (youtube_hostlist == (youtube == "zapret")),
        f"route={youtube}, nfqws={'on' if youtube_hostlist else 'off'}",
    )
    try:
        discord_list_active = bool(
            DISCORD_LIST.read_text(encoding="utf-8", errors="replace").strip()
        )
    except OSError:
        discord_list_active = False
    # Every Voice profile (built-in or imported) selects --filter-l7=stun,discord.
    discord_voice_active = "--filter-l7=stun,discord" in nfqws_text
    for name, service, active in (
        ("Discord TCP route", "discord-tcp", discord_list_active),
        ("Discord Voice route", "discord-voice", discord_voice_active),
    ):
        route = routes[service]
        add(
            name,
            route in ROUTE_VALUES
            and (route == "vless" or outbound_present("discord-direct"))
            and (active == (route == "zapret")),
            f"route={route}, nfqws={'on' if active else 'off'}",
        )
    return {"ok": True, "routes": routes, "checks": checks, "all_ok": all(item["ok"] for item in checks)}


def process_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
        return state != "Z"
    except (OSError, UnicodeError, IndexError):
        return True


def read_job_pid(path):
    """PID recorded by a panel job launcher, or None if missing/invalid."""
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    if not raw.isdigit() or int(raw) <= 1:
        return None
    return int(raw)


def job_command(pid):
    """Argument list of a live (non-zombie) process, or None."""
    if not process_alive(pid):
        return None
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None


def clear_job_files(directory, paths, place="каталоге задания"):
    """Create the private job directory and remove the previous job's files.

    Only regular files and symlinks are removed; anything else is refused.
    """
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    for path in paths:
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                raise RuntimeError(f"необычный объект в {place}: {path}")
        except FileNotFoundError:
            pass


def route_process_alive(pid):
    command = job_command(pid)
    return (
        command is not None
        and b"--route-job" in command
        and os.fsencode(str(Path(__file__))) in command
    )


def route_pid():
    return read_job_pid(ROUTE_PID)


def route_active():
    pid = route_pid()
    return bool(pid and route_process_alive(pid))


def route_status():
    payload = {
        "ok": True,
        "status": "idle",
        "active": False,
        "output": "",
        "log_tail": [],
    }
    try:
        payload.update(safe_json_file(ROUTE_STATE))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    active = route_active()
    payload["active"] = active
    if payload.get("status") in {"queued", "running"} and not active:
        payload.update(
            result_ok=False,
            status="failed",
            error=payload.get("error") or "процесс переключения завершился неожиданно",
        )
        job_id = payload.get("job_id")
        if isinstance(job_id, str):
            update_history(
                job_id,
                result_ok=False,
                status="failed",
                error=payload["error"],
                finished_utc=utc_now(),
            )
    try:
        info = ROUTE_APPLY_LOG.lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            lines = ROUTE_APPLY_LOG.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            payload["log_tail"] = [line[:1000] for line in lines[-120:]]
    except OSError:
        pass
    payload["ok"] = True
    return payload


def clear_previous_route_job():
    clear_job_files(ROUTE_JOB_DIR, (ROUTE_STATE, ROUTE_PID, ROUTE_LOG, ROUTE_APPLY_LOG))


def update_route_state(job_id, **changes):
    try:
        state = safe_json_file(ROUTE_STATE)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return False
    if state.get("job_id") != job_id:
        return False
    state.update(changes)
    atomic_text(
        ROUTE_STATE,
        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
    )
    return True


def validate_route(service, mode):
    if service not in ROUTE_REQUEST_SERVICES:
        raise ValueError("неподдерживаемый сервис")
    if mode not in {"direct", "zapret", "vpn"}:
        raise ValueError("неподдерживаемый маршрут")
    return service, mode


def read_history_item(job_id):
    item = safe_json_file(history_path(job_id))
    if item.get("job_id") != job_id:
        raise ValueError("ID записи истории не совпадает")
    return item


def launch_route_worker(state, worker_args):
    clear_previous_route_job()
    atomic_text(
        ROUTE_STATE,
        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
    )
    history = {
        key: value
        for key, value in state.items()
        if key not in {"ok", "active", "output", "stage_label", "progress"}
    }
    write_history(history)
    command = [
        sys.executable,
        str(Path(__file__)),
        "--route-job",
        state["job_id"],
        *worker_args,
    ]
    environment = command_env()
    environment["PYTHONUNBUFFERED"] = "1"
    try:
        with ROUTE_LOG.open("ab", buffering=0) as output:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                cwd=PROJECT_DIR,
                env=environment,
                start_new_session=True,
            )
    except OSError as exc:
        update_route_state(
            state["job_id"],
            result_ok=False,
            active=False,
            status="failed",
            error=str(exc),
            finished_utc=utc_now(),
        )
        update_history(
            state["job_id"],
            result_ok=False,
            status="failed",
            error=str(exc),
            finished_utc=utc_now(),
        )
        raise
    atomic_text(ROUTE_PID, f"{process.pid}\n")
    threading.Thread(target=process.wait, daemon=True).start()
    state["pid"] = process.pid
    return state


@contextlib.contextmanager
def job_start_guard():
    """Serialize job starts; a second start fails fast instead of waiting."""
    if not JOB_START_LOCK.acquire(blocking=False):
        raise RuntimeError("другое задание уже запускается; повторите через несколько секунд")
    try:
        yield
    finally:
        JOB_START_LOCK.release()


def ensure_route_job_available():
    if tuner_active():
        raise RuntimeError("маршруты нельзя менять во время подбора")
    if diagnostic_active():
        raise RuntimeError("маршруты нельзя менять во время диагностики")
    if route_active():
        raise RuntimeError("переключение маршрута уже выполняется")


def start_route_job(service, mode):
    service, mode = validate_route(service, mode)
    with job_start_guard():
        ensure_route_job_available()
        before = current_routes_fast()
        requested = dict(before)
        targets = ("discord-tcp", "discord-voice") if service == "discord" else (service,)
        for target in targets:
            requested[target] = "vless" if mode == "vpn" else mode
        job_id = secrets.token_hex(8)
        state = {
            "ok": True,
            "job_id": job_id,
            "operation": "switch",
            "status": "queued",
            "stage": "queued",
            "stage_label": "В очереди",
            "progress": 0,
            "active": True,
            "service": service,
            "mode": mode,
            "before_routes": before,
            "requested_routes": requested,
            "created_at": int(time.time()),
            "created_utc": utc_now(),
            "output": "",
        }
        return launch_route_worker(state, ["switch", service, mode])


def start_history_rollback(history_id):
    with job_start_guard():
        ensure_route_job_available()
        source = read_history_item(history_id)
        if source.get("status") != "completed":
            raise ValueError("откат доступен только для завершённой операции")
        snapshot_value = source.get("snapshot", "")
        snapshot = Path(snapshot_value) if isinstance(snapshot_value, str) else Path("")
        if not snapshot_value or not safe_snapshot(snapshot):
            raise ValueError("snapshot этой операции отсутствует или повреждён")
        job_id = secrets.token_hex(8)
        state = {
            "ok": True,
            "job_id": job_id,
            "operation": "rollback",
            "rollback_of": history_id,
            "status": "queued",
            "stage": "queued",
            "stage_label": "В очереди",
            "progress": 0,
            "active": True,
            "service": "rollback",
            "mode": "snapshot",
            "before_routes": current_routes_fast(),
            "requested_routes": source.get("before_routes", {}),
            "target_snapshot": str(snapshot),
            "created_at": int(time.time()),
            "created_utc": utc_now(),
            "output": "",
        }
        return launch_route_worker(
            state,
            ["rollback", history_id, str(snapshot)],
        )


def route_stage(output, operation):
    stages = [
        ("preflight", "Проверка конфигурации", 10),
    ]
    if "Snapshot created:" in output:
        stages.append(("snapshot", "Создание snapshot", 25))
    if operation == "switch":
        if "Patching Xray routing:" in output or "Patching Mihomo" in output:
            stages.append(("config", "Запись конфигурации", 45))
        if "Restarting XKeen..." in output:
            stages.append(("xray", "Перезапуск XKeen/Xray", 65))
        if "Restarting nfqws2 only" in output:
            stages.append(("nfqws", "Перезапуск nfqws2", 82))
        if "Started NFQWS2 service" in output:
            stages.append(("verify", "Проверка служб", 94))
    else:
        if "Rescue snapshot of current state:" in output:
            stages.append(("snapshot", "Rescue snapshot", 30))
        if "Restoring" in output:
            stages.append(("restore", "Восстановление файлов", 58))
        if "Restore complete:" in output:
            stages.append(("verify", "Проверка восстановленного состояния", 92))
    return stages[-1]


def run_route_command(command, job_id, operation, timeout=900):
    started = time.monotonic()
    timed_out = False
    last_stage = None
    with ROUTE_APPLY_LOG.open("w+b") as capture:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=capture,
            stderr=subprocess.STDOUT,
            env=command_env(),
            start_new_session=True,
        )
        while True:
            try:
                process.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                capture.flush()
                capture.seek(0)
                preview = capture.read().decode("utf-8", errors="replace")
                capture.seek(0, os.SEEK_END)
                stage = route_stage(preview, operation)
                if stage[0] != last_stage:
                    last_stage = stage[0]
                    update_route_state(
                        job_id,
                        stage=stage[0],
                        stage_label=stage[1],
                        progress=stage[2],
                    )
                if time.monotonic() - started < timeout:
                    continue
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, AttributeError):
                    process.terminate()
                try:
                    process.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, AttributeError):
                        process.kill()
                    process.wait()
                break
        capture.flush()
        capture.seek(0)
        output = capture.read().decode("utf-8", errors="replace").strip()
    if len(output) > 200000:
        output = "[...начало вывода сокращено...]\n" + output[-200000:]
    if timed_out:
        output = (
            "Команда превысила таймаут; отправлен TERM для штатного отката.\n"
            + output
        ).strip()
        return {"ok": False, "code": 124, "output": output}
    return {"ok": process.returncode == 0, "code": process.returncode, "output": output}


def run_route_job(job_id, operation, subject, target):
    try:
        if operation == "switch":
            service, mode = validate_route(subject, target)
            command = [
                "/bin/sh",
                str(SERVICE_SWITCH),
                service,
                mode,
                "--core",
                "auto",
                "--yes-router",
            ]
        elif operation == "rollback":
            history_path(subject)
            snapshot = Path(target)
            if not safe_snapshot(snapshot):
                raise ValueError("небезопасный snapshot для отката")
            command = [
                "/bin/sh",
                str(ENGINE),
                "--rollback-snapshot",
                str(snapshot),
                "--yes-router",
            ]
        else:
            raise ValueError("неподдерживаемый тип route-job")
    except (OSError, ValueError) as exc:
        update_route_state(
            job_id,
            result_ok=False,
            active=False,
            status="failed",
            stage="failed",
            stage_label="Ошибка запуска",
            error=str(exc),
            finished_utc=utc_now(),
        )
        update_history(
            job_id,
            result_ok=False,
            status="failed",
            error=str(exc),
            finished_utc=utc_now(),
        )
        return 2
    started_utc = utc_now()
    if not update_route_state(
        job_id,
        status="running",
        stage="preflight",
        stage_label="Проверка конфигурации",
        progress=10,
        active=True,
        started_utc=started_utc,
    ):
        return 2
    update_history(job_id, status="running", started_utc=started_utc)
    payload = run_route_command(command, job_id, operation)
    output = payload.get("output", "")
    finished_utc = utc_now()
    final_status = "completed" if payload["ok"] else "failed"
    snapshot = parse_snapshot_from_output(output)
    after_routes = current_routes_fast()
    update_route_state(
        job_id,
        result_ok=payload["ok"],
        active=False,
        status=final_status,
        stage=final_status,
        stage_label="Готово" if payload["ok"] else "Ошибка и откат",
        progress=100,
        code=payload["code"],
        output=output,
        snapshot=snapshot,
        after_routes=after_routes,
        finished_utc=finished_utc,
    )
    update_history(
        job_id,
        result_ok=payload["ok"],
        status=final_status,
        code=payload["code"],
        snapshot=snapshot,
        after_routes=after_routes,
        output_tail=output[-12000:],
        finished_utc=finished_utc,
    )
    return payload["code"]


def tuner_process_alive(pid):
    command = job_command(pid)
    return command is not None and os.fsencode(str(AUTOTUNER)) in command


def tuner_pid():
    return read_job_pid(TUNER_PID)


def tuner_active():
    pid = tuner_pid()
    return bool(pid and tuner_process_alive(pid))


def tuner_status():
    payload = {
        "ok": True,
        "status": "idle",
        "active": False,
        "result_available": False,
        "log_tail": [],
    }
    try:
        payload.update(safe_json_file(TUNER_STATE))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    active = tuner_active()
    payload["active"] = active
    if payload.get("status") in {
        "preparing",
        "running",
        "voice_window",
        "awaiting_voice",
        "cancelling",
    } and not active:
        payload.update(
            status="error",
            error=payload.get("error") or "процесс подбора завершился неожиданно",
        )
    try:
        info = (TUNER_JOB_DIR / "events.log").lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            lines = (TUNER_JOB_DIR / "events.log").read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            payload["log_tail"] = [line[:1000] for line in lines[-120:]]
    except OSError:
        pass
    return payload


def tuner_sources():
    """List the downloaded Flowseal BAT files and the services each one covers."""
    try:
        module = flowseal_source_module()
        sources, commit = module.read_source_cache(FLOWSEAL_SOURCE_CACHE)
    except FileNotFoundError:
        return {"ok": True, "status": "never_downloaded", "commit": "", "sources": []}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"ok": True, "status": "error", "error": str(exc), "commit": "", "sources": []}
    return {
        "ok": True,
        "status": "ready",
        "commit": commit,
        "sources": [
            {"name": source.name, "services": module.source_services(source)}
            for source in sorted(sources, key=lambda item: item.name.casefold())
        ],
    }


def validate_tuner_request(body):
    if not isinstance(body, dict):
        raise ValueError("ожидается JSON-объект")
    if set(body) - {"service", "mix_level", "max_candidates", "client_ip", "search_seed", "source_file"}:
        raise ValueError("неизвестные параметры подбора")
    service = body.get("service")
    if service not in SERVICES:
        raise ValueError("неподдерживаемый сервис")
    mix_level = body.get("mix_level", "safe")
    if mix_level not in {"off", "safe", "extended"}:
        raise ValueError("неподдерживаемый уровень смешивания")
    maximum = body.get("max_candidates", 32)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 64:
        raise ValueError("число кандидатов должно быть от 1 до 64")
    client_ip = body.get("client_ip", "")
    if not isinstance(client_ip, str) or len(client_ip) > 45:
        raise ValueError("некорректный client_ip")
    if service == "discord-voice":
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError as exc:
            raise ValueError("для Voice нужен LAN IPv4 компьютера") from exc
        if address.version != 4 or not address.is_private:
            raise ValueError("для Voice нужен частный LAN IPv4")
    elif client_ip:
        raise ValueError("client_ip допустим только для Discord Voice")
    search_seed = body.get("search_seed")
    if search_seed in (None, ""):
        search_seed = secrets.randbits(32)
    elif isinstance(search_seed, str) and search_seed.isdecimal():
        search_seed = int(search_seed, 10)
    if (
        isinstance(search_seed, bool)
        or not isinstance(search_seed, int)
        or not 0 <= search_seed <= 4294967295
    ):
        raise ValueError("seed должен быть целым числом от 0 до 4294967295")
    source_file = body.get("source_file") or None
    if source_file is not None and (
        not isinstance(source_file, str)
        or len(source_file) > 160
        or not SOURCE_FILE_NAME.fullmatch(source_file)
    ):
        raise ValueError("файл стратегии должен быть одним general*.bat")
    return {
        "service": service,
        "mix_level": mix_level,
        "max_candidates": maximum,
        "client_ip": client_ip,
        "search_seed": search_seed,
        "source_file": source_file,
    }


def clear_previous_tuner_job():
    clear_job_files(
        TUNER_JOB_DIR,
        [
            TUNER_JOB_DIR / name
            for name in (
                "state.json",
                "events.log",
                "result-report.json",
                "runner.sh",
                "verdict.txt",
                "panel-launch.pid",
                "process.log",
            )
        ],
    )


def start_tuner_job(settings):
    with job_start_guard():
        return launch_tuner_job(settings)


def launch_tuner_job(settings):
    if tuner_active():
        raise RuntimeError("подбор уже выполняется")
    if route_active():
        raise RuntimeError("сначала завершите переключение маршрута")
    if diagnostic_active():
        raise RuntimeError("сначала завершите диагностику")
    status_payload = run_command(
        ["/bin/sh", str(ENGINE), "--status"],
        timeout=40,
    )
    if not status_payload["ok"]:
        raise RuntimeError(status_payload["output"] or "не удалось прочитать маршруты")
    routes = parse_status(status_payload.get("output", ""))
    route = routes.get(STATUS_ROUTE_KEYS[settings["service"]], "unknown")
    if route != "zapret":
        raise RuntimeError(
            f"{settings['service']} использует route={route}; сначала включите Zapret"
        )
    clear_previous_tuner_job()
    job_id = secrets.token_hex(8)
    command = [
        sys.executable,
        str(AUTOTUNER),
        "--service",
        settings["service"],
        "--job-id",
        job_id,
        "--mix-level",
        settings["mix_level"],
        "--max-candidates",
        str(settings["max_candidates"]),
        "--search-seed",
        str(settings["search_seed"]),
        "--http-timeout",
        "6",
        "--voice-duration",
        "25",
    ]
    if settings["client_ip"]:
        command.extend(["--client-ip", settings["client_ip"]])
    if settings.get("source_file"):
        command.extend(["--source-file", settings["source_file"]])
    environment = command_env()
    environment["PYTHONUNBUFFERED"] = "1"
    with (TUNER_JOB_DIR / "process.log").open("ab", buffering=0) as output:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            cwd=PROJECT_DIR,
            env=environment,
            start_new_session=True,
        )
    threading.Thread(target=process.wait, daemon=True).start()
    atomic_text(TUNER_PID, f"{process.pid}\n")
    return process.pid


def cancel_tuner_job():
    pid = tuner_pid()
    if not pid or not tuner_process_alive(pid):
        raise RuntimeError("активного подбора нет")
    try:
        state = safe_json_file(TUNER_STATE)
        state["status"] = "cancelling"
        atomic_text(
            TUNER_STATE,
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
        )
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    os.killpg(pid, signal.SIGTERM)


def diagnostic_process_alive(pid):
    command = job_command(pid)
    return command is not None and os.fsencode(str(DIAGNOSTICS)) in command


def diagnostic_pid():
    return read_job_pid(DIAGNOSTIC_PID)


def diagnostic_active():
    pid = diagnostic_pid()
    return bool(pid and diagnostic_process_alive(pid))


def diagnostic_status():
    payload = {
        "ok": True,
        "status": "idle",
        "active": False,
        "progress": 0,
        "results": [],
    }
    try:
        payload.update(safe_json_file(DIAGNOSTIC_STATE))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    active = diagnostic_active()
    # Standard/DPI moved into the browser. Their old persistent reports must
    # not be mistaken for results of the current browser session.
    if payload.get("kind") in {"standard", "dpi"} and not active:
        return {"ok": True, "status": "idle", "active": False, "progress": 0, "results": []}
    payload["active"] = active
    if payload.get("status") in {"queued", "running", "cancelling"} and not active:
        payload.update(status="error", error=payload.get("error") or "процесс диагностики завершился неожиданно")
        try:
            atomic_text(DIAGNOSTIC_STATE, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        except OSError:
            pass
    payload["ok"] = True
    return payload


def clear_previous_diagnostic_job():
    clear_job_files(
        DIAGNOSTIC_JOB_DIR,
        (DIAGNOSTIC_STATE, DIAGNOSTIC_PID, DIAGNOSTIC_LOG),
        place="каталоге диагностики",
    )
    for path in DIAGNOSTIC_JOB_DIR.glob("payload-*.bin"):
        if re.fullmatch(r"payload-\d+\.bin", path.name) and path.is_file() and not path.is_symlink():
            path.unlink()


def start_diagnostic_job(kind):
    if kind != "health":
        raise ValueError("Standard/DPI tests выполняются только в браузере")
    with job_start_guard():
        return launch_diagnostic_job(kind)


def launch_diagnostic_job(kind):
    if diagnostic_active():
        raise RuntimeError("диагностика уже выполняется")
    if tuner_active():
        raise RuntimeError("сначала завершите автоподбор")
    if route_active():
        raise RuntimeError("сначала завершите переключение маршрута")
    clear_previous_diagnostic_job()
    job_id = secrets.token_hex(8)
    initial = {
        "ok": True,
        "job_id": job_id,
        "kind": kind,
        "status": "queued",
        "active": True,
        "progress": 0,
        "created_utc": utc_now(),
        "results": [],
    }
    atomic_text(DIAGNOSTIC_STATE, json.dumps(initial, ensure_ascii=False, indent=2) + "\n")
    command = [sys.executable, str(DIAGNOSTICS), "--kind", kind, "--job-id", job_id]
    environment = command_env()
    environment["PYTHONUNBUFFERED"] = "1"
    try:
        with DIAGNOSTIC_LOG.open("ab", buffering=0) as output:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                cwd=PROJECT_DIR,
                env=environment,
                start_new_session=True,
            )
    except OSError as exc:
        initial.update(active=False, status="error", error=str(exc), finished_utc=utc_now())
        atomic_text(DIAGNOSTIC_STATE, json.dumps(initial, ensure_ascii=False, indent=2) + "\n")
        raise
    atomic_text(DIAGNOSTIC_PID, f"{process.pid}\n")
    threading.Thread(target=process.wait, daemon=True).start()
    initial["pid"] = process.pid
    return initial


def cancel_diagnostic_job():
    pid = diagnostic_pid()
    if not pid or not diagnostic_process_alive(pid):
        raise RuntimeError("активной диагностики нет")
    try:
        state = safe_json_file(DIAGNOSTIC_STATE)
        state.update(status="cancelling", active=True)
        atomic_text(DIAGNOSTIC_STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    os.killpg(pid, signal.SIGTERM)


def submit_voice_verdict(works):
    state = safe_json_file(TUNER_STATE)
    if not tuner_active() or state.get("status") != "awaiting_voice":
        raise RuntimeError("сейчас ответ Voice не ожидается")
    if TUNER_VERDICT.exists():
        raise RuntimeError("ответ для этого кандидата уже отправлен")
    atomic_text(TUNER_VERDICT, "yes\n" if works else "no\n")


def apply_profile(profile):
    stage_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir="/opt/tmp",
            prefix="xkeen-profile-",
            suffix=".json",
            delete=False,
        ) as stage:
            json.dump(profile, stage, ensure_ascii=False, indent=2)
            stage.write("\n")
            stage_path = stage.name
        os.chmod(stage_path, 0o600)
        return run_command(
            [
                "/bin/sh",
                str(ENGINE),
                "--apply-import-profile",
                stage_path,
                "--yes-router",
            ],
            timeout=300,
        )
    finally:
        if stage_path:
            try:
                os.unlink(stage_path)
            except FileNotFoundError:
                pass


class Handler(BaseHTTPRequestHandler):
    server_version = "XKeenControl/6.4"

    def log_message(self, format_string, *args):
        print(f"{self.client_address[0]} {self.log_date_time_string()} {format_string % args}")

    def send_text(self, code, content, content_type):
        body = content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code, payload):
        self.send_text(code, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")

    def send_download(self, path, filename, content_type):
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                raise ValueError("небезопасный файл")
            body = path.read_text(encoding="utf-8-sig").encode("utf-8-sig")
        except (OSError, ValueError) as exc:
            self.send_json(404, {"ok": False, "error": str(exc)})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def allowed_client(self):
        if private_client(self.client_address[0]):
            return True
        self.send_json(403, {"ok": False, "error": "client is outside LAN"})
        return False

    def valid_same_origin_post(self):
        if self.headers.get("X-XKeen-Control") != "1":
            self.send_json(403, {"ok": False, "error": "control header missing"})
            return False
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if host not in {BIND_HOST, f"{BIND_HOST}:{PORT}"}:
            self.send_json(403, {"ok": False, "error": "unexpected Host header"})
            return False
        if origin and urlsplit(origin).netloc != host:
            self.send_json(403, {"ok": False, "error": "cross-origin request denied"})
            return False
        return True

    def read_json_body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("ожидается Content-Type: application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit():
            raise ValueError("некорректный Content-Length")
        length = int(raw_length)
        if not 0 <= length <= MAX_REPORT_BYTES:
            raise ValueError("JSON превышает 512 КиБ")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"некорректный JSON: {exc}") from exc

    def do_GET(self):
        if not self.allowed_client():
            return
        if self.path == "/":
            self.send_text(200, HTML, "text/html; charset=utf-8")
            return
        if self.path == "/tools/reset-discord-cache.ps1":
            self.send_download(DISCORD_CACHE_HELPER, "reset-discord-cache.ps1", "text/plain; charset=utf-8")
            return
        if self.path == "/assets/browser-diagnostics.js":
            self.send_text(200, BROWSER_DIAGNOSTICS.read_text(encoding="utf-8"), "application/javascript; charset=utf-8")
            return
        if self.path == "/api/diagnostics/targets":
            spec = importlib.util.spec_from_file_location("diagnostic_targets", DIAGNOSTICS)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.send_json(200, {
                "ok": True,
                "standard": [{"name": name, "url": url} for name, url in module.STANDARD_TARGETS if url.startswith("https://")],
                "dpi": [{"name": provider + " · " + identifier, "url": "https://" + host} for identifier, provider, host in module.DPI_TARGETS],
            })
            return
        if self.path == "/api/status":
            if not ENGINE.is_file():
                self.send_json(500, {"ok": False, "error": f"project script not found: {ENGINE}"})
                return
            payload = run_command(["/bin/sh", str(ENGINE), "--status"], timeout=40)
            payload.update(parse_status(payload.get("output", "")))
            self.send_json(200 if payload["ok"] else 500, payload)
            return
        if self.path == "/api/imported":
            self.send_json(
                200,
                {
                    "ok": True,
                    "profiles": imported_profiles(),
                    "rollback_available": IMPORT_ROLLBACK_POINTER.is_file(),
                },
            )
            return
        if self.path == "/api/tuner/status":
            self.send_json(200, tuner_status())
            return
        if self.path == "/api/tuner/sources":
            self.send_json(200, tuner_sources())
            return
        if self.path == "/api/route/status":
            self.send_json(200, route_status())
            return
        if self.path == "/api/diagnostics/status":
            self.send_json(200, diagnostic_status())
            return
        if self.path == "/api/history":
            self.send_json(200, {"ok": True, "items": route_history()})
            return
        if self.path == "/api/profile-versions":
            self.send_json(200, {"ok": True, "versions": profile_versions()})
            return
        if self.path == "/api/updates":
            self.send_json(200, cached_flowseal_update())
            return
        if self.path == "/api/checks/config":
            self.send_json(200, config_health())
            return
        self.send_json(404, {"ok": False, "error": "unknown endpoint"})

    def do_POST(self):
        if not self.allowed_client() or not self.valid_same_origin_post():
            return
        try:
            body = self.read_json_body()
        except ValueError as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})
            return

        parts = self.path.strip("/").split("/")
        if len(parts) == 4 and parts[:3] == ["api", "diagnostics", "start"]:
            if not DIAGNOSTICS.is_file():
                self.send_json(500, {"ok": False, "error": f"diagnostics not found: {DIAGNOSTICS}"})
                return
            try:
                self.send_json(202, start_diagnostic_job(parts[3]))
            except (OSError, RuntimeError, ValueError) as exc:
                self.send_json(409 if isinstance(exc, RuntimeError) else 400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/diagnostics/cancel":
            try:
                cancel_diagnostic_job()
                payload = diagnostic_status()
                payload.update(ok=True, status="cancelling", active=True)
                self.send_json(202, payload)
            except (OSError, RuntimeError) as exc:
                self.send_json(409, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/tuner/start":
            if not AUTOTUNER.is_file():
                self.send_json(500, {"ok": False, "error": f"autotuner not found: {AUTOTUNER}"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "сначала завершите переключение маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "сначала завершите диагностику"})
                return
            try:
                settings = validate_tuner_request(body)
                start_tuner_job(settings)
                payload = tuner_status()
                payload["active"] = True
                payload.setdefault("service", settings["service"])
                self.send_json(202, payload)
            except (OSError, RuntimeError, ValueError) as exc:
                self.send_json(409 if isinstance(exc, RuntimeError) else 400, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/tuner/cancel":
            try:
                cancel_tuner_job()
                payload = tuner_status()
                payload.update(ok=True, status="cancelling", active=True)
                self.send_json(202, payload)
            except (OSError, RuntimeError) as exc:
                self.send_json(409, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/tuner/verdict":
            if not isinstance(body, dict) or set(body) != {"works"} or not isinstance(body["works"], bool):
                self.send_json(400, {"ok": False, "error": "ожидается единственный bool-параметр works"})
                return
            try:
                submit_voice_verdict(body["works"])
                self.send_json(202, tuner_status())
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                self.send_json(409, {"ok": False, "error": str(exc)})
            return

        if self.path == "/api/tuner/apply":
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "сначала завершите подбор"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "сначала завершите переключение маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "сначала завершите диагностику"})
                return
            try:
                state = safe_json_file(TUNER_STATE)
                if state.get("status") != "found" or not state.get("result_available"):
                    raise ValueError("нет найденного результата для применения")
                profile = validate_report(safe_json_file(TUNER_RESULT))
                payload = apply_profile(profile)
                self.send_json(200 if payload["ok"] else 500, payload)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
            return

        xkeen_actions = {
            "/api/xkeen/start": [XKEEN, "-start"],
            "/api/xkeen/stop": [XKEEN, "-stop"],
            "/api/xkeen/restart": [XKEEN, "-restart"],
        }
        if self.path in xkeen_actions:
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "XKeen нельзя менять во время подбора"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "XKeen нельзя менять во время переключения маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "XKeen нельзя менять во время диагностики"})
                return
            payload = run_command(xkeen_actions[self.path], timeout=90)
            self.send_json(200 if payload["ok"] else 500, payload)
            return

        if (
            len(parts) == 4
            and parts[:2] == ["api", "route"]
            and parts[2] in ROUTE_REQUEST_SERVICES
            and parts[3] in {"direct", "zapret", "vpn"}
        ):
            try:
                payload = start_route_job(parts[2], parts[3])
                self.send_json(202, payload)
            except (OSError, RuntimeError, ValueError) as exc:
                self.send_json(
                    409 if isinstance(exc, RuntimeError) else 400,
                    {"ok": False, "error": str(exc)},
                )
            return

        if len(parts) == 4 and parts[:3] == ["api", "history", "rollback"]:
            try:
                payload = start_history_rollback(parts[3])
                self.send_json(202, payload)
            except (FileNotFoundError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                self.send_json(
                    409 if isinstance(exc, RuntimeError) else 400,
                    {"ok": False, "error": str(exc)},
                )
            return

        if self.path == "/api/updates/check":
            try:
                self.send_json(200, check_flowseal_update())
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
                self.send_json(502, {"ok": False, "error": str(exc)})
            return

        if len(parts) == 5 and parts[:3] == ["api", "profiles", "apply"]:
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "версию нельзя применять во время подбора"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "версию нельзя применять во время переключения маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "версию нельзя применять во время диагностики"})
                return
            try:
                _path, profile = profile_version_path(parts[3], parts[4])
                payload = apply_profile(profile)
                self.send_json(200 if payload["ok"] else 500, payload)
            except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path in {"/api/import/validate", "/api/import/apply"}:
            try:
                profile = validate_report(body)
            except ValueError as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return
            if self.path.endswith("/validate"):
                self.send_json(200, {"ok": True, "profile": profile})
                return
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя применять во время подбора"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя применять во время переключения маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя применять во время диагностики"})
                return
            payload = apply_profile(profile)
            self.send_json(200 if payload["ok"] else 500, payload)
            return

        if len(parts) == 4 and parts[:3] == ["api", "import", "clear"] and parts[3] in SERVICES:
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя удалять во время подбора"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя удалять во время переключения маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "профиль нельзя удалять во время диагностики"})
                return
            payload = run_command(
                [
                    "/bin/sh",
                    str(ENGINE),
                    "--clear-imported-profile",
                    parts[3],
                    "--yes-router",
                ],
                timeout=300,
            )
            self.send_json(200 if payload["ok"] else 500, payload)
            return

        if self.path == "/api/import/rollback":
            if tuner_active():
                self.send_json(409, {"ok": False, "error": "откат нельзя выполнять во время подбора"})
                return
            if route_active():
                self.send_json(409, {"ok": False, "error": "откат нельзя выполнять во время переключения маршрута"})
                return
            if diagnostic_active():
                self.send_json(409, {"ok": False, "error": "откат нельзя выполнять во время диагностики"})
                return
            payload = run_command(
                ["/bin/sh", str(ENGINE), "--rollback-import", "--yes-router"],
                timeout=300,
            )
            self.send_json(200 if payload["ok"] else 500, payload)
            return

        self.send_json(404, {"ok": False, "error": "unknown action"})


if __name__ == "__main__" and len(sys.argv) == 6 and sys.argv[1] == "--route-job":
    raise SystemExit(run_route_job(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))


if __name__ == "__main__":
    if (
        not ENGINE.is_file()
        or not SERVICE_SWITCH.is_file()
        or not AUTOTUNER.is_file()
        or not DIAGNOSTICS.is_file()
    ):
        raise SystemExit(
            f"Project scripts are missing. Expected {ENGINE}, {SERVICE_SWITCH}, "
            f"{AUTOTUNER} and {DIAGNOSTICS}"
        )
    print(f"XKeen Control: http://{BIND_HOST}:{PORT}")
    ThreadingHTTPServer((BIND_HOST, PORT), Handler).serve_forever()
PYEOF

chmod 700 "$APP_DIR/app.py"

cat <<EOF
Установлен файл:
  $APP_DIR/app.py

Запуск в foreground:
  /opt/bin/python3 $APP_DIR/app.py

Панель:
  http://192.168.2.1:8088

Установщик не менял XKeen, routing, nfqws2 или автозапуск.
EOF

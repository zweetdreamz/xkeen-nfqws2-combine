"""Settings and router paths of the web panel, read once at import.

Every router path (/opt/...) comes from paths.root_path(), so an isolated test (KD_TEST_ROOT with
KD_ALLOW_TEST_ROOT=1) gets all of them under its own root; without KD_TEST_ROOT they are the router paths.
"""

import os
from pathlib import Path
import re
import shutil

from kdn.common import fsutil
from kdn.common import paths
from kdn.state import nfqws


PORT = int(os.environ.get("XKEEN_WEB_PORT", "8088"))
BIND_HOST = os.environ.get("XKEEN_WEB_BIND", "192.168.2.1")
# Requests served at once; open connections, also those waiting for a slot; seconds for the request line; slots the
# heavy GETs share.
MAX_HTTP_THREADS = 16
MAX_HTTP_CONNECTIONS = 64
HTTP_FIRST_LINE_TIMEOUT = 10
HTTP_HEADER_BYTES = 32 * 1024
HTTP_HEADER_LINES = 64
HTTP_HEADER_TIMEOUT = 10
HEAVY_GET_SLOTS = 2
# An empty XKEEN_PROJECT_DIR means the default. A relative one is made absolute: the tuner and diagnostics
# workers run with cwd=PROJECT_DIR, where a relative path would be resolved a second time.
PROJECT_DIR = (
    paths.project_dir() if os.environ.get(paths.PROJECT_DIR_ENV) else paths.root_path(paths.DEFAULT_PROJECT_DIR)
).absolute()
# The panel script the route worker runs as and is recognised by. app.py sets the file that actually runs;
# this value is the fallback for an import of the configuration without the entry.
ENTRY = Path(__file__).absolute().parent.parent / "app.py"
ENGINE = PROJECT_DIR / "apply-discord-nfqws2.sh"
SERVICE_SWITCH = PROJECT_DIR / "set-service-route.sh"
VPN_MANAGER_SCRIPT = PROJECT_DIR / "tools" / "router" / "vpn_node_manager.py"
AUTOTUNER = PROJECT_DIR / "tools" / "router" / "zapret_autotune_job.py"
DIAGNOSTICS = PROJECT_DIR / "tools" / "router" / "xkeen_diagnostics.py"
# Real QUIC Initial sender (autotune part); optional until it is installed.
QUIC_PROBE = PROJECT_DIR / "tools" / "router" / "quic_probe.py"
DISCORD_CACHE_HELPER = PROJECT_DIR / "tools" / "windows" / "reset-discord-cache.ps1"
BROWSER_DIAGNOSTICS = PROJECT_DIR / "tools" / "router" / "browser-diagnostics.js"
ROUTE_CHECKER = PROJECT_DIR / 'tools' / 'router' / 'route_checker.py'
DNS_TOOL = PROJECT_DIR / 'tools' / 'router' / 'dns_mode.py'
INSPECTION_STATE = paths.root_path('/opt/etc/xkeen-web/inspection-state.json')
VPN_MONITOR_CONFIG = paths.root_path('/opt/etc/xkeen-web/vpn-monitor-config.json')
VPN_MONITOR_STATE = paths.root_path('/opt/etc/xkeen-web/vpn-monitor-state.json')
NOTIFICATION_CONFIG = paths.root_path('/opt/etc/xkeen-web/notifications-config.json')
NOTIFICATION_STATE = paths.root_path('/opt/etc/xkeen-web/notifications-state.json')
INSPECTION_RUNTIME = paths.root_path('/opt/etc/xkeen-web/inspection-runtime.json')
XKEEN = shutil.which("xkeen") or str(paths.root_path("/opt/sbin/xkeen"))
XKEEN_INIT = paths.root_path('/opt/etc/init.d/S05xkeen')
IMPORTED_PROFILE_DIR = paths.root_path("/opt/etc/nfqws2/imported-profiles")
PROFILE_VERSION_DIR = paths.root_path("/opt/etc/nfqws2/profile-versions")
RECORD_TRASH_DIR = paths.root_path("/opt/etc/xkeen-web/record-trash")
NFQWS_CONFIG = paths.root_path("/opt/etc/nfqws2/nfqws2.conf")
DISCORD_LIST = paths.root_path("/opt/etc/nfqws2/lists/user.list")
# Xray uses the last *.json file of the confdir that has a routing object.
XRAY_CONFIG_DIR = paths.root_path("/opt/etc/xray/configs")
IMPORT_ROLLBACK_POINTER = paths.root_path(
    "/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr"
)
PROJECT_LOCK_DIR = paths.root_path("/opt/tmp/keenetic-discord-nfqws2.lock")
# Temporary files the panel hands to the engine (profile imports).
IMPORT_STAGING_DIR = paths.root_path("/opt/tmp")
TUNER_JOB_DIR = paths.root_path("/opt/tmp/xkeen-zapret-tuner")
TUNER_STATE = TUNER_JOB_DIR / "state.json"
TUNER_RESULT = TUNER_JOB_DIR / "result-report.json"
TUNER_VERDICT = TUNER_JOB_DIR / "verdict.txt"
TUNER_PID = TUNER_JOB_DIR / "panel-launch.pid"
DIAGNOSTIC_JOB_DIR = paths.root_path("/opt/tmp/xkeen-diagnostics")
DIAGNOSTIC_STATE = DIAGNOSTIC_JOB_DIR / "state.json"
DIAGNOSTIC_PID = DIAGNOSTIC_JOB_DIR / "panel-launch.pid"
DIAGNOSTIC_LOG = DIAGNOSTIC_JOB_DIR / "process.log"
ROUTE_JOB_DIR = paths.root_path("/opt/tmp/xkeen-route-switch")
ROUTE_STATE = ROUTE_JOB_DIR / "state.json"
ROUTE_PID = ROUTE_JOB_DIR / "worker.pid"
ROUTE_LOG = ROUTE_JOB_DIR / "process.log"
ROUTE_APPLY_LOG = ROUTE_JOB_DIR / "apply.log"
ROUTE_HISTORY_DIR = paths.root_path("/opt/etc/xkeen-web/history")
SNAPSHOT_DIR = paths.root_path("/opt/etc/keenetic-discord-nfqws2/snapshots")
FLOWSEAL_UPDATE_STATE = paths.root_path("/opt/etc/xkeen-web/flowseal-update.json")
# Learned by zapret_autotune_job.py after a user-confirmed Discord Voice check.
VOICE_ENDPOINT_FILE = paths.root_path("/opt/etc/xkeen-web/discord-voice-endpoint.json")
FLOWSEAL_SOURCE_CACHE = paths.root_path("/opt/etc/xkeen-web/flowseal-sources.json")
AUTOMATION_CONFIG = paths.root_path("/opt/etc/xkeen-web/automation-config.json")
AUTOMATION_STATE = paths.root_path("/opt/etc/xkeen-web/automation-state.json")
LOG_FILE = paths.root_path("/opt/var/log/xkeen-web.log")
LOG_MAX_BYTES = 1024 * 1024
LOG_BACKUPS = 3
MAX_REPORT_BYTES = fsutil.MAX_JSON_BYTES
MAX_HISTORY_ITEMS = 200
# Services with an nfqws2 profile that can be tuned and imported.
SERVICES = ("youtube", "discord-tcp", "discord-voice")
# "discord" is accepted as a shorthand that switches Discord TCP and Voice together.
ROUTE_REQUEST_SERVICES = nfqws.ROUTE_SERVICES + ("discord",)
TELEGRAM_WS_PIDFILE = paths.root_path("/opt/var/run/kdn-telegram-ws.pid")
TELEGRAM_WS_PORT = 18443
# Same pattern as zapret_tuner.SOURCE_NAME_RE: one Flowseal general*.bat file.
SOURCE_FILE_NAME = re.compile(r"general[\w ()+.,-]*\.bat", re.IGNORECASE)

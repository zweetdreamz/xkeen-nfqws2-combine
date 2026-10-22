#!/usr/bin/env python3
"""Read-only XKeen/nfqws2 diagnostics adapted from Flowseal test tools.

The module never changes routing, firewall, XKeen or nfqws2 configuration.
It writes only bounded job state below /opt/tmp/xkeen-diagnostics.

The web panel (xkeen_control_script.sh) loads this file for its
post-apply check, so the invariant helpers below (nfqws2 port coverage,
NFQUEUE rules, Xray routing file and outbounds, the Telegram WS relay and
the QUIC probe) are shared by both and take their paths as arguments.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import queue
from pathlib import Path
import re
import secrets
import shutil
import signal
import ssl
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[2]
TEST_ROOT = os.environ.get("KD_DIAGNOSTICS_TEST_ROOT", "")
JOB_DIR_LOGICAL = "/opt/tmp/xkeen-diagnostics"
NFQWS_CONFIG_LOGICAL = "/opt/etc/nfqws2/nfqws2.conf"
DISCORD_LIST_LOGICAL = "/opt/etc/nfqws2/lists/user.list"
YOUTUBE_LIST_LOGICAL = "/opt/etc/nfqws2/lists/youtube.list"
XRAY_CONFIG_DIR_LOGICAL = "/opt/etc/xray/configs"
PROJECT_LOCK_LOGICAL = "/opt/tmp/keenetic-discord-nfqws2.lock"
TELEGRAM_WS_PIDFILE_LOGICAL = "/opt/var/run/kdn-telegram-ws.pid"
NFQWS_PIDFILE_LOGICAL = "/opt/var/run/nfqws2.pid"
TELEGRAM_WS_PORT = 18443
ENGINE_PATH = PROJECT_DIR / "apply-discord-nfqws2.sh"
# Written by the autotune part (contract item 2); optional until installed.
QUIC_PROBE_PATH = PROJECT_DIR / "tools" / "router" / "quic_probe.py"
QUIC_PROBE_HOST = "www.youtube.com"
# The hostlist path inside nfqws2 arguments is always the router path.
YOUTUBE_HOSTLIST_ARG = "--hostlist=/opt/etc/nfqws2/lists/youtube.list"
VOICE_L7 = "--filter-l7=stun,discord"
# Other DPI bypass tools for a router (process comm names; Windows-only
# tools such as winws or GoodbyeDPI cannot run on Keenetic).
RIVAL_PROCESSES = {
    "nfqws": "zapret (nfqws)",
    "tpws": "zapret (tpws)",
    "youtubeUnblock": "youtubeUnblock",
    "b4": "b4",
    "ciadpi": "byedpi (ciadpi)",
    "byedpi": "byedpi",
    "dpitunnel": "DPITunnel",
    "dpitunnel-cli": "DPITunnel",
    "spoofdpi": "SpoofDPI",
}
# DoH resolvers by pinned IP (RFC 8484 wire format): the answer is compared
# with the router's own resolver to spot DNS substitution.
DOH_RESOLVERS = (
    ("Yandex", "common.dot.dns.yandex.net", "77.88.8.8"),
    ("Google", "dns.google", "8.8.8.8"),
)
# Unblocked SNI used to tell an SNI block from an IP block.
SNI_CONTROL_HOST = "ya.ru"
SNI_CHECK_HOSTS = ("discord.com", "www.youtube.com")
STATE_LIMIT = 512 * 1024
STANDARD_WORKERS = 4
DPI_WORKERS = 3
STANDARD_TIMEOUT = 5
DPI_TIMEOUT = 6
DPI_BYTES = 65536

# Flowseal utils/targets.txt at commit 176f56dc3f11ce5915c26abcdde903f93d835b64.
STANDARD_TARGETS = (
    ("DiscordMain", "https://discord.com"),
    ("DiscordGateway", "https://gateway.discord.gg"),
    ("DiscordCDN", "https://cdn.discordapp.com"),
    ("DiscordUpdates", "https://updates.discord.com"),
    ("YouTubeWeb", "https://www.youtube.com"),
    ("YouTubeShort", "https://youtu.be"),
    ("YouTubeImage", "https://i.ytimg.com"),
    ("YouTubeVideoRedirect", "https://redirector.googlevideo.com"),
    ("GoogleMain", "https://www.google.com"),
    ("GoogleGstatic", "https://www.gstatic.com"),
    ("CloudflareWeb", "https://www.cloudflare.com"),
    ("CloudflareCDN", "https://cdnjs.cloudflare.com"),
    ("DiscordAPI", "https://discord.com/api/v10/gateway"),
    ("YouTube204", "https://www.youtube.com/generate_204"),
    ("GooglevideoMapping", "https://redirector.googlevideo.com/report_mapping"),
    ("CloudflareDNS1111", "PING:1.1.1.1"),
    ("CloudflareDNS1001", "PING:1.0.0.1"),
    ("GoogleDNS8888", "PING:8.8.8.8"),
    ("GoogleDNS8844", "PING:8.8.4.4"),
)

# A bounded provider-diverse subset of hyperion-cs/dpi-checkers suite.v2.json.
# Running all upstream endpoints on a small router would add load without
# improving the first-line diagnosis much.
DPI_TARGETS = (
    ("US.GH-HPRN", "Self check", "hyperion-cs.github.io"),
    ("PL.AKM-01", "Akamai", "www.mobil.com.se"),
    ("DE.AWS-01", "AWS", "amplifon.com"),
    ("US.CDN77-01", "CDN77", "cdn.eso.org"),
    ("CA.CF-01", "Cloudflare", "go.coveo.com"),
    ("FR.CNTB-01", "Contabo", "antoniotartaglia.it"),
    ("DE.DO-01", "DigitalOcean", "ui-arts.com"),
    ("CA.FST-01", "Fastly", "ssl.p.jwpcdn.com"),
    ("LU.GCORE-01", "Gcore", "gcore.com"),
    ("US.GC-01", "Google Cloud", "api.usercentrics.eu"),
    ("DE.HE-01", "Hetzner", "king.hr"),
    ("FR.OVH-01", "OVH", "www.adwin.fr"),
)

CANCELLED = threading.Event()


def root_path(logical: str) -> Path:
    if not TEST_ROOT:
        return Path(logical)
    return Path(TEST_ROOT) / logical.lstrip("/")


JOB_DIR = root_path(JOB_DIR_LOGICAL)
STATE_PATH = JOB_DIR / "state.json"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > STATE_LIMIT:
        raise RuntimeError("diagnostic state exceeds 512 KiB")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class StateWriter:
    def __init__(self, initial: dict[str, Any]):
        self.payload = dict(initial)
        self.lock = threading.Lock()
        atomic_json(STATE_PATH, self.payload)

    def write(self, **changes: Any) -> None:
        with self.lock:
            self.payload.update(changes)
            atomic_json(STATE_PATH, self.payload)


def command_path(name: str) -> str:
    return shutil.which(name) or name


def run(command: list[str], timeout: int, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    if CANCELLED.is_set():
        raise InterruptedError("diagnostics cancelled")
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env={**os.environ, "PATH": "/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin", **(extra_env or {})},
        )
        output = completed.stdout.decode("utf-8", errors="replace").strip()
        return {"ok": completed.returncode == 0, "code": completed.returncode, "output": output[-12000:]}
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", errors="replace").strip()
        return {"ok": False, "code": 124, "output": ("timeout\n" + output).strip()[-12000:]}
    except OSError as exc:
        return {"ok": False, "code": 127, "output": str(exc)}


def safe_read(path: Path, maximum: int = 1024 * 1024) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError(f"unsafe file: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def resolve_public(host: str) -> tuple[bool, str]:
    answers: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            answers.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            answers.put(exc)

    # libc DNS lookup has no per-call timeout. A daemon thread bounds our wait
    # and cannot keep this short-lived worker alive after cancellation.
    threading.Thread(target=resolve, daemon=True).start()
    try:
        answer = answers.get(timeout=4)
    except queue.Empty:
        return False, "DNS timeout (4s)"
    if isinstance(answer, OSError):
        return False, str(answer)
    addresses = sorted({item[4][0] for item in answer})
    if not addresses:
        return False, "no addresses"
    suspicious = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
            if not address.is_global:
                suspicious.append(value)
        except ValueError:
            suspicious.append(value)
    if suspicious:
        return False, "private/unexpected DNS answer: " + ", ".join(suspicious)
    return True, ", ".join(addresses[:4])


def make_check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail[:1000]}


ROUTE_VALUES = {"direct", "zapret", "vless"}
# "zapret" is still parsed from old Telegram headers but is no longer a valid mode.
TELEGRAM_ROUTE_VALUES = ROUTE_VALUES | {"ws", "unmanaged"}


def parse_active_routes(text: str) -> dict[str, str] | None:
    """Read the "# Active routes:" line written by apply-discord-nfqws2.sh.

    Returns {"discord-tcp", "discord-voice", "youtube", "telegram"} -> route,
    or None when the line is missing or malformed. The legacy line
    "Discord=X, YouTube=Y." written before the TCP/Voice split applies X to
    both Discord routes. Lines without Telegram predate it: "unmanaged".
    """
    match = re.search(r"^# Active routes: (.+)\.$", text, re.MULTILINE)
    if not match:
        return None
    values = {}
    for pair in match.group(1).split(", "):
        key, separator, value = pair.partition("=")
        allowed = TELEGRAM_ROUTE_VALUES if key == "Telegram" else ROUTE_VALUES
        if not separator or value not in allowed:
            return None
        values[key] = value
    telegram = values.pop("Telegram", "unmanaged")
    if set(values) == {"DiscordTCP", "DiscordVoice", "YouTube"}:
        return {
            "discord-tcp": values["DiscordTCP"],
            "discord-voice": values["DiscordVoice"],
            "youtube": values["YouTube"],
            "telegram": telegram,
        }
    if set(values) == {"Discord", "YouTube"}:
        return {
            "discord-tcp": values["Discord"],
            "discord-voice": values["Discord"],
            "youtube": values["YouTube"],
            "telegram": telegram,
        }
    return None


def telegram_route(text: str) -> str:
    """Return the recorded Telegram route ("unmanaged" when absent) or "unknown"."""
    routes = parse_active_routes(text)
    return routes["telegram"] if routes else "unknown"


def parse_routes(text: str) -> tuple[str, str, str]:
    """Return (Discord TCP, Discord Voice, YouTube) routes or "unknown"."""
    routes = parse_active_routes(text)
    if routes is None:
        return ("unknown", "unknown", "unknown")
    return (routes["discord-tcp"], routes["discord-voice"], routes["youtube"])


def process_ids(name: str) -> list[int]:
    result = run([command_path("pidof"), name], 5)
    if not result["ok"]:
        return []
    return [int(value) for value in result["output"].split() if value.isdigit()]


def strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments outside strings (Xray accepts JSONC)."""
    result: list[str] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            result.append(text[index:end + 1])
            index = end + 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            result.append(" ")
            index = length if end < 0 else end + 2
        else:
            result.append(char)
            index += 1
    return "".join(result)


def xray_upgrade_findings(files: dict[str, str]) -> list[str]:
    """Settings that Xray 26.10+ refuses to load, by config file name.

    - any outbound "proxySettings" (removed; sockopt.dialerProxy replaces it);
    - "addressPortStrategy" in the sockopt of a freedom outbound.
    """
    findings = []
    for name, raw_text in sorted(files.items()):
        text = strip_json_comments(raw_text)
        if re.search(r'"proxySettings"\s*:', text):
            findings.append(f"{name}: proxySettings → sockopt.dialerProxy")
        try:
            data = json.loads(text)
        except ValueError:
            continue
        outbounds = data.get("outbounds", []) if isinstance(data, dict) else []
        for outbound in outbounds if isinstance(outbounds, list) else []:
            if not isinstance(outbound, dict) or outbound.get("protocol") != "freedom":
                continue
            stream = outbound.get("streamSettings")
            sockopt = stream.get("sockopt") if isinstance(stream, dict) else None
            if isinstance(sockopt, dict) and "addressPortStrategy" in sockopt:
                findings.append(f"{name}: freedom {outbound.get('tag', '?')} sockopt.addressPortStrategy")
    return findings


def voice_profile_active(config: str) -> bool:
    """True when nfqws2 has a Discord Voice profile (built-in or imported).

    Every Voice profile the engine writes or accepts selects --filter-l7=stun,discord.
    """
    return VOICE_L7 in config


# ---------------------------------------------------------------------------
# Port ranges. nfqws2 filters write ranges with "-", TCP_PORTS/UDP_PORTS and
# iptables multiport with ":"; both are compared as merged numeric ranges.

def merge_ports(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def parse_ports(spec: str) -> list[tuple[int, int]]:
    """Parse "80,443", "19294-19344" or "19294:19344" into merged ranges."""
    ranges = []
    for item in spec.replace(" ", "").split(","):
        if not item:
            continue
        left, separator, right = item.replace(":", "-").partition("-")
        if not left.isdigit() or (separator and not right.isdigit()):
            raise ValueError(f"некорректный порт: {item}")
        low = int(left)
        high = int(right) if separator else low
        if not 1 <= low <= high <= 65535:
            raise ValueError(f"некорректный порт: {item}")
        ranges.append((low, high))
    return merge_ports(ranges)


def missing_ports(need: list[tuple[int, int]], have: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Parts of the ranges in need that no range in have covers."""
    result = []
    have = merge_ports(have)
    for low, high in merge_ports(need):
        cursor = low
        for have_low, have_high in have:
            if have_high < cursor:
                continue
            if have_low > high:
                break
            if have_low > cursor:
                result.append((cursor, have_low - 1))
            cursor = max(cursor, have_high + 1)
            if cursor > high:
                break
        if cursor <= high:
            result.append((cursor, high))
    return result


def format_ports(ranges: list[tuple[int, int]]) -> str:
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges) or "—"


# ---------------------------------------------------------------------------
# nfqws2.conf is a shell file sourced by the nfqws2-keenetic init script.

_SHELL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SHELL_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
_SHELL_IF = re.compile(r'if\s+\[\s+(-[nz])\s+"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"\s+\]\s*;?\s*(?:then)?$')


def parse_shell_values(text: str) -> dict[str, str]:
    """Final values of the assignments in a shell config such as nfqws2.conf.

    Only what nfqws2.conf uses is understood: NAME=value with double, single
    or no quotes (values may span lines), $NAME and ${NAME} expansion, and
    `if [ -n|-z "$NAME" ]; then ... else ... fi`. Nothing is executed.
    """
    values: dict[str, str] = {}
    conditions: list[bool] = []
    length = len(text)

    def expand(position: int) -> tuple[str, int]:
        if text.startswith("${", position):
            end = text.find("}", position + 2)
            if end < 0 or not _SHELL_NAME.fullmatch(text[position + 2:end]):
                return "$", position + 1
            return values.get(text[position + 2:end], ""), end + 1
        match = _SHELL_NAME.match(text, position + 1)
        if not match:
            return "$", position + 1
        return values.get(match.group(0), ""), match.end()

    def word(position: int) -> tuple[str, int]:
        parts: list[str] = []
        while position < length and text[position] not in " \t\r\n;":
            char = text[position]
            if char == '"':
                position += 1
                while position < length and text[position] != '"':
                    char = text[position]
                    if char == "\\" and position + 1 < length:
                        following = text[position + 1]
                        if following != "\n":
                            parts.append(following if following in '$"\\`' else char + following)
                        position += 2
                    elif char == "$":
                        value, position = expand(position)
                        parts.append(value)
                    else:
                        parts.append(char)
                        position += 1
                position += 1
            elif char == "'":
                end = text.find("'", position + 1)
                end = length if end < 0 else end
                parts.append(text[position + 1:end])
                position = end + 1
            elif char == "\\" and position + 1 < length:
                if text[position + 1] != "\n":
                    parts.append(text[position + 1])
                position += 2
            elif char == "$":
                value, position = expand(position)
                parts.append(value)
            else:
                parts.append(char)
                position += 1
        return "".join(parts), position

    index = 0
    while index < length:
        line_end = text.find("\n", index)
        line_end = length if line_end < 0 else line_end
        raw_line = text[index:line_end]
        line = raw_line.strip()
        start = index + len(raw_line) - len(raw_line.lstrip())
        next_index = line_end + 1
        if line.startswith("if "):
            match = _SHELL_IF.match(line)
            if match:
                current = values.get(match.group(2), "")
                conditions.append(bool(current) if match.group(1) == "-n" else not current)
            else:
                conditions.append(True)
        elif line == "else" and conditions:
            conditions[-1] = not conditions[-1]
        elif line == "fi" and conditions:
            conditions.pop()
        elif line and not line.startswith("#"):
            match = _SHELL_ASSIGN.match(text, start)
            if match:
                value, end = word(match.end())
                if all(conditions):
                    values[match.group(1)] = value
                newline = text.find("\n", end)
                next_index = length if newline < 0 else newline + 1
        index = next_index
    return values


def compose_profiles(values: dict[str, str]) -> list[list[str]]:
    """nfqws2 profiles in the order the nfqws2-keenetic init (_startup_args) builds them."""
    profiles: list[list[str]] = []

    def tokens(name: str) -> list[str]:
        return values.get(name, "").split()

    def add(arguments: list[str]) -> None:
        current: list[str] = []
        for token in arguments:
            if token == "--new":
                if current:
                    profiles.append(current)
                current = []
            else:
                current.append(token)
        if current:
            profiles.append(current)

    add(tokens("NFQWS_ARGS_CUSTOM"))
    add(tokens("NFQWS_ARGS_UDP"))
    if tokens("NFQWS_ARGS_QUIC"):
        if tokens("NFQWS_ARGS_IPSET"):
            add(tokens("NFQWS_ARGS_QUIC") + tokens("NFQWS_ARGS_IPSET"))
        add(tokens("NFQWS_ARGS_QUIC") + tokens("NFQWS_EXTRA_ARGS"))
    if tokens("NFQWS_ARGS_IPSET"):
        add(tokens("NFQWS_ARGS") + tokens("NFQWS_ARGS_IPSET"))
    add(tokens("NFQWS_ARGS") + tokens("NFQWS_EXTRA_ARGS"))
    return profiles


def option_values(profile: list[str], option: str) -> list[str]:
    prefix = f"--{option}="
    return [token[len(prefix):] for token in profile if token.startswith(prefix)]


def profile_ports(profile: list[str], proto: str) -> list[tuple[int, int]]:
    return merge_ports([item for spec in option_values(profile, f"filter-{proto}") for item in parse_ports(spec)])


def profile_label(profile: list[str]) -> str:
    lists = [Path(value).name for option in ("hostlist", "ipset") for value in option_values(profile, option)]
    if lists:
        return ", ".join(lists)
    l7 = option_values(profile, "filter-l7")
    return "l7=" + ",".join(l7) if l7 else "без hostlist"


def profile_matches_udp_443(profile: list[str]) -> bool:
    if option_values(profile, "filter-udp"):
        return not missing_ports([(443, 443)], profile_ports(profile, "udp"))
    # A profile without any port filter matches every port of both protocols.
    return not option_values(profile, "filter-tcp")


CONFIG_CHECK_LABELS = {
    "port-coverage": "nfqws2: порты профилей в очереди",
    "unhandled-ports": "nfqws2: порты без профиля",
    "listless-profile": "nfqws2: профили без hostlist",
    "empty-hostlist": "nfqws2: пустые hostlist",
    "legacy-blob": "nfqws2: fake без blob",
    "compose": "nfqws2: сборка профилей",
    "voice-range": "nfqws2: диапазон Discord Voice",
    "read": "nfqws2: чтение конфига",
}
CHECK_LINE = re.compile(r"^CHECK\|(ok|warn|error)\|([A-Za-z0-9_.-]+)\|(.*)$", re.MULTILINE)


def config_check_label(name: str) -> str:
    return CONFIG_CHECK_LABELS.get(name, f"nfqws2: {name}")


def static_port_checks(values: dict[str, str]) -> list[dict[str, str]]:
    """Built-in fallback for the engine's port-coverage and unhandled-ports checks."""
    try:
        queued = {"tcp": parse_ports(values.get("TCP_PORTS", "")), "udp": parse_ports(values.get("UDP_PORTS", ""))}
        profiles = compose_profiles(values)
        problems = []
        handled: dict[str, list[tuple[int, int]]] = {"tcp": [], "udp": []}
        catch_all = False
        for number, profile in enumerate(profiles, 1):
            desync = bool(option_values(profile, "lua-desync"))
            filters = {proto: profile_ports(profile, proto) for proto in ("tcp", "udp")}
            if desync and not filters["tcp"] and not filters["udp"]:
                catch_all = True
            for proto in ("tcp", "udp"):
                lack = missing_ports(filters[proto], queued[proto])
                if lack:
                    problems.append(
                        f"профиль {number} ({profile_label(profile)}): {proto.upper()} {format_ports(lack)} "
                        f"нет в {proto.upper()}_PORTS"
                    )
                if desync:
                    handled[proto].extend(filters[proto])
    except ValueError as exc:
        return [make_check(config_check_label("port-coverage"), "error", f"nfqws2.conf не разобран: {exc}")]
    checks = [make_check(
        config_check_label("port-coverage"),
        "error" if problems else "ok",
        "; ".join(problems) + " — эти пакеты не попадают в nfqws2"
        if problems
        else f"TCP_PORTS={format_ports(queued['tcp'])}, UDP_PORTS={format_ports(queued['udp'])} "
        f"покрывают фильтры всех профилей ({len(profiles)})",
    )]
    unhandled = [] if catch_all else [
        f"{proto.upper()} {format_ports(lack)}"
        for proto in ("tcp", "udp")
        if (lack := missing_ports(queued[proto], handled[proto]))
    ]
    checks.append(make_check(
        config_check_label("unhandled-ports"),
        "warn" if unhandled else "ok",
        "в очередь идут, но ни один профиль их не обрабатывает: " + "; ".join(unhandled)
        if unhandled
        else "каждый порт очереди обрабатывается профилем",
    ))
    return checks


def youtube_quic_static_check(text: str, values: dict[str, str]) -> dict[str, str] | None:
    """YouTube=zapret needs UDP 443 queued and a youtube.list QUIC profile that nothing shadows."""
    routes = parse_active_routes(text)
    if not routes or routes["youtube"] != "zapret":
        return None
    name = "YouTube QUIC (UDP 443)"
    try:
        udp = parse_ports(values.get("UDP_PORTS", ""))
        profiles = compose_profiles(values)
    except ValueError as exc:
        return make_check(name, "error", f"nfqws2.conf не разобран: {exc}")
    if missing_ports([(443, 443)], udp):
        return make_check(
            name,
            "error",
            f"UDP_PORTS={format_ports(udp)} без 443: QUIC YouTube не попадает в nfqws2, "
            "приложение YouTube (QUIC/HTTP3) может не загружаться",
        )
    for number, profile in enumerate(profiles, 1):
        try:
            matches = profile_matches_udp_443(profile)
        except ValueError:
            continue
        if not matches:
            continue
        if YOUTUBE_HOSTLIST_ARG in profile and option_values(profile, "lua-desync"):
            return make_check(name, "ok", f"UDP 443 в очереди; профиль {number} (youtube.list) обрабатывает QUIC")
        l7 = {item for value in option_values(profile, "filter-l7") for item in value.split(",")}
        listed = option_values(profile, "hostlist") or option_values(profile, "ipset")
        if not listed and (not l7 or "quic" in l7):
            return make_check(
                name,
                "error",
                f"профиль {number} ({profile_label(profile)}) перехватывает UDP 443 раньше профиля YouTube",
            )
    return make_check(name, "error", "нет профиля --filter-udp=443 с youtube.list: QUIC YouTube не обрабатывается")


def config_invariant_checks(text: str, runner: Any, engine: Path = ENGINE_PATH) -> list[dict[str, str]]:
    """nfqws2.conf invariants: the engine's --check-config, or a built-in fallback.

    runner(command, timeout) returns {"ok", "code", "output"}. Every CHECK line
    of the engine becomes one check. An engine without --check-config (an
    older release) answers with usage and no CHECK lines; then the static
    port checks of this module run instead. The YouTube QUIC check always runs.
    """
    values = parse_shell_values(text)
    checks: list[dict[str, str]] = []
    lines: list[tuple[str, str, str]] = []
    reason = "движок не найден"
    if engine.is_file():
        result = runner(["/bin/sh", str(engine), "--check-config"], 90)
        output = result.get("output", "") or ""
        lines = CHECK_LINE.findall(output)
        if "unknown argument" in output:
            reason = "движок без --check-config"
        else:
            reason = "движок не выполнил проверку: " + (output.strip().splitlines() or ["нет вывода"])[-1][:200]
    if lines:
        for status, name, detail in lines:
            checks.append(make_check(config_check_label(name), status, detail.strip() or "—"))
    else:
        for check in static_port_checks(values):
            check["detail"] = (check["detail"] + f" · встроенная проверка ({reason})")[:1000]
            checks.append(check)
    quic = youtube_quic_static_check(text, values)
    if quic:
        checks.append(quic)
    return checks


# ---------------------------------------------------------------------------
# Live firewall state built by the nfqws2-keenetic init from nfqws2.conf.

_SAVE_RULE = re.compile(r"^(?:\[(\d+):(\d+)\]\s+)?-A\s+(\S+)\s+(.*)$")


def nfqueue_rules(save_text: str, queue: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """NFQUEUE rules of nfqws_post/nfqws_pre and the jump counts, from iptables-save [-c]."""
    rules: list[dict[str, Any]] = []
    jumps = {"POSTROUTING": 0, "PREROUTING": 0}
    target = re.compile(r"-j NFQUEUE --queue-num " + re.escape(queue) + r"(?:\s|$)")
    for line in save_text.splitlines():
        match = _SAVE_RULE.match(line.strip())
        if not match:
            continue
        chain, spec = match.group(3), match.group(4).strip()
        if (chain, spec) in {("POSTROUTING", "-j nfqws_post"), ("PREROUTING", "-j nfqws_pre")}:
            jumps[chain] += 1
            continue
        if chain not in {"nfqws_post", "nfqws_pre"} or not target.search(spec):
            continue
        proto = re.search(r"-p (tcp|udp)\b", spec)
        ports = re.search(r"--(?:dports|sports|dport|sport) (\S+)", spec)
        if not proto or not ports:
            continue
        try:
            ranges = parse_ports(ports.group(1))
        except ValueError:
            continue
        rules.append({
            "chain": chain,
            "proto": proto.group(1),
            "ports": ranges,
            "packets": int(match.group(1)) if match.group(1) is not None else None,
        })
    return rules, jumps


def nfqueue_live_checks(
    save_text: str, values: dict[str, str], family: str = "IPv4", counters: bool = True,
) -> list[dict[str, str]]:
    """Compare the live NFQUEUE rules with TCP_PORTS/UDP_PORTS of nfqws2.conf.

    The init rebuilds the rules from the config on every nfqws2 start, so a
    mismatch means nfqws2 was not restarted after nfqws2.conf changed.
    """
    queue = values.get("NFQUEUE_NUM") or "300"
    prefix = "NFQUEUE" if family == "IPv4" else f"NFQUEUE {family}"
    rules, jumps = nfqueue_rules(save_text, queue)
    checks = []
    try:
        queued = {"tcp": parse_ports(values.get("TCP_PORTS", "")), "udp": parse_ports(values.get("UDP_PORTS", ""))}
    except ValueError as exc:
        return [make_check(f"{prefix}: порты", "error", f"TCP_PORTS/UDP_PORTS не разобраны: {exc}")]
    problems = []
    for chain in ("nfqws_post", "nfqws_pre"):
        for proto in ("udp", "tcp"):
            live = [item for rule in rules if rule["chain"] == chain and rule["proto"] == proto for item in rule["ports"]]
            lack = missing_ports(queued[proto], live)
            if lack:
                problems.append(f"{chain} {proto.upper()} без {format_ports(lack)}")
    checks.append(make_check(
        f"{prefix}: порты",
        "error" if problems else "ok",
        "; ".join(problems) + f" из {'/'.join(sorted({p.split()[1] + '_PORTS' for p in problems}))} nfqws2.conf: "
        "правила очереди устарели (nfqws2 не перезапущен после изменения конфига) или не созданы"
        if problems
        else f"очередь {queue}: TCP {format_ports(queued['tcp'])}, UDP {format_ports(queued['udp'])} как в nfqws2.conf",
    ))
    wrong = {chain: count for chain, count in jumps.items() if count != 1}
    target = {"POSTROUTING": "nfqws_post", "PREROUTING": "nfqws_pre"}
    checks.append(make_check(
        f"{prefix}: переходы",
        "error" if 0 in wrong.values() else "warn" if wrong else "ok",
        "; ".join(f"{chain} → {target[chain]}: {count} раз(а), нужен ровно один" for chain, count in wrong.items())
        if wrong
        else "POSTROUTING → nfqws_post и PREROUTING → nfqws_pre ровно по одному разу",
    ))
    if counters:
        parts = []
        for chain, short in (("nfqws_post", "исх."), ("nfqws_pre", "ответы")):
            for proto in ("udp", "tcp"):
                selected = [rule for rule in rules if rule["chain"] == chain and rule["proto"] == proto]
                if not selected:
                    continue
                ports = merge_ports([item for rule in selected for item in rule["ports"]])
                packets = [rule["packets"] for rule in selected]
                count = "?" if None in packets else str(sum(packets))
                parts.append(f"{short} {proto.upper()} {format_ports(ports)}: {count} пак.")
        checks.append(make_check(
            f"{prefix}: счётчики",
            "ok" if parts else "error",
            "; ".join(parts) if parts else f"правил NFQUEUE {queue} в nfqws_post/nfqws_pre нет",
        ))
    return checks


def ipv6_route_check(route_output: str, values: dict[str, str]) -> dict[str, str]:
    """Warn when IPv6 leaves through the WAN while nfqws2 handles only IPv4."""
    name = "IPv6 и nfqws2"
    enabled = values.get("IPV6_ENABLED", "0").strip() not in {"", "0"}
    interfaces = values.get("ISP_INTERFACE", "").split()
    devices = [
        match.group(1)
        for line in route_output.splitlines()
        if line.strip().startswith("default") and (match := re.search(r"\bdev (\S+)", line))
    ]
    wan = [device for device in devices if not interfaces or device in interfaces]
    if enabled:
        return make_check(name, "ok", "IPV6_ENABLED=1: nfqws2 обрабатывает и IPv6")
    if wan:
        return make_check(
            name,
            "warn",
            f"IPv6 default route через {', '.join(sorted(set(wan)))}, а IPV6_ENABLED=0: соединения по IPv6 "
            "(приложение YouTube на iPhone его предпочитает) идут мимо nfqws2",
        )
    return make_check(name, "ok", "IPv6 default route через WAN нет; nfqws2 работает по IPv4")


# ---------------------------------------------------------------------------
# Xray: the routing file Xray really uses, the outbounds, and the per-service
# predicates of the engine's --status (status_report in apply-discord-nfqws2.sh).

def read_xray_files(config_dir: Path) -> list[tuple[Path, Any]]:
    """Parsed *.json (JSONC) files of the confdir in Xray's (filename) order; None when unreadable."""
    result = []
    try:
        paths = sorted(config_dir.glob("*.json"))
    except OSError:
        return result
    for path in paths:
        try:
            data = json.loads(strip_json_comments(safe_read(path)))
        except (OSError, ValueError):
            data = None
        result.append((path, data))
    return result


def find_xray_routing_file(config_dir: Path, files: list[tuple[Path, Any]] | None = None) -> tuple[Path, dict] | None:
    """The last confdir file with a routing object, as the engine's find_xray_routing_file.

    Xray reads confdir files in filename order and a later routing object
    replaces an earlier one.
    """
    active = None
    for path, data in read_xray_files(config_dir) if files is None else files:
        if isinstance(data, dict) and isinstance(data.get("routing"), dict):
            active = (path, data["routing"])
    return active


def xray_outbounds(files: list[tuple[Path, Any]]) -> dict[str, dict]:
    outbounds: dict[str, dict] = {}
    for _path, data in files:
        items = data.get("outbounds") if isinstance(data, dict) else None
        for outbound in items if isinstance(items, list) else []:
            if isinstance(outbound, dict) and isinstance(outbound.get("tag"), str):
                outbounds[outbound["tag"]] = outbound
    return outbounds


def _domain_count(rule: dict) -> int:
    domain = rule.get("domain")
    return len(domain) if isinstance(domain, (list, str)) else 0


def rule_port_ranges(rules: list[dict]) -> list[tuple[int, int]]:
    """Union of the ports a set of Xray rules match; a rule without "port" matches all."""
    ranges: list[tuple[int, int]] = []
    for rule in rules:
        port = rule.get("port")
        if port is None:
            return [(1, 65535)]
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            ranges.append((port, port))
        elif isinstance(port, str):
            try:
                ranges.extend(parse_ports(port))
            except ValueError:
                continue
    return merge_ports(ranges)


def telegram_xray_route(rules: list[dict]) -> str:
    outbounds = [
        rule.get("outboundTag") for rule in rules
        if str(rule.get("ruleTag", "")).startswith("kdn-telegram")
    ]
    if not outbounds:
        return "unmanaged"
    if "telegram-ws" in outbounds:
        return "ws"
    return "direct" if outbounds[0] == "telegram-direct" else "vless"


def xray_service_rules(rules: Any) -> dict[str, Any]:
    """Which managed services the routing sends to their -direct outbound (engine --status predicates)."""
    items = [rule for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []
    voice = [
        rule for rule in items
        if rule.get("outboundTag") == "discord-direct" and rule.get("network") == "udp" and _domain_count(rule) == 0
    ]
    return {
        "discord-tcp": any(rule.get("outboundTag") == "discord-direct" and _domain_count(rule) > 0 for rule in items),
        "discord-voice": bool(voice),
        "youtube": any(rule.get("outboundTag") == "youtube-direct" for rule in items),
        "voice-ports": rule_port_ranges(voice),
        "telegram": telegram_xray_route(items),
        "tags": {rule.get("outboundTag") for rule in items if isinstance(rule.get("outboundTag"), str)},
    }


def inferred_route(present: bool, recorded: str) -> str:
    """The route --status reports for a service, given its -direct rule."""
    if not present:
        return "vless"
    return recorded if recorded in {"zapret", "direct"} else "direct"


def voice_filter_ports(config: str) -> list[tuple[int, int]]:
    """UDP ports of the Discord Voice profile without 443 (that is the QUIC port, not Voice)."""
    try:
        profiles = compose_profiles(parse_shell_values(config))
        ports = [item for profile in profiles if VOICE_L7 in profile for item in profile_ports(profile, "udp")]
    except ValueError:
        return []
    return missing_ports(ports, [(443, 443)])


def outbound_checks(rules: Any, routing: dict, outbounds: dict[str, dict], telegram_port: int = TELEGRAM_WS_PORT) -> dict[str, str]:
    """Project outbounds used by the routing must exist and go straight out.

    Xray accepts a rule that points to a missing tag and then sends the
    traffic to the first outbound, which in XKeen setups is the VPN.
    """
    items = [rule for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []
    used = {rule.get("outboundTag") for rule in items if isinstance(rule.get("outboundTag"), str)}
    problems = []
    for tag in sorted(used & {"discord-direct", "youtube-direct", "telegram-direct", "telegram-ws"}):
        outbound = outbounds.get(tag)
        if outbound is None:
            problems.append(f"{tag}: outbound не найден — Xray отправит трафик в первый outbound (обычно VPN)")
            continue
        if outbound.get("protocol") != "freedom":
            problems.append(f"{tag}: protocol={outbound.get('protocol')}, нужен freedom")
            continue
        stream = outbound.get("streamSettings")
        sockopt = stream.get("sockopt") if isinstance(stream, dict) else None
        if isinstance(sockopt, dict) and sockopt.get("dialerProxy"):
            problems.append(f"{tag}: sockopt.dialerProxy={sockopt.get('dialerProxy')} уводит трафик в другой outbound")
        if "proxySettings" in outbound:
            problems.append(f"{tag}: proxySettings уводит трафик в другой outbound")
        if tag == "telegram-ws":
            settings = outbound.get("settings")
            redirect = settings.get("redirect") if isinstance(settings, dict) else None
            if redirect != f"127.0.0.1:{telegram_port}":
                problems.append(f"telegram-ws: redirect={redirect}, нужен 127.0.0.1:{telegram_port}")
    balancers = routing.get("balancers") if isinstance(routing, dict) else None
    balancer_tags = {
        item.get("tag") for item in balancers if isinstance(item, dict)
    } if isinstance(balancers, list) else set()
    undefined = sorted(used - set(outbounds) - {"discord-direct", "youtube-direct", "telegram-direct", "telegram-ws"})
    undefined += sorted(
        f"balancer {rule['balancerTag']}" for rule in items
        if isinstance(rule.get("balancerTag"), str) and rule["balancerTag"] not in balancer_tags
    )
    if problems:
        return make_check("Xray outbounds", "error", "; ".join(problems))
    if undefined:
        return make_check("Xray outbounds", "warn", "правила ссылаются на несуществующие outbound: " + ", ".join(undefined))
    used_project = sorted(used & {"discord-direct", "youtube-direct", "telegram-direct", "telegram-ws"})
    return make_check(
        "Xray outbounds", "ok",
        ("freedom без прокси: " + ", ".join(used_project)) if used_project else "outbound проекта не используются",
    )


def route_consistency(
    config: str, rules: Any, discord_list: str, telegram: bool = True,
) -> list[dict[str, str]]:
    """Compare the recorded routes with the Xray routing rules and nfqws2 profiles.

    The Xray side uses the same predicates as the engine's --status, which
    feeds the panel's route badges.
    """
    discord_tcp, discord_voice, youtube = parse_routes(config)
    state = xray_service_rules(rules)
    active = {
        "youtube": YOUTUBE_HOSTLIST_ARG in config,
        "discord-tcp": bool(discord_list.strip()),
        "discord-voice": voice_profile_active(config),
    }
    checks = []
    for name, service, mode in (
        ("YouTube route", "youtube", youtube),
        ("Discord TCP route", "discord-tcp", discord_tcp),
        ("Discord Voice route", "discord-voice", discord_voice),
    ):
        xray = inferred_route(state[service], mode)
        okay = mode in ROUTE_VALUES and xray == mode and active[service] == (mode == "zapret")
        detail = f"route={mode}, nfqws={'on' if active[service] else 'off'}"
        if mode in ROUTE_VALUES and xray != mode:
            detail += f", Xray={xray}"
        if service == "discord-voice" and mode != "vless" and state["discord-voice"]:
            lack = missing_ports(voice_filter_ports(config), state["voice-ports"])
            if lack:
                okay = False
                detail += f", правило Xray UDP без портов {format_ports(lack)}"
        checks.append(make_check(name, "ok" if okay else "error", detail))
    if telegram:
        checks.extend(telegram_consistency(config, state["tags"]))
    return checks


def telegram_consistency(config: str, tags: set[str]) -> list[dict[str, str]]:
    checks = []
    telegram = telegram_route(config)
    telegram_active = "--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list" in config
    mtproto_active = "--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list" in config
    if telegram == "ws":
        # Relay for MTProto, direct + TLS profile for the domains.
        okay = {"telegram-ws", "telegram-direct"} <= tags and telegram_active and not mtproto_active
        checks.append(make_check(
            "Telegram route", "ok" if okay else "error",
            f"route=ws, nfqws={'on' if telegram_active else 'off'}",
        ))
    elif telegram == "zapret":
        # Recorded by an older apply or an old snapshot; the mode no longer exists.
        checks.append(make_check("Telegram route", "error", "route=zapret (режим удалён, выберите другой)"))
    elif telegram != "unmanaged":
        okay = (
            telegram in {"direct", "vless"}
            and (telegram == "vless" or "telegram-direct" in tags)
            and not telegram_active
        )
        checks.append(
            make_check(
                "Telegram route",
                "ok" if okay else "error",
                f"route={telegram}, nfqws={'on' if telegram_active else 'off'}",
            )
        )
    elif telegram_active:
        checks.append(make_check("Telegram route", "error", "route=unmanaged, nfqws=on"))
    return checks


# ---------------------------------------------------------------------------
# Processes and live probes.

def telegram_relay_status(
    pidfile: Path, port: int = TELEGRAM_WS_PORT, proc_root: Path = Path("/proc"), timeout: float = 2.0,
) -> tuple[bool, str]:
    """The Telegram WS relay runs when the pidfile PID is telegram_ws_relay.py and the port accepts."""
    try:
        raw = pidfile.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return False, f"нет pid-файла {pidfile}"
    if not raw.isdigit() or int(raw) <= 1:
        return False, f"некорректный pid-файл {pidfile}"
    pid = int(raw)
    try:
        command = (proc_root / str(pid) / "cmdline").read_bytes()
    except OSError:
        command = b""
    if not command:
        return False, f"процесс {pid} не запущен (pid-файл устарел)"
    if b"telegram_ws_relay.py" not in command:
        return False, f"PID {pid} — другой процесс, не telegram_ws_relay.py (pid-файл устарел)"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            pass
    except OSError as exc:
        return False, f"PID {pid} запущен, но 127.0.0.1:{port} не принимает соединения: {exc}"
    return True, f"PID {pid}, принимает соединения на 127.0.0.1:{port}"


QUIC_EVENT = re.compile(r"^EVENT\|QUIC\|[^|]*\|([^|]*)\|([^|]*)\|([a-z-]+)\|([^|\s]*)", re.MULTILINE)


def quic_live_check(
    runner: Any, probe: Path = QUIC_PROBE_PATH, python: str = sys.executable, host: str = QUIC_PROBE_HOST,
) -> dict[str, str]:
    """Send a real QUIC Initial to YouTube from the router itself (through nfqws2, not Xray)."""
    name = "YouTube QUIC с роутера"
    if not probe.is_file():
        return make_check(name, "warn", f"проверка недоступна: нет {probe.name}")
    result = runner([python, str(probe), host, "--timeout", "2", "--tries", "2", "--label", "health"], 15)
    match = QUIC_EVENT.search(result.get("output", "") or "")
    if not match:
        tail = (result.get("output", "") or "нет вывода").strip()[-200:]
        return make_check(name, "warn", f"проверка не выполнена: {tail}")
    probed_host, ip, status, elapsed = match.groups()
    where = f"{probed_host} ({ip or 'IP неизвестен'})"
    if status == "ok":
        return make_check(name, "ok", f"QUIC Initial к {where}: ответ за {elapsed} мс. Проверка с самого роутера, не с телефона")
    if status == "no-reply":
        return make_check(
            name, "error",
            f"QUIC Initial к {where}: нет ответа — приложение YouTube (QUIC/HTTP3) может не загружаться. "
            "Проверка с самого роутера: путь через nfqws2 и провайдера",
        )
    return make_check(name, "warn", f"проверка не выполнена: {status} для {where}")


def rival_processes(proc_root: Path, our_nfqws: int | None) -> list[str]:
    """Other DPI bypass tools running on the router, by process name."""
    found: set[str] = set()
    nfqws2 = []
    try:
        comm_paths = list(proc_root.glob("[0-9]*/comm"))
    except OSError:
        comm_paths = []
    for comm_path in comm_paths:
        try:
            pid = int(comm_path.parent.name)
            comm = comm_path.read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, ValueError):
            continue
        if comm in RIVAL_PROCESSES:
            found.add(RIVAL_PROCESSES[comm])
        elif comm == "nfqws2":
            try:
                command = (comm_path.parent / "cmdline").read_bytes()
            except OSError:
                continue
            # Config checks and packet builders of our own tools, not a second bypass.
            if b"--dry-run" in command or b"--intercept=0" in command:
                continue
            nfqws2.append(pid)
    ours = our_nfqws if our_nfqws in nfqws2 else (nfqws2[0] if len(nfqws2) == 1 else None)
    if any(pid != ours for pid in nfqws2):
        found.add("ещё один nfqws2 (не наш)")
    return sorted(found)


def dns_wire_query(host: str, query_id: int = 0) -> bytes:
    """RFC 1035 query for the A record of host (RFC 8484 recommends ID 0)."""
    labels = host.rstrip(".").split(".")
    if not all(0 < len(label) <= 63 and label.isascii() for label in labels):
        raise ValueError(f"некорректное имя: {host}")
    name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def dns_wire_answers(message: bytes) -> list[str]:
    """IPv4 addresses of the A records in a DNS response."""
    if len(message) < 12:
        raise ValueError("короткий DNS-ответ")
    _identifier, flags, questions, answers, _authority, _additional = struct.unpack("!HHHHHH", message[:12])
    if flags & 0x000F:
        raise ValueError(f"DNS rcode {flags & 0x000F}")

    def skip_name(offset: int) -> int:
        while True:
            if offset >= len(message):
                raise ValueError("обрезанный DNS-ответ")
            length = message[offset]
            if length & 0xC0 == 0xC0:
                return offset + 2
            if length == 0:
                return offset + 1
            offset += 1 + length

    offset = 12
    for _ in range(questions):
        offset = skip_name(offset) + 4
    result = []
    for _ in range(answers):
        offset = skip_name(offset)
        if offset + 10 > len(message):
            raise ValueError("обрезанный DNS-ответ")
        record_type, record_class, _ttl, size = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10
        data = message[offset:offset + size]
        offset += size
        if record_type == 1 and record_class == 1 and len(data) == 4:
            result.append(str(ipaddress.IPv4Address(data)))
    return result


def http_body(raw: bytes) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("нет HTTP-ответа")
    status_line, *header_lines = head.decode("latin-1").split("\r\n")
    parts = status_line.split()
    if len(parts) < 2 or parts[1] != "200":
        raise ValueError(f"HTTP {parts[1] if len(parts) > 1 else '?'}")
    headers = {key.strip().lower(): value.strip() for key, _sep, value in (line.partition(":") for line in header_lines)}
    if "chunked" in headers.get("transfer-encoding", "").lower():
        decoded, rest = b"", body
        while rest:
            size_line, _sep, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            decoded += rest[:size]
            rest = rest[size + 2:]
        return decoded
    length = headers.get("content-length", "")
    return body[:int(length)] if length.isdigit() else body


def doh_resolve(host: str, server_name: str, server_ip: str, timeout: float = 4.0) -> list[str]:
    """Resolve host through DNS-over-HTTPS (RFC 8484 POST) at a pinned server IP.

    The TLS certificate is verified for server_name, so the pinned IP cannot
    be answered by an interceptor. Standard library only.
    """
    query = dns_wire_query(host)
    request = (
        "POST /dns-query HTTP/1.1\r\n"
        f"Host: {server_name}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        f"Content-Length: {len(query)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + query
    context = ssl.create_default_context()
    chunks, total = [], 0
    with socket.create_connection((server_ip, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as stream:
            stream.settimeout(timeout)
            stream.sendall(request)
            while total < 65536:
                chunk = stream.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    return dns_wire_answers(http_body(b"".join(chunks)))


def dns_check(host: str) -> dict[str, str]:
    """The router's resolver compared with DoH answers from pinned resolver IPs."""
    local_ok, local_detail = resolve_public(host)
    answers, failures = [], []
    doh: set[str] = set()
    for label, server_name, server_ip in DOH_RESOLVERS:
        try:
            addresses = doh_resolve(host, server_name, server_ip)
        except (OSError, ValueError) as exc:
            failures.append(f"{label}: {exc}"[:120])
            continue
        doh.update(addresses)
        answers.append(f"DoH {label}: {', '.join(addresses[:3]) or 'нет A-записей'}")
    doh_text = "; ".join(answers + ([f"DoH недоступен ({'; '.join(failures)})"] if failures and not answers else []))
    if not local_ok:
        if doh:
            return make_check(
                f"DNS {host}", "error",
                f"DNS роутера: {local_detail}; {doh_text} — подмена или блокировка DNS у провайдера",
            )
        return make_check(f"DNS {host}", "error", f"{local_detail}; {doh_text}")
    local = set(local_detail.split(", "))
    note = "; адреса роутера не совпадают с DoH (другой узел CDN или подмена DNS)" if doh and not local & doh else ""
    return make_check(f"DNS {host}", "ok", f"роутер: {local_detail}; {doh_text}{note}".strip("; "))


def sni_block_check(host: str) -> dict[str, str]:
    """Tell an SNI block from an IP block: the same IP is asked with SNI ya.ru.

    Runs from the router: the router's own traffic passes nfqws2 but not Xray.
    """
    name = f"SNI/IP {host} (с роутера)"
    base = [
        command_path("curl"), "-sS", "-o", "/dev/null", "--max-time", "5", "--connect-timeout", "3",
        "-w", "__XKSNI__%{http_code}",
    ]
    direct = run(base + [f"https://{host}/"], 9)
    if direct["ok"]:
        code = re.search(r"__XKSNI__(\d{3})", direct["output"])
        return make_check(name, "ok", f"HTTPS отвечает (HTTP {code.group(1) if code else '?'})")
    swapped = run(base + ["-k", "--connect-to", f"{SNI_CONTROL_HOST}:443:{host}:443", f"https://{SNI_CONTROL_HOST}/"], 9)
    if swapped["ok"]:
        return make_check(
            name, "error",
            f"HTTPS не отвечает (curl {direct['code']}), а тот же сервер с SNI {SNI_CONTROL_HOST} отвечает: "
            "блокировка по SNI, текущая стратегия nfqws2 её не обходит",
        )
    return make_check(
        name, "error",
        f"сервер не отвечает и с SNI {SNI_CONTROL_HOST} (curl {direct['code']}/{swapped['code']}): "
        "блокировка по IP или недоступен порт — обход nfqws2 не поможет, нужен VPN",
    )


def run_health(writer: StateWriter) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append(make_check(name, status, detail))
        writer.write(progress=min(95, 5 + len(checks) * 3), checks=checks)

    def add_check(check: dict[str, str]) -> None:
        add(check["name"], check["status"], check["detail"])

    def engine_run(command: list[str], timeout: int) -> dict[str, Any]:
        if TEST_ROOT:
            return run(command, timeout, extra_env={"KD_TEST_ROOT": TEST_ROOT})
        return run(command, timeout)

    xray = process_ids("xray")
    nfqws = process_ids("nfqws2")
    add("Xray", "ok" if len(xray) == 1 else "error", f"PID: {xray}" if xray else "процесс не найден")
    add("nfqws2", "ok" if len(nfqws) == 1 else "error", f"PID: {nfqws}" if nfqws else "процесс не найден")

    try:
        config = safe_read(root_path(NFQWS_CONFIG_LOGICAL))
        discord_tcp_route, discord_voice_route, youtube_route = parse_routes(config)
        status = "ok" if "unknown" not in {discord_tcp_route, discord_voice_route, youtube_route} else "error"
        add(
            "Управляемые маршруты",
            status,
            f"Discord TCP={discord_tcp_route}, Discord Voice={discord_voice_route}, "
            f"YouTube={youtube_route}, Telegram={telegram_route(config)}",
        )
    except (OSError, ValueError) as exc:
        config = ""
        discord_tcp_route = discord_voice_route = youtube_route = "unknown"
        add("Конфигурация nfqws2", "error", str(exc))
    values = parse_shell_values(config)

    for label, logical, active in (
        ("Discord hostlist", DISCORD_LIST_LOGICAL, discord_tcp_route == "zapret"),
        ("YouTube hostlist", YOUTUBE_LIST_LOGICAL, youtube_route == "zapret"),
    ):
        try:
            lines = [line for line in safe_read(root_path(logical)).splitlines() if line and not line.startswith("#")]
            okay = bool(lines) if active else True
            add(label, "ok" if okay else "error", f"{len(lines)} записей; route={'zapret' if active else 'не zapret'}")
        except (OSError, ValueError) as exc:
            add(label, "error" if active else "warn", str(exc))

    config_dir = root_path(XRAY_CONFIG_DIR_LOGICAL)
    xray_files = read_xray_files(config_dir) if config_dir.is_dir() else []
    rules: list[Any] = []
    active_routing = find_xray_routing_file(config_dir, xray_files)
    if active_routing is None:
        add("Xray routing", "error", f"нет файла с объектом routing в {config_dir}")
        routing: dict = {}
    else:
        routing_path, routing = active_routing
        raw_rules = routing.get("rules", [])
        rules = raw_rules if isinstance(raw_rules, list) else []
        state = xray_service_rules(rules)
        expected = set()
        if discord_tcp_route != "vless" or discord_voice_route != "vless":
            expected.add("discord-direct")
        if youtube_route != "vless":
            expected.add("youtube-direct")
        if telegram_route(config) in {"direct", "ws"}:
            expected.add("telegram-direct")
        if telegram_route(config) == "ws":
            expected.add("telegram-ws")
        missing = sorted(expected - state["tags"])
        add(
            "Xray routing",
            "error" if missing else "ok",
            f"{routing_path.name}: " + ("missing: " + ", ".join(missing) if missing else "service-direct rules согласованы"),
        )
    add_check(outbound_checks(rules, routing, xray_outbounds(xray_files)))

    if config_dir.is_dir():
        files = {}
        for path in sorted(config_dir.glob("*.json")):
            try:
                files[path.name] = safe_read(path)
            except (OSError, ValueError):
                continue
        findings = xray_upgrade_findings(files)
        add(
            "Xray 26.10+ совместимость",
            "error" if findings else "ok",
            "; ".join(findings) if findings else "устаревших полей нет",
        )

    try:
        discord_list = safe_read(root_path(DISCORD_LIST_LOGICAL))
    except (OSError, ValueError):
        discord_list = ""
    for check in route_consistency(config, rules, discord_list):
        add_check(check)
    if telegram_route(config) == "ws":
        running, detail = telegram_relay_status(root_path(TELEGRAM_WS_PIDFILE_LOGICAL), TELEGRAM_WS_PORT)
        add("Telegram WS relay", "ok" if running else "error", detail)

    if config:
        for check in config_invariant_checks(config, engine_run, ENGINE_PATH):
            add_check(check)

    xtest = run([command_path("xkeen"), "-xtest"], 35)
    add("Xray config test", "ok" if xtest["ok"] else "error", "Configuration OK" if xtest["ok"] else xtest["output"][-500:])

    families = [("IPv4", "iptables-save")]
    if values.get("IPV6_ENABLED", "0").strip() not in {"", "0"}:
        families.append(("IPv6", "ip6tables-save"))
    for family, tool in families:
        firewall = run([command_path(tool), "-c", "-t", "mangle"], 12)
        if not firewall["ok"]:
            firewall = run([command_path(tool), "-t", "mangle"], 12)
        label = "NFQUEUE" if family == "IPv4" else f"NFQUEUE {family}"
        if not firewall["ok"]:
            add(label, "error", firewall["output"][-500:] or f"{tool} не выполнен")
            continue
        for check in nfqueue_live_checks(firewall["output"], values, family):
            add_check(check)

    route = run([command_path("ip"), "-4", "route", "show", "default"], 8)
    add("IPv4 WAN route", "ok" if route["ok"] and route["output"] else "error", route["output"] or "default route отсутствует")
    route6 = run([command_path("ip"), "-6", "route", "show", "default"], 8)
    add_check(ipv6_route_check(route6["output"] if route6["ok"] else "", values))

    for host in ("discord.com", "www.youtube.com"):
        add_check(dns_check(host))
    for host, route_mode in (("discord.com", discord_tcp_route), ("www.youtube.com", youtube_route)):
        if route_mode in {"zapret", "direct"}:
            add_check(sni_block_check(host))
    if youtube_route == "zapret":
        add_check(quic_live_check(run, QUIC_PROBE_PATH))

    try:
        usage = shutil.disk_usage(root_path("/opt"))
        free_percent = usage.free * 100 / usage.total
        status = "ok" if free_percent >= 10 else "warn" if free_percent >= 5 else "error"
        add("Свободное место /opt", status, f"{usage.free // (1024 * 1024)} MiB ({free_percent:.1f}%)")
    except OSError as exc:
        add("Свободное место /opt", "error", str(exc))

    try:
        meminfo = safe_read(root_path("/proc/meminfo"), 128 * 1024)
        values_kb = {key: int(value.split()[0]) for key, value in (line.split(":", 1) for line in meminfo.splitlines()) if value.split()}
        available = values_kb.get("MemAvailable", values_kb.get("MemFree", 0))
        status = "ok" if available >= 65536 else "warn" if available >= 32768 else "error"
        add("Доступная память", status, f"{available // 1024} MiB")
    except (OSError, ValueError) as exc:
        add("Доступная память", "warn", str(exc))

    try:
        count = int(safe_read(root_path("/proc/sys/net/netfilter/nf_conntrack_count"), 100).strip())
        maximum = int(safe_read(root_path("/proc/sys/net/netfilter/nf_conntrack_max"), 100).strip())
        ratio = count * 100 / maximum if maximum else 100
        status = "ok" if ratio < 70 else "warn" if ratio < 90 else "error"
        add("Conntrack", status, f"{count}/{maximum} ({ratio:.1f}%)")
    except (OSError, ValueError) as exc:
        add("Conntrack", "warn", str(exc))

    lock = root_path(PROJECT_LOCK_LOGICAL)
    if lock.exists():
        add("Project lock", "warn", f"присутствует {lock}; проверьте, не выполняется ли другая операция")
    else:
        add("Project lock", "ok", "активной операции нет")

    try:
        raw_pid = safe_read(root_path(NFQWS_PIDFILE_LOGICAL), 100).strip()
        our_nfqws = int(raw_pid) if raw_pid.isdigit() else None
    except (OSError, ValueError):
        our_nfqws = None
    conflicts = rival_processes(root_path("/proc"), our_nfqws)
    add("Другие DPI bypass", "warn" if conflicts else "ok", ", ".join(conflicts) if conflicts else "конфликтующих процессов не найдено")
    return checks


def curl_probe(url: str, label: str, options: list[str], timeout: int) -> dict[str, Any]:
    marker = "__XKRES__"
    command = [
        command_path("curl"),
        "-I",
        "-sS",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(min(2, timeout)),
        "-o",
        "/dev/null",
        "-w",
        f"{marker}%{{http_code}}|%{{time_total}}|%{{remote_ip}}",
        *options,
        url,
    ]
    result = run(command, timeout + 3)
    match = re.search(re.escape(marker) + r"(\d{3})\|([0-9.]+)\|([^\s]*)", result["output"])
    code = match.group(1) if match else "000"
    elapsed = float(match.group(2)) if match else -1.0
    remote_ip = match.group(3) if match else ""
    unsupported = result["code"] in {2, 4, 35} and any(word in result["output"].lower() for word in ("unsupported", "not support", "unknown option"))
    status = "unsupported" if unsupported else "ok" if result["ok"] and code != "000" else "error"
    return {
        "protocol": label,
        "status": status,
        "http_code": code,
        "time": elapsed,
        "remote_ip": remote_ip,
        "exit_code": result["code"],
        "detail": "" if status == "ok" else result["output"][-300:],
    }


def ping_probe(target: str) -> dict[str, Any]:
    result = run([command_path("ping"), "-c", "1", "-W", "1", target], 4)
    match = re.search(r"time[=<]([0-9.]+)\s*ms", result["output"])
    return {
        "status": "ok" if result["ok"] else "timeout",
        "time_ms": float(match.group(1)) if match else None,
    }


def standard_target(name: str, value: str) -> dict[str, Any]:
    if value.startswith("PING:"):
        target = value.split(":", 1)[1]
        return {"name": name, "target": target, "kind": "ping", "ping": ping_probe(target)}
    host = value.split("//", 1)[1].split("/", 1)[0]
    resolved, dns_detail = resolve_public(host)
    if not resolved:
        return {"name": name, "target": value, "kind": "url", "dns": {"status": "error", "detail": dns_detail}, "error": dns_detail}
    tests = [
        curl_probe(value, "HTTP/1.1", ["--http1.1"], STANDARD_TIMEOUT),
        curl_probe(value, "TLS1.2", ["--tlsv1.2", "--tls-max", "1.2"], STANDARD_TIMEOUT),
        curl_probe(value, "TLS1.3", ["--tlsv1.3", "--tls-max", "1.3"], STANDARD_TIMEOUT),
    ]
    return {
        "name": name,
        "target": value,
        "host": host,
        "kind": "url",
        "dns": {"status": "ok" if resolved else "error", "detail": dns_detail},
        "checks": tests,
        "ping": ping_probe(host),
    }


def run_standard(writer: StateWriter) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=STANDARD_WORKERS) as pool:
        futures = {pool.submit(standard_target, name, value): name for name, value in STANDARD_TARGETS}
        for future in concurrent.futures.as_completed(futures):
            if CANCELLED.is_set():
                raise InterruptedError("diagnostics cancelled")
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # diagnostic result, never a control path
                results.append({"name": name, "kind": "error", "error": str(exc)[:500]})
            results.sort(key=lambda item: [name for name, _ in STANDARD_TARGETS].index(item["name"]))
            writer.write(progress=10 + int(85 * len(results) / len(STANDARD_TARGETS)), results=results)
    return results


def parse_dpi_marker(output: str) -> tuple[str, int, int, float, str] | None:
    match = re.search(r"__XKDPI__(\d{3})\|(\d+)\|(\d+)\|([0-9.]+)\|([^\s]*)", output)
    if not match:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3)), float(match.group(4)), match.group(5)


def classify_dpi(code: int, parsed: tuple[str, int, int, float, str] | None, output: str, timeout: int) -> str:
    lowered = output.lower()
    if code in {2, 4, 35} and any(word in lowered for word in ("unsupported", "not support", "unknown option")):
        return "unsupported"
    if parsed:
        _http, uploaded, downloaded, elapsed, _remote = parsed
        if uploaded > 0 and downloaded == 0 and elapsed >= timeout * 0.9 and code != 0:
            return "likely_blocked"
        if code == 0:
            return "ok"
    return "fail"


def dpi_probe(host: str, label: str, options: list[str], payload: Path) -> dict[str, Any]:
    marker = "__XKDPI__"
    command = [
        command_path("curl"),
        "--range",
        f"0-{DPI_BYTES - 1}",
        "--max-time",
        str(DPI_TIMEOUT),
        "--connect-timeout",
        "3",
        "-o",
        "/dev/null",
        "-X",
        "POST",
        "--data-binary",
        f"@{payload}",
        "-sS",
        "-w",
        f"{marker}%{{http_code}}|%{{size_upload}}|%{{size_download}}|%{{time_total}}|%{{remote_ip}}",
        *options,
        f"https://{host}",
    ]
    result = run(command, DPI_TIMEOUT + 4)
    parsed = parse_dpi_marker(result["output"])
    status = classify_dpi(result["code"], parsed, result["output"], DPI_TIMEOUT)
    http_code, uploaded, downloaded, elapsed, remote_ip = parsed or ("000", 0, 0, -1.0, "")
    return {
        "protocol": label,
        "status": status,
        "http_code": http_code,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "time": elapsed,
        "remote_ip": remote_ip,
        "exit_code": result["code"],
        "detail": "" if status == "ok" else result["output"][-300:],
    }


def dpi_target(identifier: str, provider: str, host: str, payload: Path) -> dict[str, Any]:
    resolved, dns_detail = resolve_public(host)
    if not resolved:
        return {"id": identifier, "provider": provider, "host": host, "dns": {"status": "error", "detail": dns_detail}, "error": dns_detail}
    checks = [
        dpi_probe(host, "HTTP/1.1", ["--http1.1"], payload),
        dpi_probe(host, "TLS1.2", ["--tlsv1.2", "--tls-max", "1.2"], payload),
        dpi_probe(host, "TLS1.3", ["--tlsv1.3", "--tls-max", "1.3"], payload),
    ]
    return {
        "id": identifier,
        "provider": provider,
        "host": host,
        "dns": {"status": "ok" if resolved else "error", "detail": dns_detail},
        "checks": checks,
    }


def run_dpi(writer: StateWriter) -> list[dict[str, Any]]:
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    payload = JOB_DIR / f"payload-{os.getpid()}.bin"
    payload.write_bytes(secrets.token_bytes(DPI_BYTES))
    os.chmod(payload, 0o600)
    results: list[dict[str, Any]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=DPI_WORKERS) as pool:
            futures = {
                pool.submit(dpi_target, identifier, provider, host, payload): identifier
                for identifier, provider, host in DPI_TARGETS
            }
            order = [identifier for identifier, _provider, _host in DPI_TARGETS]
            for future in concurrent.futures.as_completed(futures):
                if CANCELLED.is_set():
                    raise InterruptedError("diagnostics cancelled")
                identifier = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({"id": identifier, "provider": "unknown", "host": "", "error": str(exc)[:500]})
                results.sort(key=lambda item: order.index(item["id"]))
                writer.write(progress=10 + int(85 * len(results) / len(DPI_TARGETS)), results=results)
    finally:
        payload.unlink(missing_ok=True)
    return results


def summary(kind: str, results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"ok": 0, "warn": 0, "error": 0, "unsupported": 0, "likely_blocked": 0}
    if kind == "health":
        for item in results:
            status = item.get("status", "error")
            if status == "warn":
                counts["warn"] += 1
            elif status == "ok":
                counts["ok"] += 1
            else:
                counts["error"] += 1
        return counts
    for item in results:
        if item.get("error"):
            counts["error"] += 1
        checks = item.get("checks", [])
        if item.get("kind") == "ping":
            checks = [item.get("ping", {})]
        for check in checks:
            status = check.get("status", "error")
            if status in counts:
                counts[status] += 1
            elif status == "timeout":
                counts["warn"] += 1
            else:
                counts["error"] += 1
    return counts


def handle_signal(_signum: int, _frame: Any) -> None:
    CANCELLED.set()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True, choices=("health",))
    parser.add_argument("--job-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{16}", args.job_id):
        raise SystemExit("invalid job id")
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    initial = {
        "ok": True,
        "job_id": args.job_id,
        "kind": args.kind,
        "status": "running",
        "active": True,
        "progress": 2,
        "created_utc": utc_now(),
        "source": {
            "flowseal_commit": "176f56dc3f11ce5915c26abcdde903f93d835b64",
            "targets_sha": "4a5ca2eeb8bcf40f2a5c993d2a197dbbd03195d9",
            "dpi_suite_sha": "1f44274f02802e80841081c2dc9ababcac9b4690",
        },
        "results": [],
    }
    writer = StateWriter(initial)
    try:
        if args.kind == "health":
            results = run_health(writer)
        elif args.kind == "standard":
            results = run_standard(writer)
        else:
            results = run_dpi(writer)
        if CANCELLED.is_set():
            raise InterruptedError("diagnostics cancelled")
        writer.write(
            status="completed",
            active=False,
            progress=100,
            results=results,
            summary=summary(args.kind, results),
            finished_utc=utc_now(),
        )
        return 0
    except InterruptedError:
        writer.write(status="cancelled", active=False, finished_utc=utc_now())
        return 130
    except Exception as exc:
        writer.write(status="error", active=False, error=str(exc)[:1000], finished_utc=utc_now())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

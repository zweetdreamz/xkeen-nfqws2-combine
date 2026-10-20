#!/usr/bin/env python3
"""Read-only XKeen/nfqws2 diagnostics adapted from Flowseal test tools.

The module never changes routing, firewall, XKeen or nfqws2 configuration.
It writes only bounded job state below /opt/tmp/xkeen-diagnostics.
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
import socket
import stat
import subprocess
import tempfile
import threading
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[2]
TEST_ROOT = os.environ.get("KD_DIAGNOSTICS_TEST_ROOT", "")
JOB_DIR_LOGICAL = "/opt/tmp/xkeen-diagnostics"
NFQWS_CONFIG_LOGICAL = "/opt/etc/nfqws2/nfqws2.conf"
DISCORD_LIST_LOGICAL = "/opt/etc/nfqws2/lists/user.list"
YOUTUBE_LIST_LOGICAL = "/opt/etc/nfqws2/lists/youtube.list"
XRAY_ROUTING_LOGICAL = "/opt/etc/xray/configs/05_routing.json"
XRAY_CONFIG_DIR_LOGICAL = "/opt/etc/xray/configs"
PROJECT_LOCK_LOGICAL = "/opt/tmp/keenetic-discord-nfqws2.lock"
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


def run(command: list[str], timeout: int) -> dict[str, Any]:
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
            env={**os.environ, "PATH": "/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin"},
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
TELEGRAM_ROUTE_VALUES = ROUTE_VALUES | {"unmanaged"}


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


def xray_upgrade_findings(files: dict[str, str]) -> list[str]:
    """Settings that Xray 26.10+ refuses to load, by config file name.

    - any outbound "proxySettings" (removed; sockopt.dialerProxy replaces it);
    - "addressPortStrategy" in the sockopt of a freedom outbound.
    """
    findings = []
    for name, text in sorted(files.items()):
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
    return "--filter-l7=stun,discord" in config


def route_consistency(config: str, tags: set[str], discord_list: str) -> list[dict[str, str]]:
    discord_tcp, discord_voice, youtube = parse_routes(config)
    youtube_active = "--hostlist=/opt/etc/nfqws2/lists/youtube.list" in config
    discord_tcp_active = bool(discord_list.strip())
    discord_voice_active = voice_profile_active(config)
    checks = []
    for name, mode, tag, active in (
        ("YouTube route", youtube, "youtube-direct", youtube_active),
        ("Discord TCP route", discord_tcp, "discord-direct", discord_tcp_active),
        ("Discord Voice route", discord_voice, "discord-direct", discord_voice_active),
    ):
        okay = mode in ROUTE_VALUES and (mode == "vless" or tag in tags) and active == (mode == "zapret")
        checks.append(make_check(name, "ok" if okay else "error", f"route={mode}, nfqws={'on' if active else 'off'}"))
    telegram = telegram_route(config)
    telegram_active = "--hostlist=/opt/etc/nfqws2/lists/telegram.list" in config
    if telegram != "unmanaged":
        okay = (
            telegram in ROUTE_VALUES
            and (telegram == "vless" or "telegram-direct" in tags)
            and telegram_active == (telegram == "zapret")
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


def run_health(writer: StateWriter) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append(make_check(name, status, detail))
        writer.write(progress=min(95, 8 + len(checks) * 7), checks=checks)

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

    tags = set()
    try:
        routing = json.loads(safe_read(root_path(XRAY_ROUTING_LOGICAL)))
        rules = routing.get("routing", {}).get("rules", [])
        tags = {rule.get("outboundTag") for rule in rules if isinstance(rule, dict)}
        expected = set()
        if discord_tcp_route != "vless" or discord_voice_route != "vless":
            expected.add("discord-direct")
        if youtube_route != "vless":
            expected.add("youtube-direct")
        if telegram_route(config) in {"direct", "zapret"}:
            expected.add("telegram-direct")
        missing = sorted(expected - tags)
        add("Xray routing", "error" if missing else "ok", "missing: " + ", ".join(missing) if missing else "service-direct rules согласованы")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add("Xray routing", "error", str(exc))

    config_dir = root_path(XRAY_CONFIG_DIR_LOGICAL)
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
    for check in route_consistency(config, tags, discord_list):
        add(check["name"], check["status"], check["detail"])

    xtest = run([command_path("xkeen"), "-xtest"], 35)
    add("Xray config test", "ok" if xtest["ok"] else "error", "Configuration OK" if xtest["ok"] else xtest["output"][-500:])

    firewall = run([command_path("iptables-save"), "-t", "mangle"], 12)
    has_queue = "NFQUEUE" in firewall["output"] and "300" in firewall["output"]
    add("NFQUEUE", "ok" if firewall["ok"] and has_queue else "error", "queue 300 присутствует" if has_queue else firewall["output"][-500:])

    route = run([command_path("ip"), "-4", "route", "show", "default"], 8)
    add("IPv4 WAN route", "ok" if route["ok"] and route["output"] else "error", route["output"] or "default route отсутствует")

    for host in ("discord.com", "www.youtube.com"):
        okay, detail = resolve_public(host)
        add(f"DNS {host}", "ok" if okay else "error", detail)

    try:
        usage = shutil.disk_usage(root_path("/opt"))
        free_percent = usage.free * 100 / usage.total
        status = "ok" if free_percent >= 10 else "warn" if free_percent >= 5 else "error"
        add("Свободное место /opt", status, f"{usage.free // (1024 * 1024)} MiB ({free_percent:.1f}%)")
    except OSError as exc:
        add("Свободное место /opt", "error", str(exc))

    try:
        meminfo = safe_read(root_path("/proc/meminfo"), 128 * 1024)
        values = {key: int(value.split()[0]) for key, value in (line.split(":", 1) for line in meminfo.splitlines()) if value.split()}
        available = values.get("MemAvailable", values.get("MemFree", 0))
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

    conflicts = []
    for name in ("winws", "goodbyedpi", "tpws", "nfqws"):
        if process_ids(name):
            conflicts.append(name)
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

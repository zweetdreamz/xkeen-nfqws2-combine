#!/usr/bin/env python3
"""Run the existing Flowseal strategy translator locally on the router.

The job never edits persistent network configuration and never invokes XKeen.
It renders the same temporary nfqws2 runner used by the Windows tuner. The
runner's EXIT/signal/SIGPIPE traps restore the original nfqws2 service on
success, failure, cancel, or panel disconnect. When the runner has to be
killed (SIGKILL), the job kills its candidate nfqws2 and restores the service
itself from the runner's runtime.state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[2]
WINDOWS_DIR = PROJECT_DIR / "tools" / "windows"
sys.path.insert(0, str(WINDOWS_DIR))

import zapret_tuner as tuner  # noqa: E402


TEST_ROOT = os.environ.get("KD_TUNER_TEST_ROOT", "")
LOCK_LOGICAL = "/opt/tmp/keenetic-discord-nfqws2.lock"
JOB_LOGICAL = "/opt/tmp/xkeen-zapret-tuner"
NFQWS_CONF_LOGICAL = "/opt/etc/nfqws2/nfqws2.conf"
# Discord voice server seen during the last user-confirmed Voice session.
VOICE_ENDPOINT_LOGICAL = "/opt/etc/xkeen-web/discord-voice-endpoint.json"
RUNNER_TEMPLATE = WINDOWS_DIR / "router-candidate-runner.sh"
NFQWS_INIT_LOGICAL = "/opt/etc/init.d/S51nfqws2"
NFQWS_PIDFILE_LOGICAL = "/opt/var/run/nfqws2.pid"
# The runner keeps its temporary files (and runtime.state) here.
RUNNER_TMP_LOGICAL = "/opt/tmp/zapret-tuner.{pid}"
# Seconds the runner gets after SIGTERM before it is killed. Its traps run
# only after the current command (a curl of up to --http-timeout seconds).
try:
    RUNNER_STOP_TIMEOUT = min(120, max(2, int(os.environ.get("KD_TUNER_RUNNER_STOP_TIMEOUT", "40"))))
except ValueError:
    RUNNER_STOP_TIMEOUT = 40


class JobCancelled(Exception):
    pass


def root_path(logical: str) -> Path:
    return Path(f"{TEST_ROOT}{logical}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def read_pid(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    return int(raw) if raw.isdigit() and int(raw) > 1 else None


def acquire_project_lock() -> Path:
    lock = root_path(LOCK_LOGICAL)
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        existing_pid = read_pid(lock / "pid")
        if existing_pid and process_alive(existing_pid):
            raise RuntimeError(
                f"another project operation is active (PID {existing_pid})"
            ) from None
        try:
            (lock / "pid").unlink()
        except FileNotFoundError:
            pass
        try:
            lock.rmdir()
        except OSError as error:
            raise RuntimeError(f"stale project lock is not empty: {lock}") from error
        lock.mkdir(mode=0o700)
    (lock / "pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    os.chmod(lock / "pid", 0o600)
    return lock


def release_project_lock(lock: Path | None) -> None:
    if lock is None:
        return
    try:
        if read_pid(lock / "pid") == os.getpid():
            (lock / "pid").unlink(missing_ok=True)
            lock.rmdir()
    except OSError:
        pass


ROUTE_VALUES = {"direct", "zapret", "vless"}
# Telegram is never tuned here (its block is by IP); its route is only read.
# "zapret" is accepted so that a header written by an older engine still parses.
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


def read_nfqws_conf() -> str:
    config = root_path(NFQWS_CONF_LOGICAL)
    try:
        return config.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise RuntimeError(f"cannot read current nfqws2 config: {config}") from error


def recorded_udp_settings(text: str) -> tuple[str, str]:
    """(strategy, range) from "# Discord UDP: strategy=X, range=Y." of nfqws2.conf.

    Configs written before that line existed are inferred like the engine
    does: wide when UDP_PORTS reaches 65535, flowseal otherwise.
    """
    match = re.search(
        r"^# Discord UDP: strategy=(flowseal|legacy), range=(narrow|wide)\.$",
        text,
        re.MULTILINE,
    )
    if match:
        return match.group(1), match.group(2)
    wide = re.search(r"^UDP_PORTS=.*50000[:-]65535", text, re.MULTILINE)
    return "flowseal", "wide" if wide else "narrow"


def applied_custom_args() -> str:
    """NFQWS_ARGS_CUSTOM as the package init sees it (the conf is sourced)."""
    config = root_path(NFQWS_CONF_LOGICAL)
    try:
        completed = subprocess.run(
            ["sh", "-c", '. "$1" >/dev/null 2>&1; printf "%s" "${NFQWS_ARGS_CUSTOM-}"', "sh", str(config)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def recorded_route(service: str) -> str:
    text = read_nfqws_conf()
    routes = parse_active_routes(text)
    if routes is None:
        raise RuntimeError("current managed service routes cannot be determined")
    return routes[service]


def core_pids() -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for name in ("xray", "mihomo"):
        try:
            completed = subprocess.run(
                ["pidof", name],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        pids = [
            int(value)
            for value in completed.stdout.split()
            if value.isdigit()
        ]
        if pids:
            result[name] = sorted(pids)
    return result


class StateWriter:
    def __init__(self, job_dir: Path, initial: dict[str, Any]) -> None:
        self.job_dir = job_dir
        self.state_path = job_dir / "state.json"
        self.log_path = job_dir / "events.log"
        self.payload = initial
        self.write()

    def write(self, **changes: Any) -> None:
        self.payload.update(changes)
        self.payload["updated_utc"] = utc_now()
        atomic_json(self.state_path, self.payload)

    def log(self, line: str) -> None:
        cleaned = line.replace("\x00", "").rstrip("\r\n")
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(cleaned[:4000] + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--service",
        required=True,
        choices=tuner.TUNER_SERVICES,
    )
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--mix-level", choices=("off", "safe", "extended"), default="safe")
    parser.add_argument("--max-candidates", type=int, default=32)
    parser.add_argument("--search-seed", type=tuner.parse_search_seed)
    parser.add_argument("--http-timeout", type=int, default=6)
    parser.add_argument("--voice-duration", type=int, default=25)
    parser.add_argument("--client-ip")
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--source-file")
    parser.add_argument(
        "--voice-auto",
        action="store_true",
        help="probe the learned Discord voice server instead of asking for every candidate",
    )
    parser.add_argument(
        "--voice-traffic",
        action="store_true",
        help="judge each Voice candidate by the client's own voice traffic (stay in a channel)",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not re.fullmatch(r"[0-9a-f]{16}", args.job_id):
        raise ValueError("invalid job id")
    if not 1 <= args.max_candidates <= 64:
        raise ValueError("max-candidates must be between 1 and 64")
    if not 4 <= args.http_timeout <= 20:
        raise ValueError("http-timeout must be between 4 and 20")
    if not 10 <= args.voice_duration <= 60:
        raise ValueError("voice-duration must be between 10 and 60")
    if args.service == "discord-voice":
        if not args.client_ip:
            raise ValueError("client-ip is required for Discord Voice")
        address = ipaddress.ip_address(args.client_ip)
        if address.version != 4 or not address.is_private:
            raise ValueError("client-ip must be a private LAN IPv4")
    if args.source_file is not None and (
        len(args.source_file) > 160 or not tuner.SOURCE_NAME_RE.fullmatch(args.source_file)
    ):
        raise ValueError("source-file must name one general*.bat file")
    if args.voice_auto and args.service != "discord-voice":
        raise ValueError("voice-auto applies to discord-voice only")
    if args.voice_traffic and args.service != "discord-voice":
        raise ValueError("voice-traffic applies to discord-voice only")
    if args.voice_traffic and args.voice_auto:
        raise ValueError("choose one Voice check: voice-auto or voice-traffic")
    if args.source_dir and not TEST_ROOT:
        raise ValueError("source-dir is allowed only in an isolated test root")


def voice_endpoint_valid(ip: Any, port: Any, voice_range: str = "narrow") -> bool:
    """A public IPv4 voice server on a port every Voice candidate processes."""
    if not isinstance(ip, str) or isinstance(port, bool) or not isinstance(port, int):
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Candidates filter 19294-19344 and 50000-50100 (50000-65535 in the
    # wide range); a server on another port would never be affected.
    high = 65535 if voice_range == "wide" else 50100
    in_range = 19294 <= port <= 19344 or 50000 <= port <= high
    return address.version == 4 and address.is_global and in_range


def load_voice_endpoint(voice_range: str = "narrow") -> dict[str, Any] | None:
    path = root_path(VOICE_ENDPOINT_LOGICAL)
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not voice_endpoint_valid(data.get("ip"), data.get("port"), voice_range):
        return None
    return data


def save_voice_endpoint(observed: dict[str, Any]) -> None:
    atomic_json(
        root_path(VOICE_ENDPOINT_LOGICAL),
        {
            "format": 1,
            "ip": observed["ip"],
            "port": observed["port"],
            "learned_utc": utc_now(),
        },
    )


def candidate_summary(
    candidates: list[tuner.Candidate],
) -> list[dict[str, Any]]:
    return [
        {
            "number": number,
            "candidate_id": candidate.candidate_id,
            "source_name": candidate.source_name,
            "family": candidate.family,
            "rank": candidate.rank,
            "also_from": list(candidate.also_from),
        }
        for number, candidate in enumerate(candidates, 1)
    ]


def available_log_line(available: int, maximum: int, mix_level: str) -> str:
    """Explain the run size: identical profiles are merged, the maximum is a cap."""
    depth = {"off": "только прямой перевод BAT", "safe": "Safe", "extended": "Extended"}[mix_level]
    tested = min(available, maximum)
    line = f"Разных вариантов: {available} ({depth}); максимум {maximum} — проверяется {tested}."
    if available < maximum:
        line += " Одинаковые после перевода профили проверяются один раз."
    return line


def is_builtin_profile(candidate: tuner.Candidate) -> bool:
    """The project's own profile, with the router's QUIC section or Voice range."""
    if candidate.service == "youtube" and "--new" in candidate.args:
        quic = candidate.args[candidate.args.index("--new") + 1:]
        known = tuner.known_candidate(candidate.service, [], quic)
    else:
        known = tuner.known_candidate(candidate.service, [])
    return candidate.args in {known.args, tuner.voice_candidate_in_range(known, "wide").args}


def candidate_log_line(number: int, candidates: list[tuner.Candidate]) -> str | None:
    """A readable line naming the BAT file(s) of candidate ``number``."""
    if not 1 <= number <= len(candidates):
        return None
    candidate = candidates[number - 1]
    if is_builtin_profile(candidate):
        # The project's own profile; source_name only names its BAT origin.
        return (
            f"Кандидат {number} из {len(candidates)}: встроенный профиль проекта "
            f"(основа — {candidate.source_name}) · {candidate.family}"
        )
    line = f"Кандидат {number} из {len(candidates)}: {candidate.source_name}"
    if candidate.also_from:
        line += (
            f" (тот же профиль ещё в {len(candidate.also_from)} файл(ах): "
            + ", ".join(candidate.also_from) + ")"
        )
    return line + f" · {candidate.family}"


def make_report(
    args: argparse.Namespace,
    commit: str,
    candidates: list[tuner.Candidate],
    found: tuner.Candidate | None,
    output: list[str],
) -> dict[str, Any]:
    return {
        "report_format": 1,
        "created_utc": utc_now(),
        "repository": tuner.DEFAULT_REPOSITORY,
        "ref": tuner.DEFAULT_REF,
        "commit": commit,
        "service": args.service,
        "router": "local-panel",
        "search_seed": args.search_seed,
        "source_file": args.source_file,
        "candidate_count": len(candidates),
        "found": {
            "candidate_id": found.candidate_id,
            "service": found.service,
            "source_name": found.source_name,
            "source_sha": found.source_sha,
            "source_url": found.source_url,
            "family": found.family,
            "args": list(found.args),
            "notes": list(found.notes),
            "rank": found.rank,
        } if found else None,
        "remote_output": output[-500:],
        "verification": tuner.verification_report(args.service, output, found_number(candidates, found)),
    }


def found_number(candidates: list[tuner.Candidate], found: tuner.Candidate | None) -> int | None:
    for number, candidate in enumerate(candidates, 1):
        if candidate is found:
            return number
    return None


RAW_BASELINE_LOG = {
    "pass": (
        "Без обхода (nfqws2 остановлен) проверки проходят: провайдер не блокирует "
        "этот сервис с роутера, найденный профиль ничего не доказывает."
    ),
    "fail": "Без обхода проверки не проходят: блокировка подтверждена, подбор имеет смысл.",
    "tcp-unreachable": (
        "Без обхода ни один адрес не принял TCP-соединение. Причина пока неясна; "
        "перебор стратегий продолжается."
    ),
    "ip-block": (
        "Старый runner сообщил об IP-блокировке; этот вывод не подтверждён. "
        "Проверьте результат новым запуском подбора."
    ),
    "dns-error": "Без обхода имена не резолвятся (DNS роутера): подбор остановлен.",
}
QUIC_GATE_LOG = {
    ("on", "raw-reply"): "QUIC (UDP 443) отвечает и без обхода: каждый кандидат должен его сохранить.",
    ("on", "active-reply"): "QUIC отвечает только с текущим профилем: каждый кандидат должен его сохранить.",
    ("off", "no-reply"): "QUIC с роутера не отвечает ни с профилем, ни без него: QUIC не проверяется.",
    ("off", "probe-unavailable"): "quic_probe.py недоступен: QUIC не проверяется.",
}


def parse_event(
    writer: StateWriter,
    line: str,
    candidates: list[tuner.Candidate],
) -> tuner.Candidate | None:
    if not line.startswith("EVENT|"):
        return None
    parts = line.split("|")
    event = parts[1] if len(parts) > 1 else ""
    if event == "CANDIDATE" and len(parts) >= 4:
        number = int(parts[2])
        writer.write(
            # Only the endpoint seen with the confirmed candidate is learned.
            voice_endpoint_observed=None,
            status="running",
            current_candidate=number,
            current_candidate_id=parts[3],
            needs_voice_verdict=False,
        )
        readable = candidate_log_line(number, candidates)
        if readable:
            writer.log(readable)
    elif event == "PROBE_DETAIL":
        detail = tuner.parse_probe_event(line)
        if detail:
            writer.write(last_probe_detail=detail)
    elif event == "SUITE_RESULT" and len(parts) >= 8:
        result = {"candidate": int(parts[2]), "phase": parts[3], "round": int(parts[4]),
                  "verdict": parts[5], "successes": int(parts[6]), "total": int(parts[7])}
        key = {"baseline": "baseline_result", "raw": "raw_baseline_result"}.get(parts[3], "last_suite_result")
        writer.write(**{key: result})
    elif event == "RAW_BASELINE" and len(parts) >= 3:
        writer.write(raw_baseline=parts[2], network_discriminates={"pass": False, "fail": True}.get(parts[2]))
        if parts[2] in RAW_BASELINE_LOG:
            writer.log(RAW_BASELINE_LOG[parts[2]])
    elif event == "QUIC" and len(parts) >= 7:
        quic = {"label": parts[2], "host": parts[3], "ip": parts[4], "status": parts[5],
                "ms": int(parts[6]) if parts[6].isdigit() else None}
        writer.write(last_quic_probe=quic)
    elif event == "QUIC_GATE" and len(parts) >= 4:
        writer.write(quic_gate={"state": parts[2], "reason": parts[3]})
        if (parts[2], parts[3]) in QUIC_GATE_LOG:
            writer.log(QUIC_GATE_LOG[(parts[2], parts[3])])
    elif event == "QUIC_RESULT" and len(parts) >= 6:
        writer.write(last_quic_result={"candidate": int(parts[2]), "result": parts[3],
                                       "ok": int(parts[4]), "total": int(parts[5])})
        if parts[3] == "fail":
            writer.log(f"Кандидат {parts[2]}: QUIC перестал отвечать — кандидат отклонён.")
    elif event == "FIREWALL_REASSERT" and len(parts) >= 4 and parts[3] == "restored":
        writer.write(firewall_reasserted=int(writer.payload.get("firewall_reasserted") or 0) + 1)
        writer.log(f"Перед кандидатом {parts[2]} правила NFQUEUE пропали (Keenetic перестроил iptables): восстановлены.")
    elif event == "FIREWALL_LOST" and len(parts) >= 3:
        writer.log(f"Кандидат {parts[2]}: во время проверки пропали правила NFQUEUE — результат не засчитан.")
    elif event == "UDP_RANGE" and len(parts) >= 3:
        writer.write(udp_range_runner=parts[2])
    elif event == "VOICE_BLOB" and len(parts) >= 4:
        writer.log("В NFQWS_BASE_ARGS нет blob discord_udp (--udp-strategy legacy): кандидаты получают его временно.")
    elif event == "FATAL":
        writer.write(runner_fatal="|".join(parts[2:])[:500])
    elif event == "VOICE_OBSERVATION" and len(parts) >= 5:
        writer.write(voice_observation={"outgoing_packets": int(parts[2]), "incoming_packets": int(parts[3]), "wan_match": parts[4] == "1"})
    elif event == "PROBE" and len(parts) >= 5:
        writer.write(
            last_probe={
                "candidate": int(parts[2]),
                "code": parts[3],
                "url": "|".join(parts[4:])[:500],
            }
        )
    elif event == "HTTP_RESULT" and len(parts) >= 5:
        writer.write(
            last_http_result={
                "candidate": int(parts[2]),
                "successes": int(parts[3]),
                "total": int(parts[4]),
            }
        )
    elif event == "VOICE_READY" and len(parts) >= 4:
        writer.write(
            status="voice_window",
            current_candidate=int(parts[2]),
            voice_duration=int(parts[3]),
            needs_voice_verdict=False,
        )
    elif event == "VOICE_WATCH" and len(parts) >= 4:
        writer.write(
            status="voice_watch",
            current_candidate=int(parts[2]),
            voice_duration=int(parts[3]),
            needs_voice_verdict=False,
        )
    elif event == "VOICE_TRAFFIC_RESULT" and len(parts) >= 4:
        number, state = int(parts[2]), parts[3]
        changes: dict[str, Any] = {"last_voice_traffic": {"candidate": number, "state": state}}
        if number == 0:
            changes["voice_traffic_baseline"] = state
        writer.write(**changes)
        meaning = {
            "connected": "голос подключился и держится",
            "attempts": "Discord пытается подключиться, но соединение не держится",
            "established": "голос уже был подключён до проверки — новых попыток нет",
            "idle": "голосового трафика нет — зайдите в голосовой канал и оставайтесь в нём",
            "unavailable": "диагностика недоступна",
        }.get(state, state)
        who = "Текущий профиль" if number == 0 else f"Кандидат {number}"
        writer.log(f"{who}: {meaning}.")
    elif event == "VOICE_VERDICT" and len(parts) >= 3:
        writer.write(
            status="awaiting_voice",
            current_candidate=int(parts[2]),
            needs_voice_verdict=True,
        )
    elif event == "VOICE_ENDPOINT" and len(parts) >= 6:
        ip, port = parts[2], int(parts[3])
        if voice_endpoint_valid(ip, port, writer.payload.get("udp_range", "narrow")):
            writer.write(
                voice_endpoint_observed={
                    "ip": ip,
                    "port": port,
                    "outgoing_packets": int(parts[4]),
                    "incoming_packets": int(parts[5]),
                }
            )
    elif event == "VOICE_PROBE" and len(parts) >= 6:
        probe = {"label": parts[2], "sent": int(parts[3]), "received": int(parts[4]), "valid": int(parts[5])}
        changes: dict[str, Any] = {"last_voice_probe": probe}
        if parts[2] in {"active", "raw"}:
            calibration = dict(writer.payload.get("voice_calibration") or {})
            calibration[parts[2]] = probe
            changes["voice_calibration"] = calibration
        writer.write(**changes)
    elif event == "VOICE_AUTO_MODE" and len(parts) >= 4:
        writer.write(voice_auto_mode=parts[2], voice_auto_reason=parts[3])
        if parts[3] == "raw-reply":
            writer.log(
                "Автопроверка невозможна: сохранённый голосовой сервер отвечает и без "
                "обхода, пакетом с роутера стратегии не различить. Каждый кандидат "
                "проверяется вручную: переподключитесь к голосовому каналу."
            )
    elif event == "VOICE_AUTO" and len(parts) >= 4:
        writer.write(last_voice_auto={"candidate": int(parts[2]), "result": parts[3]})
    elif event == "VOICE_UNCONFIRMED" and len(parts) >= 3:
        writer.write(voice_unconfirmed=True)
    elif event == "START_FAILED":
        writer.write(last_error="|".join(parts[2:])[:500])
    elif event == "RESTORE_ERROR":
        writer.write(restore_error="|".join(parts[2:])[:500])
    elif event == "RESTORED":
        writer.write(nfqws_restored=parts[2] if len(parts) >= 3 else "unknown")
    elif event == "FOUND" and len(parts) >= 4:
        number = int(parts[2])
        if 1 <= number <= len(candidates):
            return candidates[number - 1]
    return None


def ignore_cancel_signals() -> None:
    """Cleanup must finish: a repeated Stop (SIGTERM) or Ctrl-C is ignored.

    Otherwise a second signal raises JobCancelled inside the handler that is
    restoring nfqws2, and the job's final state is never written.
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def read_runtime_state(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            return values
        text = path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def nfqws_process(pid: int) -> bool:
    """True for a live process whose command line names nfqws2."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    return b"nfqws2" in cmdline


def recover_runner_runtime(writer: StateWriter, runner_pid: int) -> None:
    """Undo what a dead runner left: its candidate nfqws2 and a stopped service.

    The runner restores nfqws2 from its traps. A SIGKILLed (or OOM-killed)
    runner cannot: its candidate keeps queue 300 and the official service
    stays stopped. runtime.state names the candidate and the service state.
    """
    runtime_dir = root_path(RUNNER_TMP_LOGICAL.format(pid=runner_pid))
    state = read_runtime_state(runtime_dir / "runtime.state")
    if not state or state.get("runner_pid") != str(runner_pid):
        return
    candidate = state.get("candidate_pid", "")
    if candidate.isdigit() and int(candidate) > 1 and nfqws_process(int(candidate)):
        try:
            os.kill(int(candidate), signal.SIGTERM)
            for _ in range(20):
                if not process_alive(int(candidate)) or not nfqws_process(int(candidate)):
                    break
                time.sleep(0.25)
            else:
                os.kill(int(candidate), signal.SIGKILL)
        except OSError:
            pass
        writer.log(f"Убит оставшийся кандидат nfqws2 (PID {candidate}).")
        writer.write(orphan_candidate_killed=int(candidate))
    if state.get("prepared") == "1":
        init = root_path(NFQWS_INIT_LOGICAL)
        restored = "stopped"
        try:
            subprocess.run([str(init), "firewall_stop"], stdin=subprocess.DEVNULL,
                           capture_output=True, check=False, timeout=60)
            root_path(NFQWS_PIDFILE_LOGICAL).unlink(missing_ok=True)
            if state.get("was_running") == "1":
                subprocess.run([str(init), "start"], stdin=subprocess.DEVNULL,
                               capture_output=True, check=False, timeout=60)
                restored = "running"
                for _ in range(15):
                    if root_path(NFQWS_PIDFILE_LOGICAL).exists():
                        break
                    time.sleep(1)
                else:
                    restored = ""
        except (OSError, subprocess.SubprocessError):
            restored = ""
        if restored:
            writer.write(nfqws_restored=restored, restored_by="job")
            writer.log("nfqws2 восстановлен заданием после принудительной остановки проверки.")
        else:
            writer.write(restore_error="job-could-not-restart-nfqws2")
    shutil.rmtree(runtime_dir, ignore_errors=True)


def stop_and_drain_runner(
    writer: StateWriter,
    process: subprocess.Popen[str],
    candidates: list[tuner.Candidate],
) -> None:
    if process.poll() is None:
        process.terminate()
    killed = False
    try:
        remaining, _ = process.communicate(timeout=RUNNER_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        writer.log("ERROR|runner-did-not-exit-after-SIGTERM")
        process.kill()
        killed = True
        remaining, _ = process.communicate(timeout=10)
    for line in remaining.splitlines():
        writer.log(line)
        parse_event(writer, line, candidates)
    if killed:
        recover_runner_runtime(writer, process.pid)


def main() -> int:
    args = build_parser().parse_args()
    args.search_seed = tuner.resolve_search_seed(args.search_seed)
    job_dir = root_path(JOB_LOGICAL)
    job_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(job_dir, 0o700)
    writer = StateWriter(
        job_dir,
        {
            "format": 1,
            "job_id": args.job_id,
            "service": args.service,
            "status": "preparing",
            "created_utc": utc_now(),
            "pid": os.getpid(),
            "mix_level": args.mix_level,
            "max_candidates": args.max_candidates,
            "search_seed": args.search_seed,
            "source_file": args.source_file,
            "needs_voice_verdict": False,
            "result_available": False,
        },
    )
    lock: Path | None = None
    runner_process: subprocess.Popen[str] | None = None
    candidates: list[tuner.Candidate] = []
    xkeen_before = core_pids()

    def cancel_handler(_signum: int, _frame: object) -> None:
        raise JobCancelled()

    signal.signal(signal.SIGTERM, cancel_handler)
    signal.signal(signal.SIGINT, cancel_handler)

    try:
        validate_args(args)
        route = recorded_route(args.service)
        if route != "zapret":
            raise RuntimeError(
                f"{args.service} currently uses route={route}; switch it to zapret first"
            )
        lock = acquire_project_lock()
        writer.write(xkeen_pids_before=xkeen_before, route=route)
        udp_strategy, udp_range = recorded_udp_settings(read_nfqws_conf())
        youtube_quic: tuple[str, ...] | None = None
        if args.service == "discord-voice":
            writer.write(udp_strategy=udp_strategy, udp_range=udp_range)
            if udp_range == "wide":
                writer.log("Диапазон голоса wide: кандидаты Voice фильтруют 50000-65535.")
        elif args.service == "youtube":
            applied = tuner.applied_youtube_quic(applied_custom_args())
            youtube_quic = tuner.youtube_quic_section(applied)
            origin = "applied" if applied and youtube_quic == applied else "native"
            writer.write(youtube_quic={"origin": origin, "args": list(youtube_quic)})
            if applied and origin == "native":
                writer.log(
                    "Применённый QUIC-профиль YouTube не проходит проверку импорта: "
                    "кандидаты используют встроенный QUIC-профиль проекта."
                )

        if args.source_dir:
            sources, commit = tuner.load_local_sources(args.source_dir)
            writer.write(source_origin="fixture")
        elif root_path("/opt/etc/xkeen-web/flowseal-sources.json").exists():
            sources, commit = tuner.read_source_cache(root_path("/opt/etc/xkeen-web/flowseal-sources.json"))
            writer.write(source_origin="downloaded-cache")
        else:
            sources, commit = tuner.fetch_sources(
                tuner.DEFAULT_REPOSITORY,
                tuner.DEFAULT_REF,
            )
            writer.write(source_origin="github")
        if args.source_file:
            try:
                sources = tuner.select_source(sources, args.source_file)
            except ValueError as error:
                raise RuntimeError(str(error)) from error
        available = tuner.build_candidates(
            args.service,
            sources,
            args.mix_level,
            include_builtin=not args.source_file,
            youtube_quic=youtube_quic,
            voice_range=udp_range,
        )
        candidates = tuner.select_candidates(available, args.max_candidates, args.search_seed)
        writer.log(available_log_line(len(available), args.max_candidates, args.mix_level))
        if not candidates and args.source_file:
            raise RuntimeError(f"{args.source_file} has no {args.service} profile")
        if not candidates:
            raise RuntimeError("no safe candidates were generated")
        writer.write(
            commit=commit,
            candidate_count=len(candidates),
            candidates=candidate_summary(candidates),
        )

        template = RUNNER_TEMPLATE.read_text(encoding="utf-8")
        voice_target = ""
        if args.voice_auto:
            endpoint = load_voice_endpoint(udp_range)
            if endpoint is None:
                raise RuntimeError(
                    "no learned Discord voice server: run a manual Voice check and answer Yes first"
                )
            voice_target = f"{endpoint['ip']}:{endpoint['port']}"
            writer.write(voice_target=voice_target, voice_target_learned_utc=endpoint.get("learned_utc", ""))
        runner = tuner.render_runner(
            template,
            service=args.service,
            candidates=candidates,
            client_ip=args.client_ip or "127.0.0.1",
            voice_duration=args.voice_duration,
            http_timeout=args.http_timeout,
            voice_target=voice_target,
            voice_traffic=args.voice_traffic,
        )
        runner_path = job_dir / "runner.sh"
        runner_path.write_text(runner, encoding="utf-8")
        os.chmod(runner_path, 0o700)
        verdict_path = job_dir / "verdict.txt"
        verdict_path.unlink(missing_ok=True)

        environment = os.environ.copy()
        environment["TUNER_VERDICT_FILE"] = str(verdict_path)
        # The job holds the project lock; the runner checks this PID owns it.
        environment["KD_TUNER_LOCK_HELD"] = str(os.getpid())
        writer.write(status="running", started_utc=utc_now())
        runner_process = subprocess.Popen(
            ["/bin/sh", str(runner_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=environment,
        )
        writer.write(runner_pid=runner_process.pid)
        assert runner_process.stdout is not None

        found: tuner.Candidate | None = None
        output: list[str] = []
        for raw_line in runner_process.stdout:
            line = raw_line.rstrip("\r\n")
            output.append(line)
            writer.log(line)
            event_found = parse_event(writer, line, candidates)
            if event_found is not None:
                found = event_found
        return_code = runner_process.wait(timeout=40)
        # A runner killed from outside (OOM) leaves its candidate running.
        recover_runner_runtime(writer, runner_process.pid)
        if return_code != 0:
            fatal = writer.payload.get("runner_fatal")
            raise RuntimeError(
                f"temporary nfqws2 runner exited with code {return_code}"
                + (f" (FATAL: {fatal})" if fatal else "")
            )
        if writer.payload.get("restore_error"):
            raise RuntimeError("nfqws2 restoration failed: " + str(writer.payload["restore_error"]))

        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            raise RuntimeError(
                f"XKeen core PID changed unexpectedly: {xkeen_before} -> {xkeen_after}"
            )
        report = make_report(args, commit, candidates, found, output)
        atomic_json(job_dir / "result-report.json", report)
        if found is None:
            writer.write(
                status="none",
                finished_utc=utc_now(),
                xkeen_pids_after=xkeen_after,
                needs_voice_verdict=False,
                verification=report["verification"],
            )
            return 0

        if args.service == "discord-voice":
            observed = writer.payload.get("voice_endpoint_observed")
            if observed and not writer.payload.get("voice_unconfirmed"):
                # The user confirmed sound on this server: remember it for the
                # automatic Voice check.
                save_voice_endpoint(observed)
                writer.write(voice_endpoint_learned=True)
        writer.write(
            status="found",
            finished_utc=utc_now(),
            xkeen_pids_after=xkeen_after,
            needs_voice_verdict=False,
            result_available=True,
            found={
                "candidate_id": found.candidate_id,
                "source_name": found.source_name,
                "family": found.family,
                "args": list(found.args),
                "notes": list(found.notes),
            },
            verification=report["verification"],
        )
        return 0
    except JobCancelled:
        ignore_cancel_signals()
        if runner_process is not None:
            stop_and_drain_runner(writer, runner_process, candidates)
        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            writer.write(
                status="error",
                finished_utc=utc_now(),
                error=(
                    "XKeen core PID changed unexpectedly during cancellation: "
                    f"{xkeen_before} -> {xkeen_after}"
                ),
                needs_voice_verdict=False,
                xkeen_pids_after=xkeen_after,
            )
            return 1
        writer.write(
            status="cancelled",
            finished_utc=utc_now(),
            needs_voice_verdict=False,
            xkeen_pids_after=xkeen_after,
        )
        return 130
    except Exception as error:
        ignore_cancel_signals()
        if runner_process is not None:
            stop_and_drain_runner(writer, runner_process, candidates)
        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            error = RuntimeError(
                f"{error}; XKeen core PID changed unexpectedly: "
                f"{xkeen_before} -> {xkeen_after}"
            )
        writer.log(f"ERROR|{type(error).__name__}|{error}")
        writer.write(
            status="error",
            finished_utc=utc_now(),
            error=str(error)[:1000],
            needs_voice_verdict=False,
            xkeen_pids_after=xkeen_after,
        )
        return 1
    finally:
        release_project_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())

"""Tuner jobs: the request of the Zapret autotune, the job process the panel starts for it and its state files."""

import ipaddress
import json
import os
import secrets
import stat
import sys

from kdn.common import fsutil
from kdn.common import errors
from kdn.common import timeutil
from kdn.jobs import jobspec
from kdn.state import nfqws
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.infra import engine
from kdn.web.domain import refusals


# States the autotune job ends in. Any other recorded state with no live job
# process means the job died; the page relies on "active" only.
TERMINAL_TUNER_STATES = frozenset({"idle", "found", "none", "cancelled", "error", "healthy", "unhealthy", "unstable"})


def tuner_status():
    payload = {
        "ok": True,
        "status": "idle",
        "active": False,
        "result_available": False,
        "log_tail": [],
    }
    if jobfiles.COORDINATOR.starting() == "tuner":
        return {**payload, "status": "starting", "active": True}
    try:
        payload.update(fsutil.safe_json_file(cfg.TUNER_STATE))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    active = jobfiles.tuner_active()
    payload["active"] = active
    # Inverted on purpose: a new job state can never leave the page locked.
    pending = payload.get("status") not in TERMINAL_TUNER_STATES
    if pending and not active and not jobfiles.COORDINATOR.start_in_progress():
        payload.update(
            status="error",
            error=_tuner_dead_error(payload),
        )
    if pending and jobfiles.TUNER_STORE.cancel_requested():
        payload["status"] = "cancelling"
    try:
        info = (cfg.TUNER_JOB_DIR / "events.log").lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            lines = (cfg.TUNER_JOB_DIR / "events.log").read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            payload["log_tail"] = [line[:1000] for line in lines[-120:]]
    except OSError:
        pass
    return payload


def _tuner_dead_error(payload):
    error = payload.get("error") or "процесс подбора завершился неожиданно"
    path = cfg.TUNER_JOB_DIR / "process.log"
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return error
            stream.seek(max(0, info.st_size - 4096))
            lines = [line.strip() for line in stream.read(4096).decode("utf-8", errors="replace").splitlines() if line.strip()]
        tail = " | ".join(lines[-3:])[-300:]
        return error + "; process.log: " + tail if tail else error
    except OSError:
        return error


def reconcile_tuner_job(job_id=None, holds_start_lock=False):
    if jobfiles.tuner_active() or (jobfiles.COORDINATOR.start_in_progress() and not holds_start_lock):
        return False
    try:
        state = jobfiles.TUNER_STORE.read_state()
        if state.get("status") in TERMINAL_TUNER_STATES or (job_id is not None and state.get("job_id") != job_id):
            return False
        return jobfiles.TUNER_STORE.settle(state.get("job_id"), expected_statuses={state.get("status")},
            status="error", error=_tuner_dead_error(state), finished_utc=timeutil.utc_now())
    except (OSError, ValueError, RuntimeError):
        return False


def learned_voice_endpoint():
    """Discord voice server remembered for the automatic Voice check, or None."""
    try:
        data = fsutil.safe_json_file(cfg.VOICE_ENDPOINT_FILE, maximum=4096)
        ip = data.get("ip")
        if not isinstance(ip, str):
            return None
        address = ipaddress.ip_address(ip)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    port = data.get("port")
    # voice_ports_allowed also lists 443 and the STUN ports, where no voice server is learned.
    if (
        address.version != 4
        or not address.is_global
        or isinstance(port, bool)
        or not isinstance(port, int)
        or port < 19294
        or not nfqws.voice_ports_allowed(str(port), high=engine.recorded_voice_high()[0])
    ):
        return None
    learned = data.get("learned_utc", "")
    return {"ip": str(address), "port": port, "learned_utc": learned if isinstance(learned, str) else ""}


def validate_tuner_request(body):
    if not isinstance(body, dict):
        raise ValueError("ожидается JSON-объект")
    if set(body) - {"service", "mix_level", "max_candidates", "client_ip", "search_seed", "source_file", "voice_auto", "voice_traffic"}:
        raise ValueError("неизвестные параметры подбора")
    service = body.get("service")
    if service not in cfg.SERVICES:
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
        or not cfg.SOURCE_FILE_NAME.fullmatch(source_file)
    ):
        raise ValueError("файл стратегии должен быть одним general*.bat")
    voice_auto = body.get("voice_auto", False)
    if not isinstance(voice_auto, bool):
        raise ValueError("voice_auto должен быть true или false")
    if voice_auto and service != "discord-voice":
        raise ValueError("автопроверка доступна только для Discord Voice")
    voice_traffic = body.get("voice_traffic", False)
    if not isinstance(voice_traffic, bool):
        raise ValueError("voice_traffic должен быть true или false")
    if voice_traffic and service != "discord-voice":
        raise ValueError("проверка по трафику доступна только для Discord Voice")
    if voice_traffic and voice_auto:
        raise ValueError("выберите один способ проверки Voice")
    return {
        "service": service,
        "mix_level": mix_level,
        "max_candidates": maximum,
        "client_ip": client_ip,
        "search_seed": search_seed,
        "source_file": source_file,
        "voice_auto": voice_auto,
        "voice_traffic": voice_traffic,
    }


def clear_previous_tuner_job():
    jobfiles.TUNER_STORE.clear()


def start_tuner_job(settings, baseline_only=False, holder=None):
    jobfiles.COORDINATOR.ensure_idle(refusals.TUNER_START, holder=holder)
    if jobfiles.COORDINATOR.start_in_progress():
        raise errors.Busy(refusals.TUNER_START.starting)
    status_payload = engine.read_status_fields()
    if not status_payload["ok"]:
        raise RuntimeError(status_payload["output"] or "не удалось прочитать маршруты")
    route = status_payload.get(engine.STATUS_ROUTE_KEYS[settings["service"]], "unknown")
    if route != "zapret":
        raise RuntimeError(
            f"{settings['service']} использует route={route}; сначала включите Zapret"
        )
    if settings.get("voice_auto") and learned_voice_endpoint() is None:
        raise RuntimeError(
            "голосовой сервер ещё не сохранён: один раз пройдите ручную проверку Voice с ответом «Да»"
        )
    with jobfiles.COORDINATOR.exclusive(refusals.TUNER_START, family="tuner", holder=holder):
        return launch_tuner_job(settings, baseline_only=baseline_only)


def launch_tuner_job(settings, baseline_only=False):
    job_id = secrets.token_hex(8)
    command = [
        sys.executable,
        str(cfg.AUTOTUNER),
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
    if settings.get("voice_auto"):
        command.append("--voice-auto")
    if settings.get("voice_traffic"):
        command.append("--voice-traffic")
    if baseline_only:
        command.append("--baseline-only")
    initial = {"format": 1, "job_id": job_id, "service": settings["service"], "status": "queued",
               "created_utc": timeutil.utc_now(), "result_available": False, "needs_voice_verdict": False}
    spec = jobspec.JobSpec("tuner", "baseline" if baseline_only else "tuner", job_id, command,
                           cwd=cfg.PROJECT_DIR, initial=initial)
    jobfiles.TUNER_STORE.prepare(spec)
    try:
        return jobfiles.TUNER_STORE.spawn(spec, on_exit=lambda: reconcile_tuner_job(job_id, holds_start_lock=True))
    except (OSError, RuntimeError) as exc:
        jobfiles.TUNER_STORE.update_state(job_id, status="error", error=str(exc), finished_utc=timeutil.utc_now())
        raise


def cancel_tuner_job():
    return jobfiles.TUNER_STORE.request_cancel("активного подбора нет")


def submit_voice_verdict(works):
    state = fsutil.safe_json_file(cfg.TUNER_STATE)
    if not jobfiles.tuner_active() or state.get("status") != "awaiting_voice":
        raise RuntimeError("сейчас ответ Voice не ожидается")
    if cfg.TUNER_VERDICT.exists():
        raise RuntimeError("ответ для этого кандидата уже отправлен")
    fsutil.atomic_text(cfg.TUNER_VERDICT, "yes\n" if works else "no\n")

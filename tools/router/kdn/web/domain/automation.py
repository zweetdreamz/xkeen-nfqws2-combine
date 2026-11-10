"""Automation: the schedule of the nightly Zapret check, its state file and the job that runs a slot.

The scheduler thread starts a slot at the configured time; the slot job checks the services, searches a profile with
the tuner when one is unhealthy, applies it through the engine and rolls back when the check after it fails. A panel
restart in the middle of the apply is recovered by rolling the pre-apply snapshot back.
"""

from datetime import datetime, timedelta, timezone
import re
import threading
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from kdn.common import fsutil
from kdn.common import errors
from kdn.common import logsetup
from kdn.common import timeutil
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.infra import statestore
from kdn.web.infra import engine
from kdn.web.domain import validation
from kdn.web.domain import flowseal
from kdn.web.domain import health
from kdn.web.domain import tuner_jobs
from kdn.web.domain import refusals


AUTOMATION_RUN_LOCK = threading.Lock()
AUTOMATION_STATE_LOCK = threading.Lock()
AUTOMATION_CONFIG_LOCK = threading.Lock()
AUTOMATION_CANCEL = threading.Event()
CANCEL_GRACE = 150
jobfiles.COORDINATOR.add_hold("automation", lambda: AUTOMATION_RUN_LOCK.locked(), refusals.AUTOMATION_BUSY)
# The only reader and writer of automation-state.json; path and lock are looked up on every call.
STATE = statestore.StateStore(
    lambda: cfg.AUTOMATION_STATE, lambda: AUTOMATION_STATE_LOCK, lambda: {"status": "idle", "history": []}
)
STATE_UNREADABLE = (
    "состояние расписания повреждено (automation-state.json): сначала исправьте или удалите файл "
    "(копия непустого файла — automation-state.json.corrupt) и повторите"
)
# By file: the state_error already told on stderr (one line per error) and whether a copy of the file was made.
_UNREADABLE_REPORTED = {}
try:
    AUTOMATION_ZONE = ZoneInfo("Europe/Moscow")
except ZoneInfoNotFoundError:  # Windows test runtime lacks tzdata; router has it.
    AUTOMATION_ZONE = timezone(timedelta(hours=3), "Europe/Moscow")


def default_automation_config():
    return {
        "version": 1, "enabled": False, "times": ["03:00"],
        "services": {
            service: {"enabled": True, "mix_level": "safe", "max_candidates": 32,
                      "source_file": ""}
            for service in ("youtube", "discord-tcp")
        },
    }


# Every change of automation-config.json that starts from what is on disk goes through it, under the lock.
CONFIG = statestore.StateStore(
    lambda: cfg.AUTOMATION_CONFIG, lambda: AUTOMATION_CONFIG_LOCK, default_automation_config
)


def validate_automation_config(value):
    if not isinstance(value, dict) or set(value) != {"version", "enabled", "times", "services"}:
        raise ValueError("неверный формат расписания")
    if value["version"] != 1 or not isinstance(value["enabled"], bool):
        raise ValueError("неверная версия или состояние расписания")
    times = value["times"]
    if not isinstance(times, list) or not 1 <= len(times) <= 6:
        raise ValueError("задайте от 1 до 6 времён запуска")
    if any(not isinstance(item, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", item)
           for item in times) or len(set(times)) != len(times):
        raise ValueError("время должно быть в формате ЧЧ:ММ без повторов")
    services = value["services"]
    if not isinstance(services, dict) or set(services) != {"youtube", "discord-tcp"}:
        raise ValueError("расписание поддерживает только YouTube и Discord TCP")
    normalized = {}
    for name, item in services.items():
        if not isinstance(item, dict) or set(item) != {"enabled", "mix_level", "max_candidates", "source_file"}:
            raise ValueError(f"неверный сценарий {name}")
        if not isinstance(item["enabled"], bool) or item["mix_level"] not in {"off", "safe", "extended"}:
            raise ValueError(f"неверный режим подбора {name}")
        maximum = item["max_candidates"]
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 64:
            raise ValueError(f"кандидатов {name} должно быть 1–64")
        source = item["source_file"]
        if not isinstance(source, str) or (source and (len(source) > 160 or not cfg.SOURCE_FILE_NAME.fullmatch(source))):
            raise ValueError(f"неверный BAT-файл {name}")
        normalized[name] = {"enabled": item["enabled"], "mix_level": item["mix_level"],
                            "max_candidates": maximum, "source_file": source}
    if value["enabled"] and not any(item["enabled"] for item in normalized.values()):
        raise ValueError("включите хотя бы один сервис")
    return {"version": 1, "enabled": value["enabled"], "times": sorted(times),
            "services": normalized}


def automation_config():
    try:
        return validate_automation_config(fsutil.safe_json_file(cfg.AUTOMATION_CONFIG))
    except FileNotFoundError:
        return default_automation_config()


def automation_state():
    return STATE.read()


def save_automation_state(state):
    """Replace the state file as a whole: the seam the tests seed it through; the panel itself uses STATE."""
    STATE.write(state)


def state_blocker(state):
    """Why nothing may start while the stored state is unreadable, else an empty string."""
    return STATE_UNREADABLE if "state_error" in state else ""


def report_unreadable_state(state, message):
    """Tell stderr about an unreadable state file once per error and keep a copy of it until one has been made."""
    path = str(cfg.AUTOMATION_STATE)
    error = state["state_error"]
    reported, preserved = _UNREADABLE_REPORTED.get(path, (None, False))
    if reported == error:
        return
    logsetup.panel_logger().warning("%s: %s", message, error)
    _UNREADABLE_REPORTED[path] = (error, preserved or STATE.preserve())


def save_automation_config(config):
    """Validate and store the schedule under the lock and return the status; enabling needs a usable state."""
    config = validate_automation_config(config)

    def replace(stored):
        if config["enabled"]:
            # Checked under the lock: a recovery that fails meanwhile turns the schedule off right after this save.
            state = automation_state()
            blocker = state_blocker(state)
            if blocker:
                raise ValueError(blocker)
            if state.get("status") == "recovery-failed":
                raise ValueError("после неудачного отката сначала проверьте nfqws2 и выполните ручное восстановление")
        stored.clear()
        stored.update(config)

    CONFIG.mutate(replace)
    return automation_status()


def automation_status():
    config = automation_config()
    state = automation_state()
    if state.get("status") == "running" and not AUTOMATION_RUN_LOCK.locked():
        # Refresh under the state lock: a slot may have completed or started
        # after the first read. GET still never writes; startup recovery does.
        with AUTOMATION_STATE_LOCK:
            state = automation_state()
            if state.get("status") == "running" and not AUTOMATION_RUN_LOCK.locked():
                state = {**state, "status": "interrupted", "active": False,
                         "error": "панель перезапустилась во время задания; проверьте nfqws2 и отчёт подбора"}
    if state_blocker(state):
        state = {**state, "error": STATE_UNREADABLE}
    now = datetime.now(AUTOMATION_ZONE)
    upcoming = []
    if config["enabled"]:
        for day in (0, 1):
            date = (now + timedelta(days=day)).date()
            for clock in config["times"]:
                hour, minute = map(int, clock.split(":"))
                event = datetime(date.year, date.month, date.day, hour, minute, tzinfo=AUTOMATION_ZONE)
                if event > now:
                    upcoming.append(event.isoformat())
    return {"ok": True, "config": config, "state": state,
            "active": AUTOMATION_RUN_LOCK.locked(), "next_run": min(upcoming) if upcoming else None,
            "timezone": "Europe/Moscow"}


def automation_write(**changes):
    return STATE.update(**changes)


def automation_note(message):
    def append_event(state):
        events = state.get("events", [])
        if not isinstance(events, list):
            events = []
        events.append({"at": timeutil.utc_now(), "message": str(message)[:500]})
        state["events"] = events[-80:]

    STATE.mutate(append_event)


def wait_automation_tuner(pid, deadline_seconds):
    deadline = time.monotonic() + deadline_seconds
    while jobfiles.tuner_process_alive(pid):
        if AUTOMATION_CANCEL.is_set():
            _cancel_and_wait(pid)
            raise RuntimeError("задание остановлено пользователем")
        if time.monotonic() >= deadline:
            _cancel_and_wait(pid)
            raise RuntimeError("подбор превысил лимит времени; восстановление nfqws2 запущено")
        time.sleep(2)
    result = tuner_jobs.tuner_status()
    if result.get("status") == "error":
        raise RuntimeError(str(result.get("error") or "ошибка подборщика")[:500])
    return result


def _cancel_and_wait(pid):
    try:
        tuner_jobs.cancel_tuner_job()
    except (OSError, RuntimeError) as exc:
        # A failed signal or a lost pidfile must not release the automation
        # lease while its known worker may still be restoring nfqws2.
        logsetup.panel_logger().warning("tuner cancellation request failed: %s", exc)
    deadline = time.monotonic() + CANCEL_GRACE
    while jobfiles.tuner_process_alive(pid):
        if time.monotonic() >= deadline:
            raise RuntimeError("подбор не завершился после остановки; проверьте nfqws2")
        time.sleep(1)


def automation_check_service(service, scenario):
    settings = tuner_jobs.validate_tuner_request({
        "service": service, "mix_level": scenario["mix_level"],
        "max_candidates": scenario["max_candidates"],
        "source_file": scenario["source_file"],
    })
    pid = tuner_jobs.start_tuner_job(settings, baseline_only=True, holder="automation")
    result = wait_automation_tuner(pid, 180)
    if result.get("status") not in {"healthy", "unhealthy", "unstable"}:
        raise RuntimeError("проверка текущего профиля не дала результата")
    quic = result.get("baseline_quic") or {}
    settings["baseline_quic_replies"] = quic.get("replies", 0)
    return result["status"], settings


def _transaction_change(operation_id, *, clear=False, **changes):
    def change(state):
        current = state.get('transaction')
        if not isinstance(current, dict) or current.get('operation_id') != operation_id:
            raise RuntimeError('запись автоприменения изменилась; завершение чужой операции запрещено')
        state['transaction'] = None if clear else dict(current, **changes)
    return change


def _cleanup_import_history():
    try:
        result = engine.cleanup_import_history()
        if not result.get('ok'):
            automation_note('Очистка старых focused snapshots отложена')
    except (OSError, RuntimeError, ValueError):
        automation_note('Очистка старых focused snapshots отложена')


def automation_rollback_import(reason):
    transaction = automation_state().get('transaction')
    if not isinstance(transaction, dict) or transaction.get('schema') != 2:
        raise RuntimeError('нет достоверной записи состояния до автоприменения; legacy recovery требует ручной проверки')
    # A direct call has the same pre-lock worker protection as startup recovery.
    try:
        engine.wait_import_idle()
    except RuntimeError:
        disable_automation_after_recovery()
        raise
    source, fingerprint = engine.recovery_source(transaction)
    operation_id = transaction['operation_id']
    pinned = STATE.mutate(_transaction_change(operation_id, original_source=source,
        source_fingerprint=fingerprint, phase='restoring'))['transaction']
    automation_write(phase='rolling-back')
    automation_note('Откат: ' + reason)
    rollback = engine.rollback_import(source=source, operation_context=pinned)
    if not engine.recovery_confirmed(rollback, pinned):
        raise RuntimeError('автоматический откат не подтверждён для всей focused области: '
                           + (rollback.get('output') or 'нет вывода')[-500:])
    STATE.mutate(_transaction_change(operation_id, clear=True))
    automation_note('Предыдущий профиль nfqws2 восстановлен')
    automation_write(last_rollback_utc=timeutil.utc_now())
    _cleanup_import_history()


def with_applied_pointer(pointer, operation_id=None):
    """Attach the observed cue without allowing a stale worker to replace a newer transaction."""
    return _transaction_change(operation_id, applied_pointer=pointer)


def run_automation_slot(slot, config):
    results = {}
    try:
        automation_note("Проверка обновлений Flowseal")
        update = flowseal.check_flowseal_update()
        automation_write(flowseal_commit=update.get("downloaded_commit", ""))
        if not engine.process_running("xray"):
            raise RuntimeError("Xray остановлен: ночной перебор не запускается")
        if not engine.process_running("nfqws2"):
            raise RuntimeError("nfqws2 остановлен: ночной перебор не запускается")
        for service in ("youtube", "discord-tcp"):
            scenario = config["services"][service]
            if not scenario["enabled"]:
                results[service] = "disabled"
                continue
            if AUTOMATION_CANCEL.is_set():
                raise RuntimeError("задание остановлено пользователем")
            route = engine.current_routes_fast().get(service)
            if route != "zapret":
                results[service] = "skipped-route"
                automation_note(f"{service}: пропущен, маршрут {route}")
                continue
            automation_write(current_service=service, phase="checking")
            verdict, settings = automation_check_service(service, scenario)
            pre_quic_replies = settings.get("baseline_quic_replies", 0)
            if verdict == "healthy":
                if service == "youtube" and pre_quic_replies == 0:
                    results[service] = "quic-unverified"
                    automation_note("youtube: HTTP прошёл, но QUIC не ответил; подбор не запускается без подтверждённой причины")
                else:
                    results[service] = "healthy"
                    automation_note(f"{service}: действующий профиль прошёл две проверки")
                continue
            if verdict == "unstable":
                results[service] = "unstable"
                automation_note(f"{service}: нестабильный результат, перебор и применение пропущены")
                continue
            automation_note(f"{service}: проверка не прошла, запускаю перебор")
            automation_write(phase="searching")
            pid = tuner_jobs.start_tuner_job(settings, holder="automation")
            found = wait_automation_tuner(pid, 7200)
            if found.get("status") == "none":
                results[service] = "not-found"
                automation_note(f"{service}: рабочий кандидат не найден")
                continue
            if found.get("status") != "found" or not found.get("result_available"):
                raise RuntimeError(f"{service}: подбор завершился без проверенного кандидата")
            report = fsutil.safe_json_file(cfg.TUNER_RESULT)
            profile = validation.validate_report(report)
            if profile["service"] != service:
                raise RuntimeError("сервис найденного профиля не совпадает")
            candidate_id = profile["candidate_id"]
            if AUTOMATION_CANCEL.is_set():
                raise RuntimeError("задание остановлено до применения")
            pending = engine.new_import_transaction(profile)
            automation_write(phase="applying", candidate_id=candidate_id, transaction=pending)
            automation_note(f"{service}: применяю кандидат {candidate_id}; движок создаёт снимок")
            applied = engine.apply_profile(profile, operation_context=pending)
            if not applied["ok"]:
                automation_rollback_import("движок не подтвердил применение")
                raise RuntimeError(f"{service}: применение не удалось: " + (applied.get("output") or "нет вывода")[-500:])
            STATE.mutate(with_applied_pointer(engine.import_pointer_value(), pending["operation_id"]))
            try:
                if AUTOMATION_CANCEL.is_set():
                    raise RuntimeError("задание остановлено после применения")
                automation_write(phase="verifying")
                post_health = health.config_health()
                if not post_health.get("all_ok"):
                    raise RuntimeError("проверка конфигурации после применения не прошла")
                post_verdict, post_settings = automation_check_service(service, scenario)
                if post_verdict != "healthy":
                    raise RuntimeError("сервис не прошёл две проверки после применения")
                if service == "youtube" and post_settings.get("baseline_quic_replies", 0) < pre_quic_replies:
                    raise RuntimeError("после применения потерян ранее работавший QUIC")
                if AUTOMATION_CANCEL.is_set():
                    raise RuntimeError("задание остановлено после применения")
            except Exception as exc:
                automation_rollback_import(str(exc))
                raise RuntimeError(f"{service}: новый профиль откатан: {exc}") from exc
            results[service] = "applied" if service != "youtube" or pre_quic_replies else "applied-quic-unverified"
            STATE.mutate(_transaction_change(pending["operation_id"], clear=True))
            _cleanup_import_history()
            automation_note(f"{service}: профиль {candidate_id} применён и проверен" +
                            ("; QUIC не был подтверждён" if results[service] == "applied-quic-unverified" else ""))
        final = "cancelled" if AUTOMATION_CANCEL.is_set() else "completed"
        automation_write(status=final, active=False, phase="done", current_service="",
                         finished_utc=timeutil.utc_now(), results=results)
    except Exception as exc:
        automation_note(f"Ошибка: {exc}")
        error = str(exc)[:1000]

        def finish_with_error(state):
            # A transaction that is still pending needs the recovery: decided on the state this write replaces.
            pending = isinstance(state.get("transaction"), dict)
            state.update(status="cancelled" if AUTOMATION_CANCEL.is_set() else "error",
                         active=False, phase="recovery-needed" if pending else "failed", current_service="",
                         finished_utc=timeutil.utc_now(), error=error, results=results)

        STATE.mutate(finish_with_error)
    finally:
        AUTOMATION_CANCEL.clear()
        AUTOMATION_RUN_LOCK.release()


def launch_automation_slot(slot, config):
    if state_blocker(automation_state()):
        # Not even the note of a missed slot: a write would replace the file nobody can read.
        return False
    if not AUTOMATION_RUN_LOCK.acquire(blocking=False):
        # Do not run a missed slot immediately after the previous long job ends.
        automation_write(last_slot=slot)
        return False
    started = False
    try:
        # The scheduler's state/config snapshots may predate a recovery that just
        # released this lease. Never turn its failure or pending transaction into
        # a fresh run. Read the schedule again while holding the same lease.
        state = automation_state()
        if (state_blocker(state) or state.get("status") == "recovery-failed"
                or isinstance(state.get("transaction"), dict)):
            return False
        config = automation_config()
        now = datetime.now(AUTOMATION_ZONE)
        if (not config["enabled"] or now.strftime("%H:%M") not in config["times"]
                or slot != now.strftime("%Y-%m-%dT%H:%M%z") or state.get("last_slot") == slot):
            return False
        try:
            jobfiles.COORDINATOR.ensure_idle(refusals.AUTOMATION_START, holder="automation")
            busy = jobfiles.COORDINATOR.start_in_progress()
        except errors.Busy:
            busy = True
        if busy:
            automation_write(last_slot=slot, status="skipped", active=False,
                             finished_utc=timeutil.utc_now(), error="роутер занят другим заданием")
            return False
        AUTOMATION_CANCEL.clear()
        automation_write(last_slot=slot, status="running", active=True, phase="updating",
                         started_utc=timeutil.utc_now(), finished_utc="", current_service="",
                         error="", results={}, events=[], last_rollback_utc="")
        threading.Thread(target=run_automation_slot, args=(slot, config), daemon=True).start()
        started = True
        return True
    finally:
        # The worker owns this lock once it has started.
        if not started:
            AUTOMATION_RUN_LOCK.release()


def automation_loop():
    while True:
        try:
            state = automation_state()
            if state_blocker(state):
                report_unreadable_state(state, "automation scheduler paused, state unreadable")
            else:
                _UNREADABLE_REPORTED.pop(str(cfg.AUTOMATION_STATE), None)
                if (isinstance(state.get("transaction"), dict)
                        and state.get("status") != "recovery-failed"
                        and not AUTOMATION_RUN_LOCK.locked()):
                    start_automation_recovery(blocking=False)
                config = automation_config()
                now = datetime.now(AUTOMATION_ZONE)
                clock = now.strftime("%H:%M")
                slot = now.strftime("%Y-%m-%dT%H:%M%z")
                if (state.get("status") != "recovery-failed" and config["enabled"] and clock in config["times"]
                        and state.get("last_slot") != slot):
                    launch_automation_slot(slot, config)
        except Exception as exc:
            logsetup.panel_logger().warning("automation scheduler: %s: %s", type(exc).__name__, exc)
        time.sleep(15)


def disable_automation_after_recovery():
    def turn_off(stored):
        if "state_error" in stored:
            raise ValueError(stored["state_error"])
        config = validate_automation_config(stored)
        if not config["enabled"]:
            return False
        stored.clear()
        stored.update(config, enabled=False)

    try:
        CONFIG.mutate(turn_off)
    except (OSError, ValueError) as exc:
        automation_note(f"Не удалось выключить расписание после прерывания: {exc}")


def recover_automation_transaction():
    try:
        automation_note("Панель перезапустилась во время автоприменения; проверяю откат")
        last_error = None
        for attempt in range(3):
            try:
                automation_rollback_import("незавершённое автоприменение после перезапуска")
                last_error = None
                break
            except engine.ImportWorkerPending:
                raise  # Do not multiply the bounded worker deadline by recovery retries.
            except (OSError, RuntimeError, ValueError) as exc:
                last_error = exc
                if "не совпал с исходным" in str(exc) or attempt == 2:
                    break
                time.sleep(15)
        if last_error is not None:
            raise RuntimeError(str(last_error))
        automation_write(status="recovered", active=False, phase="done", current_service="",
                         finished_utc=timeutil.utc_now(), error="Автоприменение прервано; исходный профиль восстановлен")
    except Exception as exc:
        automation_note(f"КРИТИЧНО: автоматическое восстановление не завершено: {exc}")
        automation_write(status="recovery-failed", active=False, phase="recovery-needed",
                         finished_utc=timeutil.utc_now(), error=str(exc)[:1000])
    finally:
        disable_automation_after_recovery()
        AUTOMATION_RUN_LOCK.release()


def start_automation_recovery(blocking=True):
    state = automation_state()
    if "state_error" in state:
        report_unreadable_state(state, "automation recovery state unreadable")
        return
    if state.get("status") == "recovery-failed":
        return
    if isinstance(state.get("transaction"), dict):
        if not AUTOMATION_RUN_LOCK.acquire(blocking=blocking):
            return
        try:
            automation_write(status="recovering", active=True, phase="recovering",
                             error="Проверяю прерванное автоприменение")
            threading.Thread(target=recover_automation_transaction, daemon=True,
                             name="zapret-automation-recovery").start()
        except Exception:
            AUTOMATION_RUN_LOCK.release()
            raise
    elif state.get("status") == "running":
        automation_write(status="interrupted", active=False, phase="failed",
                         finished_utc=timeutil.utc_now(), error="панель перезапустилась во время проверки; изменений профиля не было")

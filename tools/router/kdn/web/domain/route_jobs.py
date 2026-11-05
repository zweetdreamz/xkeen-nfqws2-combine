"""Route jobs: a route switch, a VPN node switch or a history rollback, run by a detached worker process.

The panel writes the job state and the history record, then starts the worker (the entry file with --route-job).
The worker runs the engine command and records the result. Status polls only present a view; the reaper,
explicit reconciliation or the next launch persist a dead job's failure and its pre-apply snapshot.
"""

import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading
import time

from kdn.common import fsutil
from kdn.common import paths
from kdn.common import proc
from kdn.common import timeutil
from kdn.common import errors
from kdn.jobs import jobspec
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.infra import engine
from kdn.web.domain import history
from kdn.web.domain import refusals


# Serializes the one-time conversion of a dead route job into "failed".
ROUTE_STATE_LOCK = threading.RLock()
ROUTE_STATUS_FIELDS = ("ok", "job_id", "operation", "service", "mode", "status", "stage", "stage_label", "progress",
                       "active", "result_ok", "code", "error", "snapshot", "rollback_of", "outbound_tag",
                       "created_utc", "started_utc", "finished_utc", "output")
STATUS_OUTPUT_TAIL = 400
STATUS_ERROR_LIMIT = 300
STATUS_BYTE_LIMIT = 2048
STATE_OUTPUT_LIMIT = 100_000
STATE_BYTE_LIMIT = 400 * 1024
SWITCH_OPERATIONS = ("switch", "rollback", "vpn-node", "vpn-recover")


def route_apply_log():
    """Text of the route worker's apply.log, empty if it is missing or not a regular file."""
    try:
        info = cfg.ROUTE_APPLY_LOG.lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            return cfg.ROUTE_APPLY_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""


def reconcile_route_job(holds_start_lock=False):
    """Mark a queued/running route job whose worker process is gone as failed.

    Shared by the reaper and the next job launch, so a dead worker's
    snapshot reaches the history before its job files are cleared. A job being
    started holds JOB_START_LOCK until its PID file exists, so a poll leaves
    the state alone while the lock is held; only the lock holder passes True.
    """
    try:
        payload = fsutil.safe_json_file(cfg.ROUTE_STATE)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if (
        payload.get("status") in {"queued", "running"}
        and not jobfiles.route_active()
        and (holds_start_lock or not jobfiles.COORDINATOR.start_in_progress())
    ):
        return bool(mark_dead_route_job(payload, route_apply_log()))
    return None


def dead_route_changes(payload, apply_log):
    text = ("процесс переключения завершился неожиданно" if payload.get("operation", "switch") in SWITCH_OPERATIONS
            else "процесс операции завершился неожиданно")
    return {"result_ok": False, "active": False, "status": "failed", "stage": "failed",
            "stage_label": "Процесс прерван", "error": payload.get("error") or text,
            "snapshot": payload.get("snapshot") or engine.parse_snapshot_from_output(apply_log),
            "finished_utc": timeutil.utc_now()}


def route_view(holds_start_lock=False):
    payload = {"ok": True, "status": "idle", "active": False, "output": ""}
    try:
        payload.update(jobfiles.ROUTE_STORE.read_state())
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    payload["active"] = jobfiles.route_active()
    if (payload.get("status") in {"queued", "running"} and not payload["active"]
            and (holds_start_lock or not jobfiles.COORDINATOR.start_in_progress())):
        payload.update(dead_route_changes(payload, route_apply_log()))
    payload["ok"] = True
    return payload


def route_status():
    if jobfiles.COORDINATOR.starting() == "route":
        return {"ok": True, "status": "starting", "active": True, "output": ""}
    payload = {key: value for key, value in route_view().items() if key in ROUTE_STATUS_FIELDS}
    payload["output"] = str(payload.get("output", ""))[-STATUS_OUTPUT_TAIL:]
    if "error" in payload:
        payload["error"] = str(payload["error"])[:STATUS_ERROR_LIMIT]
    for field in ("output", "error"):
        while len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > STATUS_BYTE_LIMIT and payload.get(field):
            value = payload[field]
            keep = len(value) // 2
            payload[field] = (value[-keep:] if field == "output" else value[:keep]) if keep else ""
    if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > STATUS_BYTE_LIMIT:
        # Invalid metadata cannot be shortened without changing identifiers.
        raise ValueError("метаданные задания превышают лимит статуса")
    return payload


def route_result(job_id=None):
    payload = route_view()
    if job_id is not None and payload.get("job_id") != job_id:
        raise errors.NotFound("состояние задания изменилось")
    result = payload.get("result")
    payload = {**payload, **result} if isinstance(result, dict) else payload
    payload.setdefault("job_id", None)
    payload.setdefault("result_ok", None)  # idle or still running, no final outcome yet
    return payload


def mark_dead_route_job(payload, apply_log):
    """Record once that the route worker died, keeping its pre-apply snapshot.

    The engine prints "Snapshot created:" before it changes anything, so a
    worker killed later (reboot, OOM) still leaves a usable snapshot in
    apply.log. The failed state is written to ROUTE_STATE and the history
    exactly once; later polls see "failed" and change nothing.
    """
    with ROUTE_STATE_LOCK:
        try:
            current = fsutil.safe_json_file(cfg.ROUTE_STATE)
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            return {}
        if current.get("job_id") != payload.get("job_id") or current.get("status") not in {"queued", "running"}:
            return {}
        changes = dead_route_changes(current, apply_log)
        job_id = payload.get("job_id")
        try:
            changed = jobfiles.ROUTE_STORE.settle(job_id, expected_statuses={"queued", "running"}, **changes)
        except RuntimeError:  # a worker appeared after the first liveness check
            return {}
        if not changed:
            return {}
        discard_payload(job_id)
        if current.get("_history_enabled", True):
            record = {key: value for key, value in changes.items() if key not in {"active", "stage", "stage_label"}}
            if apply_log:
                record["output_tail"] = apply_log[-12000:]
            history.update_history(job_id, **record)
        return changes


def clear_previous_route_job():
    with ROUTE_STATE_LOCK:
        jobfiles.ROUTE_STORE.clear()


def update_route_state(job_id, **changes):
    return jobfiles.ROUTE_STORE.update_state(job_id, **changes)


def stage_payload(job_id, data):
    with ROUTE_STATE_LOCK:
        fsutil.atomic_text(jobfiles.route_payload_path(), json.dumps({"job_id": job_id, "data": data}, ensure_ascii=False) + "\n")


def take_payload(job_id):
    with ROUTE_STATE_LOCK:
        try:
            payload = fsutil.safe_json_file(jobfiles.route_payload_path())
        except FileNotFoundError as exc:
            raise LookupError("данные задания отсутствуют") from exc
        if payload.get("job_id") != job_id:
            raise LookupError("состояние задания изменилось")
        if "data" not in payload:
            raise LookupError("данные задания повреждены")
        jobfiles.route_payload_path().unlink()
        return payload["data"]


def discard_payload(job_id=None):
    with ROUTE_STATE_LOCK:
        path = jobfiles.route_payload_path()
        if job_id is not None:
            try:
                if fsutil.safe_json_file(path).get("job_id") != job_id:
                    return False
            except FileNotFoundError:
                return False
            except (OSError, ValueError):
                # A corrupt payload can be removed only while its job still
                # owns the family, never on behalf of an older reaper.
                if jobfiles.ROUTE_STORE.job_id() != job_id:
                    return False
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False


def validate_route(service, mode):
    if service not in cfg.ROUTE_REQUEST_SERVICES:
        raise ValueError("неподдерживаемый сервис")
    allowed = {"direct", "zapret", "vpn"}
    if service == "telegram":
        if mode == "zapret":
            raise ValueError("режим Zapret для Telegram удалён: выберите Direct, VPN, WS или Выкл")
        allowed = {"direct", "vpn", "ws", "unmanaged"}
    if mode not in allowed:
        raise ValueError("неподдерживаемый маршрут")
    return service, mode


def launch_route_worker(state, worker_args, *, history=True, payload=None):
    # Keep prepare/payload publication atomic with respect to old reapers in
    # this panel process. JobStore additionally rechecks job.id under its lock.
    with ROUTE_STATE_LOCK:
        reconcile_route_job(holds_start_lock=True)
        initial = dict(state)
        if not history:
            initial["_history_enabled"] = False
        spec = jobspec.JobSpec("route", state.get("operation", worker_args[0]), state["job_id"],
                               [sys.executable, str(cfg.ENTRY), "--route-job", state["job_id"], *worker_args],
                               cwd=cfg.PROJECT_DIR, env={paths.PROJECT_DIR_ENV: str(cfg.PROJECT_DIR)}, initial=initial)
        jobfiles.ROUTE_STORE.prepare(spec)
        def on_exit():
            with ROUTE_STATE_LOCK:
                try:
                    # The known child has exited; do not lose an early-exit
                    # reconciliation just because its caller still holds the
                    # coordinator's start lock for a few instructions.
                    reconcile_route_job(holds_start_lock=True)
                finally:
                    discard_payload(state["job_id"])

        try:
            if history:
                _write_initial_history(initial)
            if payload is not None:
                stage_payload(state["job_id"], payload)
            pid = jobfiles.ROUTE_STORE.spawn(spec, on_exit=on_exit)
        except BaseException as exc:
            try:
                fail_route_job(state["job_id"], str(exc), history=history)
            finally:
                discard_payload(state["job_id"])
            raise
        return {**state, "pid": pid}


def _write_initial_history(state):
    record = {key: value for key, value in state.items()
              if key not in {"ok", "active", "output", "stage_label", "progress", "_history_enabled"}}
    history.write_history(record)


def start_route_job(service, mode):
    service, mode = validate_route(service, mode)
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family="route"):
        engine.require_supported_target()
        before = engine.current_routes_fast()
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
            "created_utc": timeutil.utc_now(),
            "output": "",
        }
        return launch_route_worker(state, ["switch", service, mode])


def start_history_rollback(history_id):
    # An unpolled dead job may be the requested restore point.
    reconcile_route_job()
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family="route"):
        engine.require_supported_target()
        reconcile_route_job(holds_start_lock=True)
        source = history.read_history_item(history_id)
        # A failed operation may be half-applied (worker killed after the
        # snapshot); its pre-apply snapshot is still a valid restore point.
        if source.get("status") not in {"completed", "failed"}:
            raise ValueError("откат доступен только для завершённой или прерванной операции")
        snapshot_value = source.get("snapshot", "")
        snapshot = Path(snapshot_value) if isinstance(snapshot_value, str) else Path("")
        if not snapshot_value or not engine.safe_snapshot(snapshot):
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
            "before_routes": engine.current_routes_fast(),
            "requested_routes": source.get("before_routes", {}),
            "target_snapshot": str(snapshot),
            "created_at": int(time.time()),
            "created_utc": timeutil.utc_now(),
            "output": "",
        }
        return launch_route_worker(
            state,
            ["rollback", history_id, str(snapshot)],
        )


def run_route_command(command, job_id, operation, timeout=900):
    started = time.monotonic()
    timed_out = False
    last_stage = None
    with cfg.ROUTE_APPLY_LOG.open("w+b") as capture:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=capture,
            stderr=subprocess.STDOUT,
            env=proc.command_env(),
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
                stage = engine.route_stage(preview, operation)
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
                proc.stop_process_group(process, 120)
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


def begin_route_job(job_id):
    with ROUTE_STATE_LOCK:
        if not update_route_state(job_id, status="running", stage="preflight", stage_label="Проверка конфигурации",
                                  progress=10, active=True, started_utc=timeutil.utc_now()):
            return False
        state = jobfiles.ROUTE_STORE.read_state()
        if state.get("_history_enabled", True):
            history.update_history(job_id, status="running", started_utc=state["started_utc"])
        return True


def _fit_finished_state(state, output):
    keep = min(len(output), STATE_OUTPUT_LIMIT)
    while True:
        state["output"] = (("[...начало вывода сокращено...]\n" if keep < len(output) else "") +
                           (output[-keep:] if keep else ""))
        if len((json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode("utf-8")) <= STATE_BYTE_LIMIT:
            return state
        if not keep:
            raise ValueError("метаданные результата превышают лимит состояния")
        keep //= 2


def _record_finish(job_id, state, output):
    history.update_history(job_id, result_ok=state["result_ok"], status=state["status"], code=state["code"],
                           snapshot=state["snapshot"], after_routes=state["after_routes"], output_tail=output[-12000:],
                           finished_utc=state["finished_utc"], **({"error": state["error"]} if state.get("error") else {}))


def finish_route_job(job_id, payload, *, history=True, extras=None):
    with ROUTE_STATE_LOCK:
        try:
            state = jobfiles.ROUTE_STORE.read_state()
        except (OSError, ValueError):
            return 2
        if state.get("job_id") != job_id:
            return 2
        output = str(payload.get("output", ""))
        ok = bool(payload["ok"])
        final = "completed" if ok else "failed"
        result = {key: value for key, value in payload.items() if key not in {"ok", "code", "output"}}
        result.update(extras or {})
        state.update(result_ok=ok, active=False, status=final, stage=final, progress=100,
                     stage_label="Готово" if ok else "Ошибка и откат", code=payload.get("code", 0 if ok else 1),
                     snapshot=engine.parse_snapshot_from_output(output), after_routes=engine.current_routes_fast(),
                     finished_utc=timeutil.utc_now(), result=result)
        if not ok:
            state["error"] = str(payload.get("error") or output)[:3000]
        state = _fit_finished_state(state, output)
        if not update_route_state(job_id, **{key: value for key, value in state.items() if key != "job_id"}):
            return 2
        if history and state.get("_history_enabled", True):
            _record_finish(job_id, state, output)
        return state["code"]


def fail_route_job(job_id, error, label="Ошибка запуска", history=True):
    with ROUTE_STATE_LOCK:
        try:
            state = jobfiles.ROUTE_STORE.read_state()
        except (OSError, ValueError):
            return False
        if state.get("job_id") != job_id or state.get("status") in {"completed", "failed"}:
            return False
        changes = {"result_ok": False, "active": False, "status": "failed", "stage": "failed",
                   "stage_label": label, "error": str(error)[:3000], "finished_utc": timeutil.utc_now()}
        changed = update_route_state(job_id, **changes)
        if changed and history and state.get("_history_enabled", True):
            _record_failure(job_id, changes)
        return changed


def _record_failure(job_id, changes):
    history.update_history(job_id, **{key: value for key, value in changes.items()
                                      if key not in {"active", "stage", "stage_label"}})


def run_route_job(job_id, operation, subject, target):
    try:
        if operation == "switch":
            service, mode = validate_route(subject, target)
            command = engine.service_switch_command(service, mode)
        elif operation == "vpn-node":
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", subject):
                raise ValueError("некорректное имя VPN-ноды")
            command = [sys.executable, str(cfg.VPN_MANAGER_SCRIPT), "activate", subject]
        elif operation == "vpn-recover":
            command = [sys.executable, str(cfg.VPN_MANAGER_SCRIPT), "recover"]
        elif operation == "rollback":
            history.history_path(subject)
            snapshot = Path(target)
            if not engine.safe_snapshot(snapshot):
                raise ValueError("небезопасный snapshot для отката")
            command = engine.rollback_snapshot_command(snapshot)
        else:
            raise ValueError("неподдерживаемый тип route-job")
    except (OSError, ValueError) as exc:
        fail_route_job(job_id, str(exc))
        return 2
    if not begin_route_job(job_id):
        return 2
    payload = run_route_command(command, job_id, operation)
    return finish_route_job(job_id, payload)

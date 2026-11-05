"""Diagnostic jobs: the health diagnostics the panel starts as a background process and reports on."""

import json
import secrets
import sys

from kdn.common import fsutil
from kdn.common import timeutil
from kdn.jobs import jobspec
from kdn.web.infra import config as cfg
from kdn.web.infra import engine
from kdn.web.infra import jobfiles
from kdn.web.domain import refusals


def diagnostic_status():
    payload = {
        "ok": True,
        "status": "idle",
        "active": False,
        "progress": 0,
        "results": [],
    }
    if jobfiles.COORDINATOR.starting() == "diagnostic":
        return {**payload, "status": "starting", "active": True}
    try:
        payload.update(fsutil.safe_json_file(cfg.DIAGNOSTIC_STATE))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload.update(status="error", error=f"state: {exc}")
    active = jobfiles.diagnostic_active()
    # Standard/DPI moved into the browser. Their old persistent reports must
    # not be mistaken for results of the current browser session.
    if payload.get("kind") in {"standard", "dpi"} and not active:
        return {"ok": True, "status": "idle", "active": False, "progress": 0, "results": []}
    payload["active"] = active
    pending = payload.get("status") in {"queued", "running", "cancelling"}
    if pending and not active and not jobfiles.COORDINATOR.start_in_progress():
        payload.update(status="error", error=payload.get("error") or "процесс диагностики завершился неожиданно")
    if pending and jobfiles.DIAGNOSTIC_STORE.cancel_requested():
        payload["status"] = "cancelling"
    payload["ok"] = True
    return payload


def clear_previous_diagnostic_job():
    jobfiles.DIAGNOSTIC_STORE.clear()


def reconcile_diagnostic_job(job_id=None, holds_start_lock=False):
    if jobfiles.diagnostic_active() or (jobfiles.COORDINATOR.start_in_progress() and not holds_start_lock):
        return False
    try:
        state = jobfiles.DIAGNOSTIC_STORE.read_state()
        if state.get("status") not in {"queued", "running", "cancelling"} or (job_id is not None and state.get("job_id") != job_id):
            return False
        return jobfiles.DIAGNOSTIC_STORE.settle(state.get("job_id"), expected_statuses={state.get("status")},
            status="error", error=state.get("error") or "процесс диагностики завершился неожиданно", finished_utc=timeutil.utc_now())
    except (OSError, ValueError, RuntimeError):
        return False


def start_diagnostic_job(kind):
    if kind != "health":
        raise ValueError("Standard/DPI tests выполняются только в браузере")
    with jobfiles.COORDINATOR.exclusive(refusals.DIAGNOSTIC_START, family="diagnostic"):
        engine.require_supported_target()
        return launch_diagnostic_job(kind)


def launch_diagnostic_job(kind):
    job_id = secrets.token_hex(8)
    initial = {
        "ok": True,
        "job_id": job_id,
        "kind": kind,
        "status": "queued",
        "active": True,
        "progress": 0,
        "created_utc": timeutil.utc_now(),
        "results": [],
    }
    command = [sys.executable, str(cfg.DIAGNOSTICS), "--kind", kind, "--job-id", job_id]
    spec = jobspec.JobSpec("diagnostic", kind, job_id, command, cwd=cfg.PROJECT_DIR, initial=initial)
    jobfiles.DIAGNOSTIC_STORE.prepare(spec)
    try:
        pid = jobfiles.DIAGNOSTIC_STORE.spawn(spec, on_exit=lambda: reconcile_diagnostic_job(job_id, holds_start_lock=True))
    except (OSError, RuntimeError) as exc:
        initial.update(active=False, status="error", error=str(exc), finished_utc=timeutil.utc_now())
        jobfiles.DIAGNOSTIC_STORE.update_state(job_id, **{key: value for key, value in initial.items() if key != "job_id"})
        raise
    initial["pid"] = pid
    return initial


def cancel_diagnostic_job():
    return jobfiles.DIAGNOSTIC_STORE.request_cancel("активной диагностики нет")

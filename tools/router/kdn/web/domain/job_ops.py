"""Worker-side router operations and periodic reconciliation, never HTTP admission."""
import json
import re
import threading

from kdn.common import logsetup
from kdn.web.infra import config as cfg
from kdn.web.infra import engine
from kdn.web.infra import jobfiles
from kdn.web.domain import diagnostic_jobs
from kdn.web.domain import health
from kdn.web.domain import route_jobs
from kdn.web.domain import tuner_jobs
from kdn.web.domain import vpn


OPERATIONS = ("xkeen", "apply-profile", "import-clear", "import-rollback", "vpn-add", "vpn-check", "inspection-setup", "dns-mode")
RECONCILE_INTERVAL = 30


def with_post_checks(payload):
    """Attach health only to a successful change; a failed check cannot erase the change's result."""
    if payload.get("ok"):
        try:
            payload["health"] = health.config_health()
        except Exception as exc:
            payload["health_error"] = f"{type(exc).__name__}: {exc}"[:500]
    return payload


def _validate(operation, subject, target):
    if target != "-":
        raise ValueError("неподдерживаемые аргументы операции")
    if operation == "xkeen":
        engine.xkeen_command(subject)
    elif operation == 'dns-mode' and subject not in ('vless', 'doh'):
        raise ValueError('DNS mode: vless or doh')
    elif operation == "apply-profile" and subject not in {"import", "tuner", "version"}:
        raise ValueError("неподдерживаемый режим применения")
    elif operation == "import-clear" and subject not in cfg.SERVICES:
        raise ValueError("неподдерживаемый сервис")
    elif operation == "import-rollback" and subject != "-":
        raise ValueError("неподдерживаемые аргументы операции")
    elif operation in {"vpn-add", "vpn-check"} and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", subject):
        raise ValueError("некорректное имя VPN-ноды")


def _checked(job_id, payload):
    if payload.get("ok"):
        route_jobs.update_route_state(job_id, stage="verify", stage_label="Проверка результата", progress=94)
    return with_post_checks(payload)


def _execute(job_id, operation, subject):
    if operation == 'dns-mode':
        return engine.set_dns_mode(subject)
    if operation == 'inspection-setup':
        return engine.setup_route_checker()
    if operation == "xkeen":
        return engine.run_xkeen_action(engine.xkeen_command(subject), xray_expected=subject != "stop")
    if operation == "apply-profile":
        return _checked(job_id, engine.apply_profile(route_jobs.take_payload(job_id)))
    if operation == "import-clear":
        return _checked(job_id, engine.clear_imported_profile(subject))
    if operation == "import-rollback":
        return _checked(job_id, engine.rollback_import())
    if operation == "vpn-add":
        data = route_jobs.take_payload(job_id)
        name = data.get('name') if isinstance(data, dict) else None
        expected = name if isinstance(name, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,31}', name) else 'new-node'
        if not isinstance(name, str) or expected != subject or not isinstance(data.get("source"), str):
            raise ValueError("данные VPN-ноды не совпадают с заданием")
        result = vpn.vpn_manager().add(data["name"], data["source"])
        return {"ok": True, "code": 0, "output": result.get('warning', ''), "node": result["node"]}
    result = vpn.vpn_manager().check(subject)
    return {"ok": True, "code": 0, "output": result.get('warning', ''), "health": result["health"]}


def run_job(job_id, operation, subject, target):
    if operation not in OPERATIONS:
        return route_jobs.run_route_job(job_id, operation, subject, target)
    try:
        try:
            _validate(operation, subject, target)
        except ValueError as exc:
            route_jobs.fail_route_job(job_id, str(exc), history=False)
            return 2
        if not route_jobs.begin_route_job(job_id):
            return 2
        route_jobs.update_route_state(job_id, stage="running", stage_label="Выполнение", progress=50)
        try:
            payload = _execute(job_id, operation, subject)
        except LookupError as exc:
            route_jobs.fail_route_job(job_id, str(exc), history=False)
            return 2
        except (OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            payload = {"ok": False, "code": 1, "output": str(exc)}
        return route_jobs.finish_route_job(job_id, payload, history=False)
    finally:
        route_jobs.discard_payload(job_id)


def reconcile_jobs():
    changed = []
    for family, callback in (("route", route_jobs.reconcile_route_job), ("tuner", tuner_jobs.reconcile_tuner_job),
                             ("diagnostic", diagnostic_jobs.reconcile_diagnostic_job)):
        if callback():
            changed.append(family)
    with route_jobs.ROUTE_STATE_LOCK:
        if not jobfiles.route_active() and not jobfiles.COORDINATOR.start_in_progress():
            if route_jobs.discard_payload() and "route" not in changed:
                changed.append("route")
    return changed


def reconcile_loop(stop=None, interval=RECONCILE_INTERVAL):
    stop = threading.Event() if stop is None else stop
    while not stop.is_set():
        try:
            reconcile_jobs()
        except Exception:
            logsetup.panel_logger().exception("job reconciliation failed")
        stop.wait(interval)

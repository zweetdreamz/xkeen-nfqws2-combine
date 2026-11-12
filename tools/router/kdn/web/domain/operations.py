"""Admission and file-only preflight of router-changing operations; work runs in a job."""
import secrets
import time

from kdn.common import fsutil
from kdn.common import timeutil
from kdn.web.infra import config as cfg
from kdn.web.infra import engine
from kdn.web.infra import jobfiles
from kdn.web.domain import profiles
from kdn.web.domain import refusals
from kdn.web.domain import route_jobs
from kdn.web.domain import validation
from kdn.web.domain import vpn


def _launch(operation, subject, service, mode, payload=None):
    state = {"ok": True, "job_id": secrets.token_hex(8), "operation": operation, "service": service, "mode": mode,
             "status": "queued", "stage": "queued", "stage_label": "В очереди", "progress": 0, "active": True,
             "created_at": int(time.time()), "created_utc": timeutil.utc_now(), "output": ""}
    return route_jobs.launch_route_worker(state, [operation, subject, "-"], history=False, payload=payload)


def start_xkeen_job(action):
    engine.xkeen_command(action)
    with jobfiles.COORDINATOR.exclusive(refusals.XKEEN_ACTION, family="route"):
        engine.require_supported_target()
        return _launch("xkeen", action, "xkeen", action)


def start_dns_switch(mode):
    if mode not in ('vless', 'doh'):
        raise ValueError('DNS mode: vless or doh')
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family='route'):
        engine.require_supported_target()
        return _launch('dns-mode', mode, 'dns', mode)


def start_dns_fallback_job():
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family='route'):
        engine.require_supported_target()
        return _launch('dns-fallback','doh','dns','doh')


def start_inspection_setup():
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family='route'):
        engine.require_supported_target()
        return _launch('inspection-setup', '-', 'diagnostics', 'setup')


def start_apply_job(profile, mode="import"):
    if mode not in {"import", "tuner", "version"}:
        raise ValueError("неподдерживаемый режим применения")
    with jobfiles.COORDINATOR.exclusive(refusals.PROFILE_APPLY, family="route"):
        engine.require_supported_target()
        return _launch("apply-profile", mode, profile["service"], mode, profile)


def start_tuner_apply_job():
    with jobfiles.COORDINATOR.exclusive(refusals.TUNER_APPLY, family="route"):
        engine.require_supported_target()
        state = fsutil.safe_json_file(cfg.TUNER_STATE)
        if state.get("status") != "found" or not state.get("result_available"):
            raise ValueError("нет найденного результата для применения")
        profile = validation.validate_report(fsutil.safe_json_file(cfg.TUNER_RESULT))
        return _launch("apply-profile", "tuner", profile["service"], "tuner", profile)


def start_version_apply_job(service, version_id):
    with jobfiles.COORDINATOR.exclusive(refusals.VERSION_APPLY, family="route"):
        engine.require_supported_target()
        _path, profile = profiles.profile_version_path(service, version_id)
        return _launch("apply-profile", "version", service, "version", profile)


def start_import_clear_job(service):
    if service not in cfg.SERVICES:
        raise ValueError("неподдерживаемый сервис")
    with jobfiles.COORDINATOR.exclusive(refusals.PROFILE_CLEAR, family="route"):
        engine.require_supported_target()
        return _launch("import-clear", service, service, "clear")


def start_import_rollback_job():
    with jobfiles.COORDINATOR.exclusive(refusals.IMPORT_ROLLBACK, family="route"):
        engine.require_supported_target()
        return _launch("import-rollback", "-", "import", "rollback")


def start_vpn_add_job(name, source):
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE, family="route"), vpn.VPN_STORE_LOCK:
        engine.require_supported_target()
        manager = vpn.vpn_manager()
        module = vpn.VPN_MODULE
        manager._mutation_allowed()
        name = module.display_name(name)
        if name == "current":
            raise ValueError("зарезервированное имя ноды")
        state = manager.load()
        if (any(module.display_name(row.get('name', key)).casefold() == name.casefold()
                                        for key, row in state['nodes'].items())
                or len(state["nodes"]) >= module.MAX_NODES):
            raise ValueError("нода уже существует или достигнут предел 16 нод")
        try:
            module.normalize_outbound(source)
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise ValueError('некорректная ссылка или JSON outbound') from None
        subject = name if module.NODE_NAME.fullmatch(name) else 'new-node'
        return _launch("vpn-add", subject, "vpn", "add", {"name": name, "source": source})


def start_vpn_check_job(node_id):
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE, family="route"), vpn.VPN_STORE_LOCK:
        engine.require_supported_target()
        manager = vpn.vpn_manager()
        manager._mutation_allowed()
        if node_id not in manager.load()["nodes"]:
            raise ValueError("нода не найдена")
        return _launch("vpn-check", node_id, "vpn", "check")

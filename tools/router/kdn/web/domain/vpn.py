"""VPN node manager of the panel: the router tool loaded as a module, and the jobs that switch the active node."""

import importlib.util
import hashlib
import json
import re
import secrets
import threading
import time

from kdn.common import timeutil
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.infra import engine
from kdn.web.domain import route_jobs
from kdn.web.domain import refusals


VPN_MODULE_LOCK = threading.Lock()
VPN_STORE_LOCK = threading.RLock()
VPN_MODULE = None


def vpn_manager():
    global VPN_MODULE
    with VPN_MODULE_LOCK:
        if VPN_MODULE is None:
            spec = importlib.util.spec_from_file_location("xkeen_vpn_node_manager", cfg.VPN_MANAGER_SCRIPT)
            if spec is None or spec.loader is None:
                raise ImportError(f"не удалось загрузить {cfg.VPN_MANAGER_SCRIPT}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            VPN_MODULE = module
    return VPN_MODULE.VpnNodeManager()


def nodes_status():
    """Status of the node registry, read under the store lock."""
    with VPN_STORE_LOCK:
        return vpn_manager().status()


def active_identity():
    """File-only identity for IP policy; never exposes or mutates outbound settings."""
    with VPN_STORE_LOCK:
        manager = vpn_manager()
        if manager.transaction_file.exists() or manager.transaction_file.is_symlink():
            raise ValueError('сначала восстановите незавершённое переключение VPN')
        state = manager.load()
        _document, current = manager._current_file()
        outbound = VPN_MODULE.normalize_outbound(state['nodes'][state['active']]['outbound'])
        if VPN_MODULE.normalize_outbound(current) != outbound:
            raise ValueError('активная нода изменена вне панели; требуется синхронизация')
        digest = hashlib.sha256(json.dumps(outbound, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        return {'node_id': state['active'], 'source_digest': digest}


def remove_node(node_id):
    """Remove a node from the registry, refused while a job starts or a route job runs."""
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE):
        with VPN_STORE_LOCK:
            return vpn_manager().remove(node_id)


def sync_current():
    """Take the active outbound into the registry, refused while a job starts or a route job runs."""
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE):
        with VPN_STORE_LOCK:
            return vpn_manager().sync_current()


def update_node(node_id, changes):
    if (not isinstance(changes, dict) or not changes or set(changes) - {'name', 'source'}
            or any(not isinstance(value, str) for value in changes.values())):
        raise ValueError('ожидаются name и/или полный source ноды')
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE):
        with VPN_STORE_LOCK:
            return vpn_manager().update(node_id, **changes)


def start_vpn_node_job(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", name):
        raise ValueError("некорректное имя VPN-ноды")
    jobfiles.COORDINATOR.ensure_idle(refusals.ROUTE_CHANGE)
    engine.require_supported_target()
    status = engine.read_status_fields()
    if not status["ok"] or status.get("detected_core") != "xray":
        raise ValueError("выбор VPN-ноды доступен только при активном ядре Xray")
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family="route"):
        engine.require_supported_target()
        with VPN_STORE_LOCK:
            manager = vpn_manager()
            if name not in manager.load()["nodes"]:
                raise ValueError("VPN-нода не найдена")
            manager_status = manager.status()
            if manager_status["recovery_needed"]:
                raise ValueError("предыдущее переключение прервалось; сначала восстановите прежнюю ноду")
            if manager_status["drift"]:
                raise ValueError("активный outbound изменён вне панели; синхронизируйте текущую ноду")
            if manager_status.get("warning"):
                raise ValueError(manager_status["warning"])
        before = engine.current_routes_fast()
        job_id = secrets.token_hex(8)
        state = {
            "ok": True, "job_id": job_id, "operation": "vpn-node",
            "status": "queued", "stage": "queued", "stage_label": "В очереди",
            "progress": 0, "active": True, "service": "vpn", "mode": "node",
            "outbound_tag": name, "before_routes": before,
            "requested_routes": dict(before), "created_at": int(time.time()),
            "created_utc": timeutil.utc_now(), "output": "",
        }
        return route_jobs.launch_route_worker(state, ["vpn-node", name, "-"])


def start_vpn_recovery_job():
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE, family="route"):
        engine.require_supported_target()
        with VPN_STORE_LOCK:
            if not vpn_manager().status()["recovery_needed"]:
                raise ValueError("незавершённого переключения VPN нет")
        before = engine.current_routes_fast()
        job_id = secrets.token_hex(8)
        state = {
            "ok": True, "job_id": job_id, "operation": "vpn-recover",
            "status": "queued", "stage": "queued", "stage_label": "В очереди",
            "progress": 0, "active": True, "service": "vpn", "mode": "recover",
            "before_routes": before, "requested_routes": dict(before),
            "created_at": int(time.time()), "created_utc": timeutil.utc_now(), "output": "",
        }
        return route_jobs.launch_route_worker(state, ["vpn-recover", "-", "-"])

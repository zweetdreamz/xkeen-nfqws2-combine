"""Manual checker jobs and cached results, independent of tuner/diagnostic flows."""
import secrets
import threading
import time

from kdn.common import errors
from kdn.inspection import request
from kdn.web.infra import config as cfg
from kdn.web.infra import inspection as infra
from kdn.web.infra import jobfiles
from kdn.web.domain import refusals, vpn_monitor


def inspection_status():
    with infra.STATE_LOCK:
        result = infra.read_inspection_state(cfg.INSPECTION_STATE, {'status': 'idle', 'results': {}})
    result['ok'], result['active'] = True, infra.RUN_LOCK.locked()
    if result.get('status') == 'running' and not result['active']:
        result['status'] = 'interrupted'
    return result


def _execute(job_id, kind, payload):
    try:
        result = vpn_monitor.observe(payload) if kind == 'vpn' else infra.run_inspection_worker(kind, payload)
        with infra.STATE_LOCK:
            saved = infra.read_inspection_state(cfg.INSPECTION_STATE, {})
            results = saved.get('results', {}) | {kind: result}
            infra.write_inspection_state(cfg.INSPECTION_STATE, {'status': result['status'], 'kind': kind, 'job_id': job_id,
                                            'finished_at': int(time.time()), 'results': results})
    finally:
        infra.RUN_LOCK.release()


def start(kind, payload):
    payload = request.checker_request(kind, payload)
    with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE):
        if not infra.RUN_LOCK.acquire(blocking=False):
            raise errors.Busy(refusals.INSPECTION_BUSY)
        try:
            job_id = secrets.token_hex(8)
            with infra.STATE_LOCK:
                saved = infra.read_inspection_state(cfg.INSPECTION_STATE, {})
                infra.write_inspection_state(cfg.INSPECTION_STATE, saved | {'status': 'running', 'kind': kind, 'job_id': job_id})
            threading.Thread(target=_execute, args=(job_id, kind, payload), daemon=True, name='route-inspection').start()
        except BaseException:
            infra.RUN_LOCK.release()
            raise
    return {'ok': True, 'job_id': job_id, 'kind': kind, 'status': 'running', 'active': True}

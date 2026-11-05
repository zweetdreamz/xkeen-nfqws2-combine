"""Regular observation of the manually chosen node; no node/service mutation API."""
import threading
import time

from kdn.common import errors, lock
from kdn.inspection import policy, receipt
from kdn.web.infra import config as cfg
from kdn.web.infra import inspection
from kdn.web.infra import jobfiles
from kdn.web.domain import refusals, vpn


def monitor_config():
    return policy.validate_monitor_config(inspection.read_inspection_state(cfg.VPN_MONITOR_CONFIG, policy.defaults()))


def monitor_state():
    saved = inspection.read_inspection_state(cfg.VPN_MONITOR_STATE, {})
    now = int(time.time())
    timestamp = lambda value: type(value) is int and 0 < value <= now
    if not isinstance(saved, dict):
        raise ValueError('повреждено состояние мониторинга')
    if 'last_attempt' in saved and not timestamp(saved['last_attempt']):
        raise ValueError('некорректное время проверки')
    result = saved.get('result', {})
    if not isinstance(result, dict):
        raise ValueError('повреждён результат мониторинга')
    if result:
        if (result.get('kind') != 'vpn' or result.get('status') not in ('completed', 'skipped', 'unavailable')
                or not timestamp(result.get('checked_at'))):
            raise ValueError('некорректный результат/время мониторинга')
        if result['status'] == 'completed':
            if not isinstance(result.get('observed'), dict):
                raise ValueError('повреждено наблюдение IP')
            policy._expected({key: [value] for key, value in result['observed'].items() if value is not None})
    history = saved.get('history', [])
    if not isinstance(history, list) or len(history) > 100:
        raise ValueError('повреждена история мониторинга')
    for row in history:
        if not isinstance(row, dict) or not timestamp(row.get('at')) or not isinstance(row.get('status'), str):
            raise ValueError('некорректное событие мониторинга')
    return saved


def vpn_monitor_status():
    with inspection.STATE_LOCK:
        try:
            settings, saved = monitor_config(), monitor_state()
        except (ValueError, TypeError, OSError):
            return {'ok': True, 'config': policy.defaults(), 'state': {}, 'identity': {}, 'expected': {},
                    'verdict': 'unavailable', 'active': inspection.RUN_LOCK.locked(), 'next_check': None,
                    'detail': 'Конфиг или состояние мониторинга повреждены; автоматические проверки приостановлены'}
        try:
            identity = vpn.active_identity()
            classification = policy.verdict(settings, identity, saved.get('result', {}))
            expected = policy.expected(settings, identity)
            detail = ''
        except (OSError, ValueError, RuntimeError):
            identity, expected, classification = {}, {}, 'unavailable'
            detail = 'Активная нода не подтверждена; проверьте синхронизацию/восстановление'
        result = saved.get('result', {})
        if result.get('status') == 'completed' and not receipt.observation_current(
                cfg.INSPECTION_RUNTIME, cfg.XRAY_CONFIG_DIR, result.get('runtime_identity')):
            classification = 'stale'
        age = int(time.time()) - result.get('checked_at', 0)
        if classification == 'healthy' and age > max(300, settings['interval_minutes'] * 120):
            classification = 'stale'
        return {'ok': True, 'config': settings, 'state': saved, 'identity': identity, 'expected': expected,
                'verdict': classification, 'active': inspection.RUN_LOCK.locked(), 'detail': detail,
                'next_check': saved.get('last_attempt', 0) + settings['interval_minutes'] * 60 if settings['enabled'] else None}


def save(changes, expected_identity):
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE), lock.ProjectLock(cfg.PROJECT_LOCK_DIR), inspection.STATE_LOCK:
        identity = vpn.active_identity()
        if expected_identity != identity:
            raise ValueError('нода изменилась; обновите статус и подтвердите её IP заново')
        updated = policy.configure(monitor_config(), identity, changes)
        inspection.write_inspection_state(cfg.VPN_MONITOR_CONFIG, updated)
    return vpn_monitor_status()


def approve_vpn_monitor_ips(families, expected_identity, observation_id):
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE), lock.ProjectLock(cfg.PROJECT_LOCK_DIR), inspection.STATE_LOCK:
        identity, result = vpn.active_identity(), monitor_state().get('result', {})
        if expected_identity != identity or not observation_id or result.get('observation_id') != observation_id:
            raise ValueError('нода или наблюдение изменились; обновите статус и подтвердите показанный IP заново')
        if not receipt.observation_current(cfg.INSPECTION_RUNTIME, cfg.XRAY_CONFIG_DIR, result.get('runtime_identity')):
            raise ValueError('Xray или конфиг изменились после наблюдения; выполните новую проверку')
        updated = policy.approve_monitor_ips(monitor_config(), identity, result, families)
        inspection.write_inspection_state(cfg.VPN_MONITOR_CONFIG, updated)
    return vpn_monitor_status()


def observe(payload):
    result = inspection.run_inspection_worker('vpn', payload)
    with inspection.STATE_LOCK:
        try:
            identity = vpn.active_identity()
            classification = policy.verdict(monitor_config(), identity, result)
        except (ValueError, OSError, RuntimeError):
            classification = 'stale'
        inspection.write_inspection_state(cfg.VPN_MONITOR_STATE, policy.record_observation(monitor_state(), result, classification))
    return result


def tick(now=None):
    now = int(time.time()) if now is None else now
    settings, saved = monitor_config(), monitor_state()
    if not settings['enabled'] or now < saved.get('last_attempt', 0) + settings['interval_minutes'] * 60:
        return False
    try:
        with jobfiles.COORDINATOR.exclusive(refusals.ROUTE_CHANGE):
            if not inspection.RUN_LOCK.acquire(blocking=False):
                return False
    except errors.Busy:
        return False
    try:
        observe({'families': settings['families']})
        return True
    finally:
        inspection.RUN_LOCK.release()


def loop(stop=None):
    stop = threading.Event() if stop is None else stop
    while not stop.is_set():
        try:
            tick()
        except (ValueError, OSError, RuntimeError, TypeError):
            # Corrupt/unsupported state cannot enable probing or restart anything.
            pass
        stop.wait(15)

"""Observe the chosen VPN; three proven outages can request a guarded DNS job."""
import threading
import time
import re

from kdn.common import errors, lock
from kdn.inspection import policy, receipt
from kdn.web.infra import config as cfg, engine
from kdn.web.infra import inspection
from kdn.web.infra import jobfiles
from kdn.web.domain import refusals, vpn


def monitor_config():
    return policy.validate_monitor_config(inspection.read_inspection_state(cfg.VPN_MONITOR_CONFIG, policy.defaults()))


def _registry_monitor_config():
    # Explicit save/approve callers hold ProjectLock: CLI and web registry
    # mutations cannot race this snapshot or its subsequent publication.
    with vpn.VPN_STORE_LOCK:
        registry_ids = vpn.vpn_manager().load()['nodes']
    return policy.prune_removed_nodes(monitor_config(), registry_ids)


def monitor_state():
    saved = inspection.read_inspection_state(cfg.VPN_MONITOR_STATE, {})
    now = int(time.time())
    timestamp = lambda value: type(value) is int and 0 < value <= now
    if not isinstance(saved, dict):
        raise ValueError('повреждено состояние мониторинга')
    if type(saved.get('failure_streak',0)) is not int or not 0 <= saved.get('failure_streak',0) <= 1000:
        raise ValueError('повреждён счётчик отказов VPN')
    if 'last_attempt' in saved and not timestamp(saved['last_attempt']):
        raise ValueError('некорректное время проверки')
    fallback=saved.get('dns_fallback',{})
    if (not isinstance(fallback,dict) or (fallback and
            (fallback.get('status') not in {'pending','queued','running','completed','already-doh','skipped','error'}
             or not isinstance(fallback.get('incident'),str) or not re.fullmatch(r'[0-9a-f]{32}',fallback['incident'])
             or not timestamp(fallback.get('at'))))):
        raise ValueError('повреждено состояние перехода DNS')
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
        updated = policy.configure(_registry_monitor_config(), identity, changes)
        inspection.write_inspection_state(cfg.VPN_MONITOR_CONFIG, updated)
    return vpn_monitor_status()


def approve_vpn_monitor_ips(families, expected_identity, observation_id):
    with jobfiles.COORDINATOR.exclusive(refusals.VPN_STORE), lock.ProjectLock(cfg.PROJECT_LOCK_DIR), inspection.STATE_LOCK:
        identity, result = vpn.active_identity(), monitor_state().get('result', {})
        if expected_identity != identity or not observation_id or result.get('observation_id') != observation_id:
            raise ValueError('нода или наблюдение изменились; обновите статус и подтвердите показанный IP заново')
        if not receipt.observation_current(cfg.INSPECTION_RUNTIME, cfg.XRAY_CONFIG_DIR, result.get('runtime_identity')):
            raise ValueError('Xray или конфиг изменились после наблюдения; выполните новую проверку')
        updated = policy.approve_monitor_ips(_registry_monitor_config(), identity, result, families)
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


def _fallback_candidate(saved, now):
    result = saved.get('result',{})
    completed=result.get('finished_at',result.get('checked_at',0))
    settings=monitor_config()
    if not settings['enabled'] or not settings['dns_fallback_enabled'] or saved.get('failure_streak',0) < 3:
        return False
    identity=vpn.active_identity()
    return (settings['enabled'] and saved.get('failure_streak',0) >= 3
            and isinstance(saved.get('failure_incident'),str)
            and re.fullmatch(r'[0-9a-f]{32}',saved['failure_incident']) is not None
            and type(completed) is int and 0 <= now-completed <= 180
            and result.get('status') == 'completed'
            and result.get('node_id') == identity.get('node_id')
            and result.get('source_digest') == identity.get('source_digest')
            and result.get('families') == settings['families']
            and policy.dns_outage(result,policy.verdict(settings,identity,result))
            and receipt.observation_current(cfg.INSPECTION_RUNTIME,cfg.XRAY_CONFIG_DIR,result.get('runtime_identity')))


def maybe_start_dns_fallback():
    from kdn.web.domain import operations
    now = int(time.time())
    with inspection.STATE_LOCK:
        saved = monitor_state()
        if not _fallback_candidate(saved,now):
            return False
        incident = saved['failure_incident']
        previous=saved.get('dns_fallback',{})
        if previous.get('incident') == incident:
            retry_pending=previous.get('status')=='pending' and now-previous.get('at',now)>180
            retry_skipped=previous.get('status')=='skipped' and saved['result'].get('checked_at',0)>previous.get('at',0)
            if not (retry_pending or retry_skipped):
                return False
        saved['dns_fallback']={'incident':incident,'status':'pending','at':now}
        inspection.write_inspection_state(cfg.VPN_MONITOR_STATE,saved)
    try:
        operations.start_dns_fallback_job()
    except errors.Busy:
        with inspection.STATE_LOCK:
            saved=monitor_state()
            if saved.get('dns_fallback',{}).get('status') == 'pending':
                saved.pop('dns_fallback',None)
                inspection.write_inspection_state(cfg.VPN_MONITOR_STATE,saved)
        return False
    except (OSError,RuntimeError,ValueError):
        _finish_dns_fallback(incident,'error')
        return False
    # The detached worker owns all later marker transitions. A parent-side
    # queued write could otherwise overwrite an already completed worker.
    return True


def _finish_dns_fallback(incident,status):
    if not re.fullmatch(r'[0-9a-f]{32}',incident):
        return
    with inspection.STATE_LOCK:
        saved=monitor_state()
        saved['dns_fallback']={'incident':incident,'status':status,'at':int(time.time())}
        inspection.write_inspection_state(cfg.VPN_MONITOR_STATE,saved)


def run_dns_fallback_job():
    saved=monitor_state()
    incident=saved.get('dns_fallback',{}).get('incident','')
    try:
        if saved.get('dns_fallback',{}).get('status') not in ('pending','queued'):
            return {'ok':True,'code':0,'output':'DNS fallback skipped: no pending automatic request'}
        if not _fallback_candidate(saved,int(time.time())) or incident != saved['failure_incident']:
            _finish_dns_fallback(incident,'skipped')
            return {'ok':True,'code':0,'output':'DNS fallback skipped: observation changed or is stale'}
        _finish_dns_fallback(incident,'running')
        dns=engine.read_dns_mode()
        if dns.get('supported') and dns.get('mode') == 'doh' and not dns.get('pending'):
            _finish_dns_fallback(incident,'already-doh')
            return {'ok':True,'code':0,'output':'DNS already uses DoH; nothing changed'}
        if not dns.get('supported') or dns.get('pending') or dns.get('mode') != 'vless':
            raise ValueError('DNS fallback is not safe in the current state')
        if not _fallback_candidate(monitor_state(),int(time.time())):
            _finish_dns_fallback(incident,'skipped')
            return {'ok':True,'code':0,'output':'DNS fallback skipped: VPN observation changed'}
        result=engine.set_dns_mode('doh')
        after=engine.read_dns_mode() if result.get('ok') else {}
        if not after.get('supported') or after.get('pending') or after.get('mode') != 'doh':
            raise RuntimeError('DNS fallback did not complete')
        _finish_dns_fallback(incident,'completed')
        return result
    except (OSError,RuntimeError,ValueError,TypeError):
        _finish_dns_fallback(incident,'error')
        return {'ok':False,'code':1,'output':'Automatic DNS fallback failed; inspect DNS state before retrying'}


def loop(stop=None):
    stop = threading.Event() if stop is None else stop
    while not stop.is_set():
        try:
            tick()
            maybe_start_dns_fallback()
        except (ValueError, OSError, RuntimeError, TypeError):
            # Corrupt/unsupported state cannot enable probing or restart anything.
            pass
        stop.wait(15)

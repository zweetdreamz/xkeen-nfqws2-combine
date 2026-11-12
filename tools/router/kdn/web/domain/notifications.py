"""Bounded event outbox, fixed public ntfy destination; never changes networking."""
import hashlib
import json
import re
import threading
import time
import secrets

from kdn.web.infra import config as cfg
from kdn.web.infra import inspection
from kdn.inspection import transport


TEXT = {
    'test': ('Уведомления подключены', 'Сообщения панели будут приходить в эту тему.', 3),
    'youtube-applied': ('YouTube: профиль обновлён', 'Ночной подбор применил и проверил новый профиль Zapret.', 3),
    'discord-tcp-applied': ('Discord: профиль обновлён', 'Ночной подбор применил и проверил новый TCP-профиль Zapret.', 3),
    'night-failed': ('Ночная проверка: ошибка', 'Нужна проверка журнала панели. Автоматическая замена VPN не выполнялась.', 4),
    'night-not-found': ('Zapret: профиль не найден', 'Ночной подбор не нашёл рабочего профиля. Проверьте панель.', 4),
    'rolled-back': ('Профиль восстановлен', 'Новый профиль не прошёл проверку. Предыдущий профиль восстановлен.', 4),
    'recovery-failed': ('Не завершено восстановление', 'Требуется ручная проверка панели. Не повторяйте изменения вслепую.', 5),
    'vpn-check-failed': ('VPN: проверка не проходит', 'Три проверки подряд не подтвердили IP/HTTPS через выбранную ноду. Проверьте соединение и ноду.', 4),
    'vpn-ip-changed': ('VPN: изменился выходной IP', 'Адрес не совпадает с одобренным. Новый IP не принят, нода не переключалась.', 5),
    'inspection-unavailable': ('Контроль VPN недоступен', 'Три проверки подряд не выполнены. Проверьте диагностический доступ и состояние панели.', 4),
    'vpn-recovered': ('VPN снова работает', 'Одобренный IP и HTTPS через выбранную ноду подтверждены.', 3),
    'dns-fallback': ('DNS переключён на DoH', 'После трёх подтверждённых отказов VPN DNS Home переведён с VLESS на DoH. Автоматического возврата на VLESS нет.', 4),
    'dns-fallback-failed': ('Не удалось переключить DNS', 'Автоматический переход на DoH не завершён. Проверьте состояние DNS в панели; VPN-нода не переключалась.', 5),
}
_NOTIFICATION_LOCK = threading.RLock()


def _settings():
    data = inspection.read_inspection_state(cfg.NOTIFICATION_CONFIG, {})
    if not isinstance(data, dict):
        raise ValueError('invalid notification config')
    result = {'version': 1, 'enabled': False, 'topic': '', 'token': '', 'events': list(TEXT)} | data
    if (type(result['version']) is not int or result['version'] != 1
            or type(result['enabled']) is not bool or not isinstance(result['topic'], str)
            or (result['topic'] and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', result['topic']))
            or (result['enabled'] and not result['topic']) or not isinstance(result['token'], str)
            or len(result['token']) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in result['token'])
            or not isinstance(result['events'], list)
            or any(not isinstance(k, str) or k not in TEXT for k in result['events'])):
        raise ValueError('некорректные настройки уведомлений')
    return result


def notification_status():
    with _NOTIFICATION_LOCK:
        settings = _settings()
        saved = inspection.read_inspection_state(cfg.NOTIFICATION_STATE, {})
        return {'ok': True, 'enabled': settings['enabled'], 'topic': settings['topic'],
                'token_set': bool(settings['token']), 'events': settings['events'],
                'choices': [{'id': k, 'title': v[0]} for k, v in TEXT.items() if k != 'test'],
                'url': 'https://ntfy.sh/' + settings['topic'] if settings['topic'] else '',
                'pending': len(saved.get('queue', [])), 'last_delivery': saved.get('last_delivery'),
                'error': saved.get('last_error', '')}


def save_notifications(body):
    if (not isinstance(body, dict) or set(body) - {'enabled', 'topic', 'token', 'clear_token', 'events', 'confirm_topic_change'}
            or type(body.get('enabled')) is not bool or not isinstance(body.get('topic'), str)
            or type(body.get('clear_token', False)) is not bool or not isinstance(body.get('token', ''), str)):
        raise ValueError('некорректные параметры уведомлений')
    with _NOTIFICATION_LOCK:
        old = _settings()
        changed = body['topic'] != old['topic']
        if changed and old['topic'] and body.get('confirm_topic_change') is not True:
            raise ValueError('подтвердите смену темы и очистку очереди')
        result = dict(old, enabled=body['enabled'], topic=body['topic'], events=body.get('events', old['events']))
        if body.get('clear_token'):
            result['token'] = ''
        elif body.get('token'):
            result['token'] = body['token']
        # Validate before replacing any files, without echoing write-only token.
        if ((result['topic'] and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', result['topic']))
                or (result['enabled'] and not result['topic'])
                or len(result['token']) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in result['token'])
                or not isinstance(result['events'], list)
                or any(not isinstance(k, str) or k not in TEXT for k in result['events'])):
            raise ValueError('проверьте тему, токен и события')
        inspection.write_inspection_state(cfg.NOTIFICATION_CONFIG, result)
        if changed:
            inspection.write_inspection_state(cfg.NOTIFICATION_STATE, {})
    return notification_status()


def notification_test():
    with _NOTIFICATION_LOCK:
        settings = _settings()
        if not settings['enabled']:
            raise ValueError('сначала включите и сохраните уведомления')
        state = inspection.read_inspection_state(cfg.NOTIFICATION_STATE, {}) or {
            'channel': hashlib.sha256(settings['topic'].encode()).hexdigest(), 'queue': [], 'seen': [], 'dropped': 0}
        _validate_state(state)
        if not state.get('seeded'):
            derive(state, inspection.read_inspection_state(cfg.AUTOMATION_STATE, {}),
                   inspection.read_inspection_state(cfg.VPN_MONITOR_STATE, {}), int(time.time()))
        else:
            _event(state, 'test-' + secrets.token_hex(16), 'test', int(time.time()))
        inspection.write_inspection_state(cfg.NOTIFICATION_STATE, state)
    return {'ok': True, 'queued': True}


def _event(state, key, kind, now):
    identity = hashlib.sha256(key.encode()).hexdigest()[:32]
    if identity in state['seen']:
        return
    state['seen'] = (state['seen'] + [identity])[-128:]
    state['queue'].append({'id': identity, 'kind': kind, 'at': now, 'next': now, 'tries': 0})
    if len(state['queue']) > 32:
        state['dropped'] += len(state['queue']) - 32
        state['queue'] = state['queue'][-32:]


def derive(state, auto, monitor, now):
    """Observe committed summaries only; no raw error/config/IP enters a message."""
    auto_key = [auto.get('last_slot'), auto.get('finished_utc'), auto.get('status')]
    monitor_key = monitor.get('last_attempt', 0)
    result=monitor.get('result',{})
    if not isinstance(result,dict):
        raise ValueError('invalid monitor observation')
    monitor_scope=hashlib.sha256(json.dumps([result.get('node_id'),result.get('source_digest'),result.get('runtime_identity')],sort_keys=True).encode()).hexdigest()
    if not state.get('seeded'):
        state.update(seeded=True, auto_key=auto_key, monitor_key=monitor_key, monitor_scope=monitor_scope)
        _event(state, 'initial', 'test', now)
        return
    if auto_key != state.get('auto_key') and auto.get('status') in ('completed', 'error', 'recovered', 'recovery-failed', 'cancelled'):
        state['auto_key'] = auto_key
        prefix = json.dumps(auto_key)
        for service in ('youtube', 'discord-tcp'):
            if auto.get('results', {}).get(service) in ('applied', 'applied-quic-unverified'):
                _event(state, prefix+service, service+'-applied', now)
        status = auto.get('status')
        if status in ('error', 'recovery-failed'):
            pending = status == 'recovery-failed' or (auto.get('phase') == 'recovery-needed' and isinstance(auto.get('transaction'), dict))
            _event(state, prefix+'failure', 'recovery-failed' if pending else 'night-failed', now)
        if status == 'recovered' or auto.get('last_rollback_utc'):
            _event(state, prefix+'rollback', 'rolled-back', now)
        if 'not-found' in auto.get('results', {}).values():
            _event(state, prefix+'notfound', 'night-not-found', now)
    if monitor_key and monitor_key != state.get('monitor_key'):
        state['monitor_key'] = monitor_key
        if state.get('monitor_scope') != monitor_scope:
            state.update(monitor_scope=monitor_scope,alert='',fail_kind='',failures=0)
        verdict = monitor.get('verdict')
        old = state.get('alert')
        if verdict == 'healthy':
            if old:
                _event(state, str(monitor_key)+'recovered', 'vpn-recovered', now)
            state.update(alert='', fail_kind='', failures=0)
        elif verdict == 'ip-mismatch':
            if old != 'vpn-ip-changed':
                _event(state, str(monitor_key)+'ip', 'vpn-ip-changed', now)
            state.update(alert='vpn-ip-changed', fail_kind='', failures=0)
        else:
            kind = 'vpn-check-failed' if verdict in ('unreachable', 'partial') else 'inspection-unavailable'
            state['failures'] = state.get('failures', 0)+1 if state.get('fail_kind') == kind else 1
            state['fail_kind'] = kind
            if state['failures'] >= 3 and old != kind:
                _event(state, str(monitor_key)+kind, kind, now)
                state['alert'] = kind
    fallback=monitor.get('dns_fallback',{})
    dns_key=[fallback.get('incident'),fallback.get('status'),fallback.get('at')]
    if fallback.get('status') in ('completed','error') and dns_key != state.get('dns_key'):
        state['dns_key']=dns_key
        _event(state,json.dumps(dns_key),'dns-fallback' if fallback['status']=='completed' else 'dns-fallback-failed',now)


def _publish(topic, row, token=''):
    title, message, priority = TEXT[row['kind']]
    body = json.dumps({'topic': topic, 'title': title, 'message': message, 'priority': priority,
                       'sequence_id': row['id']}, ensure_ascii=False).encode()
    payload = 'data = ' + json.dumps(body.decode(), ensure_ascii=False) + '\n'
    if token:
        payload += 'header = ' + json.dumps('Authorization: Bearer ' + token) + '\n'
    raw = transport.run(['curl', '-q', '--config', '-', '--silent', '--show-error', '--fail', '--proto', '=https',
                         '--noproxy', '*', '--proxy', '', '--connect-timeout', '5', '--max-time', '8',
                         '--max-filesize', '4096', '--header', 'Content-Type: application/json',
                         'https://ntfy.sh/'], data=payload.encode(), timeout=10, limit=4096)
    ack = json.loads(raw)
    if not isinstance(ack, dict) or ack.get('event') != 'message' or ack.get('topic') != topic:
        raise ValueError('notification acknowledgement invalid')


def _validate_state(state):
    if (not isinstance(state, dict) or not isinstance(state.get('queue'), list) or len(state['queue']) > 32
            or not isinstance(state.get('seen'), list) or len(state['seen']) > 128):
        raise ValueError('invalid notification state')
    for row in state['queue']:
        if (not isinstance(row, dict) or set(row) != {'id', 'kind', 'at', 'next', 'tries'}
                or not isinstance(row['kind'], str) or row['kind'] not in TEXT or not isinstance(row['id'], str)
                or not re.fullmatch('[0-9a-f]{32}', row['id'])
                or any(type(row[k]) is not int or row[k] < 0 for k in ('at', 'next', 'tries'))):
            raise ValueError('invalid notification row')


def notification_tick(now=None):
    with _NOTIFICATION_LOCK:
        return _notification_tick(now)


def _notification_tick(now=None):
    now = int(time.time()) if now is None else now
    settings = _settings()
    if not settings['enabled']:
        return
    topic = settings.get('topic')
    if not isinstance(topic, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', topic):
        raise ValueError('invalid notification topic')
    channel = hashlib.sha256(topic.encode()).hexdigest()
    state = inspection.read_inspection_state(cfg.NOTIFICATION_STATE, {})
    if not state:
        state = {'channel': channel, 'queue': [], 'seen': [], 'dropped': 0}
    _validate_state(state)
    if state.get('channel') != channel:
        raise ValueError('notification channel changed; explicit state reset required')
    before = json.dumps(state, sort_keys=True)
    auto = inspection.read_inspection_state(cfg.AUTOMATION_STATE, {})
    monitor = inspection.read_inspection_state(cfg.VPN_MONITOR_STATE, {})
    if not isinstance(auto, dict) or not isinstance(monitor, dict):
        raise ValueError('invalid source summaries')
    if not isinstance(auto.get('results', {}), dict) or not isinstance(auto.get('events', []), list):
        raise ValueError('invalid automation summary')
    derive(state, auto, monitor, now)
    state['queue'] = [row for row in state['queue'] if row['kind'] == 'test' or row['kind'] in settings['events']]
    expired = [row for row in state['queue'] if now-row['at'] > 86400]
    state['dropped'] += len(expired)
    state['queue'] = [row for row in state['queue'] if row not in expired]
    if json.dumps(state, sort_keys=True) != before:
        inspection.write_inspection_state(cfg.NOTIFICATION_STATE, state)
    due = next((row for row in state['queue'] if row['next'] <= now), None)
    if due is None:
        return
    try:
        _publish(topic, due, settings['token'])
    except (OSError, ValueError, RuntimeError):
        due['tries'] = min(20, due['tries']+1)
        due['next'] = now + min(900, 30 * 2**min(due['tries'], 5))
        state['last_error'] = 'Не удалось доставить уведомление; повтор запланирован'
    else:
        state['queue'].remove(due)
        state.update(last_delivery=now, last_error='')
    inspection.write_inspection_state(cfg.NOTIFICATION_STATE, state)


def notification_loop(stop=None):
    stop = threading.Event() if stop is None else stop
    while not stop.is_set():
        try:
            notification_tick()
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            pass  # No network/route changes, no private payloads in logs.
        stop.wait(15)

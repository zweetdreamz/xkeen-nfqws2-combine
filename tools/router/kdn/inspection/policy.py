"""Pure monitor policy. Observation never modifies approved IPs or active nodes."""
import copy
import ipaddress
import re
import time


FAMILIES = ('ipv4', 'ipv6')


def defaults():
    return {'version': 1, 'enabled': False, 'interval_minutes': 5, 'families': list(FAMILIES), 'nodes': {}}


def _families(value):
    if (not isinstance(value, list) or not 1 <= len(value) <= 2
            or any(not isinstance(x, str) or x not in FAMILIES for x in value) or len(set(value)) != len(value)):
        raise ValueError('выберите ipv4 и/или ipv6')
    return value


def _expected(value):
    if not isinstance(value, dict) or set(value) - set(FAMILIES):
        raise ValueError('ожидаются списки expected ipv4/ipv6')
    result = {}
    for family, rows in value.items():
        if not isinstance(rows, list) or len(rows) > 8:
            raise ValueError('до 8 разрешённых IP для каждой family')
        normalized = []
        for text in rows:
            if not isinstance(text, str) or len(text) > 45:
                raise ValueError('некорректный IP')
            address = ipaddress.ip_address(text)
            if not address.is_global or address.version != (4 if family == 'ipv4' else 6):
                raise ValueError('нужен публичный IP соответствующей family')
            normalized.append(str(address))
        result[family] = list(dict.fromkeys(normalized))
    return result


def validate_monitor_config(value):
    if not isinstance(value, dict) or set(value) != set(defaults()) or value.get('version') != 1:
        raise ValueError('повреждён конфиг мониторинга')
    if type(value['enabled']) is not bool or type(value['interval_minutes']) is not int or not 1 <= value['interval_minutes'] <= 1440:
        raise ValueError('интервал 1..1440 минут, enabled — boolean')
    _families(value['families'])
    if not isinstance(value['nodes'], dict) or len(value['nodes']) > 16:
        raise ValueError('до 16 записей контроля IP')
    for node_id, node in value['nodes'].items():
        if (not isinstance(node_id, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,31}', node_id)
                or not isinstance(node, dict) or set(node) != {'source_digest', 'expected'}
                or not isinstance(node['source_digest'], str) or not re.fullmatch('[0-9a-f]{64}', node['source_digest'])):
            raise ValueError('некорректная привязка контроля IP')
        _expected(node['expected'])
    return copy.deepcopy(value)


def expected(config, identity):
    node = config['nodes'].get(identity.get('node_id'), {})
    return node.get('expected', {}) if node.get('source_digest') == identity.get('source_digest') else {}


def prune_removed_nodes(config, registry_ids):
    """Free deleted IDs; existing source bindings remain subject to explicit approval."""
    result = validate_monitor_config(config)
    result['nodes'] = {key: node for key, node in result['nodes'].items() if key in registry_ids}
    return result


def configure(config, identity, changes):
    result = validate_monitor_config(config)
    if not isinstance(changes, dict) or set(changes) - {'enabled', 'interval_minutes', 'families', 'expected'}:
        raise ValueError('неизвестные настройки мониторинга')
    for key in ('enabled', 'interval_minutes', 'families'):
        if key in changes:
            result[key] = copy.deepcopy(changes[key])
    if 'expected' in changes:
        result['nodes'][identity['node_id']] = {'source_digest': identity['source_digest'],
                                              'expected': _expected(changes['expected'])}
    result = validate_monitor_config(result)
    if result['enabled'] and any(not expected(result, identity).get(family) for family in result['families']):
        raise ValueError('сначала явно одобрите IP активной ноды для всех выбранных family')
    return result


def approve_monitor_ips(config, identity, result, families):
    _families(families)
    now = time.time()
    if (result.get('status') != 'completed' or result.get('kind') != 'vpn'
            or any(result.get(key) != value for key, value in identity.items())
            or type(result.get('checked_at')) is not int or not 0 <= now - result['checked_at'] <= 300):
        raise ValueError('нужно свежее наблюдение текущей ноды (до 5 минут)')
    approved = copy.deepcopy(expected(config, identity))
    for family in families:
        observed = result.get('observed', {}).get(family)
        if not observed:
            raise ValueError('IP выбранной family не подтверждён')
        approved[family] = [observed]
    return configure(config, identity, {'expected': approved})


def verdict(config, identity, result):
    status = result.get('status', 'unknown')
    if status != 'completed':
        return status
    if any(result.get(key) != value for key, value in identity.items()):
        return 'stale'
    allowed = expected(config, identity)
    observed = result.get('observed', {})
    if any(observed.get(f) and allowed.get(f) and observed[f] not in allowed[f] for f in config['families']):
        return 'ip-mismatch'
    if not any(allowed.get(f) for f in config['families']):
        return 'unapproved'
    if any(not observed.get(f) or not allowed.get(f) for f in config['families']):
        return 'partial'
    if result.get('connectivity') != 'reachable':
        return 'unreachable'
    return 'healthy'


def record_observation(state, result, classification):
    state = copy.deepcopy(state)
    previous = state.get('result', {})
    signature = lambda r: (r.get('node_id'), r.get('source_digest'), r.get('observed'))
    history = state.get('history', [])[-100:]
    if classification != state.get('verdict') or signature(previous) != signature(result):
        history.append({'at': int(time.time()), 'status': classification, 'node_id': result.get('node_id'),
                        'observed': result.get('observed', {})})
    state.update(result=result, verdict=classification, history=history[-100:], last_attempt=int(time.time()))
    return state

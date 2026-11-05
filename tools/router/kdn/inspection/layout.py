"""Owned diagnostic listener layout, with collision checks and no IO."""
import copy
import re


FILE = '99_kdn_inspection_tail.json'
VPN_TAG = 'vless-reality'
DIRECT_TAG = 'kdn-inspect-direct'
VPN_IN = 'kdn-inspect-vpn'
DIRECT_IN = 'kdn-inspect-direct-in'
VPN_PORT = 18445
DIRECT_PORT = 18446
API_PORT = 10085
API_SERVICES = ('RoutingService', 'HandlerService')


def rules():
    return [{'type': 'field', 'ruleTag': 'kdn-inspect-' + mode,
             'inboundTag': [inbound], 'network': 'tcp', 'outboundTag': outbound}
            for mode, inbound, outbound in (('vpn', VPN_IN, VPN_TAG), ('direct', DIRECT_IN, DIRECT_TAG))]


def fragment(mark=None):
    outbound = {'tag': DIRECT_TAG, 'protocol': 'freedom', 'settings': {}}
    if mark is not None:
        if type(mark) is not int or not 0 <= mark <= 2147483647:
            raise ValueError('invalid inspection Direct mark')
        outbound['streamSettings'] = {'sockopt': {'mark': mark}}
    return {'inbounds': [{'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                         'settings': {'auth': 'noauth', 'udp': False}}
                        for tag, port in ((VPN_IN, VPN_PORT), (DIRECT_IN, DIRECT_PORT))],
            'outbounds': [outbound]}


def api_port(documents):
    rows = [doc['api'] for doc in documents.values() if 'api' in doc]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError('diagnostic loopback API is not prepared')
    api = rows[0]
    match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})', str(api.get('listen', '')))
    if (not match or not 1 <= int(match[1]) <= 65535 or not isinstance(api.get('tag'), str)
            or not api['tag'] or not isinstance(api.get('services'), list)
            or any(service not in api['services'] for service in API_SERVICES)):
        raise ValueError('diagnostic API requires numeric loopback and both read services')
    return int(match[1])


def _covers(value, ports):
    if type(value) is int:
        return value in ports
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError('unrepresentable inbound port')
    for item in value.split(','):
        numbers = item.split('-')
        if not 1 <= len(numbers) <= 2 or any(not n.isascii() or not n.isdecimal() for n in numbers):
            raise ValueError('unrepresentable inbound port')
        low, high = int(numbers[0]), int(numbers[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError('invalid inbound port range')
        if any(low <= port <= high for port in ports):
            return True
    return False


def prepare(documents, mark=None):
    """Return changed documents only; preserve every manual rule and protected VPN file."""
    docs = copy.deepcopy(documents)
    own = fragment(mark)
    existing = docs.get(FILE)
    if existing is not None:
        comparable = {key: value for key, value in existing.items() if key != 'api'}
        old_marks = [None, mark]
        try:
            old_marks.append(existing['outbounds'][0]['streamSettings']['sockopt']['mark'])
        except (KeyError, TypeError, IndexError):
            pass
        if not any(comparable == fragment(value) for value in old_marks):
            raise ValueError('reserved inspection file contains unowned content')
    apis = [(name, doc['api']) for name, doc in docs.items() if 'api' in doc]
    if len(apis) > 1:
        raise ValueError('multiple API fragments are unsupported')
    if apis:
        api_name, api = apis[0]
        if api_name == '04_outbounds.json' or not isinstance(api, dict):
            raise ValueError('API configuration is protected or invalid')
        if not isinstance(api.get('services'), list) or any(not isinstance(s, str) for s in api['services']):
            raise ValueError('invalid API services')
        api = copy.deepcopy(api)
        api['services'] += [service for service in API_SERVICES if service not in api['services']]
        docs[api_name]['api'] = api
        api_port({api_name: {'api': api}})
        if api_name == FILE:
            own['api'] = api
    else:
        own['api'] = {'tag': 'kdn-inspection-api', 'listen': f'127.0.0.1:{API_PORT}', 'services': list(API_SERVICES)}
    port = api_port({name: doc for name, doc in docs.items() if name != FILE} | {FILE: own})
    if port in (VPN_PORT, DIRECT_PORT):
        raise ValueError('API port conflicts with a diagnostic SOCKS listener')
    reserved = (VPN_IN, DIRECT_IN, DIRECT_TAG)
    for name, doc in docs.items():
        if name == FILE:
            continue
        for row in doc.get('inbounds', []):
            if row.get('tag') in reserved or _covers(row.get('port'), (VPN_PORT, DIRECT_PORT, port)):
                raise ValueError('inspection listener tag/port conflicts with existing inbound')
        if any(row.get('tag') in reserved for row in doc.get('outbounds', [])):
            raise ValueError('inspection outbound tag collision')
    routing_names = [name for name, doc in docs.items() if isinstance(doc.get('routing'), dict)]
    if not routing_names or routing_names[-1] == '04_outbounds.json':
        raise ValueError('mutable routing fragment not found')
    active = routing_names[-1]
    for name in routing_names:
        rows = docs[name]['routing'].get('rules', [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('invalid Xray rules')
        kept = []
        for row in rows:
            if row.get('ruleTag') in ('kdn-inspect-vpn', 'kdn-inspect-direct'):
                if row not in rules():
                    raise ValueError('inspection rule ownership conflict')
            elif any(tag in str(row.get('inboundTag', '')) for tag in (VPN_IN, DIRECT_IN)):
                raise ValueError('manual rule conflicts with diagnostic inbound')
            else:
                kept.append(row)
        docs[name]['routing']['rules'] = (rules() if name == active else []) + kept
    if not any(row.get('tag') == VPN_TAG and row.get('protocol') not in ('freedom', 'blackhole', 'loopback', 'dns')
               for doc in docs.values() for row in doc.get('outbounds', [])):
        raise ValueError('active VPN outbound is missing')
    docs[FILE] = own
    return {name: doc for name, doc in docs.items() if documents.get(name) != doc}

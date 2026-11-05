"""One bounded inspection, under the same project lock as cooperating writers."""
import time
import secrets
import ipaddress
from urllib.parse import urlsplit

from kdn.common import lock
from kdn.engine import transaction
from kdn.inspection import context, layout, native, probe, request, resources, transport, wire


def _route(live, query):
    if not any(row.get('tag') == query['inbound'] for doc in live.documents.values() for row in doc.get('inbounds', [])):
        raise ValueError('requested inbound does not exist in configured Xray')
    addresses = [query['ip']] if query['ip'] else context.resolve(query['domain'])
    raw = live.client.call('ListOutbounds')
    protocols = dict(wire.handler_tags(raw))
    rows = []
    for address in addresses:
        outbound = live.client.route(**(query | {'ip': address}))
        protocol = protocols.get(outbound, 'unknown')
        if outbound == layout.VPN_TAG:
            native.prove(live.binary, {'outbounds': [live.outbound]}, raw, b'', inbound=False)
        rows.append({'ip': address, 'outbound': outbound,
                     'path': 'direct' if protocol == 'xray.proxy.freedom.Config' else 'block' if protocol == 'xray.proxy.blackhole.Config'
                     else 'vpn' if outbound == layout.VPN_TAG else 'other'})
    return {'routes': rows, 'query': query, 'scope': 'Xray TestRoute, TCP/UDP routing decision',
            'note': ('IP задан явно. ' if query['ip'] else 'Использованы ответы DNS роутера (до 8); DNS клиента может отличаться. ')
                    + 'Без source IP/порта контекст неполный. Direct может обрабатываться nfqws2; доступность этим тестом не доказана.'}


def _fetch(live, mode, url, *, tls='', family=None):
    try:
        candidates = [ipaddress.ip_address(ip) for ip in context.resolve(urlsplit(url).hostname)]
    except (ValueError, OSError, transport.Failure):
        candidates = []
    candidates = [ip for ip in candidates if ip.is_global and (family is None or ip.version == (4 if family == 'ipv4' else 6))]
    if not candidates:
        return {'ok': False, 'reachable': False, 'http_code': None, 'bytes': 0, 'latency_ms': None,
                'body': b'', 'detail': 'DNS не дал публичный адрес требуемой family'}
    target_ip = str(candidates[0])
    source_port = context.source_port()
    live.route_path(mode, target_ip, source_port)
    live.stable()
    result = probe.fetch(url, layout.VPN_PORT if mode == 'vpn' else layout.DIRECT_PORT,
                         target_ip=target_ip, source_port=source_port, tls=tls)
    live.stable()
    live.route_path(mode, target_ip, source_port)
    return result | {'target_ip': target_ip}


def _vpn(live, query):
    live.prove_paths(['vpn'])
    observed, checks = {}, []
    for family in query['families']:
        result = _fetch(live, 'vpn', resources.IP_URLS[family], family=family)
        try:
            if not result['ok']:
                raise ValueError('IP endpoint did not succeed')
            observed[family] = probe.parse_ip(result['body'], family)
            detail = 'Выходной IP получен через активный VPN'
        except (ValueError, TypeError):
            observed[family] = None
            detail = 'Выходной IP этой family не подтверждён'
        checks.append({'family': family, 'ok': observed[family] is not None, 'detail': detail,
                       'http_code': result['http_code'], 'latency_ms': result['latency_ms']})
    canary = _fetch(live, 'vpn', resources.CANARY, family=query['families'][0])
    checks.append({'name': 'HTTPS canary', **{k: v for k, v in canary.items() if k != 'body'}})
    # Re-read actual handlers, not merely files/PID, after all network requests.
    live.prove_paths(['vpn'])
    return {'observed': observed, 'families': query['families'], 'checks': checks,
            'connectivity': 'reachable' if canary['ok'] else 'unconfirmed',
            'scope': 'Активный Xray → выбранная VPN-нода → HTTPS; проверяются только указанные IP family и TCP'}


def _resources(live, query):
    live.prove_paths(query['paths'])
    rows = []
    for key in query['targets']:
        name, url = resources.TARGETS[key]
        for mode in query['paths']:
            for tls in (('1.2', '1.3') if query['extended'] else ('',)):
                result = _fetch(live, mode, url, tls=tls)
                rows.append({'id': key, 'name': name, 'path': mode, 'tls': tls or 'auto',
                             **{k: v for k, v in result.items() if k != 'body'}})
    live.prove_paths(query['paths'])
    return {'checks': rows, 'attribution': resources.ATTRIBUTION,
            'scope': 'HTTPS/TCP с проверкой сертификата. Direct через Freedom, с действующим nfqws2/политиками Keenetic. UDP/QUIC не проверяются.'}


def run(ctx, kind, payload):
    query = request.checker_request(kind, payload)
    started = int(time.time())
    base = {'ok': True, 'kind': kind, 'checked_at': started, 'observation_id': secrets.token_hex(16)}
    try:
        transaction.guard(ctx, readonly=True)
        with lock.ProjectLock(ctx.paths.lock_dir):
            if context.pending_recovery(ctx):
                return base | {'status': 'skipped', 'detail': 'Ожидается завершение/восстановление операции'}
            live = context.Live(ctx)
            result = {'route': _route, 'vpn': _vpn, 'resources': _resources}[kind](live, query)
            live.stable()
            return base | result | live.identity | {'status': 'completed', 'finished_at': int(time.time()),
                                                   'runtime_identity': live.runtime_identity}
    except lock.LockBusy:
        return base | {'status': 'skipped', 'detail': 'Проект занят другой операцией'}
    except (ValueError, OSError, RuntimeError):
        return base | {'status': 'unavailable', 'detail': 'Проверка не подтверждена: подготовьте loopback API/SOCKS, проверьте curl HTTP2, Xray и синхронизацию ноды. Службы не менялись.'}

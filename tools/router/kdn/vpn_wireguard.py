"""WireGuard share links and native Xray outbound validation."""
import base64
import ipaddress
import re
from urllib.parse import urlsplit, unquote, parse_qsl


def key(value):
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('WireGuard: ключ должен содержать 32 байта base64') from None
    return value


def endpoint(value):
    uri = urlsplit('udp://' + value)
    if not uri.hostname or not uri.port or uri.path or uri.username or uri.query or uri.fragment:
        raise ValueError('WireGuard: некорректный endpoint')
    return uri.hostname, uri.port


def validate(settings):
    if not isinstance(settings, dict):
        raise ValueError('WireGuard: settings должен быть объектом')
    key(settings.get('secretKey'))
    if not isinstance(settings.get('address'), list) or not settings['address']:
        raise ValueError('WireGuard: нужен address')
    for address in settings['address']:
        ipaddress.ip_interface(address)
    peers = settings.get('peers')
    if not isinstance(peers, list) or not peers:
        raise ValueError('WireGuard: нужен peers')
    for peer in peers:
        if not isinstance(peer, dict): raise ValueError('WireGuard: некорректный peer')
        key(peer.get('publicKey'))
        endpoint(peer.get('endpoint', ''))
        if peer.get('preSharedKey'): key(peer['preSharedKey'])
        for network in peer.get('allowedIPs', ['0.0.0.0/0', '::/0']):
            ipaddress.ip_network(network, strict=False)
        if 'keepAlive' in peer and (type(peer['keepAlive']) is not int or not 0 <= peer['keepAlive'] <= 65535):
            raise ValueError('WireGuard: некорректный keepAlive')
    # Isolated probes must never allocate native TUN interfaces/routing tables.
    settings['noKernelTun'] = True


def parse(source, tag):
    if (not isinstance(source, str) or len(source.encode()) > 32768
            or any(ord(c) < 32 for c in source) or re.search(r'%(?![0-9a-fA-F]{2})', source)):
        raise ValueError('WireGuard: некорректная ссылка')
    uri = urlsplit(source)
    if uri.scheme.lower() not in ('wireguard', 'wg') or uri.path not in ('', '/') or uri.password:
        raise ValueError('WireGuard: некорректная ссылка')
    host, port = endpoint(uri.netloc.rsplit('@', 1)[-1])
    pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
    query = dict(pairs)
    allowed = {'address','publickey','presharedkey','mtu','dns','reserved','keepalive','allowedips'}
    if len(query) != len(pairs) or set(query) - allowed:
        raise ValueError('WireGuard: неизвестные или повторяющиеся параметры; используйте JSON')
    peer = {'endpoint':f'[{host}]:{port}' if ':' in host else f'{host}:{port}',
            'publicKey':query.get('publickey',''),
            'allowedIPs':query.get('allowedips','0.0.0.0/0,::/0').split(',')}
    if query.get('presharedkey'): peer['preSharedKey'] = query['presharedkey']
    if 'keepalive' in query: peer['keepAlive'] = int(query['keepalive'])
    settings = {'secretKey':unquote(uri.username or ''),
                'address':query.get('address','').split(','), 'peers':[peer]}
    if 'mtu' in query:
        settings['mtu'] = int(query['mtu'])
        if not 576 <= settings['mtu'] <= 65535: raise ValueError('WireGuard: некорректный MTU')
    if 'dns' in query:
        settings['remoteDNS'] = [str(ipaddress.ip_address(v)) for v in query['dns'].split(',')]
    if 'reserved' in query:
        settings['reserved'] = [int(v) for v in query['reserved'].split(',')]
        if len(settings['reserved']) != 3 or any(not 0 <= v <= 255 for v in settings['reserved']):
            raise ValueError('WireGuard: reserved должен содержать 3 байта')
    validate(settings)
    return {'tag':tag, 'protocol':'wireguard', 'settings':settings, 'streamSettings':{}}

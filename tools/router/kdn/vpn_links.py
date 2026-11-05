"""Loss-aware URI import for Xray26.10.31, not a generic subscription parser.

Reference: XTLS/Xray-core v26.10.31 infra/conf/transport_{method,security,finalmask}.go.
Unknown/ambiguous/inapplicable query keys fail closed; raw JSON is handled by
the manager separately and retains fields. URI values are decoded exactly once.
"""
import json
import re
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid


def _object(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if not isinstance(result, dict):
        raise ValueError('JSON object required')
    return result


def parse_link(source, tag='vless-reality'):
    if (not isinstance(source, str) or len(source.encode('utf-8')) > 32768
            or re.search(r'%(?![0-9a-fA-F]{2})', source) or any(ord(c) < 32 for c in source)):
        raise ValueError('invalid VPN URI')
    uri = urlsplit(source)
    protocol = uri.scheme.lower()
    if protocol not in {'vless', 'trojan', 'hy2', 'hysteria2'} or not uri.hostname:
        raise ValueError('unsupported VPN URI')
    if uri.path not in {'', '/'}:
        raise ValueError('URI path is not a transport path; use query path or JSON')
    query = {}
    for key, value in parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, errors='strict'):
        if key in query:
            raise ValueError('duplicate URI parameter; use JSON outbound')
        query[key] = value
    used = set()

    def get(key, default=''):
        used.add(key)
        return query.get(key, default)

    for key in ('insecure', 'allowInsecure'):
        value = get(key)
        if value and value.lower() not in {'0', 'false'}:
            raise ValueError('insecure TLS is unsupported; use certificate pinning')
    is_hy = protocol in {'hy2', 'hysteria2'}
    port = uri.port or (443 if is_hy else 0)
    if not 1 <= port <= 65535:
        raise ValueError('port required')
    network = get('type', 'hysteria' if is_hy else 'tcp').lower()
    security = get('security', 'tls' if protocol != 'vless' else 'none').lower()
    if network not in ({'hysteria'} if is_hy else {'tcp', 'raw', 'ws', 'grpc', 'xhttp', 'splithttp'}):
        raise ValueError('unsupported URI transport; use JSON outbound')
    if security not in {'none', 'tls', 'reality'} or (protocol != 'vless' and security == 'none'):
        raise ValueError('unsupported security')
    if security == 'reality' and network not in {'tcp', 'raw', 'grpc', 'xhttp', 'splithttp'}:
        raise ValueError('Reality does not support this transport')
    stream = {'network': network, 'security': security}
    settings = {'address': uri.hostname, 'port': port}
    auth = unquote(uri.username or '', errors='strict')
    if protocol == 'vless':
        if uri.password is not None:
            raise ValueError('VLESS password field is not supported')
        settings.update(id=str(uuid.UUID(auth)), encryption=get('encryption', 'none'))
        if get('flow'):
            settings['flow'] = query['flow']
    else:
        if uri.password is not None:
            auth += ':' + unquote(uri.password, errors='strict')
        if not auth:
            raise ValueError('password required')
        if is_hy:
            settings['version'] = 2
            stream['hysteriaSettings'] = {'version': 2, 'auth': auth}
        else:
            settings['password'] = auth
    if security == 'tls':
        tls = {'serverName': get('sni', uri.hostname)}
        for key, field in (('fp', 'fingerprint'), ('pcs', 'pinnedPeerCertSha256'),
                           ('vcn', 'verifyPeerCertByName'), ('ech', 'echConfigList'),
                           ('pinSHA256', 'pinnedPeerCertSha256')):
            value = get(key)
            if value:
                if field in tls and tls[field] != value:
                    raise ValueError('conflicting TLS aliases')
                tls[field] = value
        if get('alpn', 'h3' if is_hy else ''):
            tls['alpn'] = get('alpn', 'h3' if is_hy else '').split(',')
        stream['tlsSettings'] = tls
    elif security == 'reality':
        password, public_key = get('password'), get('pbk')
        if password and public_key and password != public_key:
            raise ValueError('conflicting Reality aliases')
        if not (password or public_key) or not get('sni'):
            raise ValueError('Reality key and server name required')
        reality = {'serverName': get('sni'), 'fingerprint': get('fp', 'chrome'),
                   'shortId': get('sid'), 'spiderX': get('spx', '/')}
        reality['password' if password else 'publicKey'] = password or public_key
        if get('pqv'):
            reality['mldsa65Verify'] = get('pqv')
        stream['realitySettings'] = reality
    if network == 'ws':
        stream['wsSettings'] = {'path': get('path', '/')}
        if get('host'):
            stream['wsSettings']['host'] = get('host')
    elif network == 'grpc':
        grpc = {'serviceName': get('serviceName')}
        if get('authority'):
            grpc['authority'] = get('authority')
        mode = get('mode')
        if mode:
            if mode not in {'gun', 'multi'}:
                raise ValueError('unsupported gRPC mode')
            grpc['multiMode'] = mode == 'multi'
        stream['grpcSettings'] = grpc
    elif network in {'xhttp', 'splithttp'}:
        xhttp = {'path': get('path', '/')}
        for key in ('host', 'mode'):
            if get(key):
                xhttp[key] = get(key)
        if xhttp.get('mode', 'auto') not in {'auto', 'packet-up', 'stream-up', 'stream-one'}:
            raise ValueError('unsupported XHTTP mode')
        if get('extra'):
            xhttp['extra'] = _object(get('extra'))
        stream['xhttpSettings' if network == 'xhttp' else 'splithttpSettings'] = xhttp
    if get('finalmask'):
        stream['finalmask'] = _object(get('finalmask'))
    # Hopping/obfs subscription dialects are not interchangeable. Full Xray
    # finalmask JSON is supported; unknown URI dialects are explicit rejection.
    if set(query) - used:
        raise ValueError('неподдерживаемые параметры URI или транспорта; используйте JSON outbound')
    return {'tag': tag, 'protocol': 'hysteria' if is_hy else protocol,
            'settings': settings, 'streamSettings': stream}

"""Explicit field edits of one outbound; untouched settings and secrets survive."""
import copy
import ipaddress
import re
import uuid
from kdn import vpn_wireguard


FIELDS = frozenset({'address', 'port', 'sni', 'fingerprint', 'alpn', 'flow',
                    'uuid', 'password', 'public_key', 'short_id', 'encryption',
                    'path', 'host', 'service_name', 'obfs_password'})


def _host(value):
    if not value:
        raise ValueError('адрес сервера не может быть пустым')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('некорректный адрес сервера или SNI') from None
    if len(value) > 253 or not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
        raise ValueError('некорректный адрес сервера или SNI')
    return value


def _section(parent, key):
    value = parent.setdefault(key, {})
    if not isinstance(value, dict):
        raise ValueError('неоднозначная структура outbound; используйте полный JSON')
    return value


def _put(parent, key, value):
    if value == '':
        parent.pop(key, None)
    else:
        parent[key] = value


def patch_outbound(outbound, changes):
    if not isinstance(changes, dict) or not changes or set(changes) - FIELDS:
        raise ValueError('некорректный список изменяемых полей VPN')
    for key, value in changes.items():
        if key == 'port':
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError('порт должен быть целым числом от 1 до 65535')
        elif (not isinstance(value, str) or len(value.encode('utf-8')) > 4096
              or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError('некорректное значение поля VPN')
    result = copy.deepcopy(outbound)
    settings, stream = result['settings'], result['streamSettings']
    protocol, security, network = result['protocol'], stream.get('security'), stream.get('network', 'tcp')
    if protocol == 'wireguard':
        if set(changes) - {'address', 'port'}:
            raise ValueError('WireGuard: ключи и прочие параметры меняются ссылкой или JSON')
        peers = settings.get('peers', [])
        if len(peers) != 1:
            raise ValueError('WireGuard: для редактирования нужен один peer')
        host, port = vpn_wireguard.endpoint(peers[0]['endpoint'])
        host = _host(changes['address']) if 'address' in changes else host
        port = changes.get('port', port)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('WireGuard: некорректный порт')
        peers[0]['endpoint'] = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        return result
    server, auth = settings, settings
    # Keep legacy single-server Xray JSON intact instead of writing ineffective
    # flat fields alongside vnext/servers. Multi-server edits are ambiguous.
    container = 'vnext' if protocol == 'vless' else 'servers' if protocol == 'trojan' else None
    if container and container in settings:
        rows = settings[container]
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError('для редактирования полей нужен один сервер в outbound')
        server = auth = rows[0]
        if protocol == 'vless':
            users = server.get('users')
            if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
                raise ValueError('для редактирования полей нужен один пользователь VLESS')
            auth = users[0]
    for key, value in changes.items():
        if key == 'address':
            server['address'] = _host(value)
        elif key == 'port':
            server['port'] = value
        elif key in {'sni', 'fingerprint', 'alpn', 'public_key', 'short_id'}:
            if not isinstance(security, str) or security not in {'tls', 'reality'}:
                raise ValueError('поле требует TLS или Reality')
            tls = _section(stream, 'realitySettings' if security == 'reality' else 'tlsSettings')
            if key == 'sni':
                _put(tls, 'serverName', _host(value) if value else '')
            elif key == 'fingerprint':
                if value and value not in {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized'}:
                    raise ValueError('неподдерживаемый TLS fingerprint')
                _put(tls, 'fingerprint', value)
            elif key == 'alpn':
                if security != 'tls':
                    raise ValueError('ALPN редактируется только для TLS')
                values = [item.strip() for item in value.split(',')] if value else []
                if any(not re.fullmatch(r'[A-Za-z0-9./_-]{1,255}', item) for item in values):
                    raise ValueError('некорректный ALPN')
                if values:
                    tls['alpn'] = values
                else:
                    tls.pop('alpn', None)
            elif security != 'reality':
                raise ValueError('поле требует Reality')
            elif key == 'short_id':
                if len(value) > 16 or len(value) % 2 or not re.fullmatch(r'[0-9a-fA-F]*', value):
                    raise ValueError('Short ID: до 16 шестнадцатеричных символов, чётная длина')
                tls['shortId'] = value
            elif value:
                if not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
                    raise ValueError('некорректный публичный ключ Reality')
                tls['password' if 'password' in tls else 'publicKey'] = value
        elif key in {'uuid', 'flow', 'encryption'}:
            if protocol != 'vless':
                raise ValueError('поле требует VLESS')
            if key == 'uuid' and value:
                try:
                    auth['id'] = str(uuid.UUID(value))
                except ValueError:
                    raise ValueError('некорректный UUID') from None
            elif key == 'flow':
                if value not in {'', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}:
                    raise ValueError('неподдерживаемый Flow')
                _put(auth, 'flow', value)
            elif key == 'encryption' and value:
                if not re.fullmatch(r'[A-Za-z0-9_+./=:-]+', value):
                    raise ValueError('некорректное шифрование VLESS')
                auth['encryption'] = value
        elif key == 'password':
            if protocol not in {'trojan', 'hysteria'}:
                raise ValueError('пароль редактируется для Trojan или Hysteria2')
            if value:
                if protocol == 'hysteria':
                    _section(stream, 'hysteriaSettings')['auth'] = value
                else:
                    auth['password'] = value
        elif key in {'path', 'host'}:
            if not isinstance(network, str):
                raise ValueError('некорректный транспорт VPN')
            section = {'ws': 'wsSettings', 'xhttp': 'xhttpSettings', 'splithttp': 'splithttpSettings',
                       'httpupgrade': 'httpupgradeSettings'}.get(network)
            if not section:
                raise ValueError('поле требует WS, XHTTP или HTTPUpgrade')
            transport = _section(stream, section)
            _put(transport, key, value)
            if key == 'host' and isinstance(transport.get('headers'), dict) and 'Host' in transport['headers']:
                _put(transport['headers'], 'Host', value)
        elif key == 'service_name':
            if network != 'grpc':
                raise ValueError('Service name требует gRPC')
            _put(_section(stream, 'grpcSettings'), 'serviceName', value)
        elif key == 'obfs_password':
            if protocol != 'hysteria':
                raise ValueError('пароль обфускации требует Hysteria2')
            mask_config = stream.get('finalmask')
            masks = mask_config.get('udp', []) if isinstance(mask_config, dict) else []
            if not isinstance(masks, list):
                raise ValueError('некорректная конфигурация UDP mask')
            matches = [mask for mask in masks if isinstance(mask, dict) and mask.get('type') == 'salamander']
            if len(matches) != 1:
                raise ValueError('нужен один существующий Salamander/Gecko mask')
            if value:
                _section(matches[0], 'settings')['password'] = value
    return result

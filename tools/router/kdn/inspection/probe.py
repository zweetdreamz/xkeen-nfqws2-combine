"""Explicit SOCKS HTTPS probes. A failed proxy never falls back to Direct."""
import ipaddress
import json
from urllib.parse import urlsplit

from kdn.inspection import resources, transport


def parse_ip(raw, family):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate IP response key')
            result[key] = value
        return result
    if family not in resources.IP_URLS or len(raw) > 1024:
        raise ValueError('invalid IP observation')
    value = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(value, dict) or set(value) != {'ip'} or not isinstance(value['ip'], str):
        raise ValueError('invalid IP response')
    ip = ipaddress.ip_address(value['ip'])
    if ip.version != (4 if family == 'ipv4' else 6) or not ip.is_global:
        raise ValueError('IP response family or scope mismatch')
    return str(ip)


def fetch(url, port, *, target_ip, source_port, tls='', curl='curl'):
    if url not in resources.URLS or type(port) is not int or not 1 <= port <= 65535 or tls not in ('', '1.2', '1.3'):
        raise ValueError('unsupported resource check')
    address = ipaddress.ip_address(target_ip)
    if not address.is_global or type(source_port) is not int or not 1024 <= source_port <= 65535:
        raise ValueError('inspection requires a pinned public IP and explicit source port')
    host = urlsplit(url).hostname
    destination = str(address) if address.version == 4 else '[' + str(address) + ']'
    command = [curl, '--disable', '--silent', '--show-error', '--noproxy', '', '--proxy', '',
               '--socks5', f'127.0.0.1:{port}', '--proto', '=https', '--proto-redir', '=https',
               '--interface', '127.0.0.1', '--local-port', str(source_port),
               '--connect-to', f'{host}:443:{destination}:443',
               '--connect-timeout', '3', '--max-time', '6', '--max-filesize', '65536', '--range', '0-65535',
               '--http1.1', '--header', 'Connection: close', '--user-agent', 'XKeen-Resource-Checker/1',
               '--write-out', '\nKDN:%{http_code}:%{size_download}:%{time_total}']
    if tls:
        command += ['--tlsv' + tls, '--tls-max', tls]
    command.append(url)
    failure = None
    try:
        raw = transport.run(command, timeout=7, limit=66000)
    except transport.Failure as error:
        raw, failure = error.partial, error.code
    try:
        body, separator, stats = raw.rpartition(b'\nKDN:')
        if not separator:
            body, stats = raw, b'000:0:0'
        code, size, duration = stats.decode('ascii').split(':')
        if failure is not None:
            size = len(body)
            reason = 'timeout' if failure in (28, 124) else 'reset' if failure in (52, 55, 56) else 'limit' if failure == 63 else 'network'
            pattern = 'partial-16-34k' if 14000 <= size <= 34000 and reason in ('timeout', 'reset') else 'incomplete'
            return {'ok': False, 'reachable': code.isdecimal() and int(code) >= 100,
                    'http_code': int(code) if code.isdecimal() and int(code) >= 100 else None,
                    'bytes': min(size, 65536), 'latency_ms': None, 'body': b'', 'failure': reason, 'read_pattern': pattern,
                    'detail': ('Обрыв после 14–34 КиБ; возможен пороговый сбой, требуется сравнение путей. DPI этим не доказан.'
                               if pattern == 'partial-16-34k' else 'HTTPS не завершён: ' + reason + '. Причина DPI не установлена.')}
        if not separator or len(body) > 65536 or not code.isdecimal() or not 100 <= int(code) <= 599:
            raise ValueError('invalid HTTP observation')
        return {'ok': 200 <= int(code) < 400, 'reachable': True, 'http_code': int(code),
                'bytes': int(float(size)), 'latency_ms': round(float(duration) * 1000), 'body': body,
                'detail': 'HTTPS ответ получен' if int(code) < 400 else 'HTTPS доступен; HTTP отказ не доказывает DPI'}
    except ValueError:
        return {'ok': False, 'reachable': False, 'http_code': None, 'bytes': 0, 'latency_ms': None,
                'body': b'', 'detail': 'Нет подтверждённого HTTPS-ответа: TLS, DNS, сеть или лимит. Причина DPI не установлена.'}

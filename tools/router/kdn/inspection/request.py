"""Bounded input contracts shared by HTTP admission and diagnostic worker."""
import ipaddress
import re

from kdn.inspection import resources


def checker_request(kind, value):
    if not isinstance(value, dict):
        raise ValueError('ожидается объект параметров проверки')
    if kind == 'route':
        if set(value) - {'domain', 'ip', 'inbound', 'network', 'port', 'source', 'source_port'}:
            raise ValueError('неизвестные поля маршрута')
        result = dict(domain='', ip='', inbound='redirect', network='tcp', port=443, source='', source_port=0) | value
        for key in ('domain', 'ip', 'inbound', 'network', 'source'):
            if not isinstance(result[key], str):
                raise ValueError('параметры маршрута должны быть строками')
        domain = result['domain'].strip().rstrip('.').lower()
        try:
            domain = domain.encode('idna').decode('ascii')
        except UnicodeError as error:
            raise ValueError('некорректное доменное имя') from error
        if domain and (len(domain) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                                              for part in domain.split('.'))):
            raise ValueError('введите домен без URL, пути и порта')
        result['domain'] = domain
        for key in ('ip', 'source'):
            if result[key]:
                result[key] = str(ipaddress.ip_address(result[key]))
        if (not domain and not result['ip']) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', result['inbound']):
            raise ValueError('укажите домен/IP и inbound')
        if result['network'] not in ('tcp', 'udp'):
            raise ValueError('network: tcp или udp')
        if any(type(result[key]) is not int or not minimum <= result[key] <= 65535
               for key, minimum in (('port', 1), ('source_port', 0))):
            raise ValueError('некорректный порт')
        return result
    if kind == 'resources':
        if set(value) - {'targets', 'paths', 'extended'}:
            raise ValueError('неизвестные поля ресурсной проверки')
        result = {'targets': ['youtube', 'discord'], 'paths': ['direct', 'vpn'], 'extended': False} | value
        for key, allowed, maximum in (('targets', resources.TARGETS, 4), ('paths', ('direct', 'vpn'), 2)):
            rows = result[key]
            if (not isinstance(rows, list) or not 1 <= len(rows) <= maximum or any(not isinstance(x, str) or x not in allowed for x in rows)
                    or len(set(rows)) != len(rows)):
                raise ValueError('неподдерживаемый набор ресурсов/путей')
        if type(result['extended']) is not bool or ('tcp16' in result['targets'] and not result['extended']):
            raise ValueError('TCP16 доступен только в расширенной ручной проверке')
        return result
    if kind == 'vpn':
        if set(value) - {'families'}:
            raise ValueError('неизвестные поля проверки VPN')
        families = value.get('families', ['ipv4', 'ipv6'])
        if (not isinstance(families, list) or not 1 <= len(families) <= 2
                or any(not isinstance(x, str) or x not in resources.IP_URLS for x in families)
                or len(set(families)) != len(families)):
            raise ValueError('выберите ipv4 и/или ipv6')
        return {'families': families}
    raise ValueError('неизвестный вид проверки')

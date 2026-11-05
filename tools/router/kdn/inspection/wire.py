"""Small bounded protobuf wire subset for three unary read-only Xray RPCs."""
import ipaddress


MAX_MESSAGE = 1024 * 1024


class Invalid(ValueError):
    pass


def varint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise Invalid('invalid protobuf integer')
    data = bytearray()
    while value > 127:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data) + bytes([value])


def integer(number, value):
    return varint(number << 3) + varint(value)


def blob(number, value):
    if len(value) > MAX_MESSAGE:
        raise Invalid('protobuf size limit')
    return varint((number << 3) | 2) + varint(len(value)) + value


def text(number, value):
    return blob(number, value.encode('utf-8'))


def _read(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            break
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise Invalid('invalid protobuf varint')


def fields(data):
    if len(data) > MAX_MESSAGE:
        raise Invalid('protobuf size limit')
    result, pos = [], 0
    while pos < len(data):
        tag, pos = _read(data, pos)
        number, kind = tag >> 3, tag & 7
        if not 0 < number < 2**29 or len(result) >= 8192:
            raise Invalid('protobuf field limit')
        if kind == 0:
            value, pos = _read(data, pos)
        elif kind in (1, 2, 5):
            if kind == 2:
                length, pos = _read(data, pos)
            else:
                length = 8 if kind == 1 else 4
            if pos + length > len(data):
                raise Invalid('truncated protobuf')
            value, pos = data[pos:pos + length], pos + length
        else:
            raise Invalid('unsupported protobuf wire type')
        result.append((number, kind, value))
    return result


def string(data, number):
    values = [value for field, kind, value in fields(data) if field == number and kind == 2]
    if len(values) != 1 or len(values[0]) > 256:
        raise Invalid('missing or ambiguous protobuf string')
    try:
        value = values[0].decode('utf-8')
    except UnicodeError as error:
        raise Invalid('invalid protobuf string') from error
    if not value or any(ord(char) < 32 for char in value):
        raise Invalid('invalid protobuf string')
    return value


def route_request(inbound, network, port, domain='', ip='', source='', source_port=0, local_ip='', local_port=0):
    if network not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
        raise Invalid('invalid route target')
    if len(inbound) > 128 or len(domain) > 253 or not 0 <= source_port <= 65535:
        raise Invalid('invalid route context')
    context = text(1, inbound) + integer(2, 2 if network == 'tcp' else 3) + integer(6, port)
    if domain:
        context += text(7, domain)
    if ip:
        context += blob(4, ipaddress.ip_address(ip).packed)
    if source:
        context += blob(3, ipaddress.ip_address(source).packed)
    if source_port:
        context += integer(5, source_port)
    if local_ip:
        context += blob(13, ipaddress.ip_address(local_ip).packed)
    if local_port:
        context += integer(14, local_port)
    return blob(1, context) + text(2, 'outbound')


def route_result(data):
    return string(data, 12)


def handler_tags(data):
    result = []
    for number, kind, row in fields(data):
        if number != 1 or kind != 2 or len(result) >= 128:
            raise Invalid('unexpected handler response')
        proxy = [v for n, k, v in fields(row) if n == 3 and k == 2]
        result.append((string(row, 1), string(proxy[0], 1) if len(proxy) == 1 else ''))
    if len({tag for tag, _protocol in result}) != len(result):
        raise Invalid('duplicate handler tags')
    return result

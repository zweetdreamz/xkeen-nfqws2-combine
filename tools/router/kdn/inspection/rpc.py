"""Loopback-only gRPC, with no mutating methods or general-purpose URL input."""
import re
import struct

from kdn.inspection import transport, wire


METHODS = {
    'TestRoute': 'xray.app.router.command.RoutingService/TestRoute',
    'ListOutbounds': 'xray.app.proxyman.command.HandlerService/ListOutbounds',
    'ListInbounds': 'xray.app.proxyman.command.HandlerService/ListInbounds',
    'ListRule': 'xray.app.router.command.RoutingService/ListRule',
}


class Unavailable(RuntimeError):
    pass


def require_http2():
    try:
        version = transport.run(['curl', '--disable', '--version'], timeout=3, limit=8192)
    except transport.Failure as error:
        raise Unavailable('curl with HTTP2 is required') from error
    if not any(line.startswith(b'Features:') and b'HTTP2' in line.split() for line in version.splitlines()):
        raise Unavailable('curl with HTTP2 is required')


def unframe(data):
    if len(data) > wire.MAX_MESSAGE + 16384:
        raise Unavailable('RPC response limit')
    headers, separator, remaining = data.partition(b'\r\n\r\n')
    if not separator or not re.match(rb'HTTP/(?:2|2\.0) 200[ \t]*(?:\r\n|$)', headers):
        raise Unavailable('RPC requires HTTP2 status 200')
    if b'content-type: application/grpc' not in headers.lower():
        raise Unavailable('RPC content type')
    if len(remaining) < 5 or remaining[0] != 0:
        raise Unavailable('RPC missing or compressed frame')
    size = struct.unpack('!I', remaining[1:5])[0]
    if size > wire.MAX_MESSAGE or len(remaining) < 5 + size:
        raise Unavailable('RPC truncated frame')
    body, trailers = remaining[5:5 + size], remaining[5 + size:]
    all_headers = headers.split(b'\r\n')[1:]
    if trailers:
        if not trailers.endswith(b'\r\n'):
            raise Unavailable('RPC malformed trailers')
        all_headers.extend(trailers.rstrip(b'\r\n').split(b'\r\n'))
    statuses = []
    for line in all_headers:
        key, colon, value = line.partition(b':')
        if not colon or not re.fullmatch(rb'[a-zA-Z0-9_-]+', key):
            raise Unavailable('RPC malformed headers')
        if key.lower() == b'grpc-status':
            statuses.append(value.strip())
    if statuses != [b'0']:
        raise Unavailable('RPC failed or missing status')
    return body


class Client:
    def __init__(self, port=10085, *, curl='curl'):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('RPC port must be a loopback port number')
        self.port, self.curl = port, curl

    def call(self, method, body=b''):
        if method not in METHODS:
            raise ValueError('read-only RPC allowlist')
        if len(body) > wire.MAX_MESSAGE:
            raise ValueError('RPC request limit')
        command = [self.curl, '--disable', '--silent', '--show-error', '--include', '--http2-prior-knowledge',
                   '--proxy', '', '--noproxy', '*', '--proto', '=http', '--connect-timeout', '2', '--max-time', '4',
                   '--max-filesize', str(wire.MAX_MESSAGE), '--request', 'POST',
                   '--header', 'content-type: application/grpc', '--header', 'te: trailers', '--data-binary', '@-',
                   f'http://127.0.0.1:{self.port}/{METHODS[method]}']
        try:
            return unframe(transport.run(command, data=b'\0' + struct.pack('!I', len(body)) + body,
                                         timeout=5, limit=wire.MAX_MESSAGE + 16384))
        except (transport.Failure, wire.Invalid) as error:
            raise Unavailable('Xray read-only API unavailable; check services and curl HTTP2') from error

    def route(self, *, inbound, network, port, domain='', ip='', source='', source_port=0, local_ip='', local_port=0):
        return wire.route_result(self.call('TestRoute', wire.route_request(
            inbound, network, port, domain, ip, source, source_port, local_ip, local_port)))

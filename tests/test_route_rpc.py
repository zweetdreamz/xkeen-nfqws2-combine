"""Read-only Xray RPC: malformed responses must never authorize a live probe."""
import ipaddress
from pathlib import Path
import struct
import sys

import pytest

from kdn.inspection import rpc, transport, wire


def response(body=b'', status='0'):
    return (b'HTTP/2 200\r\ncontent-type: application/grpc\r\n\r\n'
            + b'\0' + struct.pack('!I', len(body)) + body
            + b'grpc-status: ' + status.encode() + b'\r\n')


def test_route_context_matches_native_proto():
    request = wire.route_request('redirect', 'tcp', 443, 'example.org', '2001:db8::1', '192.0.2.2', 12345)
    outer = wire.fields(request)
    ctx = wire.fields(outer[0][2])
    assert (2, 0, 2) in ctx  # Xray TCP enum is 2, not 1.
    assert (4, 2, ipaddress.ip_address('2001:db8::1').packed) in ctx
    assert (3, 2, ipaddress.ip_address('192.0.2.2').packed) in ctx
    assert outer[1] == (2, 2, b'outbound')
    assert wire.route_result(wire.text(12, 'vless-reality')) == 'vless-reality'
    assert rpc.unframe(response(b'native').replace(b'HTTP/2 200\r', b'HTTP/2 200 \r')) == b'native'


@pytest.mark.parametrize('data', [b'\x08\x80', b'\x0a\xff\x7f', b'\0', b'\x0b', b'\x08' + b'\xff'*10])
def test_invalid_wire_rejected(data):
    with pytest.raises(wire.Invalid):
        wire.fields(data)


@pytest.mark.parametrize('data', [
    response(status='13'), response()[:-4], response().replace(b'HTTP/2 200', b'HTTP/2 500'),
    response().replace(b'\0\0\0\0\0', b'\1\0\0\0\0'),
    response() + b'junk', response().replace(b'grpc-status: 0', b'other: 0'),
    response() + b'grpc-status: 0\r\n',
])
def test_grpc_fails_closed(data):
    with pytest.raises(rpc.Unavailable):
        rpc.unframe(data)


def test_transport_no_unbounded_output_or_deadline():
    with pytest.raises(transport.Failure, match='limit'):
        transport.run([sys.executable, '-c', 'import os; os.write(1,b"a"*100000)'], limit=1024)
    with pytest.raises(transport.Failure, match='timeout'):
        transport.run([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.05)


def test_rpc_is_loopback_and_readonly(monkeypatch):
    commands = []

    def run(argv, **kwargs):
        commands.append((argv, kwargs))
        return response(wire.text(12, 'direct'))

    monkeypatch.setattr(transport, 'run', run)
    client = rpc.Client(10085)
    assert client.route(inbound='redirect', network='udp', port=443, domain='example.org', ip='192.0.2.1') == 'direct'
    argv, kwargs = commands[0]
    assert argv[1] == '--disable'
    assert '--http2-prior-knowledge' in argv
    assert argv[argv.index('--proxy') + 1] == ''
    assert argv[-1] == 'http://127.0.0.1:10085/xray.app.router.command.RoutingService/TestRoute'
    assert kwargs['data'][0] == 0
    with pytest.raises(ValueError):
        client.call('RemoveOutbound')
    with pytest.raises(ValueError):
        rpc.Client('192.168.1.1:10085')


def test_typed_handlers_do_not_return_settings_as_status():
    row = wire.text(1, 'vpn') + wire.blob(3, wire.text(1, 'xray.proxy.vless.outbound.Config') + wire.blob(2, b'private'))
    assert wire.handler_tags(wire.blob(1, row)) == [('vpn', 'xray.proxy.vless.outbound.Config')]


def test_worker_timeout_reaps_stubborn_nested_probe(tmp_path):
    marker = tmp_path / 'orphan'
    ready = tmp_path / 'ready'
    router_dir = Path(__file__).resolve().parents[1] / 'tools/router'
    probe_code = ('import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                  f'Path({str(ready)!r}).touch(); time.sleep(1.5); Path({str(marker)!r}).touch()')
    worker_code = (f'import sys; sys.path.insert(0,{str(router_dir)!r}); import route_checker; '
                   'from kdn.inspection import transport; route_checker._install_signal_handlers(); '
                   f'transport.run([sys.executable,"-c",{probe_code!r}], timeout=10)')
    with pytest.raises(transport.Failure, match='timeout'):
        transport.run([sys.executable, '-c', worker_code], timeout=.5, termination_grace=2)
    assert ready.exists(), 'the nested process must be running when outer timeout occurs'
    # The marker would be created only by an orphan. Wait in a bounded child,
    # then verify the real external side effect, rather than mirroring cleanup.
    transport.run([sys.executable, '-c', 'import time; time.sleep(1.2)'])
    assert not marker.exists()

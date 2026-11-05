"""Inspection is read-only unless diagnostic access is explicitly prepared."""
import copy
import json

import pytest

from kdn.inspection import layout, native, probe


def corpus():
    return {'04_outbounds.json': {'outbounds': [
        {'tag': 'vless-reality', 'protocol': 'vless', 'settings': {}},
        {'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}]},
        '05_routing.json': {'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
            {'inboundTag': ['dns-main-xkeen'], 'outboundTag': 'vless-reality'},
            {'inboundTag': ['redirect', 'tproxy'], 'network': 'tcp,udp', 'outboundTag': 'direct'}]}}}


def test_explicit_layout_preserves_protected_config_default_and_manual_routes():
    docs = corpus()
    before = copy.deepcopy(docs)
    updates = layout.prepare(docs)
    assert docs == before
    assert '04_outbounds.json' not in updates
    assert updates['05_routing.json']['routing']['rules'][2:] == before['05_routing.json']['routing']['rules']
    own = updates[layout.FILE]
    assert own['api']['listen'] == '127.0.0.1:10085'
    assert all(row['listen'] == '127.0.0.1' for row in own['inbounds'])
    assert own['outbounds'][0]['protocol'] == 'freedom'
    assert not layout.prepare(docs | updates)


@pytest.mark.parametrize('conflict', [
    {'api': {'tag': 'api', 'listen': '0.0.0.0:10085', 'services': ['RoutingService']}},
    {'inbounds': [{'tag': 'user', 'listen': '0.0.0.0', 'port': 18445}]},
    {'outbounds': [{'tag': layout.DIRECT_TAG, 'protocol': 'freedom'}]},
])
def test_setup_refuses_conflicts_before_any_change(conflict):
    docs = corpus() | {'03_custom.json': conflict}
    with pytest.raises(ValueError):
        layout.prepare(docs)


def test_existing_loopback_api_is_extended_without_losing_services():
    docs = corpus() | {'01_api.json': {'api': {'tag': 'user-api', 'listen': '127.0.0.1:11111',
                                             'services': ['StatsService']}}}
    updated = layout.prepare(docs)
    assert updated['01_api.json']['api'] == {'tag': 'user-api', 'listen': '127.0.0.1:11111',
        'services': ['StatsService', 'RoutingService', 'HandlerService']}
    assert 'api' not in updated[layout.FILE]


def test_native_proof_compares_full_settings_not_tag(monkeypatch):
    expected = {'outbound': [{'tag': 'vpn', 'senderSettings': {'network': 'tcp'},
                              'proxySettings': {'account': {'id': 'synthetic-old'}}}]}
    live = {'outbounds': [copy.deepcopy(expected['outbound'][0])]}
    monkeypatch.setattr(native, 'compile_config', lambda *_a: expected)
    monkeypatch.setattr(native, 'decode', lambda *_a: live)
    native.prove('xray', {'outbounds': []}, b'live', b'', inbound=False)
    live['outbounds'][0]['proxySettings']['account']['id'] = 'synthetic-new'
    with pytest.raises(ValueError, match='live'):
        native.prove('xray', {}, b'live', b'', inbound=False)


def test_native_json_skips_loader_notice_braces():
    assert native._json(b'2026 [Info] Reading config: &{Name:stdin: Format:json}\n{\n"outbound": []\n}\n') == {'outbound': []}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native.transport, 'run', lambda *_a, **_kw: b'Xray 26.10.31 synthetic')
        native.require_version('xray')
        patch.setattr(native.transport, 'run', lambda *_a, **_kw: b'Xray 26.9.1 synthetic')
        with pytest.raises(ValueError, match='26.10.31'):
            native.require_version('xray')


def test_egress_ip_is_strict_and_family_specific():
    assert probe.parse_ip(b'{"ip":"2001:4860:4860::8888"}', 'ipv6') == '2001:4860:4860::8888'
    for data, family in [(b'{"ip":"1.1.1.1"}', 'ipv6'), (b'<html>1.1.1.1</html>', 'ipv4'),
                         (b'{"ip":"127.0.0.1"}', 'ipv4'), (b'{"ip":"1.1.1.1","ip":"8.8.8.8"}', 'ipv4')]:
        with pytest.raises(ValueError):
            probe.parse_ip(data, family)


def test_probe_mandatory_explicit_socks_tls_and_fixed_targets(monkeypatch):
    commands = []
    def run(argv, **kwargs):
        commands.append(argv)
        return b'{"ip":"1.1.1.1"}\nKDN:200:15:0.01'
    monkeypatch.setattr(probe.transport, 'run', run)
    result = probe.fetch('https://api.ipify.org?format=json', 18445, target_ip='1.1.1.1', source_port=45678)
    assert result['http_code'] == 200 and json.loads(result['body'])['ip'] == '1.1.1.1'
    args = commands[0]
    assert args[1] == '--disable'
    assert args[args.index('--socks5') + 1] == '127.0.0.1:18445'
    assert args[args.index('--noproxy') + 1] == ''
    assert '--insecure' not in args and '--location' not in args
    with pytest.raises(ValueError):
        probe.fetch('https://192.168.2.1', 18445, target_ip='1.1.1.1', source_port=45678)


def test_tcp16_keeps_bounded_partial_size_without_exposing_body(monkeypatch):
    def reset(*_args, **_kwargs):
        raise probe.transport.Failure('command failed', code=56, partial=b'x' * 18000)
    monkeypatch.setattr(probe.transport, 'run', reset)
    result = probe.fetch('https://speed.cloudflare.com/__down?bytes=65536', 18445, target_ip='1.1.1.1', source_port=45678)
    assert result['bytes'] == 18000
    assert result['read_pattern'] == 'partial-16-34k'
    assert not result['ok']

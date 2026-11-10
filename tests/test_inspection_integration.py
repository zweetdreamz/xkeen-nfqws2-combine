"""Safety boundaries of setup, live checks and periodic/manual observations."""
from pathlib import Path
import json
import os
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

import panel_harness
import test_engine_apply_ops as apply_fixture
from kdn.engine import inspection_setup, options
from kdn.inspection import context, layout, policy, probe, receipt, request, worker, wire


@pytest.fixture
def setup_case():
    case = apply_fixture.NativeApplyTests()
    case.setUp()
    try:
        case.put('/opt/etc/xray/configs/03_inbounds.json', b'{"inbounds":[{"tag":"redirect","protocol":"dokodemo-door","port":61219,"settings":{"network":"tcp","followRedirect":true}}]}')
        case.put('/opt/etc/xray/configs/04_outbounds.json', b'{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"vless-reality","protocol":"vless","settings":{}}]}')
        case.ctx.options = options.parse_args(['--setup-route-checker', '--yes-router'])
        case.xkeen_action.return_value = 123
        case.stack.enter_context(mock.patch.object(receipt, 'process_start', return_value='12345'))
        case.stack.enter_context(mock.patch.object(context, '_listener_owned', return_value=False))
        case.stack.enter_context(mock.patch.object(inspection_setup, 'verify_access'))
        # Transaction sequencing fixture; readiness has real proc and timing
        # coverage in test_inspection_readiness.py and isolated runtime probes.
        case.stack.enter_context(mock.patch.object(inspection_setup, 'wait_for_listeners'))
        case.stack.enter_context(mock.patch.object(inspection_setup.system, 'find_xray', return_value=Path('/synthetic/xray')))
        case.stack.enter_context(mock.patch.object(inspection_setup.native, 'require_version'))
        yield case
    finally:
        case.doCleanups()


def test_setup_is_explicit_idempotent_and_keeps_node_nfqws_default(setup_case):
    case = setup_case
    before = case.vpn.read_bytes()
    assert inspection_setup.run(case.ctx) == 0, case.err.getvalue()
    assert case.vpn.read_bytes() == before
    assert Path(case.paths.xray_config_dir, layout.FILE).exists()
    assert case.xkeen_action.call_count == 1
    assert inspection_setup.run(case.ctx) == 0
    assert case.xkeen_action.call_count == 1
    case.nfqws_restart.assert_not_called()


def test_setup_restart_failure_restores_exact_files_and_runtime(setup_case):
    case = setup_case
    before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in Path(case.paths.xray_config_dir).iterdir()}
    case.xkeen_action.side_effect = [RuntimeError('injected failure'), None]
    assert inspection_setup.run(case.ctx) == 1
    after = {p.name: (p.read_bytes(), p.stat().st_mode) for p in Path(case.paths.xray_config_dir).iterdir()}
    assert after == before
    assert case.xkeen_action.call_count == 2
    assert not Path(case.paths.latest_pointer).exists()
    case.nfqws_restart.assert_not_called()


def test_listener_deadline_restores_files_and_does_not_skip_rpc_proof(setup_case):
    case = setup_case
    before = {p.name: p.read_bytes() for p in Path(case.paths.xray_config_dir).iterdir()}
    with mock.patch.object(inspection_setup, 'wait_for_listeners', side_effect=RuntimeError('deadline')):
        assert inspection_setup.run(case.ctx) == 1
    after = {p.name: p.read_bytes() for p in Path(case.paths.xray_config_dir).iterdir()}
    assert before == after
    assert case.xkeen_action.call_count == 2
    inspection_setup.verify_access.assert_not_called()
    case.nfqws_restart.assert_not_called()


@pytest.mark.parametrize('kind,value', [('route', {'domain': 'https://example.org'}),
    ('route', {'domain': 'example.org', 'port': True}), ('resources', {'targets': ['tcp16']}),
    ('resources', {'paths': ['direct', 'direct']}), ('vpn', {'families': []}), ('vpn', {'auto_switch': True})])
def test_invalid_checker_requests_cannot_start_work(kind, value):
    with pytest.raises(ValueError):
        request.checker_request(kind, value)


def test_route_uses_live_protocol_and_multiple_router_dns_answers(monkeypatch):
    raw = wire.blob(1, wire.text(1, 'direct') + wire.blob(3, wire.text(1, 'xray.proxy.freedom.Config')))
    client = SimpleNamespace(call=lambda _method: raw, route=lambda **_kwargs: 'direct')
    live = SimpleNamespace(client=client, documents={'in': {'inbounds': [{'tag': 'redirect'}]}})
    monkeypatch.setattr(context, 'resolve', lambda _domain: ['1.1.1.1', '2606:4700:4700::1111'])
    result = worker._route(live, request.checker_request('route', {'domain': 'Example.Org'}))
    assert [r['path'] for r in result['routes']] == ['direct', 'direct']
    assert result['query']['domain'] == 'example.org'


def test_vpn_partial_ip_never_silently_uses_direct(monkeypatch):
    calls = []
    live = SimpleNamespace(prove_paths=lambda paths: calls.append(tuple(paths)),
                           route_path=lambda mode, ip, source: calls.append((mode, ip, source)), stable=lambda: None)
    monkeypatch.setattr(context, 'resolve', lambda _host: ['1.1.1.1', '2606:4700:4700::1111'])
    def fetch(url, port, **_kwargs):
        assert port == layout.VPN_PORT
        if 'api6.' in url:
            return {'ok': False, 'body': b'', 'http_code': None, 'latency_ms': None}
        return {'ok': True, 'body': b'{"ip":"1.1.1.1"}', 'http_code': 200, 'latency_ms': 10}
    monkeypatch.setattr(probe, 'fetch', fetch)
    result = worker._vpn(live, {'families': ['ipv4', 'ipv6']})
    assert result['observed'] == {'ipv4': '1.1.1.1', 'ipv6': None}
    assert all(call[0] == 'vpn' for call in calls)


def test_no_network_when_live_path_proof_fails(monkeypatch):
    class Unproven:
        def prove_paths(self, _paths):
            raise ValueError('missing live handler')
    fetch = mock.Mock(side_effect=AssertionError('network must not start'))
    monkeypatch.setattr(probe, 'fetch', fetch)
    with pytest.raises(ValueError):
        worker._vpn(Unproven(), {'families': ['ipv4']})
    fetch.assert_not_called()


def test_owned_direct_rejects_chaining_before_network():
    live = object.__new__(context.Live)
    document = layout.fragment()
    document['outbounds'][0]['streamSettings'] = {'sockopt': {'dialerProxy': layout.VPN_TAG}}
    live.documents = {layout.FILE: document}
    with pytest.raises(ValueError, match='plain owned'):
        live.prove_paths(['direct'])


@pytest.fixture
def panel():
    return panel_harness.load_panel()


def test_monitor_get_has_no_probe_disabled_tick_no_work_and_state_private(panel, monkeypatch):
    monitor = panel.module('domain.vpn_monitor')
    infra = panel.module('infra.inspection')
    config = panel.module('infra.config')
    monkeypatch.setattr(monitor.vpn, 'active_identity', lambda: {'node_id': 'current', 'source_digest': 'a'*64})
    run = mock.Mock(side_effect=AssertionError('no implicit probe'))
    monkeypatch.setattr(infra, 'run_inspection_worker', run)
    assert not monitor.vpn_monitor_status()['config']['enabled']
    assert not monitor.tick()
    assert not config.VPN_MONITOR_CONFIG.exists()
    infra.write_inspection_state(config.VPN_MONITOR_STATE, {'history': []})
    assert config.VPN_MONITOR_STATE.stat().st_mode & 0o777 == 0o600
    run.assert_not_called()


def test_approval_requires_exact_shown_observation_and_identity(panel, monkeypatch):
    monitor, infra = panel.module('domain.vpn_monitor'), panel.module('infra.inspection')
    cfg = panel.module('infra.config')
    identity = {'node_id': 'current', 'source_digest': 'a'*64}
    monkeypatch.setattr(monitor.vpn, 'active_identity', lambda: identity)
    monkeypatch.setattr(monitor.vpn, 'vpn_manager', lambda: SimpleNamespace(load=lambda: {'nodes': {'current': {}}}))
    monkeypatch.setattr(monitor.receipt, 'observation_current', lambda *_args: True)
    import time
    result = identity | {'kind': 'vpn', 'status': 'completed', 'checked_at': int(time.time()),
                         'observed': {'ipv4': '1.1.1.1'}, 'observation_id': 'new-observation', 'connectivity': 'reachable'}
    infra.write_inspection_state(cfg.VPN_MONITOR_STATE, {'result': result})
    with pytest.raises(ValueError, match='изменились'):
        monitor.approve_vpn_monitor_ips(['ipv4'], identity, 'old-observation')
    with pytest.raises(ValueError, match='изменилась'):
        monitor.save({'families': ['ipv4'], 'expected': {'ipv4': ['8.8.8.8']}}, identity | {'node_id': 'other'})
    assert not cfg.VPN_MONITOR_CONFIG.exists()
    monitor.approve_vpn_monitor_ips(['ipv4'], identity, 'new-observation')
    settings = monitor.save({'families': ['ipv4'], 'enabled': True}, identity)['config']
    assert settings['nodes']['current']['expected']['ipv4'] == ['1.1.1.1']


def test_background_observes_only_vpn_preserves_config_and_non_overlap(panel, monkeypatch):
    monitor, infra = panel.module('domain.vpn_monitor'), panel.module('infra.inspection')
    cfg = panel.module('infra.config')
    identity = {'node_id': 'current', 'source_digest': 'a'*64}
    monkeypatch.setattr(monitor.vpn, 'active_identity', lambda: identity)
    settings = policy.configure(policy.defaults(), identity,
                                {'families': ['ipv4'], 'expected': {'ipv4': ['1.1.1.1']}, 'enabled': True})
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG, settings)
    before = cfg.VPN_MONITOR_CONFIG.read_bytes()
    calls = []
    def check(kind, payload):
        calls.append((kind, payload))
        assert infra.RUN_LOCK.locked()
        assert not monitor.tick(now=10**10)
        import time
        return identity | {'status': 'completed', 'kind': kind, 'checked_at': int(time.time()),
                           'observed': {'ipv4': '8.8.8.8'}, 'connectivity': 'reachable'}
    monkeypatch.setattr(infra, 'run_inspection_worker', check)
    assert monitor.tick(now=10**10)
    assert calls == [('vpn', {'families': ['ipv4']})]
    assert cfg.VPN_MONITOR_CONFIG.read_bytes() == before
    assert monitor.monitor_state()['verdict'] == 'ip-mismatch'


def test_worker_timeout_has_no_partial_json_or_raw_output(panel, monkeypatch):
    infra = panel.module('infra.inspection')
    monkeypatch.setattr(infra.transport, 'run', lambda *_a, **_k: b'not JSON')
    assert infra.run_inspection_worker('vpn', {'families': ['ipv4']})['status'] == 'unavailable'


def test_pending_focused_recovery_skips_checks(setup_case):
    case = setup_case
    case.put('/opt/etc/xkeen-web/automation-state.json', b'{"status":"recovery-failed","phase":"recovery-needed","transaction":{"schema":1}}')
    result = worker.run(case.ctx, 'vpn', {'families': ['ipv4']})
    assert result['status'] == 'skipped'


def test_invalid_saved_state_is_unavailable_and_scheduler_survives(panel):
    monitor, infra = panel.module('domain.vpn_monitor'), panel.module('infra.inspection')
    cfg = panel.module('infra.config')
    for invalid in ({'result': None}, {'result': {'kind': 'vpn', 'status': 'completed', 'checked_at': 'future'}},
                    {'history': None}, {'last_attempt': 10**20}):
        infra.write_inspection_state(cfg.VPN_MONITOR_STATE, invalid)
        assert monitor.vpn_monitor_status()['verdict'] == 'unavailable'
        stop = mock.Mock()
        stop.is_set.side_effect = [False, True]
        monitor.loop(stop)
        stop.wait.assert_called_once_with(15)


def test_cached_health_and_approval_expire_after_external_restart(panel, monkeypatch):
    import time
    monitor, infra = panel.module('domain.vpn_monitor'), panel.module('infra.inspection')
    cfg = panel.module('infra.config')
    identity = {'node_id': 'current', 'source_digest': 'a'*64}
    monkeypatch.setattr(monitor.vpn, 'active_identity', lambda: identity)
    result = identity | {'kind': 'vpn', 'status': 'completed', 'checked_at': int(time.time()),
                         'observed': {'ipv4': '1.1.1.1'}, 'observation_id': 'shown', 'connectivity': 'reachable'}
    infra.write_inspection_state(cfg.VPN_MONITOR_STATE, {'result': result})
    monkeypatch.setattr(monitor.receipt, 'observation_current', lambda *_args: False)
    assert monitor.vpn_monitor_status()['verdict'] == 'stale'
    with pytest.raises(ValueError, match='изменились'):
        monitor.approve_vpn_monitor_ips(['ipv4'], identity, 'shown')
    assert not cfg.VPN_MONITOR_CONFIG.exists()


def test_receipt_is_private_and_invalid_after_source_or_process_changes(tmp_path):
    directory = tmp_path / 'configs'
    directory.mkdir()
    source = directory / layout.FILE
    source.write_text(json.dumps(layout.fragment()))
    cue = tmp_path / 'inspection-runtime.json'
    pid = os.getpid()
    old_digest = receipt.corpus_digest(directory)
    receipt.record(cue, directory, pid, expected_digest=old_digest)
    assert receipt.matches(cue, directory, pid)
    cue.chmod(0o644)
    assert not receipt.matches(cue, directory, pid)
    cue.chmod(0o600)
    source.write_text(json.dumps(layout.fragment(123)))
    assert not receipt.matches(cue, directory, pid)
    assert not receipt.refresh_if_prepared(cue, directory, pid, expected_digest=old_digest)
    assert not receipt.matches(cue, directory, 2147483647)


def test_live_identity_source_port_route_and_drift_guards(tmp_path, monkeypatch):
    import vpn_node_manager
    directory = tmp_path / 'configs'
    directory.mkdir()
    vpn = {'tag': layout.VPN_TAG, 'protocol': 'vless', 'settings': {'vnext': [{'address': 'vpn.example', 'port': 443,
           'users': [{'id': '00000000-0000-4000-8000-000000000001', 'encryption': 'none'}]}]}, 'streamSettings': {'network': 'tcp'}}
    (directory / '04_outbounds.json').write_text(json.dumps({'outbounds': [vpn]}))
    own = layout.fragment()
    own['api'] = {'tag': 'api', 'listen': '127.0.0.1:10085', 'services': list(layout.API_SERVICES)}
    (directory / layout.FILE).write_text(json.dumps(own))
    manager = vpn_node_manager.VpnNodeManager(xray_dir=directory, state_file=tmp_path/'vpn-nodes.json')
    paths = SimpleNamespace(xray_config_dir=str(directory), test_root=str(tmp_path))
    ctx = SimpleNamespace(paths=paths, environ={})
    cue = tmp_path / 'opt/etc/xkeen-web/inspection-runtime.json'
    receipt.record(cue, directory, os.getpid())
    monkeypatch.setattr(context.system, 'find_xray', lambda *_a: sys.executable)
    monkeypatch.setattr(context.native, 'require_version', lambda _binary: None)
    monkeypatch.setattr(context.xkeen_service, 'pid', lambda _ctx: os.getpid())
    monkeypatch.setattr(context, '_listener_owned', lambda *_a: True)
    routes = []
    class Client:
        port = 10085
        def __init__(self, _port):
            pass
        def call(self, method):
            return method.encode()
        def route(self, **query):
            routes.append(query)
            return layout.VPN_TAG
    monkeypatch.setattr(context.rpc, 'Client', Client)
    proof = mock.Mock()
    monkeypatch.setattr(context.native, 'prove', proof)
    live = context.Live(ctx, manager=manager)
    live.prove_paths(['vpn', 'direct'])
    proof.assert_called_once()
    live.route_path('vpn', '1.1.1.1', 45678)
    assert routes == [{'inbound': layout.VPN_IN, 'network': 'tcp', 'port': 443, 'ip': '1.1.1.1',
                       'source': '127.0.0.1', 'source_port': 45678, 'local_ip': '127.0.0.1', 'local_port': layout.VPN_PORT}]
    live.stable()
    (directory / '05_foreign.json').write_text('{"routing":{"rules":[]}}')
    with pytest.raises(ValueError, match='stale'):
        live.stable()
    with pytest.raises(ValueError, match='re-arm'):
        context.Live(ctx, manager=manager)

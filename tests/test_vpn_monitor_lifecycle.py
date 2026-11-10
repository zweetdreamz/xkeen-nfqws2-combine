"""Deleted CLI/web registry IDs cannot consume monitor approval slots forever."""
import copy
import hashlib
import json
import time
from unittest import mock

import pytest

import panel_harness
from test_vpn_store_boundaries import store as store
from test_vpn_node_manager import outbound
from tools.router import vpn_node_manager as nodes


@pytest.fixture
def monitor_case(store, monkeypatch):
    panel = panel_harness.load_panel()
    monitor = panel.module('domain.vpn_monitor')
    infra = panel.module('infra.inspection')
    cfg = panel.module('infra.config')
    monkeypatch.setattr(monitor.vpn, 'vpn_manager', lambda: store)
    monkeypatch.setattr(monitor.vpn, 'VPN_MODULE', nodes)
    monkeypatch.setattr(cfg, 'PROJECT_LOCK_DIR', store.lock_dir)
    monkeypatch.setattr(cfg, 'VPN_MONITOR_CONFIG', store.state_file.parent / 'monitor-config.json')
    monkeypatch.setattr(cfg, 'VPN_MONITOR_STATE', store.state_file.parent / 'monitor-state.json')
    monkeypatch.setattr(monitor.receipt, 'observation_current', lambda *_args: True)
    return store, monitor, infra, cfg


def approve(monitor, infra, cfg, operation):
    identity = monitor.vpn.active_identity()
    if operation == 'configure':
        monitor.save({'families': ['ipv4'], 'expected': {'ipv4': ['1.1.1.1']}}, identity)
    else:
        observation = identity | {'kind': 'vpn', 'status': 'completed', 'checked_at': int(time.time()),
                                   'observed': {'ipv4': '1.1.1.1'}, 'observation_id': 'shown',
                                   'connectivity': 'reachable'}
        infra.write_inspection_state(cfg.VPN_MONITOR_STATE, {'result': observation})
        monitor.approve_vpn_monitor_ips(['ipv4'], identity, 'shown')


@pytest.mark.parametrize('operation', ['configure', 'approve'])
def test_seventeenth_historical_node_can_be_explicitly_approved_after_cli_deletions(monitor_case, operation):
    store, monitor, infra, cfg = monitor_case
    store.remove('reserve')
    approve(monitor, infra, cfg, operation)
    with mock.patch.object(store, '_xray_pids', return_value=frozenset({'42'})), \
            mock.patch.object(store, '_test_staged'), mock.patch.object(store, '_restart_xkeen'):
        for index in range(1, 18):
            previous = store.load()['active']
            target = f'node_{index}'
            store.add(target, outbound())
            store.activate(target)
            store.remove(previous)  # CLI manager path; no web removal hook.
            assert len(store.load()['nodes']) == 1
            approve(monitor, infra, cfg, operation)
    settings = monitor.monitor_config()
    identity = monitor.vpn.active_identity()
    assert set(settings['nodes']) == {'node_17'}
    assert monitor.policy.expected(settings, identity) == {'ipv4': ['1.1.1.1']}


@pytest.mark.parametrize('operation', ['configure', 'approve'])
def test_pruning_preserves_current_registry_approvals_and_never_inherits_stale_digest(monitor_case, operation):
    store, monitor, infra, cfg = monitor_case
    identity = monitor.vpn.active_identity()
    reserve_source = store.load()['nodes']['reserve']['outbound']
    digest = hashlib.sha256(json.dumps(reserve_source, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    preserved = {'source_digest': digest, 'expected': {'ipv4': ['8.8.8.8']}}
    settings = monitor.policy.defaults()
    settings['nodes'] = {f'deleted_{i}': copy.deepcopy(preserved) for i in range(14)}
    settings['nodes']['reserve'] = copy.deepcopy(preserved)
    settings['nodes']['current'] = {'source_digest': 'f' * 64,
                                    'expected': {'ipv6': ['2606:4700:4700::1111']}}
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG, settings)
    assert monitor.policy.expected(settings, identity) == {}
    approve(monitor, infra, cfg, operation)
    saved = monitor.monitor_config()
    assert set(saved['nodes']) == {'current', 'reserve'}
    assert saved['nodes']['reserve'] == preserved
    assert monitor.policy.expected(saved, identity) == {'ipv4': ['1.1.1.1']}
    assert not saved['enabled']


@pytest.mark.parametrize('failure', ['invalid-approval', 'failed-write'])
def test_failed_explicit_change_does_not_publish_pruning_or_mutate_registry(monitor_case, monkeypatch, failure):
    store, monitor, infra, cfg = monitor_case
    settings = monitor.policy.defaults()
    settings['nodes']['deleted'] = {'source_digest': 'b' * 64, 'expected': {'ipv4': ['8.8.8.8']}}
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG, settings)
    before, registry = cfg.VPN_MONITOR_CONFIG.read_bytes(), store.state_file.read_bytes()
    identity = monitor.vpn.active_identity()
    if failure == 'invalid-approval':
        with pytest.raises(ValueError):
            monitor.approve_vpn_monitor_ips(['ipv4'], identity, 'missing')
    else:
        def fail(*_args):
            raise OSError('injected write failure')
        monkeypatch.setattr(infra, 'write_inspection_state', fail)
        with pytest.raises(OSError, match='injected'):
            monitor.save({'families': ['ipv4'], 'expected': {'ipv4': ['1.1.1.1']}}, identity)
    assert cfg.VPN_MONITOR_CONFIG.read_bytes() == before
    assert store.state_file.read_bytes() == registry


@pytest.mark.parametrize('operation', ['configure', 'approve'])
def test_unreadable_registry_does_not_clear_or_publish_existing_approvals(monitor_case, monkeypatch, operation):
    store, monitor, infra, cfg = monitor_case
    settings = monitor.policy.defaults()
    settings['nodes']['retained'] = {'source_digest': 'a' * 64, 'expected': {'ipv4': ['8.8.8.8']}}
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG, settings)
    before = cfg.VPN_MONITOR_CONFIG.read_bytes()
    identity = monitor.vpn.active_identity()
    monkeypatch.setattr(monitor.vpn, 'active_identity', lambda: identity)
    def fail():
        raise ValueError('registry unavailable')
    monkeypatch.setattr(store, 'load', fail)
    with pytest.raises(ValueError, match='registry unavailable'):
        approve(monitor, infra, cfg, operation)
    assert cfg.VPN_MONITOR_CONFIG.read_bytes() == before


def test_settings_only_change_keeps_existing_source_binding_without_approving_new_source(monitor_case):
    store, monitor, infra, cfg = monitor_case
    identity = monitor.vpn.active_identity()
    settings = monitor.policy.defaults()
    stale = {'source_digest': 'f' * 64, 'expected': {'ipv4': ['8.8.8.8']}}
    settings['nodes'] = {'current': copy.deepcopy(stale), 'deleted': copy.deepcopy(stale)}
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG, settings)
    monitor.save({'interval_minutes': 10}, identity)
    saved = monitor.monitor_config()
    assert saved['nodes'] == {'current': stale}
    assert monitor.policy.expected(saved, identity) == {}
    assert not saved['enabled']

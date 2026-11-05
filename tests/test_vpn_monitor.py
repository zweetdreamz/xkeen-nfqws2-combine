"""IP approval is explicit, per source and per family; the monitor only observes."""
import copy
import time

import pytest

from kdn.inspection import policy


IDENTITY = {'node_id': 'current', 'source_digest': 'a' * 64}


def observation(**changes):
    return {'ok': True, 'kind': 'vpn', 'status': 'completed', 'checked_at': int(time.time()),
            'finished_at': int(time.time()), 'observed': {'ipv4': '1.1.1.1', 'ipv6': None},
            'connectivity': 'reachable', **IDENTITY, **changes}


def test_first_ip_never_enrolled_and_mismatch_never_changes_approval():
    config = policy.defaults()
    config['families'] = ['ipv4']
    original = copy.deepcopy(config)
    result = observation()
    assert policy.verdict(config, IDENTITY, result) == 'unapproved'
    assert config == original
    config = policy.approve_monitor_ips(config, IDENTITY, result, ['ipv4'])
    approved = copy.deepcopy(config)
    assert policy.verdict(config, IDENTITY, result) == 'healthy'
    assert policy.verdict(config, IDENTITY, observation(observed={'ipv4': '8.8.8.8'})) == 'ip-mismatch'
    assert config == approved


def test_source_change_never_inherits_approval_or_stale_result():
    result = observation()
    config = policy.approve_monitor_ips(policy.defaults(), IDENTITY, result, ['ipv4'])
    new = IDENTITY | {'source_digest': 'b' * 64}
    assert policy.verdict(config, new, result) == 'stale'
    with pytest.raises(ValueError):
        policy.approve_monitor_ips(config, new, result, ['ipv4'])
    with pytest.raises(ValueError):
        policy.approve_monitor_ips(config, IDENTITY, observation(checked_at=int(time.time()) - 301), ['ipv4'])


def test_ipv6_unknown_is_not_green_and_enable_needs_all_selected_families():
    config = policy.approve_monitor_ips(policy.defaults(), IDENTITY, observation(), ['ipv4'])
    config['families'] = ['ipv4', 'ipv6']
    assert policy.verdict(config, IDENTITY, observation()) == 'partial'
    with pytest.raises(ValueError):
        policy.configure(config, IDENTITY, {'enabled': True})
    config = policy.configure(config, IDENTITY, {'families': ['ipv4'], 'enabled': True})
    assert config['enabled']


def test_explicit_manual_expected_ip_and_bounded_settings():
    config = policy.configure(policy.defaults(), IDENTITY, {'families': ['ipv4'], 'expected': {'ipv4': ['8.8.8.8']}, 'enabled': True})
    assert config['nodes']['current']['expected']['ipv4'] == ['8.8.8.8']
    for body in ({'balance': True}, {'interval_minutes': 0}, {'enabled': 'yes'}, {'families': []},
                 {'expected': {'ipv4': ['127.0.0.1']}}):
        with pytest.raises(ValueError):
            policy.configure(config, IDENTITY, body)


def test_history_records_transitions_and_stays_bounded():
    state = {}
    for n in range(120):
        state = policy.record_observation(state, observation(), 'healthy' if n % 2 else 'ip-mismatch')
    assert len(state['history']) == 100
    assert len(policy.record_observation(state, observation(), state['verdict'])['history']) == 100


def test_unknown_and_failed_checks_never_look_healthy():
    config = policy.approve_monitor_ips(policy.defaults() | {'families': ['ipv4']}, IDENTITY, observation(), ['ipv4'])
    assert policy.verdict(config, IDENTITY, observation(status='skipped')) == 'skipped'
    assert policy.verdict(config, IDENTITY, observation(status='unavailable')) == 'unavailable'
    assert policy.verdict(config, IDENTITY, observation(connectivity='unconfirmed')) == 'unreachable'

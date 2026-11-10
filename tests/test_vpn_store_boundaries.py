"""Registry byte limits apply before publication and transaction artifacts."""
import copy
import json
from unittest import mock

import pytest

from tools.router import vpn_node_manager as nodes
from test_vpn_node_manager import outbound


NOW = '2026-01-01T00:00:00Z'
HEALTH = {'ok': True, 'detail': 'Проверено'}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


@pytest.fixture
def store(tmp_path, monkeypatch):
    directory = tmp_path / 'xray'
    directory.mkdir()
    (directory / '04_outbounds.json').write_bytes(encoded({'outbounds': [outbound()]}))
    manager = nodes.VpnNodeManager(xray_dir=directory, state_file=tmp_path / 'nodes.json',
                                   backup_dir=tmp_path / 'backups', lock_dir=tmp_path / 'lock',
                                   nfqws_conf=tmp_path / 'absent.conf')
    monkeypatch.setattr(manager, '_require_supported_xkeen', lambda: None)
    monkeypatch.setattr(manager, 'probe', lambda _outbound: copy.deepcopy(HEALTH))
    monkeypatch.setattr(nodes, 'utc_now', lambda: NOW)
    state = manager.load()
    state['nodes']['reserve'] = {'name': 'Резерв', 'outbound': outbound('backup.example'),
                                 'created_utc': NOW, 'health': None}
    # A compact but valid existing registry must remain readable on rejection.
    manager.state_file.write_text(json.dumps(state, ensure_ascii=False), encoding='utf-8')
    # Initialize persistent lock coordination before checking mutation artifacts.
    with nodes.project_lock.ProjectLock(manager.lock_dir):
        pass
    return manager


@pytest.mark.parametrize('operation', ['add', 'update', 'check', 'sync', 'remove', 'activate', 'failed-activate'])
def test_oversized_publication_keeps_registry_live_config_and_artifacts(store, monkeypatch, operation):
    state = store.load()
    if operation == 'remove':
        # Compact imports can fit although indentation of the surviving node cannot.
        state['nodes']['current']['outbound']['settings']['headers'] = {f'X-{i}': '' for i in range(100)}
        store.state_file.write_text(json.dumps(state, ensure_ascii=False), encoding='utf-8')
        store.outbound_file.write_bytes(encoded({'outbounds': [state['nodes']['current']['outbound']]}))
    candidate = copy.deepcopy(state)
    if operation == 'add':
        candidate['nodes']['extra'] = {'name': 'extra', 'outbound': outbound(), 'created_utc': NOW, 'health': None}
        perform = lambda: store.add('extra', json.dumps(outbound()))
    elif operation == 'update':
        candidate['nodes']['reserve'].update(name='Новое имя', updated_utc=NOW)
        perform = lambda: store.update('reserve', name='Новое имя')
    elif operation == 'check':
        candidate['nodes']['reserve']['health'] = HEALTH
        perform = lambda: store.check('reserve')
    elif operation == 'sync':
        candidate['nodes']['current']['health'] = None
        perform = store.sync_current
    elif operation == 'remove':
        del candidate['nodes']['reserve']
        perform = lambda: store.remove('reserve')
    else:
        monkeypatch.setattr(store, '_xray_pids', lambda: frozenset({'42'}))
        if operation == 'failed-activate':
            health = {'ok': False, 'detail': 'Недоступно'}
            monkeypatch.setattr(store, 'probe', lambda _outbound: health)
            candidate['nodes']['reserve']['health'] = health
        else:
            candidate['active'] = 'reserve'
            candidate['nodes']['reserve']['health'] = HEALTH
        perform = lambda: store.activate('reserve')
    # UTF-8 bytes, indentation and trailing newline all count toward the budget.
    limit = len(encoded(candidate)) - 1
    assert len(store.state_file.read_bytes()) < limit
    monkeypatch.setattr(nodes, 'MAX_STORE_BYTES', limit)
    before = {p.relative_to(store.state_file.parent): p.read_bytes()
              for p in store.state_file.parent.rglob('*') if p.is_file()}
    with mock.patch.object(store, '_test_staged') as staged, mock.patch.object(store, '_restart_xkeen') as restart:
        with pytest.raises(ValueError, match='размер'):
            perform()
    after = {p.relative_to(store.state_file.parent): p.read_bytes()
             for p in store.state_file.parent.rglob('*') if p.is_file()}
    assert before == after
    assert not store.backup_dir.exists()
    assert not (store.state_file.parent / 'vpn-node-versions').exists()
    assert not (store.state_file.parent / 'vpn-node-trash').exists()
    assert store.load() == state
    staged.assert_not_called()
    restart.assert_not_called()


@pytest.mark.parametrize('spare_bytes', [0, 1])
def test_exact_utf8_limit_is_accepted_and_next_byte_is_rejected(store, monkeypatch, spare_bytes):
    candidate = store.load()
    candidate['nodes']['reserve']['health'] = HEALTH
    limit = len(encoded(candidate)) - spare_bytes
    assert len(encoded(candidate).decode('utf-8')) < limit
    monkeypatch.setattr(nodes, 'MAX_STORE_BYTES', limit)
    if spare_bytes:
        before = store.state_file.read_bytes()
        with pytest.raises(ValueError, match='размер'):
            store.check('reserve')
        assert store.state_file.read_bytes() == before
    else:
        assert store.check('reserve')['ok']
        assert store.state_file.read_bytes() == encoded(candidate)
        assert store.state_file.stat().st_size == limit


@pytest.mark.parametrize('operation', ['add', 'update'])
def test_many_valid_flat_outbounds_cannot_publish_unreadable_registry(store, operation):
    large = outbound()
    large['streamSettings'] = {'network': 'ws', 'wsSettings': {
        'path': '/', 'headers': {f'X-{i:04d}': '' for i in range(2000)}}}
    nodes.normalize_outbound(large)  # Each individual outbound is within its own limit.
    state = store.load()
    state['nodes'] = {'current': state['nodes']['current']}
    for index in range(13):
        state['nodes'][f'node_{index}'] = {'name': f'node_{index}', 'outbound': large,
                                          'created_utc': NOW, 'health': HEALTH}
    if operation == 'update':
        state['nodes']['reserve'] = {'name': 'Резерв', 'outbound': outbound(), 'created_utc': NOW, 'health': HEALTH}
    original = encoded(state)
    assert len(original) <= nodes.MAX_STORE_BYTES
    store.state_file.write_bytes(original)
    with pytest.raises(ValueError, match='размер'):
        if operation == 'add':
            store.add('reserve', json.dumps(large))
        else:
            store.update('reserve', source=json.dumps(large))
    assert store.state_file.read_bytes() == original
    assert store.load() == state
    assert not (store.state_file.parent / 'vpn-node-versions').exists()

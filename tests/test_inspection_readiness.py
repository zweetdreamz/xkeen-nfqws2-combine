"""Bounded setup readiness: missing ports may wait, identity/conflicts must not."""
from types import SimpleNamespace
import json

import pytest

from kdn.engine import inspection_setup as setup
from kdn.inspection import context, layout


@pytest.fixture
def ready_case(monkeypatch):
    clock = [0.0]
    expected = {'version': 1, 'pid': 42, 'starttime': '100', 'corpus_digest': 'digest'}
    ctx = SimpleNamespace(paths=SimpleNamespace(xray_config_dir='/synthetic'))
    monkeypatch.setattr(setup.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(setup.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0]+seconds))
    monkeypatch.setattr(setup.receipt, 'value', lambda *_a: dict(expected))
    monkeypatch.setattr(setup.xkeen_service, 'pid', lambda *_a: 42)
    monkeypatch.setattr(setup.apply_files, '_corpus', lambda *_a: [
        (layout.FILE, json.dumps({'api': {'tag': 'api', 'listen': '127.0.0.1:10085',
                                       'services': list(layout.API_SERVICES)}}).encode(), 0o600)])
    monkeypatch.setattr(context, '_listener_present', lambda *_a: False)
    return ctx, clock, expected


def test_pid_before_listener_waits_for_every_owned_port(ready_case, monkeypatch):
    ctx, clock, _ = ready_case
    visited = []
    def owned(pid, port):
        visited.append((pid, port))
        return clock[0] >= .4 if port == layout.API_PORT else True
    monkeypatch.setattr(context, '_listener_owned', owned)
    setup.wait_for_listeners(ctx, 42, 'digest', timeout=1)
    assert .4 <= clock[0] < 1
    assert {p for _, p in visited} == {layout.API_PORT, layout.VPN_PORT, layout.DIRECT_PORT}
    assert {pid for pid, _ in visited} == {42}


def test_absent_listener_has_finite_deadline(ready_case, monkeypatch):
    ctx, clock, _ = ready_case
    monkeypatch.setattr(context, '_listener_owned', lambda *_a: False)
    with pytest.raises(RuntimeError, match='deadline'):
        setup.wait_for_listeners(ctx, 42, 'digest', timeout=.5)
    assert clock[0] == .5


def test_foreign_owner_fails_without_sleep(ready_case, monkeypatch):
    ctx, clock, _ = ready_case
    monkeypatch.setattr(context, '_listener_owned', lambda *_a: False)
    monkeypatch.setattr(context, '_listener_present', lambda *_a: True)
    with pytest.raises(ValueError, match='outside'):
        setup.wait_for_listeners(ctx, 42, 'digest')
    assert clock[0] == 0


def test_port_appearing_between_proc_reads_rechecks_ownership(ready_case, monkeypatch):
    ctx, clock, _ = ready_case
    answers = iter((False, True, True, True))
    monkeypatch.setattr(context, '_listener_owned', lambda *_a: next(answers))
    monkeypatch.setattr(context, '_listener_present', lambda *_a: True)
    setup.wait_for_listeners(ctx, 42, 'digest')
    assert clock[0] == 0


@pytest.mark.parametrize('field', ['pid', 'starttime', 'corpus_digest'])
def test_changed_identity_or_files_abort_wait(ready_case, monkeypatch, field):
    ctx, clock, expected = ready_case
    monkeypatch.setattr(context, '_listener_owned', lambda *_a: False)
    if field == 'pid':
        monkeypatch.setattr(setup.xkeen_service, 'pid', lambda *_a: 99 if clock[0] else 42)
    else:
        monkeypatch.setattr(setup.receipt, 'value', lambda *_a: expected | ({field: 'changed'} if clock[0] else {}))
    with pytest.raises(ValueError, match='changed'):
        setup.wait_for_listeners(ctx, 42, 'digest')
    assert clock[0] == .2


def test_digest_mismatch_is_not_readiness(ready_case):
    ctx, clock, _ = ready_case
    with pytest.raises(ValueError, match='files changed'):
        setup.wait_for_listeners(ctx, 42, 'different')
    assert clock[0] == 0


@pytest.mark.parametrize('table,address', [('tcp','0100007F'),('tcp','00000000'),('tcp6','0'*32)])
def test_presence_detects_loopback_or_wildcard_conflicts(tmp_path, table, address):
    folder=tmp_path/'42'/'net';folder.mkdir(parents=True)
    (folder/'tcp').write_text('header\n')
    (folder/table).write_text('header\n0: '+address+':2765 0:0000 0A 0 0 0 0 0 123\n')
    assert context._listener_present(42, 10085, proc_root=tmp_path)
    assert not context._listener_present(42, 18445, proc_root=tmp_path)


def test_presence_proc_budget_is_fail_closed(tmp_path):
    folder=tmp_path/'42'/'net';folder.mkdir(parents=True)
    (folder/'tcp').write_text('header\n'*8194)
    with pytest.raises(ValueError, match='limit'):
        context._listener_present(42, 10085, proc_root=tmp_path)

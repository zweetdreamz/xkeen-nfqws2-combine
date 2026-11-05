import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from kdn.engine import dns_mode as d, console


def running(profile='DnsVlessMain', extra=''):
    return ('hostname example\nwifi password SECRET\n!\ndns-proxy\n'
            '    intercept enable\n    filter engine public\n'
            '    filter profile DnsProfile0 description secure-doh\n'
            '    filter profile DnsProfile0 https upstream https://one.one.one.one/dns-query\n'
            '    filter profile DnsProfile0 intercept enable\n'
            '    filter profile DnsVlessMain dns53 upstream 192.168.2.1:15355\n'
            '    filter profile DnsVlessMain intercept enable\n'
            '    filter assign interface profile Guest DnsProfile0\n'
            '    filter assign interface profile Home '+profile+'\n'+extra+'!\n')


class Native:
    def __init__(self):
        self.profile='DnsVlessMain';self.calls=[];self.fail_save=False;self.drift=False
    def __call__(self,ctx,command):
        self.calls.append(command)
        if command=='show running-config':
            return running(self.profile, '    filter assign host profile MAC DnsProfile0\n' if self.drift else '')
        if command.startswith('dns-proxy filter assign interface profile Home '):
            self.profile=command.rsplit(' ',1)[1]
        elif command=='system configuration save':
            if self.fail_save:
                self.fail_save=False;raise RuntimeError('save failed')
        else:raise AssertionError('unexpected native command')
        return 'OK'


@pytest.fixture
def case(tmp_path,monkeypatch):
    native=Native();out=io.StringIO();err=io.StringIO()
    ctx=SimpleNamespace(paths=SimpleNamespace(state_root=str(tmp_path/'state'),lock_dir=str(tmp_path/'lock')),
                        environ={},console=console.Console(out,err))
    monkeypatch.setattr(d.transaction,'guard',lambda *_a,**_kw: None)
    monkeypatch.setattr(d.confvalues,'init_value',lambda *_a: 'off')
    monkeypatch.setattr(d,'_native',native)
    return ctx,native,out,err


def test_parse_modes_preserves_guest_and_dns_definitions():
    before=d.parse_dns(running());after=d.parse_dns(running('DnsProfile0'))
    assert before['mode']=='vless' and after['mode']=='doh'
    assert before['fingerprint']==after['fingerprint']
    assert 'SECRET' not in json.dumps(before)


@pytest.mark.parametrize('text',[
    running('Unknown'),running().replace('https upstream','dns53 upstream'),
    running().replace('192.168.2.1:15355','192.168.2.1:15354'),
    running().replace('filter engine public','filter engine unknown'),
    running(extra='    filter assign interface profile Home DnsProfile0\n'),
    'hostname something\n',
])
def test_unsupported_topology_fails_closed(text):
    with pytest.raises(ValueError):d.parse_dns(text)


def test_status_is_read_only_and_does_not_create_record(case):
    ctx,native,_,_=case
    result=d.dns_status(ctx)
    assert result['mode']=='vless' and result['supported'] and not result['pending']
    assert native.calls==['show running-config']
    assert not d._marker(ctx).exists()


def test_switch_uses_only_profile_assignment_and_native_save(case):
    ctx,native,out,_=case
    assert d.switch_dns(ctx,'doh')==0
    assert native.profile=='DnsProfile0'
    assert [s for s in native.calls if s!='show running-config']==[
        'dns-proxy filter assign interface profile Home DnsProfile0','system configuration save']
    assert 'RESULT|ok' in out.getvalue()
    record=json.loads(d._marker(ctx).read_text())
    assert record['phase']=='completed' and record['before']=='DnsVlessMain'
    assert d._marker(ctx).stat().st_mode & 0o777==0o600


def test_same_mode_is_noop(case):
    ctx,native,_,_=case
    assert d.switch_dns(ctx,'vless')==0
    assert native.calls==['show running-config']
    assert not d._marker(ctx).exists()


def test_save_failure_restores_and_persists_previous_assignment(case):
    ctx,native,out,_=case;native.fail_save=True
    assert d.switch_dns(ctx,'doh')==1
    assert native.profile=='DnsVlessMain'
    assert native.calls.count('system configuration save')==2
    assert 'RESULT|rolled-back' in out.getvalue()
    assert json.loads(d._marker(ctx).read_text())['phase']=='rolled-back'


def test_pending_record_requires_explicit_previous_mode_recovery(case):
    ctx,native,_,_=case
    before=d.parse_dns(running())
    record={'version':1,'phase':'pending','before':'DnsVlessMain','after':'DnsProfile0','fingerprint':before['fingerprint']}
    d._store(ctx,record);native.profile='DnsProfile0'
    status=d.dns_status(ctx)
    assert status['pending'] and status['recovery_mode']=='vless'
    assert d.switch_dns(ctx,'doh')==1
    assert native.profile=='DnsProfile0'
    assert d.switch_dns(ctx,'vless')==0
    assert native.profile=='DnsVlessMain'
    assert json.loads(d._marker(ctx).read_text())['phase']=='rolled-back'


def test_pending_drift_and_corrupt_record_cannot_be_overwritten(case):
    ctx,native,_,_=case
    d._store(ctx,{'version':1,'phase':'pending','before':'DnsVlessMain','after':'DnsProfile0','fingerprint':'wrong'})
    assert d.switch_dns(ctx,'vless')==1
    assert native.calls==['show running-config']
    d._marker(ctx).write_text('{broken')
    assert not d.dns_status(ctx)['supported']


def test_no_mutation_without_guard_or_with_proxy_router_enabled(case,monkeypatch):
    ctx,native,_,_=case
    with mock.patch.object(d.transaction,'guard',side_effect=ValueError('confirmation')):
        assert d.switch_dns(ctx,'doh')==1
    assert native.calls==[]
    monkeypatch.setattr(d.confvalues,'init_value',lambda *_a: 'on')
    assert d.switch_dns(ctx,'doh')==1
    assert native.calls==[]


def test_invalid_mode_is_never_a_command(case):
    ctx,native,_,_=case
    with pytest.raises(ValueError):d.switch_dns(ctx,'doh; reboot')
    assert native.calls==[]


def test_recovery_symlink_refused(case,tmp_path):
    ctx,native,_,_=case
    Path(ctx.paths.state_root).mkdir()
    external=tmp_path/'external';external.write_text('{}')
    d._marker(ctx).symlink_to(external)
    assert d.switch_dns(ctx,'doh')==1
    assert external.read_text()=='{}'
    assert native.profile=='DnsVlessMain'

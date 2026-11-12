"""Three proven outages can request DoH, never stale/partial diagnostics."""
import time
from unittest import mock

import pytest
import panel_harness
from kdn.inspection import policy
from kdn.web.domain import notifications


@pytest.fixture
def fallback(tmp_path,monkeypatch):
    panel=panel_harness.load_panel()
    monitor=panel.module('domain.vpn_monitor')
    infra=panel.module('infra.inspection')
    cfg=panel.module('infra.config')
    monkeypatch.setattr(cfg,'VPN_MONITOR_CONFIG',tmp_path/'config.json')
    monkeypatch.setattr(cfg,'VPN_MONITOR_STATE',tmp_path/'state.json')
    identity={'node_id':'current','source_digest':'a'*64}
    monkeypatch.setattr(monitor.vpn,'active_identity',lambda:dict(identity))
    monkeypatch.setattr(monitor.receipt,'observation_current',lambda *_args:True)
    settings=policy.defaults()
    settings.update(enabled=True,families=['ipv4'],dns_fallback_enabled=True)
    settings['nodes']['current']={'source_digest':identity['source_digest'],'expected':{'ipv4':['1.1.1.1']}}
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG,settings)

    def sample(number,**changes):
        result={'ok':True,'kind':'vpn','status':'completed',**identity,'checked_at':int(time.time())-4+number,
                'observation_id':str(number),'families':['ipv4'],'runtime_identity':{'pid':123},
                'observed':{'ipv4':None},'connectivity':'unconfirmed',**changes}
        state=policy.record_observation(monitor.monitor_state(),result,policy.verdict(settings,identity,result))
        infra.write_inspection_state(cfg.VPN_MONITOR_STATE,state)
        return state
    return monitor,infra,cfg,identity,sample,panel.module('domain.operations')


def test_exactly_three_failures_enqueue_once_and_worker_only_changes_dns(fallback):
    monitor,_infra,_cfg,_identity,sample,ops=fallback
    with mock.patch.object(ops,'start_dns_fallback_job',return_value={'job_id':'a'*16}) as start:
        sample(1);sample(2)
        assert not monitor.maybe_start_dns_fallback()
        sample(3)
        assert monitor.maybe_start_dns_fallback()
        assert not monitor.maybe_start_dns_fallback()
        start.assert_called_once()
    with mock.patch.object(monitor.engine,'read_dns_mode',side_effect=[{'supported':True,'mode':'vless','pending':False},{'supported':True,'mode':'doh','pending':False}]), \
            mock.patch.object(monitor.engine,'set_dns_mode',return_value={'ok':True,'code':0,'output':'done'}) as switch:
        assert monitor.run_dns_fallback_job()['ok']
        switch.assert_called_once_with('doh')
    assert monitor.monitor_state()['dns_fallback']['status']=='completed'


def test_already_doh_never_switches_or_restarts(fallback):
    monitor,infra,cfg,_identity,sample,_ops=fallback
    for number in (1,2,3): saved=sample(number)
    saved['dns_fallback']={'incident':saved['failure_incident'],'status':'queued','at':int(time.time())}
    infra.write_inspection_state(cfg.VPN_MONITOR_STATE,saved)
    with mock.patch.object(monitor.engine,'read_dns_mode',return_value={'supported':True,'mode':'doh'}), \
            mock.patch.object(monitor.engine,'set_dns_mode') as switch:
        assert monitor.run_dns_fallback_job()['ok']
        switch.assert_not_called()
    assert monitor.monitor_state()['dns_fallback']['status']=='already-doh'


def test_worker_finishing_during_launch_is_not_overwritten(fallback):
    monitor,_infra,_cfg,_identity,sample,ops=fallback
    for number in (1,2,3): sample(number)
    def finish_early():
        monitor.run_dns_fallback_job()
        return {'job_id':'a'*16}
    with mock.patch.object(monitor.engine,'read_dns_mode',return_value={'supported':True,'mode':'doh'}), \
            mock.patch.object(ops,'start_dns_fallback_job',side_effect=finish_early):
        assert monitor.maybe_start_dns_fallback()
    assert monitor.monitor_state()['dns_fallback']['status']=='already-doh'


def test_dns_fallback_is_opt_in(fallback):
    monitor,infra,cfg,_identity,sample,ops=fallback
    for number in (1,2,3): sample(number)
    settings=monitor.monitor_config();settings['dns_fallback_enabled']=False
    infra.write_inspection_state(cfg.VPN_MONITOR_CONFIG,settings)
    with mock.patch.object(ops,'start_dns_fallback_job') as start:
        assert not monitor.maybe_start_dns_fallback()
        start.assert_not_called()


@pytest.mark.parametrize('changes',[{'status':'unavailable'},{'status':'skipped'},
    {'observed':{'ipv4':'1.1.1.1'}},{'connectivity':'reachable'},
    {'observed':{'ipv6':None},'families':['ipv6']}])
def test_non_outages_do_not_count_or_switch(fallback,changes):
    monitor,_infra,_cfg,_identity,sample,ops=fallback
    for number in (1,2,3): sample(number,**changes)
    with mock.patch.object(ops,'start_dns_fallback_job') as start:
        assert monitor.monitor_state()['failure_streak']==0
        assert not monitor.maybe_start_dns_fallback()
        start.assert_not_called()


def test_duplicate_observation_and_node_change_reset_threshold(fallback):
    monitor,_infra,_cfg,identity,sample,_ops=fallback
    sample(1);sample(1)
    assert monitor.monitor_state()['failure_streak']==1
    sample(2)
    identity['source_digest']='b'*64
    assert sample(3)['failure_streak']==0  # approval is bound to the old source


@pytest.mark.parametrize('failure',['identity','pending','command'])
def test_worker_revalidates_and_does_not_claim_success_on_failure(fallback,failure):
    monitor,infra,cfg,identity,sample,_ops=fallback
    for number in (1,2,3): saved=sample(number)
    saved['dns_fallback']={'incident':saved['failure_incident'],'status':'queued','at':int(time.time())}
    infra.write_inspection_state(cfg.VPN_MONITOR_STATE,saved)
    if failure=='identity': identity['source_digest']='c'*64
    with mock.patch.object(monitor.engine,'read_dns_mode',return_value={'supported':True,'mode':'vless','pending':failure=='pending'}), \
            mock.patch.object(monitor.engine,'set_dns_mode',return_value={'ok':False}) as switch:
        result=monitor.run_dns_fallback_job()
        if failure in ('identity','pending'): switch.assert_not_called()
        else: assert not result['ok']
    assert monitor.monitor_state()['dns_fallback']['status'] in ('skipped','error')


def test_dns_notification_only_after_completion_and_no_duplicates():
    state={'queue':[],'seen':[],'dropped':0}
    notifications.derive(state,{}, {},100);state['queue']=[]
    monitor={'dns_fallback':{'incident':'a'*32,'status':'queued','at':101}}
    notifications.derive(state,{},monitor,101)
    assert not state['queue']
    monitor['dns_fallback'].update(status='completed',at=102)
    notifications.derive(state,{},monitor,102)
    notifications.derive(state,{},monitor,103)
    assert [row['kind'] for row in state['queue']]==['dns-fallback']

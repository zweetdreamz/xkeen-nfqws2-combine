import json
from unittest import mock

import pytest

from kdn.web.domain import notifications as n


def state():
    return {'queue': [], 'seen': [], 'dropped': 0}


def seed():
    s=state();n.derive(s, {}, {}, 100);s['queue']=[]
    return s


def test_first_start_does_not_replay_old_events():
    s=state()
    n.derive(s, {'status':'completed','finished_utc':'old','results':{'youtube':'applied'}},
             {'last_attempt':90,'verdict':'ip-mismatch'},100)
    assert [r['kind'] for r in s['queue']]==['test']


def test_night_success_error_and_rollback_are_deduplicated_and_private():
    s=seed()
    auto={'status':'error','finished_utc':'new','last_slot':'slot',
          'results':{'youtube':'applied-quic-unverified','discord-tcp':'not-found'},'error':'SECRET 1.2.3.4',
          'last_rollback_utc':'confirmed','events':[{'message':'SECRET text is not parsed'}]}
    n.derive(s,auto,{},101);before=json.dumps(s)
    n.derive(s,auto,{},102)
    assert json.dumps(s)==before
    assert {r['kind'] for r in s['queue']}=={'youtube-applied','night-failed','night-not-found','rolled-back'}
    assert 'SECRET' not in before and '1.2.3.4' not in before


def test_three_actual_failures_not_three_polls_and_recovery_once():
    s=seed()
    for at in (101,102):
        n.derive(s,{}, {'last_attempt':at,'verdict':'unreachable'},at)
        n.derive(s,{}, {'last_attempt':at,'verdict':'unreachable'},at)
    assert not s['queue']
    n.derive(s,{}, {'last_attempt':103,'verdict':'unreachable'},103)
    assert [r['kind'] for r in s['queue']]==['vpn-check-failed']
    n.derive(s,{}, {'last_attempt':104,'verdict':'unreachable'},104)
    assert len(s['queue'])==1
    n.derive(s,{}, {'last_attempt':105,'verdict':'healthy'},105)
    n.derive(s,{}, {'last_attempt':106,'verdict':'healthy'},106)
    assert [r['kind'] for r in s['queue']]==['vpn-check-failed','vpn-recovered']


def test_changed_ip_is_immediate_and_unavailable_is_not_claimed_as_dead_vpn():
    s=seed();n.derive(s,{}, {'last_attempt':101,'verdict':'ip-mismatch'},101)
    assert s['queue'][0]['kind']=='vpn-ip-changed'
    for at in (102,103,104):n.derive(s,{}, {'last_attempt':at,'verdict':'unavailable'},at)
    assert s['queue'][-1]['kind']=='inspection-unavailable'


def test_queue_and_seen_are_bounded():
    s=seed()
    for i in range(200):n._event(s,str(i),'night-failed',i)
    assert len(s['queue'])==32 and len(s['seen'])==128 and s['dropped']==168


@pytest.fixture
def files(tmp_path,monkeypatch):
    for key in ('NOTIFICATION_CONFIG','NOTIFICATION_STATE','AUTOMATION_STATE','VPN_MONITOR_STATE'):
        monkeypatch.setattr(n.cfg,key,tmp_path/key)
    n.cfg.NOTIFICATION_CONFIG.write_text(json.dumps({'enabled':True,'topic':'kdn-'+48*'a'}))
    return tmp_path


def test_tick_retries_persistent_queue_and_does_not_resend_after_restart(files):
    with mock.patch.object(n,'_publish',side_effect=OSError('private error')) as publish:
        n.notification_tick(now=1000)
        assert publish.call_count==1
        s=json.loads(n.cfg.NOTIFICATION_STATE.read_text())
        assert s['queue'][0]['tries']==1 and s['queue'][0]['next']>1000
        assert 'private error' not in json.dumps(s)
        n.notification_tick(now=1001);assert publish.call_count==1
    with mock.patch.object(n,'_publish') as publish:
        n.notification_tick(now=2000);assert publish.call_count==1
        n.notification_tick(now=2001);assert publish.call_count==1
    assert json.loads(n.cfg.NOTIFICATION_STATE.read_text())['queue']==[]


def test_disabled_corrupt_and_channel_change_cannot_send(files):
    with mock.patch.object(n,'_publish') as publish:
        n.cfg.NOTIFICATION_CONFIG.write_text('{"enabled":false}')
        n.notification_tick(now=1000);publish.assert_not_called()
        n.cfg.NOTIFICATION_CONFIG.write_text(json.dumps({'enabled':True,'topic':'kdn-'+48*'a'}))
        n.cfg.NOTIFICATION_STATE.write_text('{"queue": "bad"}')
        with pytest.raises(ValueError):n.notification_tick(now=1000)
        s=state()|{'channel':'wrong'}
        n.cfg.NOTIFICATION_STATE.write_text(json.dumps(s))
        with pytest.raises(ValueError):n.notification_tick(now=1000)
        publish.assert_not_called()


def test_expired_events_not_delivered(files):
    s=state()|{'channel':n.hashlib.sha256(('kdn-'+48*'a').encode()).hexdigest(),'seeded':True}
    n._event(s,'old','night-failed',1)
    n.cfg.NOTIFICATION_STATE.write_text(json.dumps(s))
    with mock.patch.object(n,'_publish') as publish:
        n.notification_tick(now=90000);publish.assert_not_called()
    assert json.loads(n.cfg.NOTIFICATION_STATE.read_text())['dropped']==1


def test_transport_has_wall_output_tls_limits_and_no_topic_in_argv():
    topic='kdn-'+48*'b'
    with mock.patch.object(n.transport,'run',return_value=json.dumps({'event':'message','topic':topic}).encode()) as run:
        n._publish(topic,{'kind':'vpn-ip-changed','id':'a'*32})
        args,kwargs=run.call_args
        assert args[0][-1]=='https://ntfy.sh/' and '-q' in args[0]
        assert topic not in ' '.join(args[0])
        assert '-k' not in args[0] and '--location' not in args[0]
        assert kwargs['timeout']==10 and kwargs['limit']==4096
        config=kwargs['data'].decode().splitlines()[0].removeprefix('data = ')
        body=json.loads(json.loads(config));assert body['topic']==topic
        assert set(body)=={'topic','title','message','priority','sequence_id'}
    with mock.patch.object(n.transport,'run',return_value=b'{}'),pytest.raises(ValueError):
        n._publish(topic,{'kind':'test','id':'a'*32})


def test_settings_write_only_token_preserve_clear_and_topic_confirmation(files):
    topic='kdn-'+48*'a'
    public=n.save_notifications({'enabled':True,'topic':topic,'token':'PRIVATE-KEY'})
    assert public['token_set'] and 'PRIVATE-KEY' not in json.dumps(public) and 'token' not in public
    n.save_notifications({'enabled':False,'topic':topic,'token':''})
    assert n._settings()['token']=='PRIVATE-KEY'
    n.save_notifications({'enabled':False,'topic':topic,'clear_token':True})
    assert not n.notification_status()['token_set']
    with pytest.raises(ValueError):n.save_notifications({'enabled':True,'topic':'different'})
    n.save_notifications({'enabled':True,'topic':'different','confirm_topic_change':True})
    assert json.loads(n.cfg.NOTIFICATION_STATE.read_text())=={}


def test_invalid_settings_dont_replace_valid_config(files):
    before=n.cfg.NOTIFICATION_CONFIG.read_bytes()
    for patch in ({'topic':'bad/../topic'},{'token':'injected\nHeader: value'},{'events':['unknown']}):
        with pytest.raises(ValueError):n.save_notifications({'enabled':True,'topic':'valid-topic'}|patch)
        assert n.cfg.NOTIFICATION_CONFIG.read_bytes()==before


def test_test_queue_and_event_filter(files):
    n.save_notifications({'enabled':True,'topic':'kdn-'+48*'a','events':[]})
    assert n.notification_test()['queued']
    with mock.patch.object(n,'_publish') as publish:
        n.notification_tick(now=2000000000)
        # Old synthetic test may expire; enqueue current test for actual send.
        n.notification_test();n.notification_tick()
        assert publish.called
    n.save_notifications({'enabled':False,'topic':'kdn-'+48*'a'})
    with pytest.raises(ValueError):n.notification_test()

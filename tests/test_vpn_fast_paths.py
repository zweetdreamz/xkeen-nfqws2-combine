"""Bounded offline acceptance of fast pings and cheap registry operations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from kdn import vpn_ping
from kdn.web.infra import vpn_compatibility
import test_vpn_node_edit as fixtures
from test_vpn_node_manager import outbound


class RegistryTests(unittest.TestCase):
    setUp = fixtures.VpnNodeEditTests.setUp

    def test_auto_name_duplicates_and_no_probe(self):
        with mock.patch.object(self.manager,'probe',side_effect=AssertionError('no probe')):
            one=self.manager.add('🇩🇪 Berlin | reserve',json.dumps(outbound()),auto_name=True)
            two=self.manager.add('🇩🇪 Berlin | reserve',json.dumps(outbound()),auto_name=True)
        self.assertEqual(one['node']['name'],'🇩🇪 Berlin reserve')
        self.assertEqual(two['node']['name'],'🇩🇪 Berlin reserve 2')
        self.assertEqual(self.live.read_bytes(),self.before)

    def test_auto_name_from_fragment_json_and_address(self):
        uri='vless://6f1c7e0a-6b1a-4c35-9a52-7a3f2b8e9c10@vpn.example:443?security=tls#Link%20name'
        one=self.manager.add('',uri,auto_name=True)
        self.assertEqual(one['node']['name'],'Link name')
        data=outbound();data['tag']='JSON name'
        two=self.manager.add('',json.dumps(data),auto_name=True)
        self.assertEqual(two['node']['name'],'JSON name')
        data.pop('tag')
        three=self.manager.add('',json.dumps(data),auto_name=True)
        self.assertEqual(three['node']['name'],'vpn.example')

    def test_ping_batch_is_one_run_and_does_not_erase_diagnostics(self):
        state=self.manager.load()
        state['nodes']['reserve']['health']={'ok':False,'detail':'old diagnostic'}
        self.manager._save_state(state)
        with mock.patch.object(vpn_ping,'run',return_value={key:{'ok':True,'latency_ms':20} for key in state['nodes']}) as run:
            result=self.manager.ping_nodes()
        run.assert_called_once()
        self.assertEqual(len(result['results']),2)
        self.assertEqual(self.manager.load()['nodes']['reserve']['health']['detail'],'old diagnostic')
        self.assertEqual(self.manager.load()['nodes']['reserve']['ping']['latency_ms'],20)
        self.assertEqual(self.live.read_bytes(),self.before)

    def test_external_edit_during_ping_is_not_overwritten(self):
        def measure(_nodes,_binary):
            state=self.manager.load()
            state['nodes']['reserve']['outbound']['settings']['port']=9443
            self.manager._save_state(state)
            return {'reserve':{'ok':True,'latency_ms':20}}
        with mock.patch.object(vpn_ping,'run',side_effect=measure):
            result=self.manager.ping_nodes(['reserve'])
        self.assertFalse(result['ping']['ok'])
        self.assertEqual(self.manager.load()['nodes']['reserve']['outbound']['settings']['port'],9443)
        self.assertIsNone(self.manager.load()['nodes']['reserve'].get('ping'))


class CompatibilityTests(unittest.TestCase):
    def test_positive_cache_binary_replacement_and_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            command=Path(tmp)/'command'
            command.write_text('version one')
            manager=SimpleNamespace(xkeen=str(command),xray=str(command),_require_supported_xray=mock.Mock())
            with mock.patch.object(vpn_compatibility.xkeen,'require') as require, mock.patch.object(vpn_compatibility.time,'monotonic',return_value=100):
                vpn_compatibility.require_registry_versions(manager)
                vpn_compatibility.require_registry_versions(manager)
                self.assertEqual(require.call_count,1)
                command.write_text('version two changed')
                vpn_compatibility.require_registry_versions(manager)
                self.assertEqual(require.call_count,2)
            with mock.patch.object(vpn_compatibility.xkeen,'require') as require, mock.patch.object(vpn_compatibility.time,'monotonic',return_value=200):
                vpn_compatibility.require_registry_versions(manager)
                require.assert_called_once()


@unittest.skipUnless(sys.platform=='linux','Linux abstract sockets and parent-death helper')
class PingTests(unittest.TestCase):
    def test_one_process_two_routed_nodes_and_warm_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'launches'
            executable=Path(tmp)/'xray'
            executable.write_text('#!'+sys.executable+'\n'+'''
import json, socket, sys, threading, time
from pathlib import Path
config=json.loads(Path(sys.argv[-1]).read_text())
with open(MARKER,'a') as marker: marker.write('launch\\n')
assert config['outbounds'][0]['protocol']=='blackhole'
rules={row['inboundTag'][0]:row['outboundTag'] for row in config['routing']['rules']}
outs={row['tag']:row for row in config['outbounds']}
listeners=[]
def serve(sock,status):
    connection,_=sock.accept()
    with connection:
        for number in range(2):
            data=b''
            while b'\\r\\n\\r\\n' not in data: data+=connection.recv(2048)
            assert data.startswith(b'HEAD /generate_204 HTTP/1.1')
            time.sleep(0.08 if number==0 else 0.02)
            connection.sendall(('HTTP/1.1 '+str(status)+' OK\\r\\nContent-Length: 0\\r\\nConnection: keep-alive\\r\\n\\r\\n').encode())
    sock.close()
for row in config['inbounds']:
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    sock.bind('\\0'+row['listen'][1:]);sock.listen()
    address=outs[rules[row['tag']]]['settings']['address']
    threading.Thread(target=serve,args=(sock,201 if address=='one.invalid' else 202),daemon=True).start()
print('core: Xray fixture started',flush=True)
time.sleep(30)
'''.replace('MARKER',repr(str(marker))))
            executable.chmod(0o700)
            original={'one':outbound('one.invalid'),'two':outbound('two.invalid')}
            before=copy.deepcopy(original)
            result=vpn_ping.run(original,str(executable),timeout=1)
            self.assertEqual(marker.read_text().splitlines(),['launch'])
            self.assertEqual([result[key]['http_code'] for key in ('one','two')],[201,202])
            for value in result.values():
                self.assertTrue(value['ok'])
                self.assertLess(value['latency_ms'],value['total_ms']-40)
                self.assertEqual(value['latency_kind'],'http_keepalive')
            self.assertEqual(original,before)
            # Kernel removes the abstract sockets when the owned child exits.
            self.assertFalse(any(b'kdn-ping-' in line for line in Path('/proc/net/unix').read_bytes().splitlines()))

    def test_invalid_batch_and_blackhole_default(self):
        with self.assertRaises(ValueError):
            vpn_ping.run({},'/not-executed')
        config,sockets=vpn_ping.configuration({'one':outbound()},'test')
        self.assertEqual(config['outbounds'][0]['protocol'],'blackhole')
        self.assertEqual(config['routing']['rules'][0]['outboundTag'],config['outbounds'][1]['tag'])
        self.assertEqual(len(sockets),1)

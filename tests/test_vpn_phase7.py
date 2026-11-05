"""P7.3-6: loss-aware links, isolated checks, recovery and bounded history."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import urlencode

from kdn.engine.nfqws_process import ProcessResult
from tools.router import vpn_node_manager as nodes
import test_vpn_node_manager as fixtures

UUID = fixtures.UUID
outbound = fixtures.outbound


class VpnLinks26Tests(unittest.TestCase):
    def link(self, **query):
        return f'vless://{UUID}@vpn.example:443?' + urlencode(query)

    def test_transport_and_security_matrix_preserves_fields(self):
        for network in ('tcp', 'raw', 'ws', 'grpc', 'xhttp', 'splithttp'):
            for security in ('none', 'tls', 'reality'):
                if network == 'ws' and security == 'reality':
                    continue
                query = dict(type=network, security=security)
                if security == 'tls':
                    query.update(sni='front.example', pcs='ab' * 32, vcn='front.example', ech='test-ech')
                elif security == 'reality':
                    query.update(sni='front.example', password='A' * 43, pqv='verify', spx='%2Fonce')
                if network == 'ws':
                    query.update(host='ws.example', path='/%2Fonce')
                elif network == 'grpc':
                    query.update(serviceName='service%2Fonce', authority='grpc.example', mode='multi')
                elif network in {'xhttp', 'splithttp'}:
                    query.update(host='xhttp.example', path='/path%2Fonce', mode='packet-up',
                                 extra=json.dumps({'noSSEHeader': True}))
                with self.subTest(network=network, security=security):
                    parsed = nodes.normalize_outbound(self.link(**query))
                    stream = parsed['streamSettings']
                    self.assertEqual((stream['network'], stream['security']), (network, security))
                    if security == 'tls':
                        self.assertEqual(stream['tlsSettings']['pinnedPeerCertSha256'], 'ab' * 32)
                        self.assertEqual(stream['tlsSettings']['echConfigList'], 'test-ech')
                    elif security == 'reality':
                        self.assertEqual(stream['realitySettings']['password'], 'A' * 43)
                        self.assertEqual(stream['realitySettings']['spiderX'], '%2Fonce')
                        self.assertEqual(stream['realitySettings']['mldsa65Verify'], 'verify')
                    if network == 'ws':
                        self.assertEqual(stream['wsSettings'], {'host': 'ws.example', 'path': '/%2Fonce'})
                    elif network == 'grpc':
                        self.assertTrue(stream['grpcSettings']['multiMode'])
                        self.assertEqual(stream['grpcSettings']['serviceName'], 'service%2Fonce')
                    elif network in {'xhttp', 'splithttp'}:
                        self.assertTrue(stream[network + 'Settings']['extra']['noSSEHeader'])

    def test_no_silent_loss_or_ambiguous_queries(self):
        for source in (
            self.link(type='tcp', host='unused.example'), self.link(type='ws', mode='multi'),
            self.link(type='grpc', mode='unknown'), self.link(type='xhttp', mode='unknown'),
            self.link(type='tcp', security='none', sni='unused.example'),
            self.link(type='tcp') + '&type=ws', self.link(type='xhttp', extra='[]'),
            self.link(type='xhttp', extra='{"x":1,"x":2}'), self.link(type='ws', path='ok') + '&fp=%FF',
            'hy2://secret@hy.example?obfs=salamander&obfs-password=secret',
            'hy2://secret@hy.example?mport=10000-20000', self.link(pbk='key', password='different', security='reality', sni='x'),
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                nodes.safe_normalize_outbound(source)

    def test_hysteria_finalmask_json_and_pinning_preserved(self):
        mask = {'udp': [{'type': 'udphop', 'settings': {'mode': 'intervalremote',
                 'remotePorts': '10000-20000', 'interval': '30'}}], 'quicParams': {'congestion': 'bbr'}}
        uri = 'hy2://secret@hy.example?' + urlencode({'finalmask': json.dumps(mask), 'pinSHA256': 'ab' * 32})
        parsed = nodes.normalize_outbound(uri)
        self.assertEqual(parsed['streamSettings']['finalmask'], mask)
        self.assertEqual(parsed['streamSettings']['tlsSettings']['pinnedPeerCertSha256'], 'ab' * 32)
        self.assertEqual(nodes.normalize_outbound(json.dumps(parsed)), parsed)
        parsed['streamSettings']['xhttpSettings'] = {'extra': {'downloadSettings': {'sockopt': {'dialerProxy': 'other'}}}}
        with self.assertRaises(ValueError):
            nodes.normalize_outbound(parsed)


class VpnStorePhase7Tests(unittest.TestCase):
    setUp = fixtures.VpnNodeTests.setUp
    pending_transaction = fixtures.VpnNodeTests.pending_transaction

    def reserve(self):
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True}):
            self.manager.add('reserve', json.dumps(outbound('reserve.example')))

    def test_recovery_blocks_every_mutator_without_probes_or_writes(self):
        self.reserve()
        self.pending_transaction()
        before = self.manager.state_file.read_bytes()
        for action in (lambda: self.manager.add('third', '{}'), lambda: self.manager.check('reserve'),
                       lambda: self.manager.remove('reserve'), self.manager.sync_current,
                       lambda: self.manager.rename('reserve', 'New name'),
                       lambda: self.manager.activate('reserve')):
            with self.subTest(action=action), mock.patch.object(self.manager, 'probe') as probe:
                with self.assertRaises((RuntimeError, ValueError)):
                    action()
                probe.assert_not_called()
                self.assertEqual(self.manager.state_file.read_bytes(), before)

    def test_late_registry_failure_restores_both_files_and_mode(self):
        self.reserve()
        before = self.outbounds.read_bytes(), self.manager.state_file.read_bytes()
        self.outbounds.chmod(0o640)
        original = nodes.atomic_json
        def fail_registry(path, value, *args, **kwargs):
            if path == self.manager.state_file and value.get('active') == 'reserve':
                raise OSError('simulated registry publication failure')
            return original(path, value, *args, **kwargs)
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True}), \
                mock.patch.object(self.manager, '_test_staged'), \
                mock.patch.object(self.manager, '_xray_pids', return_value=frozenset({'100'})), \
                mock.patch.object(self.manager, '_restart_xkeen') as restart, \
                mock.patch.object(nodes, 'atomic_json', side_effect=fail_registry):
            with self.assertRaises(OSError):
                self.manager.activate('reserve')
        self.assertEqual((self.outbounds.read_bytes(), self.manager.state_file.read_bytes()), before)
        self.assertEqual(self.outbounds.stat().st_mode & 0o777, 0o640)
        self.assertEqual(restart.call_count, 2)
        self.assertFalse(self.manager.transaction_file.exists())

    def test_recovery_equal_bytes_stopped_runtime_and_absent_registry(self):
        snapshot = self.pending_transaction()
        self.outbounds.write_bytes((snapshot / '04_outbounds.json').read_bytes())
        nodes.atomic_json(self.manager.state_file, {'new': 'partial registry'})
        with mock.patch.object(self.manager, '_test_staged'), \
                mock.patch.object(self.manager, '_xray_pids', return_value=frozenset()), \
                mock.patch.object(self.manager, '_restart_xkeen') as restart:
            result = self.manager.recover_pending()
        self.assertTrue(result['restarted'])
        restart.assert_called_once_with(frozenset())
        self.assertFalse(self.manager.state_file.exists())
        self.assertFalse(self.manager.transaction_file.exists())

    def test_marker_unlink_failure_restores_already_committed_registry(self):
        self.reserve()
        before = self.outbounds.read_bytes(), self.manager.state_file.read_bytes()
        original = Path.unlink
        attempts = []
        def unlink(path, *args, **kwargs):
            if path == self.manager.transaction_file:
                attempts.append(path)
                if len(attempts) == 1:
                    raise OSError('simulated marker unlink failure')
            return original(path, *args, **kwargs)
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True}), \
                mock.patch.object(self.manager, '_test_staged'), \
                mock.patch.object(self.manager, '_xray_pids', return_value=frozenset({'100'})), \
                mock.patch.object(self.manager, '_restart_xkeen') as restart, \
                mock.patch.object(Path, 'unlink', new=unlink):
            with self.assertRaisesRegex(OSError, 'marker unlink'):
                self.manager.activate('reserve')
        self.assertEqual((self.outbounds.read_bytes(), self.manager.state_file.read_bytes()), before)
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(len(attempts), 2)
        self.assertFalse(self.manager.transaction_file.exists())

    def test_checksum_mismatch_stops_recovery_before_writes(self):
        snapshot = self.pending_transaction()
        tx = json.loads(self.manager.transaction_file.read_text())
        tx['checksums'] = {'04_outbounds.json': '0' * 64}
        self.manager.transaction_file.write_text(json.dumps(tx))
        before = self.outbounds.read_bytes()
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.manager.recover_pending()
        self.assertEqual(self.outbounds.read_bytes(), before)
        self.assertTrue(snapshot.is_dir())

    def test_recovery_status_survives_corrupt_registry_without_repair(self):
        self.pending_transaction()
        self.manager.state_file.write_text('{broken')
        before = self.manager.state_file.read_bytes()
        status = self.manager.status()
        self.assertTrue(status['recovery_needed'])
        self.assertEqual(status['nodes'], [])
        self.assertEqual(self.manager.state_file.read_bytes(), before)

    def test_post_commit_cleanup_failure_is_a_warning_not_false_failure(self):
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True}), \
                mock.patch.object(self.manager, '_prune_private_history', side_effect=OSError('permissions')):
            result = self.manager.add('reserve', json.dumps(outbound()))
        self.assertTrue(result['ok'])
        self.assertIn('очистка', result['warning'])
        self.assertIn('reserve', self.manager.load()['nodes'])

    def test_external_edit_during_probe_is_preserved(self):
        self.reserve()
        external = json.dumps({'outbounds': [outbound('external.example')]})
        def edit(_node):
            self.outbounds.write_text(external)
            return {'ok': True}
        with mock.patch.object(self.manager, 'probe', side_effect=edit), \
                mock.patch.object(self.manager, '_test_staged'), \
                mock.patch.object(self.manager, '_xray_pids', return_value=frozenset({'100'})), \
                mock.patch.object(self.manager, '_restart_xkeen') as restart:
            with self.assertRaisesRegex(ValueError, 'changed during preflight'):
                self.manager.activate('reserve')
        self.assertEqual(self.outbounds.read_text(), external)
        restart.assert_not_called()

    def test_cancel_rolls_back_and_keeps_original_system_exit(self):
        self.reserve()
        before = self.outbounds.read_bytes(), self.manager.state_file.read_bytes()
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True}), \
                mock.patch.object(self.manager, '_test_staged'), \
                mock.patch.object(self.manager, '_xray_pids', return_value=frozenset({'100'})), \
                mock.patch.object(self.manager, '_restart_xkeen', side_effect=[SystemExit(130), None]):
            with self.assertRaises(SystemExit) as caught:
                self.manager.activate('reserve')
        self.assertEqual(caught.exception.code, 130)
        self.assertEqual((self.outbounds.read_bytes(), self.manager.state_file.read_bytes()), before)

    def test_retention_preserves_unknown_and_pending_sources(self):
        trash = self.root / 'vpn-node-trash'
        trash.mkdir()
        for i in range(40):
            (trash / f'{1000000000 + i}-reserve-12345678.json').write_text('{}')
        (trash / 'unrelated.json').write_text('keep')
        self.manager._prune_private_history()
        self.assertEqual(len(list(trash.glob('*reserve*'))), 32)
        self.assertTrue((trash / 'unrelated.json').exists())
        self.pending_transaction()
        (trash / '9999999999-reserve-12345678.json').write_text('{}')
        self.manager._prune_private_history()
        self.assertEqual(len(list(trash.glob('*reserve*'))), 33)

    def test_header_mismatch_and_external_edit_refuse_activation(self):
        self.manager.nfqws_conf = self.root / 'nfqws2.conf'
        self.manager.nfqws_conf.write_text('# Proxy outbound: other.\n')
        self.assertIn('Proxy outbound', self.manager.status()['warning'])
        self.reserve()
        with mock.patch.object(self.manager, 'probe') as probe, self.assertRaises(ValueError):
            self.manager.activate('reserve')
        probe.assert_not_called()


class VpnIdentityTests(unittest.TestCase):
    def test_only_daemon_with_own_confdir_counts_not_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manager = nodes.VpnNodeManager(proc_root=root, xray_dir=Path('/own/config'))
            for pid, args in {'1': ['/opt/sbin/xray', 'run', '-c', '/probe.json'],
                              '2': ['/opt/sbin/xray', 'run', '-confdir', '/other'],
                              '3': ['/opt/sbin/xray', 'run', '-confdir', '/own/config'],
                              '4': ['/opt/sbin/xray', 'run', '-test', '-confdir', '/own/config']}.items():
                (root / pid).mkdir()
                (root / pid / 'cmdline').write_bytes('\0'.join(args).encode() + b'\0')
            with mock.patch.object(nodes.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='1 2 3 4')):
                self.assertEqual(manager._xray_pids(), frozenset({'3'}))

    def test_version_guard_uses_actual_supported_version(self):
        manager = nodes.VpnNodeManager()
        for version, accepted in [('XKeen 2.1.0', True), ('XKeen 2.0', False), ('unknown', False)]:
            with self.subTest(version=version), mock.patch.object(nodes.xkeen, 'probe',
                    return_value=nodes.xkeen.parse_version(version)), mock.patch.object(manager, '_require_supported_xray'):
                if accepted:
                    manager._require_supported_xkeen()
                else:
                    with self.assertRaises(ValueError):
                        manager._require_supported_xkeen()

    def test_core_version_guard_refuses_silently_ignored_new_fields(self):
        manager = nodes.VpnNodeManager()
        for version, accepted in [('Xray 26.10.31 (test)', True), ('Xray 26.11.1 (test)', True),
                                  ('Xray 25.12.1', False), ('Xray 26.3.27', False), ('Xray 27.1.1', False)]:
            with self.subTest(version=version), mock.patch.object(nodes.nfqws_process, 'run',
                    return_value=ProcessResult(0, version)):
                if accepted:
                    manager._require_supported_xray()
                else:
                    with self.assertRaises(ValueError):
                        manager._require_supported_xray()


class VpnProbeTests(unittest.TestCase):
    def test_memory_watchdog_fails_check_and_kills_only_probe(self):
        manager = nodes.VpnNodeManager()
        process = mock.Mock(pid=99999999)
        process.poll.return_value = None
        def run(argv, **_kwargs):
            if argv[0] == manager.curl:
                time.sleep(0.25)
            return mock.Mock(returncode=0, stdout='204')
        with mock.patch.object(manager, '_require_supported_xkeen'), \
                mock.patch.object(nodes.subprocess, 'run', side_effect=run), \
                mock.patch.object(nodes.subprocess, 'Popen', return_value=process), \
                mock.patch.object(nodes.socket, 'socket') as sock, \
                mock.patch.object(Path, 'read_text', return_value='VmRSS:\t100000 kB\n'):
            sock.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 1234)
            sock.return_value.__enter__.return_value.connect_ex.return_value = 0
            health = manager.probe(outbound())
        self.assertFalse(health['ok'])
        process.kill.assert_called_once()
        self.assertIn('памяти', health['detail'])

    def test_all_targets_required_and_server_error_is_not_success(self):
        for codes, ok in [(['204', '200'], True), (['204', '500'], False), (['403'], False), (['200'], False)]:
            with self.subTest(codes=codes), tempfile.TemporaryDirectory() as folder:
                manager = nodes.VpnNodeManager(state_file=Path(folder) / 'nodes.json')
                process = mock.Mock(pid=99999999)
                process.poll.return_value = None
                answers = [mock.Mock(returncode=0), *(mock.Mock(returncode=0, stdout=code) for code in codes)]
                with mock.patch.object(manager, '_require_supported_xkeen'), \
                        mock.patch.object(nodes.subprocess, 'run', side_effect=answers) as run, \
                        mock.patch.object(nodes.subprocess, 'Popen', return_value=process), \
                        mock.patch.object(nodes.socket, 'socket') as sock:
                    sock.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 1234)
                    sock.return_value.__enter__.return_value.connect_ex.return_value = 0
                    result = manager.probe(outbound())
                self.assertEqual(result['ok'], ok)
                self.assertIn('checked_at', result)
                process.terminate.assert_called_once()
                curls = [call.args[0] for call in run.call_args_list if call.args[0][0] == manager.curl]
                self.assertTrue(all('--socks5-hostname' in args and '--noproxy' in args and '--disable' in args for args in curls))
                self.assertEqual(len(curls), len(codes))

    def test_probe_parent_death_terminates_exec_child(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / 'test-xray'
            executable.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(30)\n')
            executable.chmod(0o700)
            driver = ('import os,subprocess,sys,time; '
                      'p=subprocess.Popen([sys.executable,"-m","kdn.vpn_probe_child",str(os.getpid()),'
                      + repr(str(executable)) + ',"unused"]); print(p.pid,flush=True); time.sleep(30)')
            env = {**os.environ, 'PYTHONPATH': str(Path(nodes.__file__).resolve().parent)}
            parent = subprocess.Popen([sys.executable, '-c', driver], stdout=subprocess.PIPE, text=True, env=env)
            child = None
            try:
                child = int(parent.stdout.readline())
                time.sleep(0.3)
                self.assertTrue(Path('/proc', str(child), 'status').exists())
                self.assertNotIn('\nState:\tZ', Path('/proc', str(child), 'status').read_text())
                parent.kill()
                parent.wait(timeout=3)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status = Path('/proc', str(child), 'status')
                    try:
                        child_status = status.read_text()
                    except (FileNotFoundError, ProcessLookupError):
                        break  # reaped between the check and read is also successful termination
                    if '\nState:\tZ' in child_status:
                        break
                    time.sleep(0.05)
                else:
                    self.fail('probe survived its worker')
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=3)
                parent.stdout.close()
                if child is not None:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

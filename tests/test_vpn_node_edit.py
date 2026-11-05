"""Private registry edits never mutate the live outbound, expose secrets or restart."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tools.router import vpn_node_manager as node_module

from kdn.common import lock
from tools.router.vpn_node_manager import VpnNodeManager, display_name
from test_vpn_node_manager import outbound, UUID


class VpnNodeEditTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(VpnNodeManager, '_require_supported_xkeen')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        xray = self.root / 'xray'
        xray.mkdir()
        self.live = xray / '04_outbounds.json'
        self.live.write_text(json.dumps({'outbounds': [outbound()]}))
        (xray / '05_routing.json').write_text('{"routing":{"rules":[{"outboundTag":"vless-reality"}]}}')
        self.manager = VpnNodeManager(xray_dir=xray, state_file=self.root / 'vpn-nodes.json',
                                      backup_dir=self.root / 'backups', lock_dir=self.root / 'project.lock')
        with mock.patch.object(self.manager, 'probe', return_value={'ok': True, 'checked_utc': 'now'}):
            self.manager.add('reserve', json.dumps(outbound('backup.example')))
        self.before = self.live.read_bytes()

    def test_unicode_name_separate_from_id_and_active_rename_no_drift(self):
        with mock.patch.object(self.manager, 'probe', return_value={'ok': False}):
            added = self.manager.add('🇩🇪 Германия — резерв', json.dumps(outbound()))['node']
        self.assertRegex(added['id'], r'^node_[a-f0-9]{16}$')
        self.assertEqual(added['name'], '🇩🇪 Германия — резерв')
        renamed = self.manager.rename('current', 'Основной VPN')['node']
        self.assertEqual(renamed['id'], 'current')
        self.assertTrue(renamed['active'])
        self.assertFalse(self.manager.status()['drift'])
        self.assertEqual(self.live.read_bytes(), self.before)

    def test_reserve_edit_resets_health_keeps_id_and_creates_private_version(self):
        with mock.patch.object(self.manager, 'probe', side_effect=AssertionError('unexpected probe')):
            result = self.manager.update('reserve', name='Токио', source=json.dumps(outbound('new.example')))['node']
        self.assertEqual(result['id'], 'reserve')
        self.assertIsNone(result['health'])
        self.assertEqual(result['name'], 'Токио')
        self.assertEqual(self.live.read_bytes(), self.before)
        self.assertNotIn(UUID, json.dumps(result))
        files = list((self.root / 'vpn-node-versions').glob('*.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'vpn-node-versions').stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads(files[0].read_text())['outbound']['settings']['address'], 'backup.example')
        self.assertEqual(self.manager.load()['version'], 1)

    def test_rename_keeps_secret_and_health(self):
        old = self.manager.load()['nodes']['reserve']
        node = self.manager.rename('reserve', 'Резерв 2')
        new = self.manager.load()['nodes']['reserve']
        self.assertEqual(new['outbound'], old['outbound'])
        self.assertEqual(new['health'], old['health'])
        self.assertEqual(node['node']['id'], 'reserve')

    def test_refusals_are_atomic_and_do_not_expose_source(self):
        initial = self.manager.state_file.read_bytes()
        for kwargs in ({'source': json.dumps(outbound())},):
            with self.assertRaisesRegex(ValueError, 'активной'):
                self.manager.update('current', **kwargs)
        for value in ('', 'bad;id', 'a\nb', 'a\u202eb', 'a' * 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.manager.rename('reserve', value)
        with self.assertRaisesRegex(ValueError, 'используется'):
            self.manager.rename('reserve', 'Текущее подключение')
        source = f'vless://{UUID}@host.example:SECRET-PORT?security=tls'
        with self.assertRaises(ValueError) as error:
            self.manager.update('reserve', source=source)
        self.assertNotIn('SECRET', str(error.exception))
        self.assertNotIn(UUID, str(error.exception))
        self.assertEqual(self.manager.state_file.read_bytes(), initial)
        with lock.ProjectLock(self.manager.lock_dir), self.assertRaises(RuntimeError):
            self.manager.rename('reserve', 'Другое имя')
        self.manager.transaction_file.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'восстановите'):
            self.manager.rename('reserve', 'Другое имя')

    def test_public_projection_never_echoes_arbitrary_transport_objects(self):
        state = self.manager.load()
        node = state['nodes']['reserve']
        node['outbound']['settings']['address'] = 'user:SECRET@host'
        node['outbound']['streamSettings']['network'] = {'password': 'SECRET'}
        node['outbound']['streamSettings']['security'] = {'uuid': UUID}
        node['health'] = {'ok': False, 'password': 'SECRET', 'details': {'uuid': UUID}}
        public = self.manager._public_node('reserve', node, 'current')
        self.assertNotIn('SECRET', json.dumps(public))
        self.assertNotIn(UUID, json.dumps(public))

    def test_nfc_and_no_read_time_registry_migration(self):
        self.assertEqual(display_name(' Cafe\u0301 '), 'Café')
        initial = self.manager.state_file.read_bytes()
        self.manager.status()
        self.assertEqual(self.manager.state_file.read_bytes(), initial)

    def test_renamed_ascii_label_can_be_reused_without_overwriting_old_id(self):
        self.manager.rename('reserve', 'Токио')
        with mock.patch.object(self.manager, 'probe', return_value={'ok': False}):
            result = self.manager.add('reserve', json.dumps(outbound()))
        self.assertNotEqual(result['node']['id'], 'reserve')
        self.assertEqual(self.manager.load()['nodes']['reserve']['name'], 'Токио')

    def test_atomic_registry_failure_keeps_old_state_and_private_rescue(self):
        initial = self.manager.state_file.read_bytes()
        real = node_module.atomic_json
        def write(path, data, mode=0o600):
            if path == self.manager.state_file:
                raise OSError('injected disk failure')
            real(path, data, mode)
        with mock.patch.object(node_module, 'atomic_json', side_effect=write), self.assertRaises(OSError):
            self.manager.rename('reserve', 'Другое имя')
        self.assertEqual(self.manager.state_file.read_bytes(), initial)
        self.assertEqual(len(list((self.root / 'vpn-node-versions').glob('*.json'))), 1)
        self.assertFalse(self.manager.lock_dir.exists())

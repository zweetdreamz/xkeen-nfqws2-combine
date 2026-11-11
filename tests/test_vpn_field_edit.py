"""Partial edits retain opaque connection settings, never switch live VPN."""
import copy
import json
import unittest
from unittest import mock

from kdn import vpn_fields
import test_vpn_node_edit as fixtures
from test_vpn_node_manager import outbound, UUID


class PartialEditTests(unittest.TestCase):
    setUp = fixtures.VpnNodeEditTests.setUp

    def test_address_and_port_keep_credentials_transport_and_unknown_options(self):
        old = self.manager.load()['nodes']['reserve']['outbound']
        old['streamSettings']['sockopt'] = {'mark': 255, 'tcpKeepAliveIdle': 60}
        old['settings']['encryption'] = 'mlkem768x25519plus.native.0rtt.fixture'
        state = self.manager.load()
        state['nodes']['reserve']['outbound'] = copy.deepcopy(old)
        self.manager._save_state(state)
        with mock.patch.object(self.manager, 'probe', side_effect=AssertionError('no network')):
            result = self.manager.update('reserve', fields={'address': '203.0.113.7', 'port': 8443})
        new = self.manager.load()['nodes']['reserve']['outbound']
        expected = copy.deepcopy(old)
        expected['settings'].update(address='203.0.113.7', port=8443)
        self.assertEqual(new, expected)
        self.assertEqual(self.live.read_bytes(), self.before)
        self.assertIsNone(result['node']['health'])
        self.assertNotIn(UUID, json.dumps(result))

    def test_active_partial_edit_creates_reserve_without_touching_active_or_config(self):
        original = self.manager.load()['nodes']['current']['outbound']
        with mock.patch.object(self.manager, 'probe', side_effect=AssertionError('no network')):
            result = self.manager.update('current', fields={'address': '2001:db8::7'})
        state = self.manager.load()
        self.assertTrue(result['draft'])
        self.assertFalse(result['node']['active'])
        self.assertEqual(state['active'], 'current')
        self.assertEqual(state['nodes']['current']['outbound'], original)
        draft = state['nodes'][result['node']['id']]['outbound']
        self.assertEqual(draft['settings']['address'], '2001:db8::7')
        self.assertEqual(draft['settings']['id'], original['settings']['id'])
        self.assertEqual(draft['streamSettings'], original['streamSettings'])
        self.assertEqual(self.live.read_bytes(), self.before)

    def test_sni_and_fingerprint_keep_reality_key_and_short_id(self):
        old = self.manager.load()['nodes']['reserve']['outbound']
        self.manager.update('reserve', fields={'sni': 'new.example', 'fingerprint': 'firefox'})
        new = self.manager.load()['nodes']['reserve']['outbound']
        expected = copy.deepcopy(old)
        expected['streamSettings']['realitySettings'].update(serverName='new.example', fingerprint='firefox')
        self.assertEqual(new, expected)

    def test_invalid_partial_edit_is_atomic_and_does_not_echo_secrets(self):
        original = self.manager.state_file.read_bytes()
        for changes in ({'port': True}, {'port': 65536}, {'address': 'https://bad.example/'},
                        {'uuid': 'SECRET-UUID'}, {'password': 'SECRET'}, {'dialerProxy': 'other'},
                        {'short_id': 'not-hex'}, {'public_key': 'SECRET'}, {'sni': '\nSECRET'}):
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError) as caught:
                self.manager.update('reserve', fields=changes)
            self.assertNotIn('SECRET', str(caught.exception))
            self.assertEqual(self.manager.state_file.read_bytes(), original)
        with self.assertRaises(ValueError):
            self.manager.update('reserve', source=json.dumps(outbound()), fields={'port': 8443})

    def test_legacy_single_server_fields_are_patched_in_place(self):
        old = outbound()
        old['settings'] = {'vnext': [{'address': 'old.example', 'port': 443,
                                    'users': [{'id': UUID, 'encryption': 'none', 'level': 8}]}]}
        new = vpn_fields.patch_outbound(old, {'address': 'new.example', 'port': 8443})
        self.assertEqual(new['settings']['vnext'][0]['address'], 'new.example')
        self.assertEqual(new['settings']['vnext'][0]['users'], old['settings']['vnext'][0]['users'])
        self.assertNotIn('address', new['settings'])
        self.assertEqual(old['settings']['vnext'][0]['address'], 'old.example')

    def test_transport_and_hysteria_passwords_preserve_other_fields(self):
        hy = {'protocol': 'hysteria', 'settings': {'version': 2, 'address': 'hy.example', 'port': 443},
              'streamSettings': {'network': 'hysteria', 'security': 'tls',
                  'tlsSettings': {'serverName': 'hy.example', 'alpn': ['h3']},
                  'hysteriaSettings': {'version': 2, 'auth': 'old-auth'},
                  'finalmask': {'quicParams': {'congestion': 'bbr'}, 'udp': [
                      {'type': 'salamander', 'settings': {'password': 'old-mask', 'packetSize': '100-200'}}]}}}
        new = vpn_fields.patch_outbound(hy, {'password': 'new-auth', 'obfs_password': 'new-mask'})
        self.assertEqual(new['streamSettings']['hysteriaSettings']['auth'], 'new-auth')
        self.assertEqual(new['streamSettings']['finalmask']['udp'][0]['settings'], {'password': 'new-mask', 'packetSize': '100-200'})
        self.assertEqual(new['streamSettings']['tlsSettings'], hy['streamSettings']['tlsSettings'])
        ws = outbound()
        ws['streamSettings'].update(network='ws', wsSettings={'path': '/old?key=private', 'headers': {'Host': 'old.example', 'X-Token': 'private'}})
        new = vpn_fields.patch_outbound(ws, {'path': '/new', 'host': 'new.example'})
        self.assertEqual(new['streamSettings']['wsSettings']['headers'], {'Host': 'new.example', 'X-Token': 'private'})

    def test_other_explicit_fields_and_alpn_use_protocol_specific_locations(self):
        value = outbound()
        new_uuid = '00000000-0000-4000-8000-000000000007'
        changed = vpn_fields.patch_outbound(value, {'uuid': new_uuid, 'encryption': 'none',
                    'flow': 'xtls-rprx-vision', 'public_key': 'B' * 43, 'short_id': 'aabb'})
        self.assertEqual(changed['settings']['id'], new_uuid)
        self.assertEqual(changed['settings']['flow'], 'xtls-rprx-vision')
        self.assertEqual(changed['streamSettings']['realitySettings']['publicKey'], 'B' * 43)
        self.assertEqual(changed['streamSettings']['realitySettings']['shortId'], 'aabb')
        value['streamSettings'] = {'network': 'grpc', 'security': 'tls',
                                  'tlsSettings': {'serverName': 'front.example'},
                                  'grpcSettings': {'serviceName': 'old', 'authority': 'keep.example'}}
        changed = vpn_fields.patch_outbound(value, {'alpn': 'h2,http/1.1', 'service_name': 'new'})
        self.assertEqual(changed['streamSettings']['tlsSettings']['alpn'], ['h2', 'http/1.1'])
        self.assertEqual(changed['streamSettings']['grpcSettings'], {'serviceName': 'new', 'authority': 'keep.example'})

    def test_repeated_active_edits_have_unique_labels_and_full_registry_refuses_safely(self):
        first = self.manager.update('current', fields={'port': 8443})
        second = self.manager.update('current', fields={'port': 9443})
        self.assertNotEqual(first['node']['id'], second['node']['id'])
        self.assertNotEqual(first['node']['name'], second['node']['name'])
        state = self.manager.load()
        for number in range(16 - len(state['nodes'])):
            state['nodes'][f'extra{number}'] = {'name': f'extra{number}', 'outbound': outbound(), 'health': None}
        self.manager._save_state(state)
        original = self.manager.state_file.read_bytes()
        with self.assertRaises(ValueError):
            self.manager.update('current', fields={'port': 4433})
        self.assertEqual(self.manager.state_file.read_bytes(), original)
        self.assertEqual(self.live.read_bytes(), self.before)

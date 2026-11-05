"""Status blocks expose approved metadata, never Xray credentials or RCI tokens."""
import json
import tempfile
import unittest
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import statusblocks, xrayconf


class BlockTests(unittest.TestCase):
    def test_token_presence_not_value_and_missing_vs_empty_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            fixture.write('/opt/etc/xkeen/xkeen.json', '{"killswitch":true,"rci_token":"DO-NOT-EXPOSE"}')
            fixture.set_init('pbr_strict', '')
            block = statusblocks.xkeen_block(engine_run.make_context(fixture, ['--status', '--json']))
            self.assertTrue(block['config']['rci_token_set'])
            self.assertTrue(block['config']['killswitch'])
            self.assertNotIn('DO-NOT-EXPOSE', json.dumps(block))
            self.assertIsNone(block['init']['dscp_enable'])
            self.assertEqual(block['init']['pbr_strict'], '')
            with mock.patch.object(statusblocks, 'MAX_XKEEN_JSON', 1):
                self.assertFalse(statusblocks.xkeen_block(engine_run.make_context(fixture, ['--status', '--json']))['config']['rci_token_set'])

    def test_inbound_roles_allowed_network_and_rule_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            fixture.write('/opt/etc/xray/configs/03_inbounds.json', json.dumps({'inbounds': [
                {'tag': 'renamed', 'protocol': 'tunnel', 'settings': {'followRedirect': True, 'allowedNetwork': 'tcp,udp'}},
                {'tag': 'not-by-tag', 'protocol': 'dokodemo-door', 'settings': {'network': 'udp'}, 'streamSettings': {'sockopt': {'tproxy': 'tproxy'}}}]}))
            ctx = engine_run.make_context(fixture, ['--status', '--json'])
            rows = statusblocks.xray_block(ctx)['inbounds']
            self.assertEqual([row['role'] for row in rows], ['redirect', 'tproxy'])
            self.assertEqual([row['allowed_network'] for row in rows], ['tcp,udp', 'udp'])
            self.assertEqual(xrayconf.rules_summary({'routing': {'rules': [{'type': 'field'}, {}]}})['with_type_field'], 1)

    def test_version_ansi_real_style_timeout_and_bounded_config(self):
        fixture = engine_scenarios.build('fresh')
        ctx = engine_run.make_context(fixture, ['--status', '--json'])
        for version, expected in [('\x1b[32m  Версия XKeen 2.1 Stable\x1b[0m\nXray 26\n', '2.1'), ('XKeen 2.1.1 Beta\n', '2.1.1-beta')]:
            with mock.patch.object(statusblocks.xkeen, 'probe', return_value=statusblocks.xkeen.parse_version(version)):
                self.assertEqual(statusblocks.xkeen_block(ctx)['version'], expected)
        with mock.patch.object(statusblocks.xkeen, 'probe', return_value=''):
            with self.assertRaises(statusblocks.xkeen.UnsupportedXKeen):
                statusblocks.xkeen_block(ctx)
        with mock.patch.object(statusblocks, 'MAX_XKEEN_JSON', 1):
            self.assertEqual(statusblocks.xkeen_block(ctx)['config']['rci_token_set'], False)
        standalone = engine_run.make_context(fixture, ['--status', '--standalone-zapret'])
        self.assertIsNone(statusblocks.xkeen_block(standalone))
        self.assertIsNone(statusblocks.xray_block(standalone))
        mihomo = engine_run.make_context(fixture, ['--status', '--core', 'mihomo'])
        self.assertIsNone(statusblocks.xray_block(mihomo))

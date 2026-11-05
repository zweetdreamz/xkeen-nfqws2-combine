"""Route wrapper state is read under the writer lock; argv is never shell-evaluated."""
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import apply_files, route_switch as switch
from test_engine_apply_files import ApplyFilesFixture


class RouteSwitchTests(ApplyFilesFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.fields = dict(discord_tcp_route='zapret', discord_voice_route='direct', youtube_route='vless',
                           telegram_route='ws', udp_range='wide', udp_strategy='legacy')

    def test_service_preserves_other_resources_and_udp_inside_apply_lock(self):
        def collect(ctx):
            apply_files.require_owner(ctx)
            return SimpleNamespace(fields=self.fields)
        with mock.patch.object(switch.status, 'collect', side_effect=collect):
            with mock.patch.object(switch.apply_ops, 'operation') as operation:
                self.assertEqual(switch.run(self.ctx, 'service', ['youtube', 'direct', '--yes-router']), 0,
                                 self.err.getvalue())
                operation.assert_called_once()
                self.assertEqual(self.ctx.resolved.youtube_route, 'direct')
                self.assertEqual(self.ctx.resolved.discord_tcp_route, 'zapret')
                self.assertEqual(self.ctx.resolved.discord_voice_route, 'direct')
                self.assertEqual(self.ctx.resolved.telegram_route, 'ws')
                self.assertTrue(self.ctx.resolved.wide_udp)
                self.assertEqual(self.ctx.resolved.udp_strategy, 'legacy')

    def test_alias_and_explicit_overrides_are_arguments_not_eval(self):
        with mock.patch.object(switch.status, 'collect', return_value=SimpleNamespace(fields=self.fields)):
            with mock.patch.object(switch.apply_ops, 'operation'):
                args = ['discord', 'vpn', '--narrow-udp', '--yes-router']
                self.assertEqual(switch.run(self.ctx, 'service', args), 0)
                self.assertEqual(self.ctx.resolved.discord_tcp_route, 'vless')
                self.assertEqual(self.ctx.resolved.discord_voice_route, 'vless')
                self.assertFalse(self.ctx.resolved.wide_udp)
                for bad in ('direct; touch /tmp/BAD', '$(id)', 'ws'):
                    with self.subTest(bad=bad):
                        self.assertEqual(switch.run(self.ctx, 'service', ['discord', bad, '--yes-router']), 1)

    def test_presets_and_bad_state_refused_without_apply(self):
        with mock.patch.object(switch.status, 'collect', return_value=SimpleNamespace(fields=self.fields)):
            for preset, values in switch.PRESETS.items():
                with self.subTest(preset=preset):
                    args = switch.build(self.ctx, 'preset', [preset, '--yes-router'])
                    self.assertIn(values[0], args)
                    self.assertIn(values[1], args)
            self.fields['discord_voice_route'] = 'unknown'
            with mock.patch.object(switch.apply_ops, 'operation') as operation:
                self.assertEqual(switch.run(self.ctx, 'service', ['youtube', 'direct', '--yes-router']), 1)
                operation.assert_not_called()

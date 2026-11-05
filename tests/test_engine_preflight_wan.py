"""WAN checks are compared with the original read-only shell checks in isolated roots."""
import tempfile
import unittest
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import findings, preflight_wan, system


class WanTests(unittest.TestCase):
    def test_full_preflight_matches_legacy_all_scenarios(self):
        cases = []
        for name in engine_scenarios.names():
            fixture = engine_scenarios.build(name)
            extra = {'TEST_BUSYBOX_APPLETS': '1'} if name == 'odd-values' else None
            for args in (['--preflight', '--core', 'xray'], ['--preflight'], ['--preflight', '--standalone-zapret']):
                cases.append((args, fixture, extra))
        reference = iter(engine_run.legacy_results(cases))
        for name in engine_scenarios.names():
            fixture = engine_scenarios.build(name)
            extra = {'TEST_BUSYBOX_APPLETS': '1'} if name == 'odd-values' else None
            for args in (['--preflight', '--core', 'xray'], ['--preflight'], ['--preflight', '--standalone-zapret']):
                with self.subTest(name=name, args=args):
                    expected = next(reference)
                    actual = engine_run.run_mode('preflight', args, fixture)
                    self.assertFalse(actual.fallback)
                    self.assertEqual(actual, expected)
        engine_scenarios.assert_unchanged()

    def test_route_fallbacks_marks_rejected_routes_and_ipv6(self):
        fixture = engine_scenarios.build('fresh')
        for text, expected in [('1.1.1.1 dev wan0 src 192.0.2.1\n', 'wan0'), ('unreachable 1.1.1.1 dev wan0 error -1\n', ''),
                               ('1.1.1.1 dev lo\n', ''), ('default via 192.0.2.1 dev wan6\n', 'wan6')]:
            with self.subTest(text=text), mock.patch.object(system, 'run', return_value=system.Completed(0, text)) as run:
                self.assertEqual(preflight_wan.route_interface('255', fixture.env), expected)
                self.assertNotIn('mark', run.call_args.args[0])
            with mock.patch.object(system, 'run', return_value=system.Completed(0, text)) as run:
                self.assertEqual(preflight_wan.route_interface_v6('123', fixture.env), expected)
                self.assertIn('mark', run.call_args.args[0])

    def test_invalid_loopback_missing_wan_and_exclusion(self):
        fixture = engine_scenarios.build('fresh')
        for value, message in [('lo', 'loopback'), ('a/b', 'invalid WAN'), ('does-not-exist', 'does not exist')]:
            with self.assertRaisesRegex(preflight_wan.WanError, message):
                preflight_wan.validate_wan_interfaces(value, fixture.env)
        with tempfile.TemporaryDirectory() as tmp:
            local = engine_fixture.make_root(tmp)
            local.write('/opt/etc/xkeen/port_exclude.lst', '443\n')
            ctx = engine_run.make_context(local, ['--preflight'])
            request = preflight_wan.WanRequest(required_ports='443', test_root=str(local.root))
            state = findings.State()
            preflight_wan.check(ctx.paths, ctx.environ, request, state)
            self.assertEqual(state.errors, 1)
            self.assertIn('overlaps required Discord ports', state.findings[0].text)
            local.write('/opt/etc/xkeen/port_exclude.lst', '')
            local.set_init('ipv6_support', 'on')
            for ipv4, ipv6, expected in [('other4', 'other6', 'IPv4 WAN: other4'), ('fixture-wan', 'other6', 'IPv6 WAN: other6')]:
                with mock.patch.object(preflight_wan, 'route_interface', return_value=ipv4), \
                     mock.patch.object(preflight_wan, 'route_interface_v6', return_value=ipv6):
                    state = findings.State()
                    preflight_wan.check(ctx.paths, ctx.environ, request, state)
                self.assertEqual(state.errors, 1)
                self.assertEqual(state.ipv6, '1')
                self.assertIn(expected, state.findings[0].text)

    def test_reserved_policy_and_mihomo_handover_before_output(self):
        fixture = engine_scenarios.build('fresh')
        ctx = engine_run.make_context(fixture, ['--preflight'])
        request = preflight_wan.WanRequest(test_root='')
        with mock.patch.object(system, 'run', return_value=system.Completed(0, 'DESCRIPTION = __KEENETIC_DISCORD_NFQWS2_UNBOUND__:')):
            state = findings.State()
            preflight_wan.check_unbound_policy(ctx.paths, ctx.environ, request, state)
        self.assertEqual(state.errors, 1)
        result = engine_run.run_mode('preflight', ['--preflight', '--core', 'mihomo'], fixture)
        self.assertEqual((result.fallback, result.out, result.err), (True, '', ''))

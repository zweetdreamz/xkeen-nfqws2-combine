"""Xray preflight library: first-error ordering, mark/proxy selection and bounded tests."""
import unittest
import subprocess
from pathlib import Path
import tempfile
import time
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
import engine_shell
from kdn.engine import config, findings, preflight_xray, system


class MarkTests(unittest.TestCase):
    def test_decimal_bounds(self):
        for text in ('1', '255', '4294967295', '0001'):
            self.assertTrue(preflight_xray.valid_decimal_mark(text))
        for text in ('', '0', '-1', '0x123', '4294967296', '1.0', ' 1', '1\n'):
            self.assertFalse(preflight_xray.valid_decimal_mark(text))

    def test_decimal_marks_match_shell_including_large_and_padded_values(self):
        for text in ('0', '1', '255', '4294967295', '4294967296', '0x123', '-1', '1.0', ' 1', '1\n', '9' * 5000, '0' * 5000 + '1'):
            ref = engine_shell.run_function('valid_decimal_mark', text)
            self.assertEqual(preflight_xray.valid_decimal_mark(text), ref.returncode == 0)


class XrayTests(unittest.TestCase):
    def request(self, ctx):
        options = ctx.resolved
        return preflight_xray.XrayRequest({'tcp': options.discord_tcp_route, 'voice': options.discord_voice_route,
                                          'youtube': options.youtube_route}, options.direct_mark_requested,
                                         options.proxy_outbound_requested, options.telegram_route, ctx.paths.test_root)

    def test_library_errors_match_full_legacy_preflight(self):
        for scenario, args in [('fresh', ['--direct-mark', '0x123']), ('fresh', ['--proxy-outbound', 'missing']),
                               ('xray-no-binary', []), ('xray-test-fails', []), ('xray-broken-json-file', [])]:
            with self.subTest(scenario=scenario, args=args):
                fixture = engine_scenarios.build(scenario)
                argv = ['--preflight', '--core', 'xray', *args]
                ctx = engine_run.make_context(fixture, argv)
                state = findings.State()
                preflight_xray.check(ctx.paths, ctx.environ, self.request(ctx), state)
                ref = engine_run.run_legacy(argv, fixture)
                self.assertEqual(state.errors, 1)
                self.assertEqual(''.join(item.text for item in state.findings), ref.err.split('Preflight failed with', 1)[0])

    def test_first_error_stops_later_checks_and_optional_proxy_failure_is_silent(self):
        fixture = engine_scenarios.build('fresh')
        ctx = engine_run.make_context(fixture, ['--preflight'])
        state = findings.State()
        with mock.patch.object(preflight_xray, 'resolve_direct_mark', side_effect=preflight_xray.XrayCheckError('bad mark\n')), \
             mock.patch.object(preflight_xray, 'resolve_proxy_outbound') as proxy:
            preflight_xray.check(ctx.paths, ctx.environ, self.request(ctx), state)
        proxy.assert_not_called()
        self.assertEqual(state.errors, 1)
        request = preflight_xray.XrayRequest({'tcp': 'direct', 'voice': 'direct', 'youtube': 'direct'})
        state = findings.State()
        with mock.patch.object(preflight_xray, 'resolve_proxy_outbound', side_effect=preflight_xray.XrayCheckError('ignored\n')):
            preflight_xray.check(ctx.paths, ctx.environ, request, state)
        self.assertEqual((state.errors, state.findings, state.proxy_outbound), (0, [], ''))

    def test_proxy_priority_and_invalid_inherited_mark(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            ctx = engine_run.make_context(fixture, ['--preflight'])
            request = self.request(ctx)
            self.assertEqual(preflight_xray.resolve_proxy_outbound(ctx.paths, request), 'vless-reality')
            fixture.write('/opt/etc/xray/configs/99_extra.json', '{"outbounds":[{"tag":"other","protocol":"trojan"}]}')
            with fixture.path('/opt/etc/nfqws2/nfqws2.conf').open('a') as handle:
                handle.write('\n# Proxy outbound: other.\n')
            self.assertEqual(preflight_xray.resolve_proxy_outbound(ctx.paths, request), 'other')
            request.proxy_outbound_requested = 'vless-reality'
            self.assertEqual(preflight_xray.resolve_proxy_outbound(ctx.paths, request), 'vless-reality')
            fixture.write('/opt/etc/xray/configs/98_mark.json', '{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":255.0}}}]}')
            with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'not a valid decimal number: 255.0'):
                preflight_xray.resolve_direct_mark(ctx.paths, request)

    def test_dat_ws_missing_config_and_mark_inheritance(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            ctx = engine_run.make_context(fixture, ['--preflight', '--telegram-route', 'vless'])
            dat = Path(tmp, 'dat'); dat.mkdir()
            paths = ctx.paths.replace(xray_dat_dir=str(dat))
            state = findings.State()
            preflight_xray.check(paths, ctx.environ, self.request(ctx), state)
            self.assertIn('geosite_v2fly.dat', state.findings[0].text)
            missing = ctx.paths.replace(xray_config_dir=str(Path(tmp, 'missing')))
            state = findings.State()
            preflight_xray.check(missing, ctx.environ, self.request(ctx), state)
            self.assertEqual(state.findings[0].text, 'ERROR: Xray config directory not found: ' + missing.xray_config_dir + '\n')
            with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'with ssl and asyncio'):
                preflight_xray.telegram_ws_ready(ctx.paths.replace(telegram_ws_python=str(Path(tmp, 'missing-python'))), ctx.environ)
            with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'relay is missing'):
                preflight_xray.telegram_ws_ready(ctx.paths.replace(telegram_ws_relay=str(Path(tmp, 'missing-relay'))), ctx.environ)
            fixture.set_init('proxy_router', 'on')
            self.assertEqual(preflight_xray.resolve_direct_mark(ctx.paths, self.request(ctx)), '255')
            fixture.write('/opt/etc/xray/configs/99_mark.json', '{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":123}}}]}')
            self.assertEqual(preflight_xray.resolve_direct_mark(ctx.paths, self.request(ctx)), '123')

    def test_xray_tail_bytes_no_final_newline_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            paths = config.EnginePaths.from_environ(fixture.env)
            binary = fixture.mock_bin / 'xray'
            payload = ''.join(f'line-{number}\n' for number in range(29)) + '\udcfflast'
            binary.write_bytes(b'#!/bin/sh\ncat <<\'END\'\n' + b'END\nexit 2\n')
            with mock.patch.object(system, 'run', return_value=system.Completed(23, payload)):
                result = preflight_xray.xray_test_config(paths, fixture.env)
            self.assertEqual(result, 'ERROR: Xray configuration test failed:\n' + ''.join(f'line-{number}\n' for number in range(10, 29)) + '\udcfflast')
            tail = subprocess.run(['tail', '-n', '20'], input=payload.encode('utf-8', 'surrogateescape'), capture_output=True, check=True)
            self.assertEqual(result, 'ERROR: Xray configuration test failed:\n' + tail.stdout.decode('utf-8', 'surrogateescape'))
            binary.write_text('#!/bin/sh\nsleep 2\n')
            original = config.timeout
            with mock.patch.object(config, 'timeout', side_effect=lambda name, env=None: .2 if name == 'xray_test' else original(name, env)):
                started = time.monotonic()
                result = preflight_xray.xray_test_config(paths, fixture.env)
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(result, 'ERROR: Xray configuration test timed out after 0.2s.\n')


class DirectMarkCollisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = engine_fixture.make_root(self.temporary.name)
        self.ctx = engine_run.make_context(self.fixture, ['--preflight'])
        self.request = preflight_xray.XrayRequest({'tcp': 'zapret'})

    def append_config(self, text):
        with Path(self.ctx.paths.nfqws_conf).open('a') as stream:
            stream.write('\n' + text + '\n')

    def test_explicit_and_inherited_marks_colliding_with_default_skip_bit_fail(self):
        for mark in ('1073741824', '1073741825', '1610612736'):
            self.request.direct_mark_requested = mark
            with self.subTest(mark=mark), self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
                preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)
        self.request.direct_mark_requested = ''
        self.fixture.write('/opt/etc/xray/configs/99_mark.json',
                           '{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":1073741824}}}]}')
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_custom_nfqws_fwmark_and_package_processed_mask_are_checked(self):
        self.append_config('NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=0x20"\nMARK_PROCESSED="0x80/0x80"')
        for mark in ('32', '33', '128', '129'):
            self.request.direct_mark_requested = mark
            with self.subTest(mark=mark), self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
                preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)
        for mark in ('1', '4', '1073741824'):
            self.request.direct_mark_requested = mark
            self.assertEqual(preflight_xray.resolve_direct_mark(self.ctx.paths, self.request), mark)

    def test_processed_mask_uses_iptables_equality_rather_than_shared_bits(self):
        self.append_config('NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=0x10000000"\nMARK_PROCESSED="0x1/0x3"')
        for mark in ('2', '3', '255'):
            self.request.direct_mark_requested = mark
            self.assertEqual(preflight_xray.resolve_direct_mark(self.ctx.paths, self.request), mark)
        for mark in ('1', '5'):
            self.request.direct_mark_requested = mark
            with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
                preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_ambiguous_masks_and_fwmark_aliases_fail_explicitly(self):
        base = Path(self.ctx.paths.nfqws_conf).read_bytes()
        for suffix in ('MARK_PROCESSED=bogus', 'MARK_PROCESSED="1/2/3"', 'MARK_PROCESSED="1 2"', 'MARK_PROCESSED="1\n2"',
                       'MARK_PROCESSED=""', 'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwm=0x20"',
                       'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=1 --fwmark=2"',
                       'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=bogus"',
                       'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=0"',
                       'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=0X20"',
                       'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS -- --fwmark=0x20"'):
            Path(self.ctx.paths.nfqws_conf).write_bytes(base)
            self.append_config(suffix)
            self.request.direct_mark_requested = '255'
            with self.subTest(suffix=suffix), self.assertRaisesRegex(preflight_xray.XrayCheckError, 'ambiguous|unparseable|nonzero|MARK_PROCESSED'):
                preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_package_literal_default_is_read_but_init_footer_never_runs(self):
        marker = Path(self.temporary.name) / 'must-not-exist'
        self.fixture.write('/opt/etc/init.d/S51nfqws2',
            'MARK_PROCESSED="0x10/0x10"\n. "$CONFFILE"\n' + 'touch ' + str(marker) + '\n')
        self.request.direct_mark_requested = '16'
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)
        self.assertFalse(marker.exists())
        self.fixture.write('/opt/etc/init.d/S51nfqws2', 'unset MARK_PROCESSED\n. "$CONFFILE"\n')
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'MARK_PROCESSED'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)
        self.fixture.write('/opt/etc/init.d/S51nfqws2', 'MARK_PROCESSED="$OTHER_MASK"\n. "$CONFFILE"\n')
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'MARK_PROCESSED'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)
        self.fixture.write('/opt/etc/init.d/S51nfqws2', '. "$CONFFILE"\nMARK_PROCESSED="0x10/0x10"\n')
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'MARK_PROCESSED'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_iptables_octal_value_mask_is_not_guessed_as_decimal(self):
        self.append_config('NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS --fwmark=0x10000000"\nMARK_PROCESSED="010/017"')
        self.request.direct_mark_requested = '10'
        self.assertEqual(preflight_xray.resolve_direct_mark(self.ctx.paths, self.request), '10')
        self.request.direct_mark_requested = '8'
        with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
            preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_implicit_freedom_mark_checks_kernel_zero_and_preserves_empty_setting(self):
        self.fixture.set_init('proxy_router', 'off')
        with mock.patch.object(preflight_xray.xrayconf, 'freedom_mark', return_value=''):
            self.assertEqual(preflight_xray.resolve_direct_mark(self.ctx.paths, self.request), '')
            self.append_config('MARK_PROCESSED="0/0x40000000"')
            with self.assertRaisesRegex(preflight_xray.XrayCheckError, 'collid'):
                preflight_xray.resolve_direct_mark(self.ctx.paths, self.request)

    def test_implicit_mark_without_installed_nfqws_package_keeps_stock_fallback(self):
        self.fixture.set_init('proxy_router', 'off')
        Path(self.ctx.paths.nfqws_init).unlink()
        Path(self.ctx.paths.nfqws_conf).unlink()
        with mock.patch.object(preflight_xray.xrayconf, 'freedom_mark', return_value=''):
            self.assertEqual(preflight_xray.resolve_direct_mark(self.ctx.paths, self.request), '')

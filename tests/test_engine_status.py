"""Native text status compared with the actual legacy collector."""
import unittest
import os
from pathlib import Path
import shutil
import tempfile
import io
import time
import json
from unittest import mock

import engine_run
import engine_scenarios
import engine_fixture
from kdn.engine import cli, config, console, confvalues
from kdn.engine import status


class StatusTests(unittest.TestCase):
    def test_collect_fields_match_shell_key_lines(self):
        for name in engine_scenarios.names():
            fixture = engine_scenarios.build(name)
            # B6/R9: router semantics are authoritative for the deliberately
            # backslash-containing odd-values case, not dash's echo escapes.
            extra = {'TEST_BUSYBOX_APPLETS': '1'} if name == 'odd-values' else None
            separators = ' \t\n\r\v\f' if extra or os.environ.get('TEST_BUSYBOX_APPLETS') == '1' else ' \t\n'
            with self.subTest(name=name), mock.patch.object(confvalues, 'AWK_FIELD_SEPARATORS', separators):
                before = engine_scenarios.digest(fixture)
                report = status.collect_fields(engine_run.make_context(fixture, ['--status']))
                legacy = engine_run.run_legacy(['--status'], fixture, extra)
                prefix = legacy.out.split('State directory:', 1)[0]
                expected = [tuple(line.split('=', 1)) for line in prefix.split('\n') if '=' in line]
                self.assertEqual(list(report.fields.items()), expected)
                self.assertEqual(''.join(line + '\n' for line in report.warnings), legacy.err)
                self.assertEqual(engine_scenarios.digest(fixture), before)

    def test_unknown_core_keeps_value_and_reports_error_without_aborting(self):
        report = status.collect_fields(engine_run.make_context(engine_scenarios.build('unknown-core'), ['--status']))
        self.assertEqual(report.fields['detected_core'], 'unknown-fixture')
        self.assertEqual(report.warnings, ["ERROR: XKeen core is 'unknown-fixture'; expected xray or mihomo."])

    def test_no_routing_file_gives_unknown_routes(self):
        report = status.collect_fields(engine_run.make_context(engine_scenarios.build('xray-no-routing-file'), ['--status']))
        self.assertEqual([report.fields[key] for key in ('discord_tcp_route', 'discord_voice_route', 'youtube_route')], ['unknown'] * 3)

    def test_status_without_jq_still_reads_xray_routes(self):
        fixture = engine_scenarios.build('fresh')
        ctx = engine_run.make_context(fixture, ['--status'])
        expected = status.collect_fields(ctx).fields
        with tempfile.TemporaryDirectory() as tmp:
            for command in ('xkeen', 'opkg', 'pidof'):
                Path(tmp, command).symlink_to(fixture.mock_bin / command)
            Path(tmp, 'cat').symlink_to(shutil.which('cat'))
            ctx.environ = dict(ctx.environ, PATH=tmp)
            self.assertIsNone(shutil.which('jq', path=tmp))
            self.assertEqual(status.collect_fields(ctx).fields, expected)
            self.assertEqual(expected['youtube_route'], 'vless')

    def test_effective_standalone_does_not_overwrite_recorded_deployment(self):
        fixture = engine_scenarios.build('applied-default')
        report = status.collect_fields(engine_run.make_context(fixture, ['--status', '--standalone-zapret']))
        self.assertEqual(report.fields['deployment_mode'], 'xkeen-integrated')
        self.assertEqual(report.fields['detected_core'], 'standalone')
        self.assertEqual(report.fields['xkeen_runtime'], 'unmanaged')
        self.assertEqual(report.fields['custom_mark'], 'unmanaged')

    def test_missing_conf_omits_conditional_fields(self):
        report = status.collect_fields(engine_run.make_context(engine_scenarios.build('no-conf'), ['--status']))
        for key in ('discord_voice_profile', 'discord_voice_udp', 'proxy_outbound'):
            self.assertNotIn(key, report.fields)
        self.assertEqual(report.fields['udp_range'], 'unknown')

    def test_status_matches_shell(self):
        for name in engine_scenarios.names():
            fixture = engine_scenarios.build(name)
            extra = {'TEST_BUSYBOX_APPLETS': '1'} if name == 'odd-values' else None
            separators = ' \t\n\r\v\f' if extra or os.environ.get('TEST_BUSYBOX_APPLETS') == '1' else ' \t\n'
            with self.subTest(name=name), mock.patch.object(confvalues, 'AWK_FIELD_SEPARATORS', separators):
                before = engine_scenarios.digest(fixture)
                actual = engine_run.run_mode('status', ['--status'], fixture)
                self.assertFalse(actual.fallback)
                if name == 'no-xkeen-binary':
                    self.assertEqual(actual.rc, 2)
                    self.assertIn('XKeen 2.1+', actual.err)
                    self.assertEqual(actual.out, '')
                    self.assertEqual(engine_scenarios.digest(fixture), before)
                    continue
                self.assertEqual(actual, engine_run.run_legacy(['--status'], fixture, extra))
                if name != 'odd-values':
                    self.assertEqual(engine_run.run_dispatcher(['--status'], fixture), actual)
                self.assertEqual(engine_scenarios.digest(fixture), before)

    def test_json_flag_uses_native_collector_after_task_19(self):
        result = engine_run.run_mode('status', ['--status', '--json'], engine_scenarios.build('fresh'))
        self.assertFalse(result.fallback)
        self.assertEqual(json.loads(result.out)['schema'], 1)

    def test_odd_values_pin_router_echo_semantics_instead_of_dash_escapes(self):
        fixture = engine_scenarios.build('odd-values')
        # A BusyBox fixture already has sh/awk/sed/grep/tr in mock_bin;
        # clearing TEST_BUSYBOX_APPLETS alone does not undo those symlinks.
        with tempfile.TemporaryDirectory() as tmp:
            for applet in ('sh', 'awk', 'sed', 'grep', 'tr'):
                Path(tmp, applet).symlink_to(shutil.which(applet, path=os.defpath))
            dash = engine_run.run_legacy(['--status'], fixture,
                        {'TEST_BUSYBOX_APPLETS': '0', 'PATH': tmp + os.pathsep + fixture.env['PATH']})
        router = engine_run.run_legacy(['--status'], fixture, {'TEST_BUSYBOX_APPLETS': '1'})
        self.assertIn('detected_core=xray\\nfixture\n', router.out)
        self.assertIn('detected_core=xray\nfixture\n', dash.out)
        self.assertNotEqual(dash.out, router.out)
        self.assertEqual(engine_run.run_mode('status', ['--status'], fixture), router)

    def test_not_a_router_prints_no_partial_report(self):
        out, err = io.StringIO(), io.StringIO()
        ctx = cli.Context(['--status'], {}, console.Console(out, err), paths=config.EnginePaths.from_environ({}))
        with mock.patch.object(status.system, 'is_router', return_value=False), mock.patch.object(status.system, 'run') as run, \
                mock.patch.object(status.xkeen, 'require', return_value='2.1'):
            self.assertEqual(status.run(ctx), 1)
        run.assert_not_called()
        self.assertEqual((out.getvalue(), err.getvalue()), ('', 'ERROR: this does not look like a Keenetic Entware environment.\n'))

    def test_xkeen_timeout_warns_and_discards_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            (fixture.mock_bin / 'xkeen').write_text('#!/bin/sh\nif [ "$1" = -v ]; then echo "XKeen 2.1"; elif [ "$1" = -status ]; then printf partial; sleep 2; else printf "ok:%s\\n" "$1"; fi\n')
            original_timeout = config.timeout
            with mock.patch.object(config, 'timeout', side_effect=lambda name, env=None: .2 if name == 'xkeen_status' else original_timeout(name, env)):
                started = time.monotonic()
                result = engine_run.run_mode('status', ['--status'], fixture)
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(result.rc, 0)
            self.assertEqual(result.err, 'WARNING: xkeen -status timed out.\n')
            self.assertNotIn('partial', result.out)
            self.assertTrue(result.out.endswith('ok:-cp\nok:-cpe\nok:-tp\n'))

    def test_unreadable_output_bytes_no_newlines_stderr_and_nonzero_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            (fixture.mock_bin / 'xkeen').write_bytes(b'#!/bin/sh\nif [ "$1" = -v ]; then echo "XKeen 2.1"; exit 0; fi\nprintf "\\377raw:%s" "$1"\nprintf hidden >&2\nexit 7\n')
            actual = engine_run.run_mode('status', ['--status'], fixture)
            expected = engine_run.run_legacy(['--status'], fixture)
            self.assertEqual(actual, expected)
            self.assertTrue(actual.out.endswith('\udcffraw:-status\udcffraw:-cp\udcffraw:-cpe\udcffraw:-tp'))
            self.assertEqual(actual.err, '')

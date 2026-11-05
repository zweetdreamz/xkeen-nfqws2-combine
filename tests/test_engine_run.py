"""Engine runners and immutable session scenarios share the same shell builders."""
import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import engine_run
import engine_scenarios
import engine_fixture
from kdn.engine import confvalues


class RunnerTests(unittest.TestCase):
    def test_run_legacy_prints_the_plan(self):
        result = engine_run.run_legacy(['--print-plan'], engine_scenarios.build('fresh'))
        self.assertEqual(result.rc, 0, result.err)
        self.assertIn('Discord TCP=zapret', result.out)

    def test_run_mode_reports_a_fallback_for_stubs(self):
        result = engine_run.run_mode('preflight', ['--preflight', '--core', 'mihomo'], engine_scenarios.build('fresh'))
        self.assertTrue(result.fallback)

    def test_engine_run_imports_engine_at_module_level(self):
        tree = ast.parse(Path(engine_run.__file__).read_text(encoding='utf-8'))
        names = {alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                 and node.module == 'kdn.engine' for alias in node.names}
        self.assertTrue({'cli', 'config'} <= names)

    def test_every_scenario_builds_and_is_stable(self):
        for name in engine_scenarios.names():
            with self.subTest(name=name):
                fixture = engine_scenarios.build(name)
                self.assertIs(engine_scenarios.build(name), fixture)
        # The command-specific suites compare actual output with the legacy
        # oracle. Here only the shared builders and their immutability matter.
        engine_scenarios.assert_unchanged()

    def test_scenario_names_match_the_shell_list(self):
        expected = {'fresh', 'applied-default', 'routes-matrix-1', 'routes-matrix-2', 'routes-matrix-3',
                    'telegram-vless', 'telegram-recorded-zapret', 'imported-voice-narrow', 'imported-voice-wide',
                    'standalone', 'check-udp443-not-queued', 'check-empty-user-list', 'check-extra-args-empty',
                    'check-legacy-fake', 'check-two-empty-lists', 'check-custom-profile-1984', 'argv-corpus'}
        self.assertTrue(expected <= set(engine_scenarios.names()))
        self.assertEqual(len(engine_scenarios.names()), len(set(engine_scenarios.names())))

    def test_extended_scenarios_are_available(self):
        expected = {'xray-jsonc-routing', 'xray-two-routing-files', 'xray-broken-json-file', 'xray-no-routing-file',
                    'xray-no-binary', 'xray-test-fails', 'no-conf', 'no-init', 'no-xkeen-init', 'unknown-core', 'no-xkeen-binary',
                    'snapshots-baseline', 'snapshots-all', 'snapshots-missing', 'snapshots-symlink', 'snapshots-outside',
                    'snapshots-dotdot', 'snapshots-empty', 'snapshots-two-lines', 'snapshots-double-slash',
                    'nfqws-runtime-foreign-cmdline', 'nfqws-runtime-stopped', 'nfqws-runtime-wrong-qnum',
                    'nfqws-runtime-dry-run', 'synthetic21', 'odd-values'}
        self.assertTrue(expected <= set(engine_scenarios.names()))

    def test_scenario_content_is_not_only_a_set_of_names(self):
        for name, routes in (('routes-matrix-1', ('direct', 'vless', 'zapret')),
                             ('routes-matrix-2', ('vless', 'zapret', 'direct')),
                             ('routes-matrix-3', ('zapret', 'direct', 'vless'))):
            fixture = engine_scenarios.build(name)
            text = fixture.path('/opt/etc/nfqws2/nfqws2.conf').read_bytes().decode('utf-8')
            self.assertEqual(tuple(confvalues.recorded_route(text, service) for service in ('discord-tcp', 'discord-voice', 'youtube')), routes)
        for name, high in (('imported-voice-narrow', '50100'), ('imported-voice-wide', '65535')):
            fixture = engine_scenarios.build(name)
            text = fixture.path('/opt/etc/nfqws2/nfqws2.conf').read_bytes().decode('utf-8')
            self.assertIn('50000:' + high, text)
            self.assertIn('# Discord Voice profile: imported ', text)
        fixture = engine_scenarios.build('xray-no-routing-file')
        status = engine_run.run_legacy(['--status'], fixture)
        self.assertEqual(status.rc, 0, status.err)
        self.assertIn('discord_tcp_route=unknown\n', status.out)
        self.assertIn('youtube_route=unknown\n', status.out)
        vectors = [json.loads(row) for row in engine_scenarios.build('argv-corpus').path('/argv-corpus.jsonl').read_text().split('\n') if row]
        self.assertIn(['--status'], vectors)
        self.assertIn(['--bogus'], vectors)
        custom = engine_scenarios.build('check-custom-profile-1984').path('/opt/etc/nfqws2/nfqws2.conf').read_text()
        self.assertLess(custom.index('--filter-tcp=1984'), custom.index('# BEGIN keenetic-discord-nfqws2'))
        queue = engine_scenarios.build('check-udp443-not-queued').path('/opt/etc/nfqws2/nfqws2.conf').read_text()
        self.assertTrue(queue.endswith('UDP_PORTS=3478:3481,5349,19294:19344,50000:50100\n'))

    def test_in_process_main_dispatcher_and_legacy_agree_for_snapshot_mode(self):
        fixture = engine_scenarios.build('snapshots-all')
        result = engine_run.run_python(['--show-snapshots'], fixture)
        self.assertFalse(result.fallback)
        self.assertEqual(result, engine_run.run_legacy(['--show-snapshots'], fixture))

    def test_inherited_engine_override_does_not_force_dispatcher_to_legacy(self):
        fixture = engine_scenarios.build('fresh')
        with mock.patch.dict(os.environ, {'KDN_ENGINE': 'not-an-engine'}):
            result = engine_run.run_dispatcher(['--show-snapshots'], fixture)
        self.assertEqual(result.rc, 0, result.err)

    def test_busybox_session_really_uses_the_requested_shell_and_applets(self):
        if os.environ.get('TEST_BUSYBOX_APPLETS') != '1':
            return
        fixture = engine_scenarios.build('fresh')
        for applet in ('sh', 'awk', 'sed', 'grep', 'tr'):
            self.assertEqual((fixture.mock_bin / applet).resolve().name, 'busybox')

    def test_digest_gate_detects_an_accidental_write(self):
        # This intentional writer owns a separate root, never a shared scenario.
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            with mock.patch.dict(engine_scenarios._cache, {'mutation-probe': (fixture, engine_scenarios.digest(fixture))}):
                path = fixture.path('/mutation-probe')
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(AssertionError, 'read-only scenario mutated: mutation-probe'):
                    engine_scenarios.assert_unchanged()
                path.unlink()
                engine_scenarios.assert_unchanged()
        engine_scenarios.assert_unchanged()

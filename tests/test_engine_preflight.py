"""Requirements/core checks retain legacy ordering without activating native preflight."""
import unittest
from pathlib import Path
import shutil
import tempfile
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
import engine_shell
from kdn.engine import config, findings, preflight, system


class RequirementTests(unittest.TestCase):
    def test_stock_requirements_and_core(self):
        ctx = engine_run.make_context(engine_scenarios.build('fresh'), ['--preflight'])
        state = findings.State()
        preflight.check_requirements(ctx, state)
        preflight.detect_core(ctx, state)
        self.assertEqual((state.errors, state.findings, state.detected_core), (0, [], 'xray'))

    def test_missing_commands_match_real_preflight_and_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            for missing in (('ip',), ('jq',), ('xkeen',), ('ip', 'xkeen', 'jq')):
                farm = Path(tmp, '-'.join(missing))
                farm.mkdir()
                for command in (*preflight.REQUIRED_COMMANDS, 'xkeen', 'jq', 'sha256sum', 'cat', 'head', 'tail', 'python3', 'sh'):
                    if command not in missing:
                        target = shutil.which(command, path=fixture.env['PATH'])
                        if target:
                            (farm / command).symlink_to(target)
                ctx = engine_run.make_context(fixture, ['--preflight', '--core', 'xray'])
                ctx.environ = dict(ctx.environ, PATH=str(farm))
                state = findings.State()
                preflight.check_requirements(ctx, state)
                preflight.detect_core(ctx, state)
                expected = engine_run.run_legacy(['--preflight', '--core', 'xray'], fixture,
                              {'PATH': str(farm), 'TEST_BUSYBOX_APPLETS': '0'})
                with self.subTest(missing=missing):
                    self.assertEqual(state.errors, len(missing))
                    self.assertEqual(''.join(item.text for item in state.findings), expected.err.split('Preflight failed with', 1)[0])
                    self.assertEqual({item.stream for item in state.findings}, {'err'})

    def test_missing_init_unknown_core_and_mihomo_seam(self):
        for name in ('no-xkeen-init', 'unknown-core'):
            fixture = engine_scenarios.build(name)
            ctx = engine_run.make_context(fixture, ['--preflight'])
            state = findings.State()
            preflight.check_requirements(ctx, state)
            preflight.detect_core(ctx, state)
            expected = engine_run.run_legacy(['--preflight'], fixture)
            self.assertEqual(state.errors, 1)
            self.assertEqual(''.join(item.text for item in state.findings), expected.err.split('Preflight failed with', 1)[0])
        fixture = engine_scenarios.build('fresh')
        self.assertTrue(preflight.needs_legacy(engine_run.make_context(fixture, ['--preflight', '--core', 'mihomo'])))
        self.assertFalse(preflight.needs_legacy(engine_run.make_context(fixture, ['--preflight', '--standalone-zapret'])))
        with tempfile.TemporaryDirectory() as tmp:
            local = engine_fixture.make_root(tmp)
            local.set_init('name_client', 'mihomo')
            self.assertTrue(preflight.needs_legacy(engine_run.make_context(local, ['--preflight'])))

    def test_standalone_and_legacy_udp_do_not_require_optional_integrated_parts(self):
        ctx = engine_run.make_context(engine_scenarios.build('fresh'), ['--preflight', '--standalone-zapret', '--udp-strategy', 'legacy'])
        original = system.have
        with mock.patch.object(system, 'have', side_effect=lambda name, env: name not in ('xkeen', 'jq', 'sha256sum') and original(name, env)):
            state = findings.State()
            preflight.check_requirements(ctx, state)
            preflight.detect_core(ctx, state)
        self.assertEqual((state.errors, state.findings, state.detected_core), (0, [], 'standalone'))

    def test_blob_errors_match_the_original_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            ctx = engine_run.make_context(fixture, ['--preflight'])
            blob = Path(tmp, 'blob')
            for content in (None, b'wrong'):
                if content is not None:
                    blob.write_bytes(content)
                ctx.paths = ctx.paths.replace(source_discord_udp_blob=str(blob))
                state = findings.State()
                preflight.check_requirements(ctx, state)
                ref = engine_shell.run_function('verify_discord_udp_blob_source', defs=['have'],
                          variables={'SOURCE_DISCORD_UDP_BLOB': blob, 'UDP_STRATEGY': 'flowseal',
                                     'DISCORD_UDP_BLOB_SHA256': config.DISCORD_UDP_BLOB_SHA256}, env=fixture.env)
                self.assertEqual(state.errors, 1)
                self.assertEqual(''.join(item.text for item in state.findings), ref.stderr)
            state = findings.State()
            original = system.have
            with mock.patch.object(system, 'have', side_effect=lambda name, env: name != 'sha256sum' and original(name, env)):
                preflight.check_requirements(ctx, state)
            self.assertEqual(state.findings[0].text, 'ERROR: sha256sum is required to verify the Flowseal Discord UDP blob.\n')

    def test_https_requirement_outside_test_root_and_guard(self):
        ctx = engine_run.make_context(engine_scenarios.build('fresh'), ['--preflight'])
        ctx.paths = ctx.paths.replace(test_root='')
        original_have = system.have
        with mock.patch.object(system, 'is_router', return_value=True), mock.patch.object(system, 'package_present', return_value=True), \
             mock.patch.object(system, 'have', side_effect=lambda name, env: name == 'wget' or original_have(name, env)), \
             mock.patch.object(system, 'run', return_value=system.Completed(0, 'BusyBox wget')) as run:
            state = findings.State()
            preflight.check_requirements(ctx, state)
            run.assert_called_once()
        self.assertEqual(state.errors, 1)
        self.assertIn('HTTPS-capable wget', state.findings[0].text)
        with mock.patch.object(system, 'is_router', return_value=True), mock.patch.object(system, 'package_present', return_value=True), \
             mock.patch.object(system, 'have', side_effect=lambda name, env: name == 'wget' or original_have(name, env)), \
             mock.patch.object(system, 'run', return_value=system.Completed(0, 'GNU wget +https')):
            state = findings.State()
            preflight.check_requirements(ctx, state)
        self.assertEqual((state.errors, state.findings), (0, []))
        with mock.patch.object(system, 'is_router', return_value=False), mock.patch.object(system, 'package_present', return_value=False):
            state = findings.State()
            preflight.check_requirements(ctx, state)
        self.assertEqual(state.findings[0].text, 'ERROR: this does not look like a Keenetic Entware environment.\n')

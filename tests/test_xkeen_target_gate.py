"""P10.2/3: real version-only subprocesses; no router/network or version bypass."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from kdn.common import xkeen
from kdn.engine import cli, config, console, transaction, statusblocks
from target_fixture import version_executable


class TargetGateTests(unittest.TestCase):
    def test_detached_workers_refuse_before_job_files_or_network_probes(self):
        router = Path(cli.__file__).resolve().parents[2]
        for version in ('XKeen 2.0', 'unknown', 'XKeen 3.0'):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary = version_executable(root / 'bin/xkeen', version)
                env = dict(os.environ, KD_TEST_ROOT=folder, KD_ALLOW_TEST_ROOT='1',
                           PATH=str(binary.parent) + os.pathsep + os.defpath)
                before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
                for script, args in (
                    ('xkeen_diagnostics.py', ['--kind', 'health']),
                    ('zapret_autotune_job.py', ['--service', 'youtube']),
                ):
                    with self.subTest(version=version, script=script):
                        done = subprocess.run([sys.executable, str(router / script), *args,
                                               '--job-id', '0123456789abcdef'], env=env,
                                              capture_output=True, text=True, timeout=15)
                        self.assertEqual(done.returncode, 2, done.stderr)
                        self.assertIn('unsupported_xkeen', done.stdout)
                        self.assertEqual({p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}, before)

    def test_pure_version_matrix_no_inference(self):
        for value, expected in [('XKeen 2.1', '2.1'), ('XKeen 2.1.1 Stable', '2.1.1'),
                                ('XKeen 2.1.1 Beta (build)', '2.1.1-beta'), ('XKeen 2.1.1β', '2.1.1β'),
                                ('\x1b[31mXKeen v2.2\x1b[0m', '2.2'), ('XKeen 2.0', ''),
                                ('XKeen 2.0.9', ''), ('XKeen 3.0', ''), ('2.1', ''),
                                ('XKeen 2.1 / XKeen 2.0', ''), ('XKeen 2.1 / XKeen 2.2', ''),
                                ('init has pbr_strict=on', '')]:
            with self.subTest(value=value):
                self.assertEqual(xkeen.parse_version(value), expected)

    def test_real_bounded_probe_success_timeout_and_output_ceiling(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = version_executable(Path(folder) / 'xkeen')
            self.assertEqual(xkeen.require(binary), '2.1.1')
            version_executable(binary, 'XKeen 2.0')
            with self.assertRaises(xkeen.UnsupportedXKeen):
                xkeen.require(binary)
            version_executable(binary, 'XKeen 2.1\n' + 'x' * 5000)
            self.assertEqual(xkeen.probe(binary), '')
            binary.write_text('#!/bin/sh\nexec sleep 30\n')
            started = time.monotonic()
            self.assertEqual(xkeen.probe(binary, timeout=0.05), '')
            self.assertLess(time.monotonic() - started, 3)

    def test_every_operational_cli_mode_rejects_before_config_dispatch_or_lock(self):
        modes = (['--status'], ['--status', '--json'], ['--check-config'], ['--print-nfqws-profiles'],
                 ['--preflight'], ['--apply', '--yes-router'], ['--snapshot-baseline', '--yes-router'],
                 ['--rollback', '--yes-router'], ['--rollback-latest', '--yes-router'],
                 ['--rollback-snapshot', '/unread/snapshot', '--yes-router'],
                 ['--apply-import-profile', '/unread/profile', '--yes-router'],
                 ['--clear-imported-profile', 'youtube', '--yes-router'], ['--rollback-import', '--yes-router'])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = version_executable(root / 'bin/xkeen', 'XKeen 2.0')
            env = {'PATH': str(binary.parent) + os.pathsep + os.defpath,
                   'KD_TEST_ROOT': folder, 'KD_ALLOW_TEST_ROOT': '1'}
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            for args in modes:
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(args=args), mock.patch.object(cli.confvalues, 'read_text',
                        side_effect=AssertionError('old config read')), \
                        mock.patch.object(cli, '_run_mutation', side_effect=AssertionError('mutation dispatched')):
                    self.assertEqual(cli.main(args, env, out, err), 2)
                    if '--json' in args:
                        result = json.loads(out.getvalue())
                        self.assertFalse(result['supported'])
                        self.assertEqual(result['error_code'], 'unsupported_xkeen')
                        self.assertEqual(result['fields'], {})
                    else:
                        self.assertIn('XKeen 2.1+', err.getvalue())
            after = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(after, before)
            paths = config.EnginePaths.from_environ(env)
            self.assertFalse(Path(paths.lock_dir).exists())

    def test_offline_modes_do_not_probe_target_or_read_effective_config(self):
        for args in (['--help'], ['--print-plan']):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(args=args), mock.patch.object(xkeen, 'probe', side_effect=AssertionError('target probe')), \
                    mock.patch.object(cli.confvalues, 'read_text', side_effect=AssertionError('target config')):
                shell_help = mock.Mock()
                self.assertEqual(cli.main(args, {}, out, err, execve=shell_help), 0)
                if args == ['--help']:
                    shell_help.assert_called_once()  # only the small non-operational help path
                else:
                    self.assertTrue(out.getvalue())

    def test_direct_transaction_guard_has_no_test_root_version_bypass(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            binary = version_executable(Path(folder) / 'bin/xkeen', 'unknown')
            env = {'KD_TEST_ROOT': folder, 'KD_ALLOW_TEST_ROOT': '1', 'PATH': str(binary.parent)}
            paths = config.EnginePaths.from_environ(env)
            ctx = SimpleNamespace(paths=paths, environ=env, options=SimpleNamespace(confirmed=True),
                                  console=console.Console(io.StringIO(), io.StringIO()))
            operation = mock.Mock()
            with mock.patch.object(transaction.system, 'is_router', return_value=True):
                self.assertNotEqual(transaction.execute(ctx, operation), 0)
            operation.assert_not_called()
            self.assertFalse(Path(paths.lock_dir).exists())

    def test_status_block_unknown_never_infers_generation_from_init(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            binary = version_executable(Path(folder) / 'xkeen', 'unknown')
            ctx = SimpleNamespace(environ={'PATH': str(binary.parent)})
            with mock.patch.object(statusblocks.confvalues, 'read_text', side_effect=AssertionError('init read')):
                with self.assertRaises(xkeen.UnsupportedXKeen):
                    statusblocks.xkeen_block(ctx)


class PanelTargetGateTests(unittest.TestCase):
    def test_unsupported_admission_and_json_no_text_fallback(self):
        import panel_harness
        ns = panel_harness.load_panel('phase10-negative')
        engine = ns.module('kdn.web.infra.engine')
        cfg = ns.module('kdn.web.infra.config')
        version_executable(cfg.XKEEN, 'XKeen 2.0')
        with mock.patch.object(engine.proc, 'run_command', side_effect=AssertionError('old engine fallback')):
            payload = engine.read_status_fields()
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['error_code'], 'unsupported_xkeen')
        operations = ns.module('kdn.web.domain.operations')
        with mock.patch.object(operations, '_launch') as launch:
            with self.assertRaises(ValueError):
                operations.start_vpn_add_job('safe', 'vless://not-read')
        launch.assert_not_called()


"""Lock ownership, cancellation, redaction and native focused mutation guards."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.common import lock
from kdn.engine import cli, config, console, import_ops, options, profile_descriptor, snapshot_store, transaction


class NativeTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.environ = {'KD_TEST_ROOT': self.tmp.name, 'KD_ALLOW_TEST_ROOT': '1'}
        from target_fixture import version_executable
        executable = version_executable(Path(self.tmp.name) / 'bin/xkeen')
        self.environ['PATH'] = str(executable.parent) + os.pathsep + os.defpath
        from target_fixture import supported_environment
        supported_environment(self.environ)
        self.paths = config.EnginePaths.from_environ(self.environ)
        self.out, self.err = io.StringIO(), io.StringIO()
        self.ctx = SimpleNamespace(paths=self.paths, environ=self.environ,
                                   options=SimpleNamespace(confirmed=True), console=console.Console(self.out, self.err))

    def test_one_result_is_emitted_only_after_releasing_lock(self):
        events = []
        original = self.ctx.console.out
        def emit(line):
            if line.startswith('RESULT|'):
                events.append(Path(self.paths.lock_dir).exists())
            original(line)
        with mock.patch.object(console.Console, 'out', side_effect=emit):
            def operation(tx):
                self.assertTrue(Path(self.paths.lock_dir).is_dir())
                self.assertEqual((Path(self.paths.lock_dir) / 'pid').read_text().strip(), str(os.getpid()))
                tx.stage('verify')
            self.assertEqual(transaction.execute(self.ctx, operation), 0)
        self.assertEqual(events, [False])
        self.assertEqual(self.out.getvalue().count('RESULT|'), 1)

    def test_lockbusy_does_not_enter_operation_or_release_foreign_lock(self):
        operation = mock.Mock()
        with lock.ProjectLock(self.paths.lock_dir):
            before = (Path(self.paths.lock_dir) / 'pid').read_bytes()
            self.assertEqual(transaction.execute(self.ctx, operation), 1)
            self.assertEqual((Path(self.paths.lock_dir) / 'pid').read_bytes(), before)
        operation.assert_not_called()
        self.assertEqual(self.out.getvalue().count('RESULT|failed'), 1)

    def test_signal_rolls_back_while_lock_held_and_preserves_exit130(self):
        events = []
        def operation(tx):
            tx.arm(lambda: events.append(Path(self.paths.lock_dir).is_dir()))
            raise SystemExit(130)
        self.assertEqual(transaction.execute(self.ctx, operation), 130)
        self.assertEqual(events, [True])
        self.assertIn('STAGE|restore', self.out.getvalue())
        self.assertEqual(self.out.getvalue().count('RESULT|rolled-back'), 1)
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_partial_rollback_and_opaque_exception_redaction(self):
        def operation(tx):
            tx.arm(mock.Mock(side_effect=RuntimeError('rollback-private-secret')))
            raise OSError('private-config-contents')
        self.assertEqual(transaction.execute(self.ctx, operation), 1)
        self.assertIn('RESULT|partial', self.out.getvalue())
        self.assertIn('CRITICAL:', self.err.getvalue())
        self.assertNotIn('private-', self.err.getvalue())
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_confirmation_path_identity_and_root_guards_precede_lock(self):
        self.ctx.options.confirmed = False
        operation = mock.Mock()
        self.assertEqual(transaction.execute(self.ctx, operation), 1)
        self.assertFalse(Path(self.paths.lock_dir).exists())
        self.ctx.options.confirmed = True
        self.ctx.paths = self.paths.replace(nfqws_conf='/different/config')
        self.assertEqual(transaction.execute(self.ctx, operation), 1)
        operation.assert_not_called()
        self.ctx.paths = config.EnginePaths.from_environ({})
        self.ctx.environ = {}
        with mock.patch.object(transaction.system, 'is_router', return_value=True), \
                mock.patch.object(transaction.os, 'geteuid', return_value=1001), self.assertRaises(ValueError):
            transaction.guard(self.ctx)

    def test_live_20_and_unknown_versions_refused_before_mutation(self):
        self.ctx.paths = config.EnginePaths.from_environ({})
        self.ctx.environ = {}
        with mock.patch.object(transaction.system, 'is_router', return_value=True), \
                mock.patch.object(transaction.os, 'geteuid', return_value=0), \
                mock.patch.object(transaction.confvalues, 'init_value', return_value='xray'):
            for text in ('XKeen 2.0', 'unknown', 'XKeen 3.0'):
                with self.subTest(version=text), mock.patch.object(transaction.xkeen, 'probe', return_value=''):
                    with self.assertRaisesRegex(ValueError, '2.1'):
                        transaction.guard(self.ctx)
            with mock.patch.object(transaction.xkeen, 'probe', return_value='2.1'):
                transaction.guard(self.ctx)
        self.ctx.environ = {'KD_TEST_ROOT': '/', 'KD_ALLOW_TEST_ROOT': '1'}
        self.ctx.paths = config.EnginePaths.from_environ(self.ctx.environ)
        with self.assertRaises(ValueError):
            transaction.guard(self.ctx)


class ImportOperationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, 'KD_TEST_ROOT': str(self.root), 'KD_ALLOW_TEST_ROOT': '1'}
        from target_fixture import supported_environment
        supported_environment(self.env)
        self.paths = config.EnginePaths.from_environ(self.env)
        self.base = Path(self.paths.nfqws_conf).parent
        fixture = Path(__file__).parent / 'fixtures/engine/nfqws-neutral'
        shutil.copytree(fixture, self.base)
        self.initial = Path(self.paths.nfqws_conf).read_bytes()
        self.out, self.err = io.StringIO(), io.StringIO()
        self.staging = self.root / 'opt/tmp/input.json'
        self.staging.parent.mkdir(parents=True)
        self.profile = {'format': 1, 'service': 'discord-tcp', 'source_name': 'test.bat', 'source_sha': '',
                        'source_url': '', 'family': 'test', 'rank': 1, 'notes': [], 'report': {},
                        'args': ['--filter-tcp=443', '--filter-l7=tls',
                                 '--hostlist=/opt/etc/nfqws2/lists/user.list',
                                 '--payload=tls_client_hello', '--lua-desync=fake:blob=fake_default_tls']}
        self.profile['candidate_id'] = profile_descriptor.candidate_id(self.profile)
        self.staging.write_text(json.dumps(self.profile))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.pid = self.stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'pid', return_value=77))
        self.checked = self.stack.enter_context(mock.patch.object(import_ops.nfqws_validate, 'validate_config'))
        self.restarted = self.stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'restart'))
        self.stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'action'))
        self.restored = self.stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'restore_state'))

    def context(self, argv=None):
        argv = argv or ['--apply-import-profile', str(self.staging), '--yes-router']
        parsed = options.parse_args(argv)
        return cli.Context(argv, self.env, console.Console(self.out, self.err), paths=self.paths,
                           options=parsed, resolved=options.resolve(parsed, self.initial.decode()))

    def test_corrupt_descriptor_symlink_and_traversal_never_reach_validation(self):
        self.staging.write_bytes(b'{invalid')
        self.assertEqual(import_ops.run(self.context()), 1)
        self.staging.unlink()
        real = self.staging.parent / 'real.json'
        real.write_text(json.dumps(self.profile))
        self.staging.symlink_to(real)
        self.assertEqual(import_ops.run(self.context()), 1)
        self.staging.unlink()
        self.staging.write_text(json.dumps(self.profile))
        traversal = str(self.staging.parent / 'unused/../input.json')
        self.assertEqual(import_ops.run(self.context(['--apply-import-profile', traversal, '--yes-router'])), 1)
        self.checked.assert_not_called()
        self.restarted.assert_not_called()
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)

    def test_stopped_service_and_non_zapret_route_rejected_before_snapshot(self):
        self.pid.return_value = None
        self.assertEqual(import_ops.run(self.context()), 1)
        self.pid.return_value = 77
        path = Path(self.paths.nfqws_conf)
        path.write_bytes(self.initial.replace(b'Discord TCP=zapret', b'Discord TCP=vless'))
        # Explicit state seam avoids depending on one historical header spelling.
        state = (path.read_bytes(), ('vless', 'zapret', 'zapret', 'unmanaged'), 'flowseal', False, {})
        with mock.patch.object(import_ops, '_context', return_value=state):
            self.assertEqual(import_ops.run(self.context()), 1)
        self.checked.assert_not_called()
        self.assertFalse((Path(self.paths.state_root) / 'nfqws-import-snapshots').exists())

    def test_validation_order_and_cancel_after_mutation_restore_original(self):
        calls = []
        self.checked.side_effect = lambda _ctx, path: calls.append(('validate', Path(path).read_bytes()))
        original_capture = import_ops._capture
        def capture(tx, purpose, receipt=None):
            calls.append(('snapshot', Path(self.paths.nfqws_conf).read_bytes()))
            return original_capture(tx, purpose, receipt)
        self.restarted.side_effect = SystemExit(130)
        with mock.patch.object(import_ops, '_capture', side_effect=capture):
            self.assertEqual(import_ops.run(self.context()), 130)
        self.assertEqual([name for name, _value in calls[:3]], ['validate', 'snapshot', 'validate'])
        self.assertEqual(calls[1][1], self.initial)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
        self.restored.assert_called_once()
        self.assertIn('RESULT|rolled-back', self.out.getvalue())

    def test_clear_missing_is_noop_and_archive_is_private_and_collision_safe(self):
        target = self.base / 'imported-profiles/discord-tcp.json'
        if target.exists():
            target.unlink()
        self.assertEqual(import_ops.run(self.context(['--clear-imported-profile', 'discord-tcp', '--yes-router'])), 0)
        self.checked.assert_not_called()
        self.restarted.assert_not_called()
        with mock.patch.object(import_ops.time, 'strftime', return_value='20260101T000000Z'):
            import_ops._archive(self.context(), import_ops._archive_plan(self.context(), self.profile, 'applied'))
            import_ops._archive(self.context(), import_ops._archive_plan(self.context(), self.profile, 'applied'))
        versions = list((self.base / 'profile-versions/discord-tcp').glob('*.json'))
        self.assertEqual(len(versions), 2)
        for version in versions:
            self.assertEqual(version.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(version.read_text())['candidate_id'], self.profile['candidate_id'])

    def test_invalid_rollback_pointer_and_service_fail_before_snapshot(self):
        pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text(str(self.root / 'outside-snapshot') + '\n')
        self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 1)
        self.assertFalse((Path(self.paths.state_root) / 'nfqws-import-snapshots').exists())
        self.restarted.assert_not_called()
        ctx = self.context(['--clear-imported-profile', 'discord-tcp', '--yes-router'])
        ctx.options.clear_profile = 'unsupported'
        with self.assertRaises(ValueError):
            import_ops.operation(transaction.Transaction(ctx))

    def test_legacy_header_fallback_and_telegram_normalization(self):
        with mock.patch.object(import_ops.confvalues, 'recorded_telegram_route', return_value='zapret'):
            self.assertEqual(import_ops._context(self.context())[1][-1], 'direct')
        target = Path(self.paths.state_root) / 'nfqws-import-snapshots/old'
        (target / 'nfqws2').mkdir(parents=True)
        (target / 'nfqws2/nfqws2.conf').write_bytes(self.initial)
        pointer = target.parent.parent / 'latest-nfqws-import.ptr'
        pointer.write_text(str(target) + '\n')
        metadata = SimpleNamespace(rows=(), value=lambda key: '2.1' if key == 'XKEEN_VERSION' else '')
        with mock.patch.object(import_ops.snapshot_store, 'verify', return_value=SimpleNamespace(metadata=metadata)), \
                mock.patch.object(import_ops, '_capture', return_value=target), \
                mock.patch.object(import_ops, '_restore') as restore, \
                mock.patch.object(import_ops.snapshot_store, 'publish_pointer'):
            self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 0)
            restore.assert_called_once_with(mock.ANY, target)

    def voice_profile(self):
        profile = {**self.profile, 'service': 'discord-voice', 'args': [
            '--filter-udp=50000-65535', '--filter-l7=stun,discord',
            '--payload=stun,discord_ip_discovery', '--lua-desync=fake:blob=discord_udp:repeats=2']}
        profile['candidate_id'] = profile_descriptor.candidate_id(profile)
        return profile

    def test_wide_voice_narrow_range_hint_is_only_for_valid_wide_schema(self):
        self.staging.write_text(json.dumps(self.voice_profile()))
        self.assertEqual(import_ops._profile(self.staging)['service'], 'discord-voice')
        with self.assertRaisesRegex(ValueError, '--wide-udp.*--clear-imported-profile'):
            import_ops._profile(self.staging, high=50100)
        for invalid in ([1], {**self.voice_profile(), 'candidate_id': 'invalid'},
                        {**self.profile, 'candidate_id': 'invalid'}):
            self.staging.write_text(json.dumps(invalid))
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as failure:
                import_ops._profile(self.staging, high=50100)
            self.assertNotIn('--wide-udp', str(failure.exception))

    def test_clear_wide_voice_profile_remains_possible_under_narrow_mode(self):
        target = self.base / 'imported-profiles/discord-voice.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.voice_profile()))
        self.assertEqual(import_ops.run(self.context(['--clear-imported-profile', 'discord-voice', '--yes-router'])), 0,
                         self.err.getvalue())
        self.assertFalse(target.exists())
        self.assertTrue(list((self.base / 'profile-versions/discord-voice').glob('*.json')))

    def test_absent_old_focused_config_does_not_run_strict_validation(self):
        shutil.rmtree(self.base)
        saved = snapshot_store.create(self.paths, purpose='absent-test', focused=True,
                                      xkeen_version='2.1', metadata=(('NFQWS_RUNNING', '0'),))
        self.base.mkdir(parents=True)
        Path(self.paths.nfqws_conf).write_bytes(self.initial)
        with mock.patch.object(import_ops.snapshot_store, 'restore_files', wraps=snapshot_store.restore_files) as restored_files:
            import_ops._restore(self.context(), saved)
        self.checked.assert_not_called()
        restored_files.assert_called_once()
        self.restored.assert_called_once_with(mock.ANY, '0')
        self.assertFalse(Path(self.paths.nfqws_conf).exists())

    def test_existing_retention_protects_current_pointer_and_newest_only(self):
        for name, result in (('expire_history', (0, 0)), ('expire_versions', 0)):
            patcher = mock.patch.object(import_ops.record_retention, name, return_value=result)
            patcher.start()
            self.addCleanup(patcher.stop)
        folder = Path(self.paths.state_root) / 'nfqws-import-snapshots'
        folder.mkdir(parents=True)
        entries = [folder / ('20260101-000000-' + str(number)) for number in range(1, 5)]
        for entry in entries:
            entry.mkdir()
            (entry / 'test-sentinel').write_text('disposable')
            (entry / 'STATE.tsv').write_text('FORMAT\t1\nNFQWS_PRESENT\t0\nCREATED_UTC\t2026-01-01T00:00:00Z\n')
        unrelated = folder / 'user-manual-copy'
        unrelated.mkdir()
        pointer = import_ops._pointer(self.context())
        pointer.write_text(str(entries[1]) + '\n')
        self.env['KD_IMPORT_SNAPSHOT_KEEP'] = '1'
        with mock.patch.object(import_ops.snapshot_store, 'verify') as verify:
            import_ops._prune(self.context(), entries[0])
        self.assertEqual(verify.call_args_list, [mock.call(entries[3], focused=True), mock.call(entries[2], focused=True)])
        self.assertFalse(entries[2].exists())
        self.assertTrue(all(entry.exists() for entry in (entries[0], entries[1], entries[3], unrelated)))
        pointer.write_text(str(self.root / 'outside-snapshot') + '\n')
        self.env['KD_IMPORT_SNAPSHOT_KEEP'] = 'invalid'
        with mock.patch.object(import_ops.snapshot_store, 'verify') as verify:
            with self.assertRaises(ValueError):
                import_ops._prune(self.context(), entries[0])
            verify.assert_not_called()
        pointer.unlink()
        with mock.patch.object(import_ops.snapshot_store, 'verify') as verify:
            import_ops._prune(self.context(), entries[0])
            self.assertEqual(verify.call_args_list, [mock.call(entries[3], focused=True), mock.call(entries[1], focused=True)])
        self.assertFalse(entries[1].exists())

    def test_retention_failure_warns_without_changing_working_config(self):
        with mock.patch.object(import_ops, '_prune', side_effect=ValueError('corrupt-snapshot')):
            import_ops._prune_after_success(self.context(), self.root / 'unused')
        self.assertIn('WARNING:', self.err.getvalue())
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)

    def test_rollback_import_failure_restores_preoperation_pointer(self):
        self.assertEqual(import_ops.run(self.context()), 0)
        pointer = import_ops._pointer(self.context())
        before = pointer.read_bytes()
        config_before = Path(self.paths.nfqws_conf).read_bytes()
        with mock.patch.object(import_ops.snapshot_store, 'publish_pointer', side_effect=RuntimeError('injected publish failure')):
            self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 1)
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), config_before)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())

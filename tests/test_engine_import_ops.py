"""Native focused operations on disposable roots with explicit service seams."""
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from kdn.engine import cli, config, console, import_ops, options, profile_descriptor, snapshot_store


class ImportOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.environ)
        self.paths = config.EnginePaths.from_environ(self.environ)
        source = Path(__file__).parent / 'fixtures/engine/nfqws-neutral'
        shutil.copytree(source, Path(self.paths.nfqws_conf).parent)
        self.out, self.err = io.StringIO(), io.StringIO()
        self.args = ['--apply-import-profile', str(self.root / 'opt/tmp/import.json'), '--yes-router']
        self.profile = {
            'format': 1, 'service': 'discord-tcp', 'source_name': 'fixture.bat', 'source_sha': '',
            'source_url': '', 'family': 'fixture', 'rank': 1, 'notes': [], 'report': {},
            'args': ['--filter-tcp=443', '--filter-l7=tls', '--hostlist=/opt/etc/nfqws2/lists/user.list',
                     '--payload=tls_client_hello', '--lua-desync=fake:blob=fake_default_tls'],
        }
        self.profile['candidate_id'] = profile_descriptor.candidate_id(self.profile)
        staging = Path(self.args[1])
        staging.parent.mkdir(parents=True)
        staging.write_text(json.dumps(self.profile), encoding='utf-8')
        self.initial = Path(self.paths.nfqws_conf).read_bytes()

    def context(self, argv=None):
        argv = self.args if argv is None else argv
        parsed = options.parse_args(argv)
        return cli.Context(argv, self.environ, console.Console(self.out, self.err), paths=self.paths,
                           options=parsed, resolved=options.resolve(parsed, self.initial.decode()))

    def seams(self):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'pid', return_value=123))
        self.validate = stack.enter_context(mock.patch.object(import_ops.nfqws_validate, 'validate_config'))
        self.restart = stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'restart'))
        stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'action'))
        self.restore_state = stack.enter_context(mock.patch.object(import_ops.nfqws_service, 'restore_state'))
        return stack

    def test_apply_clear_and_rollback_preserve_external_components(self):
        unrelated = self.root / 'opt/etc/xray/configs/04_outbounds.json'
        unrelated.parent.mkdir(parents=True)
        unrelated.write_bytes(b'active-vpn-must-stay')
        with self.seams():
            self.assertEqual(import_ops.run(self.context()), 0, self.err.getvalue())
            imported = Path(self.paths.nfqws_conf).parent / 'imported-profiles/discord-tcp.json'
            self.assertEqual(json.loads(imported.read_text())['candidate_id'], self.profile['candidate_id'])
            pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
            self.assertTrue(pointer.exists())
            self.assertEqual(import_ops.run(self.context(['--clear-imported-profile', 'discord-tcp', '--yes-router'])), 0)
            self.assertFalse(imported.exists())
            self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 0, self.err.getvalue())
            self.assertTrue(imported.exists())
            self.assertEqual(unrelated.read_bytes(), b'active-vpn-must-stay')
            self.assertEqual(self.out.getvalue().count('RESULT|ok'), 3)
            self.assertEqual(self.restart.call_count, 2)
            self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_failed_restart_restores_config_and_pointer(self):
        pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
        pointer.parent.mkdir(parents=True)
        pointer.write_bytes(b'old-pointer\n')
        with self.seams():
            self.restart.side_effect = RuntimeError('injected failed restart')
            self.assertEqual(import_ops.run(self.context()), 1)
            self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
            self.assertEqual(pointer.read_bytes(), b'old-pointer\n')
            self.assertIn('RESULT|rolled-back', self.out.getvalue())
            self.restore_state.assert_called_once()

    def test_prevalidation_failure_does_not_create_snapshot(self):
        with self.seams():
            self.validate.side_effect = ValueError('injected strict check failure')
            self.assertEqual(import_ops.run(self.context()), 1)
            self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
            self.assertFalse((Path(self.paths.state_root) / 'nfqws-import-snapshots').exists())
            self.restart.assert_not_called()
            self.assertIn('RESULT|failed', self.out.getvalue())

    def test_confirmation_and_staging_boundary_precede_effective_writes(self):
        with self.seams():
            self.assertEqual(import_ops.run(self.context(self.args[:-1])), 1)
            outside = self.root / 'outside.json'
            outside.write_text(json.dumps(self.profile))
            self.assertEqual(import_ops.run(self.context(['--apply-import-profile', str(outside), '--yes-router'])), 1)
            self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
            self.restart.assert_not_called()

    def test_routes_mismatch_refuses_focused_rollback_before_rescue(self):
        with self.seams():
            self.assertEqual(import_ops.run(self.context()), 0)
            pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
            saved_pointer = pointer.read_bytes()
            path = Path(self.paths.nfqws_conf)
            path.write_bytes(path.read_bytes().replace(b'YouTube=zapret', b'YouTube=direct'))
            # If fixture uses a different spelling, change the deployment line
            # which is also part of the legacy focused compatibility header.
            path.write_bytes(path.read_bytes().replace(b'# Deployment mode: xkeen-integrated.',
                                                       b'# Deployment mode: standalone-zapret.'))
            previous = path.read_bytes()
            self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 1)
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(pointer.read_bytes(), saved_pointer)

    def test_snapshot_corruption_is_refused(self):
        with self.seams():
            self.assertEqual(import_ops.run(self.context()), 0)
            pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
            saved = Path(pointer.read_text().strip())
            (saved / 'nfqws2/nfqws2.conf').write_bytes(b'corrupted')
            with self.assertRaises(ValueError):
                snapshot_store.verify(saved, focused=True)
            previous = Path(self.paths.nfqws_conf).read_bytes()
            self.assertEqual(import_ops.run(self.context(['--rollback-import', '--yes-router'])), 1)
            self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), previous)

    def test_invalid_split_descriptor_is_rejected_before_validation_snapshot_and_restart(self):
        from panel_fixtures import VALID_ARGS
        self.profile['service'] = 'youtube'
        self.profile['args'] = ['--new', *[token for token in VALID_ARGS['youtube'] if token != '--new']]
        self.profile['candidate_id'] = profile_descriptor.candidate_id(self.profile)
        Path(self.args[1]).write_text(json.dumps(self.profile), encoding='utf-8')
        with self.seams():
            self.assertEqual(import_ops.run(self.context()), 1)
            self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
            self.assertFalse((Path(self.paths.state_root) / 'nfqws-import-snapshots').exists())
            self.assertFalse((Path(self.paths.nfqws_conf).parent / 'imported-profiles').exists())
            self.validate.assert_not_called()
            self.restart.assert_not_called()

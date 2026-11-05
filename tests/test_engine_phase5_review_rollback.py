"""Regression tests for independent phase5 rollback/version-provenance review."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import config, console, relay_restore, rollback_ops as rollback, snapshot_policy, snapshot_store


class VersionProvenanceReviewTests(unittest.TestCase):
    def test_actual_supported_version_is_authoritative_over_supported_cached_package(self):
        for actual in ('2.1.1β', '2.1.1-beta.1', '2.2'):
            with self.subTest(actual=actual):
                queried = []

                def run(ctx, argv, actual=actual, queried=queried, **kwargs):
                    queried.append(argv)
                    output = ('Package: xkeen\nStatus: install user installed\nVersion: 2.1\n'
                              if argv[0] == 'opkg' else 'XKeen ' + actual + '\n')
                    return SimpleNamespace(output=output, returncode=0, timed_out=False, output_limited=False)

                with mock.patch.object(rollback, '_run', side_effect=run), \
                        mock.patch.object(rollback.xkeen, 'probe', return_value=actual):
                    version = rollback.xkeen_version(SimpleNamespace(environ={}))
                self.assertEqual(version, actual)
                self.assertFalse(snapshot_policy.versions_compatible(version, '2.1'))
                self.assertEqual(queried, [['opkg', 'status', 'xkeen']])

    def test_unsupported_failed_ambiguous_actual_version_never_falls_back_to_package(self):
        for output, code in (('XKeen 2.0\n', 0), ('XKeen 2.1\nXKeen 2.2\n', 0),
                             ('unlabelled 2.1', 0), ('XKeen 2.1', 1)):
            with self.subTest(output=output, code=code):
                with mock.patch.object(rollback, 'package_version', return_value='2.1'):
                    done = SimpleNamespace(output=output, returncode=code, timed_out=False, output_limited=False)
                    with mock.patch.object(rollback, '_run', return_value=done), \
                            mock.patch.object(rollback.xkeen, 'probe', return_value=''):
                        with self.assertRaises(ValueError):
                            rollback.xkeen_version(SimpleNamespace(environ={}))

    def test_strict_package_query_error_is_not_ignored_for_actual_version(self):
        with mock.patch.object(rollback, 'package_version', side_effect=RuntimeError('package query failed')):
            with mock.patch.object(rollback, '_run') as actual, \
                    mock.patch.object(rollback.xkeen, 'probe', return_value='2.1'):
                with self.assertRaises(RuntimeError):
                    rollback.xkeen_version(SimpleNamespace(environ={}))
        actual.assert_not_called()

    def test_current_script_version_change_preserves_privileged_init(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': temporary, 'KD_ALLOW_TEST_ROOT': '1'})
            init = Path(paths.xkeen_init)
            init.parent.mkdir(parents=True)
            init.write_bytes(b'2.1.1 prerelease init')
            with mock.patch.object(rollback, 'package_version', return_value='2.1'):
                done = SimpleNamespace(output='XKeen 2.1.1-beta.1', returncode=0, timed_out=False, output_limited=False)
                with mock.patch.object(rollback, '_run', return_value=done), \
                        mock.patch.object(rollback.xkeen, 'probe', return_value='2.1.1-beta.1'):
                    version = rollback.xkeen_version(SimpleNamespace(environ={}))
            snapshot = snapshot_store.create(paths, purpose='actual-version', xkeen_version=version)
            init.write_bytes(b'current 2.1 init')
            with self.assertRaises(ValueError):
                snapshot_store.restore_files(paths, snapshot, current_xkeen_version='2.1')
            self.assertEqual(init.read_bytes(), b'current 2.1 init')


class RelayRescueReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.directory), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.environ)
        self.paths = config.EnginePaths.from_environ(self.environ)
        Path(self.paths.lock_dir).parent.mkdir(parents=True)
        self.out, self.err = io.StringIO(), io.StringIO()
        self.ctx = SimpleNamespace(paths=self.paths, environ=self.environ,
            options=SimpleNamespace(mode='rollback-baseline', confirmed=True),
            resolved=SimpleNamespace(standalone=False), console=console.Console(self.out, self.err))
        self.conf = Path(self.paths.nfqws_conf)
        self.conf.parent.mkdir(parents=True)
        self.conf.write_bytes(b'# Deployment mode: xkeen-integrated.\n'
            b'# Active routes: DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Telegram=direct.\n')
        auxiliary = {'PACKAGES.tsv': b''.join((name + '\tABSENT\t-\n').encode() for name in rollback.PACKAGES),
                     'RUNTIME.tsv': b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\n'}
        self.target = snapshot_store.create(self.paths, purpose='target', xkeen_version='2.1', auxiliary=auxiliary)
        snapshot_store.publish_pointer(self.paths, self.paths.baseline_pointer, self.target, baseline=True)
        self.conf.write_bytes(self.conf.read_bytes().replace(b'Telegram=direct.', b'Telegram=ws.'))
        self.initial_conf = self.conf.read_bytes()

    def exercise(self, *, init_present, initially_running=False):
        init = Path(config.list_path(relay_restore.INIT, self.paths.test_root))
        flag = self.directory / 'relay-running'
        self.environ['RELAY_REVIEW_FLAG'] = str(flag)
        data = (b'#!/bin/sh\n# Telegram WS relay of keenetic-discord-nfqws2\n'
                b'case "$1" in\nstop) rm -f "$RELAY_REVIEW_FLAG" ;;\n'
                b'status) test -f "$RELAY_REVIEW_FLAG" ;;\n'
                b'start|restart) : > "$RELAY_REVIEW_FLAG" ;;\n*) exit 2 ;;\nesac\n')
        if init_present:
            init.parent.mkdir(parents=True, exist_ok=True)
            init.write_bytes(data)
            init.chmod(0o700)
        if initially_running:
            flag.touch()
        pointer = Path(self.paths.baseline_pointer).read_bytes()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback.transaction, 'guard'))
            stack.enter_context(mock.patch.object(rollback, 'package_version', return_value=''))
            stack.enter_context(mock.patch.object(rollback, 'xkeen_version', return_value='2.1'))
            stack.enter_context(mock.patch.object(rollback, '_run', return_value=SimpleNamespace(
                output='', returncode=0, timed_out=False, output_limited=False)))
            stack.enter_context(mock.patch.object(rollback.xkeen_service, 'pid', return_value=None))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'pid', return_value=None))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'action'))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'restore_state'))
            stack.enter_context(mock.patch.object(rollback, '_xkeen_state'))
            stack.enter_context(mock.patch.object(relay_restore, 'preflight'))
            reconcile = stack.enter_context(mock.patch.object(relay_restore, 'reconcile',
                side_effect=RuntimeError('listen port busy; no transient relay may start during rescue')))
            stack.enter_context(mock.patch.object(rollback, '_packages',
                side_effect=[RuntimeError('initial restore injected failure'), None]))
            self.assertEqual(rollback.run(self.ctx), 1, self.err.getvalue())
        reconcile.assert_not_called()
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertNotIn('RESULT|partial', self.out.getvalue())
        self.assertEqual(self.conf.read_bytes(), self.initial_conf)
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), pointer)
        self.assertEqual(flag.exists(), initially_running)
        if init_present:
            self.assertEqual(init.read_bytes(), data)
            self.assertEqual(init.stat().st_mode & 0o777, 0o700)
        else:
            self.assertFalse(init.exists())

    def test_saved_stopped_ws_relay_does_not_start_transiently_on_rescue(self):
        self.exercise(init_present=True)

    def test_saved_absent_ws_relay_does_not_start_transiently_on_rescue(self):
        self.exercise(init_present=False)

    def test_saved_running_relay_is_restored_once_using_original_owned_init(self):
        self.exercise(init_present=True, initially_running=True)

    def exercise_standalone(self, failure=False):
        auxiliary = {'PACKAGES.tsv': b''.join((name + '\tABSENT\t-\n').encode() for name in rollback.PACKAGES),
                     'RUNTIME.tsv': b'XKEEN_RUNNING\tUNMANAGED\nNFQWS_RUNNING\t0\n'}
        target = snapshot_store.create(self.paths, purpose='standalone', scope='standalone', xkeen_version='2.1', auxiliary=auxiliary)
        snapshot_store.publish_pointer(self.paths, self.paths.baseline_pointer, target)
        target_conf = self.conf.read_bytes()
        self.conf.write_bytes(b'current standalone config')
        current = self.conf.read_bytes()
        init = Path(config.list_path(relay_restore.INIT, self.paths.test_root))
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_bytes(b'#!/bin/sh\n# unrelated WS service; standalone must ignore\n')
        unrelated = init.read_bytes()
        self.ctx.resolved.standalone = True
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback.transaction, 'guard'))
            stack.enter_context(mock.patch.object(rollback, 'package_version', return_value=''))
            version = stack.enter_context(mock.patch.object(rollback, 'xkeen_version',
                return_value='2.1'))
            stack.enter_context(mock.patch.object(rollback, '_run', return_value=SimpleNamespace(
                output='', returncode=0, timed_out=False, output_limited=False)))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'pid', return_value=None))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'action'))
            stack.enter_context(mock.patch.object(rollback.nfqws_service, 'restore_state'))
            xkeen = stack.enter_context(mock.patch.object(rollback, '_xkeen_state',
                side_effect=AssertionError('standalone changed XKeen')))
            relay_calls = [stack.enter_context(mock.patch.object(relay_restore, name,
                side_effect=AssertionError('standalone touched WS relay')))
                for name in ('preflight', 'capture', 'reconcile', 'restore_init', 'restore_saved')]
            stack.enter_context(mock.patch.object(rollback, '_packages',
                side_effect=[RuntimeError('injected failure'), None] if failure else None))
            self.assertEqual(rollback.run(self.ctx), 1 if failure else 0, self.err.getvalue())
        version.assert_called()
        xkeen.assert_not_called()
        for call in relay_calls:
            call.assert_not_called()
        self.assertEqual(init.read_bytes(), unrelated)
        self.assertEqual(self.conf.read_bytes(), current if failure else target_conf)
        self.assertIn('RESULT|rolled-back' if failure else 'RESULT|ok', self.out.getvalue())

    def test_pure_standalone_restore_keeps_xkeen_and_relay_outside_scope(self):
        self.exercise_standalone()

    def test_pure_standalone_rescue_keeps_xkeen_and_relay_outside_scope(self):
        self.exercise_standalone(failure=True)

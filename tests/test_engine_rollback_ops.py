"""Full snapshot transaction with real disposable data and mocked services/packages."""
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import cli, config, console, options, rollback_ops as rollback, snapshot_store
from kdn.engine import nfqws_process


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.directory), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.environ)
        self.paths = config.EnginePaths.from_environ(self.environ)
        self.out, self.err = io.StringIO(), io.StringIO()
        source = Path(__file__).parent / 'fixtures/engine/nfqws-neutral'
        shutil.copytree(source, Path(self.paths.nfqws_conf).parent)
        self.initial = Path(self.paths.nfqws_conf).read_bytes()
        self.stack = __import__('contextlib').ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(rollback, 'package_version', return_value=''))
        self.stack.enter_context(mock.patch.object(rollback.xkeen_service, 'pid', return_value=None))
        self.stack.enter_context(mock.patch.object(rollback.nfqws_service, 'pid', return_value=None))
        self.stack.enter_context(mock.patch.object(rollback.nfqws_service, 'action'))
        self.stack.enter_context(mock.patch.object(rollback.nfqws_service, 'restore_state'))

    def context(self, *argv, standalone=True):
        argv = [*(['--without-xkeen'] if standalone else []), *argv, '--yes-router']
        parsed = options.parse_args(argv)
        return cli.Context(argv, self.environ, console.Console(self.out, self.err), paths=self.paths,
                           options=parsed, resolved=options.resolve(parsed, self.initial.decode()))

    def baseline(self, standalone=True):
        self.assertEqual(rollback.run(self.context('--snapshot-baseline', standalone=standalone)), 0, self.err.getvalue())
        return Path(Path(self.paths.baseline_pointer).read_text().strip())

    def test_baseline_immutable_and_full_restore(self):
        baseline = self.baseline()
        original_pointer = Path(self.paths.baseline_pointer).read_bytes()
        Path(self.paths.nfqws_conf).write_bytes(b'changed config')
        self.assertEqual(rollback.run(self.context('--snapshot-baseline')), 0)
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), original_pointer)
        self.assertEqual(rollback.run(self.context('--rollback')), 0, self.err.getvalue())
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
        self.assertTrue(baseline.exists())
        self.assertEqual(self.out.getvalue().count('RESULT|ok'), 3)
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_latest_and_selected_are_bounded_to_snapshot_store(self):
        target = self.baseline()
        snapshot_store.publish_pointer(self.paths, self.paths.latest_pointer, target)
        self.assertEqual(rollback.run(self.context('--rollback-latest')), 0)
        self.assertEqual(rollback.run(self.context('--rollback-snapshot', str(target))), 0)
        self.assertEqual(rollback.run(self.context('--rollback-snapshot', '/tmp/unowned')), 1)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)

    def test_invalid_auxiliary_refused_before_rescue_or_service_change(self):
        target = self.baseline()
        (target / 'RUNTIME.tsv').write_bytes(b'XKEEN_RUNNING\t9\nNFQWS_RUNNING\t0\n')
        count = len(list(Path(self.paths.snapshot_root).iterdir()))
        self.assertEqual(rollback.run(self.context('--rollback')), 1)
        self.assertEqual(len(list(Path(self.paths.snapshot_root).iterdir())), count)
        rollback.nfqws_service.action.assert_not_called()

    def test_integrated_direct_restore_checks_capture_before_first_service_stop(self):
        target = self.baseline(standalone=False)
        ctx = self.context('--rollback', standalone=False)
        with mock.patch.object(rollback.nfqws_process, '_memfd', side_effect=OSError('unavailable')), \
                mock.patch.object(rollback.snapshot_store, 'restore_files') as restore_files, \
                self.assertRaisesRegex(RuntimeError, 'memfd'):
            rollback.restore(ctx, target)
        rollback.nfqws_service.action.assert_not_called()
        restore_files.assert_not_called()

    def test_integrated_rollback_checks_capture_before_rescue_or_service_stop(self):
        self.baseline(standalone=False)
        ctx = self.context('--rollback', standalone=False)
        with mock.patch.object(rollback.nfqws_process, '_memfd', side_effect=OSError('unavailable')), \
                mock.patch.object(rollback, 'capture', side_effect=AssertionError('unexpected rescue')) as capture:
            self.assertEqual(rollback.run(ctx), 1)
        capture.assert_not_called()
        rollback.nfqws_service.action.assert_not_called()
        self.assertIn('memfd', self.err.getvalue())

    def test_standalone_rollback_does_not_require_service_capture(self):
        self.baseline()
        with mock.patch.object(rollback.nfqws_process, 'service_capture_ready',
                side_effect=RuntimeError('unavailable')) as readiness:
            self.assertEqual(rollback.run(self.context('--rollback')), 0, self.err.getvalue())
        readiness.assert_not_called()

    def test_restore_error_returns_to_rescue_state_and_keeps_pointer(self):
        self.baseline()
        pointer = Path(self.paths.baseline_pointer).read_bytes()
        Path(self.paths.nfqws_conf).write_bytes(b'user-current-config')
        with mock.patch.object(rollback, '_packages', side_effect=[RuntimeError('injected package failure'), None]):
            self.assertEqual(rollback.run(self.context('--rollback')), 1)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), b'user-current-config')
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), pointer)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())

    def test_signal_failure_uses_rescue_before_releasing_lock(self):
        self.baseline()
        pointer = Path(self.paths.baseline_pointer).read_bytes()
        Path(self.paths.nfqws_conf).write_bytes(b'current-before-signal')
        with mock.patch.object(rollback, '_packages', side_effect=[SystemExit(130), None]):
            self.assertEqual(rollback.run(self.context('--rollback')), 130)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), b'current-before-signal')
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), pointer)
        self.assertFalse(Path(self.paths.lock_dir).exists())
        self.assertIn('RESULT|rolled-back', self.out.getvalue())

    def test_unknown_mode_does_not_capture_or_mutate(self):
        ctx = self.context('--snapshot-baseline')
        ctx.options.mode = 'apply'
        with mock.patch.object(rollback, 'capture', side_effect=AssertionError('capture called')):
            self.assertEqual(rollback.run(ctx), 1)
        self.assertFalse(Path(self.paths.snapshot_root).exists())

    def test_partial_rescue_and_untrusted_ws_init_are_not_success(self):
        self.baseline(standalone=False)
        relay = Path(rollback.config_path(self.context('--rollback'), '/opt/etc/init.d/S99kdn-telegram-ws'))
        relay.parent.mkdir(parents=True, exist_ok=True)
        relay.write_bytes(b'#!/bin/sh\n# unrelated service\n')
        with mock.patch.object(rollback, '_relay_route', return_value='ws'):
            self.assertEqual(rollback.run(self.context('--rollback', standalone=False)), 1)
            self.assertIn('project-owned', self.err.getvalue())
        relay.unlink()
        with mock.patch.object(rollback, 'restore', side_effect=RuntimeError('injected repeated failure')):
            self.assertEqual(rollback.run(self.context('--rollback', standalone=False)), 1)
            self.assertIn('RESULT|partial', self.out.getvalue())

    def test_existing_owned_ws_relay_restarts_and_stops_with_real_disposable_init(self):
        self.baseline(standalone=False)
        relay = Path(rollback.config_path(self.context('--rollback'), '/opt/etc/init.d/S99kdn-telegram-ws'))
        relay.parent.mkdir(parents=True, exist_ok=True)
        flag = self.directory / 'relay-running'
        self.environ['RELAY_FLAG'] = str(flag)
        relay.write_text('''#!/bin/sh
# Telegram WS relay of keenetic-discord-nfqws2
case "$1" in
  restart) : > "$RELAY_FLAG" ;;
  stop) rm -f "$RELAY_FLAG" ;;
  status) test -f "$RELAY_FLAG" ;;
  *) exit 2 ;;
esac
''')
        relay.chmod(0o700)
        with mock.patch.object(rollback.relay_restore, 'preflight'):
            with mock.patch.object(rollback.relay_restore, 'render', return_value=relay.read_bytes()):
                with mock.patch.object(rollback, '_relay_route', return_value='ws'):
                    self.assertEqual(rollback.run(self.context('--rollback', standalone=False)), 0, self.err.getvalue())
        self.assertTrue(flag.exists())
        with mock.patch.object(rollback, '_relay_route', return_value='direct'):
            self.assertEqual(rollback.run(self.context('--rollback', standalone=False)), 0, self.err.getvalue())
        self.assertFalse(flag.exists())
        self.assertFalse(relay.exists())  # native reconcile matches legacy removal now

    def test_snapshot_inventory_cannot_authorise_arbitrary_package_commands(self):
        target = self.baseline()
        package = target / 'PACKAGES.tsv'
        package.write_bytes(package.read_bytes() + b'--evil\tPRESENT\t1\n')
        with mock.patch.object(rollback, '_run', side_effect=AssertionError('external command executed')):
            self.assertEqual(rollback.run(self.context('--rollback')), 1)

    def test_legacy_package_and_standalone_runtime_formats_are_accepted(self):
        target = self.baseline()
        runtime = (target / 'RUNTIME.tsv').read_bytes()
        self.assertIn(b'XKEEN_RUNNING\tUNMANAGED', runtime)
        self.assertIn(b'ABSENT\t-', (target / 'PACKAGES.tsv').read_bytes())
        saved = snapshot_store.verify(target)
        self.assertEqual(rollback.validate_auxiliary(saved)[1]['XKEEN_RUNNING'], 'UNMANAGED')
        (target / 'IPV6_RUNTIME.txt').write_bytes(b'net.ipv6.conf.eth0.disable_ipv6 = 1\n' * 2)
        with self.assertRaises(ValueError):
            rollback.validate_auxiliary(snapshot_store.verify(target))

    def test_integrated_snapshot_refuses_unmanaged_runtime(self):
        target = self.baseline()
        state = (target / 'STATE.tsv').read_bytes().replace(b'SCOPE\tstandalone', b'SCOPE\tintegrated')
        (target / 'STATE.tsv').write_bytes(state)
        # Keep a valid integrated inventory; validate_auxiliary itself is pure.
        saved = SimpleNamespace(auxiliary={'PACKAGES.tsv': (target / 'PACKAGES.tsv').read_bytes(),
            'RUNTIME.tsv': b'XKEEN_RUNNING\tUNMANAGED\nNFQWS_RUNNING\t0\n'},
            metadata=SimpleNamespace(scope='integrated'))
        with self.assertRaises(ValueError):
            rollback.validate_auxiliary(saved)

    def test_version_specific_baseline_rollover_preserves_original_and_previous(self):
        ctx = self.context('--snapshot-baseline')
        ctx.resolved.standalone = False
        with mock.patch.object(rollback, 'xkeen_version', return_value='2.0'):
            self.assertEqual(rollback.run(ctx), 0, self.err.getvalue())
        original = Path(self.paths.baseline_pointer).read_bytes()
        with mock.patch.object(rollback, 'xkeen_version', return_value='2.1'):
            self.assertEqual(rollback.run(ctx), 0, self.err.getvalue())
            version_pointer = Path(self.paths.xkeen_baseline_pointer).read_bytes()
            count = len(list(Path(self.paths.snapshot_root).iterdir()))
            self.assertEqual(rollback.run(ctx), 0, self.err.getvalue())
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), original)
        self.assertEqual(Path(self.paths.xkeen_baseline_pointer).read_bytes(), version_pointer)
        self.assertEqual(len(list(Path(self.paths.snapshot_root).iterdir())), count)
        self.assertEqual(snapshot_store.verify(Path(version_pointer.decode().strip())).metadata.value('XKEEN_VERSION'), '2.1')
        self.assertTrue(Path(original.decode().strip()).exists())

    def test_integrated_then_standalone_baseline_keeps_xkeen_second_stage_unmanaged(self):
        standalone = self.baseline()
        ctx = self.context('--snapshot-baseline')
        ctx.resolved.standalone = False
        with mock.patch.object(rollback, 'xkeen_version', return_value='2.1'):
            self.assertEqual(rollback.run(ctx), 0, self.err.getvalue())
        integrated = Path(Path(self.paths.xkeen_baseline_pointer).read_text().strip())
        events = []
        original = rollback.restore

        def restore(current_ctx, saved):
            events.append(str(saved.path if hasattr(saved, 'path') else saved))
            return original(current_ctx, saved)

        ctx.options.mode = 'rollback-baseline'
        with mock.patch.object(rollback, '_xkeen_state') as xkeen:
            with mock.patch.object(rollback, 'restore', side_effect=restore):
                self.assertEqual(rollback.run(ctx), 0, self.err.getvalue())
        self.assertEqual(events, [str(integrated), str(standalone)])
        self.assertEqual(xkeen.call_args_list, [mock.call(ctx, '0'), mock.call(ctx, '0')])


class RollbackPackageServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.directory), KD_ALLOW_TEST_ROOT='1')
        self.ctx = SimpleNamespace(environ=self.environ, paths=config.EnginePaths.from_environ(self.environ),
            console=console.Console(io.StringIO(), io.StringIO()))

    def test_strict_package_query_does_not_treat_timeout_as_absence(self):
        for result in (nfqws_process.ProcessResult(124, '', timed_out=True),
                       nfqws_process.ProcessResult(127, ''),
                       nfqws_process.ProcessResult(0, '', output_limited=True)):
            with self.subTest(result=result), mock.patch.object(rollback.nfqws_process, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    rollback.package_version(self.ctx, 'jq')
        for text, expected in (('', ''), ('Package: jq\nStatus: deinstall ok not-installed\n', ''),
            ('Package: jq\nStatus: install ok installed\nVersion: 1.7.1-2\n', '1.7.1-2')):
            with mock.patch.object(rollback, '_run', return_value=nfqws_process.ProcessResult(0, text)):
                self.assertEqual(rollback.package_version(self.ctx, 'jq'), expected)
        for text in ('bad state', 'Package: evil\nStatus: install ok installed\nVersion: 1\n',
                     'Package: jq\nStatus: install ok installed\n', 'Package: jq\nPackage: jq\n'):
            with self.subTest(text=text), mock.patch.object(rollback, '_run', return_value=nfqws_process.ProcessResult(0, text)):
                with self.assertRaises(ValueError):
                    rollback.package_version(self.ctx, 'jq')
        with self.assertRaises(ValueError):
            rollback.package_version(self.ctx, '--evil')

    def test_auxiliary_tables_reject_ambiguous_or_unbounded_runtime_commands(self):
        packages = b''.join((name + '\tABSENT\t-\n').encode() for name in rollback.PACKAGES)
        saved = SimpleNamespace(auxiliary={'PACKAGES.tsv': packages,
            'RUNTIME.tsv': b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\n'},
            metadata=SimpleNamespace(scope='integrated'))
        for data in (b'kernel.kptr_restrict=0\n', b'net.ipv6.conf.all.disable_ipv6=2\n',
                     b'net.ipv6.conf.all.disable_ipv6=0;touch /tmp/evil\n'):
            saved.auxiliary['IPV6_RUNTIME.txt'] = data
            with self.subTest(data=data), self.assertRaises(ValueError):
                rollback.validate_auxiliary(saved)
        saved.auxiliary['IPV6_RUNTIME.txt'] = b'net.ipv6.conf.eth0.1.disable_ipv6 = 1\n'
        self.assertEqual(rollback.validate_auxiliary(saved)[2], [('net.ipv6.conf.eth0.1.disable_ipv6', '1')])
        for runtime in (b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\nNFQWS_RUNNING\t1\n',
                        b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\textra\n'):
            saved.auxiliary['RUNTIME.tsv'] = runtime
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                rollback.validate_auxiliary(saved)

    def test_packages_execute_only_whitelisted_argv_with_real_disposable_process(self):
        import sys

        executable = self.directory / 'opkg'
        db = self.directory / 'packages.json'
        log = self.directory / 'commands.jsonl'
        db.write_text(json.dumps({'jq': '1', 'ca-certificates': '2'}))
        executable.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
path = os.environ['PACKAGE_DB']
with open(path) as stream: data = json.load(stream)
action, name = sys.argv[1:]
with open(os.environ['PACKAGE_LOG'], 'a') as stream: stream.write(json.dumps(sys.argv[1:]) + '\\n')
if action == 'status':
    if name in data: print('Package: ' + name + '\\nStatus: install ok installed\\nVersion: ' + data[name])
elif action == 'remove': data.pop(name, None)
elif action == 'install': data[name] = '3'
else: raise SystemExit(2)
with open(path, 'w') as stream: json.dump(data, stream)
''')
        executable.chmod(0o700)
        self.ctx.environ.update(PATH=str(self.directory) + os.pathsep + os.environ['PATH'],
            PACKAGE_DB=str(db), PACKAGE_LOG=str(log))
        packages = {name: ['ABSENT', '-'] for name in rollback.PACKAGES}
        packages['ca-certificates'] = ['PRESENT', '1']  # installed2 retained, no downgrade
        packages['wget-ssl'] = ['PRESENT', '3']
        rollback._packages(self.ctx, packages)
        self.assertEqual(json.loads(db.read_text()), {'ca-certificates': '2', 'wget-ssl': '3'})
        commands = [json.loads(row) for row in log.read_text().splitlines()]
        self.assertIn(['remove', 'jq'], commands)
        self.assertIn(['install', 'wget-ssl'], commands)
        self.assertTrue(all(len(argv) == 2 and argv[1] in rollback.PACKAGES for argv in commands))

    def test_xkeen_version_accepts_21_plus_but_not_20_or_failed_output(self):
        with mock.patch.object(rollback, 'package_version', return_value=''):
            for text, expected in (('XKeen 2.0', ''), ('XKeen 2.1.1β', '2.1.1β'),
                                   ('XKeen 2.0 then 2.1', ''), ('unknown', '')):
                with self.subTest(text=text), mock.patch.object(rollback.xkeen, 'probe', return_value=expected):
                    if expected:
                        self.assertEqual(rollback.xkeen_version(self.ctx), expected)
                    else:
                        with self.assertRaises(ValueError):
                            rollback.xkeen_version(self.ctx)

    def test_xkeen_start_never_retries_the_removed_20_start_path(self):
        target = Path(self.ctx.paths.xkeen_init)
        target.parent.mkdir(parents=True)
        target.write_text('#!/bin/sh\nexit 0\n')
        with mock.patch.object(rollback.xkeen_service, 'pid', return_value=None):
            with mock.patch.object(rollback, 'xkeen_version', return_value='2.0'):
                with mock.patch.object(rollback, '_run', side_effect=[nfqws_process.ProcessResult(1, ''), nfqws_process.ProcessResult(0, '')]) as run:
                    with self.assertRaises(ValueError):
                        rollback._xkeen_state(self.ctx, '1')
                    self.assertEqual(run.call_count, 0)  #2.0 is refused before any service command.
            with mock.patch.object(rollback, 'xkeen_version', return_value='2.1'):
                with mock.patch.object(rollback.xkeen_service.nfqws_process, 'run_service', return_value=nfqws_process.ProcessResult(1, '')) as run:
                    with self.assertRaises(RuntimeError):
                        rollback._xkeen_state(self.ctx, '1')
                    self.assertEqual(run.call_count, 1)

    def test_xkeen_commands_run_foreground_with_disposable_init_and_state(self):
        init = Path(self.ctx.paths.xkeen_init)
        init.parent.mkdir(parents=True)
        flag = self.directory / 'core-running'
        log = self.directory / 'xkeen-events'
        self.ctx.environ.update(CORE_FLAG=str(flag), CORE_LOG=str(log))
        init.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CORE_LOG"
case "$1:$2" in
  start:on) : > "$CORE_FLAG" ;;
  start:) exit 2 ;;
  stop:) rm -f "$CORE_FLAG" ;;
  *) exit 2 ;;
esac
''')
        init.chmod(0o700)
        with mock.patch.object(rollback, 'xkeen_version', return_value='2.1'):
            with mock.patch.object(rollback.xkeen_service, 'pid', side_effect=lambda ctx: 123 if flag.exists() else None):
                rollback._xkeen_state(self.ctx, '1')
                self.assertTrue(flag.exists())
                rollback._xkeen_state(self.ctx, '0')
                self.assertFalse(flag.exists())
        self.assertEqual(log.read_text().splitlines(), ['start on', 'stop'])

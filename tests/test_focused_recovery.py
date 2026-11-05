"""Focused recovery uses real launcher and snapshot/file writes on disposable roots."""
import os
from pathlib import Path
import select
import json
import sys
import threading
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from kdn.web.infra import engine
import test_engine_import_ops
from kdn.engine import snapshot_store, import_worker
from kdn.web.domain import automation


class NativeImportIdentityTests(unittest.TestCase):
    def test_real_launcher_waiting_before_lock_is_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'bin/xkeen'
            binary.parent.mkdir()
            ready, release = root / 'ready', root / 'release'
            os.mkfifo(release)
            binary.write_text('#!/bin/sh\n: > "$READY"\nread -r ignored < "$RELEASE"\nprintf "XKeen 2.1\\n"\n')
            binary.chmod(0o700)
            launcher = Path(__file__).resolve().parents[1] / 'apply-discord-nfqws2.sh'
            env = dict(os.environ, KD_TEST_ROOT=directory, KD_ALLOW_TEST_ROOT='1', KDN_ENGINE='python',
                       READY=str(ready), RELEASE=str(release), PATH=str(binary.parent) + ':' + os.environ['PATH'])
            child = subprocess.Popen(['/bin/sh', str(launcher), '--apply-import-profile', str(root / 'profile.json'),
                                      '--yes-router', '--focused-operation-context', '{}'],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), 'native version gate was not reached')
                self.assertIsNone(child.poll())
                self.assertFalse((root / 'opt/tmp/keenetic-discord-nfqws2.lock').exists())
                with mock.patch.multiple(engine.cfg, ENGINE=launcher, AUTOMATION_STATE=root / 'automation-state.json',
                                         AUTOMATION_CONFIG=root / 'automation-config.json'):
                    self.assertTrue(engine.import_process_active(), 'live native worker lost its launcher argv')
                    pending = {'schema': 2, 'operation_id': 'a' * 32, 'before_hash': 'b' * 64}
                    automation.STATE.update(transaction=pending)
                    wait = engine.wait_import_idle
                    with mock.patch.object(engine, 'wait_import_idle', lambda: wait(timeout=0)):
                        with self.assertRaisesRegex(RuntimeError, 'ещё работает'):
                            automation.automation_rollback_import('live worker before lock')
                    self.assertEqual(automation.STATE.read()['transaction'], pending)
            finally:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=5)


class BoundedIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.launcher = self.root / 'project/apply-discord-nfqws2.sh'
        self.proc = self.root / 'proc'
        self.proc.mkdir()
        self.process = self.proc / '123'
        self.process.mkdir()
        self.environment = {'KDN_ENGINE_SCRIPT': str(self.launcher),
            'KDN_ENGINE_SCRIPT_DIR': str(self.launcher.parent),
            'KDN_ENGINE_ADDED_PYTHONPATH': str(self.launcher.parent / 'tools/router'),
            'PYTHONPATH': str(self.launcher.parent / 'tools/router')}
        patch = mock.patch.object(import_worker, '_PROC_ROOT', self.proc)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, args, environment=None, state='S'):
        (self.process / 'cmdline').write_bytes(b'\0'.join(os.fsencode(arg) for arg in args) + b'\0')
        env = self.environment if environment is None else environment
        (self.process / 'environ').write_bytes(b'\0'.join(os.fsencode(key + '=' + value) for key, value in env.items()))
        (self.process / 'stat').write_text('123 (synthetic process) ' + state + ' ' + ' '.join(['0'] * 18 + ['1234']))

    def test_only_exact_project_native_or_legacy_mutation_is_active(self):
        for flag, value in (('--apply-import-profile', '/tmp/synthetic.json'),
                            ('--clear-imported-profile', 'youtube'), ('--rollback-import', None)):
            tail = [flag, *([value] if value else []), '--yes-router']
            for prefix in (['python3', '-P', '-m', 'kdn.engine'], ['python3', '-m', 'kdn.engine'],
                           ['/bin/sh', str(self.launcher)]):
                with self.subTest(flag=flag, prefix=prefix):
                    self.write(prefix + tail)
                    self.assertIs(import_worker.active(self.launcher), True)
        for argv in (['python3', '-P', '-m', 'kdn.engine', '--status'],
                     ['python3', '-P', '-m', 'kdn.engine', '--rollback-import', '--help'],
                     ['python3', '-P', '-m', 'foreign.engine', '--rollback-import'],
                     ['python3', '-c', 'kdn.engine --rollback-import ' + str(self.launcher)],
                     ['/bin/sh', str(self.launcher) + '.foreign', '--rollback-import']):
            with self.subTest(argv=argv):
                self.write(argv)
                self.assertIs(import_worker.active(self.launcher), False)
        self.write(['python3', '-m', 'kdn.engine', '--rollback-import'],
                   dict(self.environment, KDN_ENGINE_SCRIPT='/foreign/apply-discord-nfqws2.sh'))
        self.assertIs(import_worker.active(self.launcher), False)
        self.write(['python3', '-m', 'kdn.engine', '--rollback-import'], state='Z')
        self.assertIs(import_worker.active(self.launcher), False)

    def test_unknown_scan_bounds_unreadable_proof_and_pid_reuse_are_not_absence(self):
        self.write(['python3', '-m', 'kdn.engine', '--rollback-import'], {})
        self.assertIsNone(import_worker.active(self.launcher))
        self.write(['python3', '-m', 'kdn.engine', '--rollback-import'])
        with mock.patch.object(import_worker, '_identity', side_effect=[(b'S', b'1'), (b'S', b'2')]):
            self.assertIsNone(import_worker.active(self.launcher))
        with mock.patch.object(import_worker, '_MAX_PROCESSES', 0):
            self.assertIsNone(import_worker.active(self.launcher))
        with mock.patch.object(import_worker, '_PROC_ROOT', self.root / 'missing'):
            self.assertIsNone(import_worker.active(self.launcher))
        with mock.patch.object(import_worker, '_MAX_ENVIRON', 1):
            self.assertIsNone(import_worker.active(self.launcher))
        with mock.patch.object(import_worker, '_MAX_COMMAND', 1):
            self.assertIsNone(import_worker.active(self.launcher))


class FocusedKillTests(test_engine_import_ops.ImportOperationsTests):
    def setUp(self):
        super().setUp()
        self.launcher = Path(__file__).resolve().parents[1] / 'apply-discord-nfqws2.sh'
        self.environ['KDN_ENGINE_SCRIPT'] = str(self.launcher)
        self.environ['PYTHONPATH'] = str(self.launcher.parent / 'tools/router')
        self.runtime = self.root / 'runtime'
        self.runtime.write_text('running')
        self.pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
        self.base = Path(self.paths.nfqws_conf).parent
        self.target = self.base / 'imported-profiles/discord-tcp.json'
        self.statefile = self.root / 'opt/etc/xkeen-web/automation-state.json'
        self.configfile = self.statefile.with_name('automation.json')
        self.addCleanup(mock.patch.stopall)
        mock.patch.multiple(engine.cfg, ENGINE=self.launcher, NFQWS_CONFIG=Path(self.paths.nfqws_conf),
                            IMPORTED_PROFILE_DIR=self.target.parent, IMPORT_ROLLBACK_POINTER=self.pointer,
                            AUTOMATION_STATE=self.statefile, AUTOMATION_CONFIG=self.configfile).start()
        # Parent tests deliberately run against the same disposable state as the worker.
        mock.patch.object(automation, 'AUTOMATION_STATE_LOCK', threading.Lock()).start()

    def pending(self):
        value = engine.new_import_transaction(self.profile)
        automation.STATE.update(transaction=value)
        return value

    def worker(self, args, pause=''):
        env = dict(self.environ, FOCUSED_PAUSE=pause)
        return subprocess.Popen([sys.executable, '-P', str(Path(__file__).with_name('focused_recovery_worker.py')), *args],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def interrupt(self, args, pause):
        child = self.worker(args, pause)
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while b'FOCUSED_READY' not in output:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, 'worker did not reach interruption seam')
                self.assertTrue(select.select([child.stdout], [], [], remaining)[0])
                chunk = os.read(child.stdout.fileno(), 4096)
                if not chunk:
                    self.fail(child.stderr.read().decode())
                output.extend(chunk)
            child.kill()
            child.communicate(timeout=5)
            self.assertEqual(child.returncode, -9)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def apply_args(self, pending):
        return [*self.args, '--focused-operation-context', json.dumps(pending)]

    def run_adapter(self, command, timeout):
        child = self.worker(command[2:])
        out, err = child.communicate(timeout=timeout)
        return {'ok': child.returncode == 0, 'code': child.returncode,
                'output': (out + err).decode()}

    def recover(self):
        with mock.patch.object(engine.proc, 'run_command', self.run_adapter):
            automation.automation_rollback_import('synthetic interruption')

    def test_kill_after_descriptor_keeps_verified_early_cue(self):
        pending = self.pending()
        self.interrupt(self.apply_args(pending), 'after-descriptor')
        self.assertTrue(self.target.exists())
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
        self.assertTrue(self.pointer.exists(), 'descriptor changed before recovery cue')
        snapshot_store.verify(Path(self.pointer.read_text().strip()), focused=True)
        self.recover()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.target.parent.exists())
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), self.initial)
        self.assertEqual(self.runtime.read_text(), 'running')
        self.assertIsNone(automation.STATE.read()['transaction'])

    def test_repeated_kill_restores_original_descriptor_bytes_modes_and_source(self):
        self.target.parent.mkdir(mode=0o750)
        original = dict(self.profile, report={'created_utc': 'synthetic original'})
        original_bytes = (json.dumps(original) + '  \n').encode()
        self.target.write_bytes(original_bytes)
        self.target.chmod(0o640)
        pending = self.pending()
        before = snapshot_store.focused_inventory(self.base)
        self.interrupt(self.apply_args(pending), 'after-descriptor')
        source, fingerprint = engine.recovery_source(pending)
        pinned = dict(pending, original_source=source, source_fingerprint=fingerprint)
        automation.STATE.update(transaction=pinned)
        args = ['--rollback-import', '--yes-router', '--recover-import-source', source,
                '--focused-operation-context', json.dumps(pinned)]
        for seam in ('restore-data', 'after-restart'):
            self.interrupt(args, seam)
            self.assertEqual(self.pointer.read_text().strip(), source)
            self.assertEqual(automation.STATE.read()['transaction']['original_source'], source)
        self.recover()
        self.assertEqual(self.target.read_bytes(), original_bytes)
        self.assertEqual(snapshot_store.focused_inventory(self.base), before)
        self.assertEqual(self.runtime.read_text(), 'running')
        self.assertEqual(self.pointer.read_text().strip(), source)
        self.assertIsNone(automation.STATE.read()['transaction'])

    def test_no_cue_and_legacy_hash_match_preserve_pending(self):
        pending = self.pending()
        with self.assertRaises(ValueError):
            self.recover()
        self.assertEqual(automation.STATE.read()['transaction'], pending)
        legacy = {key: value for key, value in pending.items() if key not in ('schema', 'operation_id')}
        automation.STATE.update(transaction=legacy)
        with self.assertRaisesRegex(RuntimeError, 'legacy'):
            self.recover()
        self.assertEqual(automation.STATE.read()['transaction'], legacy)

    def test_foreign_descriptor_bytes_mode_and_extra_list_are_not_adopted(self):
        pending = self.pending()
        self.interrupt(self.apply_args(pending), 'after-descriptor')
        original = self.target.read_bytes()
        variants = ('report', 'mode', 'extra')
        for variant in variants:
            with self.subTest(variant=variant):
                if variant == 'report':
                    value = json.loads(original)
                    value['report']['foreign'] = 'synthetic drift'
                    self.target.write_text(json.dumps(value))
                elif variant == 'mode':
                    self.target.chmod(0o644)
                else:
                    (self.base / 'lists/foreign.list').write_text('synthetic.invalid')
                current = snapshot_store.focused_inventory(self.base)
                with self.assertRaisesRegex(RuntimeError, 'foreign drift'):
                    self.recover()
                self.assertEqual(snapshot_store.focused_inventory(self.base), current)
                self.assertIsNotNone(automation.STATE.read()['transaction'])
                self.target.write_bytes(original)
                self.target.chmod(0o600)
                (self.base / 'lists/foreign.list').unlink(missing_ok=True)

    def test_foreign_pointer_and_corrupt_pinned_source_are_refused(self):
        pending = self.pending()
        self.interrupt(self.apply_args(pending), 'after-descriptor')
        source, fingerprint = engine.recovery_source(pending)
        pinned = dict(pending, original_source=source, source_fingerprint=fingerprint)
        automation.STATE.update(transaction=pinned)
        self.pointer.write_text('foreign-operation')
        with self.assertRaises(ValueError):
            self.recover()
        self.pointer.write_text(source + '\n')
        state = Path(source) / 'STATE.tsv'
        state.write_bytes(state.read_bytes().replace(b'SCRIPT_VERSION\t', b'SCRIPT_VERSION\tchanged-'))
        with self.assertRaisesRegex(ValueError, 'fingerprint changed'):
            self.recover()
        self.assertEqual(automation.STATE.read()['transaction'], pinned)

    def test_direct_recovery_wait_timeout_keeps_transaction_and_disables_schedule(self):
        pending = self.pending()
        automation.CONFIG.write({**automation.default_automation_config(), 'enabled': True})
        with (mock.patch.object(engine, 'import_process_active', return_value=None),
              mock.patch.object(engine.time, 'monotonic', side_effect=[0, 361])):
            with self.assertRaisesRegex(RuntimeError, 'неизвестно'):
                automation.automation_rollback_import('test')
        self.assertEqual(automation.STATE.read()['transaction'], pending)
        self.assertFalse(automation.automation_config()['enabled'])

    def test_durable_pin_precedes_restore_and_stale_completion_cannot_clear_new_transaction(self):
        pending = self.pending()
        self.interrupt(self.apply_args(pending), 'after-descriptor')
        def displaced(**kwargs):
            pinned = automation.STATE.read()['transaction']
            self.assertEqual(pinned['original_source'], kwargs['source'])
            self.assertEqual(pinned['source_fingerprint'], kwargs['operation_context']['source_fingerprint'])
            automation.STATE.update(transaction=dict(pending, operation_id='f' * 32))
            return {'ok': True, 'output': 'FOCUSED_RECOVERED|' + pending['operation_id'] + '|'
                    + pinned['source_fingerprint'] + '\nRESULT|ok'}
        with mock.patch.object(engine, 'rollback_import', displaced):
            with self.assertRaisesRegex(RuntimeError, 'чужой операции'):
                automation.automation_rollback_import('test')
        self.assertEqual(automation.STATE.read()['transaction']['operation_id'], 'f' * 32)


    def test_startup_worker_timeout_is_not_retried(self):
        pending = self.pending()
        run_lock = threading.Lock()
        run_lock.acquire()
        with (mock.patch.object(automation, 'AUTOMATION_RUN_LOCK', run_lock),
              mock.patch.object(engine, 'wait_import_idle', side_effect=engine.ImportWorkerPending('busy')) as wait):
            automation.recover_automation_transaction()
        wait.assert_called_once()
        self.assertEqual(automation.STATE.read()['status'], 'recovery-failed')
        self.assertEqual(automation.STATE.read()['transaction'], pending)
        self.assertFalse(run_lock.locked())

"""Regenerate/reconcile WS init on loopback only, never external network/router."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import engine_shell

from kdn.common import fsutil
from kdn.engine import config, console, nfqws_process, relay_restore as relay, rollback_ops, snapshot_store


HELPER = '''import argparse, json, os, signal, socket, sys, time
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--listen")
p.add_argument("--pidfile", type=Path)
p.add_argument("--log")
p.add_argument("--cf-domains-file")
p.add_argument("--cf-ips-file")
p.add_argument("--mark", type=int, default=0)
a = p.parse_args()
a.pidfile.parent.mkdir(parents=True, exist_ok=True)
a.pidfile.write_text(str(os.getpid()) + "\\n")
host, port = a.listen.rsplit(":", 1)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port)))
s.listen()
with open(os.environ['RELAY_EVENTS'], 'a') as out:
    out.write(json.dumps({'mark': a.mark, 'listen': a.listen}) + "\\n")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
try:
    while True: time.sleep(.1)
finally:
    s.close()
'''


class RelayRestoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='relay-restore-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.directory), KD_ALLOW_TEST_ROOT='1',
            KDN_ENGINE_SCRIPT_DIR=str(self.directory / "project's files"),
            KD_TEST_TELEGRAM_WS_PORT=str(port), RELAY_EVENTS=str(self.directory / 'events'))
        from target_fixture import supported_environment
        supported_environment(self.environ)
        paths = config.EnginePaths.from_environ(self.environ)
        self.out, self.err = io.StringIO(), io.StringIO()
        self.ctx = SimpleNamespace(environ=self.environ, paths=paths,
            options=SimpleNamespace(confirmed=True), resolved=SimpleNamespace(standalone=False),
            console=console.Console(self.out, self.err))
        python = Path(paths.telegram_ws_python)
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        helper = Path(paths.telegram_ws_relay)
        helper.parent.mkdir(parents=True)
        helper.write_text(HELPER)
        conf = Path(paths.nfqws_conf)
        conf.parent.mkdir(parents=True)
        conf.write_text('# Deployment mode: xkeen-integrated.\n')
        self.outbound = Path(paths.xray_config_dir) / '04_direct.json'
        self.outbound.parent.mkdir(parents=True)
        self.mark(255)
        self.addCleanup(self.cleanup_relay)

    def cleanup_relay(self):
        try:
            relay.reconcile(self.ctx, 'direct')
        except (ValueError, RuntimeError, OSError):
            pass

    def mark(self, value):
        self.outbound.write_text(json.dumps({'outbounds': [{'protocol': 'freedom',
            'streamSettings': {'sockopt': {'mark': value}}}]}))

    def events(self):
        return [json.loads(line) for line in Path(self.environ['RELAY_EVENTS']).read_text().splitlines()]

    def test_missing_init_is_created_and_mark_recomputed_then_removed(self):
        self.assertFalse(relay._path(self.ctx).exists())
        relay.preflight(self.ctx, ('ws',))
        relay.reconcile(self.ctx, 'ws')
        init = relay._path(self.ctx)
        self.assertIn(b'MARK=255\n', init.read_bytes())
        self.assertEqual(relay._command(self.ctx, init, 'status').returncode, 0)
        self.mark(777)
        relay.reconcile(self.ctx, 'ws')
        self.assertIn(b'MARK=777\n', init.read_bytes())
        self.assertEqual([event['mark'] for event in self.events()], [255, 777])
        relay.reconcile(self.ctx, 'direct')
        self.assertFalse(init.exists())

    def test_unknown_init_is_not_executed_or_overwritten(self):
        init = relay._path(self.ctx)
        init.parent.mkdir(parents=True)
        init.write_bytes(b'#!/bin/sh\n# unrelated executable\n')
        with mock.patch.object(relay.nfqws_process, 'run', side_effect=AssertionError('executed unknown init')):
            with self.assertRaises(ValueError):
                relay.preflight(self.ctx, ('ws',))
            with self.assertRaises(ValueError):
                relay.reconcile(self.ctx, 'direct')
        self.assertEqual(init.read_bytes(), b'#!/bin/sh\n# unrelated executable\n')

    def test_rescue_restores_original_bytes_mode_and_running_state(self):
        relay.reconcile(self.ctx, 'ws')
        init = relay._path(self.ctx)
        init.chmod(0o700)
        saved = relay.capture(self.ctx)
        self.assertTrue(saved.running)
        self.mark(888)
        relay.reconcile(self.ctx, 'ws')
        self.assertNotEqual(init.read_bytes(), saved.data)
        relay.restore_init(self.ctx, saved)
        self.assertEqual(init.read_bytes(), saved.data)
        self.assertEqual(init.stat().st_mode & 0o777, 0o700)
        self.assertNotEqual(relay._command(self.ctx, init, 'status', required=False).returncode, 0)
        relay.restore_saved(self.ctx, saved)
        self.assertEqual(relay._command(self.ctx, init, 'status').returncode, 0)
        self.assertEqual(self.events()[-1]['mark'], 255)

    def test_absent_rescue_state_removes_new_init_and_owned_daemon(self):
        saved = relay.capture(self.ctx)
        self.assertIsNone(saved.data)
        relay.reconcile(self.ctx, 'ws')
        relay.restore_saved(self.ctx, saved)
        self.assertFalse(relay._path(self.ctx).exists())
        port = int(self.environ['KD_TEST_TELEGRAM_WS_PORT'])
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))

    def test_port_helper_mark_and_canonical_context_guards(self):
        self.environ['KD_TEST_TELEGRAM_WS_PORT'] = '18443;bad'
        with self.assertRaises(ValueError):
            relay.preflight(self.ctx, ('ws',))
        self.environ['KD_TEST_TELEGRAM_WS_PORT'] = '18443'
        Path(self.ctx.paths.telegram_ws_relay).write_text('unsupported helper')
        with self.assertRaises(ValueError):
            relay.preflight(self.ctx, ('ws',))
        Path(self.ctx.paths.telegram_ws_relay).write_text(HELPER)
        self.mark('invalid;command')
        with self.assertRaises(ValueError):
            relay.render(self.ctx)
        self.ctx.paths = self.ctx.paths.replace(nfqws_conf='/tmp/forged')
        with self.assertRaises(ValueError):
            relay.capture(self.ctx)

    def test_stale_foreign_pid_is_never_signalled(self):
        init = relay._path(self.ctx)
        fsutil.atomic_bytes(init, relay.render(self.ctx), 0o755)
        child = subprocess.Popen(['sleep', '30'])

        def cleanup_child():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)

        self.addCleanup(cleanup_child)
        pidfile = Path(config.list_path('/opt/var/run/kdn-telegram-ws.pid', self.ctx.paths.test_root))
        pidfile.parent.mkdir(parents=True)
        pidfile.write_text(str(child.pid) + '\n')
        self.assertFalse(relay.capture(self.ctx).running)
        relay.reconcile(self.ctx, 'direct')
        self.assertIsNone(child.poll())
        child.terminate()
        child.wait(timeout=5)

    def test_failed_start_can_restore_prior_helper_exactly_without_daemon(self):
        init = relay._path(self.ctx)
        old = b'#!/bin/sh\n# Telegram WS relay of keenetic-discord-nfqws2\nexit 1\n'
        fsutil.atomic_bytes(init, old, 0o700)
        saved = relay.RelayState(old, 0o700, False)

        def command(ctx, path, verb, required=True):
            if verb == 'restart':
                raise RuntimeError('injected start failure')
            return nfqws_process.ProcessResult(1 if verb == 'status' else 0, '')

        with mock.patch.object(relay, '_command', side_effect=command):
            with self.assertRaises(RuntimeError):
                relay.reconcile(self.ctx, 'ws')
            relay.restore_saved(self.ctx, saved)
        self.assertEqual(init.read_bytes(), old)
        self.assertEqual(init.stat().st_mode & 0o777, 0o700)

    def test_full_rollback_failure_after_relay_removal_restores_helper_before_rescue(self):
        conf = Path(self.ctx.paths.nfqws_conf)
        conf.write_text('# Deployment mode: xkeen-integrated.\n'
            '# Active routes: DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Telegram=direct.\n')
        auxiliary = {'PACKAGES.tsv': b''.join((name + '\tABSENT\t-\n').encode() for name in rollback_ops.PACKAGES),
                     'RUNTIME.tsv': b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\n'}
        baseline = snapshot_store.create(self.ctx.paths, purpose='baseline', xkeen_version='2.1', auxiliary=auxiliary)
        snapshot_store.publish_pointer(self.ctx.paths, self.ctx.paths.baseline_pointer, baseline, baseline=True)
        baseline_pointer = Path(self.ctx.paths.baseline_pointer).read_bytes()
        conf.write_text(conf.read_text().replace('Telegram=direct.', 'Telegram=ws.'))
        current = conf.read_bytes()
        self.mark(777)
        relay.reconcile(self.ctx, 'ws')
        init = relay._path(self.ctx)
        init.chmod(0o700)
        old_init = init.read_bytes()
        self.ctx.options.mode = 'rollback-baseline'
        original = relay.reconcile
        failed = []

        def fail_after_removal(ctx, route):
            original(ctx, route)
            if route != 'ws' and not failed:
                failed.append(True)
                raise RuntimeError('injected after relay removal')

        with mock.patch.object(rollback_ops, 'package_version', return_value=''):
            with mock.patch.object(rollback_ops, 'xkeen_version', return_value='2.1'):
                with mock.patch.object(rollback_ops.xkeen_service, 'pid', return_value=None):
                    with mock.patch.object(rollback_ops.nfqws_service, 'pid', return_value=None):
                        with mock.patch.object(rollback_ops.nfqws_service, 'action'):
                            with mock.patch.object(rollback_ops.nfqws_service, 'restore_state'):
                                with mock.patch.object(relay, 'reconcile', side_effect=fail_after_removal):
                                    self.assertEqual(rollback_ops.run(self.ctx), 1, self.err.getvalue())
        self.assertEqual(conf.read_bytes(), current)
        self.assertEqual(init.read_bytes(), old_init)
        self.assertEqual(init.stat().st_mode & 0o777, 0o700)
        self.assertEqual(relay._command(self.ctx, init, 'status').returncode, 0)
        self.assertEqual(Path(self.ctx.paths.baseline_pointer).read_bytes(), baseline_pointer)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())

    def test_legacy_process_identity_helpers_are_copied_not_runtime_extracted(self):
        text = relay.render(self.ctx).decode()
        function = engine_shell.extract_function('write_telegram_ws_init')
        body = function.split('<<EOF\n', 1)[1].split('\nEOF', 1)[0]
        # Undo heredoc quote escapes only in test oracle, not production code.
        body = body.replace('\\$', '$').replace('\\\\', '\\')
        for name in ('is_relay', 'relay_pids', 'running', 'listening'):
            actual = engine_shell.extract_function(name, text)
            expected = engine_shell.extract_function(name, body)
            compact = lambda source: [line.strip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith('#')]
            with self.subTest(name=name):
                self.assertEqual(compact(actual), compact(expected))

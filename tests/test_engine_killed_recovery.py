"""SIGKILL cannot auto-undo; a committed rescue remains manually restorable."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest

from kdn.engine import config, snapshot_store


class KilledRecoveryTests(unittest.TestCase):
    def test_killed_owner_leaves_rescue_and_manual_rollback_takes_over_stale_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(os.environ, KD_TEST_ROOT=directory, KD_ALLOW_TEST_ROOT='1')
            from target_fixture import supported_environment
            supported_environment(env)
            paths = config.EnginePaths.from_environ(env)
            conf = Path(paths.nfqws_conf)
            conf.parent.mkdir(parents=True)
            conf.write_bytes(b'before-kill\n')
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            opkg = fake_bin / 'opkg'
            opkg.write_text('#!/bin/sh\nexit 0\n')
            opkg.chmod(0o700)
            env['PATH'] = str(fake_bin) + os.pathsep + env['PATH']
            router = Path(__file__).resolve().parents[1] / 'tools/router'
            env['PYTHONPATH'] = str(router)
            code = '''
import os, time
from pathlib import Path
from kdn.engine import cli, config, console, options, rollback_ops, snapshot_store, transaction
args=['--rollback-latest','--without-xkeen','--yes-router']
paths=config.EnginePaths.from_environ(os.environ)
parsed=options.parse_args(args)
ctx=cli.Context(args,dict(os.environ),console.Console.process(),paths=paths,
    options=parsed,resolved=options.resolve(parsed,''))
def operation(tx):
    packages=b''.join((name+'\\tABSENT\\t-\\n').encode() for name in rollback_ops.PACKAGES)
    saved=snapshot_store.create(paths,purpose='pre-kill-rescue',scope='standalone',xkeen_version='2.1',auxiliary={
        'PACKAGES.tsv':packages,'RUNTIME.tsv':b'XKEEN_RUNNING\\tUNMANAGED\\nNFQWS_RUNNING\\t0\\n',
        'IPV6_RUNTIME.txt':b''})
    snapshot_store.publish_pointer(paths,paths.latest_pointer,saved)
    tx.arm(lambda:snapshot_store.restore_files(paths,saved,current_xkeen_version='2.1'))
    ctx.console.out('Rescue snapshot of current state: '+str(saved))
    tx.stage('nfqws')
    Path(paths.nfqws_conf).write_bytes(b'interrupted-change\\n')
    print('READY',flush=True)
    time.sleep(3600)
transaction.execute(ctx,operation)
'''
            process = subprocess.Popen([sys.executable, '-c', code], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            captured = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    deadline = time.monotonic() + 15
                    while b'READY\n' not in captured:
                        self.assertGreater(deadline - time.monotonic(), 0, 'rescue was not published in time')
                        ready = selector.select(min(1, max(0, deadline - time.monotonic())))
                        if ready:
                            chunk = os.read(process.stdout.fileno(), 4096)
                            self.assertTrue(chunk, 'rescue child exited before ready')
                            captured.extend(chunk)
                            self.assertLess(len(captured), 65536)
                process.kill()
                rest, errors = process.communicate(timeout=5)
                captured.extend(rest)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            self.assertEqual(process.returncode, -9, errors.decode('utf-8', 'replace'))
            self.assertNotIn(b'RESULT|ok', captured)
            self.assertEqual(conf.read_bytes(), b'interrupted-change\n')
            saved = Path(Path(paths.latest_pointer).read_text().strip())
            snapshot_store.verify(saved)
            self.assertTrue(Path(paths.lock_dir).exists())
            # A new worker uses a fresh interpreter, not modules from another
            # PanelHarness generation left in the test runner's sys.modules.
            restored = subprocess.run([sys.executable, '-P', '-m', 'kdn.engine',
                '--rollback-latest', '--without-xkeen', '--yes-router'], env=env,
                capture_output=True, text=True, timeout=30)
            self.assertEqual(restored.returncode, 0, restored.stderr)
            self.assertIn('RESULT|ok', restored.stdout)
            self.assertEqual(conf.read_bytes(), b'before-kill\n')
            self.assertFalse(Path(paths.lock_dir).exists())

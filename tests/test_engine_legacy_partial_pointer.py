"""A failed shell apply never publishes itself as the last successful change."""
import os
from pathlib import Path
import shlex
import tempfile
import unittest

import engine_shell


class PartialPointerTests(unittest.TestCase):
    def test_partial_rescue_keeps_previous_pointer_or_previous_absence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            previous = root / 'successful-snapshot'
            previous.mkdir()
            pointer = root / 'latest-preapply.ptr'
            for old in (str(previous), ''):
                pointer.write_text('/failed-attempt-rescue\n')
                done = engine_shell.run_function('trigger', defs=(
                    'on_exit',
                    'cleanup_tmp() { :; }', 'release_lock() { :; }',
                    'restore_snapshot_internal() { return 1; }',
                    'safe_snapshot_path() { [ -d "$1" ]; }',
                    'atomic_pointer() { printf "%s\\n" "$2" > "$1"; }',
                    'trigger() { false; on_exit; }',
                ), variables={
                    'MODE': 'apply', 'NFQWS_TRANSACTION_ACTIVE': 0,
                    'AUTO_ROLLBACK_IN_PROGRESS': 0, 'NFQWS_IMPORT_BACKUP': '',
                    'TRANSACTION_ACTIVE': 1, 'PREAPPLY_SNAPSHOT': '/failed-attempt-rescue',
                    'LATEST_POINTER_REPLACED': 1, 'PREVIOUS_LATEST_SNAPSHOT': old,
                    'LATEST_POINTER': str(pointer),
                }, shell=shlex.split(os.environ.get('TEST_SHELL', 'sh')))
                with self.subTest(previous=old):
                    self.assertEqual(done.returncode, 1)
                    self.assertIn('RESULT|partial', done.stdout)
                    self.assertIn('Manual recovery snapshot: /failed-attempt-rescue', done.stderr)
                    if old:
                        self.assertEqual(pointer.read_text(), old + '\n')
                    else:
                        self.assertFalse(pointer.exists())

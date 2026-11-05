"""Exit instrumentation cannot report success before rollback/lock release."""
from pathlib import Path
import tempfile
import unittest

import engine_shell


class ExitTests(unittest.TestCase):
    def test_results_and_lock_release_at_the_actual_print(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp, 'lock')
            for active, restore_rc, expected in ((0, 0, 'failed'), (1, 0, 'rolled-back'), (1, 1, 'partial')):
                lock.mkdir()
                ref = engine_shell.run_function('finish_failure', defs=['on_exit',
                        'cleanup_tmp() { :; }', 'restore_snapshot_internal() { return "$RESTORE_RC"; }',
                        'release_lock() { rmdir "$LOCK_DIR"; }',
                        'printf() { case "$1" in RESULT*) [ ! -e "$LOCK_DIR" ] || return 77 ;; esac; command printf "$@"; }',
                        'finish_failure() { false; on_exit; }'],
                        variables={'MODE': 'apply', 'LOCK_DIR': lock, 'NFQWS_TRANSACTION_ACTIVE': 0,
                                   'TRANSACTION_ACTIVE': active, 'AUTO_ROLLBACK_IN_PROGRESS': 0,
                                   'PREAPPLY_SNAPSHOT': '/dummy', 'LATEST_POINTER_REPLACED': 0, 'RESTORE_RC': restore_rc})
                with self.subTest(expected=expected):
                    self.assertEqual(ref.returncode, 1, ref.stderr)
                    self.assertEqual(ref.stdout, 'RESULT|' + expected + '\n')
                    self.assertFalse(lock.exists())

"""Existing full-snapshot retention on disposable roots; no router services."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import config, console, rollback_ops as rollback, snapshot_store, transaction


class FullRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, 'KD_TEST_ROOT': str(self.root), 'KD_ALLOW_TEST_ROOT': '1'}
        from target_fixture import supported_environment
        supported_environment(self.env)
        self.paths = config.EnginePaths.from_environ(self.env)
        self.out, self.err = io.StringIO(), io.StringIO()
        self.ctx = SimpleNamespace(paths=self.paths, environ=self.env,
                                   options=SimpleNamespace(confirmed=True, mode='rollback-snapshot'),
                                   console=console.Console(self.out, self.err))
        Path(self.paths.nfqws_conf).parent.mkdir(parents=True)
        Path(self.paths.nfqws_conf).write_bytes(b'# disposable config\n')
        self.folder = Path(self.paths.snapshot_root)
        self.history = self.root / 'opt/etc/xkeen-web/history'

    def snapshots(self, count):
        def old_stamp(fmt, *args):
            return '2026-01-01T00:00:00Z' if fmt == '%Y-%m-%dT%H:%M:%SZ' else '20260101-000000'
        with mock.patch.object(snapshot_store.time, 'strftime', side_effect=old_stamp):
            values = [snapshot_store.create(self.paths, purpose='retention-test', scope='standalone')
                      for _ in range(count)]
        return sorted(values, key=lambda path: path.name)

    def history_entry(self, name, snapshot):
        self.history.mkdir(parents=True, exist_ok=True)
        path = self.history / (name + '.json')
        path.write_text(json.dumps({'job_id': name, 'snapshot': str(snapshot)}))
        return path

    def test_trashed_history_protects_snapshot_even_without_active_history(self):
        snapshots = self.snapshots(4)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        trash = self.root / 'opt/etc/xkeen-web/record-trash/history'
        trash.mkdir(parents=True)
        record = trash / '1700000000-abcd-old.json'
        record.write_text(json.dumps({'snapshot': str(snapshots[1])}))
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(snapshots[0].exists())
        self.assertTrue(snapshots[1].exists())
        self.assertFalse(snapshots[2].exists())
        self.assertTrue(snapshots[3].exists())
        self.assertTrue(record.exists())

    def test_corrupt_trash_or_combined_budget_stops_all_pruning(self):
        snapshots = self.snapshots(3)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        self.history_entry('active', snapshots[1])
        trash = self.root / 'opt/etc/xkeen-web/record-trash/history'
        trash.mkdir(parents=True)
        record = trash / 'old.json'
        record.write_text('{broken')
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(p.exists() for p in snapshots))
        record.write_text('{}')
        with mock.patch.object(rollback, 'MAX_HISTORY_RECORDS', 1):
            rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(p.exists() for p in snapshots))

    def test_default_age30_min1_preserves_pointers_rescue_target_and_oldest_history(self):
        snapshots = self.snapshots(32)
        for pointer, target in zip((self.paths.baseline_pointer, self.paths.xkeen_baseline_pointer,
                                    self.paths.latest_pointer), snapshots[:3], strict=True):
            Path(pointer).write_text(str(target) + '\n')
        self.history_entry('very-old-history', snapshots[5])
        self.history_entry('another-record', snapshots[6])
        # The oldest record must not be dropped by a UI pagination/read limit.
        os.utime(self.history / 'very-old-history.json', (1, 1))
        target = snapshot_store.verify(snapshots[4])
        rollback._prune_after_success(self.ctx, snapshots[3], (target,))
        protected = set(snapshots[:7]) | {snapshots[-1]}
        self.assertEqual({path for path in snapshots if path.exists()}, protected)
        self.assertEqual(self.err.getvalue(), '')
        self.assertIn('Old snapshots removed: 24', self.out.getvalue())

    def test_zero_keep_protects_nested_history_and_unowned_names(self):
        snapshots = self.snapshots(4)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        self.history.mkdir(parents=True)
        (self.history / 'nested.json').write_text(json.dumps({'other': [0, {'path': str(snapshots[1])}]}))
        (self.history / 'README.txt').write_text('not a history record')
        unowned = self.folder / 'user-backup'
        unowned.mkdir()
        (unowned / 'MANIFEST').write_text('not ours')
        alias = self.folder / '20200101-000000-999'
        alias.symlink_to(unowned, target_is_directory=True)
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(snapshots[0].exists())
        self.assertTrue(snapshots[1].exists())
        self.assertFalse(snapshots[2].exists())
        self.assertTrue(snapshots[3].exists())  # keep=0 cannot remove the newest point
        self.assertTrue(unowned.is_dir())
        self.assertTrue(alias.is_symlink())

    def test_invalid_keep_uses1_and_huge_numeric_keep_never_deletes(self):
        snapshots = self.snapshots(24)
        self.env['KD_SNAPSHOT_KEEP'] = 'invalid'
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertEqual(sum(path.exists() for path in snapshots), 2)
        self.env['KD_SNAPSHOT_KEEP'] = '9' * 5000
        before = set(self.folder.iterdir())
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertEqual(set(self.folder.iterdir()), before)

    def test_corrupt_doomed_snapshot_prevents_all_deletions(self):
        snapshots = self.snapshots(3)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        (snapshots[1] / 'files/opt/etc/nfqws2/nfqws2.conf').write_bytes(b'corrupted')
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        self.assertIn('WARNING:', self.err.getvalue())

    def test_corrupt_or_symlink_history_fails_closed_without_deleting(self):
        snapshots = self.snapshots(3)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        record = self.history_entry('record', snapshots[1])
        record.write_bytes(b'{broken-json')
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        record.unlink()
        record.write_text('{"snapshot":' + json.dumps(str(snapshots[1])) + ',"snapshot":"other"}')
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        record.unlink()
        outside = self.root / 'outside-history.json'
        outside.write_text('{}')
        record.symlink_to(outside)
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        self.assertEqual(outside.read_text(), '{}')

    def test_history_file_count_bytes_and_pointer_targets_are_bounded(self):
        snapshots = self.snapshots(3)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        self.history_entry('one', snapshots[1])
        self.history_entry('two', snapshots[1])
        with mock.patch.object(rollback, 'MAX_HISTORY_RECORDS', 1):
            rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        with mock.patch.object(rollback, 'MAX_HISTORY_BYTES', 1):
            rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        Path(self.paths.baseline_pointer).write_text(str(self.root / 'outside-snapshot') + '\n')
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        Path(self.paths.baseline_pointer).unlink()
        rollback._prune_after_success(self.ctx, self.root / 'outside-current')
        self.assertTrue(all(path.exists() for path in snapshots))
        with mock.patch.object(rollback, 'MAX_RETENTION_ENTRIES', 1):
            rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))

    def test_large_history_structure_and_file_size_cancel_cleanup(self):
        snapshots = self.snapshots(3)
        self.env['KD_SNAPSHOT_KEEP'] = '0'
        record = self.history_entry('large', snapshots[1])
        record.write_text(json.dumps([0] * 65537))
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))
        record.write_bytes(b' ' * 524289)
        rollback._prune_after_success(self.ctx, snapshots[0])
        self.assertTrue(all(path.exists() for path in snapshots))

    def test_no_store_noop_and_guard_refuses_different_owned_root(self):
        rollback._prune_after_success(self.ctx, self.folder / 'unused')
        self.assertEqual(self.err.getvalue(), '')
        self.ctx.paths = self.paths.replace(snapshot_root=str(self.root))
        rollback._prune_after_success(self.ctx, self.root / 'unused')
        self.assertTrue(Path(self.paths.nfqws_conf).exists())
        self.assertIn('WARNING:', self.err.getvalue())

    def test_cleanup_runs_after_commit_and_cannot_rollback_restored_state(self):
        saved = SimpleNamespace(metadata=SimpleNamespace(scope='standalone'))
        rescue = self.folder / '20260101-000000-1'
        self.ctx.paths = self.paths
        events = []
        tx = transaction.Transaction(self.ctx)
        self.ctx.resolved = SimpleNamespace(standalone=True)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(rollback, 'resolve_targets', return_value=[saved]))
            stack.enter_context(mock.patch.object(rollback, 'capture', return_value=rescue))
            stack.enter_context(mock.patch.object(rollback.relay_restore, 'capture', return_value=None))
            stack.enter_context(mock.patch.object(rollback, 'restore', side_effect=lambda *_: events.append('restored')))
            def prune(_ctx, _current, _targets):
                self.assertFalse(tx.changed)
                events.append('prune')
                raise ValueError('injected invalid cleanup inventory')
            stack.enter_context(mock.patch.object(rollback, '_prune_snapshots', side_effect=prune))
            rollback.operation(tx)
        self.assertEqual(events, ['restored', 'prune'])
        self.assertFalse(tx.changed)
        self.assertIn('rollback complete', self.out.getvalue())
        self.assertIn('WARNING:', self.err.getvalue())

"""Age-based metadata rotation on disposable roots; no services or router."""
import datetime as dt
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.common import retention
from kdn.engine import config, console, record_retention as records, rollback_ops, snapshot_store
from panel_fixtures import make_candidate
from target_fixture import supported_environment

NOW = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc).timestamp()


class RecordRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        supported_environment(env)
        self.paths = config.EnginePaths.from_environ(env)
        self.ctx = SimpleNamespace(paths=self.paths, environ=env, options=SimpleNamespace(confirmed=True),
                                   console=console.Console(io.StringIO(), io.StringIO()))
        self.clock = mock.patch.object(retention.time, 'time', return_value=NOW)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)

    def capture(self, focused=False):
        def formatted(fmt, *args):
            return '2026-01-01T00:00:00Z' if fmt == '%Y-%m-%dT%H:%M:%SZ' else '20260101-000000'
        with mock.patch.object(snapshot_store.time, 'strftime', side_effect=formatted):
            return snapshot_store.create(self.paths, purpose='record-age-test', focused=focused,
                xkeen_version='2.1', metadata=(('NFQWS_RUNNING', '0'),) if focused else ())

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def entry(self, number, snapshot='', **changes):
        return {'job_id': f'{number:016x}', 'status': 'completed', 'snapshot': str(snapshot),
                'created_utc': '2026-09-01T00:00:00Z', 'finished_utc': '2026-09-01T00:00:00Z', **changes}

    def test_one_snapshot_prevents_metadata_cleanup(self):
        self.capture()
        data = self.entry(1)
        source = self.write('opt/etc/xkeen-web/history/' + data['job_id'] + '.json', data)
        self.assertEqual(records.expire_history(self.paths), (0, 0))
        self.assertTrue(source.exists())
        self.capture()
        self.assertEqual(records.expire_history(self.paths), (1, 0))
        self.assertFalse(source.exists())

    def test_history_trash_undo_window_and_snapshot_reference_protection(self):
        old, current = self.capture(), self.capture()
        data = self.entry(1, old)
        source = self.write('opt/etc/xkeen-web/history/' + data['job_id'] + '.json', data)
        original = source.read_bytes()
        rollback_ops._prune_snapshots(self.ctx, current)
        self.assertFalse(source.exists())
        trash = self.root / 'opt/etc/xkeen-web/record-trash/history'
        [archived] = list(trash.glob('*.json'))
        self.assertEqual(archived.read_bytes(), original)
        self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
        self.assertEqual(trash.stat().st_mode & 0o777, 0o700)
        self.assertTrue(old.exists(), 'fresh trash must retain its rollback reference')
        self.now.return_value = NOW + 31 * 86400
        rollback_ops._prune_snapshots(self.ctx, current)
        self.assertFalse(archived.exists())
        self.assertFalse(old.exists())
        self.assertTrue(current.exists())

    def test_active_baseline_latest_and_unknown_records_stay(self):
        baseline, latest = self.capture(), self.capture()
        Path(self.paths.baseline_pointer).write_text(str(baseline))
        for number, changes in ((1, {'snapshot': str(baseline)}), (2, {'snapshot': str(latest)}),
                                (3, {'status': 'running'}), (4, {'finished_utc': 'unknown'})):
            data = self.entry(number, **changes)
            self.write('opt/etc/xkeen-web/history/' + data['job_id'] + '.json', data)
        self.assertEqual(records.expire_history(self.paths), (0, 0))
        self.assertEqual(len(list((self.root / 'opt/etc/xkeen-web/history').glob('*.json'))), 4)

    def test_bad_record_or_budget_prevents_complete_batch(self):
        self.capture()
        self.capture()
        data = self.entry(1)
        source = self.write('opt/etc/xkeen-web/history/' + data['job_id'] + '.json', data)
        bad = source.parent / ('f' * 16 + '.json')
        bad.write_text('{broken-private-data')
        with self.assertRaises(ValueError):
            records.expire_history(self.paths)
        self.assertTrue(source.exists())
        bad.write_text(json.dumps(self.entry(15)))
        with mock.patch.object(records, 'MAX_RECORDS', 1):
            with self.assertRaises(ValueError):
                records.expire_history(self.paths)
        self.assertTrue(source.exists())

    def test_versions_keep_active_newest_and_recent_trash(self):
        self.capture(True)
        old = make_candidate('youtube', format=1, report={}, family='old')
        active = make_candidate('youtube', format=1, report={}, family='active')
        newest = make_candidate('youtube', format=1, report={}, family='newest')
        base = 'opt/etc/nfqws2/profile-versions/youtube/'
        old_name = f'20260901T000000Z-{old["candidate_id"]}-replaced-1.json'
        old_file = self.write(base + old_name, old)
        active_file = self.write(base + f'20260902T000000Z-{active["candidate_id"]}-applied-2.json', active)
        newest_file = self.write(base + f'20261103T000000Z-{newest["candidate_id"]}-applied-3.json', newest)
        self.write('opt/etc/nfqws2/imported-profiles/youtube.json', active)
        trash = 'opt/etc/xkeen-web/record-trash/versions/youtube/'
        aged_trash = self.write(trash + f'{int(NOW-31*86400)}-12345678-' + old_name, old)
        fresh_trash = self.write(trash + f'{int(NOW-86400)}-12345678-' + old_name, old)
        self.assertEqual(records.expire_versions(self.paths), 0, 'one focused snapshot is not enough')
        self.capture(True)
        self.assertEqual(records.expire_versions(self.paths), 2)
        self.assertFalse(old_file.exists())
        self.assertFalse(aged_trash.exists())
        self.assertTrue(all(p.exists() for p in (active_file, newest_file, fresh_trash)))

    def test_hardlinked_metadata_is_not_moved_or_chmodded(self):
        self.capture()
        self.capture()
        data = self.entry(1)
        source = self.write('opt/etc/xkeen-web/history/' + data['job_id'] + '.json', data)
        linked = self.root / 'external-copy.json'
        os.link(source, linked)
        before = linked.read_bytes(), linked.stat().st_mode
        with self.assertRaises(ValueError):
            records.expire_history(self.paths)
        self.assertTrue(source.exists())
        self.assertEqual((linked.read_bytes(), linked.stat().st_mode), before)


    def test_pending_state_protects_versions_for_every_caller_until_clear(self):
        old = make_candidate('youtube', format=1, report={}, family='old')
        newest = make_candidate('youtube', format=1, report={}, family='newest')
        base = 'opt/etc/nfqws2/profile-versions/youtube/'
        old_file = self.write(base + f'20260901T000000Z-{old["candidate_id"]}-replaced-1.json', old)
        self.write(base + f'20261103T000000Z-{newest["candidate_id"]}-applied-3.json', newest)
        self.capture(True)
        self.capture(True)
        state = self.write('opt/etc/xkeen-web/automation-state.json', {'transaction': {'phase': 'recovery-failed'}})
        self.assertEqual(records.expire_versions(self.paths), 0)
        self.assertTrue(old_file.exists())
        state.write_text('{broken')
        self.assertEqual(records.expire_versions(self.paths), 0)
        self.assertTrue(old_file.exists())
        state.write_text('{"transaction": null}')
        self.assertEqual(records.expire_versions(self.paths), 1)
        self.assertFalse(old_file.exists())

"""30-day retention: real disposable snapshots, no service/network changes."""
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
from kdn.engine import config, console, import_ops, rollback_ops, snapshot_store
from target_fixture import supported_environment

NOW = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc).timestamp()


def stamp(days):
    return dt.datetime.fromtimestamp(NOW - days * 86400, dt.timezone.utc).isoformat()


class AgePolicyTests(unittest.TestCase):
    def test_strict_boundary_unknown_dates_and_boot_clock(self):
        for value, expected in ((stamp(31), True), (stamp(30), False), (stamp(29), False),
                                (stamp(-1), False), ('', False), ('bad', False),
                                ('2026-01-01T00:00:00', False), ('1970-01-01T00:00:00Z', False),
                                ('2026-01-01T00:00:00+03:00', False)):
            with self.subTest(value=value):
                self.assertEqual(retention.older_than_limit(value, now=NOW), expected)
        for now in (0, float('nan'), float('inf'), 'bad'):
            self.assertFalse(retention.older_than_limit(stamp(31), now=now))

    def test_minimum_cannot_be_zero_or_disabled_by_bad_value(self):
        for value, expected in (('0', 1), ('1', 1), ('2', 2), ('invalid', 1),
                                ('-1', 1), ('１２', 1), ('9' * 5000, 16384)):
            with self.subTest(value=str(value)[:10]):
                self.assertEqual(retention.keep_count(value), expected)


class SnapshotAgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        supported_environment(env)
        self.ctx = SimpleNamespace(paths=config.EnginePaths.from_environ(env), environ=env,
            options=SimpleNamespace(confirmed=True), console=console.Console(io.StringIO(), io.StringIO()))
        config_file = Path(self.ctx.paths.nfqws_conf)
        config_file.parent.mkdir(parents=True)
        config_file.write_bytes(b'# disposable config\n')
        patch = mock.patch.object(retention.time, 'time', return_value=NOW)
        patch.start()
        self.addCleanup(patch.stop)

    def capture(self, created, focused):
        def formatted(fmt, *args):
            return created if fmt == '%Y-%m-%dT%H:%M:%SZ' else '20260101-000000'
        with mock.patch.object(snapshot_store.time, 'strftime', side_effect=formatted):
            return snapshot_store.create(self.ctx.paths, purpose='age-test', xkeen_version='2.1',
                focused=focused, metadata=(('NFQWS_RUNNING', '0'),) if focused else ())

    def prune(self, current, focused):
        if focused:
            import_ops._prune(self.ctx, current)
        else:
            rollback_ops._prune_snapshots(self.ctx, current)

    def test_only_older_than30_days_is_removed(self):
        for focused in (False, True):
            with self.subTest(focused=focused):
                old, boundary, young, future = [self.capture(stamp(days), focused) for days in (31, 30, 29, -1)]
                self.prune(young, focused)
                self.assertFalse(old.exists())
                self.assertTrue(all(p.exists() for p in (boundary, young, future)))

    def test_last_old_snapshot_survives_and_zero_keep_does_not_override_it(self):
        self.ctx.environ.update(KD_SNAPSHOT_KEEP='0', KD_IMPORT_SNAPSHOT_KEEP='0')
        for focused in (False, True):
            with self.subTest(focused=focused):
                older = self.capture(stamp(45), focused)
                current = self.capture(stamp(44), focused)
                self.prune(current, focused)
                self.assertFalse(older.exists())
                self.prune(current, focused)
                self.assertTrue(current.exists())
                snapshot_store.verify(current, focused=focused)

    def test_missing_or_unknown_date_stays(self):
        for focused in (False, True):
            with self.subTest(focused=focused):
                unknown = self.capture('unknown', focused)
                current = self.capture(stamp(40), focused)
                self.prune(current, focused)
                self.assertTrue(unknown.exists())
                self.assertTrue(current.exists())

    def test_corrupt_doomed_snapshot_aborts_before_any_delete(self):
        for focused in (False, True):
            with self.subTest(focused=focused):
                first, corrupt, current = [self.capture(stamp(40), focused) for _ in range(3)]
                payload = corrupt / ('nfqws2/nfqws2.conf' if focused else 'files/opt/etc/nfqws2/nfqws2.conf')
                payload.write_bytes(b'tampered payload')
                with self.assertRaises(ValueError):
                    self.prune(current, focused)
                self.assertTrue(all(p.exists() for p in (first, corrupt, current)))

    def test_trash_reference_protects_old_focused_snapshot(self):
        full_old = self.capture(stamp(50), False)
        old = self.capture(stamp(50), True)
        full_current = self.capture(stamp(40), False)
        current = self.capture(stamp(40), True)
        self.assertEqual(old.name, full_old.name)
        trash = self.root / 'opt/etc/xkeen-web/record-trash/history'
        trash.mkdir(parents=True)
        (trash / 'old.json').write_text(json.dumps({'snapshot': str(old)}))
        self.prune(full_current, False)
        self.assertFalse(full_old.exists())  # same ID in another store is not the referenced snapshot
        self.prune(current, True)
        self.assertTrue(old.exists())
        self.assertTrue(current.exists())

    def test_deep_trash_record_cancels_focused_gc_without_failing_working_state(self):
        old = self.capture(stamp(50), True)
        current = self.capture(stamp(40), True)
        trash = self.root / 'opt/etc/xkeen-web/record-trash/history'
        trash.mkdir(parents=True)
        (trash / 'old.json').write_text('[' * 2000 + '0' + ']' * 2000)
        before = Path(self.ctx.paths.nfqws_conf).read_bytes()
        with mock.patch.object(rollback_ops.json, 'loads', side_effect=RecursionError('nested record')):
            import_ops._prune_after_success(self.ctx, current)
        self.assertTrue(old.exists())
        self.assertTrue(current.exists())
        self.assertEqual(Path(self.ctx.paths.nfqws_conf).read_bytes(), before)


    def test_pending_or_ambiguous_state_protects_focused_source_until_clear(self):
        old, current = [self.capture(stamp(45), True) for _ in range(2)]
        pointer = Path(self.ctx.paths.state_root) / 'latest-nfqws-import.ptr'
        snapshot_store.publish_pointer(self.ctx.paths, pointer, current, focused=True)
        state = self.root / 'opt/etc/xkeen-web/automation-state.json'
        state.parent.mkdir(parents=True)
        for content in (json.dumps({'status': 'recovery-failed', 'transaction': {'original_source': str(old)}}),
                        '{broken', '{"transaction": {}, "transaction": null}', '[]'):
            state.write_text(content)
            self.prune(current, True)
            self.assertTrue(old.exists())
        state.write_text('{"transaction": null}')
        self.prune(current, True)
        self.assertFalse(old.exists())
        self.assertTrue(current.exists())

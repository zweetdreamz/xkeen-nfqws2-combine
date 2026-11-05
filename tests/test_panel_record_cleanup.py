"""UI record cleanup never deletes an active profile or route snapshot."""

import json
from pathlib import Path
import stat
import tempfile
import unittest

import panel_harness
from panel_fixtures import make_candidate, make_report


class RecordCleanupTests(panel_harness.PanelTestCase):
    ns_name = "record_cleanup_test"

    def test_history_list_is_bounded_metadata_not_full_recovery_payload(self):
        self.history.mkdir()
        job_id = '0123456789abcdef'
        path = self.history / (job_id + '.json')
        data = {'job_id': job_id, 'operation': 'switch', 'service': 'youtube', 'status': 'completed',
                'created_utc': '2026-01-01T00:00:00Z', 'snapshot': '',
                'before_routes': {'youtube': 'direct', 'credentials': 'PRIVATE_SENTINEL'},
                'output_tail': 'x' * 10000 + 'done', 'error': 'e' * 10000,
                'source': 'PRIVATE_SENTINEL', 'output': 'SECRET_OUTPUT' * 10000}
        path.write_text(json.dumps(data), encoding='utf-8')
        before = path.read_bytes()
        [row] = self.panel['route_history']()
        self.assertNotIn('source', row)
        self.assertNotIn('output', row)
        self.assertEqual(row['before_routes'], {'youtube': 'direct'})
        self.assertEqual(len(row['output_tail']), 1024)
        self.assertTrue(row['output_tail'].endswith('done'))
        self.assertEqual(len(row['error']), 512)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.panel['read_history_item'](job_id), data)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.panel = cls.ns

    def setUp(self):
        (panel_harness.ROOT / "tests" / ".generated").mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=panel_harness.ROOT / "tests" / ".generated")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.history = self.root / "history"
        self.versions = self.root / "versions"
        self.imported = self.root / "imported"
        self.trash = self.root / "trash"
        self.patch(
            ROUTE_HISTORY_DIR=self.history,
            PROFILE_VERSION_DIR=self.versions,
            IMPORTED_PROFILE_DIR=self.imported,
            RECORD_TRASH_DIR=self.trash,
            route_active=lambda: False,
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
        )

    def test_history_moves_to_trash_but_snapshot_stays(self):
        job_id = "0123456789abcdef"
        self.history.mkdir()
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        path = self.history / f"{job_id}.json"
        path.write_text(json.dumps({"job_id": job_id, "snapshot": str(snapshot)}), encoding="utf-8")
        result = self.panel["delete_history_record"](job_id)
        self.assertTrue(result["snapshot_preserved"])
        self.assertFalse(path.exists())
        self.assertTrue(snapshot.is_dir())
        self.assertEqual(len(list((self.trash / "history").glob("*.json"))), 1)
        self.assertEqual(self.panel["route_history"](), [])

    def test_trash_directories_are_private(self):
        # A record in the trash is never destroyed: its directories are 0o700 when created and when they were looser.
        loose = self.trash / "history"
        loose.mkdir(parents=True)
        for directory in (self.trash, loose):
            directory.chmod(0o755)
        self.history.mkdir()
        for name, kind, service in (("a.json", "history", ""), ("b.json", "versions", "youtube")):
            record = self.history / name
            record.write_text("{}", encoding="utf-8")
            archived = self.panel["archive_record"](record, kind, service)
            self.assertEqual(archived.parent, self.trash.joinpath(kind, service))
            self.assertFalse(record.exists())
        for directory in (self.trash, loose, self.trash / "versions", self.trash / "versions" / "youtube"):
            with self.subTest(directory=str(directory.relative_to(self.root))):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_running_job_blocks_cleanup(self):
        with self.patched(route_active=lambda: True):
            with self.assertRaises(RuntimeError):
                self.panel["delete_history_record"]("0123456789abcdef")

    def test_active_version_is_protected_and_old_version_is_recoverable(self):
        service = "discord-tcp"
        active = self.panel["validate_report"](make_report(service))
        old_candidate = make_candidate(service, family="older-family")
        old = self.panel["validate_report"](make_report(service, candidate=old_candidate))
        self.imported.mkdir()
        (self.imported / f"{service}.json").write_text(json.dumps(active), encoding="utf-8")
        directory = self.versions / service
        directory.mkdir(parents=True)
        active_id = f"20261027T000000Z-{active['candidate_id']}-applied-1"
        old_id = f"20260101T000000Z-{old['candidate_id']}-replaced-1"
        (directory / f"{active_id}.json").write_text(json.dumps(active), encoding="utf-8")
        (directory / f"{old_id}.json").write_text(json.dumps(old), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "активную версию"):
            self.panel["delete_profile_version"](service, active_id)
        self.assertTrue((directory / f"{active_id}.json").is_file())
        self.assertTrue(self.panel["delete_profile_version"](service, old_id)["archived"])
        self.assertFalse((directory / f"{old_id}.json").exists())
        self.assertEqual(len(list((self.trash / "versions" / service).glob("*.json"))), 1)
        self.assertTrue((directory / f"{active_id}.json").is_file())


if __name__ == "__main__":
    unittest.main()

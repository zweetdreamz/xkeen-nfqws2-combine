"""Frozen oracles preserve all bytes except explicitly variable fixture paths."""

import importlib.util
import gzip
from pathlib import Path
import tempfile
from unittest import TestCase, mock


SPEC = importlib.util.spec_from_file_location(
    "golden_record", Path(__file__).with_name("engine-golden-record.py")
)
RECORDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORDER)


class GoldenRecordTests(TestCase):
    def test_snapshot_fixture_paths_are_stable_before_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary, 'opt/etc/keenetic-discord-nfqws2')
            source = state / 'snapshots/20261030-120000-123'
            source.mkdir(parents=True)
            pointer = state / 'baseline.ptr'
            pointer.write_bytes(str(source).encode() + b'\n')
            (source / 'STATE.tsv').write_bytes(b'opaque\xff')
            RECORDER.stabilise_snapshots(temporary)
            destination = state / 'snapshots/fixture-0000'
            self.assertEqual(pointer.read_bytes(), str(destination).encode() + b'\n')
            self.assertEqual((destination / 'STATE.tsv').read_bytes(), b'opaque\xff')
            self.assertFalse(source.exists())
            RECORDER.stabilise_snapshots(temporary)
            self.assertEqual(pointer.read_bytes(), str(destination).encode() + b'\n')

    def test_only_explicit_root_and_work_pid_are_normalised(self):
        raw = b"/tmp/root.a/x\xff\r\n/tmp/rootXa/x 123 keenetic-discord-nfqws2.456"
        self.assertEqual(
            RECORDER.normalise(raw, "/tmp/root.a"),
            b"@ROOT@/x\xff\r\n/tmp/rootXa/x 123 keenetic-discord-nfqws2.PID",
        )

    def test_record_then_check_is_exact_and_missing_or_changed_oracle_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "source")
            target = Path(temporary, "oracle", "status.out")
            source.write_bytes(b"/root/a\xff\n")
            with mock.patch("sys.argv", ["record", "record", "/root", str(source), str(target)]):
                self.assertEqual(RECORDER.main(), 0)
            compressed = target.with_suffix('.out.gz')
            self.assertEqual(gzip.decompress(compressed.read_bytes()), b"@ROOT@/a\xff\n")
            with mock.patch("sys.argv", ["record", "check", "/root", str(source), str(target)]):
                self.assertEqual(RECORDER.main(), 0)
                source.write_bytes(b"/root/a\xff")
                with mock.patch("sys.stderr"):
                    self.assertEqual(RECORDER.main(), 1)
                    compressed.unlink()
                    self.assertEqual(RECORDER.main(), 1)
                self.assertFalse(target.exists())

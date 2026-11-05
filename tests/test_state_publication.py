"""Shared router worker helpers; disposable paths, no services/network."""
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from kdn.common import fsutil, timeutil


class StatePublicationTests(unittest.TestCase):
    def test_metadata_enumeration_budget_and_link_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / 'records'
            self.assertEqual(fsutil.bounded_files(directory), [])
            directory.mkdir()
            (directory / 'a.json').write_text('{}')
            (directory / 'b.txt').write_text('not a record')
            self.assertEqual(fsutil.bounded_files(directory), [directory / 'a.json'])
            with self.assertRaisesRegex(ValueError, 'budget'):
                fsutil.bounded_files(directory, maximum=1)
            link = Path(folder) / 'alias'
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                fsutil.bounded_files(link)
            self.assertTrue((directory / 'a.json').is_file())

    def test_json_encoding_and_permissions_preserve_worker_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private/state.json'
            data = {'text': 'привет', 'n': 1}
            fsutil.atomic_json(path, data, parent_mode=0o700)
            self.assertEqual(path.read_bytes(), (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode())
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_size_and_serialization_failures_do_not_publish_or_leave_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.json'
            fsutil.atomic_json(path, {'old': 1})
            before = path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, 'budget'):
                fsutil.atomic_json(path, {'text': 'я' * 100}, maximum=20, too_large='budget')
            with self.assertRaises(TypeError):
                fsutil.atomic_json(path, {'bad': object()})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_replace_failure_preserves_previous_state(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.json'
            fsutil.atomic_json(path, {'old': 1})
            before = path.read_bytes()
            with mock.patch.object(fsutil.os, 'replace', side_effect=OSError('injected')):
                with self.assertRaises(OSError):
                    fsutil.atomic_json(path, {'new': 1})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_both_timestamp_contracts_remain_available(self):
        self.assertRegex(timeutil.utc_now(), r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        precise = timeutil.utc_now_iso()
        self.assertTrue(precise.endswith('+00:00'))
        self.assertEqual(dt.datetime.fromisoformat(precise).utcoffset(), dt.timedelta(0))

    def test_atomic_text_preserves_text_contract_and_closes_failed_fdopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config'
            fsutil.atomic_text(path, 'привет\n')
            self.assertEqual(path.read_bytes(), ('привет' + os.linesep).encode('utf-8'))
            before = path.read_bytes()
            for publish, value in ((fsutil.atomic_text, 'new'), (fsutil.atomic_bytes, b'new')):
                with self.subTest(publish=publish.__name__):
                    with mock.patch.object(fsutil.os, 'fdopen', side_effect=OSError('fdopen failure')):
                        with mock.patch.object(fsutil.os, 'close', wraps=os.close) as close:
                            with self.assertRaisesRegex(OSError, 'fdopen failure'):
                                publish(path, value)
                            self.assertEqual(close.call_count, 1)
                            descriptor = close.call_args.args[0]
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(list(path.parent.iterdir()), [path])

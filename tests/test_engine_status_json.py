"""One collected status drives both text and JSON, including lock and safe blocks."""
import json
import os
import tempfile
import unittest
import ast
from pathlib import Path
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import status


class JsonTests(unittest.TestCase):
    def test_only_json_path_imports_lock_and_collects_blocks(self):
        tree = ast.parse(Path(status.__file__).read_text(encoding='utf-8'))
        imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                   and node.module == 'kdn.common' and any(alias.name == 'lock' for alias in node.names)]
        self.assertEqual(len(imports), 1)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_json_lock')
        self.assertIn(imports[0], function.body)
        fixture = engine_scenarios.build('fresh')
        with mock.patch.object(status, '_json_lock', side_effect=AssertionError('text imported lock')), \
             mock.patch.object(status.statusblocks, 'xkeen_block', side_effect=AssertionError('text queried JSON blocks')):
            result = engine_run.run_mode('status', ['--status'], fixture)
        self.assertEqual(result.rc, 0)

    def test_document_matches_text_fields_and_snapshots_all_scenarios(self):
        for name in engine_scenarios.names():
            fixture = engine_scenarios.build(name)
            with self.subTest(name=name):
                text = engine_run.run_mode('status', ['--status'], fixture)
                result = engine_run.run_mode('status', ['--status', '--json'], fixture)
                if name == 'no-xkeen-binary':
                    self.assertEqual((text.rc, result.rc), (2, 2))
                    doc = json.loads(result.out)
                    self.assertEqual(doc['error_code'], 'unsupported_xkeen')
                    self.assertFalse(doc['supported'])
                    self.assertEqual(doc['fields'], {})
                    self.assertIn('XKeen 2.1+', text.err)
                    continue
                self.assertEqual((result.rc, result.err), (text.rc, text.err))
                self.assertTrue(result.out.startswith('{\n') and result.out.endswith('\n'))
                doc = json.loads(result.out)
                self.assertEqual(doc['text'], text.out)
                self.assertEqual(doc['schema'], 1)
                self.assertEqual(['%s=%s' % pair for pair in doc['fields'].items()], text.out.split('State directory:', 1)[0].split('\n')[:-1])
                self.assertIn('lock', doc)
                if name == 'no-conf':
                    self.assertNotIn('proxy_outbound', doc['fields'])
                if name.startswith('snapshots-') and name not in ('snapshots-baseline', 'snapshots-all', 'snapshots-two-lines'):
                    self.assertIsNone(doc['snapshots']['baseline'])

    def test_lock_states_and_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            for pid in (None, '', str(os.getpid()), '999999999'):
                lockdir = fixture.path('/opt/tmp/keenetic-discord-nfqws2.lock')
                if pid is not None:
                    lockdir.mkdir(exist_ok=True)
                    (lockdir / 'pid').write_text(pid)
                doc = json.loads(engine_run.run_python(['--status', '--json'], fixture).out)
                self.assertEqual(doc['lock']['exists'], pid is not None)
                self.assertEqual(doc['lock']['alive'], pid == str(os.getpid()))
            with mock.patch.object(status.system, 'is_router', return_value=False):
                result = engine_run.run_python(['--status', '--json'], fixture)
            self.assertEqual((result.rc, result.out), (1, ''))
            self.assertIn('ERROR:', result.err)

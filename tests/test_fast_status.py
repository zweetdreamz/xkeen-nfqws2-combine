"""Fast advisory read cannot invoke the full engine status or version probe."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


class FastStatusTests(unittest.TestCase):
    def handler(self, processes):
        source = Path(__file__).resolve().parents[1] / 'tools/router/kdn/web/api/read_routes.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'get_fast_status')
        proc = Mock()
        proc.glob.return_value = processes
        engine = SimpleNamespace(STATUS_ROUTE_KEYS={'youtube':'youtube_route'},
            current_routes_fast=lambda: {'youtube':'zapret'})
        scope = {'Path':lambda _:proc, 'engine':engine,
                 'router':SimpleNamespace(json_response=lambda status,payload:payload)}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), scope)
        return scope['get_fast_status'](None)

    def test_running(self):
        process = Mock()
        process.__truediv__ = Mock(return_value=Mock(read_text=lambda:'xray\n'))
        result = self.handler([process])
        self.assertEqual(result['xkeen_runtime'], 'running')
        self.assertEqual(result['youtube_route'], 'zapret')
        self.assertTrue(result['advisory'])

    def test_stopped(self):
        process = Mock()
        process.__truediv__ = Mock(return_value=Mock(read_text=lambda:'python3\n'))
        self.assertEqual(self.handler([process])['xkeen_runtime'], 'stopped')

    def test_no_procfs_is_unknown(self):
        self.assertEqual(self.handler([])['xkeen_runtime'], 'unknown')

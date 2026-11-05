"""Adapter boundaries: local fakes only, no services or network."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from kdn.common import paths, proc


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools/router' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkerHelperContracts(unittest.TestCase):
    def test_pid_adapter_preserves_invalid_and_missing_cases(self):
        job = load('helper_job', 'zapret_autotune_job.py')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'pid'
            self.assertIsNone(job.read_pid(path))
            for value, expected in ((b'42\n', 42), (b'1', None), (b'0', None),
                                    (b'-4', None), (b'abc', None), (b'\xff', None)):
                with self.subTest(value=value):
                    path.write_bytes(value)
                    self.assertEqual(job.read_pid(path), expected)
                    self.assertEqual(job.read_pid(path), proc.read_job_pid(path))

    def test_diagnostics_env_and_result_contract(self):
        diagnostic = load('helper_diagnostics', 'xkeen_diagnostics.py')
        with mock.patch.dict(os.environ, {'PATH': 'host-only', 'HELPER_TEST': 'kept'}):
            with mock.patch.object(diagnostic.subprocess, 'run',
                                   return_value=subprocess.CompletedProcess(['fake'], 0, b' ok\n')) as run:
                self.assertEqual(diagnostic.run(['fake'], 7, {'PATH': 'explicit'}),
                                 {'ok': True, 'code': 0, 'output': 'ok'})
                self.assertEqual(run.call_args.kwargs['env']['PATH'], 'explicit')
                self.assertEqual(run.call_args.kwargs['env']['HELPER_TEST'], 'kept')
                self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
                self.assertEqual(os.environ['PATH'], 'host-only')
                diagnostic.run(['fake'], 7)
                self.assertEqual(run.call_args.kwargs['env']['PATH'], proc.ROUTER_PATH)
            diagnostic.CANCELLED.set()
            try:
                with mock.patch.object(diagnostic.subprocess, 'run') as run:
                    with self.assertRaises(InterruptedError):
                        diagnostic.run(['fake'], 1)
                    run.assert_not_called()
            finally:
                diagnostic.CANCELLED.clear()

    def test_worker_test_roots_do_not_authorize_engine_or_panel_root(self):
        # Worker fixtures have separate namespaces; no translation into a live bypass.
        for key in ('KD_TUNER_TEST_ROOT', 'KD_DIAGNOSTICS_TEST_ROOT'):
            with self.subTest(key=key):
                env = {key: '/fixture'}
                self.assertEqual(paths.test_root(env), '')
                env['KD_TEST_ROOT'] = '/fixture'
                with self.assertRaises(RuntimeError):
                    paths.test_root(env)

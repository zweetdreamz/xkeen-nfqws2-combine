"""CPU deltas and reclaimable memory using synthetic procfs counters."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('resource_metrics', Path(__file__).resolve().parents[1]
    / 'tools/router/kdn/web/domain/metrics.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MetricsTests(unittest.TestCase):
    def setUp(self):
        M._previous = M._cached = None
        M._sampled_at = 0

    def test_cpu_delta_memory_and_shared_cache(self):
        memory = 'MemTotal: 524288 kB\nMemAvailable: 393216 kB\n'
        with patch.object(M.Path, 'read_text', side_effect=[
                'cpu 10 0 10 80 0 0 0 0 999 999\n', memory,
                'cpu 20 0 20 160 0 0 0 0 999 999\n', memory]) as read, \
                patch.object(M.time, 'monotonic', side_effect=[1, 1.5, 3]):
            first = M.snapshot()
            self.assertIsNone(first['cpu_percent'])
            self.assertEqual(M.snapshot(), first)
            second = M.snapshot()
            self.assertEqual(read.call_count, 4)
        self.assertEqual(second['cpu_percent'], 20)
        self.assertEqual(second['memory'], {'used_mib':128, 'total_mib':512, 'percent':25})

    def test_unavailable_procfs(self):
        with patch.object(M.Path, 'read_text', side_effect=OSError):
            self.assertEqual(M.snapshot(), {'ok':True, 'cpu_percent':None, 'memory':None})

    def test_old_kernel_memory(self):
        with patch.object(M.Path, 'read_text', side_effect=['cpu 1 0 0 1\n',
                'MemTotal: 1024 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 200 kB\nSReclaimable: 100 kB\nShmem: 50 kB\n']):
            self.assertEqual(M.snapshot()['memory']['percent'], 56.1)

"""Bounded reference workers preserve order, failures and caller-owned setup."""

import threading
from unittest import TestCase, mock

import engine_run


class ParallelReferenceTests(TestCase):
    def test_all_cases_run_once_in_parallel_but_results_stay_in_input_order(self):
        barrier = threading.Barrier(4, timeout=5)
        seen = []
        lock = threading.Lock()
        caller = threading.get_ident()

        def cases():
            for index in range(4):
                self.assertEqual(threading.get_ident(), caller)
                yield ([str(index)], object(), {'case': str(index)})

        def run(args, fixture, extra):
            with lock:
                seen.append((args[0], threading.get_ident(), extra))
            barrier.wait()
            return engine_run.Result(int(args[0]), args[0], 'stderr:' + args[0])

        with mock.patch.object(engine_run, 'run_legacy', side_effect=run):
            results = engine_run.legacy_results(cases())
        self.assertEqual([item.rc for item in results], list(range(4)))
        self.assertEqual([item.err for item in results], ['stderr:' + str(i) for i in range(4)])
        self.assertEqual(sorted(item[0] for item in seen), ['0', '1', '2', '3'])
        self.assertTrue(all(item[1] != caller for item in seen))
        self.assertTrue(all(item[2] == {'case': item[0]} for item in seen))

    def test_worker_exception_is_not_swallowed(self):
        with mock.patch.object(engine_run, 'run_legacy', side_effect=RuntimeError('reference failed')):
            with self.assertRaisesRegex(RuntimeError, 'reference failed'):
                engine_run.legacy_results([([], object(), None)])

    def test_worker_bounds_and_empty_input(self):
        for value in (True, 0, 9, -1, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                engine_run.legacy_results([], workers=value)
        self.assertEqual(engine_run.legacy_results([]), [])

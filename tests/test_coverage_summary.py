"""Coverage gates aggregate raw statements and branches, never rounded row percentages."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("kdn_coverage_summary", Path(__file__).resolve().parents[1] / "tools/dev/coverage_summary.py")
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class CoverageSummaryTests(unittest.TestCase):
    def test_groups_include_branches_and_keep_engine_out_of_phase3_only(self):
        row = {"summary": {"num_statements": 10, "num_branches": 2, "covered_lines": 9, "covered_branches": 1}}
        groups = SUMMARY.summarize({"files": {"tools/router/kdn/jobs/jobstore.py": row,
                                             "tools/router/kdn/engine/options.py": row,
                                             "tools/windows/example.py": row}})
        self.assertEqual(groups["kdn"]["statements"], 20)
        self.assertEqual(groups["phase3_kdn"]["statements"], 10)
        self.assertEqual(groups["engine"]["statements"], 10)
        self.assertAlmostEqual(groups["jobs"]["percent"], 100 * 10 / 12)
        self.assertEqual(groups["api"]["percent"], 100)

    def test_thresholds_are_exact_not_rounded(self):
        self.assertTrue(SUMMARY.meets_thresholds({"kdn": {"percent": 90.5}, "total": {"percent": 88.5}}))
        self.assertFalse(SUMMARY.meets_thresholds({"kdn": {"percent": 90.4999}, "total": {"percent": 99}}))
        self.assertTrue(SUMMARY.meets_thresholds({"kdn": {"percent": 90.5}, "engine": {"percent": 90}, "total": {"percent": 88.5}}))
        self.assertFalse(SUMMARY.meets_thresholds({"kdn": {"percent": 99}, "engine": {"percent": 89.9999}, "total": {"percent": 99}}))

    def test_phase5_fast_profile_reduces_thresholds_by_ten_percent_relative(self):
        groups = {'kdn': {'percent': 81.45}, 'engine': {'percent': 81.0}, 'total': {'percent': 79.65}}
        self.assertTrue(SUMMARY.meets_thresholds(groups, 'phase5-fast'))
        self.assertFalse(SUMMARY.meets_thresholds(groups))
        self.assertTrue(SUMMARY.meets_thresholds(groups, 'phase6-fast'))
        self.assertEqual(SUMMARY.THRESHOLDS['phase6-fast'], SUMMARY.THRESHOLDS['phase5-fast'])
        for name in groups:
            lower = {key: dict(value) for key, value in groups.items()}
            lower[name]['percent'] -= 0.0001
            with self.subTest(group=name):
                self.assertFalse(SUMMARY.meets_thresholds(lower, 'phase5-fast'))
        with self.assertRaises(ValueError):
            SUMMARY.meets_thresholds(groups, 'misspelled-profile')

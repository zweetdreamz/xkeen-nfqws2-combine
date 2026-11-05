from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "tools" / "dat-reader"
sys.path.insert(0, str(SCRIPT_DIR))
SPEC = importlib.util.spec_from_file_location("router_dat_report_test", SCRIPT_DIR / "router_dat_report.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class RouterDatReportTests(unittest.TestCase):
    def test_routing_selector_field_and_category_checks(self):
        lookup = {
            "geosite.dat": {"format": "geosite", "categories": [{"name": "ANTHROPIC", "count": 19}]},
            "geoip.dat": {"format": "geoip", "categories": [{"name": "FASTLY", "count": 82}]},
        }
        data = {"routing": {"rules": [
            {"outboundTag": "vpn", "domain": ["ext:geosite.dat:anthropic"],
             "ip": ["ext:geoip.dat:fastly", "ext:geosite.dat:anthropic"]},
        ]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routing.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            rows = REPORT.routing_selectors(path, lookup, {})
        self.assertEqual(len(rows), 3)
        self.assertEqual([item["field_correct"] for item in rows], [True, True, False])
        self.assertTrue(all(item["category_exists"] for item in rows))

    def test_markdown_includes_full_index_and_cautions_on_shared_cdn(self):
        records = [{"file": "geoip.dat", "format": "geoip", "bytes": 100,
                    "sha256": "a" * 64, "category_count": 1, "entry_count": 82,
                    "categories": [{"name": "FASTLY", "count": 82}]}]
        text = REPORT.markdown_report(records, [], {}, "fixture")
        self.assertIn("Полный перечень категорий", text)
        self.assertIn("FASTLY", text)
        self.assertIn("Широкая сеть/CDN", text)


if __name__ == "__main__":
    unittest.main()

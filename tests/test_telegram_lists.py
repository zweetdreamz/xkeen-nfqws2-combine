"""The Telegram lists in config/ must follow the v2fly categories that Xray uses.

The nfqws2 hostlist/ipset (Zapret) and the Mihomo rules are built from
config/telegram-user.list and config/telegram-ip.list, while Xray matches
ext:geosite_v2fly.dat:telegram and ext:geoip_v2fly.dat:telegram. If the dat
files are updated, these tests show that the lists need the same update.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "dat-reader" / "dat_reader.py"
SPEC = importlib.util.spec_from_file_location("dat_reader_telegram", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
dat_reader = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dat_reader
SPEC.loader.exec_module(dat_reader)


def read_list(name: str) -> list[str]:
    return (ROOT / "config" / name).read_text(encoding="utf-8").split()


def category(path: Path, name: str):
    for item in dat_reader.read_dat(path).categories:
        if item.name.lower() == name:
            return item
    raise AssertionError(f"{name} not found in {path.name}")


class TelegramListTests(unittest.TestCase):
    def test_domains_match_geosite_v2fly(self):
        telegram = category(ROOT / "dat" / "geosite_v2fly.dat", "telegram")
        expected = sorted({rule.value for rule in telegram.domains})
        self.assertEqual(read_list("telegram-user.list"), expected)

    def test_networks_match_geoip_v2fly(self):
        telegram = category(ROOT / "dat" / "geoip_v2fly.dat", "telegram")
        networks = read_list("telegram-ip.list")
        self.assertEqual(len(networks), telegram.network_count)
        parsed = [ipaddress.ip_network(value) for value in networks]
        self.assertEqual(len(set(parsed)), len(parsed))
        self.assertIn(ipaddress.ip_network("149.154.160.0/20"), parsed)

    def test_broad_zkeenip_category_is_not_used(self):
        networks = {ipaddress.ip_network(value) for value in read_list("telegram-ip.list")}
        broad = ipaddress.ip_network("194.221.0.0/16")
        self.assertFalse(any(net.version == 4 and net.overlaps(broad) for net in networks))


if __name__ == "__main__":
    unittest.main()

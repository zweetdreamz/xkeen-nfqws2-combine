from __future__ import annotations

import importlib.util
import ipaddress
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "dat-reader" / "dat_reader.py"
SPEC = importlib.util.spec_from_file_location("dat_reader", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
dat_reader = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dat_reader
SPEC.loader.exec_module(dat_reader)


def varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def uint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def blob(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def text(number: int, value: str) -> bytes:
    return blob(number, value.encode())


def domain(value: str, domain_type: int = 2, attribute: str | None = None) -> bytes:
    message = uint(1, domain_type) + text(2, value)
    if attribute is not None:
        message += blob(3, text(1, attribute) + uint(2, 1))
    return message


def geosite_fixture() -> bytes:
    discord = (
        text(1, "discord")
        + blob(2, domain("discord.com", 2, "test"))
        + blob(2, domain("gateway.discord.gg", 3))
    )
    youtube = text(1, "youtube") + blob(2, domain("youtube", 0))
    return blob(1, discord) + blob(1, youtube)


def geoip_fixture() -> bytes:
    cidr = blob(1, ipaddress.ip_address("203.0.113.0").packed) + uint(2, 24)
    entry = text(1, "test") + blob(2, cidr)
    return blob(1, entry)


class DatReaderTests(unittest.TestCase):
    def test_reads_geosite_categories_domains_and_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geosite.dat"
            path.write_bytes(geosite_fixture())
            database = dat_reader.read_dat(path)

        self.assertEqual(database.format, "geosite")
        self.assertEqual([item.name for item in database.categories], ["discord", "youtube"])
        rule = database.categories[0].domains[0]
        self.assertEqual((rule.type, rule.value), ("domain", "discord.com"))
        self.assertEqual(rule.attributes[0].key, "test")
        self.assertIs(rule.attributes[0].value, True)

    def test_reads_geoip_and_does_not_treat_it_as_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geoip.dat"
            path.write_bytes(geoip_fixture())
            database = dat_reader.read_dat(path)

        self.assertEqual(database.format, "geoip")
        self.assertEqual(database.categories[0].network_count, 1)

    def test_match_uses_xray_domain_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geosite.dat"
            path.write_bytes(geosite_fixture())
            database = dat_reader.read_dat(path)

        rows = dat_reader._domain_rows([database], match="cdn.discord.com")
        self.assertEqual([row[2].value for row in rows], ["discord.com"])

    def test_cli_category_and_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geosite.dat"
            path.write_bytes(geosite_fixture())
            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                status = dat_reader.main([str(path), "--category", "youtube", "--json"])

        self.assertEqual(status, 0)
        self.assertIn('"value": "youtube"', output.getvalue())
        self.assertEqual(errors.getvalue(), "")


if __name__ == "__main__":
    unittest.main()

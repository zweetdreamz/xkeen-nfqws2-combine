"""Characterization unit tests for tools/dat-reader/dat_reader.py.

Protobuf payloads are assembled by hand so the tests cover the low-level wire
decoder, the GeoSite/GeoIP detection logic and the command-line front end
without any real geo databases.
"""

from __future__ import annotations

import importlib.util
import io
import ipaddress
import json
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "dat-reader" / "dat_reader.py"
SPEC = importlib.util.spec_from_file_location("dat_reader_units", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
dat_reader = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dat_reader
SPEC.loader.exec_module(dat_reader)


# --- hand-rolled protobuf encoder -------------------------------------------------

def varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def key(number: int, wire_type: int) -> bytes:
    return varint((number << 3) | wire_type)


def uint(number: int, value: int) -> bytes:
    return key(number, 0) + varint(value)


def blob(number: int, value: bytes) -> bytes:
    return key(number, 2) + varint(len(value)) + value


def text(number: int, value: str) -> bytes:
    return blob(number, value.encode("utf-8"))


def fixed32(number: int, value: int) -> bytes:
    return key(number, 5) + struct.pack("<I", value)


def fixed64(number: int, value: int) -> bytes:
    return key(number, 1) + struct.pack("<Q", value)


def attribute(name: str, *, flag: bool | None = None, integer: int | None = None) -> bytes:
    message = text(1, name)
    if flag is not None:
        message += uint(2, int(flag))
    if integer is not None:
        message += uint(3, integer & ((1 << 64) - 1))
    return message


def domain(value: str, domain_type: int | None = 2, attributes: tuple[bytes, ...] = ()) -> bytes:
    message = b"" if domain_type is None else uint(1, domain_type)
    message += text(2, value)
    for item in attributes:
        message += blob(3, item)
    return message


def geosite_entry(name: str, *domains: bytes) -> bytes:
    return text(1, name) + b"".join(blob(2, item) for item in domains)


def cidr(address: str, prefix: int) -> bytes:
    return blob(1, ipaddress.ip_address(address).packed) + uint(2, prefix)


def geoip_entry(name: str, *networks: bytes) -> bytes:
    return text(1, name) + b"".join(blob(2, item) for item in networks)


def database(*entries: bytes) -> bytes:
    return b"".join(blob(1, entry) for entry in entries)


def geosite_bytes() -> bytes:
    return database(
        geosite_entry(
            "discord",
            domain("discord.com", 2, (attribute("cn", flag=True), attribute("weight", integer=-5))),
            domain("gateway.discord.gg", 3),
        ),
        geosite_entry("youtube", domain("youtube", 0), domain(r"^r\d+\.googlevideo\.com$", 1)),
    )


def geoip_bytes() -> bytes:
    return database(
        geoip_entry("private", cidr("10.0.0.0", 8), cidr("192.168.0.0", 16)),
        geoip_entry("test6", cidr("2001:db8::", 32)),
    )


def rule(kind: str, value: str) -> dat_reader.DomainRule:
    return dat_reader.DomainRule(type=kind, value=value)


class FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def run_main(argv, stdin: bytes | None = None):
    output = io.StringIO()
    errors = io.StringIO()
    patches = [redirect_stdout(output), redirect_stderr(errors)]
    if stdin is not None:
        patches.append(mock.patch.object(sys, "stdin", FakeStdin(stdin)))
    with patches[0], patches[1]:
        if stdin is not None:
            with patches[2]:
                status = dat_reader.main(argv)
        else:
            status = dat_reader.main(argv)
    return status, output.getvalue(), errors.getvalue()


# --- tests ------------------------------------------------------------------------

class WireFormatTests(unittest.TestCase):
    def fields(self, data: bytes):
        return list(dat_reader._wire_fields(data))

    def test_varint_errors(self):
        with self.assertRaisesRegex(dat_reader.DatFormatError, "too long"):
            self.fields(b"\x80" * 11)
        with self.assertRaisesRegex(dat_reader.DatFormatError, "truncated protobuf varint"):
            self.fields(b"\x80")
        with self.assertRaisesRegex(dat_reader.DatFormatError, "truncated protobuf varint"):
            self.fields(key(1, 0))  # key present, value missing

    def test_varint_round_trip(self):
        for value in (0, 1, 127, 128, 300, (1 << 63), (1 << 64) - 1):
            with self.subTest(value=value):
                encoded = varint(value)
                self.assertEqual(dat_reader._read_varint(encoded + b"tail", 0), (value, len(encoded)))

    def test_unsupported_wire_types(self):
        for wire_type in (3, 4, 6, 7):
            with self.subTest(wire_type=wire_type):
                with self.assertRaisesRegex(dat_reader.DatFormatError, f"unsupported protobuf wire type {wire_type}"):
                    self.fields(key(1, wire_type))

    def test_field_number_zero_is_rejected(self):
        with self.assertRaisesRegex(dat_reader.DatFormatError, "field number 0"):
            self.fields(b"\x00")

    def test_truncated_fixed_and_length_delimited_fields(self):
        cases = (
            (key(1, 1) + b"\x00" * 7, "truncated fixed64"),
            (key(1, 5) + b"\x00" * 3, "truncated fixed32"),
            (key(1, 2) + varint(5) + b"ab", "truncated length-delimited"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    self.fields(data)

    def test_fixed32_fixed64_varint_and_bytes_are_yielded(self):
        data = fixed32(1, 0x01020304) + fixed64(2, 7) + uint(3, 300) + text(4, "hi")
        self.assertEqual(
            self.fields(data),
            [
                (1, 5, struct.pack("<I", 0x01020304)),
                (2, 1, struct.pack("<Q", 7)),
                (3, 0, 300),
                (4, 2, b"hi"),
            ],
        )
        self.assertEqual(self.fields(b""), [])

    def test_signed_int64(self):
        self.assertEqual(dat_reader._signed_int64(0), 0)
        self.assertEqual(dat_reader._signed_int64((1 << 63) - 1), (1 << 63) - 1)
        self.assertEqual(dat_reader._signed_int64(1 << 63), -(1 << 63))
        self.assertEqual(dat_reader._signed_int64((1 << 64) - 1), -1)

    def test_decode_text(self):
        self.assertEqual(dat_reader._decode_text("тест".encode(), "f"), "тест")
        with self.assertRaisesRegex(dat_reader.DatFormatError, "f is not valid UTF-8"):
            dat_reader._decode_text(b"\xff", "f")
        for value in (b"", b"a\nb", b"\x00"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(dat_reader.DatFormatError, "empty or contains control"):
                    dat_reader._decode_text(value, "f")


class MessageParserTests(unittest.TestCase):
    def test_attribute_values(self):
        self.assertEqual(dat_reader._parse_attribute(attribute("a")), dat_reader.Attribute("a", None))
        self.assertEqual(dat_reader._parse_attribute(attribute("a", flag=False)), dat_reader.Attribute("a", False))
        self.assertEqual(dat_reader._parse_attribute(attribute("a", integer=-1)), dat_reader.Attribute("a", -1))
        # Unknown fields are ignored.
        self.assertEqual(dat_reader._parse_attribute(attribute("a") + fixed32(9, 0)).key, "a")

    def test_attribute_errors(self):
        cases = (
            (uint(1, 1), "attribute key has an invalid wire type"),
            (text(1, "a") + text(2, "x"), "boolean attribute has an invalid wire type"),
            (text(1, "a") + text(3, "x"), "integer attribute has an invalid wire type"),
            (uint(2, 1), "domain attribute has no key"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    dat_reader._parse_attribute(data)

    def test_domain_defaults_to_plain_and_ignores_unknown_fields(self):
        parsed = dat_reader._parse_domain(domain("example", None) + fixed64(7, 1))
        self.assertEqual(parsed, dat_reader.DomainRule("plain", "example", ()))

    def test_domain_errors(self):
        cases = (
            (uint(1, 9) + text(2, "x"), "invalid type"),
            (text(1, "x") + text(2, "x"), "invalid type"),
            (uint(1, 2) + uint(2, 5), "domain value has an invalid wire type"),
            (uint(1, 2) + text(2, "x") + uint(3, 1), "domain attribute has an invalid wire type"),
            (uint(1, 2), "domain rule has no value"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    dat_reader._parse_domain(data)

    def test_geosite_entry_errors(self):
        cases = (
            (uint(1, 1), "geosite category has an invalid name"),
            (text(1, "x") + uint(2, 1), "geosite domain has an invalid wire type"),
            (blob(2, domain("x")), "geosite category has no name"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    dat_reader._parse_geosite_entry(data)

    def test_cidr_validation(self):
        dat_reader._validate_cidr(cidr("203.0.113.0", 32))
        dat_reader._validate_cidr(cidr("2001:db8::", 128))
        dat_reader._validate_cidr(blob(1, b"\x00" * 4))  # prefix defaults to 0
        cases = (
            (uint(1, 4), "address has an invalid wire type"),
            (blob(1, b"\x00" * 4) + blob(2, b"x"), "prefix has an invalid wire type"),
            (blob(1, b"\x00" * 5), "not 4 or 16 bytes"),
            (uint(2, 8), "not 4 or 16 bytes"),
            (cidr("203.0.113.0", 33), "outside the address width"),
            (cidr("2001:db8::", 129), "outside the address width"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    dat_reader._validate_cidr(data)

    def test_geoip_entry_counts_networks_validating_only_first(self):
        entry = geoip_entry("x", cidr("10.0.0.0", 8), b"not-a-valid-cidr", b"")
        self.assertEqual(dat_reader._parse_geoip_entry(entry), dat_reader.IpCategory("x", 3))

    def test_geoip_entry_errors(self):
        cases = (
            (uint(1, 1), "GeoIP category has an invalid name"),
            (text(1, "x") + uint(2, 1), "GeoIP CIDR has an invalid wire type"),
            (blob(2, cidr("10.0.0.0", 8)), "GeoIP category has no name"),
            (geoip_entry("x", blob(1, b"\x00")), "not 4 or 16 bytes"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(dat_reader.DatFormatError, message):
                    dat_reader._parse_geoip_entry(data)

    def test_root_entries(self):
        self.assertEqual(dat_reader._root_entries(blob(1, b"a") + uint(5, 1) + blob(1, b"b")), [b"a", b"b"])
        with self.assertRaisesRegex(dat_reader.DatFormatError, "no entries"):
            dat_reader._root_entries(b"")
        with self.assertRaisesRegex(dat_reader.DatFormatError, "no entries"):
            dat_reader._root_entries(uint(2, 1))
        with self.assertRaisesRegex(dat_reader.DatFormatError, "invalid wire type"):
            dat_reader._root_entries(uint(1, 1))


class ReadDatTests(unittest.TestCase):
    def test_read_geosite_bytes(self):
        db = dat_reader.read_dat_bytes(geosite_bytes())
        self.assertEqual(db.format, "geosite")
        self.assertEqual(db.path, Path("<stdin>"))
        self.assertEqual([c.name for c in db.categories], ["discord", "youtube"])
        first = db.categories[0].domains[0]
        self.assertEqual(first.attributes, (dat_reader.Attribute("cn", True), dat_reader.Attribute("weight", -5)))
        self.assertEqual([r.type for r in db.categories[1].domains], ["plain", "regex"])

    def test_read_geoip_bytes(self):
        db = dat_reader.read_dat_bytes(geoip_bytes(), Path("geoip.dat"))
        self.assertEqual(db.format, "geoip")
        self.assertEqual(db.path, Path("geoip.dat"))
        self.assertEqual(db.categories, (dat_reader.IpCategory("private", 2), dat_reader.IpCategory("test6", 1)))

    def test_categories_without_rules_are_not_supported(self):
        with self.assertRaisesRegex(dat_reader.DatFormatError, "not a supported"):
            dat_reader.read_dat_bytes(database(text(1, "empty")))

    def test_garbage_is_not_supported(self):
        with self.assertRaises(dat_reader.DatFormatError):
            dat_reader.read_dat_bytes(b"\xff\xff\xff")
        with self.assertRaisesRegex(dat_reader.DatFormatError, "not a supported"):
            dat_reader.read_dat_bytes(database(b"\x0a\x01"))

    def test_read_dat_missing_file_raises_format_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(dat_reader.DatFormatError):
                dat_reader.read_dat(Path(directory) / "missing.dat")


class HelperTests(unittest.TestCase):
    def test_attribute_text(self):
        attributes = (
            dat_reader.Attribute("cn"),
            dat_reader.Attribute("ads", True),
            dat_reader.Attribute("off", False),
            dat_reader.Attribute("n", -3),
        )
        self.assertEqual(dat_reader._attribute_text(attributes), "@cn,@ads=true,@off=false,@n=-3")
        self.assertEqual(dat_reader._attribute_text(()), "")

    def test_rule_matches_full(self):
        self.assertTrue(dat_reader._rule_matches(rule("full", "Discord.com"), "discord.COM."))
        self.assertFalse(dat_reader._rule_matches(rule("full", "discord.com"), "cdn.discord.com"))

    def test_rule_matches_domain_suffix_boundary(self):
        domain_rule = rule("domain", "discord.com.")
        self.assertTrue(dat_reader._rule_matches(domain_rule, "discord.com"))
        self.assertTrue(dat_reader._rule_matches(domain_rule, "CDN.discord.com"))
        self.assertFalse(dat_reader._rule_matches(domain_rule, "notdiscord.com"))
        self.assertFalse(dat_reader._rule_matches(domain_rule, "discord.com.evil"))

    def test_rule_matches_plain_substring(self):
        self.assertTrue(dat_reader._rule_matches(rule("plain", "Tube"), "www.youtube.com"))
        self.assertFalse(dat_reader._rule_matches(rule("plain", "tube"), "discord.com"))

    def test_rule_matches_regex(self):
        regex = rule("regex", r"^r\d+\.googlevideo\.com$")
        self.assertTrue(dat_reader._rule_matches(regex, "R1.GoogleVideo.com"))
        self.assertFalse(dat_reader._rule_matches(regex, "x.googlevideo.com"))
        self.assertFalse(dat_reader._rule_matches(rule("regex", "(unclosed"), "anything"))

    def test_domain_rows_filters(self):
        geosite = dat_reader.read_dat_bytes(geosite_bytes(), Path("a.dat"))
        geoip = dat_reader.read_dat_bytes(geoip_bytes(), Path("b.dat"))
        values = lambda rows: [row[2].value for row in rows]  # noqa: E731
        self.assertEqual(len(dat_reader._domain_rows([geosite, geoip])), 4)
        self.assertEqual(values(dat_reader._domain_rows([geosite], categories={"youtube"})), ["youtube", r"^r\d+\.googlevideo\.com$"])
        self.assertEqual(values(dat_reader._domain_rows([geosite], search="DISCORD")), ["discord.com", "gateway.discord.gg"])
        self.assertEqual(values(dat_reader._domain_rows([geosite], match="r5.googlevideo.com")), [r"^r\d+\.googlevideo\.com$"])
        self.assertEqual(dat_reader._domain_rows([geoip], match="10.0.0.1"), [])

    def test_print_summary_and_rows(self):
        geosite = dat_reader.read_dat_bytes(geosite_bytes(), Path("site.dat"))
        geoip = dat_reader.read_dat_bytes(geoip_bytes(), Path("ip.dat"))
        output = io.StringIO()
        with redirect_stdout(output):
            dat_reader._print_summary([geosite, geoip])
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "site.dat  geosite  categories=2 domains=4",
                "  discord\t2",
                "  youtube\t2",
                "ip.dat  geoip  categories=2 networks=3",
                "  (IP database: it contains no domain rules)",
                "  private\t2",
                "  test6\t1",
            ],
        )
        output = io.StringIO()
        with redirect_stdout(output):
            dat_reader._print_rows(dat_reader._domain_rows([geosite], categories={"discord"}))
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "site.dat\tdiscord\tdomain\tdiscord.com\t@cn=true,@weight=-5",
                "site.dat\tdiscord\tfull\tgateway.discord.gg",
            ],
        )

    def test_json_summary(self):
        geosite = dat_reader.read_dat_bytes(geosite_bytes(), Path("site.dat"))
        geoip = dat_reader.read_dat_bytes(geoip_bytes(), Path("ip.dat"))
        self.assertEqual(
            dat_reader._json_summary([geosite, geoip]),
            [
                {"file": "site.dat", "format": "geosite", "categories": [{"name": "discord", "domains": 2}, {"name": "youtube", "domains": 2}]},
                {"file": "ip.dat", "format": "geoip", "categories": [{"name": "private", "networks": 2}, {"name": "test6", "networks": 1}]},
            ],
        )

    def test_expand_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "sub").mkdir()
            (base / "b.dat").write_bytes(b"")
            (base / "sub" / "a.dat").write_bytes(b"")
            (base / "skip.txt").write_bytes(b"")
            paths, errors = dat_reader._expand_paths(
                ["-", str(base), str(base / "*.dat"), "-", str(base / "missing.dat")]
            )
        self.assertEqual(errors, [])
        self.assertEqual(
            paths,
            [Path("-"), base / "b.dat", base / "sub" / "a.dat", base / "missing.dat"],
        )

    def test_expand_paths_reports_os_errors(self):
        with mock.patch.object(dat_reader.Path, "is_dir", side_effect=OSError("denied")):
            paths, errors = dat_reader._expand_paths(["nonexistent-xyz.dat"])
        self.assertEqual(paths, [])
        self.assertEqual(errors, ["nonexistent-xyz.dat: denied"])
        with mock.patch.object(dat_reader.Path, "resolve", side_effect=OSError("loop")):
            paths, errors = dat_reader._expand_paths(["nonexistent-xyz.dat"])
        self.assertEqual(paths, [])
        self.assertEqual(errors, ["nonexistent-xyz.dat: loop"])


class MainTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.site = self.base / "geosite.dat"
        self.site.write_bytes(geosite_bytes())
        self.ip = self.base / "geoip.dat"
        self.ip.write_bytes(geoip_bytes())

    def test_stdin_summary(self):
        status, output, errors = run_main(["-"], stdin=geosite_bytes())
        self.assertEqual(status, 0)
        self.assertEqual(errors, "")
        self.assertIn("<stdin>  geosite  categories=2 domains=4", output)

    def test_stdin_garbage_is_error(self):
        status, output, errors = run_main(["-"], stdin=b"\x80")
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("error: <stdin>: truncated protobuf varint", errors)

    def test_missing_file_is_nonzero(self):
        missing = self.base / "missing.dat"
        status, output, errors = run_main([str(missing)])
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn(f"error: {missing}: file not found", errors)

    def test_partial_failure_still_prints_valid_databases(self):
        bad = self.base / "bad.dat"
        bad.write_bytes(b"garbage")
        status, output, errors = run_main([str(self.site), str(bad)])
        self.assertEqual(status, 1)
        self.assertIn("geosite  categories=2", output)
        self.assertIn(f"error: {bad}:", errors)

    def test_path_expansion_errors_make_exit_nonzero(self):
        with mock.patch.object(dat_reader, "_expand_paths", return_value=([self.site], ["x: denied"])):
            status, output, errors = run_main(["ignored"])
        self.assertEqual(status, 1)
        self.assertIn("geosite  categories=2", output)
        self.assertIn("error: x: denied", errors)

    def test_empty_directory_has_no_dat_files(self):
        empty = self.base / "empty"
        empty.mkdir()
        status, output, errors = run_main([str(empty)])
        self.assertEqual(status, 1)
        self.assertEqual(errors.strip(), "error: no .dat files found")

    def test_directory_json_summary(self):
        status, output, errors = run_main([str(self.base), "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(errors, "")
        summary = json.loads(output)
        self.assertEqual([item["format"] for item in summary], ["geoip", "geosite"])
        self.assertEqual(summary[0]["categories"][0], {"name": "private", "networks": 2})

    def test_search_without_hits_is_nonzero(self):
        status, output, errors = run_main([str(self.site), "--search", "nothing-here"])
        self.assertEqual(status, 1)
        self.assertEqual(output, "")
        self.assertIn("No matching domain rules found.", errors)

        status, output, errors = run_main([str(self.site), "--search", "nothing-here", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output), [])

    def test_domain_actions_text_output(self):
        status, output, _errors = run_main([str(self.site), "--domains"])
        self.assertEqual(status, 0)
        self.assertEqual(len(output.splitlines()), 4)

        status, output, _errors = run_main([str(self.site), "-m", "media.discord.com"])
        self.assertEqual(status, 0)
        self.assertEqual(output, f"{self.site}\tdiscord\tdomain\tdiscord.com\t@cn=true,@weight=-5\n")

        status, output, _errors = run_main([str(self.site), "-c", "YOUTUBE", "-c", "discord"])
        self.assertEqual(status, 0)
        self.assertEqual(len(output.splitlines()), 4)

    def test_match_json_contains_attributes(self):
        status, output, _errors = run_main([str(self.site), "--match", "discord.com", "--json"])
        self.assertEqual(status, 0)
        rows = json.loads(output)
        self.assertEqual([row["value"] for row in rows], ["discord.com"])
        self.assertEqual(rows[0]["file"], str(self.site))
        self.assertEqual(rows[0]["type"], "domain")
        self.assertEqual(rows[0]["attributes"], [{"key": "cn", "value": True}, {"key": "weight", "value": -5}])
        self.assertEqual(rows[0]["category"], "discord")

    def test_geoip_with_domain_action_has_no_rows(self):
        status, _output, errors = run_main([str(self.ip), "--domains"])
        self.assertEqual(status, 1)
        self.assertIn("No matching domain rules found.", errors)

    def test_reconfigures_streams_when_supported(self):
        stdout = SimpleNamespace(reconfigure=mock.Mock(), write=lambda _text: None, flush=lambda: None)
        stderr = SimpleNamespace(reconfigure=mock.Mock(), write=lambda _text: None, flush=lambda: None)
        with mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
            status = dat_reader.main([str(self.ip)])
        self.assertEqual(status, 0)
        stdout.reconfigure.assert_called_once_with(encoding="utf-8", errors="replace")
        stderr.reconfigure.assert_called_once_with(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    unittest.main()

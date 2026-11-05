"""Guards tests/fixtures/engine/router-xkeen20, the scrubbed tree of a real router.

The tree must hold neither secrets nor real addresses. The scan looks for the
shapes of what must not be there (UUIDs, keys, e-mails, hosts, public IPs,
MACs) in file contents and in path names. A finding is reported by rule, file
and line only, never with the matched text, so that a leak does not reach the
test log. The scan itself is checked on planted violations.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import tempfile
import unittest


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "engine" / "router-xkeen20"

# A secret keyword with a value after ":" or "=", also as the first non-empty element of a (multi-line) array.
_VALUE_AFTER_KEY = r"[\"']?\s*[:=]\s*(?:\[[^\]]*?)?[\"']?"
SECRET_WORD = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:password|passwd|private_?key|public_?key|short_?ids?|sid|uuid|rci_token|secret)"
    + _VALUE_AFTER_KEY
    + r"[^\s\"',}\[\]]"
)
# A bare "id" key is too common to flag whatever it holds: only an identifier-like value counts.
ID_VALUE = re.compile(r"(?i)(?<![A-Za-z0-9])id" + _VALUE_AFTER_KEY + r"[A-Za-z0-9+/_=-]{8,}")
UUID = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
BASE64URL = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43,44}={0,1}(?![A-Za-z0-9_-])")
LONG_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
IPV6_CANDIDATE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]{3,}(?![\w:.])")
HOSTNAME = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?\.)+[A-Za-z]{2,}(?![\w-])")
# What the Xray rules may reference: file names and tags of dat files, never domains.
DAT_REFERENCE = re.compile(
    r"\bext:[A-Za-z0-9_.-]+\.dat:[A-Za-z0-9@!_-]+|\b(?:geosite|geoip):[A-Za-z0-9@!_-]+"
)

DOCUMENTATION_TLDS = frozenset({"invalid", "example"})
# One label and one of these extensions is a file name (nfqws2.conf), not a host.
FILE_EXTENSIONS = frozenset(
    {"dat", "json", "conf", "list", "lst", "sh", "ptr", "tsv", "lua", "bin", "log", "pid", "md", "txt", "jq"}
)
# Public hosts of the stock nfqws2.conf: strategy parameters and a documentation link.
PUBLIC_HOSTS = frozenset({"fonts.google.com", "www.google.com", "ozon.ru", "github.com"})

ALLOWED_IPV4 = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
        "0.0.0.0/32",
    )
)
ALLOWED_IPV6 = tuple(
    ipaddress.ip_network(net) for net in ("2001:db8::/32", "::1/128", "::/128", "fe80::/10")
)


def _line_hits(rule, pattern, lines):
    return [(rule, number) for number, line in enumerate(lines, 1) if pattern.search(line)]


def _text_hits(rule, pattern, text):
    # Whole-text search: a value may sit on another line than its key. The line reported is the key's.
    return [(rule, text.count("\n", 0, match.start()) + 1) for match in pattern.finditer(text)]


def _hostname_hits(lines):
    hits = []
    for number, line in enumerate(lines, 1):
        for match in HOSTNAME.finditer(DAT_REFERENCE.sub(" ", line)):
            host = match.group(0).lower()
            labels = host.split(".")
            if labels[-1] in DOCUMENTATION_TLDS or host in PUBLIC_HOSTS:
                continue
            if len(labels) == 2 and labels[-1] in FILE_EXTENSIONS:
                continue
            hits.append(("fqdn", number))
    return hits


def _ipv4_hits(lines):
    hits = []
    for number, line in enumerate(lines, 1):
        for match in IPV4.finditer(line):
            try:
                address = ipaddress.IPv4Address(match.group(0))
            except ValueError:
                continue
            if not any(address in network for network in ALLOWED_IPV4):
                hits.append(("public-ipv4", number))
    return hits


def _ipv6_hits(lines):
    hits = []
    for number, line in enumerate(lines, 1):
        for match in IPV6_CANDIDATE.finditer(line):
            candidate = match.group(0)
            if candidate.count(":") < 2:
                continue
            try:
                address = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            if not any(address in network for network in ALLOWED_IPV6):
                hits.append(("public-ipv6", number))
    return hits


def scan_text(text):
    """Return (rule, line number) for every shape that must not be in a fixture."""
    lines = text.split("\n")
    hits = []
    hits += _text_hits("secret-word", SECRET_WORD, text)
    hits += _text_hits("secret-word", ID_VALUE, text)
    hits += _line_hits("uuid", UUID, lines)
    hits += _line_hits("email", EMAIL, lines)
    hits += _line_hits("base64url", BASE64URL, lines)
    hits += _line_hits("long-hex", LONG_HEX, lines)
    hits += _line_hits("mac", MAC, lines)
    hits += _hostname_hits(lines)
    hits += _ipv4_hits(lines)
    hits += _ipv6_hits(lines)
    return hits


def scan_tree(root):
    """Scan the names and the contents of every file below root; report rule, path and line."""
    findings = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        for rule, _ in scan_text(relative):
            findings.append(f"{relative}: {rule} in the file name")
        if path.is_file():
            text = path.read_bytes().decode("utf-8", errors="replace")
            for rule, number in scan_text(text):
                findings.append(f"{relative}:{number}: {rule}")
    return findings


def significant_lines(path):
    text = path.read_bytes().decode("utf-8", errors="replace")
    return [line for line in text.split("\n") if line and not re.match(r"\s*(#|;|/)", line)]


def _planted():
    """One synthetic violation per rule: (rule, text that must be reported)."""
    base64url_43 = ("Ab1-_" * 9)[:43]
    base64url_44 = ("Ab1-_" * 9)[:44]
    return [
        ("uuid", "id=123e4567-e89b-12d3-a456-426614174000"),
        ("email", "owner=person@mail.test"),
        ("base64url", f"key={base64url_43}"),
        ("base64url", f"key={base64url_44}="),
        ("fqdn", "server=real-server.net"),
        ("fqdn", "server=sub.real-server.net:443"),
        ("public-ipv4", "dns=8.8.8.8"),
        ("public-ipv4", "dns=172.32.0.1"),
        ("public-ipv6", "dns=2001:4860:4860::8888"),
        ("public-ipv6", "dns=[fd00::1]:53"),
        ("mac", "client=aa:bb:cc:dd:ee:ff"),
        ("mac", "client=AA-BB-CC-DD-EE-FF"),
        ("secret-word", '"rci_token": "abc123"'),
        ("secret-word", "privateKey=abc123"),
        ("secret-word", 'shortId: "ab12"'),
        ("secret-word", '"shortIds": ["6ba85179e30d4fc2"]'),
        ("secret-word", '"shortIds": ["", "6ba85179e30d4fc2"]'),
        ("secret-word", '"shortIds": [\n  "6ba85179e30d4fc2"\n]'),
        ("secret-word", '"sid": "6ba85179e30d4fc2"'),
        ("secret-word", "sid=6ba85179e30d4fc2"),
        ("secret-word", '"publicKey": "abc"'),
        ("secret-word", '"password": ["hunter22"]'),
        ("secret-word", '"uuid": "xyz12345"'),
        ("secret-word", '"id": "6ba85179e30d4fc2"'),
        ("secret-word", '"id": [\n  "6ba85179e30d4fc2"\n]'),
        ("long-hex", "hash=" + "0123456789abcdef" * 2),
    ]


def _allowed():
    """Text the scan must let through, including the values next to the limits of the rules."""
    return [
        "dns=192.0.2.1 198.51.100.7 203.0.113.9 10.1.2.3 172.31.255.255 192.168.2.1 127.0.0.1 0.0.0.0",
        "dns=2001:db8::1 ::1 fe80::1",
        "server=domain-001.example.invalid kdn-disabled.invalid host.example",
        'domain=["ext:geosite_v2fly.dat:discord", "geosite:category-ads-all", "geoip:ru"]',
        "sni=fonts.google.com sni=www.google.com host=ozon.ru",
        "see https://github.com/bol-van/zapret2/blob/master/docs/manual.md",
        "/opt/etc/nfqws2/nfqws2.conf /opt/etc/xray/dat/zkeen.dat /opt/etc/init.d/S05xkeen apply-discord-nfqws2.sh",
        "port=590:600,1400,50000:50100 time=08:53:30 version=26.10.21",
        f"short={('Ab1-_' * 9)[:42]} longer={('Ab1-_' * 9)[:45]}",
        'rci_token="" password=""',
        '"shortIds": [""] "shortIds": [] "sid": "" sid=',
        '"id": "x" "id": [] "tag": "redirect" "ruleTag": "kdn-telegram-ip"',
        "inside the router, aside, valid: configuration_ok, xsid: value, outside: no, hybrid=Hybrid",
        "interface=eth3 mark=0x111 token=0xffffaaa",
    ]


class FixtureCleanTests(unittest.TestCase):
    def test_fixture_tree_has_no_secrets_or_real_addresses(self):
        self.assertTrue(FIXTURE_ROOT.is_dir(), "the scrubbed router tree is missing")
        self.assertEqual([], scan_tree(FIXTURE_ROOT))

    def test_fixture_tree_has_no_cr_ansi_or_nbsp(self):
        # Such bytes are built by the tests that need them; the fixture files stay plain.
        for path in sorted(FIXTURE_ROOT.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            for name, marker in (("CR", b"\r"), ("ANSI", b"\x1b"), ("NBSP", b"\xc2\xa0")):
                with self.subTest(path=path.relative_to(FIXTURE_ROOT).as_posix(), marker=name):
                    self.assertNotIn(marker, data)

    def test_fixture_tree_has_the_files_the_modes_read(self):
        expected = [
            "SOURCE.txt",
            "opt/etc/init.d/S05xkeen",
            "opt/etc/ndm/netfilter.d/proxy.sh",
            "opt/etc/nfqws2/nfqws2.conf",
            "opt/etc/xkeen/port_proxying.lst",
            "opt/etc/xkeen/port_exclude.lst",
            "opt/etc/xkeen/xkeen.json",
            "opt/etc/keenetic-discord-nfqws2/snapshots/20260723-115259-17170/STATE.tsv",
            "opt/etc/keenetic-discord-nfqws2/snapshots/20261027-212919-23690/STATE.tsv",
        ]
        expected += [
            f"opt/etc/nfqws2/lists/{name}.list"
            for name in ("auto", "exclude", "ipset", "ipset_exclude", "kdn-telegram", "user", "youtube")
        ]
        expected += [
            f"opt/etc/xray/configs/{name}.json"
            for name in (
                "01_log",
                "02_dns",
                "03_inbounds",
                "03_tor_socks_inbound",
                "04_discord_nfqws2_outbound",
                "04_outbounds",
                "04_youtube_nfqws2_outbound",
                "05_routing",
                "06_policy",
            )
        ]
        expected += [
            f"opt/etc/xray/dat/{name}.dat"
            for name in (
                "geoip_refilter",
                "geoip_v2fly",
                "geoip_zkeenip",
                "geosite_refilter",
                "geosite_v2fly",
                "geosite_zkeen",
                "zkeen",
                "zkeenip",
            )
        ]
        for logical in expected:
            with self.subTest(path=logical):
                self.assertTrue((FIXTURE_ROOT / logical).is_file())
        self.assertEqual(
            [],
            sorted(p.name for p in (FIXTURE_ROOT / "opt/etc/keenetic-discord-nfqws2").glob("*.ptr")),
            "pointers are written by the scenario under the current root",
        )

    def test_fixture_tree_keeps_the_shape_of_the_router(self):
        # The entry counts of the lists and the structure of the Xray files are what the modes depend on.
        counts = {
            "auto": 0,
            "exclude": 165,
            "ipset": 40,
            "ipset_exclude": 8,
            "kdn-telegram": 21,
            "user": 30,
            "youtube": 19,
        }
        for name, count in counts.items():
            with self.subTest(list=name):
                path = FIXTURE_ROOT / f"opt/etc/nfqws2/lists/{name}.list"
                self.assertEqual(count, len(significant_lines(path)))
        configs = FIXTURE_ROOT / "opt/etc/xray/configs"
        routing = json.loads((configs / "05_routing.json").read_text(encoding="utf-8"))
        self.assertEqual(15, len(routing["routing"]["rules"]))
        inbounds = json.loads((configs / "03_inbounds.json").read_text(encoding="utf-8"))
        self.assertEqual(["redirect", "tproxy"], [item["tag"] for item in inbounds["inbounds"]])
        outbounds = json.loads((configs / "04_outbounds.json").read_text(encoding="utf-8"))
        self.assertEqual(["vless-reality", "direct", "block"], [item["tag"] for item in outbounds["outbounds"]])
        for path in sorted(configs.glob("*.json")):
            with self.subTest(config=path.name):
                json.loads(path.read_text(encoding="utf-8"))
        conf = (FIXTURE_ROOT / "opt/etc/nfqws2/nfqws2.conf").read_text(encoding="utf-8")
        self.assertIn("# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=vless.", conf)
        init = (FIXTURE_ROOT / "opt/etc/init.d/S05xkeen").read_text(encoding="utf-8")
        self.assertIn('name_client="xray"', init)
        for path in sorted((FIXTURE_ROOT / "opt/etc/xray/dat").glob("*.dat")):
            with self.subTest(dat=path.name):
                self.assertEqual(1, path.stat().st_size)

    def test_the_scan_catches_planted_violations(self):
        for rule, text in _planted():
            with self.subTest(rule=rule, text=text), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                planted = root / "opt/etc/planted.conf"
                planted.parent.mkdir(parents=True)
                planted.write_text(f"# clean line\n{text}\n", encoding="utf-8")
                findings = scan_tree(root)
                self.assertTrue(
                    any(finding == f"opt/etc/planted.conf:2: {rule}" for finding in findings),
                    f"{rule} was not reported",
                )

    def test_the_scan_catches_a_violation_in_a_file_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "opt/etc/123e4567-e89b-12d3-a456-426614174000.conf").parent.mkdir(parents=True)
            (root / "opt/etc/123e4567-e89b-12d3-a456-426614174000.conf").write_text("x\n", encoding="utf-8")
            self.assertEqual(["opt/etc/123e4567-e89b-12d3-a456-426614174000.conf: uuid in the file name"], scan_tree(root))

    def test_the_scan_lets_documentation_values_and_file_names_through(self):
        for text in _allowed():
            with self.subTest(text=text):
                self.assertEqual([], scan_text(text))

    def test_the_scan_never_reports_the_matched_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "leak.conf").write_text("key=123e4567-e89b-12d3-a456-426614174000\n", encoding="utf-8")
            findings = scan_tree(root)
        self.assertEqual(["leak.conf:1: uuid"], findings)


if __name__ == "__main__":
    unittest.main()

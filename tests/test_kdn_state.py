"""Unit tests for kdn.state.nfqws: the nfqws2.conf header and the Voice port rules.

The module is pure text parsing, so nothing here touches the filesystem beyond
loading the router tools that carry their own copies of the parser.
"""

from __future__ import annotations

import contextlib
import importlib.util
from pathlib import Path
import sys
import unittest

from kdn.state import nfqws


ROOT = Path(__file__).resolve().parents[1]
ROUTER_DIR = ROOT / "tools" / "router"
HEADER = "# Active routes: "


def routes(tcp, voice, youtube, telegram="unmanaged"):
    return {"discord-tcp": tcp, "discord-voice": voice, "youtube": youtube, "telegram": telegram}


# (name, config text, parse_active_routes result)
ROUTE_CORPUS = (
    (
        "modern",
        HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=direct.\n",
        routes("direct", "zapret", "vless", "direct"),
    ),
    (
        "legacy applies Discord to both routes",
        HEADER + "Discord=zapret, YouTube=vless.\n",
        routes("zapret", "zapret", "vless"),
    ),
    (
        "legacy with Telegram",
        HEADER + "Discord=vless, YouTube=direct, Telegram=ws.\n",
        routes("vless", "vless", "direct", "ws"),
    ),
    (
        "no Telegram means unmanaged",
        HEADER + "DiscordTCP=vless, DiscordVoice=direct, YouTube=zapret.\n",
        routes("vless", "direct", "zapret", "unmanaged"),
    ),
    (
        "Telegram unmanaged",
        HEADER + "DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Telegram=unmanaged.\n",
        routes("direct", "direct", "direct", "unmanaged"),
    ),
    (
        "Telegram ws",
        HEADER + "DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Telegram=ws.\n",
        routes("direct", "direct", "direct", "ws"),
    ),
    (
        "Telegram zapret is still parsed",
        HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=zapret.\n",
        routes("direct", "zapret", "vless", "zapret"),
    ),
    (
        "Telegram vless",
        HEADER + "DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=vless.\n",
        routes("zapret", "zapret", "zapret", "vless"),
    ),
    (
        "header is not the first line",
        'NFQWS_ENABLED=1\n\n# Managed by apply-discord-nfqws2.sh\n'
        + HEADER + "DiscordTCP=vless, DiscordVoice=zapret, YouTube=direct, Telegram=ws.\n"
        + "# Discord UDP: strategy=flowseal, range=narrow.\nUDP_PORTS=443\n",
        routes("vless", "zapret", "direct", "ws"),
    ),
    (
        "header without the final newline",
        "x=1\n" + HEADER + "Discord=direct, YouTube=vless.",
        routes("direct", "direct", "vless"),
    ),
    (
        "the first header line wins",
        HEADER + "Discord=direct, YouTube=direct.\n" + HEADER + "Discord=vless, YouTube=vless.\n",
        routes("direct", "direct", "direct"),
    ),
    (
        "the first header line wins even when it is malformed",
        HEADER + "Discord=other, YouTube=direct.\n" + HEADER + "Discord=vless, YouTube=vless.\n",
        None,
    ),
    ("foreign value", HEADER + "DiscordTCP=other, DiscordVoice=direct, YouTube=direct.\n", None),
    (
        "foreign Telegram value",
        HEADER + "DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Telegram=other.\n",
        None,
    ),
    ("unmanaged is Telegram-only", HEADER + "DiscordTCP=unmanaged, DiscordVoice=direct, YouTube=direct.\n", None),
    ("ws is Telegram-only", HEADER + "Discord=ws, YouTube=direct.\n", None),
    (
        "extra key",
        HEADER + "DiscordTCP=direct, DiscordVoice=direct, YouTube=direct, Extra=direct.\n",
        None,
    ),
    (
        "legacy and split keys together",
        HEADER + "Discord=direct, DiscordTCP=direct, DiscordVoice=direct, YouTube=direct.\n",
        None,
    ),
    ("Voice is missing", HEADER + "DiscordTCP=direct, YouTube=direct.\n", None),
    ("YouTube is missing", HEADER + "Discord=direct.\n", None),
    ("pair without a value separator", HEADER + "DiscordTCP=direct, DiscordVoice, YouTube=direct.\n", None),
    ("no space after the comma", HEADER + "DiscordTCP=direct,DiscordVoice=direct,YouTube=direct.\n", None),
    ("no final dot", HEADER + "Discord=direct, YouTube=direct\n", None),
    # `$` ends a line at "\n" only, so the "\r" of a CRLF config sits between the dot and the line end.
    ("CRLF line ending", HEADER + "Discord=direct, YouTube=direct.\r\n", None),
    (
        "CRLF config",
        "NFQWS_ENABLED=1\r\n" + HEADER + "DiscordTCP=direct, DiscordVoice=direct, YouTube=direct.\r\nUDP_PORTS=443\r\n",
        None,
    ),
    ("not at the line start", "  " + HEADER + "Discord=direct, YouTube=direct.\n", None),
    ("empty list", HEADER + ".\n", None),
    ("no header", "NFQWS_ENABLED=1\nUDP_PORTS=443\n", None),
    ("empty text", "", None),
)

UDP_LINE = "# Discord UDP: strategy={strategy}, range={range}.\n"
WIDE_PORTS = "443,3478:3481,5349,19294:19344,50000:65535"
NARROW_PORTS = "443,3478:3481,5349,19294:19344,50000:50100"

# (name, config text, recorded_voice_range result)
RANGE_CORPUS = (
    ("header wide", UDP_LINE.format(strategy="flowseal", range="wide"), "wide"),
    ("header narrow", UDP_LINE.format(strategy="flowseal", range="narrow"), "narrow"),
    ("legacy strategy wide", UDP_LINE.format(strategy="legacy", range="wide"), "wide"),
    ("legacy strategy narrow", UDP_LINE.format(strategy="legacy", range="narrow"), "narrow"),
    ("any lowercase strategy is read from the header", UDP_LINE.format(strategy="odd", range="wide"), "wide"),
    (
        "header wins over a wide UDP_PORTS",
        UDP_LINE.format(strategy="flowseal", range="narrow") + f'UDP_PORTS="{WIDE_PORTS}"\n',
        "narrow",
    ),
    (
        "header wins over a narrow UDP_PORTS",
        f'UDP_PORTS="{NARROW_PORTS}"\n' + UDP_LINE.format(strategy="legacy", range="wide"),
        "wide",
    ),
    (
        "header among other lines",
        "NFQWS_ENABLED=1\n" + HEADER + "Discord=direct, YouTube=direct.\n"
        + UDP_LINE.format(strategy="flowseal", range="wide") + "TCP_PORTS=443\n",
        "wide",
    ),
    ("strategy outside [a-z] falls back, nothing to infer", UDP_LINE.format(strategy="FOO", range="wide"), "narrow"),
    (
        "strategy outside [a-z] falls back to UDP_PORTS",
        UDP_LINE.format(strategy="FOO", range="narrow") + f'UDP_PORTS="{WIDE_PORTS}"\n',
        "wide",
    ),
    ("unknown range falls back", UDP_LINE.format(strategy="flowseal", range="huge"), "narrow"),
    (
        "the first header line wins, narrow then wide",
        UDP_LINE.format(strategy="flowseal", range="narrow") + UDP_LINE.format(strategy="legacy", range="wide"),
        "narrow",
    ),
    (
        "the first header line wins, wide then narrow",
        UDP_LINE.format(strategy="legacy", range="wide") + UDP_LINE.format(strategy="flowseal", range="narrow"),
        "wide",
    ),
    (
        "a malformed header line is skipped for the next valid one",
        UDP_LINE.format(strategy="FOO", range="narrow") + UDP_LINE.format(strategy="legacy", range="wide"),
        "wide",
    ),
    (
        "an unknown range line is skipped for the next valid one",
        UDP_LINE.format(strategy="flowseal", range="huge") + UDP_LINE.format(strategy="flowseal", range="wide"),
        "wide",
    ),
    # `$` ends a line at "\n" only: the header with a CRLF ending is not read and UDP_PORTS decides.
    (
        "CRLF header is ignored, UDP_PORTS narrow",
        f'# Discord UDP: strategy=flowseal, range=wide.\r\nUDP_PORTS="{NARROW_PORTS}"\r\n',
        "narrow",
    ),
    (
        "CRLF header is ignored, UDP_PORTS wide",
        f'# Discord UDP: strategy=flowseal, range=narrow.\r\nUDP_PORTS="{WIDE_PORTS}"\r\n',
        "wide",
    ),
    ("CRLF header alone falls back to narrow", "# Discord UDP: strategy=flowseal, range=wide.\r\n", "narrow"),
    ("indented header is ignored", "  " + UDP_LINE.format(strategy="flowseal", range="wide"), "narrow"),
    ("header with a trailing blank is ignored", "# Discord UDP: strategy=flowseal, range=wide. \n", "narrow"),
    ("quoted wide UDP_PORTS without the header", 'UDP_PORTS="50000:65535"\n', "wide"),
    ("unquoted wide UDP_PORTS with a dash", f"UDP_PORTS={WIDE_PORTS.replace('50000:', '50000-')}\n", "wide"),
    ("wide UDP_PORTS inside a list", f'UDP_PORTS="{WIDE_PORTS}"\n', "wide"),
    ("narrow UDP_PORTS", f'UDP_PORTS="{NARROW_PORTS}"\n', "narrow"),
    ("near miss, 40000:65535", 'UDP_PORTS="443,40000:65535"\n', "narrow"),
    ("near miss, 50000:65534", 'UDP_PORTS="443,50000:65534"\n', "narrow"),
    ("two UDP_PORTS lines, wide then narrow", f'UDP_PORTS="{WIDE_PORTS}"\nUDP_PORTS="{NARROW_PORTS}"\n', "narrow"),
    ("two UDP_PORTS lines, narrow then wide", f'UDP_PORTS="{NARROW_PORTS}"\nUDP_PORTS="{WIDE_PORTS}"\n', "wide"),
    ("UDP_PORTS not at the line start", f'  UDP_PORTS="{WIDE_PORTS}"\n', "narrow"),
    ("other variable ending in UDP_PORTS", f'EXTRA_UDP_PORTS="{WIDE_PORTS}"\n', "narrow"),
    ("empty text", "", "narrow"),
    ("no UDP settings", HEADER + "Discord=direct, YouTube=direct.\nTCP_PORTS=443\n", "narrow"),
)


@contextlib.contextmanager
def isolated_imports():
    """Drop the project modules and sys.path entries that loading a router tool leaves behind."""
    modules = set(sys.modules)
    path = list(sys.path)
    try:
        yield
    finally:
        sys.path[:] = path
        for name in set(sys.modules) - modules:
            module_file = getattr(sys.modules[name], "__file__", None)
            if module_file and Path(module_file).resolve().is_relative_to(ROOT):
                del sys.modules[name]


def load_tool(filename):
    path = ROUTER_DIR / filename
    spec = importlib.util.spec_from_file_location(f"kdn_state_test_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RouteHeaderTests(unittest.TestCase):
    def test_route_constants(self):
        self.assertEqual(nfqws.ROUTE_SERVICES, ("discord-tcp", "discord-voice", "youtube", "telegram"))
        self.assertIsInstance(nfqws.ROUTE_VALUES, frozenset)
        self.assertEqual(nfqws.ROUTE_VALUES, {"direct", "zapret", "vless"})
        self.assertIsInstance(nfqws.TELEGRAM_ROUTE_VALUES, frozenset)
        self.assertEqual(nfqws.TELEGRAM_ROUTE_VALUES, {"direct", "zapret", "vless", "ws", "unmanaged"})

    def test_parse_active_routes_corpus(self):
        for name, text, expected in ROUTE_CORPUS:
            with self.subTest(name):
                self.assertEqual(nfqws.parse_active_routes(text), expected)

    def test_parse_active_routes_returns_a_fresh_dict(self):
        text = HEADER + "Discord=direct, YouTube=vless.\n"
        first = nfqws.parse_active_routes(text)
        first["youtube"] = "changed"
        self.assertEqual(nfqws.parse_active_routes(text)["youtube"], "vless")

    def test_unknown_routes_is_fresh(self):
        first = nfqws.unknown_routes()
        second = nfqws.unknown_routes()
        self.assertIsNot(first, second)
        self.assertEqual(tuple(first), nfqws.ROUTE_SERVICES)
        self.assertEqual(set(first.values()), {"unknown"})
        first["youtube"] = "changed"
        self.assertEqual(second["youtube"], "unknown")
        self.assertEqual(nfqws.unknown_routes()["youtube"], "unknown")


class ToolCopiesTests(unittest.TestCase):
    """The parser is copied into router tools until phase 8: the copies must agree on the corpus."""

    @classmethod
    def setUpClass(cls):
        stack = contextlib.ExitStack()
        cls.addClassCleanup(stack.close)
        stack.enter_context(isolated_imports())
        cls.tools = {name: load_tool(name) for name in ("zapret_autotune_job.py", "xkeen_diagnostics.py")}

    def test_tool_copies_agree(self):
        for filename, tool in self.tools.items():
            with self.subTest(filename, check="constants"):
                self.assertEqual(tool.ROUTE_VALUES, nfqws.ROUTE_VALUES)
                self.assertEqual(tool.TELEGRAM_ROUTE_VALUES, nfqws.TELEGRAM_ROUTE_VALUES)
            for name, text, _expected in ROUTE_CORPUS:
                with self.subTest(filename, case=name):
                    self.assertEqual(tool.parse_active_routes(text), nfqws.parse_active_routes(text))


class VoiceRangeTests(unittest.TestCase):
    def test_recorded_voice_range(self):
        for name, text, expected in RANGE_CORPUS:
            with self.subTest(name):
                self.assertEqual(nfqws.recorded_voice_range(text), expected)

    def test_voice_high(self):
        self.assertEqual(nfqws.NARROW_VOICE_HIGH, 50100)
        self.assertEqual(nfqws.WIDE_VOICE_HIGH, 65535)
        self.assertEqual(nfqws.voice_high("wide"), 65535)
        self.assertEqual(nfqws.voice_high("narrow"), 50100)
        for other in ("", "huge", "WIDE", None):
            with self.subTest(other=other):
                self.assertEqual(nfqws.voice_high(other), 50100)

    def test_voice_high_follows_the_recorded_range(self):
        for name, text, expected in RANGE_CORPUS:
            with self.subTest(name):
                high = nfqws.voice_high(nfqws.recorded_voice_range(text))
                self.assertEqual(high, 65535 if expected == "wide" else 50100)

    def test_voice_ports_allowed(self):
        allowed = nfqws.voice_ports_allowed
        for value in (
            "443",
            "3478",
            "3478-3481",
            "3479-3480",
            "5349",
            "19294-19344",
            "19300",
            "50000-65535",
            "60000",
            "443,3478-3481,50000-65535",
        ):
            with self.subTest(value=value):
                self.assertTrue(allowed(value))
        for value in (
            "",
            "80",
            "443-444",
            "3477-3481",
            "3478-3482",
            "5350",
            "19293-19344",
            "49999-65535",
            "50000-65536",
            "3481-3478",
            "abc",
            "1-2-3",
            "443,80",
            "443,",
            " 443",
        ):
            with self.subTest(value=value):
                self.assertFalse(allowed(value))
        # The narrow range ends at 50100, as the engine's VOICE_HIGH.
        self.assertTrue(allowed("19294-19344,50000-50100", 50100))
        self.assertFalse(allowed("50000-50101", 50100))
        self.assertFalse(allowed("60000", 50100))

    def test_voice_ports_allowed_depends_on_the_upper_port(self):
        self.assertTrue(nfqws.voice_ports_allowed("50000-65535", high=65535))
        self.assertFalse(nfqws.voice_ports_allowed("50000-65535", high=50100))
        self.assertTrue(nfqws.voice_ports_allowed("50000-65535"))
        self.assertTrue(nfqws.voice_ports_allowed("50000-50100", high=nfqws.voice_high("narrow")))
        self.assertFalse(nfqws.voice_ports_allowed("50000-50101", high=nfqws.voice_high("narrow")))


if __name__ == "__main__":
    unittest.main()

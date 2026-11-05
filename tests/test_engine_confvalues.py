"""Tests of kdn.engine.confvalues: the awk and sed readers of init, hook and nfqws2.conf, ported to Python.

The unit tests pin the quirks one by one; the differential tests run the real functions of
apply-discord-nfqws2.sh (extracted by engine_shell) and the port on one corpus and compare stdout, stderr and the
return code, under the awk of the test stand (mawk) and under busybox awk (the awk of the router). The two awks
split default-FS fields differently (see ``AWK_FIELD_SEPARATORS``): the port is checked under both models.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import contextlib
import os
from pathlib import Path
import shutil
import tempfile
import threading
import types
import unittest
from unittest import mock

import engine_shell
from kdn.engine import confvalues


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "engine" / "router-xkeen20" / "opt" / "etc"
CONFVALUES = ROOT / "tools" / "router" / "kdn" / "engine" / "confvalues.py"
HAS_BUSYBOX = shutil.which("busybox") is not None


def _system_awk_is_mawk():
    if not shutil.which("awk"):
        return False
    return engine_shell.run_sh("awk -W version 2>&1 | head -n 1").stdout.startswith("mawk")


SYSTEM_AWK_IS_MAWK = _system_awk_is_mawk()
NOT_MAWK = "the system awk is not mawk: the stand model of the field separators does not apply"
# Default-FS separators of mawk (the stand) and of busybox awk (the router).
MAWK_SEPARATORS = " \t\n"
BUSYBOX_SEPARATORS = " \t\n\v\f\r"
HEADER = "# Active routes: "


def paths_for(init=None, hook=None, conf=None):
    return types.SimpleNamespace(xkeen_init=init, xkeen_hook=hook, nfqws_conf=conf)


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = self.enterContext(tempfile.TemporaryDirectory(prefix="confvalues-"))

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(data if isinstance(data, bytes) else data.encode("utf-8", "surrogateescape"))
        return path


class ReadTextTests(TempDirTestCase):
    def test_read_text_keeps_cr_and_lines_split_only_on_lf(self):
        path = self.write("f", b"a\r\nb\rc\n\xc2\xa0x\xff\n")
        text = confvalues.read_text(path)
        self.assertEqual(text, "a\r\nb\rc\n\u00a0x\udcff\n")
        self.assertEqual(confvalues.lines(text), ["a\r", "b\rc", "\u00a0x\udcff"])
        self.assertEqual(confvalues.read_text(Path(path)), text)

    def test_lines_splits_only_on_lf_and_drops_one_final_empty_record(self):
        self.assertEqual(confvalues.lines(""), [])
        self.assertEqual(confvalues.lines(None), [])
        self.assertEqual(confvalues.lines("a"), ["a"])
        self.assertEqual(confvalues.lines("a\n"), ["a"])
        self.assertEqual(confvalues.lines("a\n\n"), ["a", ""])
        self.assertEqual(confvalues.lines("\n"), [""])
        odd = "a\x0bb\x0cc\u2028d\x85e\u00a0f\r"
        self.assertEqual(confvalues.lines(odd + "\n" + odd), [odd, odd])

    def test_read_text_of_a_file_that_sh_would_not_test_with_f_is_none(self):
        self.assertIsNone(confvalues.read_text(os.path.join(self.tmp, "missing")))
        self.assertIsNone(confvalues.read_text(self.tmp))
        os.symlink(os.path.join(self.tmp, "missing"), os.path.join(self.tmp, "dangling"))
        self.assertIsNone(confvalues.read_text(os.path.join(self.tmp, "dangling")))
        self.assertIsNone(confvalues.read_text(None))

    def test_read_text_does_not_open_devices_or_fifos(self):
        # [ -f ] is false for them; a FIFO opened for reading would block.
        self.assertIsNone(confvalues.read_text("/dev/null"))
        fifo = os.path.join(self.tmp, "fifo")
        os.mkfifo(fifo)
        result = []
        reader = threading.Thread(target=lambda: result.append(confvalues.read_text(fifo)), daemon=True)
        reader.start()
        reader.join(5)
        blocked = reader.is_alive()
        if blocked:
            # Lets a reader stuck in open() go, so that the test process can end.
            with contextlib.suppress(OSError):
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            reader.join(5)
        self.assertFalse(blocked)
        self.assertEqual(result, [None])

    def test_read_text_follows_symlinks_and_reads_empty_files(self):
        path = self.write("f", b"")
        self.assertEqual(confvalues.read_text(path), "")
        os.symlink(self.write("g", b"x=1\n"), os.path.join(self.tmp, "link"))
        self.assertEqual(confvalues.read_text(os.path.join(self.tmp, "link")), "x=1\n")


class FieldsTests(unittest.TestCase):
    def test_fields_is_the_public_name_of_the_awk_field_splitter(self):
        self.assertIs(confvalues.fields, confvalues._fields)
        self.assertEqual(confvalues.fields("  Version:\t1.2-3  "), ["Version:", "1.2-3"])
        self.assertEqual(confvalues.fields(""), [])
        self.assertEqual(confvalues.fields("a\u00a0b c"), ["a\u00a0b", "c"])
        self.assertEqual(confvalues.fields("a\rb\x0cc\x0bd"), ["a", "b", "c", "d"])
        with mock.patch.object(confvalues, "AWK_FIELD_SEPARATORS", MAWK_SEPARATORS):
            self.assertEqual(confvalues.fields("a\rb c"), ["a\rb", "c"])


class AssignedValueTests(unittest.TestCase):
    def test_assigned_value_first_match_quotes_and_whitespace(self):
        text = 'a=1\nb="two"\nk=\'three\'\na=9\nc =  spaced \t\nd=  "kept inner"  \n'
        self.assertEqual(confvalues.assigned_value(text, "a"), "1")
        self.assertEqual(confvalues.assigned_value(text, "b"), "two")
        self.assertEqual(confvalues.assigned_value(text, "k"), "three")
        self.assertEqual(confvalues.assigned_value(text, "d"), "kept inner")
        self.assertEqual(confvalues.assigned_value(text, "missing"), "")
        self.assertEqual(confvalues.assigned_value("", "a"), "")
        self.assertEqual(confvalues.assigned_value(None, "a"), "")

    def test_assigned_value_requires_the_exact_key_field(self):
        text = "key =1\nkey2=2\n key=3\nKEY=4\nkey\t=5\nxkey=6\n"
        self.assertEqual(confvalues.assigned_value(text, "key"), "")
        self.assertEqual(confvalues.assigned_value(text + "key=7\n", "key"), "7")
        self.assertEqual(confvalues.assigned_value(text, "key2"), "2")
        self.assertEqual(confvalues.assigned_value(text, "key "), "1")

    def test_assigned_value_handles_crlf_and_equals_in_value(self):
        self.assertEqual(confvalues.assigned_value("key=val\r\n", "key"), "val")
        self.assertEqual(confvalues.assigned_value('key="val"\r\n', "key"), "val")
        self.assertEqual(confvalues.assigned_value("key=a=b=\r\n", "key"), "a=b=")
        self.assertEqual(confvalues.assigned_value('key="a=b"\n', "key"), "a=b")
        self.assertEqual(confvalues.assigned_value("key==\n", "key"), "=")
        self.assertEqual(confvalues.assigned_value('key="x\r"\n', "key"), "x\r")
        self.assertEqual(confvalues.assigned_value("key=a\rb\n", "key"), "a\rb")

    def test_assigned_value_keeps_nbsp_and_formfeed_semantics(self):
        self.assertEqual(confvalues.assigned_value("k=\u00a0v\u00a0\n", "k"), "\u00a0v\u00a0")
        self.assertEqual(confvalues.assigned_value("k=v\u00a0w\n", "k"), "v\u00a0w")
        self.assertEqual(confvalues.assigned_value("k=\u2003v\u2003\n", "k"), "\u2003v\u2003")
        self.assertEqual(confvalues.assigned_value("k=\x85v\x85\n", "k"), "\x85v\x85")
        # [[:space:]] is blank, tab, CR, LF, VT and FF.
        self.assertEqual(confvalues.assigned_value("k=\x0c\x0b v\x0c\x0b \n", "k"), "v")
        self.assertEqual(confvalues.assigned_value('k=\x0c"v"\x0c\n', "k"), "v")
        self.assertEqual(confvalues.assigned_value('k=" "\n', "k"), " ")
        self.assertEqual(confvalues.assigned_value("k=\u00a0\n", "k"), "\u00a0")

    def test_assigned_value_quote_stripping_rules(self):
        cases = {
            '""': "",
            "''": "",
            '"': '"',
            "'": "'",
            "\"x'": "\"x'",
            "'x\"": "'x\"",
            '"x"y"': 'x"y',
            "'x'y'": "x'y",
            "\"'x'\"": "'x'",
            '""""': '""',
            '"x" # c': '"x" # c',
            "x\"": 'x"',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(confvalues.assigned_value(f"k={value}\n", "k"), expected)

    def test_assigned_value_of_a_line_without_equals_is_the_line_itself(self):
        # awk: $1 is the whole line, sub() does not match, so the "value" is the key.
        self.assertEqual(confvalues.assigned_value("k\n", "k"), "k")
        self.assertEqual(confvalues.assigned_value("k\nk=2\n", "k"), "k")
        self.assertEqual(confvalues.assigned_value("k  \n", "k"), "")
        self.assertEqual(confvalues.assigned_value("k\n", "k", last=True), "k")

    def test_assigned_value_does_not_see_through_a_bom_or_export(self):
        self.assertEqual(confvalues.assigned_value("\ufeffk=1\nk=2\n", "k"), "2")
        self.assertEqual(confvalues.assigned_value("export k=1\n", "k"), "")

    def test_nfqws_value_takes_the_last_assignment_even_when_empty(self):
        self.assertEqual(confvalues.assigned_value("k=1\nk=2\nk=3\n", "k", last=True), "3")
        self.assertEqual(confvalues.assigned_value("k=1\nk=\n", "k", last=True), "")
        self.assertEqual(confvalues.assigned_value('k=1\nk=""\n', "k", last=True), "")
        self.assertEqual(confvalues.assigned_value("k=\nk=2\n", "k", last=True), "2")
        self.assertEqual(confvalues.assigned_value("k=1\nk=\nk=3\n", "k"), "1")
        self.assertEqual(confvalues.assigned_value("k=1\nk=2", "k", last=True), "2")

    def test_assigned_value_of_the_first_match_ignores_later_lines(self):
        self.assertEqual(confvalues.assigned_value("k=\nk=2\n", "k"), "")
        self.assertEqual(confvalues.assigned_value("k=1\nk=2\n", "k"), "1")


class FileReadersTests(TempDirTestCase):
    def test_init_runtime_and_nfqws_values_read_their_own_file(self):
        paths = paths_for(
            self.write("init", 'name_client="xray"\nk=init\n'),
            self.write("hook", "k=hook\nmode_proxy='Hybrid'\n"),
            self.write("conf", "k=conf1\nk=conf2\nUDP_PORTS=1\n"),
        )
        self.assertEqual(confvalues.init_value(paths, "k"), "init")
        self.assertEqual(confvalues.init_value(paths, "name_client"), "xray")
        self.assertEqual(confvalues.runtime_value(paths, "k"), "hook")
        self.assertEqual(confvalues.runtime_value(paths, "mode_proxy"), "Hybrid")
        self.assertEqual(confvalues.nfqws_value(paths, "k"), "conf2")
        self.assertEqual(confvalues.nfqws_value(paths, "UDP_PORTS"), "1")
        self.assertEqual(confvalues.nfqws_value(paths, "name_client"), "")

    def test_missing_files_give_empty_values(self):
        paths = paths_for(
            os.path.join(self.tmp, "no-init"), os.path.join(self.tmp, "no-hook"), os.path.join(self.tmp, "no-conf")
        )
        for function in (confvalues.init_value, confvalues.runtime_value, confvalues.xkeen_effective_value, confvalues.nfqws_value):
            with self.subTest(function=function.__name__):
                self.assertEqual(function(paths, "k"), "")
        self.assertEqual(confvalues.init_value(paths_for(self.tmp), "k"), "")

    def test_xkeen_effective_value_prefers_a_non_empty_runtime_value(self):
        init = self.write("init", "a=init\nb=init\nc=init\n")
        hook = self.write("hook", "a=hook\nb=\nd=hook\n")
        paths = paths_for(init, hook, None)
        self.assertEqual(confvalues.xkeen_effective_value(paths, "a"), "hook")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "b"), "init")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "c"), "init")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "d"), "hook")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "e"), "")
        no_hook = paths_for(init, os.path.join(self.tmp, "none"), None)
        self.assertEqual(confvalues.xkeen_effective_value(no_hook, "a"), "init")

    def test_fixture_tree_values(self):
        paths = paths_for(
            str(FIXTURE / "init.d" / "S05xkeen"),
            str(FIXTURE / "ndm" / "netfilter.d" / "proxy.sh"),
            str(FIXTURE / "nfqws2" / "nfqws2.conf"),
        )
        self.assertEqual(confvalues.init_value(paths, "name_client"), "xray")
        self.assertEqual(confvalues.init_value(paths, "table_mark"), "0x111")
        self.assertEqual(confvalues.init_value(paths, "custom_mark"), "")
        self.assertEqual(confvalues.runtime_value(paths, "mode_proxy"), "Hybrid")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "mode_proxy"), "Hybrid")
        self.assertEqual(confvalues.xkeen_effective_value(paths, "dscp_proxy"), "63")
        self.assertEqual(confvalues.nfqws_value(paths, "UDP_PORTS"), "443,19294:19344,50000:50100")
        self.assertEqual(confvalues.nfqws_value(paths, "ISP_INTERFACE"), "eth3")
        text = confvalues.read_text(paths.nfqws_conf)
        self.assertEqual(
            [confvalues.recorded_route(text, service) for service in ("discord-tcp", "discord-voice", "youtube")],
            ["zapret", "zapret", "zapret"],
        )
        self.assertEqual(confvalues.recorded_telegram_route(text), "vless")
        self.assertEqual(confvalues.recorded_deployment_mode(text), "xkeen-integrated")
        self.assertEqual(confvalues.recorded_proxy_outbound(text), "vless-reality")
        self.assertEqual(confvalues.recorded_udp_settings(text, confvalues.nfqws_value(paths, "UDP_PORTS")), ("flowseal", "narrow"))
        self.assertEqual(confvalues.voice_profile_header(text), ("f3de2c222df9", "19294-19344,50000-50100"))


class PortsTests(unittest.TestCase):
    def test_active_ports_and_ports_overlap_tables(self):
        text = "# ports\r\n80\r\n  443  \r\n\r\n#8080\r\n5222-5223\r\n596:599\n\tfoo\n80 81\n1:2:3\n+1\n7"
        self.assertEqual(confvalues.active_ports(text), "80,443,5222:5223,596:599,8081,7")
        self.assertEqual(confvalues.active_ports(""), "")
        self.assertEqual(confvalues.active_ports(None), "")
        self.assertEqual(confvalues.active_ports("# only\n\n"), "")
        self.assertEqual(confvalues.active_ports("80"), "80")
        self.assertEqual(confvalues.active_ports("80\r\r\n443\r\r\r\n"), "80,443")
        self.assertEqual(confvalues.active_ports("\x0c80\x0b\n"), "80")
        self.assertEqual(confvalues.active_ports("\u00a080\n443\u00a0\n"), "")
        self.assertEqual(confvalues.active_ports("\uff18\uff10\n"), "")
        self.assertEqual(confvalues.active_ports("80\r443\n"), "")
        self.assertEqual(confvalues.active_ports("80-\n-80\n:80\n80:\n"), "")
        table = {
            ("80", "80"): True,
            ("80", "81"): False,
            ("80:90", "85"): True,
            ("80:90", "90"): True,
            ("80:90", "91:99"): False,
            ("80:90", "70:80"): True,
            ("80-90", "91-99"): False,
            ("9:10", "10"): True,
            ("9", "10"): False,
            ("1:2:3", "2"): True,
            ("1:2:3", "3"): False,
            ("1-2-3", "2"): True,
            ("", "80"): False,
            ("80", ""): False,
            ("", ""): False,
            ("a,80", "80"): True,
            ("80,,90", "90"): True,
            ("80:", "80"): False,
            (":80", "80"): False,
            ("80 ", "80"): False,
            ("0080", "80"): True,
            ("90:80", "85"): False,
            ("50:100", "90:80"): True,
            ("443,5222:5223", "596:599,5223"): True,
            ("443,5222:5223", "596:599,5224"): False,
            ("99999999999999999999", "99999999999999999999"): True,
            ("9007199254740993", "9007199254740992"): True,
        }
        for (left, right), expected in table.items():
            with self.subTest(left=left, right=right):
                self.assertIs(confvalues.ports_overlap(left, right), expected)


class RecordedRoutesTests(unittest.TestCase):
    def route(self, text, service="youtube"):
        return confvalues.recorded_route(text, service)

    def test_recorded_route_quirks(self):
        modern = HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=direct.\n"
        self.assertEqual(
            [self.route(modern, service) for service in ("discord-tcp", "discord-voice", "youtube")],
            ["direct", "zapret", "vless"],
        )
        legacy = HEADER + "Discord=zapret, YouTube=vless.\n"
        self.assertEqual(
            [self.route(legacy, service) for service in ("discord-tcp", "discord-voice", "youtube")],
            ["zapret", "zapret", "vless"],
        )
        # The last pair of a line wins, whichever key it is.
        mixed = HEADER + "Discord=zapret, DiscordVoice=vless, YouTube=direct.\n"
        self.assertEqual(self.route(mixed, "discord-tcp"), "zapret")
        self.assertEqual(self.route(mixed, "discord-voice"), "vless")
        reversed_pairs = HEADER + "DiscordVoice=vless, Discord=zapret, YouTube=direct.\n"
        self.assertEqual(self.route(reversed_pairs, "discord-voice"), "zapret")
        duplicate = HEADER + "YouTube=direct, YouTube=vless.\n"
        self.assertEqual(self.route(duplicate), "vless")
        # The last header line wins, and it starts from nothing.
        two = HEADER + "YouTube=direct.\n" + HEADER + "YouTube=vless.\n"
        self.assertEqual(self.route(two), "vless")
        reset = HEADER + "YouTube=direct.\n" + HEADER + "DiscordTCP=direct.\n"
        self.assertIsNone(self.route(reset))
        self.assertEqual(self.route(reset, "discord-tcp"), "direct")
        # Anything that is not direct, zapret or vless, and a missing file or header, gives None.
        for value in ("bogus", "", "Direct", "ws", "unmanaged", "direct=zapret=x"):
            with self.subTest(value=value):
                expected = "direct" if value == "direct=zapret=x" else None
                self.assertEqual(self.route(HEADER + f"YouTube={value}.\n"), expected)
        self.assertIsNone(self.route(HEADER + "YouTube.\n"))
        self.assertIsNone(self.route(""))
        self.assertIsNone(self.route(None))
        self.assertIsNone(self.route("\n\n"))
        self.assertIsNone(self.route(modern, "bogus"))
        self.assertIsNone(self.route(modern, "telegram"))

    def test_recorded_route_trailing_punctuation_and_field_rules(self):
        self.assertEqual(self.route(HEADER + "YouTube=vless,\n"), "vless")
        self.assertEqual(self.route(HEADER + "YouTube=vless.\n"), "vless")
        self.assertEqual(self.route(HEADER + "YouTube=vless\n"), "vless")
        self.assertIsNone(self.route(HEADER + "YouTube=vless..\n"))
        self.assertIsNone(self.route(HEADER + "YouTube=vless.,\n"))
        # Blanks and tabs separate fields; leading blanks are fine; the three words must be separate fields.
        self.assertEqual(self.route("  #\tActive   routes:\tYouTube=vless.\n"), "vless")
        self.assertIsNone(self.route("#Active routes: YouTube=vless.\n"))
        self.assertIsNone(self.route("# Active routes:YouTube=vless.\n"))
        self.assertIsNone(self.route("# active routes: YouTube=vless.\n"))
        self.assertIsNone(self.route("# Active routes: YouTube = vless.\n"))
        self.assertIsNone(self.route("# note\nYouTube=vless\n"))
        # NBSP is not a separator.
        self.assertIsNone(self.route(HEADER + "DiscordTCP=direct,\u00a0YouTube=vless.\n"))
        self.assertEqual(self.route(HEADER + "DiscordTCP=direct,\u00a0YouTube=vless.\nx\n", "discord-tcp"), None)

    def test_recorded_route_without_a_final_newline(self):
        self.assertEqual(self.route(HEADER + "YouTube=zapret."), "zapret")

    def test_recorded_telegram_route_value_survives_lines_without_telegram(self):
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=ws.\n" + HEADER + "YouTube=vless.\n"), "ws")
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=zapret.\n"), "zapret")
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=direct,\n"), "direct")
        for value in ("vless", "unmanaged", "direct"):
            self.assertEqual(confvalues.recorded_telegram_route(HEADER + f"Telegram={value}.\n"), value)
        for value in ("garbage", "", "WS", "ws=x", "Direct", "wss"):
            with self.subTest(value=value):
                expected = "ws" if value == "ws=x" else "unmanaged"
                self.assertEqual(confvalues.recorded_telegram_route(HEADER + f"Telegram={value}.\n"), expected)
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=ws, Telegram=vless.\n"), "vless")
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=ws.\n" + HEADER + "Telegram=junk.\n"), "unmanaged")
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "Telegram=ws.\n" + HEADER + "Telegram=.\n"), "unmanaged")
        self.assertEqual(confvalues.recorded_telegram_route(HEADER + "YouTube=vless.\n"), "unmanaged")
        self.assertEqual(confvalues.recorded_telegram_route(""), "unmanaged")
        self.assertEqual(confvalues.recorded_telegram_route(None), "unmanaged")
        self.assertEqual(confvalues.recorded_telegram_route("Telegram=ws\n"), "unmanaged")

    def test_crlf_header_follows_the_awk_field_separators(self):
        youtube_last = HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\r\n"
        telegram_last = HEADER + "DiscordTCP=direct, YouTube=vless, Telegram=ws.\r\n"
        # busybox awk (the router) also splits fields on CR, VT and FF: the CR is dropped.
        self.assertEqual(confvalues.AWK_FIELD_SEPARATORS, BUSYBOX_SEPARATORS)
        self.assertEqual(self.route(youtube_last), "vless")
        self.assertEqual(confvalues.recorded_telegram_route(telegram_last), "ws")
        self.assertEqual(self.route(HEADER + "YouTube=vless\x0c.\n"), "vless")
        # mawk keeps the CR in the last field: "vless.\r" keeps its dot and is no route.
        with mock.patch.object(confvalues, "AWK_FIELD_SEPARATORS", MAWK_SEPARATORS):
            self.assertIsNone(self.route(youtube_last))
            self.assertEqual(self.route(youtube_last, "discord-tcp"), "direct")
            self.assertEqual(confvalues.recorded_telegram_route(telegram_last), "unmanaged")
            self.assertIsNone(self.route(HEADER + "YouTube=vless\x0c.\n"))

    def test_recorded_deployment_mode_proxy_outbound_and_udp_settings(self):
        mode = confvalues.recorded_deployment_mode
        self.assertEqual(mode("# Deployment mode: xkeen-integrated.\n"), "xkeen-integrated")
        self.assertEqual(mode("# x\n# Deployment mode: standalone-zapret.\n"), "standalone-zapret")
        self.assertIsNone(mode("# Deployment mode: foo.\n# Deployment mode: xkeen-integrated.\n"))
        self.assertEqual(mode("# Deployment mode: xkeen-integrated.\n# Deployment mode: foo.\n"), "xkeen-integrated")
        for text in (
            "# Deployment mode: xkeen-integrated.\r\n",
            "# Deployment mode: xkeen-integrated. \n",
            " # Deployment mode: xkeen-integrated.\n",
            "# Deployment mode: Xkeen-integrated.\n",
            "# deployment mode: xkeen-integrated.\n",
            "# Deployment Mode: xkeen-integrated.\n",
            "# Deployment mode: xkeen-integrated\n",
            "# Deployment mode: .\n",
            "# Deployment mode: xkeen_integrated.\n",
            "",
            None,
        ):
            with self.subTest(text=text):
                self.assertIsNone(mode(text))
        self.assertEqual(mode("# Deployment mode: xkeen-integrated."), "xkeen-integrated")

        proxy = confvalues.recorded_proxy_outbound
        self.assertEqual(proxy("# Proxy outbound: vless-reality.\n"), "vless-reality")
        self.assertEqual(proxy("# Proxy outbound: a.b:c-d_E9.\n"), "a.b:c-d_E9")
        self.assertEqual(proxy("# Proxy outbound: a..\n"), "a.")
        self.assertEqual(proxy("# Proxy outbound: one.\n# Proxy outbound: two.\n"), "one")
        # The first matching line decides, even when it is empty.
        self.assertIsNone(proxy("# Proxy outbound: .\n# Proxy outbound: two.\n"))
        self.assertEqual(proxy("# Proxy outbound: a b.\n# Proxy outbound: two.\n"), "two")
        for text in (
            "# Proxy outbound: x\n",
            "# Proxy outbound: x.\r\n",
            "# Proxy outbound: \u00e9.\n",
            "# proxy outbound: x.\n",
            "",
            None,
        ):
            with self.subTest(text=text):
                self.assertIsNone(proxy(text))

        udp = confvalues.recorded_udp_settings
        for strategy in ("flowseal", "legacy"):
            for voice_range in ("narrow", "wide"):
                self.assertEqual(
                    udp(f"# Discord UDP: strategy={strategy}, range={voice_range}.\n", ""), (strategy, voice_range)
                )
        # The header wins over everything else.
        self.assertEqual(
            udp("# Discord UDP: strategy=legacy, range=narrow.\n--blob=discord_udp:x\n", "50000:65535"),
            ("legacy", "narrow"),
        )
        # An invalid first header line is not skipped in favour of a valid later one.
        self.assertEqual(udp("# discord udp: strategy=legacy, range=wide.\n", ""), ("", "narrow"))
        invalid_first = "# Discord UDP: strategy=foo, range=wide.\n# Discord UDP: strategy=legacy, range=wide.\n"
        self.assertEqual(udp(invalid_first, ""), ("", "narrow"))
        self.assertEqual(udp("# Discord UDP: strategy=flowseal, range=medium.\n", "50000-65535"), ("", "wide"))
        # Without a header: the range from UDP_PORTS and the strategy from the profile.
        self.assertEqual(udp("--blob=discord_udp:@/x\n", "443,50000:65535"), ("flowseal", "wide"))
        self.assertEqual(udp("--filter-l7=stun,discord\n", "443,50000-65535"), ("legacy", "wide"))
        self.assertEqual(udp("--filter-l7=stun,discord --blob=discord_udp:x\n", ""), ("flowseal", "narrow"))
        self.assertEqual(udp("# --filter-l7=stun,discord\n", "50000:50100"), ("legacy", "narrow"))
        self.assertEqual(udp("nothing\n", ""), ("", "narrow"))
        self.assertEqual(udp("", ""), ("", "narrow"))
        self.assertEqual(udp(None, ""), ("", "narrow"))

    def test_voice_profile_header(self):
        voice = confvalues.voice_profile_header
        self.assertEqual(
            voice("# Discord Voice profile: imported f3de2c222df9, udp=19294-19344,50000-50100.\n"),
            ("f3de2c222df9", "19294-19344,50000-50100"),
        )
        self.assertEqual(voice("# Discord Voice profile: imported , udp=.\n"), ("", ""))
        self.assertEqual(voice("# Discord Voice profile: imported ab, udp=1.\n# Discord Voice profile: imported cd, udp=2.\n"), ("ab", "1"))
        for text in (
            "# Discord Voice profile: imported ABC, udp=1.\n",
            "# Discord Voice profile: imported abc, udp=1:2.\n",
            "# Discord Voice profile: imported abc,  udp=1.\n",
            "# Discord Voice profile: imported abc, udp=1.\r\n",
            "# Discord Voice profile: builtin.\n",
            "# discord voice profile: imported abc, udp=1.\n",
            "",
            None,
        ):
            with self.subTest(text=text):
                self.assertIsNone(voice(text))


class SourceRulesTests(unittest.TestCase):
    def test_no_str_split_splitlines_or_strip_without_arguments(self):
        tree = ast.parse(CONFVALUES.read_text(encoding="utf-8"))
        bad = [
            f"line {node.lineno}: .{node.func.attr}()"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("split", "rsplit", "splitlines", "strip", "lstrip", "rstrip")
            and not node.args
            and not node.keywords
        ]
        self.assertEqual(bad, [])

    def test_module_imports_stay_inside_the_budget(self):
        tree = ast.parse(CONFVALUES.read_text(encoding="utf-8"))
        imported = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        forbidden = {"dataclasses", "inspect", "typing", "tempfile", "shutil", "argparse", "logging", "enum", "subprocess"}
        self.assertEqual(sorted(imported & forbidden), [])
        # The module reads files and text only: no kdn import is needed.
        self.assertFalse({name for name in imported if name == "kdn"})


# ---------------------------------------------------------------------------------------------------------------------
# Differential tests against the shell functions.

KEYS = ("a", "b", "k", "name_client", "UDP_PORTS", "missing")

ASSIGNMENT_CORPUS = {
    "plain": b"a=1\nb=\"2\"\nk='3'\nname_client=\"xray\"\n",
    "unquoted and hex": b"a=0x111\nb=on\nk=off\nUDP_PORTS=443,50000:65535\n",
    "tab whitespace": b"a=\t1\t\nb=\t\"2\"\t\nk=\t'3 4'\t\n",
    "space whitespace": b"a=   1   \nb=  \"2\"  \nk=   \n",
    "key followed by blank": b"a =1\nb\t=2\nk =3\n",
    "key preceded by blank": b" a=1\n\tb=2\n  k=3\n",
    "prefix and suffix keys": b"a2=1\nab=2\nxa=3\nA=4\na=5\n",
    "duplicate keys": b"a=1\na=2\nb=\nb=3\nk=5\nk=\nUDP_PORTS=1\nUDP_PORTS=2\n",
    "empty values": b"a=\nb=\"\"\nk=''\n",
    "empty last value": b"a=1\na=\nUDP_PORTS=443\nUDP_PORTS=\n",
    "empty first value": b"a=\na=1\n",
    "line equal to the key": b"a\nb\nk\n",
    "line equal to the key first": b"a\na=2\nk  \n",
    "equals in the value": b"a=b=c\nb==\nk=\"x=y\"\n",
    "lone quotes": b"a=\"\nb='\nk=\"x\n",
    "mismatched quotes": b"a=\"x'\nb='x\"\nk=\"x\n",
    "quote inside": b"a=\"x\"y\"\nb='x'y'\nk=x\"y\n",
    "spaces inside quotes": b"a=\" x \"\nb=' '\nk=\"  \"\n",
    "quotes around quotes": b"a=\"'x'\"\nb='\"x\"'\nk=\"\"\"\"\n",
    "crlf": b"a=1\r\nb=\"2\"\r\nk='3'\r\nname_client=xray\r\nUDP_PORTS=1\r\n",
    "cr inside": b"a=\"x\r\"\nb=x\ry\nk=\r\n",
    "double cr": b"a=1\r\r\nb=\"2\"\r\r\n",
    "lone cr line endings": b"a=1\rb=2\rk=3\r",
    "nbsp": b"a=\xc2\xa0v\xc2\xa0\nb=v\xc2\xa0w\nk=\"\xc2\xa0\"\n",
    "nbsp only": b"a=\xc2\xa0\nb=\xc2\xa0\xc2\xa0\n",
    "em space": b"a=\xe2\x80\x831\xe2\x80\x83\nb=\"\xe2\x80\x83\"\n",
    "next line char": b"a=\xc2\x851\xc2\x85\n",
    "form feed and vertical tab": b"a=v\x0c\nb=\x0cv\nk=\x0bv\x0b\x0c\n",
    "form feed around quotes": b"a=\x0c\"v\"\x0c\nb=\x0b'w'\x0b\n",
    "comments": b"# a=1\n#b=2\na=3 # c\nb=4\n",
    "export prefix": b"export a=1\nb=2\n",
    "invalid utf8": b"a=\xff\xfe\nb=\"\xff\"\nk=\xc3\n",
    "bom": b"\xef\xbb\xbfa=1\nb=2\n",
    "no final newline": b"a=1\nb=2",
    "no final newline empty value": b"a=1\nb=",
    "blank lines": b"\n\na=1\n\n\nb=2\n\n",
    "only newlines": b"\n\n\n",
    "empty file": b"",
    "long value": b"a=" + b"x" * 5000 + b"\nb=\"" + b"y z" * 2000 + b"\"\n",
    "key as value": b"a=b=1\nb=a\n",
    "shell script": b"#!/bin/sh\nname_client=\"xray\"\ntable_mark=\"0x111\"\nif [ -z \"$a\" ]; then a=1; fi\n",
    "semicolon": b"a=1;b=2\nb=3\n",
    "backslash": b"a=x\\ny\nb=\"\\\"\"\nk=\\\n",
    "tab as the only blank": b"a\t=1\nb=\t\n",
}

PORT_CORPUS = {
    "plain": b"80\n443\n",
    "crlf": b"80\r\n443\r\n",
    "comments and blanks": b"# header\n\n80\n   # indented\n\n443\n#80\n",
    "spaces and tabs": b"  80  \n\t443\t\n \t 8443 \t\n",
    "ranges": b"80-90\n443:450\n5222\n50000-50030\n",
    "invalid lines": b"abc\n80 443\n80,443\n+80\n-1\n80-\n:80\n1:2:3\n1-2-3\n\n80x\n",
    "decimal looking": b"0\n007\n99999999999999999999\n",
    "fullwidth digits": "\uff18\uff10\n443\n".encode(),
    "nbsp": b"\xc2\xa080\n443\xc2\xa0\n80\xc2\xa081\n",
    "form feed and vertical tab": b"\x0c80\x0b\n\x0b443\x0c\n",
    "double cr": b"80\r\r\n443\r\r\r\n",
    "inner cr": b"80\r443\n",
    "comment after a number": b"80 # web\n443\n",
    "no final newline": b"80\n443",
    "single": b"80\n",
    "empty": b"",
    "only comments": b"# a\n# b\n",
    "only blank": b"\n\n  \n",
    "comment without newline": b"# a",
    "dashes": b"80--90\n80:-90\n--\n-\n:\n",
    "many": b"\n".join(str(number).encode() for number in range(1000, 1300)) + b"\n",
    "fixture proxying list": (FIXTURE / "xkeen" / "port_proxying.lst").read_bytes(),
    "fixture exclude list": (FIXTURE / "xkeen" / "port_exclude.lst").read_bytes(),
}

# Frozen shell remains characterized on its old grammar. Native2.1 parses
# commas/inline comments and validates bounded, normalized numeric endpoints.
PORT_INTENTIONAL_DIFFERENCES = {
    'invalid lines': ('', '80,443'),
    'decimal looking': ('0,007,99999999999999999999', '7'),
    'comment after a number': ('443', '80,443'),
}

OVERLAP_PAIRS = (
    ("80", "80"), ("80", "81"), ("80:90", "85"), ("80:90", "90"), ("80:90", "91:99"), ("80:90", "70:80"),
    ("80-90", "91-99"), ("80-90", "90-99"), ("9:10", "10"), ("9", "10"), ("10", "9"), ("9:10", "9:10"),
    ("1:2:3", "2"), ("1:2:3", "3"), ("1-2-3", "2"), ("1-2-3", "3"), ("1:2:x", "2"), ("", "80"), ("80", ""),
    ("", ""), ("a,80", "80"), ("80,,90", "90"), (",80", "80"), ("80,", "80"), ("80:", "80"), (":80", "80"),
    ("80 ", "80"), (" 80", "80"), ("0080", "80"), ("0", "0"), ("90:80", "85"), ("90:80", "80"), ("50:100", "90:80"),
    ("90:80", "100:50"), ("443,5222:5223", "596:599,5223"), ("443,5222:5223", "596:599,5224"),
    ("1e3", "1000"), ("0x10", "16"), ("+80", "80"), ("-80", "80"), ("80.5", "80"), ("99999999999999999999",) * 2,
    ("99999999999999999999", "99999999999999999998"), ("9007199254740993", "9007199254740992"),
    ("9007199254740992", "9007199254740993"), ("9" * 400, "9" * 400), ("9" * 400, "1"), ("1", "9" * 400),
    ("19294-19344,50000-50100", "50000:65535"), ("19294-19344,50000-50100", "443"), ("443,3478-3481", "3480"),
    ("1:2,3:4,5:6", "4:5"), ("1:2,3:4,5:6", "7"), ("\u00a080", "80"), ("\uff18\uff10", "80"), ("80\r", "80"),
    ("80\n", "80"), ("80:90", "85\n"), ("1:5", "5:1"), ("5:1", "5:1"), (":", ":"), ("-", "-"), ("::", "1"),
)


def conf(*lines, ending="\n", final=True):
    text = ending.join(lines) + (ending if final else "")
    return text.encode("utf-8", "surrogateescape")


ROUTE_LINES = (
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=direct.",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    HEADER + "DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=vless.",
    HEADER + "Discord=zapret, YouTube=vless.",
    HEADER + "Discord=zapret, YouTube=vless, Telegram=ws.",
    HEADER + "DiscordTCP=direct, DiscordTCP=vless, DiscordVoice=zapret, YouTube=vless.",
    HEADER + "Discord=zapret, DiscordTCP=direct, YouTube=vless.",
    HEADER + "DiscordTCP=direct, Discord=zapret, DiscordVoice=vless, YouTube=vless.",
    HEADER + "DiscordTCP=bogus, DiscordVoice=, YouTube, Telegram.",
    HEADER + "DiscordTCP=direct=zapret, YouTube=vless=direct, Telegram=ws=vless.",
    HEADER + "YouTube=vless,",
    HEADER + "YouTube=vless..",
    HEADER + "YouTube=vless.,",
    HEADER + "YouTube=vless",
    HEADER + "YouTube=",
    HEADER + "YouTube==vless.",
    "# Active routes:\tDiscordTCP=direct,\t\tDiscordVoice=zapret,   YouTube=vless.",
    "   # Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    "#  Active  routes:  DiscordTCP=direct,   DiscordVoice=zapret, YouTube=vless, Telegram=zapret.",
    "#Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    "# Active routes:DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    "# active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    "# Active routes:",
    "# Active routes: ",
    HEADER + "Telegram=zapret.",
    HEADER + "Telegram=garbage.",
    HEADER + "Telegram=.",
    HEADER + "Telegram=direct, Telegram=vless.",
    HEADER + "Telegram=unmanaged.",
    HEADER + "Telegram=ws, DiscordTCP=direct.",
    HEADER + "Telegram=ws,",
    HEADER + "DiscordTCP=direct,\u00a0DiscordVoice=zapret, YouTube=vless.",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\t",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless. ",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\x0b",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless\x0c.",
    HEADER + "DiscordTCP=direct, DiscordVoice=zapret,\x0cYouTube=vless.",
    "# Active routes:\x0bDiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.",
    HEADER + "DiscordTCP=Direct, DiscordVoice=ZAPRET, YouTube=VLESS, Telegram=WS.",
    HEADER + "YouTube = vless.",
    HEADER + "YouTube=vless. DiscordTCP=direct.",
    HEADER + "DiscordTCP=\u00e9, YouTube=vless\u00e9.",
    HEADER + "\udcff=\udcfe, YouTube=vless.",
)

ROUTE_MULTI_LINE_CASES = {
    "two headers, the last one has no YouTube": [
        HEADER + "DiscordTCP=direct, YouTube=direct.",
        HEADER + "DiscordTCP=zapret.",
    ],
    "two headers, the last one wins": [
        HEADER + "DiscordTCP=direct, YouTube=direct, Telegram=ws.",
        HEADER + "DiscordTCP=zapret, YouTube=vless.",
    ],
    "telegram survives a header without it": [
        HEADER + "Telegram=ws.",
        HEADER + "YouTube=vless.",
    ],
    "telegram replaced by garbage": [
        HEADER + "Telegram=ws.",
        HEADER + "Telegram=junk.",
    ],
    "telegram replaced by empty": [
        HEADER + "Telegram=vless.",
        HEADER + "Telegram=.",
    ],
    "keys outside the header": [
        "YouTube=vless",
        "# note: YouTube=vless",
        "Telegram=ws",
        "DiscordTCP=direct",
    ],
    "header between other lines": [
        "# Generated by apply-discord-nfqws2.sh 3.2.0.",
        "# Deployment mode: xkeen-integrated.",
        HEADER + "DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=ws.",
        "# Discord UDP: strategy=flowseal, range=wide.",
        "UDP_PORTS=443,50000:65535",
    ],
}

MODE_LINES = (
    "# Deployment mode: xkeen-integrated.",
    "# Deployment mode: standalone-zapret.",
    "# Deployment mode: foo.",
    "# Deployment mode: .",
    "# Deployment mode: Standalone-Zapret.",
    "# Deployment mode: xkeen-integrated. ",
    "# Deployment mode: xkeen-integrated.x",
    "# Deployment mode: xkeen-integrated",
    " # Deployment mode: xkeen-integrated.",
    "#  Deployment mode: xkeen-integrated.",
    "# Deployment mode: xkeen-integrated..",
    "# Deployment mode: xkeen_integrated.",
    "# Deployment mode: xkeen-integrated.\xa0",
    "# deployment mode: xkeen-integrated.",
    "# Deployment Mode: standalone-zapret.",
)

PROXY_LINES = (
    "# Proxy outbound: vless-reality.",
    "# Proxy outbound: a.b:c-d_e.",
    "# Proxy outbound: Ab9.",
    "# Proxy outbound: .",
    "# Proxy outbound: ..",
    "# Proxy outbound: a b.",
    "# Proxy outbound: x",
    "# Proxy outbound: x.y",
    "# Proxy outbound: x. ",
    "# Proxy outbound: \u00e9.",
    "# Proxy outbound: a/b.",
    " # Proxy outbound: x.",
    "# proxy outbound: x.",
)

UDP_LINES = (
    "# Discord UDP: strategy=flowseal, range=narrow.",
    "# Discord UDP: strategy=flowseal, range=wide.",
    "# Discord UDP: strategy=legacy, range=narrow.",
    "# Discord UDP: strategy=legacy, range=wide.",
    "# Discord UDP: strategy=flowseal, range=medium.",
    "# Discord UDP: strategy=Flowseal, range=narrow.",
    "# Discord UDP: strategy=, range=.",
    "# Discord UDP: strategy=flowseal,range=narrow.",
    "# Discord UDP: strategy=flowseal, range=narrow",
    " # Discord UDP: strategy=flowseal, range=narrow.",
    "# discord udp: strategy=legacy, range=wide.",
)

UDP_EXTRA_CASES = {
    "ports wide colon": ["UDP_PORTS=443,50000:65535"],
    "ports wide dash quoted": ['UDP_PORTS="50000-65535"'],
    "ports narrow": ["UDP_PORTS=443,50000:50100"],
    "ports inside a wide list": ["UDP_PORTS=1,50000:65535,2"],
    "ports empty": ["UDP_PORTS="],
    "ports last wins": ["UDP_PORTS=50000:65535", "UDP_PORTS=443"],
    "ports last empty": ["UDP_PORTS=50000:65535", "UDP_PORTS="],
    "ports first wins nothing": ["UDP_PORTS=443", "UDP_PORTS=50000:65535"],
    "flowseal blob": ['NFQWS_ARGS_UDP="--blob=discord_udp:@/opt/etc/nfqws2/blobs/udp.bin"'],
    "legacy filter": ['NFQWS_ARGS_UDP="--filter-l7=stun,discord"'],
    "both profile markers": ["# --filter-l7=stun,discord", "    --blob=discord_udp:@/x"],
    "marker in a comment": ["# --blob=discord_udp:"],
    "wide with flowseal blob": ["UDP_PORTS=50000:65535", "--blob=discord_udp:@/x"],
    "invalid header then valid": [
        "# Discord UDP: strategy=foo, range=wide.",
        "# Discord UDP: strategy=legacy, range=wide.",
    ],
    "valid header then invalid": [
        "# Discord UDP: strategy=legacy, range=wide.",
        "# Discord UDP: strategy=foo, range=wide.",
    ],
    "header wins over ports and blob": [
        "# Discord UDP: strategy=legacy, range=narrow.",
        "UDP_PORTS=50000:65535",
        "--blob=discord_udp:@/x",
    ],
    "invalid header with wide ports": [
        "# Discord UDP: strategy=bogus, range=wide.",
        "UDP_PORTS=50000-65535",
        "--filter-l7=stun,discord",
    ],
}

VOICE_LINES = (
    "# Discord Voice profile: imported f3de2c222df9, udp=19294-19344,50000-50100.",
    "# Discord Voice profile: imported , udp=.",
    "# Discord Voice profile: imported abc, udp=1.",
    "# Discord Voice profile: imported ABC, udp=1.",
    "# Discord Voice profile: imported abc, udp=1:2.",
    "# Discord Voice profile: imported abc,  udp=1.",
    "# Discord Voice profile: imported abc, udp=1-2,3.",
    "# Discord Voice profile: imported abc, udp=1",
    "# Discord Voice profile: builtin.",
    " # Discord Voice profile: imported abc, udp=1.",
    "# discord voice profile: imported abc, udp=1.",
)


def build_conf_corpus():
    corpus = {}
    singles = {"route": ROUTE_LINES, "mode": MODE_LINES, "proxy": PROXY_LINES, "udp": UDP_LINES, "voice": VOICE_LINES}
    for family, family_lines in singles.items():
        for number, line in enumerate(family_lines):
            corpus[f"{family} {number} lf"] = conf(line)
            corpus[f"{family} {number} crlf"] = conf(line, ending="\r\n")
            if number % 3 == 0:
                corpus[f"{family} {number} without a final newline"] = conf(line, final=False)
    for label, case_lines in ROUTE_MULTI_LINE_CASES.items():
        corpus[f"route multi {label}"] = conf(*case_lines)
        corpus[f"route multi {label} crlf"] = conf(*case_lines, ending="\r\n")
    for label, case_lines in UDP_EXTRA_CASES.items():
        corpus[f"udp {label}"] = conf(*case_lines)
    corpus["mode first invalid"] = conf("# Deployment mode: foo.", "# Deployment mode: xkeen-integrated.")
    corpus["mode two valid"] = conf("# Deployment mode: standalone-zapret.", "# Deployment mode: xkeen-integrated.")
    corpus["proxy empty first"] = conf("# Proxy outbound: .", "# Proxy outbound: two.")
    corpus["proxy invalid first"] = conf("# Proxy outbound: a b.", "# Proxy outbound: two.")
    corpus["proxy two valid"] = conf("# Proxy outbound: one.", "# Proxy outbound: two.")
    corpus["voice two valid"] = conf(VOICE_LINES[0], VOICE_LINES[2])
    corpus["voice invalid first"] = conf(VOICE_LINES[3], VOICE_LINES[2])
    corpus["full managed block"] = conf(
        "# BEGIN keenetic-discord-nfqws2",
        "# Generated by apply-discord-nfqws2.sh 3.2.0.",
        "# Deployment mode: xkeen-integrated.",
        HEADER + "DiscordTCP=zapret, DiscordVoice=direct, YouTube=vless, Telegram=ws.",
        "# Discord UDP: strategy=flowseal, range=wide.",
        VOICE_LINES[0],
        "# Proxy outbound: vless-reality.",
        'UDP_PORTS=443,50000:65535',
        "# END keenetic-discord-nfqws2",
    )
    corpus["no header"] = conf('ISP_INTERFACE="eth3"', "TCP_PORTS=443")
    corpus["empty file"] = b""
    corpus["only newlines"] = b"\n\n\n"
    corpus["fixture nfqws2.conf"] = (FIXTURE / "nfqws2" / "nfqws2.conf").read_bytes()
    return corpus


CONF_CORPUS = build_conf_corpus()
ROUTE_SERVICES = ("discord-tcp", "discord-voice", "youtube", "bogus")

# Written as the script writes them (status_report and check_header_lines): the same sed, the same expansions.
VOICE_SED = (
    "sed -n 's/^# Discord Voice profile: imported \\([0-9a-f]*\\), udp=\\([0-9,-]*\\)\\.$/\\1 \\2/p' \"$NFQWS_CONF\" "
    "| sed -n '1p'"
)
VOICE_PROBE = f"""voice_probe() {{
  status_voice="$({VOICE_SED})"
  if [ -n "$status_voice" ]; then
    printf '%s|%s\\n' "${{status_voice%% *}}" "${{status_voice#* }}"
  else
    printf 'none\\n'
  fi
}}"""
UDP_PROBE = """udp_probe() {
  recorded_udp_settings
  printf '%s|%s\\n' "$RECORDED_UDP_STRATEGY" "$RECORDED_UDP_RANGE"
}"""


class DifferentialMixin:
    """Runs the shell function and the port on one input; ``awk`` and ``separators`` select the awk to model."""

    awk = None
    separators = None
    # Tools put in front of PATH as links to busybox, besides awk (the router has busybox for all of them).
    applets = ()

    def setUp(self):
        super().setUp()
        self.tmp = self.enterContext(tempfile.TemporaryDirectory(prefix="confvalues-diff-"))
        self.counter = 0
        self.env = None
        if self.applets:
            directory = self.enterContext(tempfile.TemporaryDirectory(prefix="confvalues-applets-"))
            for tool in self.applets:
                os.symlink(os.path.abspath(shutil.which("busybox")), os.path.join(directory, tool))
            self.env = {**os.environ, "PATH": directory + os.pathsep + os.environ.get("PATH", os.defpath)}
        if self.separators is not None:
            self.enterContext(mock.patch.object(confvalues, "AWK_FIELD_SEPARATORS", self.separators))

    def new_file(self, data):
        self.counter += 1
        path = os.path.join(self.tmp, f"f{self.counter}")
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_sh(self, function, *args, variables=None, defs=()):
        return engine_shell.run_function(
            function, *args, defs=("set -eu", *defs), variables=variables, env=self.env, awk=self.awk
        )

    def run_all(self, jobs):
        """Runs [(function, args, variables, defs)] concurrently; results in the same order."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(self.run_sh, function, *args, variables=variables, defs=defs)
                for function, args, variables, defs in jobs
            ]
            return [future.result() for future in futures]

    def assert_streams(self, result, stdout, returncode=0, stderr=""):
        self.assertEqual((result.stdout, result.stderr, result.returncode), (stdout, stderr, returncode))

    def check_value_function(self, function, variable, last, python, corpus, keys=KEYS):
        files = {label: self.new_file(data) for label, data in corpus.items()}
        jobs, cases = [], []
        for label, path in files.items():
            for key in keys:
                jobs.append((function, (key,), {variable: path}, ()))
                cases.append((label, key, path))
        for (label, key, path), result in zip(cases, self.run_all(jobs), strict=True):
            with self.subTest(function=function, case=label, key=key):
                value = python(path, key)
                # What callers see is the output of $(...): trailing newlines gone.
                self.assertEqual(result.stdout.rstrip("\n"), value)
                self.assertEqual((result.stderr, result.returncode), ("", 0))
                if value:
                    self.assertEqual(result.stdout, value + "\n")
                else:
                    # A matched empty value prints an empty line for the first-match readers, nothing for the last.
                    self.assertIn(result.stdout, ("",) if last else ("", "\n"))
        return len(cases)

    def test_init_value_matches_the_shell_function(self):
        count = self.check_value_function(
            "init_value", "XKEEN_INIT", False, lambda path, key: confvalues.init_value(paths_for(path), key), ASSIGNMENT_CORPUS
        )
        self.assertGreaterEqual(count, 250)

    def test_runtime_value_matches_the_shell_function(self):
        self.check_value_function(
            "runtime_value",
            "XKEEN_HOOK",
            False,
            lambda path, key: confvalues.runtime_value(paths_for(hook=path), key),
            ASSIGNMENT_CORPUS,
        )

    def test_nfqws_value_matches_the_shell_function(self):
        corpus = {**ASSIGNMENT_CORPUS, **{f"conf {label}": data for label, data in CONF_CORPUS.items() if len(data) < 400}}
        self.check_value_function(
            "nfqws_value",
            "NFQWS_CONF",
            True,
            lambda path, key: confvalues.nfqws_value(paths_for(conf=path), key),
            corpus,
            keys=(*KEYS, "ISP_INTERFACE", "NFQWS_ARGS_UDP"),
        )

    def test_values_of_the_fixture_files_match_the_shell_functions(self):
        init = FIXTURE / "init.d" / "S05xkeen"
        hook = FIXTURE / "ndm" / "netfilter.d" / "proxy.sh"
        conf_path = FIXTURE / "nfqws2" / "nfqws2.conf"
        keys = ("name_client", "table_mark", "custom_mark", "dscp_exclude", "dscp_proxy", "proxy_dns", "proxy_router",
                "start_auto", "ipv6_support", "mode_proxy", "policy_mark", "UDP_PORTS", "TCP_PORTS", "ISP_INTERFACE",
                "NFQWS_ARGS_UDP", "NFQWS_EXTRA_ARGS", "NFQWS_ARGS_CUSTOM", "POLICY_NAME", "nothing")
        jobs = []
        for key in keys:
            jobs.append(("init_value", (key,), {"XKEEN_INIT": str(init)}, ()))
            jobs.append(("runtime_value", (key,), {"XKEEN_HOOK": str(hook)}, ()))
            jobs.append(("nfqws_value", (key,), {"NFQWS_CONF": str(conf_path)}, ()))
            jobs.append(("xkeen_effective_value", (key,), {"XKEEN_INIT": str(init), "XKEEN_HOOK": str(hook)},
                         ("runtime_value", "init_value")))
        paths = paths_for(str(init), str(hook), str(conf_path))
        python = (confvalues.init_value, confvalues.runtime_value, confvalues.nfqws_value, confvalues.xkeen_effective_value)
        results = self.run_all(jobs)
        for number, result in enumerate(results):
            key = keys[number // 4]
            function = python[number % 4]
            with self.subTest(function=function.__name__, key=key):
                value = function(paths, key)
                self.assertEqual(result.stdout.rstrip("\n"), value)
                self.assertEqual((result.stderr, result.returncode), ("", 0))

    def test_xkeen_effective_value_matches_the_shell_function(self):
        labels = list(ASSIGNMENT_CORPUS)
        jobs, cases = [], []
        for number, label in enumerate(labels):
            hook = self.new_file(ASSIGNMENT_CORPUS[label])
            other = labels[(number + 7) % len(labels)]
            init = self.new_file(ASSIGNMENT_CORPUS[other])
            for key in KEYS:
                jobs.append(("xkeen_effective_value", (key,), {"XKEEN_INIT": init, "XKEEN_HOOK": hook}, ("runtime_value", "init_value")))
                cases.append((label, other, key, init, hook))
        for (label, other, key, init, hook), result in zip(cases, self.run_all(jobs), strict=True):
            with self.subTest(hook=label, init=other, key=key):
                value = confvalues.xkeen_effective_value(paths_for(init, hook), key)
                self.assertEqual(result.stdout.rstrip("\n"), value)
                self.assertEqual((result.stderr, result.returncode), ("", 0))
                self.assertIn(result.stdout, (value + "\n",) if value else ("", "\n"))

    def test_missing_directory_and_symlinked_files_match_the_shell_functions(self):
        real = self.new_file(b"a=1\nb=\"2\"\nUDP_PORTS=3\n")
        link = os.path.join(self.tmp, "link")
        os.symlink(real, link)
        dangling = os.path.join(self.tmp, "dangling")
        os.symlink(os.path.join(self.tmp, "gone"), dangling)
        fifo = os.path.join(self.tmp, "fifo")
        os.mkfifo(fifo)
        targets = {
            "missing": os.path.join(self.tmp, "nothing"),
            "directory": self.tmp,
            "symlink": link,
            "dangling": dangling,
            "device": "/dev/null",
            "fifo": fifo,
        }
        for label, path in targets.items():
            for function, variable, python in (
                ("init_value", "XKEEN_INIT", lambda p, k: confvalues.init_value(paths_for(p), k)),
                ("runtime_value", "XKEEN_HOOK", lambda p, k: confvalues.runtime_value(paths_for(hook=p), k)),
                ("nfqws_value", "NFQWS_CONF", lambda p, k: confvalues.nfqws_value(paths_for(conf=p), k)),
            ):
                with self.subTest(case=label, function=function):
                    result = self.run_sh(function, "a", variables={variable: path})
                    value = python(path, "a")
                    self.assertEqual(result.stdout.rstrip("\n"), value)
                    self.assertEqual((result.stderr, result.returncode), ("", 0))
            with self.subTest(case=label, function="active_ports"):
                result = self.run_sh("active_ports", path)
                self.assertEqual(result.stdout, confvalues.active_ports(confvalues.read_text(path)))
                self.assertEqual((result.stderr, result.returncode), ("", 0))
            with self.subTest(case=label, function="recorded_telegram_route"):
                result = self.run_sh("recorded_telegram_route", variables={"NFQWS_CONF": path})
                self.assertEqual(result.stdout, confvalues.recorded_telegram_route(confvalues.read_text(path)) + "\n")
            for function, python in (
                ("recorded_deployment_mode", confvalues.recorded_deployment_mode),
                ("recorded_proxy_outbound", confvalues.recorded_proxy_outbound),
            ):
                with self.subTest(case=label, function=function):
                    result = self.run_sh(function, variables={"NFQWS_CONF": path})
                    value = python(confvalues.read_text(path))
                    self.assert_streams(result, "" if value is None else value + "\n", 1 if value is None else 0)

    def test_active_ports_matches_the_shell_function(self):
        files = {label: self.new_file(data) for label, data in PORT_CORPUS.items()}
        results = self.run_all([("active_ports", (path,), None, ()) for path in files.values()])
        for (label, path), result in zip(files.items(), results, strict=True):
            with self.subTest(case=label):
                actual = confvalues.active_ports(confvalues.read_text(path))
                if label in PORT_INTENTIONAL_DIFFERENCES:
                    legacy, native = PORT_INTENTIONAL_DIFFERENCES[label]
                    self.assert_streams(result, legacy)
                    self.assertEqual(actual, native)
                else:
                    self.assert_streams(result, actual)

    def test_ports_overlap_matches_the_shell_function(self):
        results = self.run_all([("ports_overlap", pair, None, ()) for pair in OVERLAP_PAIRS])
        for (left, right), result in zip(OVERLAP_PAIRS, results, strict=True):
            with self.subTest(left=left, right=right):
                overlap = confvalues.ports_overlap(left, right)
                self.assert_streams(result, "", 0 if overlap else 1)

    def test_recorded_routes_match_the_shell_functions(self):
        files = {label: self.new_file(data) for label, data in CONF_CORPUS.items()}
        jobs, cases = [], []
        for label, path in files.items():
            for service in ROUTE_SERVICES:
                jobs.append(("recorded_nfqws_route", (service,), {"NFQWS_CONF": path}, ()))
                cases.append((label, path, service))
            jobs.append(("recorded_telegram_route", (), {"NFQWS_CONF": path}, ()))
            cases.append((label, path, None))
        for (label, path, service), result in zip(cases, self.run_all(jobs), strict=True):
            with self.subTest(case=label, service=service):
                text = confvalues.read_text(path)
                if service is None:
                    self.assert_streams(result, confvalues.recorded_telegram_route(text) + "\n")
                else:
                    value = confvalues.recorded_route(text, service)
                    self.assert_streams(result, "" if value is None else value + "\n", 1 if value is None else 0)

    def test_recorded_deployment_mode_and_proxy_outbound_match_the_shell_functions(self):
        files = {label: self.new_file(data) for label, data in CONF_CORPUS.items()}
        jobs, cases = [], []
        for label, path in files.items():
            for function in ("recorded_deployment_mode", "recorded_proxy_outbound"):
                jobs.append((function, (), {"NFQWS_CONF": path}, ()))
                cases.append((label, path, function))
        python = {
            "recorded_deployment_mode": confvalues.recorded_deployment_mode,
            "recorded_proxy_outbound": confvalues.recorded_proxy_outbound,
        }
        for (label, path, function), result in zip(cases, self.run_all(jobs), strict=True):
            with self.subTest(case=label, function=function):
                value = python[function](confvalues.read_text(path))
                self.assert_streams(result, "" if value is None else value + "\n", 1 if value is None else 0)

    def test_recorded_udp_settings_matches_the_shell_function(self):
        files = {label: self.new_file(data) for label, data in CONF_CORPUS.items()}
        defs = ("recorded_udp_settings", "nfqws_value", UDP_PROBE)
        results = self.run_all([("udp_probe", (), {"NFQWS_CONF": path}, defs) for path in files.values()])
        for (label, path), result in zip(files.items(), results, strict=True):
            with self.subTest(case=label):
                text = confvalues.read_text(path)
                strategy, voice_range = confvalues.recorded_udp_settings(
                    text, confvalues.nfqws_value(paths_for(conf=path), "UDP_PORTS")
                )
                self.assert_streams(result, f"{strategy}|{voice_range}\n")

    def test_voice_profile_header_matches_the_shell_snippet(self):
        self.assertIn(VOICE_SED, engine_shell.script_text())
        self.assertIn('echo "discord_voice_profile=imported:${status_voice%% *}"', engine_shell.script_text())
        self.assertIn('echo "discord_voice_udp=${status_voice#* }"', engine_shell.script_text())
        files = {label: self.new_file(data) for label, data in CONF_CORPUS.items()}
        results = self.run_all([("voice_probe", (), {"NFQWS_CONF": path}, (VOICE_PROBE,)) for path in files.values()])
        for (label, path), result in zip(files.items(), results, strict=True):
            with self.subTest(case=label):
                header = confvalues.voice_profile_header(confvalues.read_text(path))
                self.assert_streams(result, "none\n" if header is None else f"{header[0]}|{header[1]}\n")

    def test_a_missing_conf_gives_the_documented_defaults(self):
        path = os.path.join(self.tmp, "absent")
        defs = ("recorded_udp_settings", "nfqws_value", UDP_PROBE)
        self.assert_streams(self.run_sh("udp_probe", variables={"NFQWS_CONF": path}, defs=defs), "|narrow\n")
        self.assertEqual(confvalues.recorded_udp_settings(None, ""), ("", "narrow"))
        self.assert_streams(self.run_sh("recorded_telegram_route", variables={"NFQWS_CONF": path}), "unmanaged\n")
        self.assertEqual(confvalues.recorded_telegram_route(None), "unmanaged")
        self.assert_streams(self.run_sh("recorded_nfqws_route", "youtube", variables={"NFQWS_CONF": path}), "", 1)
        self.assertIsNone(confvalues.recorded_route(None, "youtube"))

    def test_the_tools_under_test_are_the_expected_ones(self):
        probe = (
            "tool_probe() {\n"
            "  for tool in awk sed grep tr; do\n"
            '    printf "%s\\n" "$(readlink -f "$(command -v "$tool")")"\n'
            "  done\n"
            "}"
        )
        result = self.run_sh("tool_probe", defs=(probe,))
        resolved = result.stdout.split("\n")[:4]
        busybox = os.path.realpath(shutil.which("busybox")) if HAS_BUSYBOX else None
        expected = {"awk": self.awk == "busybox", "sed": bool(self.applets), "grep": bool(self.applets), "tr": bool(self.applets)}
        for tool, path in zip(("awk", "sed", "grep", "tr"), resolved, strict=True):
            with self.subTest(tool=tool):
                self.assertEqual(os.path.realpath(path) == busybox, expected[tool], path)

    def test_the_corpus_has_the_cases_the_plan_asks_for(self):
        labels = " | ".join([*ASSIGNMENT_CORPUS, *PORT_CORPUS, *CONF_CORPUS]).lower()
        for needle in ("crlf", "cr ", "nbsp", "tab", "empty", "quote", "comment", "duplicate", "invalid utf8", "no final newline"):
            with self.subTest(needle=needle):
                self.assertIn(needle, labels)
        self.assertTrue(any(b"\r" in data for data in ASSIGNMENT_CORPUS.values()))
        self.assertTrue(any(b"\xc2\xa0" in data for data in ASSIGNMENT_CORPUS.values()))
        self.assertGreaterEqual(len(ASSIGNMENT_CORPUS) * len(KEYS) + len(PORT_CORPUS) + len(OVERLAP_PAIRS) + len(CONF_CORPUS) * 9, 1000)


@unittest.skipUnless(SYSTEM_AWK_IS_MAWK, NOT_MAWK)
class SystemAwkDifferentialTests(DifferentialMixin, unittest.TestCase):
    awk = "system"
    separators = MAWK_SEPARATORS


@unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
class BusyboxAwkDifferentialTests(DifferentialMixin, unittest.TestCase):
    """The router: busybox awk, sed, grep and tr."""

    awk = "busybox"
    separators = None
    applets = ("sed", "grep", "tr")


class AwkFieldSeparatorTests(TempDirTestCase):
    """Pins the model of ``AWK_FIELD_SEPARATORS``: what each awk splits default-FS fields on."""

    CANDIDATES = [chr(code) for code in range(1, 128)] + ["\u00a0", "\u0085", "\u2003", "\u2028", "\u3000", "\ufeff"]

    def separators_of(self, awk):
        env = dict(os.environ)
        if awk == "busybox":
            applets = self.enterContext(tempfile.TemporaryDirectory(prefix="awk-applet-"))
            os.symlink(os.path.abspath(shutil.which("busybox")), os.path.join(applets, "awk"))
            env["PATH"] = applets + os.pathsep + env["PATH"]
        found = []
        for char in self.CANDIDATES:
            result = engine_shell.run_sh("printf 'a%sb' \"$CHAR\" | awk '{ print NF }'", env={**env, "CHAR": char})
            if result.stdout.strip() == "2":
                found.append(char)
        return "".join(sorted(found))

    @unittest.skipUnless(SYSTEM_AWK_IS_MAWK, NOT_MAWK)
    def test_the_system_awk_splits_fields_on_blank_and_tab_only(self):
        # A newline separates records, so it is not probed here.
        self.assertEqual(self.separators_of("system"), "".join(sorted(MAWK_SEPARATORS.replace("\n", ""))))

    @unittest.skipUnless(HAS_BUSYBOX and SYSTEM_AWK_IS_MAWK, "needs busybox and mawk")
    def test_the_two_awks_disagree_on_a_crlf_header_so_the_port_cannot_match_both(self):
        path = self.write("conf", HEADER + "DiscordTCP=direct, YouTube=vless.\r\n")
        results = {}
        for awk in ("system", "busybox"):
            result = engine_shell.run_function(
                "recorded_nfqws_route", "youtube", variables={"NFQWS_CONF": path}, awk=awk
            )
            results[awk] = (result.stdout, result.returncode)
        self.assertEqual(results, {"system": ("", 1), "busybox": ("vless\n", 0)})
        text = confvalues.read_text(path)
        self.assertEqual(confvalues.recorded_route(text, "youtube"), "vless")
        with mock.patch.object(confvalues, "AWK_FIELD_SEPARATORS", MAWK_SEPARATORS):
            self.assertIsNone(confvalues.recorded_route(text, "youtube"))

    @unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
    def test_busybox_awk_splits_fields_on_isspace_and_the_port_uses_that_by_default(self):
        self.assertEqual(self.separators_of("busybox"), "".join(sorted(BUSYBOX_SEPARATORS.replace("\n", ""))))
        self.assertEqual(confvalues.AWK_FIELD_SEPARATORS, BUSYBOX_SEPARATORS)


if __name__ == "__main__":
    unittest.main()

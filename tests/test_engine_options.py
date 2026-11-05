"""Tests of kdn.engine.options.parse_args: the argument loop of apply-discord-nfqws2.sh in Python.

The test is differential. The text of the script from its first line through the ``done`` of the argument loop
is run under every installed POSIX shell (dash, busybox ash) with the argv of a case, followed by a dump of
every variable the loop sets; parse_args must give the same value in every field, or the same error message and
exit code. The cases are the rows of tests/fixtures/engine/mode-table.tsv, every flag on its own, every value
option with and without a value and with a value that looks like a flag, and a seeded random corpus of flags,
values, empty strings, spaces, quotes and unknown words. A drift guard compares the flags of the loop with
the lists of this file, so a new option in the script fails the test until it is added to both sides.

``--json`` is not in the loop (the legacy path answers ``unknown argument: --json``, B1 of the plan), so it is
tested on the Python side only.

``resolve`` is tested the same way against the block between the ``done`` of the loop and the mode dispatch
(``if [ "$MODE" = "help" ]``): the real text of the script runs under dash (with the awk and sed of the stand) and
under busybox ash (busybox awk, sed, grep and tr first on PATH, as on the router, R13) on roots that hold different
nfqws2.conf files, and every variable and every message must agree. tests/fixtures/engine/argv-validation.tsv pins
the outcome of the validation (R8) for both sides.
"""

from __future__ import annotations

import os
import io
import json
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import engine_shell

from kdn.engine import cli
from kdn.engine import options as engine_options


ROOT = engine_shell.ROOT
MODE_TABLE = ROOT / "tests" / "fixtures" / "engine" / "mode-table.tsv"
VALIDATION_TABLE = ROOT / "tests" / "fixtures" / "engine" / "argv-validation.tsv"
PACKAGE_PATH = ROOT / "tools" / "router"
SHELLS = {
    "dash": ("dash",),
    "busybox ash": ("busybox", "sh"),
}
SIX_MODES = ("status", "check-config", "print-nfqws-profiles", "show-snapshots", "preflight", "print-plan")
SEED = 20261028
RANDOM_CASES = 300

# The variables the loop sets -> the fields of Options; "flag" fields hold 0 or 1 in the shell and a bool here.
FIELDS = (
    ("MODE", "mode", "text"),
    ("IMPORT_PROFILE_REQUESTED", "import_profile", "text"),
    ("CLEAR_IMPORTED_PROFILE", "clear_profile", "text"),
    ("ROLLBACK_SNAPSHOT_REQUESTED", "rollback_snapshot", "text"),
    ("CONFIRMED", "confirmed", "flag"),
    ("WIDE_UDP", "wide_udp", "flag"),
    ("STANDALONE_ZAPRET", "standalone", "flag"),
    ("UDP_STRATEGY", "udp_strategy", "text"),
    ("DISCORD_TCP_ROUTE_MODE", "discord_tcp_route", "text"),
    ("DISCORD_VOICE_ROUTE_MODE", "discord_voice_route", "text"),
    ("YOUTUBE_ROUTE_MODE", "youtube_route", "text"),
    ("TELEGRAM_ROUTE_MODE", "telegram_route", "text"),
    ("DISCORD_TCP_ROUTE_EXPLICIT", "discord_tcp_route_explicit", "flag"),
    ("DISCORD_VOICE_ROUTE_EXPLICIT", "discord_voice_route_explicit", "flag"),
    ("YOUTUBE_ROUTE_EXPLICIT", "youtube_route_explicit", "flag"),
    ("TELEGRAM_ROUTE_EXPLICIT", "telegram_route_explicit", "flag"),
    ("PROXY_OUTBOUND_REQUESTED", "proxy_outbound_requested", "text"),
    ("CORE_REQUESTED", "core_requested", "text"),
    ("DIRECT_MARK_REQUESTED", "direct_mark_requested", "text"),
    ("WAN_INTERFACE_REQUESTED", "wan_interface_requested", "text"),
)
DEFAULTS = {
    "mode": "help",
    "import_profile": "",
    "clear_profile": "",
    "rollback_snapshot": "",
    "confirmed": False,
    "wide_udp": False,
    "standalone": False,
    "udp_strategy": "flowseal",
    "discord_tcp_route": "zapret",
    "discord_voice_route": "zapret",
    "youtube_route": "vless",
    "telegram_route": "",
    "discord_tcp_route_explicit": False,
    "discord_voice_route_explicit": False,
    "youtube_route_explicit": False,
    "telegram_route_explicit": False,
    "proxy_outbound_requested": "",
    "core_requested": "auto",
    "direct_mark_requested": "",
    "wan_interface_requested": "",
    "json": False,
    "focused_context": "",
    "recover_import_source": "",
}
# option -> the text after "requires" in its error message
VALUE_OPTIONS = {
    "--apply-import-profile": "a staging JSON file.",
    "--clear-imported-profile": "a service.",
    "--rollback-snapshot": "a snapshot path.",
    "--udp-strategy": "flowseal or legacy.",
    "--discord-route": "direct, zapret or vless.",
    "--discord-tcp-route": "direct, zapret or vless.",
    "--discord-voice-route": "direct, zapret or vless.",
    "--youtube-route": "direct, zapret or vless.",
    "--telegram-route": "direct, vless, ws or unmanaged.",
    "--proxy-outbound": "an Xray outbound tag.",
    "--core": "auto, xray, or mihomo.",
    "--direct-mark": "a decimal Keenetic policy mark.",
    "--wan-interface": "one interface or a quoted list.",
}
# option -> (mode it sets or None, fields that receive its value)
OPTION_EFFECTS = {
    "--apply-import-profile": ("apply-import-profile", ("import_profile",)),
    "--clear-imported-profile": ("clear-imported-profile", ("clear_profile",)),
    "--rollback-snapshot": ("rollback-snapshot", ("rollback_snapshot",)),
    "--udp-strategy": (None, ("udp_strategy",)),
    "--discord-route": (None, ("discord_tcp_route", "discord_voice_route")),
    "--discord-tcp-route": (None, ("discord_tcp_route",)),
    "--discord-voice-route": (None, ("discord_voice_route",)),
    "--youtube-route": (None, ("youtube_route",)),
    "--telegram-route": (None, ("telegram_route",)),
    "--proxy-outbound": (None, ("proxy_outbound_requested",)),
    "--core": (None, ("core_requested",)),
    "--direct-mark": (None, ("direct_mark_requested",)),
    "--wan-interface": (None, ("wan_interface_requested",)),
}
PLAIN_FLAGS = (
    "--print-plan", "--preflight", "--status", "--check-config", "--print-nfqws-profiles", "--show-snapshots",
    "--show-rollback", "--snapshot-baseline", "--apply", "--rollback-import", "--rollback", "--rollback-baseline",
    "--rollback-latest", "--yes-router", "--wide-udp", "--narrow-udp", "--standalone-zapret", "--without-xkeen",
    "--no-xkeen", "--integrated", "-h", "--help",
)  # fmt: skip
KNOWN = (*VALUE_OPTIONS, *PLAIN_FLAGS)
LOOKALIKES = ("--status", "--help", "--yes-router", "--core", "-h", "")
VALUES = (
    "x", "", " ", "a b", "  ", "--status", "--apply", "--core", "-h", "--yes-router", "direct", "zapret", "vless",
    "ws", "unmanaged", "xray", "mihomo", "auto", "legacy", "flowseal", "123", "*", "$HOME", "`id`", "'", '"',
    "a\nb", "--", "-", "-n", "-e", "--help=1", "caf\u00e9", "\udcff", "a\\b", "\\n", "\tx", "x ", "$(id)", ";",
    "/opt/etc/snapshots/1", "p.json", "youtube",
)  # fmt: skip
UNKNOWN = (
    "--bogus", "bogus", "-x", "--status=1", "--STATUS", "--core=xray", "-", "--", "--json-x", " --status",
    "--status ", "-hh", "--help ", "\u2013status", "--apply\n", "--rollback-snapshots", "-n",
)  # fmt: skip
INSERT_AT = ("start", "end")


def table_rows():
    """(expected class, argv) of every row of mode-table.tsv."""
    rows = []
    for line in MODE_TABLE.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        # An empty argv has an empty (or no) second column.
        expected, _, tokens = line.partition("\t")
        rows.append((expected, ["" if token == "@empty@" else token for token in tokens.split()]))
    return rows


def class_of(mode):
    """Read modes plus the seven migrated phase5 modes; fullapply is legacy."""
    mutations = {'apply', 'snapshot-baseline', 'rollback-baseline', 'rollback-latest', 'rollback-import',
                 'apply-import-profile', 'clear-imported-profile', 'rollback-snapshot'}
    return mode if mode in SIX_MODES or mode in mutations or mode == "help" else "other"


def installed_shells():
    return {label: argv for label, argv in SHELLS.items() if shutil.which(argv[0])}


def split_script():
    """(text before the argument loop, the loop through its ``done``)."""
    text = engine_shell.script_text()
    head = 'while [ "$#" -gt 0 ]; do\n  case "$1" in\n'
    assert text.count(head) == 1, "the argument loop of the script was not found"
    start = text.index(head)
    end = text.index("\ndone\n", start) + len("\ndone\n")
    loop = text[start:end]
    assert loop.endswith("  shift\ndone\n") and "\nwhile " not in loop[len(head) :], "the loop was cut wrongly"
    return text[:start], loop


def loop_labels():
    """(all case labels, labels of the options that take a value) of the real argument loop."""
    loop = split_script()[1]
    labels = {label for found in re.findall(r"(?m)^    (-[-A-Za-z|]+)\)", loop) for label in found.split("|")}
    valued = set(re.findall(r"(?m)^    (--[a-z-]+)\)\n      shift\n", loop))
    return labels, valued


def corpus():
    """The argvs of the differential test: the same list for every shell, seeded."""
    rng = random.Random(SEED)
    cases = [argv for _, argv in table_rows() if "--json" not in argv]
    cases += [[flag] for flag in KNOWN]
    cases += [[option, "value"] for option in VALUE_OPTIONS]
    cases += [[option, other] for option in VALUE_OPTIONS for other in LOOKALIKES]
    cases += [[option, other, "--status"] for option in VALUE_OPTIONS for other in ("--apply", "")]
    cases += [
        ["--bogus", "--core"],
        ["--core", "--bogus"],
        ["--core", "--bogus", "--help"],
        ["--status", "--bogus", "--help"],
        ["--help", "--yes-router", "--status"],
        ["--status", "--help"],
        ["--status", "--check-config"],
        ["--status", "--help", "--yes-router"],
        ["--help", "--status"],
        ["--core", "xray", "--preflight"],
        ["--rollback-snapshot", "--yes-router"],
        ["--yes-router", "--yes-router", "--help"],
        ["--yes-router", "--apply-import-profile", "--yes-router"],
        ["--wide-udp", "--narrow-udp", "--wide-udp"],
        ["--standalone-zapret", "--integrated", "--no-xkeen"],
        ["--discord-route", "vless", "--discord-voice-route", "direct"],
        ["--discord-voice-route", "direct", "--discord-route", "vless"],
        ["--discord-tcp-route", "vless", "--discord-route", "direct", "--youtube-route", "zapret"],
        ["--telegram-route", "zapret", "--telegram-route", "ws"],
        ["--core", "xray", "--core", "mihomo"],
        ["--wan-interface", "eth3 eth4", "--direct-mark", "0x1"],
        ["--proxy-outbound", "", "--wan-interface", ""],
        ["--unknown\\n"],
        ["a\\tb"],
        ["--core", "a\\tb"],
    ]
    options = tuple(VALUE_OPTIONS)
    for _ in range(RANDOM_CASES):
        argv = []
        for _ in range(rng.randint(0, 7)):
            if rng.random() < 0.55:
                argv.append(rng.choice(PLAIN_FLAGS))
            else:
                argv.extend((rng.choice(options), rng.choice(VALUES)))
        roll = rng.random()
        if roll < 0.12:
            argv.insert(rng.randint(0, len(argv)), rng.choice(UNKNOWN))
        elif roll < 0.24:
            argv.insert(rng.randint(0, len(argv)), rng.choice(VALUES))
        elif roll < 0.32:
            argv.append(rng.choice(options))
        cases.append(argv)
    return [list(case) for case in dict.fromkeys(tuple(case) for case in cases)]


class Legacy:
    """What the argument loop of the script did with an argv: an exit status plus the dump or the stderr."""

    __slots__ = ("fields", "rc", "stderr")

    def __init__(self, rc, fields, stderr):
        self.rc = rc
        self.fields = fields
        self.stderr = stderr


class LegacyLoop:
    """Runs the real text of the script up to the end of the argument loop under one shell."""

    def __init__(self, shell, root):
        self.shell = shell
        self.env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "KD_TEST_ROOT": root,
            "KD_ALLOW_TEST_ROOT": "1",
            "LC_ALL": "C.UTF-8",
        }
        self.head, self.loop = split_script()
        dump = " ".join(name for name, _, _ in FIELDS)
        self.dump = (
            f"for kdn_name in {dump}; do\n"
            '  eval "kdn_value=\\${$kdn_name}"\n'
            "  printf '%s=%s\\0' \"$kdn_name\" \"$kdn_value\"\n"
            "done\n"
        )
        self.usage = self._usage()

    def _usage(self):
        result = engine_shell.run_sh(f"{self.head}usage\n", env=self.env, shell=self.shell)
        assert (result.returncode, result.stderr) == (0, ""), result.stderr
        assert "Usage" in result.stdout or "usage" in result.stdout
        return result.stdout

    def run(self, argv):
        script = f"{self.head}set -- {' '.join(shlex.quote(arg) for arg in argv)}\n{self.loop}{self.dump}"
        result = engine_shell.run_sh(script, env=self.env, shell=self.shell)
        if result.returncode != 0:
            return Legacy(result.returncode, None, result.stderr)
        fields = {}
        for record in result.stdout.split("\0")[:-1]:
            name, _, value = record.partition("=")
            fields[name] = value
        return Legacy(0, fields, result.stderr)


def python_fields(options):
    """The value of every field of Options in the shape of a shell variable."""
    return {
        name: (str(int(getattr(options, attribute))) if kind == "flag" else getattr(options, attribute))
        for name, attribute, kind in FIELDS
    }


def error_expectations(shell_label, argv, error, legacy):
    """Differences between the error of parse_args and the stderr of the loop (empty when they agree)."""
    expected = error.message + "\n"
    stderr = legacy.stderr
    if error.message.startswith("ERROR: unknown argument: "):
        # The loop prints the usage after the message; Python prints the message only (B8 of the plan).
        if shell_label == "dash" and "\\" in error.message:
            # B6: dash's echo expands \n, \t, \\ and \c in the argument; Python and busybox print it as it is.
            prefix = error.message.split("\\", 1)[0]
            return [] if stderr.startswith(prefix) else [f"stderr {stderr!r} does not start with {prefix!r}"]
        if not stderr.startswith(expected):
            return [f"stderr {stderr[: len(expected) + 20]!r}, expected it to start with {expected!r}"]
        return []
    return [] if stderr == expected else [f"stderr {stderr!r}, expected {expected!r}"]


def compare(shell_label, loop, argv):
    """Problems found when parse_args and the loop answer one argv differently."""
    legacy = loop.run(argv)
    try:
        options, error = engine_options.parse_args(argv), None
    except engine_options.ArgError as exc:
        options, error = None, exc
    if legacy.rc == 0:
        if error is not None:
            return [f"loop accepted it, parse_args raised {error.message!r}"]
        python = python_fields(options)
        return [
            f"{name}: loop {legacy.fields.get(name)!r}, python {python[name]!r}"
            for name, _, _ in FIELDS
            if legacy.fields.get(name) != python[name]
        ]
    if legacy.rc != 2:
        return [f"the loop ended with status {legacy.rc}: {legacy.stderr!r}"]
    if error is None:
        return [f"loop rejected it ({legacy.stderr[:80]!r}), parse_args accepted it"]
    if error.code != 2:
        return [f"ArgError code {error.code}, the loop exits with 2"]
    return error_expectations(shell_label, argv, error, legacy)


class ShellCase(unittest.TestCase):
    def shells(self):
        shells = installed_shells()
        self.assertTrue(shells, "neither dash nor busybox is installed")
        return shells


class LoopTextTests(unittest.TestCase):
    """The lists of this file are the flags of the real loop."""

    def test_the_options_of_the_loop_are_the_ones_the_tests_know(self):
        labels, valued = loop_labels()
        self.assertEqual(valued, set(VALUE_OPTIONS))
        self.assertEqual(labels, set(KNOWN))

    def test_the_loop_sets_exactly_the_variables_of_the_field_table(self):
        loop = split_script()[1]
        assigned = set(re.findall(r"(?<![\w$])([A-Za-z_][A-Za-z0-9_]*)=", loop))
        self.assertEqual(assigned, {name for name, _, _ in FIELDS})
        # No other construct of the loop changes a variable.
        for construct in ("read ", "export ", "eval ", "unset ", "local ", "set "):
            self.assertNotIn(construct, loop)

    def test_every_field_of_options_is_checked_by_the_table(self):
        options = engine_options.Options()
        self.assertEqual(
            set(engine_options.Options.__slots__),
            {attribute for _, attribute, _ in FIELDS} | {"json", "focused_context", "recover_import_source"},
        )
        self.assertEqual({attribute: getattr(options, attribute) for attribute in DEFAULTS}, DEFAULTS)


class DifferentialTests(ShellCase):
    def test_parse_args_agrees_with_the_argument_loop_of_the_script(self):
        cases = corpus()
        self.assertGreaterEqual(len(cases), 400)
        with tempfile.TemporaryDirectory(prefix="kdn-options-") as root:
            for label, shell in self.shells().items():
                loop = LegacyLoop(shell, root)
                problems = []
                for argv in cases:
                    problems.extend(f"{argv!r}: {problem}" for problem in compare(label, loop, argv))
                with self.subTest(shell=label, cases=len(cases)):
                    self.assertEqual(problems[:8], [])

    def test_parse_matches_the_mode_table(self):
        rows = table_rows()
        self.assertGreaterEqual(len(rows), 54)
        problems = []
        for expected, argv in rows:
            try:
                got = class_of(engine_options.parse_args(argv).mode)
            except engine_options.ArgError:
                got = "?"
            if got != expected:
                problems.append(f"{argv!r}: table {expected!r}, parse_args {got!r}")
        self.assertEqual(problems, [])

    def test_legacy_loop_agrees_with_the_mode_table_except_for_json(self):
        with tempfile.TemporaryDirectory(prefix="kdn-options-") as root:
            for label, shell in self.shells().items():
                loop = LegacyLoop(shell, root)
                for expected, argv in table_rows():
                    legacy = loop.run(argv)
                    got = "?" if legacy.rc == 2 else class_of(legacy.fields["MODE"])
                    with self.subTest(shell=label, argv=argv):
                        if "--json" in argv:
                            # B1 of the plan: only the Python path knows --json.
                            self.assertEqual(got, "?")
                            self.assertTrue(legacy.stderr.startswith("ERROR: unknown argument: --json\n"))
                        else:
                            self.assertEqual(got, expected)


class MissingValueTests(ShellCase):
    def test_missing_values_have_the_shell_messages(self):
        with tempfile.TemporaryDirectory(prefix="kdn-options-") as root:
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "KD_TEST_ROOT": root,
                "KD_ALLOW_TEST_ROOT": "1",
            }
            for label, shell in self.shells().items():
                for option, need in VALUE_OPTIONS.items():
                    message = f"ERROR: {option} requires {need}"
                    with self.subTest(shell=label, option=option):
                        # The whole script: the loop rejects the argv before anything else runs.
                        command = " ".join(shlex.quote(part) for part in (*shell, str(engine_shell.SCRIPT), option))
                        legacy = engine_shell.run_sh(command, env=env)
                        self.assertEqual((legacy.returncode, legacy.stdout, legacy.stderr), (2, "", message + "\n"))
                        with self.assertRaises(engine_options.ArgError) as caught:
                            engine_options.parse_args([option])
                        self.assertEqual((caught.exception.message, caught.exception.code), (message, 2))
                        self.assertEqual(str(caught.exception), message)

    def test_an_unknown_argument_is_an_error_without_the_usage(self):
        with tempfile.TemporaryDirectory(prefix="kdn-options-") as root:
            env = {"PATH": os.environ.get("PATH", os.defpath), "KD_TEST_ROOT": root, "KD_ALLOW_TEST_ROOT": "1"}
            for label, shell in self.shells().items():
                command = " ".join(shlex.quote(part) for part in (*shell, str(engine_shell.SCRIPT), "--bogus"))
                legacy = engine_shell.run_sh(command, env=env)
                with self.subTest(shell=label):
                    self.assertEqual((legacy.returncode, legacy.stdout), (2, ""))
                    self.assertTrue(legacy.stderr.startswith("ERROR: unknown argument: --bogus\n"))
                    self.assertGreater(len(legacy.stderr), len("ERROR: unknown argument: --bogus\n"))
        for argv, shown in ((["--bogus"], "--bogus"), ([""], ""), (["--status", "--bogus", "--help"], "--bogus")):
            with self.subTest(argv=argv), self.assertRaises(engine_options.ArgError) as caught:
                engine_options.parse_args(argv)
            self.assertEqual(caught.exception.message, f"ERROR: unknown argument: {shown}")
            self.assertEqual(caught.exception.code, 2)

    def test_the_first_error_wins_and_nothing_after_it_is_read(self):
        with self.assertRaises(engine_options.ArgError) as caught:
            engine_options.parse_args(["--core", "--bogus", "--udp-strategy"])
        # --core takes "--bogus" as its value; the error is the missing value of --udp-strategy.
        self.assertEqual(caught.exception.message, "ERROR: --udp-strategy requires flowseal or legacy.")
        with self.assertRaises(engine_options.ArgError) as caught:
            engine_options.parse_args(["--bogus", "--udp-strategy"])
        self.assertEqual(caught.exception.message, "ERROR: unknown argument: --bogus")


class FlagTests(unittest.TestCase):
    def assert_fields(self, argv, changes):
        expected = {**DEFAULTS, **changes}
        options = engine_options.parse_args(argv)
        self.assertEqual({attribute: getattr(options, attribute) for attribute in DEFAULTS}, expected, argv)

    def test_internal_focused_adapters_require_a_focused_mutation(self):
        self.assert_fields(['--rollback-import', '--focused-operation-context', '{}',
                            '--recover-import-source', '/synthetic/source', '--yes-router'],
                           {'mode': 'rollback-import', 'focused_context': '{}',
                            'recover_import_source': '/synthetic/source', 'confirmed': True})
        self.assert_fields(['--prune-import-snapshots', '--yes-router'],
                           {'mode': 'prune-import-snapshots', 'confirmed': True})
        for args in (['--status', '--focused-operation-context', '{}'],
                     ['--rollback-import', '--recover-import-source', '/synthetic/source'],
                     ['--apply', '--focused-operation-context', '{}']):
            with self.subTest(args=args), self.assertRaises(engine_options.ArgError):
                engine_options.parse_args(args)

    def test_defaults_are_the_shell_defaults(self):
        self.assert_fields([], {})
        for name, attribute, kind in FIELDS:
            written = engine_shell.extract_assignment(name)
            expected = getattr(engine_options.Options(), attribute)
            self.assertEqual(written, str(int(expected)) if kind == "flag" else expected, name)

    def test_flags_set_the_fields(self):
        cases = [
            (["--print-plan"], {"mode": "print-plan"}),
            (["--preflight"], {"mode": "preflight"}),
            (["--status"], {"mode": "status"}),
            (["--check-config"], {"mode": "check-config"}),
            (["--print-nfqws-profiles"], {"mode": "print-nfqws-profiles"}),
            (["--show-snapshots"], {"mode": "show-snapshots"}),
            (["--show-rollback"], {"mode": "show-snapshots"}),
            (["--snapshot-baseline"], {"mode": "snapshot-baseline"}),
            (["--apply"], {"mode": "apply"}),
            (["--rollback-import"], {"mode": "rollback-import"}),
            (["--rollback"], {"mode": "rollback-baseline"}),
            (["--rollback-baseline"], {"mode": "rollback-baseline"}),
            (["--rollback-latest"], {"mode": "rollback-latest"}),
            (["-h"], {"mode": "help"}),
            (["--help"], {"mode": "help"}),
            (["--status", "--help"], {"mode": "help"}),
            (["--yes-router"], {"mode": "apply", "confirmed": True}),
            (["--status", "--yes-router"], {"mode": "status", "confirmed": True}),
            (["--yes-router", "--status"], {"mode": "status", "confirmed": True}),
            (["--yes-router", "--help"], {"mode": "help", "confirmed": True}),
            (["--help", "--yes-router"], {"mode": "apply", "confirmed": True}),
            (["--wide-udp"], {"wide_udp": True}),
            (["--wide-udp", "--narrow-udp"], {}),
            (["--narrow-udp", "--wide-udp"], {"wide_udp": True}),
            (["--narrow-udp"], {}),
            (["--standalone-zapret"], {"standalone": True}),
            (["--without-xkeen"], {"standalone": True}),
            (["--no-xkeen"], {"standalone": True}),
            (["--standalone-zapret", "--integrated"], {}),
            (["--integrated"], {}),
            (["--integrated", "--no-xkeen"], {"standalone": True}),
            (
                ["--apply-import-profile", "p.json"],
                {"mode": "apply-import-profile", "import_profile": "p.json"},
            ),
            (
                ["--clear-imported-profile", "youtube"],
                {"mode": "clear-imported-profile", "clear_profile": "youtube"},
            ),
            (
                ["--rollback-snapshot", "/s/1"],
                {"mode": "rollback-snapshot", "rollback_snapshot": "/s/1"},
            ),
            (["--udp-strategy", "legacy"], {"udp_strategy": "legacy"}),
            (
                ["--discord-route", "vless"],
                {
                    "discord_tcp_route": "vless",
                    "discord_voice_route": "vless",
                    "discord_tcp_route_explicit": True,
                    "discord_voice_route_explicit": True,
                },
            ),
            (
                ["--discord-tcp-route", "direct"],
                {"discord_tcp_route": "direct", "discord_tcp_route_explicit": True},
            ),
            (
                ["--discord-voice-route", "direct"],
                {"discord_voice_route": "direct", "discord_voice_route_explicit": True},
            ),
            (["--youtube-route", "zapret"], {"youtube_route": "zapret", "youtube_route_explicit": True}),
            (["--telegram-route", "ws"], {"telegram_route": "ws", "telegram_route_explicit": True}),
            (["--proxy-outbound", "proxy-a"], {"proxy_outbound_requested": "proxy-a"}),
            (["--core", "xray"], {"core_requested": "xray"}),
            (["--direct-mark", "255"], {"direct_mark_requested": "255"}),
            (["--wan-interface", "eth3 eth4"], {"wan_interface_requested": "eth3 eth4"}),
            (
                ["--discord-route", "vless", "--discord-voice-route", "direct"],
                {
                    "discord_tcp_route": "vless",
                    "discord_voice_route": "direct",
                    "discord_tcp_route_explicit": True,
                    "discord_voice_route_explicit": True,
                },
            ),
            (["--core", "--status"], {"core_requested": "--status"}),
            (["--rollback-snapshot", "--status"], {"mode": "rollback-snapshot", "rollback_snapshot": "--status"}),
            (
                ["--print-plan", "--wan-interface", "--status"],
                {"mode": "print-plan", "wan_interface_requested": "--status"},
            ),
            (["--status", "--apply"], {"mode": "apply"}),
            (["--apply", "--status"], {"mode": "status"}),
            (["--wan-interface", ""], {"wan_interface_requested": ""}),
            (["--telegram-route", ""], {"telegram_route": "", "telegram_route_explicit": True}),
        ]  # fmt: skip
        for argv, changes in cases:
            with self.subTest(argv=argv):
                self.assert_fields(argv, changes)

    def test_every_value_option_takes_the_next_argument_whatever_it_looks_like(self):
        for option, (mode, attributes) in OPTION_EFFECTS.items():
            for value in ("--help", "-h", "--yes-router", "--bogus", ""):
                with self.subTest(option=option, value=value):
                    options = engine_options.parse_args([option, value])
                    changes = {attribute: value for attribute in attributes}
                    for attribute in attributes:
                        if attribute.endswith("_route"):
                            changes[f"{attribute}_explicit"] = True
                    if mode:
                        changes["mode"] = mode
                    self.assert_fields([option, value], changes)
                    self.assertFalse(options.confirmed)

    def test_options_are_independent_and_compare_by_value(self):
        first = engine_options.Options()
        second = engine_options.Options()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        second.mode = "status"
        self.assertNotEqual(first, second)
        self.assertEqual(engine_options.parse_args(["--status"]), second)
        self.assertEqual(engine_options.parse_args([]), first)
        self.assertIn("mode='status'", repr(second))
        # Every field takes part in the comparison.
        for attribute in engine_options.Options.__slots__:
            changed = engine_options.Options()
            value = getattr(changed, attribute)
            setattr(changed, attribute, (not value) if isinstance(value, bool) else value + "x")
            with self.subTest(attribute=attribute):
                self.assertNotEqual(changed, first)
        self.assertNotEqual(first, "help")


class JsonFlagTests(unittest.TestCase):
    def test_json_flag_is_parsed_for_any_mode(self):
        for _, argv in table_rows():
            try:
                plain = engine_options.parse_args([arg for arg in argv if arg != "--json"])
            except engine_options.ArgError:
                continue
            for label, with_json in (("start", ["--json", *argv]), ("end", [*argv, "--json"])):
                if "--json" in argv:
                    continue
                with self.subTest(argv=argv, at=label):
                    options = engine_options.parse_args(with_json)
                    self.assertTrue(options.json)
                    expected = {attribute: getattr(plain, attribute) for attribute in DEFAULTS}
                    expected["json"] = True
                    self.assertEqual({attribute: getattr(options, attribute) for attribute in DEFAULTS}, expected)

    def test_json_flag_with_status(self):
        options = engine_options.parse_args(["--status", "--json"])
        self.assertEqual((options.mode, options.json), ("status", True))
        self.assertEqual(engine_options.parse_args(["--json", "--status"]).json, True)
        self.assertEqual(engine_options.parse_args(["--status"]).json, False)

    def test_json_is_a_value_when_a_value_option_comes_before_it(self):
        options = engine_options.parse_args(["--core", "--json"])
        self.assertEqual((options.core_requested, options.json), ("--json", False))
        with self.assertRaises(engine_options.ArgError) as caught:
            engine_options.parse_args(["--bogus", "--json"])
        self.assertEqual(caught.exception.message, "ERROR: unknown argument: --bogus")

    def test_json_does_not_change_the_mode(self):
        for argv in (["--json"], ["--json", "--yes-router"], ["--json", "--apply"]):
            with self.subTest(argv=argv):
                expected = engine_options.parse_args([arg for arg in argv if arg != "--json"])
                self.assertEqual(engine_options.parse_args(argv).mode, expected.mode)


class ResolveTests(unittest.TestCase):
    def test_wide_udp_sets_voice_high_and_required_ports(self):
        result = engine_options.resolve(engine_options.parse_args(['--status', '--wide-udp']), None)
        self.assertEqual(result.voice_high, '65535')
        self.assertIn('50000:65535', result.xkeen_required_ports)

    def test_post_loop_values_errors_and_order_match_the_real_shell(self):
        head, loop = split_script()
        text = engine_shell.script_text()
        start = text.index(loop) + len(loop)
        post = text[start:text.index('if [ "$MODE" = "help" ]; then\n  usage', start)]
        fields = [('PREVIOUS_TELEGRAM_ROUTE', 'previous_telegram_route'),
                  ('TELEGRAM_HEADER_ROUTE', 'telegram_header_route'), ('VOICE_HIGH', 'voice_high'),
                  ('XKEEN_REQUIRED_PORTS', 'xkeen_required_ports'),
                  *[(a, b) for a, b, _ in FIELDS if b.endswith('_route')]]
        dump = ''.join('printf "%s\\0" "${' + variable + '}"\n' for variable, _ in fields)
        dump += 'routes_summary\n'
        cases = [[], ['--wide-udp'], ['--standalone-zapret'], ['--core', 'mihomo'],
                 ['--telegram-route', 'zapret'], ['--telegram-route', 'bogus'],
                 ['--standalone-zapret', '--telegram-route', 'ws'],
                 ['--standalone-zapret', '--core', 'bad'],
                 ['--standalone-zapret', '--direct-mark', '1'],
                 ['--standalone-zapret', '--proxy-outbound', 'a'],
                 ['--standalone-zapret', '--discord-route', 'vless'],
                 ['--standalone-zapret', '--discord-route', 'direct', '--youtube-route', 'direct'],
                 ['--core', 'bad', '--udp-strategy', 'bad'],
                 ['--udp-strategy', 'bad', '--discord-route', 'bad'],
                 ['--discord-tcp-route', 'bad', '--discord-voice-route', 'bad'],
                 ['--discord-voice-route', 'bad', '--youtube-route', 'bad'],
                 ['--youtube-route', 'bad'], ['--proxy-outbound', 'a b'],
                 ['--proxy-outbound', 'vpn_1.a:b-c'], ['--telegram-route', 'direct'],
                 ['--telegram-route', 'vless'], ['--telegram-route', 'ws'],
                 ['--standalone-zapret', '--telegram-route', 'vless'],
                 ['--standalone-zapret', '--discord-route', 'bad'], ['--udp-strategy', 'legacy'],
                 ['--proxy-outbound', ''], ['--proxy-outbound', 'тест'],
                 ['--direct-mark', 'not-validated-here'], ['--wan-interface', 'eth9 eth10']]
        cases += [json.loads(row.split('\t')[2]) for row in VALIDATION_TABLE.read_text(encoding='utf-8').split('\n')
                  if row and not row.startswith('#')]
        self.assertEqual(set(installed_shells()), set(SHELLS), 'both differential shells are required')
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'opt/etc/nfqws2/nfqws2.conf')
            os.makedirs(os.path.dirname(config_path))
            for label, shell in installed_shells().items():
                env = {'PATH': os.environ['PATH'], 'KD_TEST_ROOT': tmp, 'KD_ALLOW_TEST_ROOT': '1', 'KDN_ENGINE': 'legacy'}
                if label == 'busybox ash':
                    farm = os.path.join(tmp, 'applets')
                    os.makedirs(farm)
                    for applet in ('awk', 'sed', 'grep', 'tr'):
                        os.symlink(shutil.which('busybox'), os.path.join(farm, applet))
                    env['PATH'] = farm + os.pathsep + env['PATH']
                for recorded in ('unmanaged', 'zapret', 'vless', 'ws'):
                    nfqws = '# Active routes: Telegram=' + recorded + '.\n'
                    with open(config_path, 'w') as handle:
                        handle.write(nfqws)
                    for mode in ('--print-plan', '--preflight'):
                        for case in cases:
                            argv = [mode, *case]
                            with self.subTest(shell=label, recorded=recorded, argv=argv):
                                result = engine_shell.run_sh(head + 'set -- ' + shlex.join(argv) + '\n' + loop + post + dump,
                                                             env=env, shell=shell)
                                parsed = engine_options.parse_args(argv)
                                before = repr(parsed)
                                try:
                                    resolved = engine_options.resolve(parsed, nfqws)
                                except engine_options.ArgError as error:
                                    self.assertEqual(result.returncode, error.code)
                                    self.assertEqual(result.stderr, ''.join(w + '\n' for w in error.warnings) + error.message + '\n')
                                else:
                                    self.assertEqual(result.returncode, 0, result.stderr)
                                    self.assertEqual(result.stderr, ''.join(w + '\n' for w in resolved.warnings))
                                    values = [getattr(resolved, field) for _, field in fields]
                                    self.assertEqual(result.stdout, '\0'.join(values) + '\0' + resolved.routes_summary())
                                self.assertEqual(repr(parsed), before)

    def test_json_flag_only_with_status(self):
        self.assertTrue(engine_options.resolve(engine_options.parse_args(['--status', '--json']), None).json)
        for argv in (['--json'], ['--print-plan', '--json'], ['--apply', '--json']):
            with self.subTest(argv=argv), self.assertRaisesRegex(engine_options.ArgError, '--json is supported only with --status'):
                engine_options.resolve(engine_options.parse_args(argv), None)

    def test_pinned_validation_table(self):
        rows = VALIDATION_TABLE.read_text(encoding='utf-8').split('\n')
        for row in rows:
            if not row or row.startswith('#'):
                continue
            rc, message, encoded = row.split('\t')
            argv = json.loads(encoded)
            with self.subTest(argv=argv), self.assertRaises(engine_options.ArgError) as caught:
                engine_options.resolve(engine_options.parse_args(argv), None)
            self.assertEqual((caught.exception.code, caught.exception.message), (int(rc), message))

    def test_cli_warnings_once_before_native_output_and_not_before_legacy_exec(self):
        warning = 'WARNING: the recorded Telegram route zapret was removed; Telegram becomes direct.\n'
        text = '# Active routes: Telegram=zapret.\n'
        with mock.patch.object(cli.confvalues, 'read_text', return_value=text), \
                mock.patch.object(cli.xkeen, 'require', return_value='2.1'):
            out, err = io.StringIO(), io.StringIO()
            seen = []
            with mock.patch.object(cli, '_run_mutation', side_effect=lambda ctx: (seen.append(ctx), ctx.console.out('native'), 0)[-1]):
                rc = cli.main(['--preflight'], environ={}, stdout=out, stderr=err)
            self.assertEqual((rc, out.getvalue(), err.getvalue()), (0, 'native\n', warning))
            self.assertEqual(seen[0].resolved.telegram_route, 'direct')
            self.assertEqual(seen[0].options.telegram_route, '')
            self.assertEqual(cli.main(['--core', 'bad', '--preflight'], environ={}, stdout=out, stderr=err), 2)
            self.assertTrue(err.getvalue().endswith(warning + 'ERROR: unsupported core: bad\n'))

            class HandOver(Exception):
                pass

            def execve(*_args):
                raise HandOver

            err = io.StringIO()
            with self.assertRaises(HandOver):
                cli.main(['--preflight', '--core', 'mihomo'],
                         environ={'KD_TEST_ROOT': '/fixture/historical', 'KD_ALLOW_TEST_ROOT': '1'},
                         stdout=io.StringIO(), stderr=err, execve=execve)
            self.assertEqual(err.getvalue(), '')


class ModuleTests(unittest.TestCase):
    def test_module_stays_within_the_import_budget(self):
        snippet = (
            "import sys\n"
            f"sys.path.insert(0, {str(PACKAGE_PATH)!r})\n"
            "before = set(sys.modules)\n"
            "import kdn.engine.options\n"
            "print(' '.join(sorted(set(sys.modules) - before)))\n"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", snippet], capture_output=True, text=True, check=False, timeout=60
        )
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        loaded = set(result.stdout.split())
        # enum is loaded by re on 3.12 and 3.13 (R11); the direct imports are checked by the structure test.
        forbidden = {"dataclasses", "inspect", "typing", "tempfile", "shutil", "argparse", "logging", "subprocess"}
        self.assertEqual(loaded & forbidden, set())
        ours = {name for name in loaded if name.startswith("kdn")}
        self.assertEqual(ours, {"kdn", "kdn.engine", "kdn.engine.options", "kdn.engine.config",
                                "kdn.engine.confvalues", "kdn.engine.legacy", "kdn.common", "kdn.common.paths"})

    def test_parse_args_does_not_modify_its_argument(self):
        argv = ["--core", "xray", "--status"]
        engine_options.parse_args(argv)
        self.assertEqual(argv, ["--core", "xray", "--status"])
        engine_options.parse_args(tuple(argv))


if __name__ == "__main__":
    unittest.main()

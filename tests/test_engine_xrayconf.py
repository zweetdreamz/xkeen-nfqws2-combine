"""Tests of kdn.engine.xrayconf: the Xray config files and the jq primitives the engine ports.

The differential tests run the real shell code of apply-discord-nfqws2.sh (``strict_json_stream``,
``strict_json_copy``, ``find_xray_routing_file``, the ``"$DIR"/*.json`` loops) under dash and busybox ash, with the
system awk and with the busybox awk, and the real ``jq`` on the same corpus, and compare them with the Python port.
Where the port is meant to differ (B7: inputs that are not what Xray writes) every case is listed in
``DIVERGENCES`` / ``RAW_DIVERGENCES`` with both sides spelled out, so a change on either side fails a test.

The router has jq 1.8.1 and the test image jq 1.7: both keep a number literal as it was written (``255.0`` stays
``255.0``, ``1e3`` prints ``1E+3``); jq 1.6 printed ``255``. The literal-sensitive tests are skipped on jq < 1.7
and without jq the differential tests are skipped, each with its own message.
"""

from __future__ import annotations

import ast
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import engine_shell
from engine_shell import run_function, run_sh

from kdn.engine import xrayconf


ROOT = engine_shell.ROOT
FIXTURE_CONFIGS = ROOT / "tests" / "fixtures" / "engine" / "router-xkeen20" / "opt" / "etc" / "xray" / "configs"
JQ = shutil.which("jq")
HAS_BUSYBOX = shutil.which("busybox") is not None
AWKS = ("system", "busybox") if HAS_BUSYBOX else ("system",)
SHELLS = {"dash": ("dash",), "busybox ash": ("busybox", "sh")}
SHELLS = {label: argv for label, argv in SHELLS.items() if shutil.which(argv[0])}
LOAD_DEFS = ["strict_json_stream"]
ROUTING_DEFS = ["make_tmp", "strict_json_copy", "strict_json_stream"]
DBL_MAX_TEXT = "1.7976931348623157e+308"


def jq_version():
    if JQ is None:
        return (0, 0)
    banner = subprocess.run([JQ, "--version"], capture_output=True, text=True, check=False).stdout
    found = re.match(r"jq-(\d+)\.(\d+)", banner.strip())
    return (int(found[1]), int(found[2])) if found else (0, 0)


needs_jq = unittest.skipUnless(JQ, "jq is not installed: the differential tests against jq are skipped")
needs_literal_jq = unittest.skipUnless(
    JQ and jq_version() >= (1, 7), "jq before 1.7 prints 255.0 as 255: the literal tests are skipped"
)
needs_unprivileged = unittest.skipIf(os.geteuid() == 0, "root reads files whatever their mode")


def plain(value):
    """The value with every NaN replaced by None, which is how jq prints it (and how json.loads reads its output)."""
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    return value


def run_jq(program, text, *flags):
    """(returncode, stdout) of ``jq <flags> program`` on the text."""
    completed = subprocess.run(
        [JQ, *flags, program],
        input=text.encode("utf-8", "surrogateescape"),
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout.decode("utf-8", "surrogateescape")


def shell_view(path, awk):
    """What the shell makes of a file: (accepted, last line jq prints). Accepted is ``strict_json_copy``'s status."""
    with tempfile.TemporaryDirectory(prefix="xrayconf-") as scratch:
        stripped = os.path.join(scratch, "stripped.json")
        copied = run_function("strict_json_copy", str(path), stripped, defs=LOAD_DEFS, awk=awk)
        if copied.returncode != 0:
            return False, None
        with open(stripped, "rb") as handle:
            printed = subprocess.run([JQ, "-c", "."], stdin=handle, capture_output=True, check=True)
    lines = printed.stdout.decode("utf-8", "surrogateescape").splitlines()
    return True, lines[-1]


class TempDirCase(unittest.TestCase):
    def make_dir(self, files=None):
        """A temporary directory holding ``files``: name -> bytes, or ("link", target) for a symlink."""
        scratch = tempfile.TemporaryDirectory(prefix="xrayconf-")
        self.addCleanup(scratch.cleanup)
        root = scratch.name
        for name, content in (files or {}).items():
            path = os.path.join(root, os.fsdecode(name))
            if isinstance(content, tuple):
                os.symlink(content[1], path)
            elif content is None:
                os.mkdir(path)
            else:
                with open(path, "wb") as handle:
                    handle.write(content)
        return root

    def load_text(self, text):
        """The document ``load_strict`` makes of the text (None when it is not a document)."""
        root = self.make_dir({"x.json": text.encode("utf-8", "surrogateescape")})
        return xrayconf.load_strict(os.path.join(root, "x.json"))

    def value_of(self, text):
        """The value of a JSON text, null and false included (they are not documents, but they are values)."""
        return self.load_text(f"[{text}]")[0]


# -------- json_files --------
GLOB_FILES = {
    "05_b.json": b"{}",
    "05_ä.json": b"{}",
    "05_B.json": b"{}",
    "A1.json": b"{}",
    "B.json": b"{}",
    "_x.json": b"{}",
    "a.json": b"{}",
    "sp ace.json": b"{}",
    "z*.json": b"{}",
    ".hidden.json": b"{}",
    ".json": b"{}",
    "x.JSON": b"{}",
    "x.json.bak": b"{}",
    "noext": b"{}",
    "json": b"{}",
    "dir.json": None,
    "real.json": b"{}",
    "link.json": ("link", "real.json"),
    "dirlink.json": ("link", "dir.json"),
    "broken.json": ("link", "missing.json"),
}
GLOB_EXPECTED = [
    "05_B.json",
    "05_b.json",
    "05_ä.json",
    "A1.json",
    "B.json",
    "_x.json",
    "a.json",
    "link.json",
    "real.json",
    "sp ace.json",
    "z*.json",
]
SHELL_GLOB = 'for f in "$1"/*.json; do [ -f "$f" ] || continue; printf "%s\\n" "$f"; done'


class JsonFilesTests(TempDirCase):
    def shell_names(self, root, shell):
        script = f"set -- {json_quote(root)}; {SHELL_GLOB}"
        completed = run_sh(script, shell=shell)
        self.assertEqual((completed.returncode, completed.stderr), (0, ""))
        prefix = root + "/"
        return [line[len(prefix) :] for line in completed.stdout.split("\n") if line]

    def test_json_files_follow_the_shell_glob(self):
        root = self.make_dir(GLOB_FILES)
        names = [path.name for path in xrayconf.json_files(root)]
        self.assertEqual(names, GLOB_EXPECTED)
        for label, shell in SHELLS.items():
            with self.subTest(shell=label):
                self.assertEqual(self.shell_names(root, shell), names)

    def test_json_files_sort_by_bytes_not_by_characters(self):
        # 0xff sorts after every UTF-8 name; a character-based sort of the decoded names would put U+DCFF first.
        root = self.make_dir()
        try:
            for raw in (b"\xff.json", b"\xc3\xa4.json", b"z.json", b"Z.json"):
                with open(os.path.join(os.fsencode(root), raw), "wb") as handle:
                    handle.write(b"{}")
        except OSError as error:
            self.skipTest(f"the file system refuses the names: {error}")
        names = [path.name for path in xrayconf.json_files(root)]
        self.assertEqual(names, ["Z.json", "z.json", "ä.json", os.fsdecode(b"\xff.json")])
        for label, shell in SHELLS.items():
            with self.subTest(shell=label):
                self.assertEqual(self.shell_names(root, shell), names)

    def test_json_files_return_paths_inside_the_directory(self):
        root = self.make_dir({"a.json": b"{}"})
        found = xrayconf.json_files(root)
        self.assertEqual(found, [Path(root) / "a.json"])
        self.assertIsInstance(found[0], Path)

    def test_json_files_of_a_trailing_slash_directory(self):
        root = self.make_dir({"a.json": b"{}"})
        self.assertEqual([path.name for path in xrayconf.json_files(root + "/")], ["a.json"])

    def test_json_files_of_a_directory_that_is_missing_or_not_a_directory(self):
        root = self.make_dir({"a.json": b"{}"})
        self.assertEqual(xrayconf.json_files(os.path.join(root, "missing")), [])
        self.assertEqual(xrayconf.json_files(os.path.join(root, "a.json")), [])
        for label, shell in SHELLS.items():
            with self.subTest(shell=label):
                self.assertEqual(self.shell_names(os.path.join(root, "missing"), shell), [])
                self.assertEqual(self.shell_names(os.path.join(root, "a.json"), shell), [])

    @needs_unprivileged
    def test_json_files_of_an_unreadable_directory(self):
        root = self.make_dir({"a.json": b"{}"})
        os.chmod(root, 0)
        self.addCleanup(os.chmod, root, 0o700)
        self.assertEqual(xrayconf.json_files(root), [])
        for label, shell in SHELLS.items():
            with self.subTest(shell=label):
                self.assertEqual(self.shell_names(root, shell), [])

    def test_json_files_of_the_real_router_tree(self):
        names = [path.name for path in xrayconf.json_files(str(FIXTURE_CONFIGS))]
        self.assertEqual(
            names,
            [
                "01_log.json",
                "02_dns.json",
                "03_inbounds.json",
                "03_tor_socks_inbound.json",
                "04_discord_nfqws2_outbound.json",
                "04_outbounds.json",
                "04_youtube_nfqws2_outbound.json",
                "05_routing.json",
                "06_policy.json",
            ],
        )
        for label, shell in SHELLS.items():
            with self.subTest(shell=label):
                self.assertEqual(self.shell_names(str(FIXTURE_CONFIGS), shell), names)


def json_quote(text):
    """The text as one single-quoted shell word."""
    return "'" + text.replace("'", "'\\''") + "'"


# -------- load_strict --------
NESTED = b"[" * 100000 + b"]" * 100000
BLOCK_ENDS_MID_LINE = b'{\n  "rules": [ /* start\n    still comment */ {"tag": "x"} ]\n}\n'
LOAD_CORPUS = {
    "plain": b'{"a":1,"b":[1,2],"c":{"d":null},"e":"x"}\n',
    "line comments": b'// leading comment\n{\n  "a": 1, // trailing\n  "b": 2\n}\n',
    "block comments": (
        b'/*\n * header\n */\n{\n  "a": /* note */ 1,\n  "b": [1, /* a * b */ 2],\n  "c": 3 /* closing */\n}\n'
    ),
    "comment markers inside strings": (
        b'{\n  "url": "http://example.org/a //b",\n  "pat": "/* not a comment */", // real comment\n'
        b'  "q": "say \\"//hi\\""\n}\n'
    ),
    "block comment ends mid-line": BLOCK_ENDS_MID_LINE,
    "line comment at the end without a newline": b'{"a":1} // done',
    "block comment at the end without a newline": b'{"a":1} /* done */',
    "unclosed block comment hides the rest": b'{"a":1}\n/* never closed\n{"b":2}',
    "slashes in the last string": b'{"u":"http://x//y"}',
    "escaped backslash before the closing quote": b'{"q":"a\\\\"} // c',
    "block comment inside a line comment": b'// a /* b\n{"a":1}\n',
    "line comment inside a block comment": b'/* a // b */ {"a":1}',
    "bare CR does not end a line comment": b'{"a":1,// c\r"b":2}',
    "BOM": b'\xef\xbb\xbf{"a":1}',
    "BOM and a comment": b'\xef\xbb\xbf// c\n{"a":1}',
    "CRLF": b'{\r\n  "a": 1, // c\r\n  "b": 2\r\n}\r\n',
    "null document": b"null",
    "false document": b"false\n",
    "true document": b"true",
    "zero document": b"0",
    "empty string document": b'""',
    "empty list document": b"[]",
    "empty object document": b"{}",
    "string document": b'"x"',
    "empty file": b"",
    "whitespace only": b" \n\n",
    "comment only": b"// nothing\n",
    "duplicate keys": b'{"a":1,"b":2,"a":3}',
    "trailing comma in an object": b'{"a":1,}',
    "trailing comma in a list": b"[1,2,]",
    "unquoted key": b"{a:1}",
    "single quotes": b"{'a':1}",
    "truncated": b'{"a":',
    "NaN": b'{"a":NaN}',
    "Infinity": b'{"a":Infinity,"b":-Infinity}',
    "NaN document": b"NaN",
    "unicode": '{"t":"é😀"}'.encode(),
    "escapes": b'{"t":"\\u00e9\\n\\"q\\"\\ud83d\\ude00"}',
    "big int": b'{"a":123456789012345678901234567890}',
    "exponents": b'{"a":1e3,"b":1.5E-2,"c":255.0,"d":-0}',
    "raw tab in a string": b'{"a":"x\ty"}',
    "raw newline in a string": b'{"a":"x\ny"}',
    "form feed between tokens": b'{"a":\x0c1}',
    "NBSP between tokens": b'{"a":\xc2\xa01}',
    "invalid escape": b'{"a":"x\\qy"}',
    "hex number": b'{"a":0x10}',
    "text after the document": b'{"a":1} x',
    "nested far too deep": NESTED,
}


class LoadStrictTests(TempDirCase):
    def write(self, content):
        root = self.make_dir({"x.json": content})
        return os.path.join(root, "x.json")

    @needs_jq
    def test_load_strict_matches_strict_json_stream_then_jq(self):
        for name, content in LOAD_CORPUS.items():
            path = self.write(content)
            document = xrayconf.load_strict(path)
            for awk in AWKS:
                with self.subTest(case=name, awk=awk):
                    accepted, printed = shell_view(path, awk)
                    if name == "nested far too deep":
                        self.assertEqual((accepted, document), (False, None))
                    elif not accepted:
                        self.assertIsNone(document)
                    else:
                        self.assertIsNotNone(document, "accepted by jq -e . but not by load_strict")
                        self.assertEqual(plain(document), json.loads(printed))

    def test_load_strict_reads_the_documents_of_the_corpus(self):
        expected = {
            "plain": {"a": 1, "b": [1, 2], "c": {"d": None}, "e": "x"},
            "line comments": {"a": 1, "b": 2},
            "block comments": {"a": 1, "b": [1, 2], "c": 3},
            "comment markers inside strings": {
                "url": "http://example.org/a //b",
                "pat": "/* not a comment */",
                "q": 'say "//hi"',
            },
            "block comment ends mid-line": {"rules": [{"tag": "x"}]},
            "line comment at the end without a newline": {"a": 1},
            "block comment at the end without a newline": {"a": 1},
            "unclosed block comment hides the rest": {"a": 1},
            "slashes in the last string": {"u": "http://x//y"},
            "escaped backslash before the closing quote": {"q": "a\\"},
            "block comment inside a line comment": {"a": 1},
            "line comment inside a block comment": {"a": 1},
            "BOM": {"a": 1},
            "BOM and a comment": {"a": 1},
            "CRLF": {"a": 1, "b": 2},
            "true document": True,
            "zero document": 0,
            "empty string document": "",
            "empty list document": [],
            "empty object document": {},
            "string document": "x",
            "duplicate keys": {"a": 3, "b": 2},
            "NaN": {"a": None},
            "NaN document": None,
            "Infinity": {"a": 1.7976931348623157e308, "b": -1.7976931348623157e308},
            "unicode": {"t": "é😀"},
            "escapes": {"t": 'é\n"q"😀'},
            "big int": {"a": 123456789012345678901234567890},
            "exponents": {"a": 1000, "b": 0.015, "c": 255, "d": 0},
        }
        for name, content in LOAD_CORPUS.items():
            with self.subTest(case=name):
                document = xrayconf.load_strict(self.write(content))
                if name in expected:
                    self.assertEqual(plain(document), expected[name])
                    self.assertIs(type(document) is bool, type(expected[name]) is bool)
                else:
                    self.assertIsNone(document)

    def test_nan_is_a_number_that_prints_as_null(self):
        document = xrayconf.load_strict(self.write(b"NaN"))
        self.assertIsInstance(document, float)
        self.assertTrue(math.isnan(document))
        self.assertEqual(xrayconf.jq_raw(document), "null")

    def test_a_document_of_null_or_false_is_not_a_document(self):
        for text in (b"null", b"false", b"  null // c\n", b"\xef\xbb\xbfnull"):
            with self.subTest(text=text):
                self.assertIsNone(xrayconf.load_strict(self.write(text)))
        for text in (b"true", b"0", b'""', b"[]", b"{}"):
            with self.subTest(text=text):
                self.assertIsNotNone(xrayconf.load_strict(self.write(text)))

    def test_load_strict_takes_a_string_or_a_path(self):
        path = self.write(b'{"a":1}')
        self.assertEqual(xrayconf.load_strict(path), {"a": 1})
        self.assertEqual(xrayconf.load_strict(Path(path)), {"a": 1})

    def test_load_strict_of_a_file_that_is_not_there(self):
        root = self.make_dir({"dir.json": None})
        self.assertIsNone(xrayconf.load_strict(os.path.join(root, "missing.json")))
        self.assertIsNone(xrayconf.load_strict(os.path.join(root, "dir.json")))

    @needs_unprivileged
    @needs_jq
    def test_load_strict_of_an_unreadable_file(self):
        path = self.write(b'{"a":1}')
        os.chmod(path, 0)
        for awk in AWKS:
            with self.subTest(awk=awk):
                self.assertEqual(shell_view(path, awk), (False, None))
        self.assertIsNone(xrayconf.load_strict(path))

    def test_load_strict_reads_the_bytes_without_folding_line_ends(self):
        # read_text would turn the CR of CRLF into LF; a bare CR inside a string must stay an error, like in jq.
        self.assertEqual(xrayconf.load_strict(self.write(b'{"a":\r\n1}')), {"a": 1})
        self.assertIsNone(xrayconf.load_strict(self.write(b'{"a":"x\ry"}')))

    @needs_jq
    def test_load_strict_of_the_real_router_files(self):
        for path in sorted(FIXTURE_CONFIGS.glob("*.json")):
            document = xrayconf.load_strict(path)
            self.assertIsInstance(document, dict, path.name)
            for awk in AWKS:
                with self.subTest(file=path.name, awk=awk):
                    accepted, printed = shell_view(path, awk)
                    self.assertTrue(accepted)
                    self.assertEqual(plain(document), json.loads(printed))

    def test_numbers_loaded_from_a_file_behave_as_numbers(self):
        document = self.value_of('{"a":255.0,"b":1e3,"c":-0,"d":7,"e":1.5}')
        self.assertEqual(document, {"a": 255, "b": 1000, "c": 0, "d": 7, "e": 1.5})
        self.assertEqual(json.dumps(document["d"]), "7")
        self.assertEqual(json.dumps(document["e"]), "1.5")
        self.assertTrue(isinstance(document["a"], float) and isinstance(document["d"], int))


# Inputs on which the port differs from the shell on purpose (B7): the shell cleans comments with awk and parses with
# jq, the port uses kdn.common.jsonc and json. Each row: the file, whether the shell accepts it, the port's answer.
DIVERGENCES = {
    "several documents in one file": (b'{"a":1} {"b":2}', True, None),
    "documents glued together": (b'{"a":1}{"b":2}', True, None),
    "leading zeros": (b'{"a":007}', True, None),
    "plus sign": (b'{"a":+1}', True, None),
    "number without an integer part": (b'{"a":.5}', True, None),
    "number without a fraction": (b'{"a":5.}', True, None),
    "lower-case nan": (b'{"a":nan}', True, None),
    "comment inside a number: awk removes it, kdn.common.jsonc leaves a space": (b'{"a":1/**/2}', True, None),
    "an escaped lone surrogate: jq refuses it, json keeps it": (b'{"a":"\\ud800"}', False, {"a": "\ud800"}),
    "an integer of more than 4300 digits": (b'{"a":' + b"9" * 5000 + b"}", True, None),
    "a positive exponent beyond the integer conversion limit": (b'{"a":1e' + b"9" * 5000 + b"}", True, None),
    "a negative exponent beyond the integer conversion limit": (b'{"a":1e-' + b"9" * 5000 + b"}", True, None),
    "an exponent padded beyond the integer conversion limit": (b'{"a":1e' + b"0" * 5000 + b"3}", True, None),
}


class LoadStrictDivergenceTests(TempDirCase):
    @needs_jq
    def test_the_documented_divergences_are_what_the_shell_and_the_port_do(self):
        for name, (content, shell_accepts, port_answer) in DIVERGENCES.items():
            root = self.make_dir({"x.json": content})
            path = os.path.join(root, "x.json")
            for awk in AWKS:
                with self.subTest(case=name, awk=awk):
                    self.assertEqual(shell_view(path, awk)[0], shell_accepts)
                    self.assertEqual(xrayconf.load_strict(path), port_answer)

    @needs_jq
    def test_invalid_utf8_in_a_string_the_shell_replaces_the_byte_the_port_keeps_it(self):
        root = self.make_dir({"x.json": b'{"t":"a\xffb"}'})
        path = os.path.join(root, "x.json")
        accepted, printed = shell_view(path, "system")
        self.assertTrue(accepted)
        self.assertEqual(json.loads(printed), {"t": "a\ufffdb"})
        self.assertEqual(xrayconf.load_strict(path), {"t": "a\udcffb"})

    def test_documents_nested_beyond_the_recursion_limit_are_not_documents(self):
        root = self.make_dir({"x.json": NESTED})
        self.assertIsNone(xrayconf.load_strict(os.path.join(root, "x.json")))


# -------- routing_file --------
def routing():
    return b'{"routing":{"rules":[]}}'


ROUTING_SCENARIOS = {
    "no files": {},
    "only a non-routing file": {"01_log.json": b'{"log":{}}'},
    "one routing file": {"05_routing.json": routing()},
    "the last routing file wins": {"05_routing.json": routing(), "10_routing.json": routing(), "01_log.json": b"{}"},
    "a file after the routing file without routing": {"05_routing.json": routing(), "06_policy.json": b"{}"},
    "routing that is a list is skipped": {"05_routing.json": routing(), "10_x.json": b'{"routing":[]}'},
    "routing that is a string is skipped": {"05_routing.json": routing(), "10_x.json": b'{"routing":"x"}'},
    "routing that is null is skipped": {"05_routing.json": routing(), "10_x.json": b'{"routing":null}'},
    "routing that is a number is skipped": {"05_routing.json": routing(), "10_x.json": b'{"routing":1}'},
    "a broken file after the routing file": {"05_routing.json": routing(), "10_x.json": b'{"routing":{'},
    "a null document after the routing file": {"05_routing.json": routing(), "10_x.json": b"null"},
    "a false document after the routing file": {"05_routing.json": routing(), "10_x.json": b"false"},
    "a list document after the routing file": {"05_routing.json": routing(), "10_x.json": b'[{"routing":{}}]'},
    "an empty routing object is a routing object": {"05_routing.json": b'{"routing":{}}'},
    "duplicate routing keys: the last one counts": {"05_routing.json": b'{"routing":[],"routing":{}}'},
    "duplicate routing keys: the last one is not an object": {"05_routing.json": b'{"routing":{},"routing":[]}'},
    "hidden files are not read": {"05_routing.json": routing(), ".99_routing.json": routing()},
    "other extensions are not read": {"05_routing.json": routing(), "99_routing.json.bak": routing()},
    "a directory named like a config is not read": {"05_routing.json": routing(), "99.json": None},
    "a symlink to a file is read": {
        "05_routing.json": routing(),
        "real.txt": routing(),
        "99_link.json": ("link", "real.txt"),
    },
    "a symlink to a directory is not read": {"05_routing.json": routing(), "d": None, "99_link.json": ("link", "d")},
    "a broken symlink is not read": {"05_routing.json": routing(), "99_link.json": ("link", "nowhere")},
    "comments and BOM": {"05_routing.json": b'\xef\xbb\xbf// xkeen\n{"routing": /* r */ {"rules":[]}} // end\n'},
    "bytewise order of names": {"05_b.json": routing(), "05_ä.json": routing(), "05_B.json": routing()},
    "uppercase sorts before lowercase": {"b.json": routing(), "B.json": routing()},
    "underscore sorts before lowercase": {"a.json": routing(), "_a.json": routing()},
}


class RoutingFileTests(TempDirCase):
    def shell_routing(self, root, awk):
        work = self.make_dir()
        completed = run_function(
            "find_xray_routing_file",
            defs=ROUTING_DEFS,
            variables={"XRAY_CONFIG_DIR": root, "WORK_TMP_DIR": work},
            awk=awk,
        )
        if completed.returncode != 0:
            self.assertEqual(completed.stdout, "")
            return None
        self.assertTrue(completed.stdout.endswith("\n"), completed.stdout)
        prefix = root + "/"
        self.assertTrue(completed.stdout.startswith(prefix), completed.stdout)
        return completed.stdout[len(prefix) : -1]

    @needs_jq
    def test_routing_file_matches_find_xray_routing_file(self):
        for name, files in ROUTING_SCENARIOS.items():
            root = self.make_dir(files)
            found = xrayconf.routing_file(root)
            for awk in AWKS:
                with self.subTest(case=name, awk=awk):
                    self.assertEqual(None if found is None else found.name, self.shell_routing(root, awk))

    def test_routing_file_is_the_last_object_routing(self):
        root = self.make_dir(
            {
                "05_routing.json": routing(),
                "07_routing.json": routing(),
                "08_array.json": b'{"routing":[]}',
                "09_broken.json": b"{",
                "10_null.json": b"null",
                ".11_hidden.json": routing(),
            }
        )
        self.assertEqual(xrayconf.routing_file(root), Path(root) / "07_routing.json")

    def test_routing_file_is_none_without_a_routing_object(self):
        self.assertIsNone(xrayconf.routing_file(self.make_dir()))
        self.assertIsNone(xrayconf.routing_file(self.make_dir({"a.json": b'{"routing":1}'})))
        self.assertIsNone(xrayconf.routing_file(os.path.join(self.make_dir(), "missing")))

    @needs_jq
    def test_routing_file_of_the_real_router_tree(self):
        found = xrayconf.routing_file(str(FIXTURE_CONFIGS))
        self.assertEqual(found, FIXTURE_CONFIGS / "05_routing.json")
        for awk in AWKS:
            with self.subTest(awk=awk):
                self.assertEqual(self.shell_routing(str(FIXTURE_CONFIGS), awk), "05_routing.json")

    @needs_jq
    def test_a_file_with_several_documents_is_skipped_where_the_shell_reads_the_last_one(self):
        # B7: jq -e looks at the last document, load_strict accepts exactly one.
        files = {"05_routing.json": routing(), "10_two.json": b'{"x":1}\n{"routing":{}}\n'}
        root = self.make_dir(files)
        self.assertEqual(xrayconf.routing_file(root).name, "05_routing.json")
        for awk in AWKS:
            with self.subTest(awk=awk):
                self.assertEqual(self.shell_routing(root, awk), "10_two.json")


# -------- jq helpers --------
SCALARS_AND_CONTAINERS = [
    "null",
    "true",
    "false",
    '""',
    '"abc"',
    '"é😀"',
    '"a\\nb"',
    "0",
    "-3",
    "2.5",
    "-2.5",
    "255.0",
    "1e3",
    "-0",
    "[]",
    "[1,2,3]",
    "[[]]",
    '[null,false,"x",{"a":1}]',
    "{}",
    '{"a":1,"b":2}',
    '{"b":1,"a":2,"c":0,"a":9}',
]


class JqHelperTests(TempDirCase):
    @needs_jq
    def test_jq_iter_matches_jq_optional_iteration(self):
        for text in SCALARS_AND_CONTAINERS:
            with self.subTest(value=text):
                code, printed = run_jq("[.[]?]", text, "-c")
                self.assertEqual(code, 0)
                self.assertEqual(list(xrayconf.jq_iter(self.value_of(text))), json.loads(printed))

    def test_jq_iter_of_containers_and_scalars(self):
        self.assertEqual(list(xrayconf.jq_iter([1, "a"])), [1, "a"])
        self.assertEqual(list(xrayconf.jq_iter({"b": 1, "a": 2})), [1, 2])
        for scalar in (None, True, False, 0, 1.5, "text", ""):
            self.assertEqual(list(xrayconf.jq_iter(scalar)), [])

    @needs_jq
    def test_jq_length_matches_jq(self):
        for text in SCALARS_AND_CONTAINERS:
            value = self.value_of(text)
            with self.subTest(value=text):
                code, printed = run_jq("length", text)
                if code == 0:
                    self.assertEqual(float(xrayconf.jq_length(value)), float(printed))
                else:
                    with self.assertRaises(xrayconf.JqError):
                        xrayconf.jq_length(value)

    def test_jq_length_of_each_kind(self):
        self.assertEqual(xrayconf.jq_length(None), 0)
        self.assertEqual(xrayconf.jq_length("é😀a"), 3)
        self.assertEqual(xrayconf.jq_length(-4), 4)
        self.assertEqual(xrayconf.jq_length(-2.5), 2.5)
        self.assertEqual(xrayconf.jq_length([1, 2]), 2)
        self.assertEqual(xrayconf.jq_length({"a": 1}), 1)
        self.assertEqual(xrayconf.jq_length({}), 0)

    @needs_jq
    def test_jq_length_of_a_boolean_is_an_error(self):
        for text, value in (("true", True), ("false", False)):
            with self.subTest(value=text):
                self.assertNotEqual(run_jq("length", text)[0], 0)
                with self.assertRaises(xrayconf.JqError):
                    xrayconf.jq_length(value)

    def test_jq_length_of_a_boolean_names_the_value(self):
        with self.assertRaisesRegex(xrayconf.JqError, r"boolean \(true\) has no length"):
            xrayconf.jq_length(True)
        with self.assertRaisesRegex(xrayconf.JqError, r"boolean \(false\) has no length"):
            xrayconf.jq_length(False)

    def test_jq_error_is_an_exception_of_its_own(self):
        self.assertTrue(issubclass(xrayconf.JqError, Exception))
        self.assertFalse(issubclass(xrayconf.JqError, (KeyError, TypeError, AttributeError)))


RAW_CORPUS = [
    '"abc"',
    '""',
    '"é😀"',
    '"a\\nb"',
    '"q\\"q"',
    '"b\\\\s"',
    '"\\u007f"',
    '"\\u0001"',
    '" padded "',
    "true",
    "false",
    "null",
    "0",
    "-1",
    "255",
    "4294967295",
    "123456789012345678901234567890",
    "[]",
    "{}",
    "[1,2]",
    '{"a":1}',
    '{"k\\u007f":["\\u007f","é😀","a\\u0001b","</x>"],"e":[],"o":{},"n":[1.0,1e3,"s\\n"]}',
    '[[[]],{"a":{"b":[null,true]}}]',
    '{"":""}',
]
# jq >= 1.7 prints a number the way it was written (decNumber's scientific string): jq 1.7 in the test image,
# 1.8.1 on the router (checked with libjq 1.8 for these literals).
LITERAL_TEXTS = {
    "255.0": "255.0",
    "-5.0": "-5.0",
    "1.5": "1.5",
    "1e3": "1E+3",
    "1E3": "1E+3",
    "1e+3": "1E+3",
    "1.5E+2": "1.5E+2",
    "100e-2": "1.00",
    "0.10": "0.10",
    "0.0": "0.0",
    "-0": "-0",
    "3.0e0": "3.0",
    "0e5": "0E+5",
    "0.0e-3": "0.0000",
    "1.0E-7": "1.0E-7",
    "0.0000001": "1E-7",
    "0.000001": "0.000001",
    "123456789.123456789e5": "12345678912345.6789",
    "12345678901234567890.5": "12345678901234567890.5",
    "1e400": "1E+400",
    "-1e400": "-1E+400",
    "1e-400": "1E-400",
    "1e999999999": "1E+999999999",
    "1e1000000000": DBL_MAX_TEXT,
    "-1e1234567890": "-" + DBL_MAX_TEXT,
    "9007199254740993": "9007199254740993",
}
GENERATED_LITERALS = [
    f"{sign}{coefficient}{exponent}"
    for sign in ("", "-")
    for coefficient in ("1", "10", "100", "15", "1.5", "0.5", "123.456", "0.001", "1000", "1.00", "9.99")
    for exponent in ("", "e0", "e1", "e-1", "e5", "e-5", "E+3", "e-8", "e20", "e-20", "e9", "E-9")
]
# Bare Python floats (not read from a file) are printed like a jq double: 255.0 -> 255.
DOUBLES = [
    "255.0",
    "1.5",
    "-2.5",
    "0.1",
    "0.25",
    "1e15",
    "1e16",
    "1e17",
    "1e20",
    "123456789012345680.0",
    "1e-5",
    "0.0001",
    "0.00001234",
    "5e-324",
    "1.7976931348623157e308",
    "0.30000000000000004",
    "4294967296.0",
    "-1000000.0",
]
# Inputs on which jq_raw differs from jq on purpose: (the literal, jq's text, the port's text).
RAW_DIVERGENCES = {
    "1e-1234567890": ("0E-1147483646", "1E-1234567890"),
}


class JqRawTests(TempDirCase):
    @needs_jq
    def test_jq_raw_formatting_and_length(self):
        for text in RAW_CORPUS:
            value = self.value_of(text)
            with self.subTest(value=text):
                code, printed = run_jq(".", text, "-r")
                self.assertEqual(code, 0)
                self.assertEqual(xrayconf.jq_raw(value) + "\n", printed)
                code, printed = run_jq("length", text)
                if code == 0:
                    self.assertEqual(float(xrayconf.jq_length(value)), float(printed))
                else:
                    with self.assertRaises(xrayconf.JqError):
                        xrayconf.jq_length(value)

    @needs_literal_jq
    def test_jq_raw_keeps_number_literals_like_jq(self):
        for literal in [*LITERAL_TEXTS, *GENERATED_LITERALS]:
            with self.subTest(literal=literal):
                code, printed = run_jq(".", literal, "-r")
                self.assertEqual(code, 0)
                self.assertEqual(xrayconf.jq_raw(self.value_of(literal)) + "\n", printed)

    @needs_literal_jq
    def test_jq_raw_keeps_number_literals_inside_containers(self):
        text = "[" + ",".join(LITERAL_TEXTS) + "]"
        code, printed = run_jq(".", text, "-r")
        self.assertEqual(code, 0)
        self.assertEqual(xrayconf.jq_raw(self.value_of(text)) + "\n", printed)
        text = "{" + ",".join(f'"k{index}":{literal}' for index, literal in enumerate(LITERAL_TEXTS)) + "}"
        code, printed = run_jq(".", text, "-r")
        self.assertEqual(code, 0)
        self.assertEqual(xrayconf.jq_raw(self.value_of(text)) + "\n", printed)

    def test_jq_raw_of_number_literals_is_pinned(self):
        # The same expectations without jq, from the jq 1.7 and libjq 1.8 output.
        for literal, expected in LITERAL_TEXTS.items():
            with self.subTest(literal=literal):
                self.assertEqual(xrayconf.jq_raw(self.value_of(literal)), expected)

    @needs_jq
    def test_jq_raw_of_computed_doubles_matches_jq(self):
        for literal in DOUBLES:
            with self.subTest(double=literal):
                code, printed = run_jq(". + 0", literal, "-r")
                self.assertEqual(code, 0)
                self.assertEqual(xrayconf.jq_raw(float(literal)) + "\n", printed)

    def test_jq_raw_of_values_that_were_not_read_from_a_file(self):
        self.assertEqual(xrayconf.jq_raw(255.0), "255")
        self.assertEqual(xrayconf.jq_raw(255), "255")
        self.assertEqual(xrayconf.jq_raw(-0.0), "-0")
        self.assertEqual(xrayconf.jq_raw(math.inf), DBL_MAX_TEXT)
        self.assertEqual(xrayconf.jq_raw(-math.inf), "-" + DBL_MAX_TEXT)
        self.assertEqual(xrayconf.jq_raw(math.nan), "null")
        self.assertEqual(xrayconf.jq_raw(True), "true")
        self.assertEqual(xrayconf.jq_raw(False), "false")
        self.assertEqual(xrayconf.jq_raw(None), "null")
        self.assertEqual(xrayconf.jq_raw("a\nb"), "a\nb")
        self.assertEqual(xrayconf.jq_raw([]), "[]")
        self.assertEqual(xrayconf.jq_raw({}), "{}")

    def test_jq_raw_of_a_string_has_no_quotes_but_a_nested_string_has(self):
        self.assertEqual(xrayconf.jq_raw("x"), "x")
        self.assertEqual(xrayconf.jq_raw(["x"]), '[\n  "x"\n]')
        self.assertEqual(xrayconf.jq_raw({"k": "v"}), '{\n  "k": "v"\n}')

    def test_jq_raw_escapes_the_delete_character_like_jq(self):
        self.assertEqual(xrayconf.jq_raw(["\x7f"]), '[\n  "\\u007f"\n]')
        self.assertEqual(xrayconf.jq_raw({"\x7f": 1}), '{\n  "\\u007f": 1\n}')

    def test_jq_raw_prints_non_ascii_text_as_it_is(self):
        self.assertEqual(xrayconf.jq_raw(["é😀"]), '[\n  "é😀"\n]')

    @needs_jq
    def test_the_documented_raw_divergences_are_what_jq_and_the_port_print(self):
        for literal, (jq_text, port_text) in RAW_DIVERGENCES.items():
            with self.subTest(literal=literal):
                self.assertEqual(run_jq(".", literal, "-r"), (0, jq_text + "\n"))
                self.assertEqual(xrayconf.jq_raw(self.value_of(literal)), port_text)

    @needs_jq
    def test_the_length_of_an_out_of_range_number_is_infinite_where_jq_gives_its_largest_double(self):
        code, printed = run_jq("length", "1e400", "-r")
        self.assertEqual((code, printed), (0, DBL_MAX_TEXT + "\n"))
        self.assertEqual(xrayconf.jq_length(self.value_of("1e400")), math.inf)
        self.assertGreater(xrayconf.jq_length(self.value_of("1e400")), 0)


# -------- structure --------
ALLOWED_IMPORTS = {"json", "os", "pathlib", "kdn.common.jsonc", "kdn.common"}
FORBIDDEN_AT_IMPORT = (
    "dataclasses",
    "inspect",
    "typing",
    "tempfile",
    "shutil",
    "argparse",
    "logging",
    "enum",
    "subprocess",
    "decimal",
)


class ModuleShapeTests(unittest.TestCase):
    def test_the_module_depends_on_json_os_pathlib_and_kdn_common_only(self):
        source = (ROOT / "tools" / "router" / "kdn" / "engine" / "xrayconf.py").read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported - ALLOWED_IMPORTS, set())

    def test_importing_the_module_stays_within_the_import_budget(self):
        # json brings in re and so enum; the module itself must add nothing to what json, os and pathlib load.
        code = (
            "import sys, json, os, pathlib; sys.path.insert(0, sys.argv[1]); watched = set(sys.argv[2:]); "
            "before = watched & set(sys.modules); import kdn.engine.xrayconf; "
            "print(sorted((watched & set(sys.modules)) - before))"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code, str(ROOT / "tools" / "router"), *FORBIDDEN_AT_IMPORT],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(completed.stdout.strip(), "[]")

    def test_the_module_does_not_run_jq(self):
        source = (ROOT / "tools" / "router" / "kdn" / "engine" / "xrayconf.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("system", source.replace("filesystem", ""))


class PredicateTests(TempDirCase):
    @needs_jq
    def test_route_predicates_match_the_actual_jq_expressions(self):
        queries = re.findall(r"jq -e '(any\(\.routing\.rules\[\]\?;[^']*)'", engine_shell.script_text())
        self.assertEqual(len(queries), 3)
        functions = [xrayconf.discord_tcp_direct, xrayconf.discord_voice_direct, xrayconf.youtube_direct]
        documents = [None, False, [], 3, "bad", {}, {"routing": None}, {"routing": "bad"}]
        rules = []
        for tag in ("discord-direct", "youtube-direct", "proxy", None, ["discord-direct"]):
            for domain in (None, False, True, 0, [], ["discord.com"], "str", {"x": "a"}):
                for network in (None, "tcp", "udp"):
                    rules.append({"outboundTag": tag, "domain": domain, "network": network})
        documents += [{"routing": {"rules": [rule]}} for rule in rules]
        for good in ({"outboundTag": "discord-direct", "domain": ["discord.com"]},
                     {"outboundTag": "discord-direct", "network": "udp"}, {"outboundTag": "youtube-direct"}):
            for bad in (None, 7, "bad", True, {"outboundTag": "discord-direct", "domain": True}):
                documents += [{"routing": {"rules": [good, bad]}}, {"routing": {"rules": [bad, good]}}]
        documents += [{"routing": {"rules": value}} for value in ({"a": rules[3]}, "bad", 1, None)]
        for document in documents:
            for function, query in zip(functions, queries, strict=True):
                with self.subTest(function=function.__name__, document=document):
                    code, _out = run_jq(query, json.dumps(document), "-e")
                    self.assertEqual(function(document), code == 0)

    @needs_jq
    def test_telegram_outbound_matches_the_actual_jq_query(self):
        query = re.search(r"jq -r '(\[\.routing\.rules\[\]\? \| select\(\(\(\.ruleTag\?[^']*)'", engine_shell.script_text()).group(1)
        cases = [None, [], {}, {"routing": "bad"}]
        for tag in (None, 3, False, {}, [], "kdn-telegram", "kdn-telegram-voice", "other"):
            for outbound in (None, False, 7, {}, "telegram-direct", "telegram-ws", "proxy"):
                rule = {"ruleTag": tag, "outboundTag": outbound}
                cases.append({"routing": {"rules": [None, 1, "bad", rule]}})
        cases.append({"routing": {"rules": [{"ruleTag": "kdn-telegram"}, {"ruleTag": "kdn-telegram2", "outboundTag": "telegram-ws"}]}})
        for document in cases:
            with self.subTest(document=document):
                code, output = run_jq(query, json.dumps(document), "-r")
                self.assertEqual(xrayconf.telegram_outbound(document), output.rstrip("\n") if code == 0 else "")


class OutboundTests(TempDirCase):
    def shell(self, name, root, *args, awk="system"):
        environment = dict(os.environ)
        shell = ("dash",)
        if awk == "busybox":
            farm = self.make_dir()
            for applet in ("awk", "sed", "grep", "tr"):
                os.symlink(shutil.which("busybox"), os.path.join(farm, applet))
            environment["PATH"] = farm + os.pathsep + environment["PATH"]
            shell = ("busybox", "sh")
        return run_function(name, *args, defs=[*ROUTING_DEFS, "find_xray_routing_file"],
            variables={"XRAY_CONFIG_DIR": root, "WORK_TMP_DIR": self.make_dir()}, env=environment, shell=shell, awk=awk)

    @needs_literal_jq
    def test_freedom_marks_match_the_shell_including_literal_format_and_errors(self):
        values = ["255", '"255"', "255.0", "1e3", "true", "false", "null", "{}", '""', '"a\\n\\n"']
        for text in values:
            root = self.make_dir({"01.json": b'{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":5}}}]}',
                                  "02.json": ('{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":' + text + '}}}]}').encode()})
            for awk in AWKS:
                with self.subTest(mark=text, awk=awk):
                    ref = self.shell("find_existing_xray_freedom_mark", root, awk=awk)
                    self.assertEqual(ref.returncode, 0, ref.stderr)
                    self.assertEqual(xrayconf.freedom_mark(root), ref.stdout.rstrip("\n"))
        for rows in ([1, {"protocol": "freedom", "streamSettings": {"sockopt": {"mark": 9}}}],
                     [{"protocol": "freedom", "streamSettings": 3}],
                     [{"protocol": "freedom", "streamSettings": {"sockopt": {"mark": 9}}}, 1]):
            root = self.make_dir({"01.json": json.dumps({"outbounds": rows}).encode()})
            self.assertEqual(xrayconf.freedom_mark(root), self.shell("find_existing_xray_freedom_mark", root).stdout.rstrip("\n"))

    @needs_jq
    def test_tag_predicates_and_discovery_match_original_functions(self):
        scenarios = [[], [{"tag": "a", "protocol": "vless"}], [{"tag": "a", "protocol": "freedom"}],
                     [{"tag": "a", "protocol": "vless"}, {"tag": "b", "protocol": "trojan"}],
                     [None, 1, {"tag": "a", "protocol": "vless"}],
                     [{"tag": "a", "protocol": "vless"}, 1], [{"tag": "a"}]]
        route_sets = [[], [{"outboundTag": "a"}], [{"outboundTag": "a"}, {"outboundTag": "b"}],
                      [{"outboundTag": "missing", "domain": ["ext:YouTube"]}],
                      [{"outboundTag": "direct", "domain": ["youtube.com"]}],
                      [1, {"outboundTag": "a", "domain": {"name": "YOUTUBE"}}],
                      [{"outboundTag": "a", "domain": [None, 1, "www.YOUTUBE.com"]}]]
        for outbounds in scenarios:
            for routes in route_sets:
                root = self.make_dir({"01.json": json.dumps({"outbounds": outbounds}).encode(),
                                      "05.json": json.dumps({"routing": {"rules": routes}}).encode()})
                for awk in AWKS:
                    with self.subTest(outbounds=outbounds, rules=routes, awk=awk):
                        for name, function in (("xray_outbound_tag_exists", xrayconf.outbound_tag_exists),
                                               ("xray_proxy_outbound_tag_exists", xrayconf.proxy_outbound_tag_exists)):
                            for tag in ("a", "missing"):
                                ref = self.shell(name, root, tag, awk=awk)
                                self.assertEqual(function(root, tag), ref.returncode == 0)
                        ref = self.shell("discover_xray_proxy_outbound", root, awk=awk)
                        self.assertEqual(xrayconf.discover_proxy_outbound(root), ref.stdout.rstrip("\n") if ref.returncode == 0 else None)
        root = self.make_dir({"01.json": b'{"outbounds":[{"tag":"only","protocol":"vless"}]}'})
        self.assertIsNone(xrayconf.discover_proxy_outbound(root))


if __name__ == "__main__":
    unittest.main()

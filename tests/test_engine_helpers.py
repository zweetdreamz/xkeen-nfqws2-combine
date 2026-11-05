"""Tests of tests/engine_shell.py: the extractors of functions and assignments from apply-discord-nfqws2.sh
and the sh runners that the engine tests share.

The scanner has to follow heredocs, quotes that span lines, backslash escapes, comments and ``$(...)`` the way
a POSIX shell does, because the script holds closing braces in the first column inside heredocs and inside
multi-line quoted strings. Every function of the real script must extract to text that dash and busybox ash
parse; the synthetic sources pin each construct on its own.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import engine_shell
from engine_shell import (
    extract_assignment,
    extract_function,
    function_names,
    function_spans,
    run_function,
    run_sh,
    script_text,
)


SCRIPT = engine_shell.SCRIPT
SCRIPT_TEXT = script_text()
SHELLS = {
    "dash": ("dash",),
    "busybox ash": ("busybox", "sh"),
}
HAS_BUSYBOX = shutil.which("busybox") is not None


def installed_shells():
    return {label: argv for label, argv in SHELLS.items() if shutil.which(argv[0])}


class ShellTestCase(unittest.TestCase):
    def assert_parses(self, text, label=""):
        """Every installed shell accepts the text under ``sh -n`` (the syntax check only)."""
        shells = installed_shells()
        self.assertTrue(shells, "neither dash nor busybox is installed")
        for shell_label, argv in shells.items():
            with self.subTest(shell=shell_label, what=label):
                result = run_sh(text, shell=(*argv, "-n"))
                self.assertEqual((result.returncode, result.stderr), (0, ""))


class ExtractFunctionOnTheScriptTests(ShellTestCase):
    def test_extract_function_handles_the_heredoc_with_a_closing_brace(self):
        text = extract_function("builtin_startup_args")
        self.assertTrue(text.startswith("builtin_startup_args() {\n  cat <<'EOF'\n_startup_args() {\n"), text[:80])
        # The heredoc ends with its own "}" in the first column, then EOF, and only then the function's "}".
        self.assertTrue(text.endswith('  echo "$args"\n}\nEOF\n}'), text[-60:])
        self.assertEqual(text.count("\n}\n"), 1)
        self.assert_parses(text, "builtin_startup_args")
        # It is the whole function: running it prints the heredoc, which is a valid function in turn.
        result = run_sh(f"{text}\nbuiltin_startup_args\n")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("_startup_args() {\n  local fastpath_workaround=\n"))
        self.assertTrue(result.stdout.endswith('  echo "$args"\n}\n'))
        self.assert_parses(result.stdout, "the heredoc body")

    def test_extract_function_handles_multiline_quoted_scripts(self):
        text = extract_function("compose_nfqws_profiles")
        self.assertTrue(text.startswith("compose_nfqws_profiles() {\n  compose_conf=\"$1\"\n"), text[:80])
        self.assertTrue(text.endswith('  [ -s "$compose_tokens" ]\n}'), text[-60:])
        # The sh -c '...' script and the awk program after it belong to the function.
        self.assertIn("  env -i PATH=\"$PATH\" sh -c '\n    set -f\n", text)
        self.assertIn("    _startup_args\n  ' compose \"$compose_conf\"", text)
        self.assertIn("  awk -v meta=\"$compose_meta\" '\n", text)
        # The sed range on the "_startup_args() {" line is inside the function, not a function start.
        self.assertIn("sed -n '/^_startup_args() {$/,/^}$/p'", text)
        self.assertEqual(len(re.findall(r"(?m)^\}", text)), 1)
        self.assert_parses(text, "compose_nfqws_profiles")

    def test_every_function_of_the_script_extracts_and_parses(self):
        names = function_names()
        self.assertEqual(len(names), len(set(names)), "a function is listed twice")
        # 151 functions today; 158 lines start with "name() {", but 7 of them sit inside heredocs.
        self.assertGreater(len(names), 100)
        shells = installed_shells()
        self.assertTrue(shells, "neither dash nor busybox is installed")
        definitions = []
        for name in names:
            text = extract_function(name)
            definitions.append(text)
            self.assertTrue(text.startswith(f"{name}() {{\n"), name)
            self.assertTrue(text.endswith("\n}"), name)
            for label, argv in shells.items():
                with self.subTest(function=name, shell=label):
                    result = run_sh(text, shell=(*argv, "-n"))
                    self.assertEqual((result.returncode, result.stderr), (0, ""))
        # Together they define every listed function in a shell that really runs the definitions (from a file:
        # the text of 150 functions is longer than one argument of exec may be).
        report = "\n".join(f"command -v {name} >/dev/null || echo missing:{name}" for name in names)
        with tempfile.TemporaryDirectory() as temp:
            definitions_file = Path(temp) / "definitions.sh"
            definitions_file.write_text("\n".join(definitions) + "\n", encoding="utf-8", errors="surrogateescape")
            for label, argv in shells.items():
                with self.subTest(shell=label, what="all definitions at once"):
                    result = run_sh(f'. "{definitions_file}"\n{report}', shell=argv)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_function_names_skip_definitions_inside_heredocs(self):
        names = function_names()
        # The heredoc of builtin_startup_args holds the init's "_startup_args() {", and the heredoc of
        # write_telegram_ws_init the six functions of the generated S99 init script, all in the first column.
        in_heredocs = {"_startup_args", "is_relay", "relay_pids", "running", "listening", "start", "stop"}
        in_file = set(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\) \{$", script_text()))
        self.assertEqual(in_file - set(names), in_heredocs)
        self.assertEqual(set(names) - in_file, set())
        self.assertIn("builtin_startup_args", names)
        self.assertIn("write_telegram_ws_init", names)
        for name in in_heredocs:
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_function(name)
        # Their text is part of the functions whose heredocs hold them.
        self.assertIn("\n_startup_args() {\n", extract_function("builtin_startup_args"))
        for name in ("is_relay", "relay_pids", "running", "listening", "start", "stop"):
            self.assertIn(f"\n{name}() {{\n", extract_function("write_telegram_ws_init"))

    def test_function_names_follow_the_file_order(self):
        names = function_names()
        positions = [SCRIPT_TEXT.index(f"\n{name}() {{\n") for name in names]
        self.assertEqual(positions, sorted(positions))

    def test_extract_function_of_an_unknown_name_raises_key_error(self):
        for name in ("no_such_function", "", "root_path ", "root"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_function(name)

    def test_extract_function_returns_the_text_as_written(self):
        text = extract_function("root_path")
        self.assertEqual(text, 'root_path() {\n  printf \'%s%s\\n\' "$TEST_ROOT" "$1"\n}')


class ExtractAssignmentOnTheScriptTests(ShellTestCase):
    def test_extract_assignment_reads_multiline_single_quoted_values(self):
        value = extract_assignment("NFQWS_PORT_AWK")
        self.assertTrue(value.startswith("\nfunction port_ranges(spec, lo, hi,"), value[:60])
        self.assertIn("\nfunction port_gaps(a, b, lo, hi, n,", value)
        # No outer quotes; the closing brace of the last function is the last line, then the newline before "'".
        self.assertTrue(value.endswith("  return out\n}\n"), value[-40:])
        self.assertFalse(value.startswith("'"))
        self.assertFalse(value.endswith("'"))
        # The value is the program that ports_same hands to awk: it runs.
        program = value + "\nBEGIN { print port_ranges(\"80,90:95\", lo, hi), lo[2], hi[2] }\n"
        result = run_sh('awk "$PROGRAM"', env={**os.environ, "PROGRAM": program})
        self.assertEqual((result.returncode, result.stdout), (0, "2 90 95\n"))

    def test_extract_assignment_accepts_unquoted_values(self):
        expected = re.search(r"(?m)^TELEGRAM_WS_PORT=(\S+)$", SCRIPT_TEXT).group(1)
        self.assertRegex(expected, r"^[0-9]+$")
        self.assertEqual(extract_assignment("TELEGRAM_WS_PORT"), expected)

    def test_extract_assignment_reads_script_version(self):
        expected = re.search(r'(?m)^SCRIPT_VERSION="([^"]*)"$', SCRIPT_TEXT).group(1)
        self.assertRegex(expected, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertEqual(extract_assignment("SCRIPT_VERSION"), expected)

    def test_extract_assignment_reads_double_quoted_values_as_written(self):
        self.assertEqual(extract_assignment("STATE_ROOT"), "$(root_path /opt/etc/keenetic-discord-nfqws2)")
        self.assertEqual(extract_assignment("SNAPSHOT_ROOT"), "$STATE_ROOT/snapshots")
        self.assertEqual(extract_assignment("MODE"), "help")

    def test_extract_assignment_agrees_with_a_regex_on_every_simple_single_line_value(self):
        simple = re.compile(
            r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\"'\s;&|()<>$`\\#]*))$"
        )
        spans = function_spans()
        checked = 0
        for found in simple.finditer(SCRIPT_TEXT):
            name = found.group(1)
            expected = next(group for group in found.groups()[1:] if group is not None)
            with self.subTest(name=name, line=SCRIPT_TEXT.count("\n", 0, found.start()) + 1):
                if any(start < found.start() < end for _, start, end in spans):
                    # A first-column line inside a function (a heredoc of the generated init script): no assignment.
                    with self.assertRaises(KeyError):
                        extract_assignment(name)
                    continue
                self.assertEqual(extract_assignment(name), expected)
                checked += 1
        self.assertGreater(checked, 60)

    def test_every_top_level_assignment_of_the_script_extracts(self):
        names = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=", SCRIPT_TEXT)
        extracted = 0
        for name in sorted(set(names)):
            with self.subTest(name=name):
                try:
                    value = extract_assignment(name)
                except KeyError:
                    continue
                extracted += 1
                self.assertIsInstance(value, str)
        self.assertGreater(extracted, 90)

    def test_extract_assignment_reads_a_nested_command_substitution(self):
        self.assertEqual(extract_assignment("SCRIPT_DIR"), '$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)')

    def test_extract_assignment_reads_a_multiline_value_with_inner_quotes(self):
        value = extract_assignment("DISCORD_UDP_BLOB_BASE_ARGS")
        self.assertEqual(
            value,
            'NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS\n'
            "                 --blob=discord_udp:@/opt/etc/nfqws2/blobs/discord_udp.bin\"",
        )

    def test_extract_assignment_ignores_text_inside_multiline_strings(self):
        # "NFQWS_ARGS_CUSTOM=" starts lines inside the quoted strings of patch_nfqws; it is no assignment.
        self.assertRegex(SCRIPT_TEXT, r"(?m)^NFQWS_ARGS_CUSTOM=")
        with self.assertRaises(KeyError):
            extract_assignment("NFQWS_ARGS_CUSTOM")

    def test_extract_assignment_of_an_unknown_name_raises_key_error(self):
        for name in ("NO_SUCH_VARIABLE", "", "SCRIPT_VERSIO", "SCRIPT_VERSION2"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_assignment(name)


class RunFunctionTests(ShellTestCase):
    def test_run_function_runs_a_function_with_variables(self):
        result = run_function("root_path", "/opt/x", variables={"TEST_ROOT": "/t/r"})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "/t/r/opt/x\n", ""))
        with tempfile.TemporaryDirectory() as temp:
            ports = Path(temp) / "port_proxying.lst"
            ports.write_bytes(b"80\n 443 \r\n# comment\n\n1000-2000\nnot-a-port\n")
            result = run_function("active_ports", str(ports))
            self.assertEqual((result.returncode, result.stderr), (0, ""))
            self.assertEqual(result.stdout.rstrip("\n"), "80,443,1000:2000")
            result = run_function("active_ports", str(Path(temp) / "missing.lst"))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_run_function_sets_variables_the_function_reads(self):
        program = extract_assignment("NFQWS_PORT_AWK")
        for left, right, expected in (("80,443", "443,80", 0), ("80:90", "80-85,86-90", 0), ("80", "443", 1)):
            with self.subTest(left=left, right=right):
                result = run_function("ports_same", left, right, variables={"NFQWS_PORT_AWK": program})
                self.assertEqual((result.returncode, result.stderr), (expected, ""))

    def test_run_function_quotes_arguments_and_variables(self):
        defs = ("show() { for shown in \"$@\"; do printf '[%s]' \"$shown\"; done; printf '<%s>' \"$VALUE\"; }",)
        arguments = ("two words", "it's", 'say "hi"', "$HOME `id`", "", "-n", "a\nb")
        result = run_function("show", *arguments, defs=defs, variables={"VALUE": "x'y $z\n\"q\""})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "[two words][it's][say \"hi\"][$HOME `id`][][-n][a\nb]<x'y $z\n\"q\">")

    def test_run_function_keeps_carriage_returns_byte_exact(self):
        defs = ("crs() { printf 'a\\r\\nb\\rc'; printf 'x\\r\\ny\\r' >&2; cat; }",)
        result = run_function("crs", defs=defs, stdin="in\r\nput\r")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "a\r\nb\rcin\r\nput\r", "x\r\ny\r"))
        with tempfile.TemporaryDirectory() as temp:
            ports = Path(temp) / "ports.lst"
            ports.write_bytes(b"80\r\n443\r\n")
            result = run_function("active_ports", str(ports))
            self.assertEqual(result.stdout.rstrip("\n"), "80,443")

    def test_run_function_returns_the_exit_status_and_both_streams(self):
        defs = ("fail() { echo out; echo err >&2; return 3; }",)
        result = run_function("fail", defs=defs)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "out\n", "err\n"))

    def test_run_function_defs_take_function_names_of_the_script_and_raw_text(self):
        defs = ("root_path", "probe() { root_path /x; echo \"$STUB\"; }", "STUB=raw-line")
        result = run_function("probe", defs=defs, variables={"TEST_ROOT": "/r"})
        self.assertEqual((result.returncode, result.stdout), (0, "/r/x\nraw-line\n"))

    def test_run_function_of_an_unknown_function_raises_key_error(self):
        with self.assertRaises(KeyError):
            run_function("no_such_function")
        with self.assertRaises(KeyError):
            run_function("probe", defs=("no_such_function",))

    def test_run_function_rejects_bad_variable_names_and_awk_values(self):
        with self.assertRaises(ValueError):
            run_function("root_path", variables={"BAD NAME": "x"})
        with self.assertRaises(ValueError):
            run_function("root_path", variables={"A;B": "x"})
        with self.assertRaises(ValueError):
            run_function("root_path", awk="gawk")

    def test_run_function_passes_env_and_shell(self):
        defs = ("show() { printf '%s|%s' \"$FROM_ENV\" \"$0\"; }",)
        result = run_function("show", defs=defs, env={**os.environ, "FROM_ENV": "set"})
        self.assertEqual((result.returncode, result.stdout.split("|")[0]), (0, "set"))
        result = run_function("show", defs=defs, env={"PATH": os.environ["PATH"]})
        self.assertEqual((result.returncode, result.stdout.split("|")[0]), (0, ""))
        for label, argv in installed_shells().items():
            with self.subTest(shell=label):
                result = run_function("root_path", "/a", shell=argv, variables={"TEST_ROOT": ""})
                self.assertEqual((result.returncode, result.stdout), (0, "/a\n"))

    @unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
    def test_run_function_with_busybox_awk_uses_the_applet(self):
        busybox = os.path.realpath(shutil.which("busybox"))
        defs = (
            "which_awk() { command -v awk; readlink -f \"$(command -v awk)\"; }",
            "run_awk() { awk 'BEGIN { print \"applet ok\" }'; }",
        )
        result = run_function("which_awk", defs=defs, awk="busybox")
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        found, resolved = result.stdout.splitlines()
        self.assertEqual(os.path.basename(found), "awk")
        self.assertEqual(resolved, busybox)
        # The directory was a temporary one and is gone after the call.
        self.assertFalse(os.path.exists(os.path.dirname(found)))
        result = run_function("run_awk", defs=defs, awk="busybox")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "applet ok\n", ""))
        # The default is the awk of the machine (mawk in the test image), untouched by the applet directory.
        machine_awk = os.path.realpath(shutil.which("awk"))
        for kwargs in ({}, {"awk": "system"}):
            with self.subTest(kwargs=kwargs):
                result = run_function("which_awk", defs=defs, **kwargs)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.splitlines()[-1], machine_awk)
                self.assertNotIn("engine-awk-", result.stdout)

    @unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
    def test_run_function_with_busybox_awk_keeps_the_rest_of_the_path(self):
        defs = ("probe() { command -v sed; }",)
        plain = run_function("probe", defs=defs)
        with_applet = run_function("probe", defs=defs, awk="busybox")
        self.assertEqual((with_applet.returncode, with_applet.stdout), (plain.returncode, plain.stdout))
        env = {"PATH": "/nonexistent-dir:/usr/bin:/bin"}
        result = run_function("probe", defs=defs, awk="busybox", env=env)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(os.path.dirname(result.stdout.strip()) in ("/usr/bin", "/bin"), True)

    @unittest.skipUnless(HAS_BUSYBOX, "busybox is not installed")
    def test_ports_same_agrees_between_the_machine_awk_and_the_busybox_applet(self):
        program = extract_assignment("NFQWS_PORT_AWK")
        cases = (("80,443", "443,80"), ("80:90", "80-85,86-90"), ("80", "443"), ("1-5", "1-4"), ("a", "a"), ("", "1"))
        for left, right in cases:
            outcomes = {}
            for awk in ("system", "busybox"):
                result = run_function("ports_same", left, right, variables={"NFQWS_PORT_AWK": program}, awk=awk)
                outcomes[awk] = (result.returncode, result.stdout, result.stderr)
            with self.subTest(left=left, right=right):
                self.assertEqual(outcomes["system"], outcomes["busybox"])


class RunShTests(unittest.TestCase):
    def test_run_sh_returns_a_completed_process_in_text_mode(self):
        result = run_sh("echo out; echo err >&2; exit 4")
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (4, "out\n", "err\n"))

    def test_run_sh_keeps_undecodable_bytes(self):
        result = run_sh("printf 'a\\377b'; printf '\\300' >&2")
        self.assertEqual((result.stdout, result.stderr), ("a\udcffb", "\udcc0"))
        self.assertEqual(result.stdout.encode("utf-8", errors="surrogateescape"), b"a\xffb")
        result = run_sh("cat", stdin="x\udcffy\n")
        self.assertEqual(result.stdout, "x\udcffy\n")

    def test_run_sh_keeps_carriage_returns_byte_exact(self):
        result = run_sh("printf 'a\\r\\nb\\rc'; printf 'x\\r\\ny\\rz\\r' >&2")
        self.assertEqual((result.stdout, result.stderr), ("a\r\nb\rc", "x\r\ny\rz\r"))
        result = run_sh("printf '\\r\\n\\n\\r\\r\\n'")
        self.assertEqual(result.stdout, "\r\n\n\r\r\n")

    def test_run_sh_hands_stdin_over_byte_exact(self):
        given = "a\r\nb\rc\n\r\n\udcff"
        result = run_sh("cat", stdin=given)
        self.assertEqual(result.stdout, given)
        self.assertEqual(run_sh("od -An -c | tr -s ' '", stdin="a\r\nb").stdout, " a \\r \\n b\n")

    def test_run_sh_stdin_defaults_to_nothing(self):
        result = run_sh("cat; echo done")
        self.assertEqual((result.returncode, result.stdout), (0, "done\n"))
        result = run_sh("cat", stdin="given")
        self.assertEqual(result.stdout, "given")

    def test_run_sh_env_is_the_whole_environment(self):
        result = run_sh('echo "${ONLY:-unset}|${HOME:-nohome}"', env={"PATH": os.environ["PATH"], "ONLY": "yes"})
        self.assertEqual(result.stdout, "yes|nohome\n")

    def test_run_sh_takes_the_shell_as_a_tuple(self):
        result = run_sh("echo $((1 + 1))", shell=("sh", "-e"))
        self.assertEqual(result.stdout, "2\n")
        result = run_sh("false; echo reached", shell=("sh", "-e"))
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        result = run_sh("false; echo reached")
        self.assertEqual(result.stdout, "reached\n")

    def test_run_sh_times_out(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_sh("sleep 5", timeout=0.2)


def function_text(name, body="  :", close="}"):
    return f"{name}() {{\n{body}\n{close}\n"


class ScannerTests(unittest.TestCase):
    """The scanner on synthetic sources: one construct per test, with a function after it that must stay intact."""

    def assert_extracts(self, body, name="subject", close="}"):
        source = function_text("before") + function_text(name, body, close) + function_text("after", "  echo after")
        text = extract_function(name, source)
        self.assertEqual(text, function_text(name, body, close).rstrip("\n"), body)
        self.assertEqual(function_names(source), ["before", name, "after"], body)
        self.assertEqual(extract_function("after", source), function_text("after", "  echo after").rstrip("\n"), body)
        # The synthetic source is real shell: every installed shell parses it, so the test pins a true construct.
        for label, argv in installed_shells().items():
            result = run_sh(source, shell=(*argv, "-n"))
            self.assertEqual((result.returncode, result.stderr), (0, ""), f"{label}: {body!r}")
        return source

    def test_a_plain_function_ends_at_the_first_closing_brace_in_the_first_column(self):
        source = "x=1\nf() {\n  if true; then\n    echo hi\n  fi\n}\ng() {\n  :\n}\n"
        self.assertEqual(extract_function("f", source), "f() {\n  if true; then\n    echo hi\n  fi\n}")
        self.assertEqual(extract_function("g", source), "g() {\n  :\n}")
        # An indented brace does not end the function.
        self.assertEqual(
            extract_function("f", "f() {\n  {\n    :\n  }\n}\n"), "f() {\n  {\n    :\n  }\n}"
        )

    def test_the_last_function_may_lack_the_final_newline(self):
        self.assertEqual(extract_function("f", "f() {\n  :\n}"), "f() {\n  :\n}")

    def test_heredocs_hide_a_closing_brace_in_every_form(self):
        forms = {
            "plain": "  cat <<EOF\n}\nEOF",
            "single quoted": "  cat <<'EOF'\n}\nEOF",
            "double quoted": '  cat <<"EOF"\n}\nEOF',
            "backslash": "  cat <<\\EOF\n}\nEOF",
            "space before the word": "  cat << EOF\n}\nEOF",
            "other word": "  cat <<END_OF_DATA\n}\nEND_OF_DATA",
            "file descriptor": "  cat 3<<EOF\n}\nEOF",
            "redirected output": '  cat > "$file" <<EOF\n}\nEOF',
            "followed by commands": "  cat <<EOF; echo done\n}\nEOF",
            "in a pipeline": "  cat <<EOF | sed 's/x/y/'\n}\nEOF",
            "empty body": "  cat <<EOF\nEOF",
            "quoted part of the word": "  cat <<E'O'F\n}\nEOF",
        }
        for label, body in forms.items():
            with self.subTest(form=label):
                self.assert_extracts(body)

    def test_a_dash_heredoc_ends_at_a_terminator_indented_with_tabs(self):
        self.assert_extracts("  cat <<-EOF\n\t}\n\tbody\n\tEOF")
        self.assert_extracts("  cat <<-EOF\n}\n\t\tEOF")
        self.assert_extracts("  cat <<-'EOF'\n}\nEOF")
        self.assert_extracts("  cat <<- EOF\n}\n\tEOF")

    def test_only_a_line_equal_to_the_word_ends_a_heredoc(self):
        # Spaces before the word, text after it, a longer word and a lowercase word are body lines.
        self.assert_extracts("  cat <<EOF\n  EOF\n}\nEOF x\n}\nEOFF\n}\neof\n}\nEOF")
        # A tab does not strip with <<EOF, so the tab-indented line is a body line.
        self.assert_extracts("  cat <<EOF\n\tEOF\n}\nEOF")
        # With <<-EOF spaces are not stripped.
        self.assert_extracts("  cat <<-EOF\n  EOF\n}\n\tEOF")

    def test_two_heredocs_on_one_line_are_read_in_order(self):
        self.assert_extracts("  cat <<A <<B\n}\nA\n}\nB")
        self.assert_extracts("  { cat <<A; cat <<-B; } | wc\n}\nA\n}\n\tB")

    def test_heredoc_inside_a_command_substitution(self):
        self.assert_extracts('  x="$(cat <<EOF\n}\nEOF\n)"')
        self.assert_extracts("  x=$(cat <<'EOF'\n'\n}\nEOF\n  )")

    def test_heredoc_body_may_hold_quotes_and_comments_that_do_not_count(self):
        self.assert_extracts("  cat <<'EOF'\nit's \"half\n# not a comment '\n`\n$(\n}\nEOF")
        self.assert_extracts("  cat <<EOF\nit's \\\n}\nEOF")

    def test_a_shift_in_arithmetic_is_not_a_heredoc(self):
        self.assert_extracts("  x=$((1 << 2))\n  y=$(( x<<2 ))\n  echo $x $y")
        self.assert_extracts('  x=$(( (1 << 2) + 1 ))\n  echo "$((x << 1))"')

    def test_single_quotes_span_lines(self):
        self.assert_extracts("  echo 'first\n}\nlast'")
        self.assert_extracts("  echo 'a\n}\n' 'b\n}\n'")
        self.assert_extracts("  awk 'BEGIN {\n  x = 1\n}\nEND {\n}\n'")
        self.assert_extracts("  echo '\"' '#' ';' '\\'\n  :")

    def test_double_quotes_span_lines(self):
        self.assert_extracts('  echo "first\n}\nlast"')
        self.assert_extracts('  echo "a \\" \n}\n still quoted" "\n}\n"')
        self.assert_extracts("  echo \"it's\n}\n\"")
        self.assert_extracts('  echo "a\\\\" "\n}\n"')

    def test_quotes_nested_in_expansions(self):
        self.assert_extracts('  echo "$(printf \'%s\' ")" \'\n}\n\')"')
        self.assert_extracts('  echo "${x:-"}"}" \'\n}\n\'')
        self.assert_extracts("  echo ${x:-'}'} '\n}\n'")
        self.assert_extracts('  echo "${x:-$(echo "\n}\n")}"')
        self.assert_extracts("  echo \"$(echo '\n}\n')\"")

    def test_backslash_escapes_quotes_and_newlines(self):
        self.assert_extracts("  echo \\' \"\n}\n\"")
        self.assert_extracts('  echo \\" \'\n}\n\'')
        self.assert_extracts("  echo a \\\n}\n b")
        self.assert_extracts("  echo \\\\ 'x\n}\n'")
        self.assert_extracts("  echo \\# 'x\n}\n'")

    def test_comments_hide_quotes_and_braces(self):
        self.assert_extracts("  # it's\n  echo ok")
        self.assert_extracts('  # a " quote\n  echo ok')
        self.assert_extracts("  echo ok # it's\n  :")
        self.assert_extracts("  : ; # don't\n  :")
        self.assert_extracts("  # <<EOF\n  echo ok")
        self.assert_extracts("  # $(\n  echo ok")
        self.assert_extracts("  case $x in\n    a) # it's\n      :\n      ;;\n  esac")
        self.assert_extracts("  ( # it's\n  :\n  )")

    def test_a_hash_inside_a_word_is_not_a_comment(self):
        self.assert_extracts("  echo $# 'a\n}\nb'")
        self.assert_extracts("  echo ${#x} 'a\n}\nb'")
        self.assert_extracts("  echo ${x#*} 'a\n}\nb'")
        self.assert_extracts("  echo ${x##*/} ${x%%#*} 'a\n}\nb'")
        self.assert_extracts("  echo a#b 'a\n}\nb'")
        self.assert_extracts("  echo \"#\" '#' 'a\n}\nb'")

    def test_command_substitutions_close_on_their_own_parenthesis(self):
        self.assert_extracts('  x="$(echo a; echo ")")" \'\n}\n\'')
        self.assert_extracts("  x=$(\n    echo '\n}\n' |\n      sed 's/)/(/'\n  )")
        self.assert_extracts("  x=$(echo $(echo a))\n  echo ok")
        self.assert_extracts("  x=$( (echo a) )\n  echo ok")
        self.assert_extracts('  x=$(( (1 + 2) * 3 ))\n  echo "$x"')

    def test_a_case_pattern_in_a_command_substitution_does_not_close_it(self):
        self.assert_extracts(
            '  x="$(case "$y" in\n    a) echo 1 ;;\n    b|c) echo 2 ;;\n    *) echo \'\n}\n\' ;;\n  esac)"\n  echo "$x"'
        )
        self.assert_extracts(
            "  x=$(\n    case $y in\n      (a) echo 1 ;;\n      b)\n        case $z in\n          c) echo 2 ;;\n"
            "        esac\n        ;;\n    esac\n  )\n  echo '\n}\n'"
        )

    def test_a_brace_group_closed_in_the_first_column_inside_a_substitution(self):
        # A bare "}" at the start of a line inside "$(...)" is not a top-level line.
        self.assert_extracts('  x=$(\n  {\n    echo b\n}\n  )\n  echo "$x"')
        self.assert_extracts('  x="$(\n  {\n    echo b\n}\n  )"')
        self.assert_extracts("  x=$(echo $(\n  {\n    echo b\n}\n  ))")

    def test_a_case_pattern_does_not_end_a_substitution_that_holds_a_brace_group(self):
        self.assert_extracts("  x=$(case $y in\n    a) echo 1 ;;\n  esac\n  {\n    echo b\n}\n  )\n  echo done")
        self.assert_extracts(
            "  x=$(echo $(case $y in\n    a) echo 1 ;;\n  esac)\n  {\n    echo b\n}\n  )\n  echo done"
        )

    def test_a_case_pattern_in_the_function_body_is_no_problem(self):
        self.assert_extracts("  case $x in\n    a) echo '\n}\n' ;;\n    *) : ;;\n  esac")

    def test_a_word_that_only_looks_like_a_keyword_is_no_keyword(self):
        # "case" as an argument and inside a name does not open a case statement in the substitution.
        self.assert_extracts("  x=$(echo case; echo a)\n  y=$(echo a)\n  echo ok")
        self.assert_extracts("  x=$(echo suitcase)\n  echo ok")
        self.assert_extracts("  x=$(printf '%s' esac)\n  echo ok")

    def test_braces_in_parameter_expansions(self):
        self.assert_extracts("  echo ${x:-{}} ${y:-a} 'a\n}\nb'")
        self.assert_extracts("  echo ${x:-${y:-z}} 'a\n}\nb'")

    def test_a_closing_brace_with_text_after_it_still_ends_the_function(self):
        self.assert_extracts("  :", close="} 2>/dev/null")

    def test_names_that_are_prefixes_or_inside_other_text_do_not_match(self):
        source = "my_f() {\n  :\n}\nf() {\n  :\n}\n  g() {\n  :\n}\n# h() {\n"
        self.assertEqual(function_names(source), ["my_f", "f"])
        self.assertEqual(extract_function("f", source), "f() {\n  :\n}")
        for name in ("g", "h", "my"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_function(name, source)

    def test_function_definitions_inside_strings_and_heredocs_are_no_functions(self):
        source = (
            "outer() {\n  cat <<'EOF'\ninner() {\n  :\n}\nEOF\n}\n"
            "x='\nquoted() {\n  :\n}\n'\nreal() {\n  echo \"\nstring() {\n\"\n}\n"
        )
        self.assertEqual(function_names(source), ["outer", "real"])
        for name in ("inner", "quoted", "string"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_function(name, source)

    def test_other_text_between_functions_is_skipped(self):
        source = "#!/bin/sh\nset -eu\nA=1\n\n# comment\nf() {\n  :\n}\nif [ -n \"$A\" ]; then\n  :\nfi\ng() {\n  :\n}\n"
        self.assertEqual(function_names(source), ["f", "g"])

    def test_an_unterminated_function_raises_value_error(self):
        sources = ("f() {\n  :\n", "f() {\n  echo 'open\n}\n", "f() {\n  cat <<EOF\n}\n", 'f() {\n  echo "open\n}\n')
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                extract_function("f", source)
        with self.assertRaises(ValueError):
            function_names("f() {\n  cat <<EOF\nbody\n")

    def test_the_error_names_the_line_where_the_unterminated_construct_opened(self):
        cases = (
            ("a() {\n  :\n}\nb() {\n  echo 'open\n}\n", "single quote opened on line 5"),
            ('a() {\n  :\n}\nb() {\n  echo "open\n}\n', "double quote opened on line 5"),
            ("a() {\n  :\n}\nb() {\n  x=$(echo\n}\n", r"\$\(\.\.\.\) substitution opened on line 5"),
            ("a() {\n  :\n}\nb() {\n  echo ${x:-\n", r"\$\{\.\.\.\} expansion opened on line 5"),
            ("a() {\n  :\n}\nb() {\n  cat <<EOF\n}\n", "heredoc <<EOF opened on line 5"),
        )
        for source, message in cases:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, message):
                function_names(source)

    def test_an_unclosed_function_at_the_end_of_a_source_raises_value_error(self):
        with self.assertRaises(ValueError):
            extract_function("g", "f() {\n  :\n}\ng() {\n  :\n  # }\n")


class AssignmentScannerTests(unittest.TestCase):
    def test_quoted_and_unquoted_values(self):
        source = (
            "A=plain\n"
            'B="double quoted"\n'
            "C='single quoted'\n"
            'D=""\n'
            "E=\n"
            "F=''\n"
            'G="$(date +%s)"\n'
            "H=$(date +%s)\n"
            "I=$((1 + 2))\n"
            'J="a $B b"\n'
            "K='it'\n"
        )
        expected = {
            "A": "plain",
            "B": "double quoted",
            "C": "single quoted",
            "D": "",
            "E": "",
            "F": "",
            "G": "$(date +%s)",
            "H": "$(date +%s)",
            "I": "$((1 + 2))",
            "J": "a $B b",
            "K": "it",
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(extract_assignment(name, source), value)

    def test_multiline_values(self):
        source = (
            "A='first\n}\nlast\n'\n"
            'B="one\n}\ntwo $(echo \'\n}\n\')\n"\n'
            "C='\nfunction f() {\n  return 1\n}\n'\n"
            "D=after\n"
        )
        self.assertEqual(extract_assignment("A", source), "first\n}\nlast\n")
        self.assertEqual(extract_assignment("B", source), "one\n}\ntwo $(echo '\n}\n')\n")
        self.assertEqual(extract_assignment("C", source), "\nfunction f() {\n  return 1\n}\n")
        self.assertEqual(extract_assignment("D", source), "after")

    def test_a_multiline_value_stops_at_the_closing_quote_not_at_the_line_end(self):
        source = "A='one\ntwo'\nB=3\n"
        self.assertEqual(extract_assignment("A", source), "one\ntwo")
        self.assertEqual(extract_assignment("B", source), "3")

    def test_trailing_text_after_the_value_is_not_part_of_it(self):
        source = "A=1 # comment\nB='x' # it's\nC=\"y\"; echo done\nD=z; E=w\nF=v && G=u\n"
        self.assertEqual(extract_assignment("A", source), "1")
        self.assertEqual(extract_assignment("B", source), "x")
        self.assertEqual(extract_assignment("C", source), "y")
        self.assertEqual(extract_assignment("D", source), "z")
        with self.assertRaises(KeyError):
            extract_assignment("E", source)
        self.assertEqual(extract_assignment("F", source), "v")

    def test_only_top_level_lines_count(self):
        source = (
            "f() {\nTOP=in_function_first_column\n  INDENTED=1\n}\n"
            "g() {\n  cat <<EOF\nHEREDOC=1\nEOF\n  x='\nQUOTED=1\n'\n}\n"
            " SPACED=1\n"
            "# COMMENTED=1\n"
            "REAL=ok\n"
        )
        self.assertEqual(extract_assignment("REAL", source), "ok")
        for name in ("TOP", "INDENTED", "HEREDOC", "QUOTED", "SPACED", "COMMENTED"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_assignment(name, source)

    def test_an_assignment_after_a_heredoc_or_string_is_found(self):
        source = "cat <<'EOF'\nA=1\nEOF\nB=2\nx='\nC=3\n'\nD=4\n"
        self.assertEqual(extract_assignment("B", source), "2")
        self.assertEqual(extract_assignment("D", source), "4")
        for name in ("A", "C"):
            with self.subTest(name=name), self.assertRaises(KeyError):
                extract_assignment(name, source)

    def test_a_name_must_match_whole(self):
        source = "AB=1\nA_B=2\nBA=3\nA=4\n"
        self.assertEqual(extract_assignment("A", source), "4")
        self.assertEqual(extract_assignment("AB", source), "1")
        with self.assertRaises(KeyError):
            extract_assignment("B", source)

    def test_only_a_name_at_the_start_of_a_line_followed_by_an_equals_sign_is_an_assignment(self):
        self.assertEqual(extract_assignment("A", "A==1\nB=1\n"), "=1")
        self.assertEqual(extract_assignment("A", "A=b=c\n"), "b=c")
        for source in ("echo A=1\n", "A\n", "A =1\n", "a=1\n", "export A=1\n", "A:=1\n"):
            with self.subTest(source=source), self.assertRaises(KeyError):
                extract_assignment("A", source)

    def test_a_value_made_of_several_quoted_parts_is_refused(self):
        for source in ("A='a'\"b\"\n", 'A="a"b\n', "A=a'b'\n", "A=a\"b\"\n", "A='a''b'\n"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                extract_assignment("A", source)

    def test_quotes_inside_a_quoted_value_or_a_substitution_are_part_of_the_value(self):
        source = 'A="a $(echo "b") c"\nB=$(echo "b")y\nC=\'say "hi"\'\nD="it\'s"\nE="a\\"b"\n'
        self.assertEqual(extract_assignment("A", source), 'a $(echo "b") c')
        self.assertEqual(extract_assignment("B", source), '$(echo "b")y')
        self.assertEqual(extract_assignment("C", source), 'say "hi"')
        self.assertEqual(extract_assignment("D", source), "it's")
        self.assertEqual(extract_assignment("E", source), 'a\\"b')

    def test_a_name_assigned_twice_at_the_top_level_is_ambiguous(self):
        with self.assertRaises(ValueError):
            extract_assignment("A", "A=1\nB=2\nA=3\n")

    def test_an_unterminated_value_raises_value_error(self):
        for source in ("A='open\nB=1\n", 'A="open\nB=1\n', "A=$(open\nB=1\n"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                extract_assignment("A", source)


class IndexTests(unittest.TestCase):
    def test_the_script_is_read_when_no_source_is_given(self):
        self.assertEqual(extract_function("root_path"), extract_function("root_path", SCRIPT_TEXT))
        self.assertEqual(extract_assignment("SCRIPT_VERSION"), extract_assignment("SCRIPT_VERSION", SCRIPT_TEXT))
        self.assertEqual(function_names(), function_names(SCRIPT_TEXT))

    def test_the_script_path_is_the_one_of_the_repository(self):
        self.assertEqual(SCRIPT, Path(__file__).resolve().parents[1] / "tests/fixtures/engine/legacy-apply-phase6.sh.txt")
        self.assertTrue(SCRIPT.is_file())


if __name__ == "__main__":
    unittest.main()

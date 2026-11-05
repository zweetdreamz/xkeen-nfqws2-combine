"""Tests of kdn.engine.config: the paths, constants and timeouts of the engine, against apply-discord-nfqws2.sh.

The constants are compared with the assignments of the script (engine_shell.extract_assignment). The paths are
compared with the values the script itself computes: the head of the script (up to ``WORK_TMP_DIR=``) is run under
dash and busybox ash with the test-root variables of a case, and every variable is printed. The roots are odd on
purpose (a trailing slash, a double slash, spaces, quotes, ``$``, a backslash, an undecodable byte): the engine
joins the root to a logical path by plain string concatenation, as ``root_path`` of the script does.
"""

from __future__ import annotations

import ast
import inspect
import io
import os
from pathlib import Path
import re
import shutil
import tempfile
import types
import unittest
from unittest import mock

import engine_shell
from kdn.common import jsonc, lock, proc
from kdn.common import paths as common_paths
from kdn.engine import cli, config, legacy, system


ROOT = engine_shell.ROOT
ENGINE_DIR = ROOT / "tools" / "router" / "kdn" / "engine"
FIXTURE = ROOT / "tests" / "fixtures" / "engine" / "router-xkeen20"
SHELLS = {
    "dash": ("dash",),
    "busybox ash": ("busybox", "sh"),
}

REFUSAL = "ERROR: KD_TEST_ROOT is reserved for isolated repository tests."

# Constant of config -> variable of the script (the same name unless listed).
CONSTANTS = (
    "PROJECT",
    "SCRIPT_VERSION",
    "TCP_PORTS_VALUE",
    "UDP_PORTS_FLOWSEAL",
    "UDP_FILTER_FLOWSEAL",
    "UDP_PORTS_WIDE",
    "UDP_FILTER_WIDE",
    "XKEEN_REQUIRED_PORTS_NARROW",
    "TELEGRAM_CALL_PORTS",
    "UNBOUND_POLICY_NAME",
    "NFQWS_DISABLED_HOST",
    "DISCORD_UDP_BLOB_SHA256",
    "YOUTUBE_TLS_BLOB_SHA256",
    "YOUTUBE_QUIC_BLOB_SHA256",
    "TELEGRAM_WS_PORT",
)
SHELL_NAME = {"XKEEN_REQUIRED_PORTS_NARROW": "XKEEN_REQUIRED_PORTS"}

# The fields of EnginePaths, in the order of the plan.
FIELDS = (
    "state_root",
    "snapshot_root",
    "baseline_pointer",
    "xkeen_baseline_pointer",
    "latest_pointer",
    "lock_dir",
    "xkeen_init",
    "xkeen_hook",
    "nfqws_init",
    "nfqws_conf",
    "nfqws_list",
    "nfqws_pidfile",
    "nfqws_bin",
    "xkeen_dir",
    "xkeen_port_proxying",
    "xkeen_port_exclude",
    "xkeen_json",
    "xray_config_dir",
    "xray_dat_dir",
    "xray_default_bin",
    "mihomo_config",
    "telegram_ws_python",
    "telegram_ws_relay",
    "source_discord_udp_blob",
    "work_tmp_root",
    "script_dir",
    "script",
    "test_root",
)
# Field -> the variable of the script that holds the same path. The three fields that are not here are checked by
# hand: xkeen_json (the script never names it), work_tmp_root (the script builds WORK_TMP_DIR from it), script.
FIELD_VARIABLES = {
    **{
        name: name.upper()
        for name in FIELDS
        if name not in ("xkeen_json", "xray_default_bin", "work_tmp_root", "script")
    },
    "xray_default_bin": "XRAY_DEFAULT_BIN",
}
# The variable that is a field in another form: work_tmp_root is its directory.
WORK_TMP_VARIABLE = "WORK_TMP_DIR"
# Variables of the script that hold a path under the root and have no field: only the mutating modes read them.
UNUSED_ROOT_VARIABLES = frozenset({
    "NFQWS_YOUTUBE_LIST",
    "NFQWS_TELEGRAM_LIST",
    "NFQWS_TELEGRAM_CF_LIST",
    "NFQWS_TELEGRAM_IPSET",
    "NFQWS_DISCORD_UDP_BLOB",
    "NFQWS_YOUTUBE_TLS_BLOB",
    "NFQWS_YOUTUBE_QUIC_BLOB",
    "IMPORTED_PROFILE_DIR",
    "PROFILE_VERSION_ROOT",
    "PANEL_HISTORY_DIR",
    "TELEGRAM_WS_INIT",
    "TELEGRAM_WS_PIDFILE",
    "TELEGRAM_WS_LOG",
    "OPKG_FEED",
})  # fmt: skip

PREFIX_END = 'WORK_TMP_DIR="$(root_path /opt/tmp/${PROJECT}.$$)"\n'
ROOT_PATH_ASSIGNMENT = re.compile(r'(?m)^([A-Z][A-Z0-9_]*)="\$\(root_path (/[^)]*)\)"$')

ODD_ROOTS = (
    "/tmp/kd-root",
    "/tmp/kd-root/",
    "/tmp/kd-root//",
    "//tmp//kd-root",
    "/tmp/kd root",
    "/tmp/kd root/",
    "/tmp/a b//c d/",
    "relative/root",
    "./relative/",
    "/",
    "//",
    " ",
    "~",
    "/tmp/$HOME/`id`/$(id)",
    "/tmp/it's \"quoted\"",
    "/tmp/back\\slash\\n",
    "/tmp/%s-%d-%%",
    "/tmp/glob*?[x]",
    "/tmp/ünï/код",
    "/tmp/bad\udcffbyte",
)
# Values of KD_ALLOW_TEST_ROOT that do not allow the test root (None: not set).
NOT_ALLOWING = (None, "0", "", "true", "yes", "2", " 1", "1 ", "01")
TELEGRAM_PORTS = (None, "", "9999", "abc", "0", " 18444 ")


def installed_shells():
    return {label: command for label, command in SHELLS.items() if shutil.which(command[0]) is not None}


def prefix_text():
    text = engine_shell.script_text()
    return text[: text.index(PREFIX_END) + len(PREFIX_END)]


def xray_default_expression():
    function = engine_shell.extract_function("xray_test_config")
    found = re.findall(r'xray_test_bin="(\$\(root_path [^)]*\))"', function)
    assert len(found) == 1, found
    return found[0]


def shell_name(constant):
    return SHELL_NAME.get(constant, constant)


def probe_variables():
    names = {shell_name(constant) for constant in CONSTANTS}
    names.update(FIELD_VARIABLES.values())
    names.update({"WORK_TMP_DIR", "PID"})
    return sorted(names)


def probe_script():
    lines = [prefix_text(), f'XRAY_DEFAULT_BIN="{xray_default_expression()}"', "PID=$$"]
    lines.extend(f"printf '%s\\n' \"{name}=${name}\"" for name in probe_variables())
    return "\n".join(lines) + "\n"


def base_environment():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def case_environment(root=None, allow="1", telegram_port=None):
    """The KD_* variables of one case; None leaves a variable out."""
    env = {}
    if root is not None:
        env["KD_TEST_ROOT"] = root
    if allow is not None:
        env["KD_ALLOW_TEST_ROOT"] = allow
    if telegram_port is not None:
        env["KD_TEST_TELEGRAM_WS_PORT"] = telegram_port
    return env


def run_head(shell, environment, script_dir):
    """Run the head of the script under ``shell`` with ``script_dir`` as the directory of the script ($0 is sh)."""
    wrapper = ("sh", "-c", 'cd "$1" && shift && exec "$@"', "probe", script_dir, *shell)
    return engine_shell.run_sh(probe_script(), env={**base_environment(), **environment}, shell=wrapper)


def parse_probe(stdout):
    values = {}
    for line in stdout.split("\n")[:-1]:
        name, _, value = line.partition("=")
        assert name not in values, name
        values[name] = value
    return values


class ConstantsTests(unittest.TestCase):
    def test_constants_match_the_shell_script(self):
        for constant in CONSTANTS:
            with self.subTest(constant=constant):
                value = getattr(config, constant)
                self.assertEqual(str(value), engine_shell.extract_assignment(shell_name(constant)))

    def test_the_port_of_the_telegram_relay_is_the_unquoted_number(self):
        self.assertEqual(engine_shell.extract_assignment("TELEGRAM_WS_PORT"), "18443")
        self.assertEqual(config.TELEGRAM_WS_PORT, 18443)
        self.assertIsInstance(config.TELEGRAM_WS_PORT, int)

    def test_the_other_constants_are_strings(self):
        for constant in CONSTANTS:
            if constant != "TELEGRAM_WS_PORT":
                with self.subTest(constant=constant):
                    self.assertIsInstance(getattr(config, constant), str)

    def test_the_constants_have_the_values_the_plan_names(self):
        # Literal copies: a change of the script shows in the test above, a change of the plan here.
        self.assertEqual(config.PROJECT, "keenetic-discord-nfqws2")
        self.assertEqual(config.UNBOUND_POLICY_NAME, "__keenetic_discord_nfqws2_unbound__")
        self.assertEqual(config.NFQWS_DISABLED_HOST, "kdn-disabled.invalid")
        self.assertEqual(config.TELEGRAM_CALL_PORTS, "590:600,1400")
        self.assertEqual(config.UDP_PORTS_FLOWSEAL, "443,3478:3481,5349,19294:19344,50000:50100")
        self.assertEqual(config.UDP_FILTER_WIDE, "443,3478-3481,5349,19294-19344,50000-65535")
        self.assertEqual(len(config.DISCORD_UDP_BLOB_SHA256), 64)
        self.assertEqual(len(config.YOUTUBE_TLS_BLOB_SHA256), 64)
        self.assertEqual(len(config.YOUTUBE_QUIC_BLOB_SHA256), 64)


class PathsTests(unittest.TestCase):
    def environ(self, root="/tmp/kd root", **extra):
        return {"KD_TEST_ROOT": root, "KD_ALLOW_TEST_ROOT": "1", **extra}

    def test_the_fields_are_the_ones_of_the_plan(self):
        self.assertEqual(sorted(config.EnginePaths.__slots__), sorted(FIELDS))
        self.assertEqual(len(set(config.EnginePaths.__slots__)), len(FIELDS))

    def test_paths_match_the_shell_script(self):
        # NAME="$(root_path /opt/...)": the logical path of the script is the field without a root.
        prefix = prefix_text()
        logical = dict(ROOT_PATH_ASSIGNMENT.findall(prefix))
        paths = config.EnginePaths.from_environ({})
        self.assertEqual(paths.test_root, "")
        by_variable = {variable: field for field, variable in FIELD_VARIABLES.items()}
        compared = set()
        for variable, path in logical.items():
            if variable in UNUSED_ROOT_VARIABLES or variable == WORK_TMP_VARIABLE:
                continue
            with self.subTest(variable=variable):
                self.assertIn(variable, by_variable)
                self.assertEqual(getattr(paths, by_variable[variable]), path)
                compared.add(variable)
        self.assertEqual(compared, set(logical) - UNUSED_ROOT_VARIABLES - {WORK_TMP_VARIABLE})
        self.assertEqual(paths.xray_default_bin, re.search(r"root_path (/[^)]*)\)", xray_default_expression()).group(1))
        self.assertEqual(logical[WORK_TMP_VARIABLE], paths.work_tmp_root + "/${PROJECT}.$$")
        self.assertEqual(paths.work_tmp_root, "/opt/tmp")

    def test_every_root_path_variable_of_the_script_is_a_field_or_listed_as_unused(self):
        found = set(dict(ROOT_PATH_ASSIGNMENT.findall(prefix_text())))
        known = {variable for variable in FIELD_VARIABLES.values() if variable != "XRAY_DEFAULT_BIN"}
        known.add(WORK_TMP_VARIABLE)
        self.assertEqual(found - known - UNUSED_ROOT_VARIABLES, set(), "a new path of the script has no field")
        self.assertLessEqual(UNUSED_ROOT_VARIABLES, found, "a listed variable is gone from the script")

    def test_paths_are_plain_concatenation(self):
        for root, expected in (
            ("/tmp/r", "/tmp/r/opt/etc/keenetic-discord-nfqws2"),
            ("/tmp/r/", "/tmp/r//opt/etc/keenetic-discord-nfqws2"),
            ("/tmp/r//", "/tmp/r///opt/etc/keenetic-discord-nfqws2"),
            ("//tmp//r", "//tmp//r/opt/etc/keenetic-discord-nfqws2"),
            ("/tmp/r s", "/tmp/r s/opt/etc/keenetic-discord-nfqws2"),
            ("rel/./r", "rel/./r/opt/etc/keenetic-discord-nfqws2"),
        ):
            with self.subTest(root=root):
                paths = config.EnginePaths.from_environ(self.environ(root))
                self.assertEqual(paths.state_root, expected)
                self.assertEqual(paths.snapshot_root, expected + "/snapshots")
                self.assertEqual(paths.lock_dir, root + "/opt/tmp/keenetic-discord-nfqws2.lock")
                self.assertEqual(paths.test_root, root)

    def test_from_environ_moves_every_path_under_the_test_root(self):
        environ = self.environ("/tmp/kd root/", KDN_ENGINE_SCRIPT_DIR="/srv/project dir")
        paths = config.EnginePaths.from_environ(environ)
        from_script_dir = {"script_dir", "script", "telegram_ws_relay", "source_discord_udp_blob"}
        for field in FIELDS:
            value = getattr(paths, field)
            self.assertIsInstance(value, str, field)
            with self.subTest(field=field):
                if field == "test_root":
                    self.assertEqual(value, "/tmp/kd root/")
                elif field in from_script_dir:
                    self.assertTrue(value.startswith("/srv/project dir"), value)
                else:
                    self.assertTrue(value.startswith("/tmp/kd root//opt/"), value)
        bare = config.EnginePaths.from_environ({})
        for field in FIELDS:
            if field not in from_script_dir and field != "test_root":
                with self.subTest(field=field, root="unset"):
                    self.assertTrue(getattr(bare, field).startswith("/opt/"), getattr(bare, field))

    def test_derived_paths_follow_their_base(self):
        paths = config.EnginePaths.from_environ(self.environ("/r", KDN_ENGINE_SCRIPT_DIR="/p"))
        self.assertEqual(paths.xkeen_port_proxying, paths.xkeen_dir + "/port_proxying.lst")
        self.assertEqual(paths.xkeen_port_exclude, paths.xkeen_dir + "/port_exclude.lst")
        self.assertEqual(paths.xkeen_json, "/r/opt/etc/xkeen/xkeen.json")
        self.assertEqual(paths.baseline_pointer, paths.state_root + "/baseline.ptr")
        self.assertEqual(paths.xkeen_baseline_pointer, paths.state_root + "/baseline-xkeen.ptr")
        self.assertEqual(paths.latest_pointer, paths.state_root + "/latest-preapply.ptr")
        self.assertEqual(paths.work_tmp_root, "/r/opt/tmp")
        self.assertEqual(paths.xray_default_bin, "/r/opt/sbin/xray")
        self.assertEqual(paths.telegram_ws_relay, "/p/tools/router/telegram_ws_relay.py")
        self.assertEqual(paths.source_discord_udp_blob, "/p/config/blobs/ACTIVE_DISCORD_UDP.bin")

    def test_xkeen_json_is_where_the_router_has_it(self):
        paths = config.EnginePaths.from_environ(self.environ(str(FIXTURE)))
        for field in (
            "xkeen_json",
            "xkeen_init",
            "xkeen_hook",
            "nfqws_conf",
            "xkeen_port_proxying",
            "xkeen_port_exclude",
        ):
            with self.subTest(field=field):
                self.assertTrue(os.path.isfile(getattr(paths, field)), getattr(paths, field))
        for field in ("xkeen_dir", "xray_config_dir", "xray_dat_dir", "snapshot_root"):
            with self.subTest(field=field):
                self.assertTrue(os.path.isdir(getattr(paths, field)), getattr(paths, field))

    def test_test_root_without_permission_is_refused(self):
        for allow in NOT_ALLOWING:
            environ = {"KD_TEST_ROOT": "/tmp/kd root"}
            if allow is not None:
                environ["KD_ALLOW_TEST_ROOT"] = allow
            with self.subTest(allow=allow):
                with self.assertRaises(RuntimeError) as caught:
                    config.EnginePaths.from_environ(environ)
                self.assertEqual("ERROR: " + str(caught.exception), REFUSAL)
                stdout, stderr = io.StringIO(), io.StringIO()
                execve = mock.Mock()
                for argv in (["--status"], ["--apply", "--yes-router"], ["--bogus"], []):
                    code = cli.main(argv, environ, stdout, stderr, execve)
                    self.assertEqual(code, 2, argv)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), (REFUSAL + "\n") * 4)
                execve.assert_not_called()

    def test_an_empty_test_root_needs_no_permission(self):
        for environ in ({}, {"KD_TEST_ROOT": ""}, {"KD_TEST_ROOT": "", "KD_ALLOW_TEST_ROOT": "0"}):
            with self.subTest(environ=environ):
                paths = config.EnginePaths.from_environ(environ)
                self.assertEqual(paths.state_root, "/opt/etc/keenetic-discord-nfqws2")

    def test_from_environ_defaults_to_the_environment_of_the_process(self):
        with mock.patch.dict(os.environ, {"KD_TEST_ROOT": "/tmp/ambient", "KD_ALLOW_TEST_ROOT": "1"}):
            self.assertEqual(config.EnginePaths.from_environ().test_root, "/tmp/ambient")
            self.assertEqual(config.EnginePaths.from_environ(None).nfqws_init, "/tmp/ambient/opt/etc/init.d/S51nfqws2")

    def test_script_dir_comes_from_the_dispatcher_or_the_package_location(self):
        self.assertEqual(str(Path(config.__file__).resolve().parents[4]), str(ROOT))
        bare = config.EnginePaths.from_environ({})
        self.assertEqual(bare.script_dir, str(ROOT))
        self.assertEqual(bare.script, str(ROOT / "apply-discord-nfqws2.sh"))
        self.assertEqual(bare.telegram_ws_relay, str(ROOT / "tools" / "router" / "telegram_ws_relay.py"))
        self.assertEqual(bare.source_discord_udp_blob, str(ROOT / "config" / "blobs" / "ACTIVE_DISCORD_UDP.bin"))
        dispatched = config.EnginePaths.from_environ({"KDN_ENGINE_SCRIPT_DIR": "/srv/a b"})
        self.assertEqual(dispatched.script_dir, "/srv/a b")
        self.assertEqual(dispatched.script, "/srv/a b/apply-discord-nfqws2.sh")
        self.assertEqual(dispatched.telegram_ws_relay, "/srv/a b/tools/router/telegram_ws_relay.py")
        both = config.EnginePaths.from_environ({
            "KDN_ENGINE_SCRIPT_DIR": "/srv/a b",
            "KDN_ENGINE_SCRIPT": "/srv/a b/apply-discord-nfqws2.sh",
        })  # fmt: skip
        self.assertEqual(both.script, "/srv/a b/apply-discord-nfqws2.sh")
        # An empty variable is no variable.
        empty = config.EnginePaths.from_environ({"KDN_ENGINE_SCRIPT_DIR": "", "KDN_ENGINE_SCRIPT": ""})
        self.assertEqual(empty.script_dir, str(ROOT))
        self.assertEqual(empty.script, str(ROOT / "apply-discord-nfqws2.sh"))

    def test_the_script_is_the_one_the_hand_over_to_the_shell_uses(self):
        for environ in (
            {},
            {"KDN_ENGINE_SCRIPT_DIR": "/srv/p"},
            {"KDN_ENGINE_SCRIPT": "/x/apply.sh", "KDN_ENGINE_SCRIPT_DIR": "/srv/p"},
        ):
            with self.subTest(environ=environ):
                self.assertEqual(config.EnginePaths.from_environ(environ).script, legacy.script_path(environ))

    def test_telegram_ws_port_is_overridden_only_under_a_test_root(self):
        paths_unset = config.EnginePaths.from_environ({})
        self.assertEqual(config.telegram_ws_port(paths_unset, {}), "18443")
        # The script ignores the variable without a test root, and an empty one.
        self.assertEqual(config.telegram_ws_port(paths_unset, {"KD_TEST_TELEGRAM_WS_PORT": "9999"}), "18443")
        environ = self.environ("/tmp/r", KD_TEST_TELEGRAM_WS_PORT="9999")
        paths = config.EnginePaths.from_environ(environ)
        self.assertEqual(config.telegram_ws_port(paths, environ), "9999")
        for value, expected in (("", "18443"), ("abc", "abc"), (" 18444 ", " 18444 ")):
            environ = self.environ("/tmp/r", KD_TEST_TELEGRAM_WS_PORT=value)
            self.assertEqual(config.telegram_ws_port(config.EnginePaths.from_environ(environ), environ), expected)

    def test_paths_are_read_only_values(self):
        paths = config.EnginePaths.from_environ(self.environ("/r"))
        with self.assertRaises(AttributeError):
            paths.state_root = "/elsewhere"
        with self.assertRaises(AttributeError):
            del paths.state_root
        with self.assertRaises(AttributeError):
            paths.extra = "x"
        self.assertEqual(paths.state_root, "/r/opt/etc/keenetic-discord-nfqws2")

    def test_paths_compare_hash_and_print_by_value(self):
        first = config.EnginePaths.from_environ(self.environ("/r"))
        second = config.EnginePaths.from_environ(self.environ("/r"))
        other = config.EnginePaths.from_environ(self.environ("/s"))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertNotEqual(first, other)
        self.assertNotEqual(first, "/r")
        self.assertEqual(len({first, second, other}), 2)
        self.assertIn("state_root='/r/opt/etc/keenetic-discord-nfqws2'", repr(first))
        self.assertTrue(repr(first).startswith("EnginePaths("))

    def test_paths_that_differ_in_one_field_are_different(self):
        paths = config.EnginePaths.from_environ(self.environ("/r"))
        for field in FIELDS:
            with self.subTest(field=field):
                changed = paths.replace(**{field: "/changed"})
                self.assertNotEqual(changed, paths)
                self.assertNotEqual(hash(changed), hash(paths))
                self.assertEqual(changed.replace(**{field: getattr(paths, field)}), paths)

    def test_replace_changes_the_named_fields_only(self):
        paths = config.EnginePaths.from_environ(self.environ("/r"))
        changed = paths.replace(nfqws_conf="/elsewhere/nfqws2.conf")
        self.assertEqual(changed.nfqws_conf, "/elsewhere/nfqws2.conf")
        self.assertEqual(changed.state_root, paths.state_root)
        self.assertEqual(paths.nfqws_conf, "/r/opt/etc/nfqws2/nfqws2.conf")
        with self.assertRaises(TypeError):
            paths.replace(no_such_field="x")

    def test_the_constructor_wants_every_field_and_no_other(self):
        values = {field: f"/{field}" for field in FIELDS}
        built = config.EnginePaths(**values)
        self.assertEqual(built.xkeen_init, "/xkeen_init")
        with self.assertRaises(TypeError):
            config.EnginePaths(**{key: value for key, value in values.items() if key != "script"})
        with self.assertRaises(TypeError):
            config.EnginePaths(**values, extra="x")

    def test_cli_main_gives_the_modes_the_paths_of_the_environment(self):
        seen = []

        def run(ctx):
            seen.append(ctx)
            return 5

        environ = self.environ("/tmp/kd root//", KDN_ENGINE_SCRIPT_DIR="/srv/p")
        with mock.patch.dict(cli.MODES, {"status": types.SimpleNamespace(run=run)}), \
                mock.patch.object(cli.xkeen, 'require', return_value='2.1'):
            code = cli.main(["--status"], environ, io.StringIO(), io.StringIO())
        self.assertEqual(code, 5)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].paths, config.EnginePaths.from_environ(environ))
        self.assertEqual(seen[0].paths.state_root, "/tmp/kd root///opt/etc/keenetic-discord-nfqws2")

    def test_cli_main_builds_the_paths_before_native_mutation(self):
        seen = []

        def exec_legacy(ctx):
            seen.append(ctx.paths)
            return 0

        environ = self.environ("/tmp/r")
        with mock.patch.object(cli, "_run_mutation", exec_legacy), \
                mock.patch.object(cli.xkeen, 'require', return_value='2.1'):
            cli.main(["--apply", "--yes-router"], environ, io.StringIO(), io.StringIO())
        self.assertEqual(seen, [config.EnginePaths.from_environ(environ)])


class TimeoutTests(unittest.TestCase):
    def test_timeouts_cover_every_external_command_name(self):
        self.assertEqual(
            dict(config.TIMEOUTS),
            {
                "xkeen_status": 20,
                "xkeen_version": 10,
                "opkg": 20,
                "process": 5,
                "ip": 10,
                "wget": 5,
                "ndmc": 20,
                "xray_test": 90,
                "python_check": 10,
                "compose": 20,
            },
        )
        for name, seconds in config.TIMEOUTS.items():
            with self.subTest(name=name):
                self.assertIsInstance(seconds, int)
                self.assertGreater(seconds, 0)

    def test_every_timeout_name_the_engine_uses_exists(self):
        used = {}
        for path in sorted(ENGINE_DIR.glob("*.py")):
            for line, name in timeout_names(ast.parse(path.read_text(encoding="utf-8"))):
                used[f"{path.name}:{line}"] = name
        self.assertLessEqual(set(used.values()), set(config.TIMEOUTS), used)

    def test_the_scan_of_timeout_names_sees_planted_uses(self):
        tree = ast.parse(
            'a = config.timeout("one", environ)\nb = timeout("two", environ)\nc = TIMEOUTS["three"]\n'
            'd = config.TIMEOUTS["four"]\ne = process.wait(timeout=5)\nf = timeout(name, environ)\n'
        )
        self.assertEqual(timeout_names(tree), [(1, "one"), (2, "two"), (3, "three"), (4, "four")])

    def test_timeout_without_a_scale_is_the_table_value(self):
        for name, seconds in config.TIMEOUTS.items():
            with self.subTest(name=name):
                self.assertEqual(config.timeout(name, {}), seconds)
                self.assertIsInstance(config.timeout(name, {}), int)
        self.assertEqual(config.timeout("xkeen_status", {}), 20)
        self.assertEqual(config.timeout("xray_test", {}), 90)

    def test_timeout_scale_multiplies_and_ignores_bad_values(self):
        scale = config.SCALE_ENV
        self.assertEqual(scale, "KDN_ENGINE_TIMEOUT_SCALE")
        for value, expected in (
            ("1", 20),
            ("2", 40),
            ("2.5", 50),
            ("10", 200),
            ("1.0", 20),
            ("01.50", 30),
            # Not a number >= 1: ignored.
            ("0.5", 20),
            ("0", 20),
            ("-2", 20),
            ("", 20),
            ("abc", 20),
            ("nan", 20),
            ("inf", 20),
            ("1e3", 20),
            ("0x10", 20),
            ("2,5", 20),
            (" 2", 20),
            ("2 ", 20),
            ("1_0", 20),
            ("٢", 20),
            ("2.", 20),
            (".5", 20),
            # Too large to be a timeout: the ceiling.
            ("9" * 400, 86400),
            ("1" + "0" * 308, 86400),
        ):
            with self.subTest(value=value):
                self.assertEqual(config.timeout("xkeen_status", {scale: value}), expected)
        self.assertEqual(config.timeout("xray_test", {scale: "2"}), 180)
        self.assertEqual(config.timeout("process", {scale: "1.5"}), 7.5)

    def test_timeout_never_exceeds_the_ceiling(self):
        self.assertEqual(config.MAX_TIMEOUT, 86400)
        scale = config.SCALE_ENV
        for value, name, expected in (
            ("1000000", "process", 86400),
            ("1000", "xray_test", 86400),
            ("960", "xray_test", 86400),
            ("959", "xray_test", 86310),
            ("4320", "xkeen_status", 86400),
        ):
            with self.subTest(value=value, name=name):
                self.assertEqual(config.timeout(name, {scale: value}), expected)
        for name in config.TIMEOUTS:
            self.assertLessEqual(config.timeout(name, {scale: "1" + "0" * 30}), config.MAX_TIMEOUT)

    def test_system_run_accepts_the_largest_timeout_config_returns(self):
        largest = max(config.timeout(name, {config.SCALE_ENV: "1" + "0" * 30}) for name in config.TIMEOUTS)
        self.assertEqual(largest, config.MAX_TIMEOUT)
        result = system.run(["true"], os.environ, largest)
        self.assertEqual((result.returncode, result.timed_out), (0, False))

    def test_timeout_reads_the_process_environment_by_default(self):
        with mock.patch.dict(os.environ, {"KDN_ENGINE_TIMEOUT_SCALE": "3"}):
            self.assertEqual(config.timeout("ip"), 30)
            self.assertEqual(config.timeout("ip", None), 30)
        with mock.patch.dict(os.environ, clear=True):
            self.assertEqual(config.timeout("ip"), 10)

    def test_an_unknown_timeout_name_is_an_error(self):
        with self.assertRaises(KeyError):
            config.timeout("no_such_command", {})


def timeout_names(tree):
    """(line, name) of every literal timeout name: timeout("name", ...) and TIMEOUTS["name"]."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            target = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            first = node.args[0]
            if target == "timeout" and isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.append((node.lineno, first.value))
        elif isinstance(node, ast.Subscript):
            target = node.value.attr if isinstance(node.value, ast.Attribute) else getattr(node.value, "id", None)
            if target == "TIMEOUTS" and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                found.append((node.lineno, node.slice.value))
    return sorted(found)


class KdnCommonSurfaceTests(unittest.TestCase):
    """The kdn.common functions the engine calls: a change in them (phase 3 works there) must not pass silently."""

    def signature(self, function):
        return str(inspect.signature(function))

    def test_kdn_common_surface_used_by_the_engine(self):
        self.assertEqual(self.signature(common_paths.test_root), "(environ=None)")
        self.assertEqual(self.signature(lock.inspect_lock), "(path)")
        self.assertEqual(self.signature(jsonc.strip_json_comments), "(text)")
        self.assertEqual(self.signature(proc.stop_process_group), "(process, grace)")

    def test_the_test_root_rule_is_the_one_of_the_script(self):
        self.assertEqual(common_paths.TEST_ROOT_ENV, "KD_TEST_ROOT")
        self.assertEqual(common_paths.ALLOW_TEST_ROOT_ENV, "KD_ALLOW_TEST_ROOT")
        self.assertEqual(common_paths.test_root({}), "")
        self.assertEqual(common_paths.test_root({"KD_TEST_ROOT": "/x/", "KD_ALLOW_TEST_ROOT": "1"}), "/x/")
        with self.assertRaises(RuntimeError) as caught:
            common_paths.test_root({"KD_TEST_ROOT": "/x"})
        self.assertEqual("ERROR: " + str(caught.exception), REFUSAL)

    def test_the_lock_snapshot_has_the_fields_the_status_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = lock.inspect_lock(os.path.join(tmp, "missing.lock"))
        self.assertEqual((state.exists, state.pid, state.alive), (False, None, False))

    def test_strip_json_comments_keeps_strings(self):
        self.assertEqual(jsonc.strip_json_comments('{"a": "//x" /* c */, // d\n"b": 1}').count("//"), 1)


class ShellDifferentialTests(unittest.TestCase):
    """The head of the script and EnginePaths on the same environment: every variable, byte for byte."""

    def shells(self):
        shells = installed_shells()
        self.assertTrue(shells, "neither dash nor busybox is installed")
        return shells

    def script_dir(self):
        """A directory with a space in its name: SCRIPT_DIR of the shell run, and the paths derived from it."""
        return os.path.realpath(self.enterContext(tempfile.TemporaryDirectory(prefix="kd script dir-")))

    def check_case(self, label, shell, environment):
        script_dir = self.script_dir()
        result = run_head(shell, environment, script_dir)
        context = f"{label}: {environment!r}: {result.stderr!r}"
        self.assertEqual(result.returncode, 0, context)
        self.assertEqual(result.stderr, "", context)
        values = parse_probe(result.stdout)
        self.assertEqual(sorted(values), probe_variables(), context)
        self.assertEqual(values["SCRIPT_DIR"], script_dir, context)
        self.assertIn(" ", values["SCRIPT_DIR"], "the script directory of the case has a space in its name")
        py_environ = {**environment, "KDN_ENGINE_SCRIPT_DIR": values["SCRIPT_DIR"]}
        paths = config.EnginePaths.from_environ(py_environ)
        for field, variable in FIELD_VARIABLES.items():
            self.assertEqual(getattr(paths, field), values[variable], f"{context}: {field} / {variable}")
        work_tmp_dir = paths.work_tmp_root + "/" + config.PROJECT + "." + values["PID"]
        self.assertEqual(work_tmp_dir, values["WORK_TMP_DIR"], context)
        self.assertEqual(paths.xkeen_json, paths.xkeen_dir + "/xkeen.json")
        self.assertEqual(paths.script, values["SCRIPT_DIR"] + "/apply-discord-nfqws2.sh")
        for constant in CONSTANTS:
            if constant == "TELEGRAM_WS_PORT":
                self.assertEqual(config.telegram_ws_port(paths, py_environ), values["TELEGRAM_WS_PORT"], context)
            else:
                self.assertEqual(getattr(config, constant), values[shell_name(constant)], f"{context}: {constant}")
        return values

    def test_paths_and_constants_for_odd_test_roots(self):
        for label, shell in self.shells().items():
            for root in ODD_ROOTS:
                with self.subTest(shell=label, root=root):
                    self.check_case(label, shell, case_environment(root))

    def test_paths_and_constants_without_a_test_root(self):
        environments = (
            {},
            case_environment(None, allow="1"),
            case_environment("", allow=None),
            case_environment("", allow="1"),
            case_environment("", allow="0"),
            case_environment(None, allow=None, telegram_port="9999"),
            case_environment("", allow="1", telegram_port="9999"),
        )
        for label, shell in self.shells().items():
            for environment in environments:
                with self.subTest(shell=label, environment=environment):
                    values = self.check_case(label, shell, environment)
                    self.assertEqual(values["TEST_ROOT"], "")
                    self.assertEqual(values["STATE_ROOT"], "/opt/etc/keenetic-discord-nfqws2")
                    self.assertEqual(values["TELEGRAM_WS_PORT"], "18443")

    def test_telegram_ws_port_override(self):
        for label, shell in self.shells().items():
            for root in ("/tmp/kd root", "/tmp/kd-root/"):
                for port in TELEGRAM_PORTS:
                    with self.subTest(shell=label, root=root, port=port):
                        values = self.check_case(label, shell, case_environment(root, telegram_port=port))
                        expected = "18443" if port in (None, "") else port
                        self.assertEqual(values["TELEGRAM_WS_PORT"], expected)

    def test_the_refusal_of_a_test_root_without_permission_is_the_text_of_the_script(self):
        script_dir = self.script_dir()
        for label, shell in self.shells().items():
            for allow in NOT_ALLOWING:
                environment = case_environment("/tmp/kd root", allow=allow)
                with self.subTest(shell=label, allow=allow):
                    result = run_head(shell, environment, script_dir)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, REFUSAL + "\n")
                    with self.assertRaises(RuntimeError) as caught:
                        config.EnginePaths.from_environ(environment)
                    self.assertEqual("ERROR: " + str(caught.exception) + "\n", result.stderr)
                    stderr = io.StringIO()
                    self.assertEqual(cli.main(["--status"], environment, io.StringIO(), stderr, mock.Mock()), 2)
                    self.assertEqual(stderr.getvalue(), result.stderr)

    def test_the_probe_runs_the_real_head_of_the_script(self):
        # Guards the probe itself: the head ends where the plan says and holds assignments only.
        prefix = prefix_text()
        self.assertTrue(prefix.endswith(PREFIX_END))
        self.assertNotIn("\nusage()", prefix)
        self.assertEqual(prefix.count("set -eu"), 1)
        self.assertIn("root_path()", prefix)


if __name__ == "__main__":
    unittest.main()

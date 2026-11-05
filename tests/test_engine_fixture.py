"""Tests of tests/engine_fixture.py: the router-like root that the engine tests share.

The tree is built by the shell function ``engine_build_root`` (tests/engine-root-fixture.sh), the same one that
tests/routing-modes-lib.sh calls for the shell suites; these tests pin what the Python side promises on top of it:
the layout, the mocks, the helpers that change the root and the environment in which the shell engine runs on it.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import engine_fixture
from engine_fixture import PROJECT, make_root


STATE_DIR = "/opt/etc/keenetic-discord-nfqws2"
MOCKS = ("xkeen", "opkg", "pidof", "ip", "xray", "iptables-save", "ip6tables-save")


class FixtureTestCase(unittest.TestCase):
    def new_root(self, **options):
        tmp = tempfile.TemporaryDirectory(prefix="engine-fixture-test.")
        self.addCleanup(tmp.cleanup)
        return make_root(tmp.name, **options)

    @staticmethod
    def run_mock(fixture, name, *args):
        return subprocess.run(
            [str(fixture.mock_bin / name), *args],
            env=fixture.env,
            capture_output=True,
            text=True,
            check=False,
        )


class MakeRootTest(FixtureTestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="engine-fixture-shared.")
        cls.fixture = make_root(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_make_root_builds_the_router_like_tree(self):
        fixture = self.fixture
        init = fixture.path("/opt/etc/init.d/S05xkeen")
        self.assertIn('name_client="xray"\n', init.read_text(encoding="utf-8"))
        self.assertTrue(os.access(init, os.X_OK))
        self.assertIn("mode_proxy='Hybrid'\n", fixture.path("/opt/etc/ndm/netfilter.d/proxy.sh").read_text())
        configs = sorted(path.name for path in fixture.path("/opt/etc/xray/configs").iterdir())
        self.assertEqual(configs, ["03_inbounds.json", "04_outbounds.json", "05_routing.json"])
        for name in configs:
            json.loads(fixture.path(f"/opt/etc/xray/configs/{name}").read_text(encoding="utf-8"))
        conf = fixture.path("/opt/etc/nfqws2/nfqws2.conf").read_text(encoding="utf-8")
        self.assertIn('ISP_INTERFACE="fixture-wan"\n', conf)
        for logical in (
            "/opt/etc/xkeen/port_proxying.lst",
            "/opt/etc/xkeen/port_exclude.lst",
            "/opt/etc/init.d/S51nfqws2",
            "/opt/usr/bin/nfqws2",
            "/opt/etc/nfqws2/blobs/tls_clienthello.bin",
            "/opt/etc/nfqws2/blobs/quic_initial.bin",
        ):
            self.assertTrue(fixture.path(logical).is_file(), logical)
        for logical in ("/opt/tmp", "/opt/var/run", "/opt/etc/opkg", "/opt/etc/nfqws2/lists"):
            self.assertTrue(fixture.path(logical).is_dir(), logical)
        self.assertTrue(fixture.path("/opt/bin/python3").is_symlink())
        self.assertTrue(os.access(fixture.path("/opt/etc/init.d/S51nfqws2"), os.X_OK))
        self.assertTrue(os.access(fixture.path("/opt/usr/bin/nfqws2"), os.X_OK))

    def test_mocks_are_executable_and_answer_like_the_router(self):
        fixture = self.fixture
        for name in MOCKS:
            self.assertTrue(os.access(fixture.mock_bin / name, os.X_OK), name)
        self.assertEqual(self.run_mock(fixture, "xkeen", "-v").stdout, "XKeen 2.1\n")
        self.assertEqual(self.run_mock(fixture, "xkeen", "-status").stdout, "running\n")
        self.assertEqual(self.run_mock(fixture, "pidof", "xray").returncode, 0)
        self.assertEqual(self.run_mock(fixture, "pidof", "unknown").returncode, 1)
        self.assertIn("Version: 1.0-test\n", self.run_mock(fixture, "opkg", "status", "nfqws2-keenetic").stdout)
        self.assertEqual(self.run_mock(fixture, "ip", "route", "show", "default").stdout, "default dev fixture-wan\n")
        self.assertEqual(self.run_mock(fixture, "ip", "link", "show", "dev", "other").returncode, 1)
        # -xtest is recorded, never answered: the engine tests with xray itself.
        self.assertEqual(self.run_mock(fixture, "xkeen", "-xtest").returncode, 0)
        self.assertEqual(fixture.path("/xkeen-xtest.called").read_text(), "xkeen -xtest\n")

    def test_root_is_reusable_by_the_shell_engine(self):
        result = subprocess.run(
            ["sh", str(PROJECT / "apply-discord-nfqws2.sh"), "--print-plan"],
            env=self.fixture.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Целевые маршруты:", result.stdout)


class BlobsTest(FixtureTestCase):
    def test_blobs_are_copied_from_the_source_when_it_has_them(self):
        source = tempfile.TemporaryDirectory(prefix="engine-fixture-blobs.")
        self.addCleanup(source.cleanup)
        (Path(source.name) / "tls_clienthello.bin").write_bytes(b"\x00tls\xff")
        fixture = self.new_root(blob_source=source.name)
        self.assertEqual(fixture.path("/opt/etc/nfqws2/blobs/tls_clienthello.bin").read_bytes(), b"\x00tls\xff")

    def test_a_blob_missing_from_the_source_gets_a_placeholder(self):
        source = tempfile.TemporaryDirectory(prefix="engine-fixture-blobs.")
        self.addCleanup(source.cleanup)
        (Path(source.name) / "tls_clienthello.bin").write_bytes(b"real")
        fixture = self.new_root(blob_source=source.name)
        placeholder = fixture.path("/opt/etc/nfqws2/blobs/quic_initial.bin").read_bytes()
        self.assertEqual(placeholder, b"placeholder quic_initial.bin\n")

    def test_without_a_source_both_blobs_are_placeholders(self):
        fixture = self.new_root(blob_source="/nonexistent/blobs")
        for name in ("tls_clienthello.bin", "quic_initial.bin"):
            data = fixture.path(f"/opt/etc/nfqws2/blobs/{name}").read_bytes()
            self.assertEqual(data, f"placeholder {name}\n".encode())


class HelpersTest(FixtureTestCase):
    def test_fixture_helpers_write_under_the_root(self):
        fixture = self.new_root()
        before = fixture.path("/opt/etc/init.d/S05xkeen").read_text(encoding="utf-8")
        fixture.set_init("name_client", "mihomo")
        after = fixture.path("/opt/etc/init.d/S05xkeen").read_text(encoding="utf-8")
        self.assertEqual(after, before.replace('name_client="xray"', 'name_client="mihomo"'))
        self.assertTrue(os.access(fixture.path("/opt/etc/init.d/S05xkeen"), os.X_OK))

        fixture.write_pointer("baseline.ptr", "20260101T000000Z-1")
        pointer = fixture.path(f"{STATE_DIR}/baseline.ptr")
        expected = f"{fixture.root}{STATE_DIR}/snapshots/20260101T000000Z-1\n"
        self.assertEqual(pointer.read_text(encoding="utf-8"), expected)
        self.assertTrue(Path(expected.strip()).is_relative_to(fixture.root))
        self.assertFalse(Path(expected.strip()).exists(), "a pointer does not create the snapshot")

        fixture.set_conf('ISP_INTERFACE="eth9"\n')
        self.assertEqual(fixture.path("/opt/etc/nfqws2/nfqws2.conf").read_text(), 'ISP_INTERFACE="eth9"\n')

    def test_write_and_write_bytes_keep_every_byte_and_create_directories(self):
        fixture = self.new_root()
        fixture.write("/opt/new/dir/text.txt", "a\r\nb \n")
        fixture.write_bytes("/opt/new/dir/bytes.bin", b"\xff\x00\r")
        fixture.write("/opt/new/dir/raw.txt", "bad\udcffbyte")
        self.assertEqual(fixture.path("/opt/new/dir/text.txt").read_bytes(), b"a\r\nb\xc2\xa0\n")
        self.assertEqual(fixture.path("/opt/new/dir/bytes.bin").read_bytes(), b"\xff\x00\r")
        self.assertEqual(fixture.path("/opt/new/dir/raw.txt").read_bytes(), b"bad\xffbyte")

    def test_path_is_the_concatenation_of_the_root_and_the_logical_path(self):
        fixture = self.new_root()
        self.assertEqual(str(fixture.path("/opt/etc")), f"{fixture.root}/opt/etc")
        self.assertEqual(fixture.path("/"), fixture.root)
        with self.assertRaises(ValueError):
            fixture.path("opt/etc")

    def test_set_init_adds_a_missing_key_after_the_assignments(self):
        fixture = self.new_root()
        fixture.set_init("policy_name", "XKeenTest")
        lines = fixture.path("/opt/etc/init.d/S05xkeen").read_text(encoding="utf-8").split("\n")
        index = lines.index('policy_name="XKeenTest"')
        self.assertEqual(lines[index - 1], 'start_auto="on"')
        self.assertTrue(lines[index + 1].startswith('fixture_xray_stop() {'))

    def test_set_init_replaces_only_the_named_key(self):
        fixture = self.new_root()
        fixture.set_init("table_id", "222")
        text = fixture.path("/opt/etc/init.d/S05xkeen").read_text(encoding="utf-8")
        self.assertIn('table_id="222"\n', text)
        self.assertIn('table_mark="0x111"\n', text)
        self.assertEqual(text.count("table_id="), 1)

    def test_set_init_refuses_values_that_break_the_line(self):
        fixture = self.new_root()
        for value in ('a"b', "a\nb"):
            with self.assertRaises(ValueError):
                fixture.set_init("name_client", value)
        with self.assertRaises(ValueError):
            fixture.set_init("bad key", "x")

    def test_write_pointer_accepts_names_with_and_without_the_suffix_and_other_directories(self):
        fixture = self.new_root()
        fixture.write_pointer("latest-preapply", "snap-2")
        self.assertTrue(fixture.path(f"{STATE_DIR}/latest-preapply.ptr").is_file())
        fixture.write_pointer("latest-nfqws-import.ptr", "imp-1", directory="nfqws-import-snapshots")
        text = fixture.path(f"{STATE_DIR}/latest-nfqws-import.ptr").read_text(encoding="utf-8")
        self.assertEqual(text, f"{fixture.root}{STATE_DIR}/nfqws-import-snapshots/imp-1\n")
        self.assertEqual(fixture.path(f"{STATE_DIR}/latest-preapply.ptr").stat().st_mode & 0o777, 0o600)


class EnvTest(FixtureTestCase):
    def test_env_points_the_shell_engine_at_the_fixture(self):
        fixture = self.new_root()
        env = fixture.env
        self.assertEqual(env["KD_TEST_ROOT"], str(fixture.root))
        self.assertEqual(env["KD_ALLOW_TEST_ROOT"], "1")
        self.assertEqual(env["KDN_ENGINE_SCRIPT_DIR"], str(PROJECT))
        self.assertEqual(env["PATH"].split(os.pathsep)[0], str(fixture.mock_bin))
        self.assertTrue(env["PATH"].endswith(os.environ["PATH"]))
        env["KD_TEST_ROOT"] = "changed"
        self.assertEqual(fixture.env["KD_TEST_ROOT"], str(fixture.root), "every access returns a new dictionary")

    def test_two_roots_do_not_share_anything(self):
        first = self.new_root()
        second = self.new_root()
        self.assertNotEqual(first.root, second.root)
        first.set_init("name_client", "mihomo")
        self.assertIn('name_client="xray"', second.path("/opt/etc/init.d/S05xkeen").read_text(encoding="utf-8"))


class ModuleTest(unittest.TestCase):
    def test_engine_fixture_imports_no_kdn_module(self):
        tree = ast.parse(Path(engine_fixture.__file__).read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertEqual([name for name in imported if name.split(".")[0] == "kdn"], [])

    def test_engine_fixture_imports_at_module_level_only(self):
        tree = ast.parse(Path(engine_fixture.__file__).read_text(encoding="utf-8"))
        nested = [
            node
            for function in ast.walk(tree)
            if isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef)
            for node in ast.walk(function)
            if isinstance(node, ast.Import | ast.ImportFrom)
        ]
        self.assertEqual(nested, [])


if __name__ == "__main__":
    unittest.main()

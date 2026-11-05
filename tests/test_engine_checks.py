"""Port arithmetic and getline list counts compared with the original awk functions."""
import contextlib
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import engine_shell
import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import checks, config, confvalues


AWKS = [("system", ["awk"])]
if shutil.which("busybox"):
    AWKS.append(("busybox", ["busybox", "awk"]))
PORT_AWK = engine_shell.extract_assignment("NFQWS_PORT_AWK")
_CHECK_SOURCE = engine_shell.extract_function("nfqws_config_check")
_START = _CHECK_SOURCE.index("    function list_entries(")
LIST_AWK = _CHECK_SOURCE[_START:_CHECK_SOURCE.index("\n    BEGIN {", _START)]


class FirstReferenceTests(unittest.TestCase):
    def test_empty_hostlist_findings_follow_first_reference_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            with fixture.path('/opt/etc/nfqws2/nfqws2.conf').open('ab') as handle:
                handle.write(b'\nNFQWS_ARGS_CUSTOM="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/missing-b.list --hostlist=/opt/etc/nfqws2/lists/missing-a.list --ipset=/opt/etc/nfqws2/lists/missing-d.list --ipset=/opt/etc/nfqws2/lists/missing-c.list"\n')
            for applets in ('0', '1'):
                with self.subTest(busybox=applets):
                    result = engine_run.run_legacy(['--check-config'], fixture, {'TEST_BUSYBOX_APPLETS': applets})
                    found = [line.split('|')[3].split(' ')[0].rsplit('/', 1)[-1] for line in result.out.split('\n')
                             if line.startswith('CHECK|') and '|empty-hostlist|' in line and '/missing-' in line]
                    self.assertEqual(found, ['missing-b.list', 'missing-a.list', 'missing-d.list', 'missing-c.list'])


class ConfigCheckTests(unittest.TestCase):
    def test_check_config_matches_shell_on_all_scenarios(self):
        separators = ' \t\n\r\v\f' if os.environ.get('TEST_BUSYBOX_APPLETS') == '1' else ' \t\n'
        reference = iter(engine_run.legacy_results(
            (['--check-config'], engine_scenarios.build(name), None) for name in engine_scenarios.names()
        ))
        for name in engine_scenarios.names():
            with self.subTest(name=name):
                fixture = engine_scenarios.build(name)
                expected = next(reference)
                with mock.patch.object(confvalues, 'AWK_FIELD_SEPARATORS', separators):
                    actual = engine_run.run_mode('check-config', ['--check-config'], fixture)
                self.assertFalse(actual.fallback)
                self.assertEqual((actual.rc, actual.out, actual.err), (expected.rc, expected.out, expected.err))
        engine_scenarios.assert_unchanged()

    def test_read_compose_errors_quiet_and_first_meta_word(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            path = fixture.path('/opt/etc/nfqws2/nfqws2.conf')
            paths = config.EnginePaths.from_environ(fixture.env)
            before_tmp = sorted(fixture.path('/opt/tmp').iterdir())
            for text in ('"unterminated\n', 'TCP_PORTS="443 80"\nUDP_PORTS="443 80"\nNFQWS_ARGS="--filter-tcp=443 --filter-udp=443"\n', None):
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text)
                expected = engine_run.run_legacy(['--check-config'], fixture)
                actual = engine_run.run_mode('check-config', ['--check-config'], fixture)
                self.assertEqual((actual.rc, actual.out, actual.err), (expected.rc, expected.out, expected.err))
                quiet, status = checks.check_config(str(path), paths, fixture.env, quiet=True)
                self.assertEqual(status, actual.rc)
                self.assertEqual(quiet, [line for line in actual.out.split('\n') if line and not line.startswith('CHECK|ok|')])
                self.assertEqual(sorted(fixture.path('/opt/tmp').iterdir()), before_tmp)

    def test_voice_range_header_lines_match_real_function(self):
        cases = ['', '# Discord UDP: strategy=flowseal, range=wide.\n']
        for voice_range in ('narrow', 'wide', 'unknown'):
            for ports in ('19294-19344,50000-50100', '19294-19344,50000-65535', '', 'bad'):
                cases.append(f'# Discord UDP: strategy=legacy, range={voice_range}.\n# Discord Voice profile: imported abcd, udp={ports}.\n')
        cases += ['# Discord UDP: strategy=flowseal, range=wide.\r\n# Discord Voice profile: imported , udp=.\n',
                  '# Discord UDP: strategy=flowseal, range=.\n# Discord UDP: strategy=flowseal, range=wide.\n# Discord Voice profile: imported a, udp=2.\n']
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config'
            for text in cases:
                path.write_bytes(text.encode())
                for label, _argv in AWKS:
                    with self.subTest(text=text, awk=label):
                        expected = engine_shell.run_function('check_header_lines', path,
                                      defs=["NFQWS_PORT_AWK='" + PORT_AWK + "'"], awk=label)
                        self.assertEqual(expected.returncode, 0, expected.stderr)
                        self.assertEqual('\n'.join(checks.header_lines(text)) + ('\n' if checks.header_lines(text) else ''), expected.stdout)

    @unittest.skipIf(os.geteuid() == 0, 'root can read chmod 000 files')
    def test_unreadable_conf_is_exit_2_with_read_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            path = fixture.path('/opt/etc/nfqws2/nfqws2.conf')
            path.chmod(0)
            try:
                # Compare the specified check function's read guard. The old
                # top-level CLI can fail earlier while awk reads Telegram's
                # recorded route from this same unreadable file.
                reference = engine_shell.run_function('nfqws_config_check', str(path), env=fixture.env)
                expected = engine_run.Result(reference.returncode, reference.stdout, reference.stderr)
                actual = engine_run.run_mode('check-config', ['--check-config'], fixture)
                self.assertEqual((actual.rc, actual.out, actual.err), (2, 'CHECK|error|read|cannot read ' + str(path) + '\n', ''))
                self.assertEqual(actual, expected)
            finally:
                path.chmod(0o600)

    def test_synthetic_profiles_cover_wildcards_empty_filters_portless_and_user_levels(self):
        cases = ['--filter-tcp=1-8 --lua-desync=fake --hostlist-domains=a.invalid',
                 '--lua-desync=fake:blob=0x00', '--filter-udp=1-3 --filter-l7=stun,discord --lua-desync=fake',
                 '--filter-tcp=* --filter-udp=!3 --lua-desync=fake:blob=0x00',
                 '--filter-tcp= --filter-tcp=3 --filter-l7= --new --new',
                 '--filter-tcp=2 --hostlist=/opt/etc/nfqws2/lists/missing.list --new --filter-tcp=3 --hostlist=/opt/etc/nfqws2/lists/missing.list',
                 '--filter-tcp=4-2 --filter-udp=0-2 --lua-desync=fake:xblob=1',
                 '--filter-tcp=1-2 --filter-tcp=8:12 --ipset-ip=0.0.0.0 --lua-desync=fake:blob=x']
        rng = random.Random(4142)
        for _ in range(16):
            cases.append(f'--filter-tcp={rng.randrange(12)}-{rng.randrange(12)} --filter-udp={rng.randrange(8)}:{rng.randrange(8)} --lua-desync=fake:blob=x')
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            for user in ('', '--filter-tcp=19 --lua-desync=fake'):
                for args in cases:
                    text = 'TCP_PORTS="1-5,8"\nUDP_PORTS="1:3"\nNFQWS_ARGS_CUSTOM=' + shlex.quote(user) + '\nNFQWS_ARGS=' + shlex.quote(args) + '\n'
                    fixture.set_conf(text)
                    with self.subTest(user=user, args=args):
                        expected = engine_run.run_legacy(['--check-config'], fixture)
                        actual = engine_run.run_mode('check-config', ['--check-config'], fixture)
                        self.assertEqual(actual, expected)


class PortTests(unittest.TestCase):
    def test_port_arithmetic_matches_awk(self):
        cases = [("", 0, 20), ("80,443", 1, 500), ("5-3,2:4,4-8", 1, 12),
                 ("*,1-3", 0, 6), (",,,", 1, 5), ("1--3,443-", 1, 5),
                 (" 80,9 ", 0, 10), ("0002:0003,1", 0, 7), ("0-65535", 0, 65535),
                 ("1,10-20,6:8,7", 1, 25), ("2-9", 10, 5), ("1-2-3,42/2,!443,80\t", 1, 3)]
        rng = random.Random(414)
        for _ in range(100):
            text = ",".join(str(rng.randrange(40)) + rng.choice(["-", ":"]) + str(rng.randrange(40)) for _ in range(6))
            cases.append((text, rng.randrange(10), rng.randrange(10, 50)))
        program = PORT_AWK + '\nNR==1 {spec=$0; next} NR==2 {n=port_ranges(spec,lo,hi); print n,PORT_WILDCARD; for(i=1;i<=n;i++) printf "%.17g %.17g\\n",lo[i],hi[i]; print "GAPS|" port_gaps($1+0,$2+0,lo,hi,n)}'
        for name, argv in AWKS:
            for text, a, b in cases:
                with self.subTest(awk=name, spec=text, a=a, b=b):
                    completed = subprocess.run([*argv, program], input=text + "\n" + f"{a} {b}\n", text=True,
                                               capture_output=True, timeout=5)
                    self.assertEqual((completed.returncode, completed.stderr), (0, ""))
                    rows = completed.stdout.split("\n")
                    ranges, wildcard = checks.port_ranges(text)
                    self.assertEqual(rows[0], f"{len(ranges)} {int(wildcard)}")
                    for actual, expected in zip(ranges, rows[1:1+len(ranges)], strict=True):
                        self.assertEqual(actual, tuple(float(value) for value in expected.split(" ")))
                    self.assertEqual("GAPS|" + checks.port_gaps(a, b, ranges), rows[1+len(ranges)])


class ListTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="engine-lists-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def reference(self, argv, path, root=""):
        return subprocess.run([*argv, "-v", "path=" + str(path), "-v", "root=" + str(root),
                               LIST_AWK + '\nBEGIN {print list_entries(path)}'], capture_output=True, text=True, timeout=5)

    def test_list_entries_matches_awk_and_only_opt_paths_are_remapped(self):
        fixtures = {"empty": b"", "comments": b"#a\n ;b\n\t/c\n\n", "lines": b"a\n b\r\n\tc", "cr": b"x\r\r\n\v\n",
                    "empty.gz": b"", "data.gz": b"not actually gzip", "space name": b"one\n"}
        for name, data in fixtures.items():
            path = self.root / name
            path.write_bytes(data)
            for label, awk in AWKS:
                with self.subTest(case=name, awk=label):
                    ref = self.reference(awk, path)
                    self.assertEqual((ref.returncode, ref.stderr), (0, ""))
                    self.assertEqual(checks.list_entries(path, ""), int(ref.stdout))
        opt = self.root / "opt/list"
        opt.parent.mkdir()
        opt.write_bytes(b"one\ntwo\n")
        for label, awk in AWKS:
            with self.subTest(awk=label):
                self.assertEqual(checks.list_entries("/opt/list", str(self.root)), int(self.reference(awk, "/opt/list", self.root).stdout))
                with contextlib.chdir(self.root):
                    self.assertEqual(checks.list_entries("lines", "/not-used"), int(self.reference(awk, "lines").stdout))
                self.assertEqual(checks.list_entries(self.root / "missing", ""), -1)
                self.assertEqual(checks.list_entries(self.root / "missing.gz", ""), -1)

    @unittest.skipIf(os.geteuid() == 0, "root can read chmod 000 fixtures")
    def test_unreadable_plain_and_gz(self):
        for name in ("denied", "denied.gz"):
            path = self.root / name
            path.write_text("x")
            path.chmod(0)
            for _label, awk in AWKS:
                ref = self.reference(awk, path)
                self.assertEqual(ref.returncode, 0, ref.stderr)
                self.assertEqual((int(ref.stdout), checks.list_entries(path, "")), (-1, -1))

    def test_directory_uses_router_semantics_and_records_system_awk_difference(self):
        self.assertEqual(checks.list_entries(self.root, ""), -1)
        for label, awk in AWKS:
            ref = self.reference(awk, self.root)
            if ref.returncode == 0:
                self.assertEqual(int(ref.stdout), -1, label)
            else:
                # mawk treats getline(directory) as a fatal error; BusyBox
                # returns -1, the router's reference and the port's behaviour.
                self.assertEqual(label, "system")
                self.assertTrue(ref.stderr)

    def test_nul_records_follow_router_not_mawk(self):
        path = self.root / "nul"
        path.write_bytes(b"a\0b\n")
        self.assertEqual(checks.list_entries(path, ""), 2)
        for label, awk in AWKS:
            ref = self.reference(awk, path)
            self.assertEqual(ref.returncode, 0, ref.stderr)
            self.assertEqual(int(ref.stdout), 2 if label == "busybox" else 1)

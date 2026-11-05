"""Native profile output compared with the original shell mode."""
import unittest
import os
import stat
from pathlib import Path
import tempfile
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import compose, confvalues, profiles


class ProfileTests(unittest.TestCase):
    def test_empty_profiles_and_global_options_are_not_discarded(self):
        composition = compose.Composition(['--qnum=300', '--new', '--new'], {'USER_PROFILES': '2'}, 'built-in')
        self.assertEqual(profiles.render(composition), ['PROFILE|1|user|--qnum=300', 'PROFILE|2|user|', 'PROFILE|3|managed|'])

    def test_profiles_match_shell_on_all_session_scenarios(self):
        separators = ' \t\n\r\v\f' if os.environ.get('TEST_BUSYBOX_APPLETS') == '1' else ' \t\n'
        for name in engine_scenarios.names():
            with self.subTest(name=name):
                fixture = engine_scenarios.build(name)
                expected = engine_run.run_legacy(['--print-nfqws-profiles'], fixture)
                with mock.patch.object(confvalues, 'AWK_FIELD_SEPARATORS', separators):
                    actual = engine_run.run_mode('print-nfqws-profiles', ['--print-nfqws-profiles'], fixture)
                self.assertFalse(actual.fallback)
                self.assertEqual((actual.rc, actual.out, actual.err), (expected.rc, expected.out, expected.err))
        engine_scenarios.assert_unchanged()

    def test_uncomposable_and_missing_config_errors_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            path = fixture.path('/opt/etc/nfqws2/nfqws2.conf')
            temporary = Path(fixture.root, 'opt/tmp')
            def inventory():
                result = {}
                for item in (temporary, *temporary.rglob('*')):
                    mode = item.lstat().st_mode
                    data = (os.readlink(item) if stat.S_ISLNK(mode) else
                            item.read_bytes() if stat.S_ISREG(mode) else None)
                    result[str(item.relative_to(temporary))] = mode, data
                return result
            before = inventory()
            for text in ('"unterminated\n', None):
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text)
                expected = engine_run.run_legacy(['--print-nfqws-profiles'], fixture)
                actual = engine_run.run_mode('print-nfqws-profiles', ['--print-nfqws-profiles'], fixture)
                self.assertEqual(actual.rc, 2)
                self.assertEqual((actual.rc, actual.out, actual.err), (expected.rc, expected.out, expected.err))
                self.assertEqual(inventory(), before)

    @unittest.skipIf(os.geteuid() == 0, 'root can read chmod 000 files')
    def test_unreadable_config_reports_compose_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            path = fixture.path('/opt/etc/nfqws2/nfqws2.conf')
            path.chmod(0)
            try:
                result = engine_run.run_mode('print-nfqws-profiles', ['--print-nfqws-profiles'], fixture)
                self.assertEqual((result.rc, result.out, result.err),
                                 (2, '', 'ERROR: cannot compose the nfqws2 arguments of ' + str(path) + '\n'))
            finally:
                path.chmod(0o600)

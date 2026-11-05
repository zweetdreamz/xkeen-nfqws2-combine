"""Plan text and substitutions are copied byte-for-byte from legacy."""
import unittest
import subprocess
import sys

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import options, plan


class PlanTests(unittest.TestCase):
    def test_render_exists_and_has_trailing_newline(self):
        text = plan.render(options.resolve(options.parse_args(['--print-plan']), None))
        self.assertTrue(text.startswith('План изменений на роутере:\n'))
        self.assertTrue(text.endswith('\n'))

    def test_plan_matches_shell_for_option_corpus_and_does_not_write(self):
        fixture = engine_scenarios.build('fresh')
        cases = [[], ['--standalone-zapret'], ['--standalone-zapret', '--wide-udp'],
                 ['--wide-udp'], ['--narrow-udp'], ['--udp-strategy', 'flowseal'], ['--udp-strategy', 'legacy'],
                 ['--core', 'xray'], ['--core', 'mihomo'], ['--direct-mark', '255'], ['--direct-mark', ''],
                 ['--wan-interface', 'a b'], ['--wan-interface', ''], ['--wan-interface', 'a\\b'],
                 ['--wide-udp', '--youtube-route', 'vless', '--telegram-route', 'ws', '--wan-interface', 'eth9']]
        cases += [[flag, value] for flag in ('--discord-tcp-route', '--discord-voice-route', '--youtube-route')
                  for value in ('direct', 'zapret', 'vless')]
        cases += [['--telegram-route', value] for value in ('direct', 'vless', 'ws', 'unmanaged')]
        before = engine_scenarios.digest(fixture)
        for case in cases:
            with self.subTest(argv=case):
                expected = engine_run.run_legacy(['--print-plan', *case], fixture)
                actual = engine_run.run_mode('print-plan', ['--print-plan', *case], fixture)
                self.assertFalse(actual.fallback)
                self.assertEqual((actual.rc, actual.out, actual.err), (expected.rc, expected.out, expected.err))
        self.assertEqual(engine_scenarios.digest(fixture), before)
        recorded = engine_scenarios.build('telegram-vless')
        # Offline planning now intentionally ignores effective router defaults.
        self.assertEqual(engine_run.run_python(['--print-plan'], recorded), engine_run.run_python(['--print-plan'], fixture))

    def test_plan_is_utf8_under_c_locale(self):
        fixture = engine_scenarios.build('fresh')
        env = fixture.env
        env.update(LC_ALL='C', PYTHONPATH=str(engine_fixture.PROJECT / 'tools/router'))
        env.pop('PYTHONIOENCODING', None)
        env.pop('PYTHONUTF8', None)
        result = subprocess.run([sys.executable, '-P', '-m', 'kdn.engine', '--print-plan'], env=env,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = engine_run.run_legacy(['--print-plan'], fixture)
        self.assertEqual(result.stdout, expected.out.encode('utf-8'))
        self.assertEqual(result.stderr, b'')

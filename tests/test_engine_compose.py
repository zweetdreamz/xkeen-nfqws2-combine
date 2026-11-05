"""Composition is compared with the actual init-sourcing shell function."""
import contextlib
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import engine_shell
import engine_fixture
from kdn.engine import compose, config, confvalues, lifecycle


class ComposeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(lifecycle.run_cleanups)
        self.root = Path(temp.name)
        self.paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': temp.name, 'KD_ALLOW_TEST_ROOT': '1'})
        self.conf = self.root / 'config'

    def compare(self, text, init=None):
        self.conf.write_bytes(text.encode('utf-8', 'surrogateescape'))
        if init is not None:
            target = Path(self.paths.nfqws_init)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(init.encode('utf-8', 'surrogateescape'))
        return_value = None
        for name, shell in (('dash', ('dash',)), ('busybox', ('busybox', 'sh'))):
            with self.subTest(shell=name, text=text, init=init):
                env = dict(os.environ)
                if name == 'busybox':
                    farm = self.root / 'applets'
                    farm.mkdir(exist_ok=True)
                    for applet in ('sh', 'awk', 'sed', 'grep', 'tr'):
                        link = farm / applet
                        if not link.exists():
                            link.symlink_to(shutil.which('busybox'))
                    env['PATH'] = str(farm) + os.pathsep + env['PATH']
                tokens, meta = self.root / 'tokens', self.root / 'meta'
                reference_work = self.root / 'reference-work'
                reference_work.mkdir(exist_ok=True)
                run = engine_shell.run_function('compose_reference', self.conf, tokens, meta,
                    defs=['builtin_startup_args', 'compose_nfqws_profiles',
                          'make_tmp() { mktemp "$REFERENCE_WORK/part.XXXXXX"; }',
                          'compose_reference() { compose_nfqws_profiles "$@" || return $?; printf "%s" "$COMPOSE_SOURCE"; }'],
                    variables={'NFQWS_INIT': self.paths.nfqws_init, 'REFERENCE_WORK': reference_work}, env=env, shell=shell)
                if run.returncode:
                    with self.assertRaises(compose.ComposeError):
                        compose.compose(str(self.conf), self.paths, env, 3)
                else:
                    with mock.patch.object(confvalues, 'AWK_FIELD_SEPARATORS', ' \t\n' if name == 'dash' else ' \t\n\v\f\r'):
                        result = compose.compose(str(self.conf), self.paths, env, 3)
                    self.assertEqual('\n'.join(result.tokens) + '\n', tokens.read_bytes().decode('utf-8', 'surrogateescape'))
                    expected = {}
                    for line in meta.read_bytes().decode('utf-8', 'surrogateescape').split('\n'):
                        if line:
                            key, _, value = line.partition(' ')
                            expected[key] = value
                    self.assertEqual(result.meta, expected)
                    self.assertEqual(result.source, run.stdout)
                    self.assertEqual(result.user_profiles, int(expected['USER_PROFILES']))
                    self.assertEqual(list(Path(self.paths.work_tmp_root).iterdir()), [])
                    return_value = result
        return return_value

    def test_builtin_and_source_script_are_byte_exact(self):
        self.assertEqual(compose.BUILTIN_STARTUP_ARGS, engine_shell.extract_function('builtin_startup_args'))
        function = engine_shell.extract_function('compose_nfqws_profiles')
        script = function.split("sh -c '", 1)[1].split("' compose ", 1)[0]
        self.assertEqual(compose.SOURCE_SCRIPT, script)

    def test_stock_config_matches_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': tmp, 'KD_ALLOW_TEST_ROOT': '1'})
            conf = Path(tmp, 'config')
            conf.write_text('TCP_PORTS=80,443\nUDP_PORTS=443\nNFQWS_ARGS="--filter-tcp=443"\n')
            result = compose.compose(str(conf), paths, dict(os.environ), 5)
            self.assertIn('--filter-tcp=443', result.tokens)
            self.assertEqual(result.meta['TCP_PORTS'], '80,443')

    def test_router_fixture_stock_config_matches_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            self.compare(fixture.path('/opt/etc/nfqws2/nfqws2.conf').read_bytes().decode('utf-8'),
                         fixture.path('/opt/etc/init.d/S51nfqws2').read_bytes().decode('utf-8'))

    def test_relative_config_argument_is_not_normalized(self):
        self.conf.write_text('NFQWS_ARGS="--path=$1"\n')
        with contextlib.chdir(self.root):
            result = compose.compose('./config', self.paths, dict(os.environ), 3)
        self.assertIn('--path=./config', result.tokens)

    def test_meta_tokens_user_profiles_managed_block_and_environment(self):
        text = ('TCP_PORTS="80 443"\nUDP_PORTS="443 80"\nNFQWS_BASE_ARGS="words --base=1"\n'
                'NFQWS_ARGS_CUSTOM="comment --filter-tcp=1 --new --filter-tcp=2 --home=$HOME --star=*"\n'
                '# BEGIN keenetic-discord-nfqws2\n'
                'NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM --new --filter-tcp=3"\n'
                '# END keenetic-discord-nfqws2\n'
                'NFQWS_ARGS="skip --filter-tcp=443 --pos=1 --seq=2"\nNFQWS_ARGS_QUIC="--filter-udp=443"\n')
        result = self.compare(text)
        self.assertEqual(result.meta['UDP_PORTS'], '443')
        self.assertEqual(result.user_profiles, 2)
        self.assertIn('--home=', result.tokens)
        self.assertIn('--star=*', result.tokens)
        self.assertNotIn('comment', result.tokens)
        self.assertIn('--filter-tcp=3', result.tokens)

    def test_set_f_prevents_glob_expansion(self):
        with contextlib.chdir(self.root):
            Path('--star=expanded').touch()
            result = self.compare('NFQWS_ARGS_CUSTOM="--star=*"\n')
        self.assertIn('--star=*', result.tokens)
        self.assertNotIn('--star=expanded', result.tokens)

    def test_busybox_field_separators_are_the_router_reference(self):
        self.compare('TCP_PORTS="80\r443"\nNFQWS_ARGS="--one\v--two\f--three\r--four"\n')

    def test_package_function_ranges_and_builtin_fallback(self):
        functions = ['_startup_args() {\n echo "--package $NFQWS_ARGS_QUIC"\n}\n',
                     '_startup_args() {\n echo --ignored\n}\n',
                     '_startup_args() {\n echo "$NFQWS_ARGS_QUIC"\n',
                     '_startup_args() {\n echo "$NFQWS_ARGS_QUIC"\nother() {\n :\n}\n',
                     '_startup_args() {\n echo "--first $NFQWS_ARGS_QUIC"\n}\n'
                     '_startup_args() {\n echo "--second $NFQWS_ARGS_QUIC"\n}\n']
        for function in functions:
            self.compare('NFQWS_ARGS_QUIC="--quic"\n', function)

    def test_source_error_timeout_and_empty_output(self):
        for text in ('exit 7\n', '"unterminated\n'):
            self.compare(text)
        self.compare('', '_startup_args() {\n # NFQWS_ARGS_QUIC\n :\n}\n')
        self.conf.write_text('sleep 1\n')
        with self.assertRaises(compose.ComposeError):
            compose.compose(str(self.conf), self.paths, dict(os.environ), .05)
        self.assertEqual(list(Path(self.paths.work_tmp_root).iterdir()), [])

    def test_missing_config_is_an_error_and_work_root_is_created(self):
        self.assertFalse(Path(self.paths.work_tmp_root).exists())
        with self.assertRaises(compose.ComposeError):
            compose.compose(str(self.conf), self.paths, dict(os.environ), 3)
        self.assertTrue(Path(self.paths.work_tmp_root).is_dir())
        self.assertEqual(list(Path(self.paths.work_tmp_root).iterdir()), [])

    def test_signal_removes_work_directory_and_child(self):
        self.conf.write_text('sleep 30\n')
        script = ('from kdn.engine import compose, config, lifecycle\n'
                  'import os, sys\n'
                  'lifecycle.install_signal_handlers()\n'
                  'try:\n'
                  ' compose.compose(sys.argv[1], config.EnginePaths.from_environ(os.environ), os.environ, 40)\n'
                  'finally:\n'
                  ' lifecycle.run_cleanups()\n')
        env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1',
                   PYTHONPATH=str(engine_shell.ROOT / 'tools/router'))
        process = subprocess.Popen([sys.executable, '-c', script, str(self.conf)], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                work = Path(self.paths.work_tmp_root)
                if work.exists() and list(work.iterdir()):
                    break
                time.sleep(.02)
            else:
                self.fail('compose did not create its work directory')
            os.killpg(process.pid, signal.SIGTERM)
            _out, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130, err)
            self.assertEqual(list(work.iterdir()), [])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)

"""Strict Lua initialization, with pinned x86 runtime; never attaches NFQUEUE."""
import gzip
import os
from pathlib import Path
import sys
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from kdn.engine import lifecycle, nfqws_process, nfqws_validate as validate
from kdn.engine import config


class BoundedProcessTests(unittest.TestCase):
    def test_stdout_eof_waits_for_exit_but_not_past_deadline(self):
        for pause, timeout, expected in ((0.05, 2, 0), (30, 0.1, 124)):
            with self.subTest(pause=pause):
                code = f'import os,time; os.close(1); os.close(2); time.sleep({pause})'
                started = time.monotonic()
                done = nfqws_process.run([sys.executable, '-c', code], os.environ, timeout=timeout)
                self.assertEqual(done.returncode, expected)
                self.assertEqual(done.timed_out, expected == 124)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(lifecycle._children, [])

    def test_success_spawn_error_and_cwd(self):
        done = nfqws_process.run([sys.executable, '-c', 'import os; print(os.getcwd())'],
                                os.environ, cwd='/tmp')
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.output.strip(), '/tmp')
        self.assertFalse(done.timed_out)
        missing = nfqws_process.run(['/no/such/executable'], os.environ)
        self.assertEqual(missing.returncode, 127)
        self.assertEqual(lifecycle._children, [])

    def test_timeout_and_output_limit_are_failures_and_reaped(self):
        started = time.monotonic()
        done = nfqws_process.run([sys.executable, '-c', 'import time; time.sleep(30)'],
                                os.environ, timeout=0.1)
        self.assertTrue(done.timed_out)
        self.assertLess(time.monotonic() - started, 3)
        done = nfqws_process.run([sys.executable, '-c', 'print("x"*1000000)'],
                                os.environ, output_limit=1024)
        self.assertTrue(done.output_limited)
        self.assertEqual(len(done.output.encode()), 1024)
        self.assertEqual(lifecycle._children, [])

    def test_invalid_budgets_rejected_before_spawn(self):
        for values in ({'timeout': 0}, {'timeout': 121}, {'output_limit': 1}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                nfqws_process.run(['/no/command'], os.environ, **values)

    def test_lifecycle_term_cancels_and_reaps_validation_child(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / 'child.pid'
            child_code = 'import os,time,pathlib; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); time.sleep(30)'
            driver = ('import os,sys; from kdn.engine import lifecycle,nfqws_process; '
                      'lifecycle.install_signal_handlers(); nfqws_process.run('
                      '[sys.executable,"-c",' + repr(child_code) + '],os.environ,timeout=30)')
            driver_env = {**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)}
            process = subprocess.Popen([sys.executable, '-c', driver], env=driver_env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            child_pid = None
            try:
                deadline = time.monotonic() + 5
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(pidfile.exists())
                child_pid = int(pidfile.read_text())
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=6), 130)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_grandchild_pipe_does_not_hold_result_past_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / 'grandchild.pid'
            code = ('import os,time,pathlib; p=os.fork(); '
                    'pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(p)) if p else time.sleep(30)')
            started = time.monotonic()
            try:
                done = nfqws_process.run([sys.executable, '-c', code], os.environ, timeout=0.2)
                self.assertTrue(done.timed_out)
                self.assertLess(time.monotonic() - started, 2)
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


class StrictAssetTests(unittest.TestCase):
    def test_gzip_fallback_bounded_and_fifo_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'lib.lua'
            path.with_suffix('.lua.gz').write_bytes(gzip.compress(b'content'))
            self.assertEqual(validate._read_asset(str(path), 100), b'content')
            with self.assertRaises(validate.ValidationError):
                validate._read_asset(str(path), 3)
            bomb = Path(folder) / 'bomb.gz'
            bomb.write_bytes(gzip.compress(b'x' * 10000))
            with self.assertRaises(validate.ValidationError):
                validate._read_asset(str(bomb), 100)
            fifo = Path(folder) / 'fifo'
            os.mkfifo(fifo)
            started = time.monotonic()
            with self.assertRaises(validate.ValidationError):
                validate._read_asset(str(fifo), 100)
            self.assertLess(time.monotonic() - started, 1)

    def test_unregistered_blob_fails_before_process_or_binary_read(self):
        with mock.patch.object(nfqws_process, 'run', side_effect=AssertionError('spawned')):
            with self.assertRaisesRegex(validate.ValidationError, 'unknown-blob'):
                validate.validate_tokens(['--lua-desync=fake:blob=missing'], '/missing', {})
            with self.assertRaisesRegex(validate.ValidationError, 'required Lua blob'):
                validate.validate_tokens(['--lua-desync=fake'], '/missing', {})
            with self.assertRaisesRegex(validate.ValidationError, 'argument budget'):
                validate.validate_tokens(['--comment=x'] * 8193, '/missing', {})

    def test_arbitrary_success_marker_executable_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'fake-nfqws2'
            binary.write_text('#!/bin/sh\nprintf "no intercept quit\\n"\n')
            binary.chmod(0o755)
            with mock.patch.object(nfqws_process, 'run', side_effect=AssertionError('spawned')):
                with self.assertRaisesRegex(validate.ValidationError, 'binary hash mismatch'):
                    validate.validate_tokens([], binary, os.environ)

    def test_test_asset_overrides_are_ignored_without_testroot(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / 'candidate.conf'
            conf.write_text('NFQWS_ARGS=""\n')
            paths = config.EnginePaths.from_environ({})
            tokens = ['--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua']
            composition = type('Composition', (), {'tokens': tokens})()
            ctx = type('Context', (), {'paths': paths, 'environ': {
                'KD_TEST_NFQWS2_BIN': '/redirected/fake', 'KD_TEST_NFQWS2_LUA_SRC': '/redirected/lua'}})()
            with mock.patch.object(validate.compose, 'compose', return_value=composition), \
                    mock.patch.object(validate.checks, '_composition_lines', return_value=([], 0)), \
                    mock.patch.object(validate.checks, 'header_lines', return_value=[]), \
                    mock.patch.object(validate, 'validate_tokens') as checked:
                validate.validate_config(ctx, str(conf))
            self.assertEqual(checked.call_args.args[0], tokens)
            self.assertEqual(checked.call_args.args[1], paths.nfqws_bin)


class PinnedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path(os.environ.get('NFQWS_TEST_RUNTIME', '/var/cache/kdn/nfqws2-blobs/runtime'))
        if not (cls.runtime / 'nfqws2').is_file():
            if 'NFQWS_TEST_RUNTIME' in os.environ:
                raise AssertionError('configured pinned nfqws runtime is missing')
            raise unittest.SkipTest('pinned nfqws runtime not provisioned; use fetch-nfqws2-runtime.sh')

    def tokens(self, *extra):
        return ['--lua-init=@' + str(self.runtime / 'zapret-lib.lua'),
                '--lua-init=@' + str(self.runtime / 'zapret-antidpi.lua'),
                '--filter-tcp=443', *extra]

    def run_validation(self, tokens, **kwargs):
        return validate.validate_tokens(tokens, self.runtime / 'nfqws2', os.environ,
                                        expected_binary_sha256=validate.PINNED_X86_SHA256, **kwargs)

    def test_real_lua_accepts_builtin_and_intercept_is_always_zero(self):
        result = self.run_validation(self.tokens('--lua-desync=fake:blob=fake_default_tls',
                                                '--dry-run', '--qnum=123', '--intercept=1', '--daemon'))
        self.assertIn('--intercept=0', result.argv)
        self.assertNotIn('--dry-run', result.argv)
        self.assertNotIn('--qnum=123', result.argv)
        self.assertNotIn('--intercept=1', result.argv)
        self.assertNotIn('--daemon', result.argv)
        self.assertIn('no intercept quit', result.output)
        self.assertEqual(lifecycle._children, [])

    def test_unprivileged_identity_not_forced_and_control_chars_rejected(self):
        with mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch.object(nfqws_process, 'run', return_value=nfqws_process.ProcessResult(0, 'no intercept quit')):
            result = self.run_validation(self.tokens('--uid=123:123', '--user=nobody'))
        self.assertFalse(any(arg.startswith(('--uid=', '--user=')) for arg in result.argv))
        for suffix in ('\0', '\r', '\n'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(validate.ValidationError, 'control character'):
                self.run_validation(self.tokens('--filter-tcp=443' + suffix))

    def test_real_lua_catches_function_error_not_seen_by_dry_run(self):
        dry_run = nfqws_process.run([str(self.runtime / 'nfqws2'), '--dry-run', '--qnum=0',
                                    *self.tokens('--lua-desync=nonexistent_function')], os.environ)
        self.assertEqual(dry_run.returncode, 0)
        with self.assertRaisesRegex(validate.ValidationError, 'Lua validation failed'):
            self.run_validation(self.tokens('--lua-desync=nonexistent_function'))

    def test_real_lua_inline_declared_and_stock_strategy_vectors(self):
        for strategy in (
            '--lua-desync=fake:blob=custom:repeats=6',
            '--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=fake_default_tls',
            '--lua-desync=hostfakesplit:host=example.org:midhost=midsld',
        ):
            with self.subTest(strategy=strategy):
                result = self.run_validation(self.tokens('--blob=custom:0x00112233', strategy))
                self.assertIn('no intercept quit', result.output)

    def test_hash_mismatch_inline_lua_and_missing_files_fail_before_spawn(self):
        with mock.patch.object(nfqws_process, 'run', side_effect=AssertionError('spawned')):
            with self.assertRaisesRegex(validate.ValidationError, 'binary hash'):
                validate.validate_tokens(self.tokens(), self.runtime / 'nfqws2', os.environ,
                                         expected_binary_sha256='0' * 64)
            with self.assertRaisesRegex(validate.ValidationError, 'inline Lua'):
                self.run_validation(self.tokens('--lua-init=error("oops")'))
            with self.assertRaisesRegex(validate.ValidationError, 'unreadable'):
                self.run_validation(self.tokens('--blob=missing:@/no/such/blob'))
            with self.assertRaisesRegex(validate.ValidationError, 'unapproved Lua'):
                self.run_validation(self.tokens(), expected_lua_sha256={})

    def test_sanitized_current_config_composes_gzip_sources_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': folder, 'KD_ALLOW_TEST_ROOT': '1'})
            base = Path(folder) / 'opt/etc/nfqws2'
            for name in ('lua', 'lists', 'blobs'):
                (base / name).mkdir(parents=True, exist_ok=True)
            for name in validate.PINNED_LUA_SHA256:
                (base / 'lua' / (name + '.gz')).write_bytes(gzip.compress((self.runtime / name).read_bytes()))
            stock = self.runtime.parent
            for name in ('tls_clienthello.bin', 'quic_initial.bin'):
                (base / 'blobs' / name).write_bytes((stock / name).read_bytes())
            project = Path(__file__).resolve().parents[1]
            (base / 'blobs/discord_udp.bin').write_bytes((project / 'config/blobs/ACTIVE_DISCORD_UDP.bin').read_bytes())
            for name in ('user.list', 'youtube.list'):
                (base / 'lists' / name).write_text('example.org\n')
            source = (project / 'tests/fixtures/engine/current-nfqws-20261101.conf').read_bytes()
            Path(paths.nfqws_conf).write_bytes(source)
            Path(paths.nfqws_bin).parent.mkdir(parents=True, exist_ok=True)
            Path(paths.nfqws_bin).symlink_to(self.runtime / 'nfqws2')
            ctx = type('Context', (), {'paths': paths, 'environ': dict(os.environ)})()
            result = validate.validate_config(ctx, paths.nfqws_conf)
            self.assertIn('no intercept quit', result.output)
            self.assertEqual(Path(paths.nfqws_conf).read_bytes(), source)
            self.assertEqual(len(result.inventory.declarations), 4)
            # Disposable roots can use reviewed external runtime assets without
            # copying an architecture-incompatible fixture binary into place.
            ctx.environ.update({'KD_TEST_NFQWS2_BIN': str(self.runtime / 'nfqws2'),
                                'KD_TEST_NFQWS2_LUA_SRC': str(self.runtime)})
            Path(paths.nfqws_bin).unlink()
            result = validate.validate_config(ctx, paths.nfqws_conf)
            self.assertEqual(result.argv[0], str(self.runtime / 'nfqws2'))
            self.assertIn('--lua-init=@' + str(self.runtime / 'zapret-lib.lua'), result.argv)
            self.assertEqual(Path(paths.nfqws_conf).read_bytes(), source)
            fake = Path(folder) / 'fake'
            fake.write_text('#!/bin/sh\nprintf "no intercept quit\\n"\n')
            fake.chmod(0o755)
            ctx.environ['KD_TEST_NFQWS2_BIN'] = str(fake)
            with self.assertRaisesRegex(validate.ValidationError, 'binary hash mismatch'):
                validate.validate_config(ctx, paths.nfqws_conf)


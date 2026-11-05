"""Service init capture must finish on init exit while its daemon owns stdout."""
import os
import errno
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from kdn.engine import lifecycle, nfqws_process


class ServiceProcessTests(unittest.TestCase):
    def test_enosys_uses_zero_storage_without_hiding_exit_or_timeout(self):
        with mock.patch.object(nfqws_process, '_memfd', side_effect=OSError(errno.ENOSYS, 'unsupported')):
            nfqws_process.service_capture_ready()
            for code, expected, timed_out in (
                    ('import os; os.write(1,b"x"*2000000); os.write(2,b"y"*2000000)', 0, False),
                    ('import sys; print("error"); sys.exit(7)', 7, False),
                    ('import time; time.sleep(10)', 124, True)):
                with self.subTest(code=code):
                    result = nfqws_process.run_service([sys.executable, '-c', code], os.environ,
                                                       timeout=0.3, output_limit=1024)
                    self.assertEqual(result.returncode, expected)
                    self.assertEqual(result.timed_out, timed_out)
                    self.assertEqual(result.capture_mode, 'discarded')
                    self.assertEqual(result.output, '')
                    self.assertEqual(lifecycle._children, [])

    def test_enosys_daemon_can_write_after_init_and_capture_close(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile, release, finished = (Path(folder) / name for name in ('pid', 'release', 'finished'))
            code = '\n'.join((
                'import os,pathlib,time,signal', 'pid=os.fork()',
                'if pid: pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(pid))',
                'else:', ' signal.signal(signal.SIGPIPE,signal.SIG_DFL)',
                ' while not pathlib.Path(' + repr(str(release)) + ').exists(): time.sleep(.01)',
                ' for _ in range(10): os.write(1,b"x"*1000000)',
                ' pathlib.Path(' + repr(str(finished)) + ').write_text("alive")',
            ))
            try:
                with mock.patch.object(nfqws_process, '_memfd', side_effect=OSError(errno.ENOSYS, 'unsupported')):
                    started = time.monotonic()
                    result = nfqws_process.run_service([sys.executable, '-c', code], os.environ, timeout=2)
                self.assertEqual(result.returncode, 0)
                self.assertLess(time.monotonic()-started, 1.5)
                release.touch()
                deadline = time.monotonic()+3
                while not finished.exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue(finished.exists(), 'discard must not send SIGPIPE or block daemon')
            finally:
                if pidfile.exists():
                    try: os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError: pass

    def test_discard_refuses_non_device_and_unavailable_sink(self):
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno())
            with mock.patch.object(os, 'open', return_value=fd), self.assertRaises(OSError):
                nfqws_process._null_capture()
            with self.assertRaises(OSError): os.fstat(fd)
        with mock.patch.object(nfqws_process, '_memfd', side_effect=OSError(errno.ENOSYS, 'unsupported')), \
                mock.patch.object(nfqws_process, '_null_capture', side_effect=OSError('no sink')), \
                mock.patch.object(subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'safe service'):
                nfqws_process.run_service(['/no/init'], os.environ)
            spawn.assert_not_called()

    def test_init_exit_does_not_wait_for_background_stdout_or_cause_sigpipe(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pidfile, release, finished = (root / name for name in ('pid', 'release', 'finished'))
            code = '\n'.join((
                'import os, pathlib, signal, time',
                'pid = os.fork()',
                'if pid:',
                '    pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(pid))',
                '    print("init completed", flush=True)',
                'else:',
                '    signal.signal(signal.SIGPIPE, signal.SIG_DFL)',
                '    while not pathlib.Path(' + repr(str(release)) + ').exists(): time.sleep(0.01)',
                '    os.write(1, b"daemon alive\\n")',
                '    pathlib.Path(' + repr(str(finished)) + ').write_text("ok")',
            ))
            started = time.monotonic()
            try:
                done = nfqws_process.run_service([sys.executable, '-c', code], os.environ, timeout=1)
                self.assertEqual(done.returncode, 0)
                self.assertFalse(done.timed_out)
                self.assertIn('init completed', done.output)
                self.assertLess(time.monotonic() - started, 0.9)
                release.touch()
                deadline = time.monotonic() + 3
                while not finished.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(finished.exists(), 'daemon must survive inherited stdout write')
                self.assertEqual(lifecycle._children, [])
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_service_timeout_output_ceiling_error_and_cwd(self):
        for code, budget, expected, timeout, limited in (
                ('import time; time.sleep(10)', 0.1, 124, True, False),
                ('import os; os.write(1, b"x" * 1025)', 2, 0, False, True),
                ('import sys; print("busy"); sys.exit(1)', 2, 1, False, False),
                ('import os; print(os.getcwd())', 2, 0, False, False)):
            with self.subTest(code=code):
                done = nfqws_process.run_service([sys.executable, '-c', code], os.environ,
                                                 timeout=budget, output_limit=1024, cwd='/tmp')
                if expected is not None:
                    self.assertEqual(done.returncode, expected)
                self.assertEqual(done.timed_out, timeout)
                self.assertEqual(done.output_limited, limited)
                self.assertLessEqual(len(done.output.encode()), 1024)
                self.assertEqual(lifecycle._children, [])
        self.assertEqual(nfqws_process.run_service(['/no/such/init'], os.environ).returncode, 127)

    def test_service_cancellation_reaps_owned_init(self):
        for discarded in (False, True):
            with self.subTest(discarded=discarded):
                self._assert_service_cancellation(discarded)

    def _assert_service_cancellation(self, discarded):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / 'pid'
            child = 'import os,time,pathlib; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); time.sleep(30)'
            driver = ('import os,sys; from kdn.engine import lifecycle,nfqws_process; '
                      + ('import errno; from unittest.mock import patch; '
                         'patch.object(nfqws_process,"_memfd",side_effect=OSError(errno.ENOSYS,"unsupported")).start(); '
                         if discarded else '') +
                      'lifecycle.install_signal_handlers(); nfqws_process.run_service('
                      '[sys.executable,"-c",' + repr(child) + '],os.environ,timeout=30)')
            process = subprocess.Popen([sys.executable, '-c', driver],
                env={**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pidfile.exists())
                process.terminate()
                self.assertEqual(process.wait(timeout=6), 130)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_unavailable_capture_fails_before_service_spawn(self):
        with mock.patch.object(nfqws_process, '_memfd', side_effect=OSError('unavailable')), \
                mock.patch.object(subprocess, 'Popen') as spawn, \
                self.assertRaisesRegex(RuntimeError, 'memfd'):
            nfqws_process.run_service(['/no/init'], os.environ)
        spawn.assert_not_called()

    def test_inherited_capture_cannot_grow_after_init_returns(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pidfile, release, finished = (root / name for name in ('pid', 'release', 'finished'))
            code = '\n'.join((
                'import os, pathlib, time', 'pid = os.fork()',
                'if pid:',
                '    pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(pid))',
                '    os.write(1, b"init")',
                'else:',
                '    while not pathlib.Path(' + repr(str(release)) + ').exists(): time.sleep(0.01)',
                '    position = os.lseek(1, 0, os.SEEK_CUR)',
                '    try:', '        os.write(1, b"x" * 100000)',
                '        os.write(1, b"overflow")',
                '    except OSError: pass',
                '    pathlib.Path(' + repr(str(finished)) + ').write_text(str(position) + ":" + str(os.fstat(1).st_size))',
            ))
            try:
                done = nfqws_process.run_service([sys.executable, '-c', code], os.environ,
                                                 timeout=2, output_limit=1024)
                self.assertEqual(done.output, 'init')
                self.assertFalse(done.output_limited)
                release.touch()
                deadline = time.monotonic() + 3
                while not finished.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(finished.read_text(), '4:1025')
            finally:
                if pidfile.exists():
                    try: os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError: pass

    def test_oversized_single_write_reports_init_error_without_faking_capture(self):
        done = nfqws_process.run_service([sys.executable, '-c',
            'import os; os.write(1, b"x" * 65536)'], os.environ, output_limit=1024)
        self.assertNotEqual(done.returncode, 0)
        self.assertLessEqual(len(done.output.encode()), 1024)
        self.assertFalse(done.timed_out)

    def test_os_wrapper_path_and_sealing_failure_close_capture(self):
        import fcntl
        fd = nfqws_process._memfd()
        with mock.patch.object(os, 'memfd_create', create=True, return_value=fd) as create:
            self.assertEqual(nfqws_process._memfd(), fd)
            create.assert_called_once_with('kdn-service-control', 3)
        with mock.patch.object(nfqws_process, '_memfd', return_value=fd), \
                mock.patch.object(fcntl, 'fcntl', side_effect=OSError('seals unavailable')), \
                mock.patch.object(subprocess, 'Popen') as spawn, \
                self.assertRaisesRegex(RuntimeError, 'file seals'):
            nfqws_process.run_service(['/no/init'], os.environ)
        spawn.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_invalid_service_budgets_rejected_before_capture(self):
        with mock.patch.object(nfqws_process, '_memfd') as create:
            for budget in ({'timeout': 0}, {'timeout': 121}, {'output_limit': 100}, {'output_limit': 1048577}):
                with self.subTest(budget=budget), self.assertRaises(ValueError):
                    nfqws_process.run_service(['/no/init'], os.environ, **budget)
        create.assert_not_called()

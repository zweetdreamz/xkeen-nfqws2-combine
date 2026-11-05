"""XKeen2.1 guards, busy-only retries and daemon identity (not node probes)."""
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import apply_files, cli, config, console, options, xkeen_service as service


def done(code=0, output='', timed_out=False, limited=False):
    return SimpleNamespace(returncode=code, output=output, timed_out=timed_out, output_limited=limited)


class XkeenServiceTests(unittest.TestCase):
    def test_discarded_output_does_not_hide_init_failure_or_missing_daemon(self):
        result = service.nfqws_process.ProcessResult(1, '', capture_mode='discarded')
        with mock.patch.object(service.nfqws_process, 'run_service', return_value=result) as run:
            with self.assertRaises(RuntimeError): service.action(self.ctx, 'start', delay=0)
            self.assertEqual(run.call_count, 1, 'no text-based busy retry without captured text')
        result.returncode = 0
        with mock.patch.object(service.nfqws_process, 'run_service', return_value=result), \
                mock.patch.object(service, 'pid', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'runtime'):
                service.action(self.ctx, 'start', delay=0)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.env)
        from target_fixture import version_executable
        self.version_binary = version_executable(self.root / '.target-version-bin/xkeen', 'XKeen 2.1.1')
        self.paths = config.EnginePaths.from_environ(self.env)
        self.init = Path(self.paths.xkeen_init)
        self.init.parent.mkdir(parents=True)
        self.init.write_text('name_client="xray"\npbr_strict="off"\n')
        self.settings = Path(self.paths.xkeen_json)
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text('{"xkeen":{"rci_token":"NEVER-LOG-TOKEN"}}')
        parsed = options.parse_args(['--apply', '--yes-router'])
        self.ctx = cli.Context([], self.env, console.Console(io.StringIO(), io.StringIO()), paths=self.paths,
                               options=parsed, resolved=options.resolve(parsed, ''))

    def test_actual_version_and_missing_ambiguous_token(self):
        with mock.patch.object(service.nfqws_process, 'run', return_value=done(output='XKeen 2.1.1')):
            with mock.patch.object(service, 'read_policies', return_value=[]) as read:
                self.assertEqual(service.preflight(self.ctx), '2.1.1')
                read.assert_called_once_with(self.ctx, 'NEVER-LOG-TOKEN')
                for value in ({}, {'rci_token': ''}, {'rci_token': 'bad\nvalue'},
                              {'a': {'rci_token': 'x'}, 'b': {'rci_token': 'x'}}):
                    self.settings.write_text(json.dumps(value))
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        service.preflight(self.ctx)
        for output in ('XKeen 2.0', 'XKeen 3.0', '2.1', 'XKeen 2.1\nXKeen 2.2'):
            from target_fixture import version_executable
            version_executable(self.version_binary, output)
            with mock.patch.object(service.nfqws_process, 'run', return_value=done(output=output)):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, '2.1'):
                    service.preflight(self.ctx)

    def test_pbr_strict_validates_prospective_outbound_marks_including_direct(self):
        self.init.write_text('name_client="xray"\npbr_strict="on"\n')
        raw = lambda mark: json.dumps({'outbounds': [{'protocol': 'vless', 'streamSettings': {'sockopt': {'mark': mark}}}]}).encode()
        with mock.patch.object(service.nfqws_process, 'run', return_value=done(output='XKeen 2.1.1')):
            with mock.patch.object(service, 'read_policies', return_value=[{'mark': '0x123'}]):
                for mark in (None, 255, '291', True, 2147483648):
                    plan = apply_files.Plan((), (('04_outbounds.json', raw(mark), 0o600),))
                    with self.subTest(mark=mark), self.assertRaises(ValueError):
                        service.preflight(self.ctx, plan=plan)
                plan = apply_files.Plan((), (('04_outbounds.json', raw(291), 0o600),))
                self.assertEqual(service.preflight(self.ctx, plan=plan), '2.1.1')
        self.assertEqual(service.policy_marks([{'mark': 'ff'}, {'mark': 'deadbeef'}, {'mark': '0x123'}]), {291})

    def test_busy_only_retry_foreground_and_new_pid(self):
        with mock.patch.object(service.nfqws_process, 'run_service', side_effect=[done(1, 'Занят другим процессом'), done()]) as run:
            with mock.patch.object(service, 'pid', side_effect=[10, 11]):
                service.action(self.ctx, 'restart', delay=0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], [self.paths.xkeen_init, 'restart', 'on'])
        with mock.patch.object(service.nfqws_process, 'run_service', return_value=done(1, 'configuration failure')) as run:
            with mock.patch.object(service, 'pid', return_value=10):
                with self.assertRaises(RuntimeError):
                    service.action(self.ctx, 'restart', delay=0)
            self.assertEqual(run.call_count, 1)
        with mock.patch.object(service.nfqws_process, 'run_service', return_value=done()):
            with mock.patch.object(service, 'pid', return_value=10):
                with self.assertRaises(RuntimeError):
                    service.action(self.ctx, 'restart', delay=0)

    def test_pid_ignores_probe_and_rejects_duplicate_daemons(self):
        proc = self.root / 'proc'
        for pid, folder in ((12, '/probe'), (13, self.paths.xray_config_dir), (14, self.paths.xray_config_dir)):
            path = proc / str(pid) / 'cmdline'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'xray\0run\0-confdir\0' + folder.encode() + b'\0')
        with mock.patch.object(service.system, 'PROC_ROOT', str(proc)):
            with mock.patch.object(service.system, 'run', return_value=SimpleNamespace(returncode=0, timed_out=False, stdout='12 13')):
                self.assertEqual(service.pid(self.ctx), 13)
            with mock.patch.object(service.system, 'run', return_value=SimpleNamespace(returncode=0, timed_out=False, stdout='13 14')):
                with self.assertRaises(RuntimeError):
                    service.pid(self.ctx)

    def test_rcI_transport_has_no_proxy_redirect_or_argv_token(self):
        import urllib.request
        class Response:
            status = 200
            payload = b'[]'
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read1(self, maximum):
                data, self.payload = self.payload, b''
                return data
        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.object(urllib.request, 'build_opener', return_value=opener) as build:
            self.assertEqual(service.read_policies(self.ctx, 'TOKEN'), [])
            self.assertEqual(build.call_args.args[0].proxies, {})
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'http://127.0.0.1:79/rci/show/ip/policy')
            self.assertEqual(request.get_header('X-ndma-tkn'), 'TOKEN')

    def test_capture_capability_preflight_refuses_before_other_work(self):
        with mock.patch.object(service.nfqws_process, '_memfd', side_effect=OSError('unavailable')), \
                mock.patch.object(service.xkeen, 'require') as require, \
                mock.patch.object(service.snapshot_store, '_read') as read, \
                self.assertRaisesRegex(RuntimeError, 'memfd'):
            service.preflight(self.ctx)
        require.assert_not_called()
        read.assert_not_called()

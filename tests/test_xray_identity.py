"""Synthetic proc identity shared by service lifecycle and VPN node switching."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from kdn.common import xray_process
from kdn.engine import xkeen_service

from tools.router import vpn_node_manager


class XrayIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / '42'
        self.directory.mkdir()
        self.confdir = '/own/config'

    def identity(self, args, env=b'XRAY_LOCATION_CONFDIR=/own/config\0', pid='42'):
        (self.directory / 'cmdline').write_bytes(b'\0'.join(item.encode() for item in args) + b'\0')
        if env is not None:
            (self.directory / 'environ').write_bytes(env)
        return xray_process.xray_identity(pid, self.confdir, proc_root=self.root)

    def test_upstream_env_daemon_is_shared_by_both_consumers(self):
        self.identity(['xray', 'run'])
        manager = vpn_node_manager.VpnNodeManager(proc_root=self.root, xray_dir=self.confdir)
        ctx = SimpleNamespace(environ={}, paths=SimpleNamespace(xray_config_dir=self.confdir))
        with mock.patch.object(xkeen_service.system, 'PROC_ROOT', str(self.root)), \
                mock.patch.object(xkeen_service.system, 'run', return_value=SimpleNamespace(
                    returncode=0, timed_out=False, stdout='42')):
            self.assertEqual(xkeen_service.pid(ctx), 42)
        self.assertTrue(manager._owns_xray_pid('42'))

    def test_all_confdir_argv_forms_take_precedence_over_environment(self):
        for flag in ('-confdir', '--confdir'):
            for args in ([flag, self.confdir], [flag + '=' + self.confdir]):
                with self.subTest(args=args):
                    self.assertTrue(self.identity(['/opt/sbin/xray', 'run', *args],
                                                  b'XRAY_LOCATION_CONFDIR=/other\0'))
                    self.assertFalse(self.identity(['xray', 'run', *[arg.replace(self.confdir, '/other') for arg in args]]))
        self.assertTrue(self.identity(['xray', 'run', '-confdir', self.confdir], env=None))

    def test_rejects_wrong_command_probes_and_ambiguous_flags(self):
        for args in (['python3', 'run', '-confdir', self.confdir],
                     ['xray', 'version', '-confdir', self.confdir],
                     ['xray', 'help'], ['xray', 'run', '-confdir'],
                     ['xray', 'run', '-c', '/probe.json'],
                     ['xray', 'run', '--c', '/probe.json'],
                     ['xray', 'run', '--c=/probe.json'],
                     ['xray', 'run', '--config=/probe.json'],
                     ['xray', 'run', '-confdir', self.confdir, '--confdir=/other'],
                     ['xray', 'run', '-confdir', self.confdir, '-confdir', self.confdir]):
            with self.subTest(args=args):
                self.assertFalse(self.identity(args))
        for flag in ('-test', '--test', '-test=true', '--test=false', '-dump', '--dump',
                     '-dump=false', '-version', '--version', '-help', '--help', '-h'):
            with self.subTest(flag=flag):
                self.assertFalse(self.identity(['xray', 'run', flag, '-confdir', self.confdir]))

    def test_rejects_incomplete_oversized_unreadable_or_ambiguous_identity(self):
        for raw in (b'xray\0run', b'xray\0run\0' + b'x' * 65536, b'xray\0\0run\0'):
            self.identity(['xray', 'run'])
            (self.directory / 'cmdline').write_bytes(raw)
            self.assertFalse(xray_process.xray_identity('42', self.confdir, proc_root=self.root))
        for env in (b'', b'XRAY_LOCATION_CONFDIR=/own/config',
                    b'XRAY_LOCATION_CONFDIR=/own/config\0XRAY_LOCATION_CONFDIR=/other\0',
                    b'XRAY_LOCATION_CONFDIR=/own/config\0' + b'x' * 65536):
            with self.subTest(length=len(env)):
                self.assertFalse(self.identity(['xray', 'run'], env))
        (self.directory / 'environ').unlink()
        self.assertFalse(self.identity(['xray', 'run'], env=None))
        for pid in ('0', '1', '-42', '../42', '2147483648', '00042'):
            self.assertFalse(xray_process.xray_identity(pid, self.confdir, proc_root=self.root))

    def test_duplicate_upstream_daemons_refused_by_both_consumers(self):
        self.identity(['xray', 'run'])
        other = self.root / '43'
        other.mkdir()
        (other / 'cmdline').write_bytes(b'xray\0run\0')
        (other / 'environ').write_bytes(b'XRAY_LOCATION_CONFDIR=/own/config\0')
        manager = vpn_node_manager.VpnNodeManager(proc_root=self.root, xray_dir=self.confdir)
        with mock.patch.object(vpn_node_manager.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='42 43')), \
                self.assertRaises(RuntimeError):
            manager._xray_pids()
        ctx = SimpleNamespace(environ={}, paths=SimpleNamespace(xray_config_dir=self.confdir))
        with mock.patch.object(xkeen_service.system, 'PROC_ROOT', str(self.root)), \
                mock.patch.object(xkeen_service.system, 'run', return_value=SimpleNamespace(returncode=0, timed_out=False, stdout='42 43')), \
                self.assertRaises(RuntimeError):
            xkeen_service.pid(ctx)

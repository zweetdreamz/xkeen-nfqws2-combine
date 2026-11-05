"""Full native apply: real file transactions and snapshots, mocked router services."""
from contextlib import ExitStack
import io
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import apply_dependencies, apply_files, apply_nfqws, apply_ops, cli, config, console
from kdn.engine import nfqws_service, nfqws_validate, options, relay_restore, rollback_ops, snapshot_store, xkeen_service


class NativeApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.env)
        from target_fixture import version_executable
        version_executable(self.root / '.target-version-bin/xkeen', 'XKeen 2.1.1')
        self.paths = config.EnginePaths.from_environ(self.env)
        source = Path(__file__).parent / 'fixtures/engine/nfqws-neutral'
        shutil.copytree(source, Path(self.paths.nfqws_conf).parent)
        self.put('/opt/etc/init.d/S05xkeen', b'name_client="xray"\npbr_strict="off"\nproxy_router="off"\n')
        self.put('/opt/etc/xkeen/xkeen.json', b'{"xkeen":{"rci_token":"fixture-token"}}')
        self.put('/opt/etc/xray/configs/03_inbounds.json', b'{"inbounds":[{"tag":"arbitrary-tproxy","settings":{"followRedirect":true,"allowedNetwork":"tcp,udp"},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}}]}')
        self.vpn = self.put('/opt/etc/xray/configs/04_outbounds.json', b'{"outbounds":[{"tag":"vpn","protocol":"vless","settings":{"secret":"KEEP"}}]}')
        self.routing = self.put('/opt/etc/xray/configs/05_routing.json', b'{"routing":{"rules":[]}}')
        self.put('/opt/etc/xkeen/port_proxying.lst', b'#USER\n1234\n')
        self.put('/opt/etc/xkeen/port_exclude.lst', b'22\n')
        Path(self.paths.work_tmp_root).mkdir(parents=True)
        self.out, self.err = io.StringIO(), io.StringIO()
        argv = ['--apply', '--discord-route', 'direct', '--youtube-route', 'vless', '--yes-router']
        parsed = options.parse_args(argv)
        self.ctx = cli.Context(argv, self.env, console.Console(self.out, self.err), paths=self.paths,
                               options=parsed, resolved=options.resolve(parsed, ''))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(xkeen_service, 'read_policies', return_value=[]))
        self.stack.enter_context(mock.patch.object(xkeen_service.nfqws_process, 'run_service',
            return_value=SimpleNamespace(returncode=0, timed_out=False, output_limited=False, output='XKeen2.1.1')))
        self.stack.enter_context(mock.patch.object(rollback_ops, 'package_version', return_value='1'))
        self.stack.enter_context(mock.patch.object(rollback_ops, 'xkeen_version', return_value='2.1.1'))
        self.stack.enter_context(mock.patch.object(apply_ops.system, 'have', return_value=True))
        def wan(_paths, _env, _request, state):
            state.wan, state.ipv6 = 'eth3', '0'
        self.stack.enter_context(mock.patch.object(apply_ops.preflight_wan, 'check', side_effect=wan))
        self.xray_check = self.stack.enter_context(mock.patch.object(apply_files, 'validate_staged'))
        self.nfqws_stage = self.stack.enter_context(mock.patch.object(apply_nfqws, 'validate_staged'))
        self.nfqws_check = self.stack.enter_context(mock.patch.object(nfqws_validate, 'validate_config'))
        self.stack.enter_context(mock.patch.object(nfqws_service, 'pid', return_value=None))
        self.stack.enter_context(mock.patch.object(nfqws_service, 'action'))
        self.stack.enter_context(mock.patch.object(nfqws_service, 'restore_state'))
        self.nfqws_restart = self.stack.enter_context(mock.patch.object(nfqws_service, 'restart'))
        self.xkeen_action = self.stack.enter_context(mock.patch.object(xkeen_service, 'action'))
        self.stack.enter_context(mock.patch.object(xkeen_service, 'pid', return_value=123))
        self.stack.enter_context(mock.patch.object(rollback_ops, '_xkeen_state'))
        self.stack.enter_context(mock.patch.object(apply_ops.preflight_xray, 'xray_test_config', return_value=None))
        self.stack.enter_context(mock.patch.object(apply_dependencies, 'install_packages'))
        self.stack.enter_context(mock.patch.object(relay_restore, 'reconcile'))

    def put(self, logical, data):
        path = Path(config.list_path(logical, self.paths.test_root))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o640)
        return path

    def test_apply_commits_preserves_global_vpn_and_immutable_baseline(self):
        vpn, old_config = self.vpn.read_bytes(), Path(self.paths.nfqws_conf).read_bytes()
        self.assertEqual(apply_ops.run(self.ctx), 0, self.err.getvalue())
        first = Path(self.paths.baseline_pointer).read_bytes()
        self.assertEqual(self.vpn.read_bytes(), vpn)
        self.assertNotEqual(Path(self.paths.nfqws_conf).read_bytes(), old_config)
        self.assertIn(b'kdn-disabled.invalid', Path(self.paths.nfqws_list).read_bytes())
        self.assertIn(b'DiscordTCP=direct', Path(self.paths.nfqws_conf).read_bytes())
        self.assertEqual(self.xkeen_action.call_args, mock.call(self.ctx, 'restart'))
        self.nfqws_restart.assert_called_once_with(self.ctx)
        self.assertIn('RESULT|ok', self.out.getvalue())
        stages = [line for line in self.out.getvalue().splitlines() if line.startswith('STAGE|')]
        self.assertEqual(stages, ['STAGE|preflight', 'STAGE|snapshot', 'STAGE|config',
                                  'STAGE|xray', 'STAGE|nfqws', 'STAGE|verify'])
        self.assertFalse(Path(self.paths.lock_dir).exists())
        self.assertEqual(apply_ops.run(self.ctx), 0, self.err.getvalue())
        self.assertEqual(Path(self.paths.baseline_pointer).read_bytes(), first)
        saved = snapshot_store.verify(Path(self.paths.latest_pointer).read_text().strip())
        rollback_ops.validate_auxiliary(saved)

    def test_failed_restart_restores_configs_runtime_pointers_and_mode(self):
        before_config, before_route = Path(self.paths.nfqws_conf).read_bytes(), self.routing.read_bytes()
        self.put('/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr', b'previous-pointer\n')
        self.xkeen_action.side_effect = RuntimeError('injected restart failure')
        self.assertEqual(apply_ops.run(self.ctx), 1)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), before_config)
        self.assertEqual(self.routing.read_bytes(), before_route)
        self.assertEqual(Path(self.paths.latest_pointer).read_bytes(), b'previous-pointer\n')
        self.assertEqual(self.routing.stat().st_mode & 0o777, 0o640)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_preflight_failure_never_snapshots_or_writes(self):
        self.xray_check.side_effect = ValueError('invalid prospective Xray config')
        before = self.routing.read_bytes()
        self.assertEqual(apply_ops.run(self.ctx), 1)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertFalse(Path(self.paths.snapshot_root).exists())
        self.xkeen_action.assert_not_called()

    def test_native_preflight_needs_no_confirmation_and_has_no_effective_writes(self):
        self.ctx.options.confirmed = False
        before = self.routing.read_bytes()
        self.assertEqual(apply_ops.preflight_run(self.ctx), 0, self.err.getvalue())
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertFalse(Path(self.paths.snapshot_root).exists())
        self.xkeen_action.assert_not_called()

    def test_signal_after_writes_restores_import_pointer_and_returns_130(self):
        before = Path(self.paths.nfqws_conf).read_bytes()
        pointer = self.put('/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr', b'old-import\n')
        self.nfqws_restart.side_effect = SystemExit(130)
        self.assertEqual(apply_ops.run(self.ctx), 130)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), before)
        self.assertEqual(pointer.read_bytes(), b'old-import\n')
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_strict_nfqws_failure_after_package_phase_rolls_back(self):
        before = Path(self.paths.nfqws_conf).read_bytes()
        self.nfqws_stage.side_effect = ValueError('strict Lua failed')
        self.assertEqual(apply_ops.run(self.ctx), 1)
        self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), before)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertFalse(Path(self.paths.latest_pointer).exists())

    def test_old_version_standalone_mihomo_refused_before_snapshot(self):
        for flag in ('old', 'standalone', 'mihomo'):
            with self.subTest(flag=flag):
                self.ctx.resolved.standalone = flag == 'standalone'
                self.ctx.resolved.core_requested = 'mihomo' if flag == 'mihomo' else 'auto'
                with mock.patch.object(xkeen_service.xkeen, 'probe', return_value='' if flag == 'old' else '2.1.1'):
                    self.assertEqual(apply_ops.run(self.ctx), 1)
                self.assertFalse(Path(self.paths.snapshot_root).exists())

    def test_conflicting_direct_mark_fails_before_snapshot_or_any_effective_write(self):
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        for inherited in (False, True):
            if inherited:
                self.ctx.resolved.direct_mark_requested = ''
                self.put('/opt/etc/xray/configs/99_mark.json',
                         b'{"outbounds":[{"protocol":"freedom","streamSettings":{"sockopt":{"mark":1073741825}}}]}')
            else:
                self.ctx.resolved.direct_mark_requested = '1073741824'
            with self.subTest(inherited=inherited):
                self.assertEqual(apply_ops.run(self.ctx), 1)
                self.assertIn('collid', self.err.getvalue())
                for path, data in before.items():
                    self.assertEqual(path.read_bytes(), data)
                self.assertFalse(Path(self.paths.snapshot_root).exists())
                self.xkeen_action.assert_not_called()
                self.nfqws_restart.assert_not_called()

    def test_implicit_zero_collision_fails_before_first_write_without_changing_mark_setting(self):
        conf = Path(self.paths.nfqws_conf)
        conf.write_bytes(conf.read_bytes() + b'\nMARK_PROCESSED="0/0x40000000"\n')
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(self.ctx.resolved.direct_mark_requested, '')
        self.assertEqual(apply_ops.run(self.ctx), 1)
        self.assertIn('collid', self.err.getvalue())
        self.assertEqual(self.ctx.resolved.direct_mark_requested, '')
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertFalse(Path(self.paths.snapshot_root).exists())
        self.xkeen_action.assert_not_called()
        self.nfqws_restart.assert_not_called()

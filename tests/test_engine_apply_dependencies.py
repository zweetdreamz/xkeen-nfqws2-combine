"""E4 port/package/relay primitives; all package/process effects are fake seams."""
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.common import lock
from kdn.engine import apply_dependencies as dep, apply_files, transaction
from test_engine_apply_files import ApplyFilesFixture


class ApplyDependenciesTests(ApplyFilesFixture, unittest.TestCase):
    def test_dependency_port_matrix(self):
        before = b'# user\n1234\n\n'
        for route in ('unmanaged', 'direct', 'vless', 'ws'):
            for high in (50100, 65535):
                with self.subTest(route=route, high=high):
                    result, warnings = dep.render_ports(before, b'590-600\n', voice_high=high, telegram=route)
                    self.assertTrue(result.startswith(b'# user\n1234\n\n'))
                    self.assertIn(f'50000:{high}\n'.encode(), result)
                    self.assertEqual(b'5222\n' in result, route != 'unmanaged')
                    self.assertEqual(b'1400\n' in result, route == 'vless')
                    self.assertNotIn(b'590:600\n', result)
                    self.assertEqual(bool(warnings), route == 'vless')
                    self.assertEqual(dep.render_ports(result, b'590-600\n', voice_high=high, telegram=route)[0], result)
        for unrestricted in (b'', b'# all ports\n'):
            self.assertEqual(dep.render_ports(unrestricted), (unrestricted, ()))

    def test_dependency_bad_port_markers(self):
        begin, end = dep.snapshot_store.BEGIN, dep.snapshot_store.END
        for raw in (b'443\n' + begin + b'\n', b'443\n' + end + b'\n',
                    b'443\n' + begin + b'\n' + begin + b'\n' + end + b'\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                dep.render_ports(raw)

    def test_dependency_prepare_port_feed_preserves_exclusions(self):
        target = __import__('pathlib').Path(self.paths.xkeen_port_proxying)
        target.parent.mkdir(parents=True)
        target.write_bytes(b'# user\n80\n')
        excluded = target.with_name('port_exclude.lst')
        excluded.write_bytes(b'1400\n')
        plan, warnings = dep.prepare_files(self.ctx, self.plan(), telegram='vless')
        self.assertTrue(warnings)
        self.assertEqual(excluded.read_bytes(), b'1400\n')
        self.assertEqual(target.read_bytes(), b'# user\n80\n')
        self.assertEqual({item.logical for item in plan.changes if item.logical in apply_files.EXTRA_FILES},
                         set(apply_files.EXTRA_FILES))
        excluded.write_bytes(b'590-600\n')
        with self.assertRaisesRegex(ValueError, 'dependency changed'):
            apply_files._validate_plan(self.ctx, plan)

    def test_dependency_package_queries_fail_closed(self):
        with mock.patch.object(dep.rollback_ops, 'package_version', side_effect=['', '1', '', '1']):
            self.assertEqual(dep.package_plan(self.ctx), (('install', 'ca-certificates'),
                              ('install', 'nfqws2-keenetic'), ('remove', 'wget-nossl')))
        with mock.patch.object(dep.rollback_ops, 'package_version', side_effect=ValueError('query failed')):
            with self.assertRaises(ValueError):
                dep.package_plan(self.ctx)

    def tx(self):
        tx = transaction.Transaction(self.ctx)
        tx.arm(lambda: None)
        return tx

    def feed(self):
        from pathlib import Path
        path = Path(dep.config.list_path(dep.FEED_PATH, self.paths.test_root))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(dep.FEED)

    def test_dependency_package_allowlist_and_guards_before_commands(self):
        with mock.patch.object(dep, '_run') as runner:
            with self.assertRaises(ValueError):
                dep.install_packages(self.tx(), ())
            with lock.ProjectLock(self.paths.lock_dir):
                for actions in ((('install', 'xkeen'),), (('remove', 'nfqws2-keenetic'),),
                                (('install', 'ca-certificates'),) * 2):
                    with self.subTest(actions=actions), self.assertRaises(ValueError):
                        dep.install_packages(self.tx(), actions)
            runner.assert_not_called()

    def test_dependency_install_verify_and_postinst_stop_on_failed_install(self):
        self.feed()
        good = SimpleNamespace(returncode=0, timed_out=False, output_limited=False, output='')
        bad = SimpleNamespace(returncode=1, timed_out=False, output_limited=False, output='secret')
        with lock.ProjectLock(self.paths.lock_dir), mock.patch.object(dep, '_run', return_value=good) as runner:
            with mock.patch.object(dep.rollback_ops, 'package_version', return_value='1'):
                dep.install_packages(self.tx(), (('install', 'ca-certificates'),))
            self.assertEqual([c.args[1] for c in runner.call_args_list],
                             [['opkg', 'update'], ['opkg', 'install', 'ca-certificates']])
        with lock.ProjectLock(self.paths.lock_dir), mock.patch.object(dep, '_run', side_effect=[good, bad]):
            with mock.patch.object(dep.nfqws_service, 'action') as stop:
                with self.assertRaisesRegex(RuntimeError, 'opkg install failed'):
                    dep.install_packages(self.tx(), (('install', 'nfqws2-keenetic'),))
                stop.assert_called_once_with(self.ctx, 'stop')

    def test_dependency_update_bounded_fallback(self):
        from pathlib import Path
        folder = Path(dep.config.list_path('/opt/var/opkg-lists', self.paths.test_root))
        folder.mkdir(parents=True)
        (folder / 'feed').write_bytes(b'usable')
        done = SimpleNamespace(returncode=1, timed_out=False, output_limited=False, output='Failed to download feed')
        with lock.ProjectLock(self.paths.lock_dir), mock.patch.object(dep, '_run', return_value=done):
            dep.update_feeds(self.tx())
            self.assertIn('using existing', self.err.getvalue())
            done.output += '\nFailed to download another'
            with self.assertRaises(RuntimeError):
                dep.update_feeds(self.tx())
            done.output_limited = True
            with self.assertRaises(RuntimeError):
                dep.update_feeds(self.tx())

    def test_dependency_relay_uses_existing_guards(self):
        with mock.patch.object(dep.relay_restore, 'preflight') as preflight:
            with mock.patch.object(dep.relay_restore, 'capture', return_value='saved'):
                self.assertEqual(dep.prepare_relay(self.ctx, 'ws'), 'saved')
                preflight.assert_called_once_with(self.ctx, ('ws',))
        with lock.ProjectLock(self.paths.lock_dir), mock.patch.object(dep.relay_restore, 'reconcile') as reconcile:
            dep.activate_relay(self.tx(), 'ws')
            reconcile.assert_called_once_with(self.ctx, 'ws')

"""Disposable-root E4 publication: real file IO, explicit process seam."""
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from kdn.common import lock
from kdn.engine import apply_files as files, cli, config, console, options, rollback_ops, snapshot_store, transaction


class ApplyFilesFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.env)
        self.paths = config.EnginePaths.from_environ(self.env)
        self.out, self.err = io.StringIO(), io.StringIO()
        argv = ['--yes-router']
        self.ctx = cli.Context(argv, self.env, console.Console(self.out, self.err),
                               paths=self.paths, options=options.parse_args(argv))
        self.put('01_inbounds.json', {'inbounds': [{'tag': 'transparent-custom',
                 'settings': {'followRedirect': True, 'allowedNetwork': 'tcp,udp'},
                 'streamSettings': {'sockopt': {'tproxy': 'tproxy'}}}]})
        self.put('04_outbounds.json', {'outbounds': [{'tag': 'vpn', 'protocol': 'vless', 'settings': {'secret': 'keep'}}]})
        self.routing = self.put('05_routing.json', {'routing': {'rules': []}})
        Path(self.paths.work_tmp_root).mkdir(parents=True)
        self.routes = dict(discord_tcp='zapret', discord_voice='zapret', youtube='zapret', telegram='unmanaged')

    def put(self, name, doc):
        path = Path(self.paths.xray_config_dir) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc), encoding='utf-8')
        path.chmod(0o640)
        return path

    def plan(self, **kwargs):
        return files.prepare_xray(self.ctx, routes=self.routes, proxy_outbound='vpn', **kwargs)

    def capture(self):
        return snapshot_store.create(self.paths, purpose='apply-rescue', xkeen_version='2.1.1',
            auxiliary={'PACKAGES.tsv': ''.join(name + '\tABSENT\t-\n' for name in rollback_ops.PACKAGES).encode(),
                       'RUNTIME.tsv': b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\n', 'IPV6_RUNTIME.txt': b''})

    def checker(self, callback=None):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(files.system, 'find_xray', return_value=Path('/fixture/xray')))
        done = SimpleNamespace(returncode=0, timed_out=False, output_limited=False)
        runner = stack.enter_context(mock.patch.object(files.nfqws_process, 'run', return_value=done))
        if callback:
            runner.side_effect = callback
        return stack, runner


class ApplyFilesTests(ApplyFilesFixture, unittest.TestCase):
    def test_prepare_is_readonly_and_preserves_vpn_and_modes(self):
        before = self.routing.read_bytes()
        plan = self.plan(mark=255)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertFalse(Path(self.paths.snapshot_root).exists())
        self.assertFalse(any(item.logical.endswith('/04_outbounds.json') for item in plan.changes))
        routing = json.loads(next(c.after for c in plan.changes if c.logical.endswith('05_routing.json')))
        self.assertEqual(routing['routing']['rules'][0]['inboundTag'], ['transparent-custom'])
        self.assertEqual(next(c.mode for c in plan.changes if c.logical.endswith('05_routing.json')), 0o640)

    def test_complete_staging_and_cleanup_and_secret_free_errors(self):
        plan = self.plan()
        seen = []
        def inspect(argv, env, **kwargs):
            directory = Path(argv[argv.index('-confdir') + 1])
            seen.append(directory)
            self.assertNotEqual(directory, self.routing.parent)
            self.assertEqual((directory / '04_outbounds.json').read_bytes(),
                             (self.routing.parent / '04_outbounds.json').read_bytes())
            self.assertTrue((directory / files.OWNED_OUTBOUNDS[0]).exists())
            self.assertEqual(env['XRAY_LOCATION_ASSET'], self.paths.xray_dat_dir)
            return SimpleNamespace(returncode=1, timed_out=False, output_limited=False, output='SECRET')
        stack, runner = self.checker(inspect)
        with stack, self.assertRaisesRegex(RuntimeError, '^prospective Xray configuration test failed$'):
            files.validate_staged(self.ctx, plan)
        self.assertFalse(seen[0].exists())
        self.assertEqual(runner.call_count, 1)

    def test_publish_then_restore_exact_bytes_modes_and_absence(self):
        before = self.routing.read_bytes()
        vpn = (self.routing.parent / '04_outbounds.json').read_bytes()
        plan, rescue = self.plan(), self.capture()
        stack, runner = self.checker()
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: files.restore_files(self.ctx, plan, rescue))
            files.publish(tx, plan, rescue)
            self.assertNotEqual(self.routing.read_bytes(), before)
            self.assertEqual(self.routing.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.routing.parent / '04_outbounds.json').stat().st_mode & 0o777, 0o640)
            tx.rollback()
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertEqual(self.routing.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.routing.parent / files.OWNED_OUTBOUNDS[0]).exists())
        self.assertEqual((self.routing.parent / '04_outbounds.json').read_bytes(), vpn)

    def test_failure_mid_publication_transaction_restores_everything(self):
        before, plan, rescue = self.routing.read_bytes(), self.plan(), self.capture()
        original = files.fsutil.atomic_bytes
        failed = False
        def fault(path, data, mode=0o600):
            nonlocal failed
            if Path(path) == self.routing and not failed:
                failed = True
                raise OSError('injected write fault')
            return original(path, data, mode)
        def operation(tx):
            tx.arm(lambda: files.restore_files(self.ctx, plan, rescue))
            files.publish(tx, plan, rescue)
        stack, _runner = self.checker()
        with stack, mock.patch.object(files.fsutil, 'atomic_bytes', side_effect=fault):
            self.assertEqual(transaction.execute(self.ctx, operation), 1)
        self.assertTrue(failed)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertFalse((self.routing.parent / files.OWNED_OUTBOUNDS[0]).exists())
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_missing_lock_unarmed_stale_and_forged_target_rejected(self):
        plan, rescue = self.plan(), self.capture()
        tx = transaction.Transaction(self.ctx)
        with self.assertRaisesRegex(ValueError, 'own project lock'):
            files.publish(tx, plan, rescue)
        with lock.ProjectLock(self.paths.lock_dir):
            with self.assertRaisesRegex(ValueError, 'armed rescue'):
                files.publish(tx, plan, rescue)
            tx.arm(lambda: None)
            evil = plan._replace(changes=(files.Change('/opt/etc/xray/configs/04_outbounds.json', None, 0o600, b'{}'),))
            with self.assertRaises(ValueError):
                files.publish(tx, evil, rescue)
            self.put('04_outbounds.json', {'outbounds': [{'tag': 'changed', 'protocol': 'vless'}]})
            with self.assertRaisesRegex(ValueError, 'changed since preparation'):
                files.publish(tx, plan, rescue)

    def test_bad_json_links_reserved_content_and_mark_fail_before_snapshot(self):
        for raw in (b'{"routing":{},"routing":{}}', b'{"routing":NaN}', b'[]', b'not-json'):
            self.routing.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.plan()
        self.put('05_routing.json', {'routing': {'rules': []}})
        with self.assertRaises(ValueError):
            self.plan(mark=2147483648)
        self.put(files.OWNED_OUTBOUNDS[0], {'outbounds': [{'tag': 'personal', 'protocol': 'vless'}]})
        with self.assertRaisesRegex(ValueError, 'not project-owned'):
            self.plan()
        (self.routing.parent / files.OWNED_OUTBOUNDS[0]).unlink()
        self.routing.unlink()
        self.routing.symlink_to(self.routing.parent / '04_outbounds.json')
        with self.assertRaises(ValueError):
            self.plan()
        self.assertFalse(Path(self.paths.snapshot_root).exists())

    def test_rescue_mismatch_rejects_before_first_write(self):
        rescue = self.capture()
        self.routing.write_bytes(b'{"routing":{"rules":[],"domainStrategy":"AsIs"}}')
        plan = self.plan()
        before = self.routing.read_bytes()
        with lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: None)
            with self.assertRaisesRegex(ValueError, 'rescue does not match'):
                files.publish(tx, plan, rescue)
        self.assertEqual(self.routing.read_bytes(), before)

    def test_budgets_and_confirmation(self):
        with mock.patch.object(files, 'MAX_FILES', 1), self.assertRaises(ValueError):
            self.plan()
        with mock.patch.object(files, 'MAX_TOTAL', 1), self.assertRaises(ValueError):
            self.plan()
        self.ctx.options = options.parse_args([])
        plan = self.plan()  # Preparing/validating is read-only, confirmation belongs to publication.
        with lock.ProjectLock(self.paths.lock_dir), self.assertRaises(ValueError):
            files.require_owner(self.ctx)
        self.assertTrue(plan.changes)

    def test_route_matrix_prepare_staging_removal_and_ws(self):
        from itertools import product
        for tcp, voice, youtube, telegram in product(*([('direct', 'zapret', 'vless')] * 3),
                                                    ('direct', 'vless', 'ws', 'unmanaged')):
            self.routes = dict(discord_tcp=tcp, discord_voice=voice, youtube=youtube, telegram=telegram)
            with self.subTest(routes=self.routes):
                plan = self.plan()
                outputs = {Path(c.logical).name: c.after for c in plan.changes}
                self.assertEqual(files.OWNED_OUTBOUNDS[0] in outputs, tcp != 'vless' or voice != 'vless')
                self.assertEqual(files.OWNED_OUTBOUNDS[1] in outputs, youtube != 'vless')
                self.assertEqual(files.OWNED_OUTBOUNDS[2] in outputs, telegram in ('direct', 'ws'))
                if telegram == 'ws':
                    self.assertEqual(json.loads(outputs[files.OWNED_OUTBOUNDS[2]])['outbounds'][1]['settings'],
                                     {'redirect': '127.0.0.1:18443'})
        self.put(files.OWNED_OUTBOUNDS[0], {'outbounds': [{'tag': 'discord-direct', 'protocol': 'freedom', 'settings': {}}]})
        plan = self.plan()
        self.assertIsNone(next(c.after for c in plan.changes if c.logical.endswith(files.OWNED_OUTBOUNDS[0])))

    def test_xray_failure_never_publishes_even_armed(self):
        plan, rescue = self.plan(), self.capture()
        before = self.routing.read_bytes()
        stack, runner = self.checker()
        runner.return_value = SimpleNamespace(returncode=1, timed_out=False, output_limited=False)
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: None)
            with self.assertRaises(RuntimeError):
                files.publish(tx, plan, rescue)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertFalse((self.routing.parent / files.OWNED_OUTBOUNDS[0]).exists())

    def test_cancel_after_first_effective_write_restores_and_releases_lock(self):
        before, plan, rescue = self.routing.read_bytes(), self.plan(), self.capture()
        original = files.fsutil.atomic_bytes
        cancelled = False
        def cancel(path, data, mode=0o600):
            nonlocal cancelled
            original(path, data, mode)
            if Path(path).parent == self.routing.parent and not cancelled:
                cancelled = True
                raise KeyboardInterrupt()
        def operation(tx):
            tx.arm(lambda: files.restore_files(self.ctx, plan, rescue))
            files.publish(tx, plan, rescue)
        stack, _runner = self.checker()
        with stack, mock.patch.object(files.fsutil, 'atomic_bytes', side_effect=cancel):
            self.assertEqual(transaction.execute(self.ctx, operation), 1)
        self.assertTrue(cancelled)
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertIn('RESULT|rolled-back', self.out.getvalue())
        self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_failed_rescue_reports_partial_and_keeps_durable_snapshot(self):
        plan, rescue = self.plan(), self.capture()
        def operation(tx):
            tx.arm(lambda: (_ for _ in ()).throw(OSError('rescue disk fault')))
            raise RuntimeError('injected operation failure')
        self.assertEqual(transaction.execute(self.ctx, operation), 1)
        self.assertIn('RESULT|partial', self.out.getvalue())
        self.assertIn('CRITICAL:', self.err.getvalue())
        self.assertFalse(Path(self.paths.lock_dir).exists())
        snapshot_store.verify(rescue)
        self.assertTrue(plan.changes)

    def test_extra_files_publish_and_restore_absence(self):
        plan = files.extend(self.ctx, self.plan(), {'/opt/etc/opkg/nfqws2-keenetic.conf': b'owned feed\n'})
        rescue = self.capture()
        stack, _runner = self.checker()
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: files.restore_files(self.ctx, plan, rescue))
            files.publish(tx, plan, rescue)
            target = self.root / 'opt/etc/opkg/nfqws2-keenetic.conf'
            self.assertEqual(target.read_bytes(), b'owned feed\n')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            tx.rollback()
            self.assertFalse(target.exists())

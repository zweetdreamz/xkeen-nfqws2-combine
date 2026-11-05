"""Forced-legacy safety bridge: no recursive lock and no unsafe filesystem fallback."""
import contextlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import engine_fixture
import engine_shell
from kdn.engine import config, snapshot_bridge as bridge, snapshot_store as store


class LegacySafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.environ = dict(os.environ, KD_TEST_ROOT=str(self.base), KD_ALLOW_TEST_ROOT='1',
                            KDN_ENGINE_SCRIPT_DIR=str(engine_shell.ROOT), KDN_SNAPSHOT_BRIDGE_PID=str(os.getpid()))
        from target_fixture import supported_environment
        supported_environment(self.environ)
        self.paths = config.EnginePaths.from_environ(self.environ)
        lock = Path(self.paths.lock_dir)
        lock.mkdir(parents=True)
        (lock / 'pid').write_text(str(os.getpid()) + '\n')

    def run_bridge(self, *args, environ=None):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return bridge.run(args, self.environ if environ is None else environ)

    def test_capture_entry_skips_outbound_and_borrows_owned_lock(self):
        source = self.base / 'opt/etc/xray/configs'
        source.mkdir(parents=True)
        (source / '04_outbounds.json').write_bytes(b'PRIVATE NODE')
        (source / '05_routing.json').write_bytes(b'routing')
        snapshot = Path(self.paths.snapshot_root) / 'test'
        target = snapshot / 'files/opt/etc/xray/configs'
        snapshot.mkdir(parents=True)
        self.assertEqual(self.run_bridge('capture-entry', '/opt/etc/xray/configs', str(target), 'integrated'), 0)
        self.assertFalse((target / '04_outbounds.json').exists())
        self.assertEqual((target / '05_routing.json').read_bytes(), b'routing')
        self.assertEqual((Path(self.paths.lock_dir) / 'pid').read_text().strip(), str(os.getpid()))

    def test_mutation_rejects_missing_mismatched_or_nonancestor_lock(self):
        source = self.base / 'opt/etc/nfqws2'
        source.mkdir(parents=True)
        snapshot = Path(self.paths.snapshot_root) / 'test'
        snapshot.mkdir(parents=True)
        target = snapshot / 'files/opt/etc/nfqws2'
        for owner in ('', 'other', '1'):
            with self.subTest(owner=owner):
                env = dict(self.environ, KDN_SNAPSHOT_BRIDGE_PID=owner)
                self.assertEqual(self.run_bridge('capture-entry', '/opt/etc/nfqws2', str(target), 'standalone', environ=env), 1)
        self.assertFalse(target.exists())
        (Path(self.paths.lock_dir) / 'pid').write_text('99999999\n')
        self.assertEqual(self.run_bridge('restore', str(snapshot), '', ''), 1)

    def test_matching_live_sibling_pid_is_not_accepted_as_shell_lock_ancestor(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            (Path(self.paths.lock_dir) / 'pid').write_text(str(child.pid) + '\n')
            env = dict(self.environ, KDN_SNAPSHOT_BRIDGE_PID=str(child.pid))
            self.assertEqual(self.run_bridge('restore', str(self.base / 'missing'), '', '', environ=env), 1)
        finally:
            child.terminate()
            child.wait(timeout=5)

    def test_capture_and_verify_reject_unowned_destinations(self):
        for args in (('capture-entry', '/etc/passwd', str(self.base / 'escape'), 'integrated'),
                     ('capture-entry', '/opt/etc/nfqws2', str(self.base / 'escape'), 'standalone'),
                     ('verify', str(self.base)), ('unknown',)):
            with self.subTest(args=args):
                self.assertEqual(self.run_bridge(*args), 1)

    def test_bridge_restore_preserves_current_node_and_unknown_version_init(self):
        configs = self.base / 'opt/etc/xray/configs'
        configs.mkdir(parents=True)
        outbound = configs / '04_outbounds.json'
        outbound.write_bytes(b'CURRENT NODE')
        init = self.base / 'opt/etc/init.d/S05xkeen'
        init.parent.mkdir(parents=True)
        init.write_bytes(b'old init')
        snapshot = store.create(self.paths, purpose='test', xkeen_version='2.0')
        init.write_bytes(b'NEW INIT')
        self.assertEqual(self.run_bridge('verify', str(snapshot)), 0)
        self.assertNotEqual(self.run_bridge('restore', str(snapshot), '', ''), 0)
        self.assertEqual(outbound.read_bytes(), b'CURRENT NODE')
        self.assertEqual(init.read_bytes(), b'NEW INIT')

    def test_missing_bundle_helper_fails_confirmation_before_any_config_write(self):
        done = engine_shell.run_function('require_confirmation',
            defs=('require_router_readonly() { :; }', 'kdn_policy_preflight'),
            variables={'CONFIRMED': 1, 'TEST_ROOT': str(self.base), 'SCRIPT_DIR': str(self.base)},
            env=self.environ, shell=shlex.split(os.environ.get('TEST_SHELL', 'sh')))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('refusing mutation', done.stderr)

    def test_real_shell_snapshot_marks_policy_and_excludes_node(self):
        fixture = engine_fixture.make_root(self.base / 'fixture')
        node = ('{"outbounds":[{"tag":"vless-reality","protocol":"vless",'
                '"settings":{"note":"NODE MUST NOT BE COPIED"}},'
                '{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}')
        outbound = fixture.write('/opt/etc/xray/configs/04_outbounds.json', node)
        for mode in ('legacy', 'flag'):
            env = fixture.env
            if mode == 'legacy':
                env['KDN_ENGINE'] = 'legacy'
            else:
                state = fixture.path('/opt/etc/keenetic-discord-nfqws2')
                state.mkdir(parents=True, exist_ok=True)
                (state / 'engine-legacy').touch()
                env.pop('KDN_ENGINE', None)
            done = engine_shell.run_sh(
                'sh "$KDN_SCRIPT" --snapshot-baseline --core xray --yes-router',
                env=dict(env, KDN_SCRIPT=str(engine_shell.ROOT / 'apply-discord-nfqws2.sh')), timeout=90)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            pointer = fixture.path('/opt/etc/keenetic-discord-nfqws2/baseline.ptr')
            snapshot = Path(pointer.read_text().strip())
            self.assertIn(store.POLICY_RECORD, (snapshot / 'MANIFEST').read_bytes())
            self.assertFalse((snapshot / 'files/opt/etc/xray/configs/04_outbounds.json').exists())
            self.assertNotIn(b'04_outbounds.json', (snapshot / 'CHECKSUMS.sha256').read_bytes())
            self.assertEqual(outbound.read_text(), node)
            store.verify(snapshot)
            pointer.unlink()  # force the engine-legacy flag case to capture too

    def test_policy_sentinel_is_accepted_once_only(self):
        snapshot = store.create(self.paths, purpose='test')
        manifest = (snapshot / 'MANIFEST').read_bytes()
        self.assertIn(store.POLICY_RECORD, manifest)
        self.assertEqual(len(store.parse_manifest(manifest)), len(store.managed_roots()))
        with self.assertRaises(ValueError):
            store.parse_manifest(store.POLICY_RECORD + manifest)

    def test_strict_generated_validation_production_and_explicit_real_fixture(self):
        for test_root, real_bin, expected in (('', '', True), (str(self.base), '/pinned/nfqws2', True),
                                               (str(self.base), '', False)):
            with self.subTest(test_root=test_root, real_bin=real_bin):
                done = engine_shell.run_function('validate_generated_nfqws_config',
                    defs=('nfqws_config_check() { :; }', 'make_tmp() { mktemp; }',
                          'compose_nfqws_profiles() { :; }', 'nfqws_dry_run() { :; }',
                          'kdn_snapshot_bridge() { printf "STRICT_VALIDATION_CALLED\\n"; }'),
                    variables={'NFQWS_CONF': '/not-executed', 'TEST_ROOT': test_root},
                    env=dict(os.environ, KD_TEST_NFQWS2_BIN=real_bin, TMPDIR=str(self.base)))
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual('STRICT_VALIDATION_CALLED' in done.stdout, expected)

    def test_strict_failure_has_no_dry_run_success_fallback(self):
        with mock.patch.object(bridge.nfqws_validate, 'validate_config', side_effect=ValueError('invalid Lua')) as validate:
            self.assertEqual(self.run_bridge('strict', '/not-executed'), 1)
            validate.assert_called_once()
            self.assertEqual(validate.call_args.args[0].paths, self.paths)
            self.assertEqual(validate.call_args.args[1], '/not-executed')

    def test_pre_policy_manifest_loop_refuses_sentinel_before_service_stop(self):
        snapshot = store.create(self.paths, purpose='test')
        # Verbatim pre-policy membership check: an old bundle does not know the
        # policy sentinel as a managed path. Original full shell retained in
        # .cache/refactor/sdd/phase-5/apply-discord-nfqws2-pre-policy.sh.
        script = '\n'.join((
            engine_shell.extract_function('managed_paths'),
            engine_shell.extract_function('is_managed_path'),
            'old_restore() {',
            '  while IFS="|" read -r verify_path verify_status; do',
            '    is_managed_path "$verify_path" integrated || return 1',
            '  done < "$KDN_MANIFEST"',
            '  printf "SERVICES_STOPPED\\n"',
            '}',
            'old_restore',
        ))
        done = engine_shell.run_sh(script, env=dict(self.environ, KDN_MANIFEST=str(snapshot / 'MANIFEST')))
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn('SERVICES_STOPPED', done.stdout)

    def test_full_restore_verification_rejects_unowned_package_metadata(self):
        snapshot = store.create(self.paths, purpose='test', auxiliary={
            'PACKAGES.tsv': b'arbitrary-package\tABSENT\t-\n',
            'RUNTIME.tsv': b'XKEEN_RUNNING\t0\nNFQWS_RUNNING\t0\n'})
        self.assertEqual(self.run_bridge('verify', str(snapshot)), 0)
        self.assertEqual(self.run_bridge('verify-full', str(snapshot)), 1)

    def test_package_state_is_emitted_only_after_all_strict_queries_succeed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(bridge.rollback_ops, 'package_version',
                                   side_effect=['1.0', '', RuntimeError('opkg failed')]):
                self.assertEqual(bridge.run(['package-state'], self.environ), 1)
        self.assertEqual(output.getvalue(), '')
        with mock.patch.object(bridge.rollback_ops, 'package_version', return_value='1.0') as query:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(bridge.run(['package-state'], self.environ), 0)
        self.assertEqual(output.getvalue(), ''.join(name + '\tPRESENT\t1.0\n' for name in bridge.rollback_ops.PACKAGES))
        self.assertEqual([call.args[1] for call in query.call_args_list], list(bridge.rollback_ops.PACKAGES))

    def test_restore_queries_existing_binary_package_before_file_mutation(self):
        directory = self.base / 'opt/etc/nfqws2'
        directory.mkdir(parents=True)
        config_file = directory / 'nfqws2.conf'
        config_file.write_bytes(b'OLD CONFIG')
        lua = directory / 'lua/a.lua'
        lua.parent.mkdir()
        lua.write_bytes(b'OLD LUA')
        snapshot = store.create(self.paths, purpose='test', xkeen_version='2.1', auxiliary={
            'PACKAGES.tsv': b'nfqws2-keenetic\tPRESENT\t1.2\n'})
        config_file.write_bytes(b'CURRENT CONFIG')
        lua.write_bytes(b'CURRENT LUA')
        binary = Path(self.paths.nfqws_bin)
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'installed binary')
        for failure in (RuntimeError('opkg unavailable'), ''):
            with self.subTest(failure=type(failure).__name__):
                arguments = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                with mock.patch.object(bridge.rollback_ops, 'package_version', **arguments):
                    self.assertEqual(self.run_bridge('restore', str(snapshot), '2.1', '1.2'), 1)
                self.assertEqual(config_file.read_bytes(), b'CURRENT CONFIG')
                self.assertEqual(lua.read_bytes(), b'CURRENT LUA')
        with mock.patch.object(bridge.rollback_ops, 'package_version', return_value='1.3'):
            self.assertEqual(self.run_bridge('restore', str(snapshot), '2.1', '1.2'), 0)
        self.assertEqual(config_file.read_bytes(), b'OLD CONFIG')
        self.assertEqual(lua.read_bytes(), b'CURRENT LUA')

    def test_xkeen_version_uses_shared_readonly_version_provenance(self):
        output = io.StringIO()
        with mock.patch.object(bridge.rollback_ops, 'xkeen_version', return_value='2.1.1β') as version:
            with contextlib.redirect_stdout(output):
                self.assertEqual(bridge.run(['xkeen-version'], self.environ), 0)
        self.assertEqual(output.getvalue(), '2.1.1β\n')
        self.assertEqual(version.call_args.args[0].paths, self.paths)

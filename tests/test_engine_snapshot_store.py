"""Disposable snapshot roots: strict verification, ownership, version/data preservation."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from kdn.engine import config, snapshot_store as store


class SnapshotStoreTests(unittest.TestCase):
    def test_full_pointer_directory_sync_error_is_not_ignored(self):
        import os
        import stat
        snapshot = self.capture()
        real_fsync = os.fsync
        def fail_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError('injected pointer directory sync failure')
            return real_fsync(descriptor)
        with mock.patch.object(os, 'fsync', side_effect=fail_directory):
            with self.assertRaisesRegex(OSError, 'pointer directory sync'):
                store.publish_pointer(self.paths, self.paths.latest_pointer, snapshot)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': str(self.base), 'KD_ALLOW_TEST_ROOT': '1'})

    def put(self, logical, content=b'original', mode=0o640):
        target = Path(config.list_path(logical, self.paths.test_root))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
        return target

    def capture(self, **kwargs):
        return store.create(self.paths, purpose='test', xkeen_version='2.1', **kwargs)

    def test_empty_full_round_trip_and_metadata(self):
        snapshot = self.capture()
        verified = store.verify(snapshot)
        self.assertEqual(verified.metadata.value('XKEEN_VERSION'), '2.1')
        self.assertEqual(len(verified.entries), len(store.managed_roots()))
        self.assertTrue(all(item.presence == 'ABSENT' for item in verified.entries))
        self.assertEqual(store.restore_files(self.paths, snapshot, current_xkeen_version='2.1').warnings, ())

    def test_present_restore_modes_and_absent_cleanup(self):
        target = self.put('/opt/etc/nfqws2/lists/user.list', b'known\xff\n', 0o640)
        snapshot = self.capture()
        target.write_bytes(b'changed')
        extra = self.put('/opt/etc/nfqws2/lists/new.list', b'new')
        store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(target.read_bytes(), b'known\xff\n')
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertFalse(extra.exists())

    def test_new_capture_excludes_outbound_and_restoring_old_keeps_it(self):
        outbound = self.put('/opt/etc/xray/configs/04_outbounds.json', b'ACTIVE SECRET')
        routing = self.put('/opt/etc/xray/configs/05_routing.json', b'old routing')
        snapshot = self.capture()
        self.assertFalse((snapshot / 'files/opt/etc/xray/configs/04_outbounds.json').exists())
        old = snapshot / 'files/opt/etc/xray/configs/04_outbounds.json'
        old.write_bytes(b'OLD SECRET')
        checks = snapshot / 'CHECKSUMS.sha256'
        checks.write_bytes(checks.read_bytes() + hashlib.sha256(b'OLD SECRET').hexdigest().encode()
                           + b'  ./opt/etc/xray/configs/04_outbounds.json\n')
        store.verify(snapshot)
        routing.write_bytes(b'new routing')
        store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(outbound.read_bytes(), b'ACTIVE SECRET')
        self.assertEqual(routing.read_bytes(), b'old routing')

    def test_absent_ancestor_never_deletes_current_outbound(self):
        snapshot = self.capture()
        outbound = self.put('/opt/etc/xray/configs/04_outbounds.json', b'keep node')
        extra = self.put('/opt/etc/xray/configs/05_routing.json', b'remove')
        store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(outbound.read_bytes(), b'keep node')
        self.assertFalse(extra.exists())

    def test_version_mismatch_refuses_even_own_port_blocks(self):
        initial = b'80\n# BEGIN keenetic-discord-nfqws2\n443\n# END keenetic-discord-nfqws2\n'
        ports = self.put('/opt/etc/xkeen/port_proxying.lst', initial)
        settings = self.put('/opt/etc/xkeen/xkeen.json', b'old version settings')
        init = self.put('/opt/etc/init.d/S05xkeen', b'old init')
        hook = self.put('/opt/etc/ndm/netfilter.d/proxy.sh', b'old hook')
        snapshot = self.capture()
        ports.write_bytes(b'CUSTOM PORTS\n# BEGIN keenetic-discord-nfqws2\n9000\n# END keenetic-discord-nfqws2\n')
        settings.write_bytes(b'NEW SETTINGS')
        init.write_bytes(b'NEW INIT')
        hook.write_bytes(b'NEW HOOK')
        with self.assertRaises(ValueError):
            store.restore_files(self.paths, snapshot, current_xkeen_version='2.2')
        self.assertEqual(ports.read_bytes(), b'CUSTOM PORTS\n# BEGIN keenetic-discord-nfqws2\n9000\n# END keenetic-discord-nfqws2\n')
        self.assertEqual(settings.read_bytes(), b'NEW SETTINGS')
        self.assertEqual(init.read_bytes(), b'NEW INIT')
        self.assertEqual(hook.read_bytes(), b'NEW HOOK')

    def test_missing_version_preserves_privileged_files(self):
        target = self.put('/opt/etc/init.d/S05xkeen', b'old')
        snapshot = store.create(self.paths, purpose='old', xkeen_version='')
        target.write_bytes(b'NEW')
        with self.assertRaises(ValueError):
            store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(target.read_bytes(), b'NEW')

    def test_unsupported_full_and_focused_snapshots_refuse_before_any_publication(self):
        for focused in (False, True):
            for saved, current in (('2.0', '2.1'), ('', '2.1'), ('2.1', ''),
                                   ('2.1', '2.0'), ('2.1-beta', '2.1'), ('2.1', '2.2')):
                with self.subTest(focused=focused, saved=saved, current=current):
                    target = self.put('/opt/etc/nfqws2/nfqws2.conf', b'saved')
                    snapshot = store.create(self.paths, purpose='negative-version', focused=focused,
                                            xkeen_version=saved, metadata=(('NFQWS_RUNNING', '0'),) if focused else ())
                    before_snapshot = {p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob('*') if p.is_file()}
                    target.write_bytes(b'CURRENT')
                    with mock.patch.object(store, '_sync', side_effect=AssertionError('publication before version gate')):
                        with self.assertRaises(ValueError):
                            store.restore_files(self.paths, snapshot, focused=focused, current_xkeen_version=current)
                    self.assertEqual(target.read_bytes(), b'CURRENT')
                    self.assertEqual({p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob('*') if p.is_file()}, before_snapshot)

    def test_package_drift_preserves_lua_init_hook_but_restores_data(self):
        data = self.put('/opt/etc/nfqws2/nfqws2.conf', b'old conf')
        lua = self.put('/opt/etc/nfqws2/lua/zapret-lib.lua', b'old lua')
        init = self.put('/opt/etc/init.d/S51nfqws2', b'old init')
        snapshot = self.capture(auxiliary={'PACKAGES.tsv': b'nfqws2-keenetic\tPRESENT\t1.2\n'})
        data.write_bytes(b'new conf')
        lua.write_bytes(b'NEW LUA')
        init.write_bytes(b'NEW INIT')
        result = store.restore_files(self.paths, snapshot, current_xkeen_version='2.1', current_nfqws_version='1.3')
        self.assertTrue(result.warnings)
        self.assertEqual(data.read_bytes(), b'old conf')
        self.assertEqual(lua.read_bytes(), b'NEW LUA')
        self.assertEqual(init.read_bytes(), b'NEW INIT')

    def test_focused_snapshot_layout_restore_keeps_package_and_other_services(self):
        data = self.put('/opt/etc/nfqws2/nfqws2.conf', b'old data')
        lua = self.put('/opt/etc/nfqws2/lua/a.lua', b'package')
        outbound = self.put('/opt/etc/xray/configs/04_outbounds.json', b'node')
        snapshot = store.create(self.paths, purpose='import', focused=True, xkeen_version='2.1',
                                metadata=(('NFQWS_RUNNING', '1'), ('ROUTES_HEADER', 'routes')))
        self.assertFalse((snapshot / 'nfqws2/lua').exists())
        self.assertEqual(store.verify(snapshot, focused=True).metadata.value('ROUTES_HEADER'), 'routes')
        data.write_bytes(b'changed')
        lua.write_bytes(b'new package')
        extra = self.put('/opt/etc/nfqws2/imported-profiles/new.json')
        store.restore_files(self.paths, snapshot, focused=True, current_xkeen_version='2.1')
        self.assertEqual(data.read_bytes(), b'old data')
        self.assertEqual(lua.read_bytes(), b'new package')
        self.assertFalse(extra.exists())
        self.assertEqual(outbound.read_bytes(), b'node')

    def test_focused_absent_restores_only_data_absence(self):
        snapshot = store.create(self.paths, purpose='import', focused=True, xkeen_version='2.1', metadata=(('NFQWS_RUNNING', '0'),))
        data = self.put('/opt/etc/nfqws2/nfqws2.conf')
        lua = self.put('/opt/etc/nfqws2/lua/a.lua')
        store.restore_files(self.paths, snapshot, focused=True, current_xkeen_version='2.1')
        self.assertFalse(data.exists())
        self.assertTrue(lua.exists())

    def test_manifest_rejects_duplicate_missing_unknown_and_traversal(self):
        snapshot = self.capture()
        manifest = (snapshot / 'MANIFEST').read_bytes()
        rows = manifest.splitlines(keepends=True)
        missing_root = rows[0] + b''.join(rows[2:])
        for raw in (manifest + manifest.splitlines()[0] + b'\n', missing_root,
                    manifest.replace(b'/opt/etc/xkeen', b'/opt/etc/../xkeen', 1),
                    manifest + b'/etc/passwd|PRESENT\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                store.parse_manifest(raw)

    def test_checksum_parser_rejects_duplicate_absolute_traversal_and_escape(self):
        prefix = b'0' * 64 + b'  '
        for raw in (prefix + b'/etc/passwd\n', prefix + b'../x\n', prefix + b'a\\b\n',
                    prefix + b'a\n' + prefix + b'./a\n', b'junk\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                store.parse_checksums(raw)

    def test_corrupt_missing_uncovered_and_extra_files_fail_before_mutation(self):
        target = self.put('/opt/etc/nfqws2/nfqws2.conf', b'current')
        for mutation in ('corrupt', 'missing', 'uncovered', 'metadata-duplicate'):
            snapshot = self.capture()
            saved = snapshot / 'files/opt/etc/nfqws2/nfqws2.conf'
            if mutation == 'corrupt':
                saved.write_bytes(b'bad')
            elif mutation == 'missing':
                saved.unlink()
            elif mutation == 'uncovered':
                saved.with_name('extra').write_bytes(b'extra')
            else:
                state = snapshot / 'STATE.tsv'
                state.write_bytes(state.read_bytes() + b'FORMAT\t1\n')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
            self.assertEqual(target.read_bytes(), b'current')

    def test_symlink_source_target_and_ancestors_fail_closed(self):
        self.put('/opt/etc/nfqws2/nfqws2.conf')
        snapshot = self.capture()
        target = Path(self.paths.nfqws_conf)
        target.unlink()
        target.symlink_to(self.base / 'outside')
        with self.assertRaises(ValueError):
            store.restore_files(self.paths, snapshot)
        with self.assertRaises(ValueError):
            self.capture()
        target.unlink()
        saved = snapshot / 'files/opt/etc/nfqws2/nfqws2.conf'
        saved.unlink()
        saved.symlink_to(self.base / 'outside')
        with self.assertRaises(ValueError):
            store.verify(snapshot)

    def test_publish_is_atomic_and_original_baseline_is_not_replaced(self):
        first, second = self.capture(), self.capture()
        self.assertNotEqual(first, second)
        self.assertTrue(store.publish_pointer(self.paths, self.paths.baseline_pointer, first, baseline=True))
        self.assertFalse(store.publish_pointer(self.paths, self.paths.baseline_pointer, second, baseline=True))
        self.assertEqual(Path(self.paths.baseline_pointer).read_text().strip(), str(first))
        with mock.patch.object(store.fsutil.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                store.publish_pointer(self.paths, self.paths.baseline_pointer, second)
        self.assertEqual(Path(self.paths.baseline_pointer).read_text().strip(), str(first))
        store.rollover_xkeen_baseline(self.paths, second, '2.1')
        self.assertEqual(Path(self.paths.xkeen_baseline_pointer).read_text().strip(), str(second))
        self.assertTrue(first.exists())
        with self.assertRaises(ValueError):
            store.rollover_xkeen_baseline(self.paths, second, '2.2')
        standalone = store.create(self.paths, purpose='standalone', scope='standalone', xkeen_version='2.1')
        with self.assertRaises(ValueError):
            store.rollover_xkeen_baseline(self.paths, standalone, '2.1')

    def test_capture_failure_never_publishes_incomplete_directory(self):
        self.put('/opt/etc/nfqws2/nfqws2.conf')
        with mock.patch.object(store.os, 'fsync', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.capture()
        self.assertEqual(list(Path(self.paths.snapshot_root).iterdir()), [])

    def test_live_guard_and_unowned_pointer(self):
        paths = self.paths.replace(test_root='')
        with self.assertRaises(RuntimeError):
            store.create(paths, purpose='no')
        snapshot = self.capture()
        with self.assertRaises(ValueError):
            store.publish_pointer(self.paths, self.base / 'unowned.ptr', snapshot)
        with self.assertRaises(ValueError):
            store.create(self.paths.replace(snapshot_root=str(self.base / 'outside')), purpose='no')
        with self.assertRaises(ValueError):
            store.create(self.paths.replace(test_root='/'), purpose='no')

    def test_source_file_budget_and_special_file_rejection(self):
        target = self.put('/opt/etc/nfqws2/nfqws2.conf', b'large')
        with mock.patch.object(store, 'MAX_FILE', 2), self.assertRaises(ValueError):
            self.capture()
        target.unlink()
        store.os.mkfifo(target)
        with self.assertRaises(ValueError):
            self.capture()

    def test_atomic_restore_failure_keeps_original_file(self):
        target = self.put('/opt/etc/nfqws2/nfqws2.conf', b'old')
        snapshot = self.capture()
        target.write_bytes(b'CURRENT')
        with mock.patch.object(store.os, 'replace', side_effect=OSError('replace failed')):
            with self.assertRaises(OSError):
                store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(target.read_bytes(), b'CURRENT')

    def test_focused_rejects_package_files_and_unexpected_top_level(self):
        self.put('/opt/etc/nfqws2/nfqws2.conf', b'data')
        snapshot = store.create(self.paths, purpose='import', focused=True, metadata=(('NFQWS_RUNNING', '0'),))
        extra = snapshot / 'arbitrary'
        extra.write_bytes(b'extra')
        with self.assertRaises(ValueError):
            store.verify(snapshot, focused=True)
        extra.unlink()
        package = snapshot / 'nfqws2/lua'
        package.mkdir()
        with self.assertRaises(ValueError):
            store.verify(snapshot, focused=True)

    def test_port_block_unclosed_is_rejected(self):
        with self.assertRaises(ValueError):
            store._merge_ports(b'current\n', store.BEGIN + b'\n443\n')
        self.assertEqual(store._merge_ports(b'custom\n', b''), b'custom\n')

    def test_real_sanitized_july_baseline_refused_without_changing_current_node(self):
        snapshot = Path(__file__).parent / 'fixtures/engine/baseline-20260723-sanitized'
        verified = store.verify(snapshot)
        self.assertEqual(verified.metadata.value('FORMAT'), '1')
        self.assertGreater(len(verified.files), 10)
        outbound = self.put('/opt/etc/xray/configs/04_outbounds.json', b'CURRENT NODE MUST REMAIN')
        init = self.put('/opt/etc/init.d/S05xkeen', b'CURRENT VERSION INIT')
        ports = self.put('/opt/etc/xkeen/port_proxying.lst', b'443\nCUSTOM\n')
        with self.assertRaises(ValueError):
            store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(outbound.read_bytes(), b'CURRENT NODE MUST REMAIN')
        self.assertEqual(init.read_bytes(), b'CURRENT VERSION INIT')
        self.assertEqual(ports.read_bytes(), b'443\nCUSTOM\n')

    def test_type_replacement_file_directory_is_bounded_to_owned_data(self):
        target = self.put('/opt/etc/nfqws2/lists/a.list', b'old file')
        snapshot = self.capture()
        target.unlink()
        target.mkdir()
        (target / 'extra').write_bytes(b'remove')
        store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(target.read_bytes(), b'old file')
        directory = target.parent
        target.unlink()
        directory.rmdir()
        directory.write_bytes(b'wrong type')
        store.restore_files(self.paths, snapshot, current_xkeen_version='2.1')
        self.assertEqual(target.read_bytes(), b'old file')

    def test_focused_bad_kind_presence_and_runtime_metadata(self):
        snapshot = store.create(self.paths, purpose='import', focused=True, metadata=(('NFQWS_RUNNING', '0'),))
        with self.assertRaises(ValueError):
            store.verify(snapshot)
        state = snapshot / 'STATE.tsv'
        original = state.read_bytes()
        state.write_bytes(original.replace(b'NFQWS_RUNNING\t0', b'NFQWS_RUNNING\tBAD'))
        with self.assertRaises(ValueError):
            store.verify(snapshot, focused=True)
        state.write_bytes(original)
        (snapshot / 'nfqws2').mkdir()
        with self.assertRaises(ValueError):
            store.verify(snapshot, focused=True)

    def test_invalid_metadata_parser_types_limits_and_scope(self):
        for raw in (None, b'a|b|c\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                store.parse_manifest(raw)
        with self.assertRaises(ValueError):
            store.parse_checksums(None)
        with self.assertRaises(ValueError):
            store.managed_roots('unknown')
        with self.assertRaises(ValueError):
            store.verify(self.base / 'missing')
        with self.assertRaises(ValueError):
            store._no_links(self.base / '..' / 'escape')
        snapshot = self.capture()
        with self.assertRaises(ValueError):
            store.publish_pointer(self.paths, self.paths.latest_pointer, self.base)
        with self.assertRaises(ValueError):
            store.rollover_xkeen_baseline(self.paths, snapshot, '')

    def test_capture_auxiliary_rejection_and_entry_budgets(self):
        for auxiliary in ({'unowned': b'bad'}, {'RUNTIME.tsv': 'not bytes'}):
            with self.subTest(auxiliary=auxiliary), self.assertRaises(ValueError):
                self.capture(auxiliary=auxiliary)
        self.put('/opt/etc/nfqws2/nfqws2.conf')
        with mock.patch.object(store, 'MAX_ENTRIES', 0), self.assertRaises(ValueError):
            self.capture()
        self.assertEqual(list(Path(self.paths.snapshot_root).iterdir()), [])

    def test_port_merge_keeps_unterminated_user_line_separate_and_absent_source_removes_block(self):
        block = store.BEGIN + b'\n443\n' + store.END + b'\n'
        self.assertEqual(store._merge_ports(b'custom', block), b'custom\n' + block)
        self.assertEqual(store._merge_ports(b'custom\n' + block, b''), b'custom\n')

    def test_incomplete_current_port_block_fails_before_any_file_change(self):
        routing = self.put('/opt/etc/xray/configs/05_routing.json', b'old routing')
        self.put('/opt/etc/xkeen/port_proxying.lst', b'80\n')
        snapshot = self.capture()
        routing.write_bytes(b'CURRENT ROUTING')
        self.put('/opt/etc/xkeen/port_proxying.lst', store.BEGIN + b'\n443\n')
        with self.assertRaises(ValueError):
            store.restore_files(self.paths, snapshot, current_xkeen_version='2.2')
        self.assertEqual(routing.read_bytes(), b'CURRENT ROUTING')

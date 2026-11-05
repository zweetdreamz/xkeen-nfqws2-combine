"""Bounded snapshot enumeration/capture and one shared strict validation path."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from kdn.engine import compose, config, nfqws_process, nfqws_validate as validate
from kdn.engine import snapshot_bridge as bridge, snapshot_store as store


class SnapshotBudgetReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1')
        from target_fixture import supported_environment
        supported_environment(self.env)
        self.paths = config.EnginePaths.from_environ(self.env)

    def put(self, logical, data):
        path = Path(config.list_path(logical, self.paths.test_root))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_enumeration_stops_before_materialising_the_whole_directory(self):
        folder = self.root / 'many'
        folder.mkdir()
        for number in range(50):
            (folder / str(number)).write_bytes(b'')
        original = store.os.scandir
        consumed = []

        class Counted:
            def __init__(self, path):
                self.iterator = original(path)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.iterator.close()

            def __iter__(self):
                return self

            def __next__(self):
                item = next(self.iterator)
                consumed.append(item.name)
                return item

        with mock.patch.object(store.os, 'scandir', side_effect=Counted), mock.patch.object(store, 'MAX_ENTRIES', 2):
            with self.assertRaises(ValueError):
                store._walk(folder)
        self.assertEqual(len(consumed), 3)

    def test_all_roots_share_one_byte_budget_before_any_copy(self):
        self.put('/opt/etc/xkeen/data', b'123456')
        self.put('/opt/etc/nfqws2/data', b'123456')
        with mock.patch.object(store, 'MAX_BYTES', 10), mock.patch.object(store, '_copy') as copy:
            with self.assertRaisesRegex(ValueError, 'aggregate'):
                store.create(self.paths, purpose='bounded')
            copy.assert_not_called()
        self.assertFalse(Path(self.paths.snapshot_root).exists())

    def test_legacy_capture_uses_the_same_aggregate_preflight(self):
        self.put('/opt/etc/xkeen/data', b'123456')
        self.put('/opt/etc/nfqws2/data', b'123456')
        snapshot = Path(self.paths.snapshot_root) / '20260101-000000-1'
        (snapshot / 'files').mkdir(parents=True)
        (snapshot / 'STATE.tsv').write_bytes(b'FORMAT\t1\nSCOPE\tintegrated\n')
        with mock.patch.object(store, 'MAX_BYTES', 10), mock.patch.object(store, '_copy') as copy:
            with self.assertRaisesRegex(ValueError, 'aggregate'):
                bridge._capture_data(self.paths, snapshot, 'integrated')
            copy.assert_not_called()
        self.assertEqual(list((snapshot / 'files').iterdir()), [])

    def test_path_name_and_depth_budgets_are_checked_before_copy(self):
        source = self.put('/opt/etc/nfqws2/lists/a/b/c.list', b'a')
        with mock.patch.object(store, 'MAX_DEPTH', 2), mock.patch.object(store, '_copy') as copy:
            with self.assertRaises(ValueError):
                store.create(self.paths, purpose='deep')
            copy.assert_not_called()
        with mock.patch.object(store, 'MAX_METADATA', 2):
            with self.assertRaises(ValueError):
                store._walk(source.parent)

    def test_focused_budget_excludes_untouched_package_data(self):
        self.put('/opt/etc/nfqws2/nfqws2.conf', b'config')
        self.put('/opt/etc/nfqws2/lua/package.lua', b'package' * 100)
        with mock.patch.object(store, 'MAX_BYTES', 6):
            snapshot = store.create(self.paths, purpose='focused', focused=True,
                                    metadata=(('NFQWS_RUNNING', '0'),))
        self.assertEqual((snapshot / 'nfqws2/nfqws2.conf').read_bytes(), b'config')
        self.assertFalse((snapshot / 'nfqws2/lua').exists())

    def test_bridge_refuses_queue_coverage_mismatch_before_runtime(self):
        path = self.put('/opt/etc/nfqws2/nfqws2.conf', b'TCP_PORTS="80"\n')
        composition = compose.Composition(
            ['--filter-tcp=443', '--filter-l7=tls', '--hostlist-domains=example.org',
             '--lua-desync=fake:blob=fake_default_tls'],
            {'TCP_PORTS': '80', 'UDP_PORTS': '443', 'USER_PROFILES': '0'}, 'review')
        with mock.patch.object(validate.compose, 'compose', return_value=composition), \
                mock.patch.object(validate, 'validate_tokens') as runtime:
            with self.assertRaises(validate.ValidationError):
                bridge._strict(self.paths, self.env, str(path))
            runtime.assert_not_called()

    def test_bridge_delegates_to_native_validator_without_a_parallel_protocol(self):
        with mock.patch.object(validate, 'validate_config') as common:
            bridge._strict(self.paths, self.env, '/candidate.conf')
        common.assert_called_once()
        self.assertEqual(common.call_args.args[0].paths, self.paths)
        self.assertEqual(common.call_args.args[1], '/candidate.conf')


class ProbeControlReviewTests(unittest.TestCase):
    def test_aliases_and_ambiguous_queue_are_refused_before_read_or_spawn(self):
        cases = (['--qnum=300', '--qnum=301'], ['--qnum', '300'], ['--qnu=300'],
                 ['--interc=1'], ['--dae'], ['--lua-i=@/not-read'], ['--blo=x:@/not-read'],
                 ['--hostlist-a=/not-read'], ['--lua-d=fake'], ['--ne'], ['--chdi=/not-used'],
                 ['--'], ['-q300'], ['positional'])
        with mock.patch.object(validate, '_read_asset', side_effect=AssertionError('asset read')), \
                mock.patch.object(nfqws_process, 'run', side_effect=AssertionError('child started')):
            for tokens in cases:
                with self.subTest(tokens=tokens), self.assertRaises(validate.ValidationError):
                    validate.validate_tokens(tokens, '/not-read', {})

    def test_exact_control_names_are_not_mistaken_for_prefix_aliases(self):
        self.assertIsNone(validate._control_options([
            '--hostlist=/tmp/test', '--hostlist-auto=/tmp/auto', '--hostlist-exclude=/tmp/exclude',
            '--lua-init=@/tmp/approved', '--lua-desync=fake:blob=known', '--blob=known:0x11',
            '--qnum=300', '--intercept=1', '--daemon', '--dry-run', '--new=name']))

    def fixture(self, root):
        values = {'binary': b'BINARY', 'zapret-lib.lua': b'LIB', 'zapret-antidpi.lua': b'ANTIDPI', 'list': b'ab'}
        for name, value in values.items():
            (root / name).write_bytes(value)
        tokens = ['--lua-init=@' + str(root / name) for name in ('zapret-lib.lua', 'zapret-antidpi.lua')]
        tokens.extend(['--hostlist=' + str(root / 'list')] * 5)
        hashes = {name: hashlib.sha256(values[name]).hexdigest() for name in ('zapret-lib.lua', 'zapret-antidpi.lua')}
        return tokens, {'expected_binary_sha256': hashlib.sha256(values['binary']).hexdigest(),
                        'expected_lua_sha256': hashes}, sum(map(len, values.values()))

    def test_distinct_assets_share_a_budget_and_repeated_assets_are_read_once(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            tokens, pins, total = self.fixture(root)
            process = stack.enter_context(mock.patch.object(nfqws_process, 'run',
                return_value=nfqws_process.ProcessResult(0, 'no intercept quit')))
            reads = stack.enter_context(mock.patch.object(validate, '_read_asset', wraps=validate._read_asset))
            validate.validate_tokens(tokens, root / 'binary', os.environ, asset_limit=total, **pins)
            self.assertEqual(reads.call_count, 4)
            process.assert_called_once()
            process.reset_mock()
            with self.assertRaisesRegex(validate.ValidationError, 'aggregate'):
                validate.validate_tokens(tokens, root / 'binary', os.environ, asset_limit=total - 1, **pins)
            process.assert_not_called()

    def test_asset_read_deadline_applies_before_child_start(self):
        def slow_read(*args, **kwargs):
            time.sleep(0.02)
            return b'binary'
        with mock.patch.object(validate, '_read_asset', side_effect=slow_read), \
                mock.patch.object(nfqws_process, 'run') as process:
            with self.assertRaisesRegex(validate.ValidationError, 'deadline'):
                validate.validate_tokens([], '/not-executed', {}, timeout=0.005)
            process.assert_not_called()
        for options in ({'timeout': 0}, {'timeout': True}, {'asset_limit': 0}, {'asset_limit': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                validate.validate_tokens([], '/not-executed', {}, **options)

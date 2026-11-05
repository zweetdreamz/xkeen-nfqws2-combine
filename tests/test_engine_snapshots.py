"""Native snapshot inspection is byte-identical to the read-only shell mode."""
import io
import os
import tempfile
import unittest
from unittest import mock

import engine_fixture
import engine_run
import engine_scenarios
from kdn.engine import cli, config, console, snapshots


class SnapshotTests(unittest.TestCase):
    def test_show_snapshots_output_matches_the_shell(self):
        names = ['fresh', 'applied-default', 'synthetic21']
        names += [name for name in engine_scenarios.names() if name.startswith('snapshots-')]
        for name in names:
            fixture = engine_scenarios.build(name)
            for root in (fixture.root, str(fixture.root) + '/'):
                changed = engine_fixture.Fixture(root, fixture.mock_bin)
                with self.subTest(name=name, root=str(root)):
                    legacy = engine_run.run_legacy(['--show-snapshots'], changed)
                    result = engine_run.run_mode('show-snapshots', ['--show-snapshots'], changed)
                    self.assertFalse(result.fallback)
                    self.assertEqual((result.rc, result.out, result.err), (legacy.rc, legacy.out, legacy.err))
                    dispatched = engine_run.run_dispatcher(['--show-snapshots'], changed)
                    self.assertEqual(dispatched, legacy)

    def test_not_a_router_is_refused(self):
        out, err = io.StringIO(), io.StringIO()
        ctx = cli.Context(['--show-snapshots'], {}, console.Console(out, err), paths=config.EnginePaths.from_environ({}))
        with mock.patch.object(snapshots, 'is_router', return_value=False):
            self.assertEqual(snapshots.run(ctx), 1)
        self.assertEqual((out.getvalue(), err.getvalue()), ('', 'ERROR: this does not look like a Keenetic Entware environment.\n'))

    def test_describe_returns_none_for_invalid_pointers(self):
        for name in ('snapshots-missing', 'snapshots-symlink', 'snapshots-outside', 'snapshots-dotdot',
                     'snapshots-empty', 'snapshots-double-slash'):
            with self.subTest(name=name):
                paths = config.EnginePaths.from_environ(engine_scenarios.build(name).env)
                self.assertIsNone(snapshots.describe(paths).baseline)

    def test_first_line_permissions_symlinks_and_raw_names_match_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = engine_fixture.make_root(tmp)
            paths = config.EnginePaths.from_environ(fixture.env)
            os.makedirs(paths.snapshot_root)
            for leaf in ('good', 'a b', 'a\rb', 'café', '.'):
                candidate = paths.snapshot_root + '/' + leaf
                os.makedirs(candidate, exist_ok=True)
                for value in (candidate, candidate + '\nignored', candidate + '\0'):
                    fixture.write_bytes('/opt/etc/keenetic-discord-nfqws2/baseline.ptr', value.encode('utf-8') + b'\n')
                    ref = engine_run.run_legacy(['--show-snapshots'], fixture)
                    result = engine_run.run_mode('show-snapshots', ['--show-snapshots'], fixture)
                    self.assertEqual((result.rc, result.out, result.err), (ref.rc, ref.out, ref.err))
            os.chmod(paths.baseline_pointer, 0)
            self.assertIsNone(snapshots.read_pointer(paths, paths.baseline_pointer))
            os.chmod(paths.baseline_pointer, 0o600)

    def test_describe_is_silent_and_does_not_write(self):
        fixture = engine_scenarios.build('snapshots-all')
        before = engine_scenarios.digest(fixture)
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            result = snapshots.describe(config.EnginePaths.from_environ(fixture.env))
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(len(snapshots.lines(result)), 4)
        self.assertEqual(engine_scenarios.digest(fixture), before)

    def test_native_snapshot_mode_keeps_lightweight_import_budget(self):
        from test_engine_structure import importtime_modules

        fixture = engine_scenarios.build('fresh')
        result, names = importtime_modules(['-m', 'kdn.engine', '--show-snapshots'],
                                          env_extra={'KD_TEST_ROOT': str(fixture.root), 'KD_ALLOW_TEST_ROOT': '1'})
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn('kdn.engine.snapshots', names)
        self.assertEqual(names & {'subprocess', 'tempfile', 'shutil', 'dataclasses', 'typing', 'argparse', 'logging'}, set())

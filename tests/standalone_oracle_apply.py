"""Test-only old apply with a freshly captured supported recovery cue.

Never relabel historical snapshots. This is not deployed or importable by the
runtime. The frozen oracle still supplies the standalone mutation regression;
the new native reader is only asked to restore a fresh supported capture.
"""
import io
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/router'))
from kdn.common import lock
from kdn.engine import cli, config, console, options, rollback_ops, snapshot_store

env = dict(os.environ)
root = env.get('KD_TEST_ROOT', '')
if env.get('KD_ALLOW_TEST_ROOT') != '1' or not root or Path(root).resolve() == Path('/'):
    raise SystemExit('disposable test root required')
paths = config.EnginePaths.from_environ(env)
parsed = options.parse_args(['--snapshot-baseline', '--standalone-zapret', '--yes-router'])
ctx = cli.Context([], env, console.Console(io.StringIO(), io.StringIO()), paths=paths,
                  options=parsed, resolved=options.resolve(parsed, ''))
with lock.ProjectLock(paths.lock_dir):
    saved = rollback_ops.capture(ctx, 'synthetic-supported-preapply', 'standalone')
done = subprocess.run(['sh', *sys.argv[1:]], env=env)
if done.returncode == 0:
    with lock.ProjectLock(paths.lock_dir):
        snapshot_store.publish_pointer(paths, paths.latest_pointer, saved)
raise SystemExit(done.returncode)

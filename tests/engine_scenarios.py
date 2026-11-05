"""Lazy session roots, built by the shared shell function and checked for mutations."""
import atexit
import hashlib
import os
from pathlib import Path
import signal
import shutil
import tempfile

import engine_fixture
import engine_shell


_cache = {}
_base = None
_names = None
_failures = {}
_build_script = '''set -eu
SCRIPT_DIR="$KDN_SCENARIO_PROJECT"
. "$SCRIPT_DIR/tests/engine-scenarios-lib.sh"
engine_scenario "$KDN_SCENARIO_NAME" "$KDN_SCENARIO_ROOT" "$KDN_SCENARIO_BIN"
'''


def names():
    global _names
    if _names is None:
        done = engine_shell.run_sh('. "$KDN_SCENARIO_PROJECT/tests/engine-scenarios-lib.sh"\nengine_scenario_names',
                                   env=dict(os.environ, KDN_SCENARIO_PROJECT=str(engine_fixture.PROJECT)))
        if done.returncode:
            raise RuntimeError(done.stderr)
        _names = tuple(value for value in done.stdout.split('\n') if value)
    return _names


def digest(fixture):
    result = hashlib.sha256()
    for base in (fixture.root, fixture.mock_bin):
        for path in sorted(base.rglob('*')):
            relative = str(path.relative_to(base)).encode('utf-8', 'surrogateescape')
            info = path.lstat()
            result.update(relative + b'\0' + str(info.st_mode).encode() + b'\0')
            if path.is_symlink():
                result.update(os.readlink(path).encode('utf-8', 'surrogateescape'))
            elif path.is_file():
                result.update(path.read_bytes())
            result.update(b'\0')
    return result.hexdigest()


def build(name):
    global _base
    if name not in names():
        raise ValueError('unknown engine scenario: ' + name)
    if name in _failures:
        raise RuntimeError(_failures[name])
    if name not in _cache:
        if _base is None:
            _base = tempfile.TemporaryDirectory(prefix='engine-scenarios-')
        fixture = engine_fixture.make_root(Path(_base.name) / name)
        _cache[name] = (fixture, None)
        if os.environ.get('TEST_BUSYBOX_APPLETS') == '1':
            busybox = shutil.which('busybox')
            if busybox is None:
                raise RuntimeError('BusyBox reference requested, but busybox is missing')
            for applet in ('sh', 'awk', 'sed', 'grep', 'tr'):
                (fixture.mock_bin / applet).symlink_to(busybox)
        env = fixture.env
        env.update(KDN_SCENARIO_PROJECT=str(engine_fixture.PROJECT), KDN_SCENARIO_NAME=name,
                   KDN_SCENARIO_ROOT=str(fixture.root), KDN_SCENARIO_BIN=str(fixture.mock_bin))
        try:
            done = engine_shell.run_sh(_build_script, env=env, timeout=90)
        except BaseException:
            _failures[name] = 'scenario build interrupted: ' + name
            raise
        if done.returncode:
            _failures[name] = f'scenario {name} failed ({done.returncode}): {done.stderr}\n{done.stdout}'
            raise RuntimeError(_failures[name])
        _cache[name] = (fixture, digest(fixture))
    return _cache[name][0]


def assert_unchanged():
    for name, (fixture, before) in _cache.items():
        if before is not None and digest(fixture) != before:
            raise AssertionError('read-only scenario mutated: ' + name)


def close():
    global _base
    # Only fixture daemons whose cmdline contains this root may be signalled.
    # A malformed or foreign pidfile must never select another process.
    for fixture, _before in _cache.values():
        for filename in ('nfqws2.pid', 'kdn-telegram-ws.pid'):
            try:
                pid = int(fixture.path('/opt/var/run/' + filename).read_bytes().split(b'\n', 1)[0])
                cmdline = Path(f'/proc/{pid}/cmdline').read_bytes()
                if pid > 1 and os.fsencode(fixture.root) in cmdline:
                    os.kill(pid, signal.SIGTERM)
            except (OSError, ValueError):
                pass
    _cache.clear()
    _failures.clear()
    if _base is not None:
        _base.cleanup()
        _base = None


atexit.register(close)

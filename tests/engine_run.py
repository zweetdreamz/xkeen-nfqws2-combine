"""Byte-exact subprocess and in-process entry points for engine comparisons."""
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import contextlib
import io
import os
import shutil
import subprocess
import tempfile

import engine_fixture
from kdn.engine import cli, config, console, confvalues, options


@dataclass(frozen=True)
class Result:
    rc: int
    out: str
    err: str
    fallback: bool = False


class _Fallback(Exception):
    pass


def _execve(*_args):
    raise _Fallback


def _environment(fixture, extra=None):
    env = fixture.env
    env.pop('KDN_ENGINE', None)
    env.update(extra or {})
    return env


def _shell(args, fixture, extra_env, legacy):
    env = _environment(fixture, extra_env)
    if legacy:
        env['KDN_ENGINE'] = 'legacy'
    with contextlib.ExitStack() as stack:
        if env.get('TEST_BUSYBOX_APPLETS') == '1':
            busybox = shutil.which('busybox', path=env['PATH'])
            if busybox is None:
                raise RuntimeError('BusyBox reference requested, but busybox is missing')
            applets = stack.enter_context(tempfile.TemporaryDirectory(prefix='engine-reference-'))
            for applet in ('sh', 'awk', 'sed', 'grep', 'tr'):
                os.symlink(busybox, os.path.join(applets, applet))
            env['PATH'] = applets + os.pathsep + env['PATH']
        done = subprocess.run(['sh', str(engine_fixture.PROJECT / 'apply-discord-nfqws2.sh'), *args],
                              env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    return Result(done.returncode, done.stdout.decode('utf-8', 'surrogateescape'),
                  done.stderr.decode('utf-8', 'surrogateescape'))


def run_legacy(args, fixture, extra_env=None):
    return _shell(args, fixture, extra_env, True)


def legacy_results(cases, *, workers=4):
    """Run independent read-only reference processes, returning every result in order.

    Materialise cases on the caller thread: fixture construction/global patches must
    never migrate to workers. No memoisation and no production timeout changes.
    """
    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError('reference workers must be an integer from 1 to 8')
    cases = tuple(cases)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(_legacy_case, cases))


def _legacy_case(case):
    args, fixture, extra = case
    return run_legacy(args, fixture, extra)


def run_dispatcher(args, fixture, extra_env=None):
    return _shell(args, fixture, extra_env, False)


def make_context(fixture, args):
    env = _environment(fixture)
    paths = config.EnginePaths.from_environ(env)
    parsed = options.parse_args(args)
    resolved = options.resolve(parsed, confvalues.read_text(paths.nfqws_conf))
    return cli.Context(list(args), env, console.Console(io.StringIO(), io.StringIO()),
                       paths=paths, options=parsed, resolved=resolved, execve=_execve)


def run_mode(mode, args, fixture):
    ctx = make_context(fixture, args)
    output = ctx.console
    delayed = cli._WarningsConsole(output, ctx.resolved.warnings)
    ctx.console = delayed
    try:
        rc = cli.MODES[mode].run(ctx)
        delayed.emit()
        fallback = False
    except _Fallback:
        rc, fallback = 0, True
    return Result(rc, output._stdout.getvalue(), output._stderr.getvalue(), fallback)


def run_python(args, fixture):
    out, err = io.StringIO(), io.StringIO()
    try:
        rc = cli.main(args, environ=_environment(fixture), stdout=out, stderr=err, execve=_execve)
        fallback = False
    except _Fallback:
        rc, fallback = 0, True
    return Result(rc, out.getvalue(), err.getvalue(), fallback)

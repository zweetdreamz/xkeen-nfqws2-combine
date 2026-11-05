"""Atomic nfqws config publication with disposable-root and router context guards."""
import os

from kdn.common import fsutil
from kdn.engine import config, nfqws_render, system, transaction


def write_config(output, paths, environ):
    """Keep mode/bytes; reject live paths, wrong targets, links and special files.

    The production transaction adapter must not bypass this guard. Atomicity
    covers the config file only; multi-file rollback is the transaction's job.
    """
    from pathlib import Path

    expected = config.EnginePaths.from_environ(environ)
    if not expected.test_root or paths.nfqws_conf != expected.nfqws_conf:
        raise ValueError('nfqws writer requires exact KD_TEST_ROOT config path')
    target = Path(paths.nfqws_conf)
    boundary = Path(expected.test_root).resolve()
    if boundary == Path(boundary.anchor) or not target.is_relative_to(boundary):
        raise ValueError('unsafe test root')
    _publish_checked(output, target, boundary)


def _publish_checked(output, target, boundary):
    import stat

    for ancestor in (target, *target.parents):
        if ancestor == boundary:
            break
        if ancestor.is_symlink():
            raise ValueError('symlink in nfqws config path')
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('nfqws config is not a regular file')
    if not isinstance(output, nfqws_render.RenderOutput):
        raise TypeError('RenderOutput required')
    fsutil.atomic_bytes(target, output.config, stat.S_IMODE(info.st_mode))


def publish_config(output, ctx):
    """Confirmed native transaction entry. Caller owns project-lock/rollback.

    Full canonical EnginePaths equality rejects forged/inconsistent contexts, not
    just a matching target filename. Live use additionally requires root and
    Keenetic identity before reading or writing any config path.
    """
    from pathlib import Path

    if ctx.options is None or ctx.options.confirmed is not True:
        raise ValueError('nfqws publication requires explicit confirmation')
    expected = config.EnginePaths.from_environ(ctx.environ)
    if ctx.paths != expected:
        raise ValueError('nfqws publication requires canonical context paths')
    if expected.test_root:
        write_config(output, expected, ctx.environ)
        return
    if os.geteuid() != 0 or not system.is_router(expected, ''):
        raise ValueError('nfqws publication requires root on a Keenetic router')
    transaction.guard(ctx)
    _publish_checked(output, Path(expected.nfqws_conf), Path('/'))

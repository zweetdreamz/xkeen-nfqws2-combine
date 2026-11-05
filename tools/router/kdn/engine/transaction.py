"""One lock and one terminal result for native mutation transactions."""
import os
from pathlib import Path

from kdn.common import lock, xkeen
from kdn.engine import config, confvalues, system


def guard(ctx, *, readonly=False):
    if not readonly and not ctx.options.confirmed:
        raise ValueError('this mode changes router state; re-run with --yes-router.')
    expected = config.EnginePaths.from_environ(ctx.environ)
    if ctx.paths != expected or not system.is_router(expected, expected.test_root):
        raise ValueError('this does not look like a Keenetic Entware environment.')
    if not expected.test_root and os.geteuid() != 0:
        raise ValueError('root privileges are required.')
    xkeen.require(environ=ctx.environ)
    if not expected.test_root:
        if confvalues.init_value(expected, 'name_client') != 'xray':
            raise ValueError('native mutations require XKeen configured for Xray; Mihomo is unsupported')
    if expected.test_root and Path(expected.test_root).resolve() == Path('/'):
        raise ValueError('unsafe test root')


class Transaction:
    __slots__ = ('ctx', 'rollback', 'changed', 'result')

    def __init__(self, ctx):
        self.ctx, self.rollback, self.changed, self.result = ctx, None, False, 'ok'

    def stage(self, name):
        self.ctx.console.out('STAGE|' + name)
        self.ctx.console.flush()

    def arm(self, rollback):
        self.rollback, self.changed = rollback, True


def execute(ctx, operation):
    """Rollback on errors/signals while lock is held; emit RESULT only after release."""
    transaction = Transaction(ctx)
    code, failure = 0, None
    try:
        transaction.stage('preflight')
        guard(ctx)
        with lock.ProjectLock(ctx.paths.lock_dir):
            try:
                operation(transaction)
            except BaseException as error:
                transaction.result = 'failed'
                code = error.code if type(error).__name__ == 'SystemExit' and isinstance(error.code, int) else 1
                failure = error
                if transaction.changed and transaction.rollback is not None:
                    try:
                        transaction.stage('restore')
                        transaction.rollback()
                        transaction.result = 'rolled-back'
                    except BaseException:
                        transaction.result = 'partial'
                        ctx.console.err('CRITICAL: rollback was only partial; keep the rescue snapshot for recovery.')
    except BaseException as error:
        code = error.code if type(error).__name__ == 'SystemExit' and isinstance(error.code, int) else 1
        failure, transaction.result = error, 'failed'
    if failure is not None:
        # Do not include argv, config contents, credentials or subprocess output.
        if isinstance(failure, (ValueError, RuntimeError)):
            ctx.console.err('ERROR: ' + str(failure))
        else:
            ctx.console.err('ERROR: native transaction failed (' + type(failure).__name__ + ').')
    ctx.console.out('RESULT|' + transaction.result)
    return code

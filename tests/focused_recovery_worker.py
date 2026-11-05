"""Disposable subprocess seams: real focused transactions/files, synthetic service."""
import os
from pathlib import Path
import signal
import sys
from unittest import mock

from kdn.engine import cli, import_ops, nfqws_service, nfqws_write, snapshot_store


root = Path(os.environ['KD_TEST_ROOT'])
runtime = root / 'runtime'
pause_at = os.environ.get('FOCUSED_PAUSE', '')


def pause(point):
    if pause_at == point:
        print('FOCUSED_READY', flush=True)
        signal.pause()


def action(_ctx, verb):
    runtime.write_text('stopped' if verb == 'stop' else 'running')


def verify(_ctx, *_args, **_kwargs):
    if runtime.read_text() != 'running':
        raise RuntimeError('synthetic service not running')
    pause('after-restart')
    return 123


publish = nfqws_write.publish_config
restore = snapshot_store.restore_files
atomic = import_ops.fsutil.atomic_bytes


def publish_config(*args, **kwargs):
    pause('after-descriptor')
    return publish(*args, **kwargs)


def restore_files(*args, **kwargs):
    result = restore(*args, **kwargs)
    pause('restore-data')
    return result


def atomic_bytes(path, *args, **kwargs):
    if path.parent.name == 'imported-profiles':
        pause('before-descriptor')
    return atomic(path, *args, **kwargs)


with (mock.patch.object(import_ops.nfqws_validate, 'validate_config'),
      mock.patch.object(nfqws_service, 'pid', lambda _ctx: 123 if runtime.read_text() == 'running' else None),
      mock.patch.object(nfqws_service, 'action', action),
      mock.patch.object(nfqws_service, 'verify', verify),
      mock.patch.object(nfqws_write, 'publish_config', publish_config),
      mock.patch.object(snapshot_store, 'restore_files', restore_files),
      mock.patch.object(import_ops.fsutil, 'atomic_bytes', atomic_bytes)):
    raise SystemExit(cli.main(sys.argv[1:]))

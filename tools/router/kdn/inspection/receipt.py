"""Provenance of project-started Xray, invalid after foreign edits or restarts.

Only a writer that actually starts/restarts Xray may issue this receipt. Queries
never create it. Failure to record optional diagnostics cannot fail normal apply.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

from kdn.common import fsutil
from kdn.common import xray_process
from kdn.inspection import layout


def corpus_digest(directory):
    files = sorted(fsutil.bounded_files(Path(directory), maximum=128))
    checksum, total = hashlib.sha256(), 0
    for path in files:
        if path.name.startswith('.') or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('unsafe Xray receipt input')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
                raise ValueError('Xray receipt file limit')
            raw = stream.read(2 * 1024 * 1024 + 1)
        total += len(raw)
        if len(raw) > 2 * 1024 * 1024 or total > 16 * 1024 * 1024:
            raise ValueError('Xray receipt corpus limit')
        checksum.update(json.dumps([path.name, hashlib.sha256(raw).hexdigest()]).encode())
    return checksum.hexdigest()


def process_start(pid):
    raw = (Path('/proc') / str(pid) / 'stat').read_text(encoding='ascii')
    return raw[raw.rfind(')') + 2:].split()[19]


def value(directory, pid):
    return {'version': 1, 'pid': pid, 'starttime': process_start(pid), 'corpus_digest': corpus_digest(directory)}


def matches(path, directory, pid):
    try:
        if any(p.is_symlink() for p in (path, *path.parents)) or stat.S_IMODE(path.stat().st_mode) != 0o600:
            return False
        saved = fsutil.safe_json_file(path, maximum=4096)
        if type(saved.get('version')) is not int or type(saved.get('pid')) is not int:
            return False
        return saved == value(directory, pid)
    except (OSError, ValueError, IndexError):
        return False


def observation_current(path, directory, runtime):
    """File/proc-only freshness check for cached status and explicit approval."""
    if (not isinstance(runtime, dict) or set(runtime) != {'pid', 'starttime', 'corpus_digest'}
            or type(runtime.get('pid')) is not int or runtime['pid'] <= 1):
        return False
    pid = runtime['pid']
    try:
        return (runtime == {key: item for key, item in value(directory, pid).items() if key != 'version'}
                and matches(path, directory, pid) and xray_process.xray_identity(pid, directory))
    except (OSError, ValueError, IndexError):
        return False


def record(path, directory, pid, *, expected_digest=None):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('unsafe Xray receipt path')
    observed = value(directory, pid)
    if expected_digest is not None and observed['corpus_digest'] != expected_digest:
        raise ValueError('Xray files changed during restart')
    fsutil.atomic_json(path, observed, maximum=4096)
    fsutil.fsync_path(path.parent)


def refresh_if_prepared(path, directory, pid, *, expected_digest):
    if pid is None or not (Path(directory) / layout.FILE).is_file():
        return False
    try:
        record(path, directory, pid, expected_digest=expected_digest)
        return True
    except (OSError, ValueError, IndexError):
        return False

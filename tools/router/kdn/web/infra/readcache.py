"""Bounded advisory UI reads only; never admission, validation or mutation."""
from copy import deepcopy
import json
import os
import stat
import threading
import time


MAX_ENTRY_BYTES = 128 * 1024
MAX_STAMPS = 512
_lock = threading.RLock()
_locks = {name: threading.RLock() for name in ('status', 'sources', 'versions')}
_entries = {}
_epoch = 0


def invalidate():
    global _epoch
    with _lock:
        _epoch += 1
        _entries.clear()


def _stamp(paths):
    """No config contents; a link, error or oversized listing disables caching."""
    result = []
    pending = list(paths)
    try:
        for path in pending:
            if len(result) >= MAX_STAMPS:
                return None
            try:
                info = path.lstat()
            except FileNotFoundError:
                result.append((str(path), None))
                continue
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                return None
            result.append((str(path), info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino))
            if stat.S_ISDIR(info.st_mode):
                # Only direct children: callers explicitly name service subdirs.
                children = []
                with os.scandir(path) as entries:
                    for child in entries:
                        if len(result) + len(children) >= MAX_STAMPS:
                            return None
                        child_info = child.stat(follow_symlinks=False)
                        if stat.S_ISLNK(child_info.st_mode) or not (stat.S_ISREG(child_info.st_mode) or stat.S_ISDIR(child_info.st_mode)):
                            return None
                        children.append((child.path, child_info.st_mtime_ns, child_info.st_ctime_ns,
                                         child_info.st_size, child_info.st_ino))
                result.extend(sorted(children))
    except OSError:
        return None
    return tuple(result)


def read(name, paths, loader, *, ttl=2, validate_hit=None):
    if name not in _locks or not 0 < ttl <= 10:
        raise ValueError('invalid UI cache policy')
    with _locks[name]:
        stamp = _stamp(paths)
        with _lock:
            epoch = _epoch
            entry = _entries.get(name)
        if stamp is not None and entry and entry[0] == epoch and entry[1] == stamp and entry[2] > time.monotonic():
            try:
                if validate_hit is not None:
                    validate_hit()  # actual version, even for a cached status
            except BaseException:
                invalidate()
                raise
            with _lock:
                if _epoch == epoch and _entries.get(name) is entry and entry[2] > time.monotonic():
                    return deepcopy(entry[3])
        data = loader()
        if (stamp is not None and isinstance(data, dict) and data.get('ok') is True
                and data.get('status') != 'error' and _stamp(paths) == stamp
                and len(json.dumps(data, ensure_ascii=False).encode('utf-8')) <= MAX_ENTRY_BYTES):
            with _lock:
                if _epoch == epoch:
                    _entries[name] = (epoch, stamp, time.monotonic() + ttl, deepcopy(data))
        return data

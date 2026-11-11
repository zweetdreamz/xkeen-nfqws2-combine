"""Short compatibility cache for registry/UI work, never for live apply.

Only positive results are cached. Binary/script replacement or TTL expiry
forces the actual version commands again; unsafe/missing paths bypass cache.
"""
import os
import threading
import time

from kdn.common import xkeen

_lock = threading.Lock()
_entries = {}
TTL = 60


def _stamp(paths):
    try:
        return tuple((os.path.realpath(path), info.st_dev, info.st_ino,
                      info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                     for path in paths for info in [os.stat(path)])
    except OSError:
        return None


def require_registry_versions(manager):
    paths = (manager.xkeen, manager.xray)
    with _lock:
        stamp = _stamp(paths)
        entry = _entries.get(paths)
        if stamp is not None and entry and entry[0] == stamp and entry[1] > time.monotonic():
            return
        xkeen.require(manager.xkeen)
        manager._require_supported_xray()
        if stamp is not None and _stamp(paths) == stamp:
            if len(_entries) >= 8:
                _entries.clear()
            _entries[paths] = (stamp, time.monotonic() + TTL)

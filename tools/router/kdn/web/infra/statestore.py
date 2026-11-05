"""A JSON state file with one lock around its read-modify-writes: the home of automation-state.json.

Writers of the file are several threads (the scheduler, the slot job, the recovery thread, the status request).
Every change that starts from what is on disk goes through ``update`` or ``mutate``, which read the file, change it
and write it back while holding the lock, so no writer overwrites another's change with a stale copy.
"""

import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from kdn.common import fsutil


CORRUPT_SUFFIX = ".corrupt"


class StateStore:
    """The state file at ``path()``, guarded by ``lock()``; ``default()`` builds the state of a missing file.

    ``path`` and ``lock`` are called on every operation, so a path or a lock that is swapped later is followed.
    The lock is a plain, non-reentrant ``threading.Lock``: ``change`` of ``mutate`` must not call the store.
    """

    def __init__(self, path, lock, default):
        self._path = path
        self._lock = lock
        self._default = default

    def read(self):
        """The state on disk: the default for a missing file, the default plus ``state_error`` for an unreadable one."""
        return self._read(self._path())

    def write(self, state):
        """Replace the file with ``state`` without its ``state_error``; an unreadable file is kept as ``.corrupt``."""
        with self._lock():
            self._save(self._path(), state)

    def preserve(self):
        """Copy an unreadable file to ``.corrupt`` under the lock; True when the copy was made.

        A missing or readable file, an empty one, a link and an oversized one are not copied: it returns False.
        """
        with self._lock():
            return _keep_corrupt_copy(self._path())

    def update(self, **changes):
        """Merge ``changes`` into the stored state under the lock and return the state."""
        return self.mutate(lambda state: state.update(changes))

    def mutate(self, change):
        """Read the state, call ``change(state)`` and write it back, all under the lock; return the state.

        When ``change`` returns ``False`` the write is skipped and the file is left untouched.
        """
        with self._lock():
            path = self._path()
            state = self._read(path)
            if change(state) is False:
                return state
            self._save(path, state)
            return state

    def _read(self, path):
        try:
            return fsutil.safe_json_file(path)
        except FileNotFoundError:
            return self._default()
        except (OSError, ValueError) as exc:
            return {**self._default(), "state_error": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _save(path, state):
        # state_error describes the unreadable file this write replaces; never persist it.
        state = {key: value for key, value in state.items() if key != "state_error"}
        _keep_corrupt_copy(path)
        fsutil.atomic_text(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        fsutil.fsync_path(path.parent)
        fsutil.fsync_path(path.parent.parent)


def _keep_corrupt_copy(path):
    """Copy a file that does not read as a JSON object to ``<name>.corrupt`` before it is overwritten.

    An empty file is not copied: it holds nothing to keep and would only replace an earlier, real copy.
    Returns True when a copy was made.
    """
    try:
        fsutil.safe_json_file(path)
        return False
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        pass
    try:
        data = _read_regular_file(path)
        if not data:
            return False
        _replace_file(path.with_name(path.name + CORRUPT_SUFFIX), data)
        return True
    except OSError as exc:
        # The copy is a courtesy: it must not keep the state from being written.
        print(f"state store: cannot keep a copy of unreadable {path.name}: {exc}", file=sys.stderr, flush=True)
        return False


def _read_regular_file(path):
    """Bytes of a regular file of at most MAX_JSON_BYTES that is not reached through a symlink, else None."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > fsutil.MAX_JSON_BYTES:
        return None
    # The file may be swapped for a symlink or a FIFO after the lstat: do not follow it, do not block on it.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > fsutil.MAX_JSON_BYTES:
            return None
        data = stream.read(fsutil.MAX_JSON_BYTES + 1)
    return data if len(data) <= fsutil.MAX_JSON_BYTES else None


def _replace_file(path, data):
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

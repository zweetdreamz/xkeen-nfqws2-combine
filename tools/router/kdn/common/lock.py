"""The project lock: one mkdir directory with a pid file, shared by every tool that changes the router.

/opt/tmp/keenetic-discord-nfqws2.lock is taken by apply-discord-nfqws2.sh, the tuner
runner (router-candidate-runner.sh), zapret_autotune_job.py and vpn_node_manager.py.
During an upgrade copies of different ages meet on the same directory, so the on-disk
protocol never changed: a directory, and a `pid` file in it that holds the owner's PID
and a newline. This module respects a holder of the old protocol; the old copies respect
a holder of this one except in the short windows described at the end.

Protocol v2:

1. Acquire with mkdir(LOCK, 0o700). Right after it the pid is published under the
   same mutex as stale takeover, atomically and exclusively: written to `pid.tmp-<pid>`
   (mode 600), hard-linked to `pid` (os.link fails
   if a pid exists; a filesystem without hard links falls back to os.replace) and the
   temporary file removed. No reader sees a half-written pid file, and a process that was
   suspended between its mkdir and the publication cannot overwrite the pid of the process
   that took its (by then stale) directory over: it gives way and starts again.
2. mkdir and the pid cannot be one atomic step, so a lock without a valid pid means
   "being taken right now", not "stale". The reader looks at the pid again and again
   for up to `pid_wait` seconds (the shell copies: KD_LOCK_PID_WAIT iterations of
   `sleep 1`; Python: DEFAULT_PID_WAIT, polled every `poll` seconds). This closes the
   race of the old protocol, where a second process saw the empty directory, took it
   for stale, removed it and took it as well. While it waits:
   - a pid shows up and the process is alive: the lock is busy;
   - a pid shows up and the process is dead: the lock is stale, no more waiting;
   - the directory disappears: the holder gave up, start again with mkdir;
   - no pid ever shows up: the lock is stale.
3. A stale lock (a dead pid, or no pid in `pid_wait` seconds) is taken over under a mutex:
   flock(2) on `<LOCK>.takeover`, a file beside the directory that is created on demand
   and never deleted (two takers must never lock two different files). The kernel drops a
   flock when its holder dies, so the mutex cannot go stale. It is polled every `poll`
   seconds for max(pid_wait, 1) seconds, then LockBusy. Under the mutex the pid is read
   once more. Not the pid seen before: the lock was released or taken over meanwhile, so
   it is busy (a live pid, or no pid yet) or taken again (gone, or another dead pid). The
   pid seen before is alive now (the number was reused): busy. Otherwise the dead pid is
   unlinked, the `pid.tmp-<pid>` of dead processes are removed, the directory is removed
   (a pid file with garbage in it goes with it), made again and the pid published, all
   before the mutex is released. Nobody moves a pid file that is not stale, so a holder
   that releases at any moment of a takeover leaves nothing behind. Other files in the
   directory are not ours to delete: the lock is then refused with "stale lock directory
   is not empty", as the engine does; a live pid or a live writer's `pid.tmp-<pid>` that
   shows up there makes it busy with that pid. Where flock is not supported (ENOLCK,
   EOPNOTSUPP, ENOSYS, EINVAL), a fresh mkdir acquisition can still publish its PID,
   but stale takeover is refused: deleting a PID without synchronization is unsafe.
4. Release removes `pid` and the directory only if the pid in the file is our own.

A pid in the file is alive unless kill(pid, 0) says "no such process" (PermissionError
means alive) or the process is a zombie.

Copies of the old protocol that have not moved here yet (an engine, tuner or
runner of an older release) may publish without this mutex, or do not wait for a pid and
take a stale lock over without the mutex (`rm pid; rmdir; mkdir`). While they are around,
a lock can be mistaken for a stale one by them in the microseconds between its mkdir and
its pid, and between the unlink of the pid and the rmdir at release; and a takeover by
such a copy that meets one by this module in the same microseconds can end with two
owners. This module waits for such writers' PIDs, but older copies that publish
without the mutex cannot provide the same publication/takeover guarantee.
"""

import contextlib
from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import Path
import time

from kdn.common import proc


DEFAULT_PID_WAIT = 2.0
PID_FILE = "pid"
TAKEOVER_SUFFIX = ".takeover"
# New tries when the lock directory vanishes under us or is taken by somebody else again.
_MAX_ATTEMPTS = 20
_VANISHED = object()
# Files a contender leaves in the directory for the moment of its own step.
_LEFTOVER_PATTERN = f"{PID_FILE}.tmp-*"
# os.link on a filesystem without hard links.
_NO_HARD_LINKS = frozenset({errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK})
# flock on a filesystem or kernel without it.
_NO_FLOCK = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS, errno.EINVAL})
# Seconds a taker waits for the takeover mutex at least, whatever pid_wait is.
_MIN_MUTEX_WAIT = 1.0


class LockBusy(RuntimeError):
    """The lock is held by a live process or cannot be taken over safely."""

    def __init__(self, message, pid=None):
        super().__init__(message)
        self.pid = pid


@dataclass(frozen=True)
class LockState:
    exists: bool
    pid: int | None
    alive: bool


def inspect_lock(path):
    """Snapshot of the lock for display and for a coordinator; reads only and never waits."""
    path = Path(path)
    if not path.exists():
        return LockState(False, None, False)
    pid = proc.read_job_pid(path / PID_FILE)
    return LockState(True, pid, pid is not None and proc.process_alive(pid))


def _link_new(source, target):
    """Make `target` another name of `source`; FileExistsError if it exists (no hard links: a rename)."""
    try:
        os.link(source, target)
    except OSError as exc:
        if exc.errno not in _NO_HARD_LINKS:
            raise
        os.replace(source, target)


def _busy(pid):
    if pid is None:
        return LockBusy("another project operation is active")
    return LockBusy(f"another project operation is active (PID {pid})", pid)


class ProjectLock:
    """The lock at `path`: acquire() raises LockBusy, release() is safe to repeat."""

    def __init__(self, path, *, pid_wait=DEFAULT_PID_WAIT, poll=0.1):
        self.path = Path(path)
        self.pid_wait = pid_wait
        self.poll = poll
        self._held = False
        self._mutex_supported = None

    @property
    def held(self):
        return self._held

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc_info):
        self.release()

    def acquire(self):
        """Take the lock or raise LockBusy; a stale lock is taken over."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(_MAX_ATTEMPTS):
            created = self._create()
            if created:
                return
            if created is False:
                continue
            observed = self._settle()
            if observed is _VANISHED:
                continue
            if observed is not None and proc.process_alive(observed):
                raise _busy(observed)
            if self._take_over(observed):
                return
        raise LockBusy("the project lock keeps changing hands")

    def release(self):
        """Remove the lock if its pid is ours; a lock taken over by another process stays."""
        if not self._held:
            return
        self._held = False
        if self._pid() != os.getpid():
            return
        (self.path / PID_FILE).unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            self.path.rmdir()

    def _pid(self):
        return proc.read_job_pid(self.path / PID_FILE)

    def _create(self):
        """mkdir and publish the pid: True if held, False if the race was lost, None if the directory exists."""
        try:
            self.path.mkdir(mode=0o700)
        except FileExistsError:
            return None
        return self._publish_pid()

    def _settle(self):
        """Wait for the holder's pid: the pid, None if none appeared in pid_wait, or _VANISHED."""
        deadline = time.monotonic() + self.pid_wait
        while True:
            pid = self._pid()
            if pid is not None:
                return pid
            if not self.path.exists():
                return _VANISHED
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(self.poll, remaining))

    def _publish_pid(self):
        """Serialize publication against stale cleanup, including its invalid-pid branch."""
        with self._takeover_mutex():
            return self._write_pid()

    def _write_pid(self):
        """Create `pid` with our pid in one step, never over another pid; False if the race was lost."""
        pid_file = self.path / PID_FILE
        temporary = self.path / f"{PID_FILE}.tmp-{os.getpid()}"
        try:
            if pid_file.exists():
                return False
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(f"{os.getpid()}\n")
            _link_new(temporary, pid_file)
        except BaseException as exc:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            # The directory was taken over under us (macOS says EINVAL for it as well), or its new owner has published.
            if isinstance(exc, FileNotFoundError | FileExistsError):
                return False
            if isinstance(exc, OSError) and (exc.errno == errno.EINVAL or not self.path.is_dir()):
                return False
            with contextlib.suppress(OSError):
                self.path.rmdir()
            raise
        temporary.unlink(missing_ok=True)
        self._held = True
        return True

    def _take_over(self, observed):
        """Take the stale lock we saw (pid `observed`, or None) over: True if held, False to start again."""
        with self._takeover_mutex() as synchronized:
            if not synchronized:
                # Without flock no observation can authorize deleting a PID:
                # a publisher or another taker may replace it before unlink.
                raise LockBusy("stale lock takeover requires flock support")
            current = self._pid()
            if current != observed:
                if self.path.exists() and (current is None or proc.process_alive(current)):
                    raise _busy(current)
                return False
            if observed is not None:
                if proc.process_alive(observed):
                    raise _busy(observed)
                (self.path / PID_FILE).unlink(missing_ok=True)
            if not self._remove_directory():
                return False
            return self._create() is True

    @contextlib.contextmanager
    def _takeover_mutex(self):
        """Serialize publication and takeover; nested publication reuses this handle's mutex."""
        if self._mutex_supported is not None:
            yield self._mutex_supported
            return
        mutex = self.path.with_name(self.path.name + TAKEOVER_SUFFIX)
        descriptor = os.open(mutex, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self._mutex_supported = self._flock(descriptor)
            yield self._mutex_supported
        finally:
            self._mutex_supported = None
            os.close(descriptor)

    def _flock(self, descriptor):
        deadline = time.monotonic() + max(self.pid_wait, _MIN_MUTEX_WAIT)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockBusy("a stale lock is being taken over") from None
                time.sleep(min(self.poll, remaining))
            except OSError as exc:
                if exc.errno not in _NO_FLOCK:
                    raise
                return False
            else:
                return True

    def _remove_directory(self):
        """Remove the stale directory; False if a pid showed up in it that is dead as well (start again)."""
        for leftover, writer in self._leftovers():
            if not proc.process_alive(writer):
                leftover.unlink(missing_ok=True)
        invalid_pid_removed = False
        while True:
            try:
                self.path.rmdir()
            except FileNotFoundError:
                return True
            except OSError as exc:
                current = self._pid()
                if current is not None:
                    if proc.process_alive(current):
                        raise _busy(current) from exc
                    return False
                writer = next((pid for _leftover, pid in self._leftovers() if proc.process_alive(pid)), None)
                if writer is not None:
                    raise _busy(writer) from exc
                pid_file = self.path / PID_FILE
                if invalid_pid_removed or not pid_file.is_file():
                    raise LockBusy(f"stale lock directory is not empty: {self.path}") from exc
                # A pid file without a valid pid (empty, garbage) is stale as well.
                invalid_pid_removed = True
                pid_file.unlink(missing_ok=True)
            else:
                return True

    def _leftovers(self):
        for leftover in self.path.glob(_LEFTOVER_PATTERN):
            writer = leftover.name.rpartition("-")[2]
            if writer.isdigit():
                yield leftover, int(writer)

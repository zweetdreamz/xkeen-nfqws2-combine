"""Admission of the panel's jobs and quick operations: the one place that decides "the router is busy".

The coordinator knows the families only by name and asks them through probes; it never touches job files. It
only ever tries the start lock and reads the other locks (a hold's `locked()`, the project lock directory), so it
cannot wait for a lock and cannot take part in a lock cycle. The project lock is inspected, never taken: the
panel's long work runs in child processes, which own it.
"""

from collections.abc import Callable
import contextlib
from dataclasses import dataclass

from kdn.common import errors
from kdn.common import lock


STARTING = "другое задание уже запускается; повторите через несколько секунд"
PROJECT_BUSY = "проект занят другой операцией (PID {pid}); повторите позже"

# The order the families are checked in, and the names their refusal texts and probes carry.
_FAMILIES = ("route", "tuner", "diagnostic")


@dataclass(frozen=True)
class Refusals:
    """Refusal texts of one operation; project=None means the operation does not ask the project lock."""

    route: str
    tuner: str
    diagnostic: str
    starting: str = STARTING
    project: str | None = PROJECT_BUSY


@dataclass(frozen=True)
class _Hold:
    held: Callable[[], bool]
    message: str


class Coordinator:
    """Decides whether a job or an operation may start: holds, active families, the project lock."""

    def __init__(self, *, start_lock, probes, project_lock):
        if set(probes) != set(_FAMILIES):
            raise ValueError(f"probes must name exactly {', '.join(_FAMILIES)}: {', '.join(sorted(probes))}")
        self._start_lock = start_lock
        self._probes = dict(probes)
        self._project_lock = project_lock
        self._holds = {}
        self._starting = None

    def add_hold(self, name, held, message):
        """Register a long external hold (`held()` is true while it lasts); the same name replaces the old one."""
        self._holds[name] = _Hold(held, message)

    def held(self, name):
        """The message of the hold `name` while it is held, else None."""
        hold = self._holds.get(name)
        if hold is not None and hold.held():
            return hold.message
        return None

    def active(self):
        """The first family that is running (route, tuner, diagnostic), or None."""
        for family in _FAMILIES:
            if self._probes[family]():
                return family
        return None

    def starting(self):
        """The family of the job that is being started right now, or None."""
        return self._starting

    def start_in_progress(self):
        """True while any start is inside exclusive(), also one without a family."""
        return self._start_lock.locked()

    def ensure_idle(self, refusals, *, holder=None):
        """Raise Busy if a hold (but `holder`'s own), a family or another process's project lock is active."""
        for name, hold in list(self._holds.items()):
            if name != holder and hold.held():
                raise errors.Busy(hold.message)
        family = self.active()
        if family is not None:
            raise errors.Busy(getattr(refusals, family))
        self._ensure_project_free(refusals)

    @contextlib.contextmanager
    def exclusive(self, refusals, *, family=None, holder=None):
        """Admit one start at a time: take the start lock without waiting, announce `family`, check the router."""
        if family is not None and family not in _FAMILIES:
            raise ValueError(f"unknown job family: {family!r}")
        if not self._start_lock.acquire(blocking=False):
            raise errors.Busy(refusals.starting)
        try:
            self._starting = family
            self.ensure_idle(refusals, holder=holder)
            yield
        finally:
            self._starting = None
            self._start_lock.release()

    def _ensure_project_free(self, refusals):
        if refusals.project is None:
            return
        path = self._project_lock()
        if path is None:
            return
        state = lock.inspect_lock(path)
        if state.exists and state.alive:
            raise errors.Busy(refusals.project.format(pid=state.pid))

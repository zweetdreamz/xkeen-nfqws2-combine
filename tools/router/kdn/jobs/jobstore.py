"""The store of one family of jobs: its state file, pid file, process and cancel marker.

Everything that changes the state file of a family goes through one RLock: prepare(), clear(), write_state(),
update_state() and settle() (and spawn() while it starts the process and writes the pid file). A reconcile that
read the state of job A therefore cannot write it back over the state of job B that was prepared meanwhile:
settle() looks at the job id and at the process again under the lock.

The panel never writes the state of a live job that it does not lead: a tool-owned family (tuner, diagnostics)
writes its state.json itself, the panel only prepares the initial state and settles a dead job it started.
"""

import contextlib
import json
import os
import signal
import stat
import subprocess
import threading
import traceback

from kdn.common import fsutil
from kdn.common import proc
from kdn.common import timeutil
from kdn.jobs import jobspec


# job.id and the cancel marker are tiny; a bigger file is not ours.
_JOB_ID_LIMIT = 256
_MARKER_LIMIT = 4096


def clear_files(directory, paths, place):
    """Create the private job directory and remove the previous job's files.

    Only regular files and symlinks are removed; anything else is refused.
    """
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    for path in paths:
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                raise RuntimeError(f"необычный объект в {place}: {path}")
        except FileNotFoundError:
            pass


class JobStore:
    """The files and the process of the jobs of ``family``; paths and markers are read from it on every call."""

    def __init__(self, family):
        self.family = family
        self._lock = threading.RLock()

    def pid(self):
        """PID in the family's pid file, or None."""
        return proc.read_job_pid(self.family.pid())

    def alive(self, pid):
        """True if ``pid`` is a live process whose argv holds every marker of the family as a whole argument."""
        markers = self.family.marker()
        if not markers:
            return False
        command = proc.job_command(pid)
        return command is not None and all(marker in command for marker in markers)

    def active(self):
        pid = self.pid()
        return bool(pid and self.alive(pid))

    def job_id(self):
        """The id prepare() recorded in job.id; empty if there is none (a job of an older panel, or run by hand)."""
        path = self.family.directory() / jobspec.JOB_ID_NAME
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                return ""
            with path.open("rb") as stream:
                return stream.read(_JOB_ID_LIMIT).decode("utf-8").strip()
        except (OSError, UnicodeError):
            return ""

    def read_state(self):
        """The state as a dict; raises what fsutil.safe_json_file raises (FileNotFoundError, OSError, ValueError)."""
        return fsutil.safe_json_file(self.family.state())

    def write_state(self, state):
        with self._lock:
            self._write(state)

    def update_state(self, job_id, **changes):
        """Merge ``changes`` into the state of ``job_id``, for a state the panel or its worker leads; else False."""
        with self._lock:
            state = self._state_of(job_id)
            if state is None:
                return False
            state.update(changes)
            self._write(state)
            return True

    def settle(self, job_id, *, expected_statuses=None, **changes):
        """Write ``changes`` into the state of a dead job (a reconcile); False if it is not that job or not ours.

        The job id and the process are checked again under the lock. A live process raises RuntimeError. For a
        tool-owned family the job must be one the panel started (job.id), not a tool run by hand. Optional
        expected_statuses is checked under the same lock, so a terminal write wins over a stale reconcile.
        """
        with self._lock:
            state = self._state_of(job_id)
            if state is None:
                return False
            if expected_statuses is not None and state.get("status") not in expected_statuses:
                return False
            if self.active():
                raise RuntimeError("задание ещё выполняется")
            if self.family.tool_owned and self.job_id() != job_id:
                return False
            state.update(changes)
            self._write(state)
            return True

    def clear(self):
        """Remove the files of the previous job: the family's files, job.id, the cancel marker and the extras."""
        with self._lock:
            family = self.family
            directory = family.directory()
            paths = [*family.files(), directory / jobspec.JOB_ID_NAME, directory / jobspec.CANCEL_REQUEST_NAME]
            clear_files(directory, paths, family.place)
            if family.extra is not None:
                for path in family.extra():
                    if path.is_file() and not path.is_symlink():
                        with contextlib.suppress(FileNotFoundError):
                            path.unlink()

    def prepare(self, spec):
        """Clear the previous job, record the id of the new one and write its initial state."""
        self._check(spec)
        with self._lock:
            self.clear()
            fsutil.atomic_text(self.family.directory() / jobspec.JOB_ID_NAME, f"{spec.job_id}\n")
            if spec.initial:
                self._write(spec.initial)

    def spawn(self, spec, on_exit=None):
        """Start the job's process in a new session, record its pid and return it.

        A thread waits for the process and calls ``on_exit()`` after it ended (an error of ``on_exit`` goes to
        stderr). An OSError of the start is raised and no pid file is written.
        """
        self._check(spec)
        family = self.family
        environment = {**proc.command_env(), "PYTHONUNBUFFERED": "1", **spec.env}
        with self._lock:
            with family.log().open("ab", buffering=0) as output:
                process = subprocess.Popen(
                    list(spec.argv),
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    cwd=spec.cwd,
                    env=environment,
                    start_new_session=True,
                )
            try:
                fsutil.atomic_text(family.pid(), f"{process.pid}\n")
                threading.Thread(target=self._reap, args=(process, on_exit), name=f"{family.name}-reaper", daemon=True).start()
            except BaseException:
                # A launched but unrecorded job must not keep changing router
                # state after the panel has reported that the start failed.
                try:
                    proc.stop_process_group(process, 2)
                except Exception:
                    with contextlib.suppress(Exception):
                        process.kill()
                    with contextlib.suppress(Exception):
                        process.wait(timeout=2)
                with contextlib.suppress(OSError):
                    family.pid().unlink(missing_ok=True)
                raise
        return process.pid

    def request_cancel(self, none_message):
        """Record the cancellation in cancel.request and TERM the job's process group; state.json is not touched.

        Raises RuntimeError(none_message) if the family has no live process of its own.
        """
        with self._lock:
            pid = self.pid()
            if not pid or not self.alive(pid):
                raise RuntimeError(none_message)
            marker = {"job_id": self.job_id(), "pid": pid, "requested_utc": timeutil.utc_now()}
            fsutil.atomic_text(
                self.family.directory() / jobspec.CANCEL_REQUEST_NAME,
                json.dumps(marker, ensure_ascii=False, indent=2) + "\n",
            )
            # prepare/spawn must not replace the family between identity
            # validation and publication/signalling of this cancellation.
            if self.pid() != pid or not self.alive(pid):
                (self.family.directory() / jobspec.CANCEL_REQUEST_NAME).unlink(missing_ok=True)
                raise RuntimeError(none_message)
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError as exc:
                (self.family.directory() / jobspec.CANCEL_REQUEST_NAME).unlink(missing_ok=True)
                raise RuntimeError(none_message) from exc
        return pid

    def cancel_requested(self):
        """True if the cancel marker belongs to the current job: its job.id and the pid of the pid file."""
        job_id = self.job_id()
        pid = self.pid()
        if not job_id or pid is None:
            return False
        try:
            marker = fsutil.safe_json_file(self.family.directory() / jobspec.CANCEL_REQUEST_NAME, maximum=_MARKER_LIMIT)
        except (OSError, ValueError):
            return False
        return marker.get("job_id") == job_id and marker.get("pid") == pid

    def _check(self, spec):
        if spec.family != self.family.name:
            raise ValueError(f"задание семейства {spec.family} передано хранилищу {self.family.name}")
        if not spec.job_id:
            raise ValueError("у задания нет идентификатора")

    def _write(self, state):
        fsutil.atomic_text(self.family.state(), json.dumps(state, ensure_ascii=False, indent=2) + "\n")

    def _state_of(self, job_id):
        """The state if it reads and belongs to ``job_id``, else None; the caller holds the lock."""
        if not isinstance(job_id, str) or not job_id:
            return None
        try:
            state = self.read_state()
        except (OSError, ValueError):
            return None
        return state if state.get("job_id") == job_id else None

    @staticmethod
    def _reap(process, on_exit):
        code = process.wait()
        # Popen stubs of the tests return something else from wait(): no real process ended, nothing to reconcile.
        if on_exit is None or not isinstance(code, int):
            return
        try:
            on_exit()
        except Exception:
            traceback.print_exc()

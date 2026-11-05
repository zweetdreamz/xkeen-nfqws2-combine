"""External commands, processes and packages of the engine: the one place where kdn.engine starts a program.

``run`` starts a command the way the script's ``$(...)`` does: the caller's environment, stdin and stderr on
/dev/null (or stderr merged into stdout), the child in the process group of the caller. ``kdn.common.proc`` is not
used: it replaces ``PATH``, starts every child in a new session and merges the streams. A child stays in
the group of the engine so that the TERM that the panel sends to the group reaches it (``proc.stop_process_group``);
it is also registered with ``lifecycle``, so the handler of the engine process kills it by its own pid. A timeout
kills the child's pid (TERM, ``KILL_GRACE`` seconds, KILL) and nothing else: never the group, which holds the
engine, and never a grandchild. A grandchild that keeps the pipe open after its parent died does not hold the
result back longer than ``DRAIN_WAIT``. Nothing here waits without a timeout: a ``Popen.wait()`` or ``communicate()``
without one holds the lock of the wait in the main thread, so the signal handler that runs in that thread cannot
reap the child it has just killed and spends ``2 * grace`` seconds on it; an unbounded run is a loop of
``SLICE``-second waits.

The ports of ``have``, ``process_running``, ``package_version``, ``package_present``, ``nfqws_service_pid`` /
``nfqws_pid_is_service`` and the xray lookup of ``xray_test_config`` read the same bytes as the shell: ``$(...)``
drops NUL bytes and trailing newlines, ``tr '\\0' ' '`` makes the cmdline one string whose words are cut at spaces
and newlines, ``kill -0`` is ``os.kill(pid, 0)``. What the port does not model: the message that ``sed`` prints to
stderr for an unreadable pidfile; ``command -v`` of busybox ash that finds a regular file without the execute bit
(dash and ``have`` skip it); an unset ``PATH`` (``os.defpath``, as ``Popen`` has it).

``timed_out`` and the status 124 describe the child itself. When the child has exited by its own and only a
grandchild keeps the pipe open past the timeout, the result keeps the child's real status, ``timed_out`` is False and
stdout holds what arrived until the timeout plus ``DRAIN_WAIT`` (it may be incomplete).

The timeouts of ``process_running``, ``package_version`` and ``nfqws_service_pid`` default to ``config.timeout``
(``process``, ``opkg``), scaled by ``KDN_ENGINE_TIMEOUT_SCALE``; a caller may pass seconds.
"""

import os
import re

from kdn.engine import config, confvalues, lifecycle


PROC_ROOT = "/proc"
NDMC = "/bin/ndmc"
OPT_ETC = "/opt/etc"
# Seconds between TERM and KILL of a child that outlived its timeout, and the wait for the output after it died.
KILL_GRACE = 2
DRAIN_WAIT = 1
SLICE = 1
# Exit statuses of a shell: command not executable, not found; the one of GNU timeout for a run that timed out.
NOT_EXECUTABLE = 126
NOT_FOUND = 127
TIMED_OUT = 124

# The default IFS of a shell: what word splitting of an unquoted $(...) cuts at.
_IFS = re.compile("[ \t\n]+")
_PID = re.compile("[0-9]+")
_QNUM = "--qnum="
_NFQWS_NAME = "nfqws2"


class Completed:
    """Result of ``run``: exit status (124 after a timeout), decoded stdout and whether the timeout ended it."""

    __slots__ = ("returncode", "stdout", "timed_out")

    def __init__(self, returncode, stdout, timed_out=False):
        self.returncode = returncode
        self.stdout = stdout
        self.timed_out = timed_out

    def __repr__(self):
        return f"Completed(returncode={self.returncode!r}, stdout={self.stdout!r}, timed_out={self.timed_out!r})"


def _executable_file(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _which(name, environ):
    """What ``command -v name`` prints for an executable file (an empty ``PATH`` entry is the current directory)."""
    if "/" in name:
        return name if _executable_file(name) else None
    for directory in environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = directory + "/" + name if directory else name
        if _executable_file(candidate):
            return candidate
    return None


def have(name, environ):
    """True when ``name`` is an executable file on the ``PATH`` of the environment (``have`` of the script)."""
    return _which(name, environ) is not None


def _subprocess():
    # CLI imports all read-only modes; only a mode that actually runs a child
    # should pay for subprocess, not print-plan or show-snapshots (rule 9).
    import subprocess
    return subprocess


def _stop(process):
    """TERM the child, KILL it when it is still there after ``KILL_GRACE`` seconds; its own pid only."""
    subprocess = _subprocess()
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=KILL_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        return
    try:
        process.kill()
        process.wait(timeout=KILL_GRACE)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _drain(process, partial):
    """Output of a child that was stopped; whatever arrived if a grandchild still holds the pipe open."""
    subprocess = _subprocess()
    try:
        output, _ = process.communicate(timeout=DRAIN_WAIT)
    except subprocess.TimeoutExpired as expired:
        output = expired.output
    return partial if output is None else output


def _communicate(process, timeout):
    """``process.communicate`` that is never untimed: no timeout means a loop of waits of ``SLICE`` seconds."""
    subprocess = _subprocess()
    if timeout is not None:
        return process.communicate(timeout=timeout)
    while True:
        try:
            return process.communicate(timeout=SLICE)
        except subprocess.TimeoutExpired:
            continue


def run(argv, environ, timeout, *, merge_stderr=False):
    """Run a command and collect its stdout (and stderr with ``merge_stderr``); ``timeout`` None waits for ever."""
    subprocess = _subprocess()
    process = None
    timed_out = False
    try:
        with lifecycle.ChildSpawn():
            try:
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
                    env=dict(environ),
                )
            except (FileNotFoundError, NotADirectoryError):
                return Completed(NOT_FOUND, "")
            except OSError:
                return Completed(NOT_EXECUTABLE, "")
            lifecycle.register_child(process)
        try:
            output, _ = _communicate(process, timeout)
        except subprocess.TimeoutExpired as expired:
            timed_out = process.poll() is None
            _stop(process)
            output = _drain(process, expired.output)
    except BaseException:
        if process is not None:
            _stop(process)
        raise
    finally:
        if process is not None:
            lifecycle.unregister_child(process)
            process.stdout.close()
    returncode = process.returncode
    if timed_out:
        returncode = TIMED_OUT
    elif returncode < 0:
        returncode = 128 - returncode
    return Completed(returncode, (output or b"").decode("utf-8", errors="surrogateescape"), timed_out)


def process_running(name, environ, timeout=None):
    """``process_running`` of the script: ``pidof name``, then ``pgrep -x name``, each only when it is installed."""
    timeout = config.timeout("process", environ) if timeout is None else timeout
    if have("pidof", environ) and run(["pidof", name], environ, timeout).returncode == 0:
        return True
    return have("pgrep", environ) and run(["pgrep", "-x", name], environ, timeout).returncode == 0


def package_version(name, environ, timeout=None):
    """Version of an installed opkg package; empty when it is not installed, opkg is missing or times out."""
    timeout = config.timeout("opkg", environ) if timeout is None else timeout
    done = run(["opkg", "status", name], environ, timeout)
    if done.timed_out:
        return ""
    installed = False
    version = ""
    for line in confvalues.lines(done.stdout):
        if line.startswith("Status:") and " installed" in line[len("Status:") :]:
            installed = True
        if line.startswith("Version:"):
            fields = confvalues.fields(line)
            version = fields[1] if len(fields) > 1 else ""
    return version if installed else ""


def package_present(name, environ, timeout=None):
    """``package_present`` of the script: the package has a non-empty installed version."""
    return package_version(name, environ, timeout) != ""


def _first_line(path):
    """First line of a file as ``$(sed -n '1p' file)`` gives it: no newline, no NUL bytes."""
    try:
        with open(path, "rb") as handle:
            line = handle.readline(4096)
    except OSError:
        return ""
    return line.rstrip(b"\n").replace(b"\0", b"").decode("utf-8", errors="surrogateescape")


def _cmdline(pid):
    """``tr '\\0' ' ' < /proc/<pid>/cmdline`` inside ``$(...)``; empty for a zombie or a process that is gone."""
    try:
        with open(f"{PROC_ROOT}/{pid}/cmdline", "rb") as handle:
            data = handle.read()
    except OSError:
        return ""
    return data.replace(b"\0", b" ").decode("utf-8", errors="surrogateescape").rstrip("\n")


def _pid_is_service(pid, nfqws_value_reader):
    """``nfqws_pid_is_service``: alive, an nfqws2 cmdline, no test instance (dry run, intercept off, other queue)."""
    if not _PID.fullmatch(pid):
        return False
    try:
        os.kill(int(pid), 0)
    except (ValueError, OverflowError, OSError):
        # A string of digits beyond a pid (ValueError past 4300 digits, OverflowError past a C int) fails
        # ``kill -0`` in the shell as well, as do a vanished pid and a pid of another user.
        return False
    if not os.path.isdir(f"{PROC_ROOT}/{pid}"):
        return True
    cmdline = _cmdline(pid)
    if _NFQWS_NAME not in cmdline:
        return False
    padded = f" {cmdline} "
    if " --dry-run " in padded or " --intercept=0 " in padded:
        return False
    queue = ""
    for word in re.split("[ \n]", cmdline):
        if word.startswith(_QNUM):
            queue = word[len(_QNUM) :]
            break
    expected = (nfqws_value_reader("NFQUEUE_NUM") if nfqws_value_reader else "") or "300"
    return queue == "" or queue == expected


def nfqws_service_pid(paths, environ, test_root, nfqws_value_reader, timeout=None):
    """Pid of the running nfqws2 service or None: the pidfile first, ``pidof nfqws2`` outside a fixture root.

    ``nfqws_value_reader(key)`` returns a value of nfqws2.conf (None reads it as empty).
    """
    pidfile = paths.nfqws_pidfile
    if os.path.isfile(pidfile):
        pid = _first_line(pidfile)
        if _pid_is_service(pid, nfqws_value_reader):
            return int(pid)
    # A fixture root must never inherit the host nfqws2 through pidof.
    if test_root or not have("pidof", environ):
        return None
    timeout = config.timeout("process", environ) if timeout is None else timeout
    done = run(["pidof", _NFQWS_NAME], environ, timeout)
    if done.timed_out:
        return None
    for pid in _IFS.split(done.stdout):
        if _pid_is_service(pid, nfqws_value_reader):
            return int(pid)
    return None


def nfqws_running(paths, environ, test_root, nfqws_value_reader, timeout=None):
    """``nfqws_running`` of the script: a service pid exists (a pid of 0 from the pidfile counts)."""
    return nfqws_service_pid(paths, environ, test_root, nfqws_value_reader, timeout) is not None


def find_xray(paths, environ):
    """The xray binary: ``xray`` on ``PATH``, else the default location; None when that one is not executable."""
    # pathlib is a slow import on the router (rule 9): only the Xray branch of --preflight pays for it.
    from pathlib import Path

    candidate = _which("xray", environ) or paths.xray_default_bin
    return Path(candidate) if os.access(candidate, os.X_OK) else None


def is_router(paths, test_root):
    """``is_router`` of the script: always true in a fixture root, else ndmc is executable and /opt/etc exists."""
    if test_root:
        return True
    return os.access(NDMC, os.X_OK) and os.path.isdir(OPT_ETC)

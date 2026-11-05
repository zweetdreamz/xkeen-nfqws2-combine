"""Children, cleanups and signals of the engine process.

legacy sh traps HUP, INT and TERM (``exit 130``), removes its temporary directory on exit, and its children share
its process group, so the panel's TERM to the group reaches them. The Python path does the same: the children
that ``system.run`` starts are registered here, the temporary resources are registered as cleanups, and the
handlers kill the children, let the ``finally`` blocks and ``run_cleanups`` run, and exit with 130.

A signal that the parent started the engine with ignored (nohup, a background job) stays ignored, as it does
in sh, and the shell engine that the run may be handed to inherits it.

The C module ``_signal`` is used instead of ``signal``: it has the same constants and ``signal()``, and it is
lighter, because ``signal`` is a wrapper that also imports enum, collections and functools. Rule 9 allows enum
to arrive through ``re`` or ``subprocess`` (R11), but a module that needs none of them does not pay for it.
"""

import time

import _signal


_children = []
_cleanups = []
_spawn_depth = 0
_pending_signal = None


class ChildSpawn:
    """Defer Python's exit handler until Popen returns and ownership is recorded.

    Unlike pthread_sigmask this never leaves the child with blocked signals.
    Engine command spawning is main-thread only; no OS handlers are replaced.
    """

    def __enter__(self):
        global _spawn_depth
        _spawn_depth += 1
        return self

    def __exit__(self, *_exc):
        global _spawn_depth, _pending_signal
        _spawn_depth -= 1
        if not _spawn_depth and _pending_signal is not None:
            signum = _pending_signal
            _pending_signal = None
            _on_signal(signum, None)


def register_child(process):
    """Remember a Popen the signal handler must kill."""
    _children.append(process)


def unregister_child(process):
    if process in _children:
        _children.remove(process)


def _send(process, signum):
    try:
        process.send_signal(signum)
    except OSError:
        pass


def terminate_children(grace=2):
    """TERM every registered child by its pid, wait up to ``grace`` seconds, then KILL the ones left."""
    children = list(_children)
    for process in children:
        _send(process, _signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and any(process.poll() is None for process in children):
        time.sleep(0.02)
    for process in children:
        if process.poll() is None:
            _send(process, _signal.SIGKILL)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and any(process.poll() is None for process in children):
        time.sleep(0.02)


def add_cleanup(func):
    """Register a callable that undoes a resource of the run (a temporary directory)."""
    _cleanups.append(func)


def run_cleanups():
    """Run the registered cleanups once each, last registered first; an error in one does not stop the rest."""
    while _cleanups:
        cleanup = _cleanups.pop()
        try:
            cleanup()
        except Exception:
            # A failed cleanup must not hide the others or change the exit code.
            pass


def _on_signal(signum, frame):
    global _pending_signal
    if _spawn_depth:
        _pending_signal = signum
        return
    terminate_children()
    raise SystemExit(130)


def install_signal_handlers():
    """TERM, HUP and INT kill the children and exit with 130, unless the signal was inherited as ignored.

    SIGPIPE kills the process, as it does a shell (Python starts with it ignored, and an ignored signal
    would reach the shell engine that the run is handed to).
    """
    for signum in (_signal.SIGTERM, _signal.SIGHUP, _signal.SIGINT):
        if _signal.getsignal(signum) != _signal.SIG_IGN:
            _signal.signal(signum, _on_signal)
    _signal.signal(_signal.SIGPIPE, _signal.SIG_DFL)

"""Linux-only isolated probe exec: the probe cannot survive its owning worker.

Run in a fresh single-threaded interpreter, never use preexec_fn in a threaded
panel. No listener/config edits here: exec only the manager-supplied Xray config.
"""
import ctypes
import os
import signal
import sys


def main(argv):
    if len(argv) != 4 or not argv[1].isdigit() or int(argv[1]) <= 1:
        return 2
    expected_parent = int(argv[1])
    if os.getppid() != expected_parent:
        return 130
    # PR_SET_PDEATHSIG survives exec. Check again to close the setup race.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        return 125
    if os.getppid() != expected_parent:
        return 130
    os.execv(argv[2], [argv[2], 'run', '-c', argv[3]])
    return 127  # pragma: no cover - execv never returns on success


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))

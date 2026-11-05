"""Bounded, cancellable validation and separate synchronous service-init capture."""
import os
import errno
import stat
import time

from kdn.engine import lifecycle


class ProcessResult:
    __slots__ = ('returncode', 'output', 'timed_out', 'output_limited', 'capture_mode')

    def __init__(self, returncode, output, timed_out=False, output_limited=False, capture_mode='captured'):
        self.returncode, self.output = returncode, output
        self.timed_out, self.output_limited = timed_out, output_limited
        self.capture_mode = capture_mode


def run(argv, environ, *, timeout=20, output_limit=65536, cwd=None):
    """No shell, no daemon/session, fixed output ceiling; kill/reap own child only.

    Linux-only selector implementation (same platform as nfqws2). Lifecycle owns
    cancellation signals so the engine's normal TERM cleanup also applies.
    """
    import selectors
    import subprocess

    if not 0 < timeout <= 120 or not 1024 <= output_limit <= 1048576:
        raise ValueError('invalid validation process budget')
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=dict(environ), cwd=cwd)
    except OSError:
        return ProcessResult(127, '')
    lifecycle.register_child(process)
    capture, timed_out, limited = bytearray(), False, False
    deadline = time.monotonic() + timeout
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if selector.select(min(0.1, remaining)):
                    data = os.read(process.stdout.fileno(), min(4096, output_limit + 1 - len(capture)))
                    if not data:
                        break
                    capture.extend(data)
                    if len(capture) > output_limit:
                        limited = True
                        del capture[output_limit:]
                        break
                elif process.poll() is not None:
                    # A child/grandchild retaining the pipe cannot keep us here
                    # past the deadline; drain already buffered bytes normally.
                    continue
    finally:
        # EOF is not waitpid: a successful program can close stdout just before
        # it exits. Do not race it with TERM and report a false -15. The same
        # original deadline still bounds a child that closes its pipe then hangs.
        try:
            if process.poll() is None and not (timed_out or limited):
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            process.stdout.close()
            lifecycle.unregister_child(process)
    return ProcessResult(124 if timed_out else process.returncode,
                         capture.decode('utf-8', 'replace'), timed_out, limited)


def _memfd():
    """Linux anonymous regular file; standalone Python may omit the os wrapper."""
    create = getattr(os, 'memfd_create', None)
    # Linux UAPI MFD_CLOEXEC=1, MFD_ALLOW_SEALING=2. These can also be
    # absent from Python builds whose libc headers predate the wrappers.
    if create is not None:
        return create('kdn-service-control', 3)
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    create = libc.memfd_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    fd = create(b'kdn-service-control', 3)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'memfd_create failed')
    return fd


def _null_capture():
    """Verified Linux discard device: zero storage, no pipe or inherited drainer."""
    fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(1, 3):
        os.close(fd)
        raise OSError('unsafe discard device')
    return fd


def _service_capture(output_limit):
    """Preallocate and seal capacity, so inherited daemon fd cannot grow a log."""
    import fcntl
    fd = None
    try:
        fd = _memfd()
        os.ftruncate(fd, output_limit + 1)
        # Linux UAPI F_ADD_SEALS=1024+9; SEAL_SEAL|SHRINK|GROW=1|2|4.
        # F_SEAL_WRITE is deliberately absent: descendants can still write.
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 7)
        return fd
    except (OSError, AttributeError, ImportError) as error:
        if fd is not None:
            os.close(fd)
        # Target kernels may expose libc/Python wrappers but return ENOSYS.
        # Do not hide descriptor exhaustion, permission errors or generic faults.
        if isinstance(error, AttributeError) or (isinstance(error, OSError) and error.errno in
                                                {errno.ENOSYS, errno.EOPNOTSUPP}):
            try:
                return _null_capture()
            except OSError as fallback_error:
                raise RuntimeError('No safe service output sink available') from fallback_error
        raise RuntimeError('XKeen service control requires Linux memfd_create and file seals') from error


def service_capture_ready():
    """Probe support before preflight permits snapshots or configuration writes."""
    os.close(_service_capture(1024))


def run_service(argv, environ, *, timeout=120, output_limit=1048576, cwd=None):
    """Wait for owned init; sealed capture or explicit zero-storage discard.

    No PIPE EOF dependency, background drainer or unbounded retained tempfile.
    Sealed mode fails oversized writes with EPERM (never SIGPIPE); unsupported
    kernels discard init diagnostics explicitly. Neither mode is a daemon log.
    """
    import subprocess

    if not 0 < timeout <= 120 or not 1024 <= output_limit <= 1048576:
        raise ValueError('invalid service process budget')
    fd = _service_capture(output_limit)
    discarded = stat.S_ISCHR(os.fstat(fd).st_mode)
    process = None
    timed_out = limited = False
    try:
        try:
            with lifecycle.ChildSpawn():
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fd,
                                           stderr=subprocess.STDOUT, env=dict(environ), cwd=cwd)
                lifecycle.register_child(process)
        except OSError:
            return ProcessResult(127, '')
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if not discarded and os.lseek(fd, 0, os.SEEK_CUR) > output_limit:
                limited = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1)
                # SEEK_CUR only observes the shared offset. pread must not rewind
                # the descriptor inherited by a still-running daemon.
                count = 0 if discarded else os.lseek(fd, 0, os.SEEK_CUR)
                limited = limited or count > output_limit
                capture = b'' if discarded else os.pread(fd, min(count, output_limit), 0)
        finally:
            if process is not None:
                lifecycle.unregister_child(process)
            os.close(fd)
    return ProcessResult(124 if timed_out else process.returncode,
                         capture.decode('utf-8', 'replace'), timed_out, limited,
                         capture_mode='discarded' if discarded else 'sealed')

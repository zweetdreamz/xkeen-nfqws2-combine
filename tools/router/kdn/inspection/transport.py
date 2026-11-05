"""Bounded in-memory subprocess pipes, including native config conversion.

No config, raw RPC response or credentials are written to diagnostic files.
"""
import os
import selectors
import subprocess
import time

from kdn.common import proc


_spawn_depth = 0
_pending_stop = None
_stopping = False


def request_stop(signum, _frame=None):
    """Worker handler: defer exit until Popen has returned an owned child.

    No pthread mask is inherited by children. Repeated TERM cannot interrupt
    the cleanup already in progress. Installed only in the checker process.
    """
    global _pending_stop, _stopping
    if _stopping:
        return
    _stopping = True
    if _spawn_depth:
        _pending_stop = signum
        return
    raise SystemExit(128 + signum)


def _raise_pending_stop():
    global _pending_stop
    if _pending_stop is not None:
        signum, _pending_stop = _pending_stop, None
        raise SystemExit(128 + signum)


class Failure(RuntimeError):
    def __init__(self, message, *, code=None, partial=b''):
        super().__init__(message)
        self.code, self.partial = code, partial


def environment():
    return {key: value for key, value in proc.command_env().items()
            if not key.lower().endswith('_proxy') and key.lower() not in ('all_proxy', 'no_proxy')}


def run(argv, *, data=b'', timeout=5, limit=1024 * 1024, termination_grace=.2):
    global _spawn_depth
    if (len(data) > 4 * 1024 * 1024 or not 0 < timeout <= 180 or not 0 < limit <= 8 * 1024 * 1024
            or not 0 < termination_grace <= 5):
        raise ValueError('inspection command budget')
    output = bytearray()
    error_size = 0
    _spawn_depth += 1
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=environment(), start_new_session=True)
    except OSError as error:
        _spawn_depth -= 1
        _raise_pending_stop()
        raise Failure('inspection command unavailable') from error
    except BaseException:
        _spawn_depth -= 1
        _raise_pending_stop()
        raise
    try:
        _spawn_depth -= 1
        _raise_pending_stop()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'out')
            selector.register(child.stderr, selectors.EVENT_READ, 'err')
            if data:
                selector.register(child.stdin, selectors.EVENT_WRITE, 'in')
            else:
                child.stdin.close()
            offset, deadline = 0, time.monotonic() + timeout
            for stream in (child.stdout, child.stderr, child.stdin):
                if not stream.closed:
                    os.set_blocking(stream.fileno(), False)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Failure('inspection timeout', code=124)
                for key, _mask in selector.select(min(.2, left)):
                    if key.data == 'in':
                        try:
                            offset += os.write(key.fd, data[offset:offset + 8192])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset == len(data):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.data == 'out':
                        output.extend(chunk)
                    else:
                        error_size += len(chunk)
                    if len(output) > limit or error_size > 65536:
                        raise Failure('inspection output limit')
            try:
                code = child.wait(timeout=max(.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise Failure('inspection timeout', code=124) from error
            if code:
                raise Failure('inspection command failed', code=code)
            return bytes(output)
    except Failure as error:
        error.partial = bytes(output[:limit])
        raise
    finally:
        if child.poll() is None:
            proc.stop_process_group(child, termination_grace)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()

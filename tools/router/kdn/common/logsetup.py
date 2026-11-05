"""The panel log: one rotating private file, and print and tracebacks routed into it.

configure_logging points the logger "kdn.panel" at the file. The files are 600 and the size is counted in bytes, also
the bytes that other holders of the file append. A rotation renames the file and opens the path again, so a descriptor
opened on the log before (the old init starts the panel with `>> xkeen-web.log 2>&1`) follows the renamed file and
never writes into the new one. redirect_std_streams makes the panel itself stop being such a holder: print, tracebacks
of threads and warnings go to the logger instead of fd 1 and 2. What a foreign holder writes is not captured.
"""

import contextlib
import io
import logging
import logging.handlers
import os
from pathlib import Path
import stat
import sys
import threading


LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
_LOGGER_NAME = "kdn.panel"
_FILE_MODE = 0o600
# A partial line (no newline yet) is written out as a record when it reaches this size.
_MAX_PENDING = 64 * 1024
# Set while a writer hands a line to the logger, so that a logging failure that reports itself on the replaced
# sys.stderr reaches the real stream instead of coming back into the logger.
_LOGGING = threading.local()


def panel_logger():
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        _prepare(logger)
        logger.addHandler(logging.NullHandler())
    return logger


def configure_logging(path, *, max_bytes, backups, stream=None, console=False):
    """Write the panel log to a rotating file; fall back to a stream when the file cannot be opened.

    A zero max_bytes or backups means the file is never rotated.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    _prepare(logger)
    path = Path(path)
    problem = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        target = _PrivateRotatingHandler(path, max_bytes, backups)
    except OSError as exc:
        problem = exc
        target = _GuardedStreamHandler(stream if stream is not None else _real_stream("stderr"))
    new_handlers = [target]
    console_stream = _real_stream("stderr")
    if console and getattr(target, "stream", None) is not console_stream:
        new_handlers.append(_GuardedStreamHandler(console_stream))
    formatter = logging.Formatter(LOG_FORMAT)
    old_handlers = list(logger.handlers)
    for handler in new_handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    for handler in old_handlers:
        logger.removeHandler(handler)
        handler.close()
    if problem is not None:
        logger.warning("log file %s is unavailable, logging to the stream: %s", path, problem)
    return logger


def redirect_std_streams(logger):
    """Replace sys.stdout (INFO) and sys.stderr (ERROR) with writers that log every line."""
    for name, level in (("stdout", logging.INFO), ("stderr", logging.ERROR)):
        stream = getattr(sys, name)
        if hasattr(stream, "kdn_original"):
            stream.logger = logger
        else:
            # What was buffered before must not reach the old file after the switch.
            with contextlib.suppress(OSError, ValueError, AttributeError):
                stream.flush()
            setattr(sys, name, _LineWriter(logger, level, stream))


def restore_std_streams():
    """Put back the streams that redirect_std_streams replaced; a stream somebody else replaced stays."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if hasattr(stream, "kdn_original"):
            stream.flush()
            setattr(sys, name, stream.kdn_original)


def _prepare(logger):
    logger.setLevel(logging.INFO)
    logger.propagate = False


def _real_stream(name):
    stream = getattr(sys, name)
    return stream.kdn_original if hasattr(stream, "kdn_original") else stream


def _open_private(path, flags):
    descriptor = os.open(path, flags, _FILE_MODE)
    # Only a regular file is narrowed (never /dev/null); one we cannot chmod is still better logged to than not.
    with contextlib.suppress(OSError):
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.fchmod(descriptor, _FILE_MODE)
    return descriptor


class _ReportsToRealStream:
    """Handler mixin: a failure of the handler is reported on the real stderr, never back into the logger."""

    def handleError(self, record):
        if not logging.raiseExceptions:
            return
        previous = getattr(_LOGGING, "active", False)
        _LOGGING.active = True
        try:
            error = sys.exc_info()[1]
            stream = _real_stream("stderr")
            if stream is not None:
                detail = f"{type(error).__name__}: {error}" if error is not None else "unknown error"
                try:
                    stream.write(f"--- Logging error ---\n{detail[:500]}\n")
                except Exception:
                    return
        finally:
            _LOGGING.active = previous


class _GuardedStreamHandler(_ReportsToRealStream, logging.StreamHandler):
    pass


class _PrivateRotatingHandler(_ReportsToRealStream, logging.handlers.RotatingFileHandler):
    """RotatingFileHandler with 600 files, a limit counted in bytes and a lossless encoding of broken text."""

    def __init__(self, path, max_bytes, backups):
        super().__init__(path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8", errors="backslashreplace")

    def _open(self):
        return self._builtin_open(
            self.baseFilename, self.mode, encoding=self.encoding, errors=self.errors, opener=_open_private
        )

    def shouldRollover(self, record):
        # The standard check adds the length in characters to the size in bytes and rotates an empty file.
        if self.maxBytes <= 0 or self.backupCount <= 0 or (os.path.exists(self.baseFilename) and not os.path.isfile(self.baseFilename)):
            return False
        if self.stream is None:
            self.stream = self._open()
        self.stream.seek(0, os.SEEK_END)
        size = self.stream.tell()
        pending = len(self.format(record).encode(self.encoding, self.errors)) + 1
        return size > 0 and size + pending >= self.maxBytes


class _LineWriter(io.TextIOBase):
    """A text stream that logs every complete line written to it; the partial line of each thread waits for its end."""

    encoding = "utf-8"
    errors = "backslashreplace"

    def __init__(self, logger, level, original):
        super().__init__()
        self.logger = logger
        self.level = level
        self.kdn_original = original
        self._pending = threading.local()

    def writable(self):
        return True

    def write(self, text):
        if getattr(_LOGGING, "active", False):
            return self._write_through(text)
        *lines, rest = (getattr(self._pending, "text", "") + text).split("\n")
        if len(rest) >= _MAX_PENDING:
            lines.append(rest)
            rest = ""
        self._pending.text = rest
        self._log(lines)
        return len(text)

    def flush(self):
        if getattr(_LOGGING, "active", False):
            return
        rest = getattr(self._pending, "text", "")
        if rest:
            self._pending.text = ""
            self._log([rest])

    def _log(self, lines):
        _LOGGING.active = True
        try:
            for line in lines:
                line = line.rstrip("\r")
                if line.strip():
                    self.logger.log(self.level, line)
        finally:
            _LOGGING.active = False

    def _write_through(self, text):
        if self.kdn_original is None:
            return len(text)
        return self.kdn_original.write(text)

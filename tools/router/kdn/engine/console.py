"""Output of the modes: stdout and stderr in one object that keeps the order of the lines in a merged stream."""

import sys


class Console:
    """Writes to two text streams; a write to one stream first flushes the other, so ``2>&1`` keeps the order."""

    __slots__ = ("_stdout", "_stderr")

    def __init__(self, stdout, stderr):
        self._stdout = stdout
        self._stderr = stderr

    @classmethod
    def process(cls):
        """The streams of this process, as UTF-8 that writes back the bytes sh would print (surrogateescape)."""
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                reconfigure(encoding="utf-8", errors="surrogateescape")
        return cls(sys.stdout, sys.stderr)

    def out(self, text="", end="\n"):
        self._stderr.flush()
        self._stdout.write(text + end)

    def err(self, text="", end="\n"):
        self._stdout.flush()
        self._stderr.write(text + end)

    def flush(self):
        self._stdout.flush()
        self._stderr.flush()

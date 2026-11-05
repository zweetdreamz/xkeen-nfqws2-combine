"""Data of the background jobs: a family of jobs (where its files lie, how its process is told) and a job to start."""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path


# Both files lie in the directory of the family and are removed by every clear().
CANCEL_REQUEST_NAME = "cancel.request"
JOB_ID_NAME = "job.id"


@dataclass(frozen=True)
class JobFamily:
    """One kind of job: the files it keeps and the argv by which its process is recognised.

    ``directory``, ``state``, ``pid``, ``log``, ``files``, ``marker`` and ``extra`` are called without arguments
    on every use, so a path or a marker that the configuration changes later is followed. ``files`` is everything
    clear() removes; ``extra`` yields more paths (payload files), of which only regular files are removed.
    Each ``marker`` entry (bytes) must be a whole argument of the live process. ``place`` names the directory in
    the "unusual object" error; ``tool_owned`` means an outside tool, not the panel, writes ``state``.
    """

    name: str
    directory: Callable[[], Path]
    state: Callable[[], Path]
    pid: Callable[[], Path]
    log: Callable[[], Path]
    files: Callable[[], Iterable[Path]]
    marker: Callable[[], tuple[bytes, ...]]
    place: str = "каталоге задания"
    extra: Callable[[], Iterable[Path]] | None = None
    tool_owned: bool = False


@dataclass(frozen=True)
class JobSpec:
    """One job to start: ``argv`` is the full command line, ``initial`` the state the panel writes before it runs."""

    family: str
    kind: str
    job_id: str
    argv: Sequence[str]
    cwd: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    initial: dict = field(default_factory=dict)

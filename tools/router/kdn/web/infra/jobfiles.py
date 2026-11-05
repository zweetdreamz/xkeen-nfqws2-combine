"""The panel's background jobs: the families (route switch, tuner, diagnostics), their stores and the coordinator.

The families describe where each kind of job keeps its files and how its process is told; every path and marker
is read from the configuration on each use. The older helpers (route_active, clear_job_files, ...) stay and
delegate to the stores; the coordinator's probes look them up on every call, so a test that patches one is seen.
"""

import os
import re
import threading

from kdn.jobs import coordinator
from kdn.jobs import jobspec
from kdn.jobs import jobstore
from kdn.web.infra import config as cfg


# Held while any background job (route, tuner, diagnostics) is being started,
# from its "nothing else is running" checks until its PID file is written.
JOB_START_LOCK = threading.Lock()

PAYLOAD_NAME = "payload.json"
_TUNER_FILES = (
    "state.json", "events.log", "result-report.json", "runner.sh", "verdict.txt", "panel-launch.pid", "process.log",
)
_DIAGNOSTIC_PAYLOAD = re.compile(r"payload-\d+\.bin")


def route_payload_path():
    """The file that hands the worker its payload (the profile of an apply, the credentials of a node)."""
    return cfg.ROUTE_JOB_DIR / PAYLOAD_NAME


def _tuner_files():
    return [cfg.TUNER_JOB_DIR / name for name in _TUNER_FILES]


def _diagnostic_payloads():
    return [path for path in cfg.DIAGNOSTIC_JOB_DIR.glob("payload-*.bin") if _DIAGNOSTIC_PAYLOAD.fullmatch(path.name)]


ROUTE = jobspec.JobFamily(
    name="route",
    directory=lambda: cfg.ROUTE_JOB_DIR,
    state=lambda: cfg.ROUTE_STATE,
    pid=lambda: cfg.ROUTE_PID,
    log=lambda: cfg.ROUTE_LOG,
    files=lambda: (cfg.ROUTE_STATE, cfg.ROUTE_PID, cfg.ROUTE_LOG, cfg.ROUTE_APPLY_LOG, route_payload_path()),
    marker=lambda: (b"--route-job", os.fsencode(str(cfg.ENTRY))),
)
TUNER = jobspec.JobFamily(
    name="tuner",
    directory=lambda: cfg.TUNER_JOB_DIR,
    state=lambda: cfg.TUNER_STATE,
    pid=lambda: cfg.TUNER_PID,
    log=lambda: cfg.TUNER_JOB_DIR / "process.log",
    files=_tuner_files,
    marker=lambda: (os.fsencode(str(cfg.AUTOTUNER)),),
    tool_owned=True,
)
DIAGNOSTIC = jobspec.JobFamily(
    name="diagnostic",
    directory=lambda: cfg.DIAGNOSTIC_JOB_DIR,
    state=lambda: cfg.DIAGNOSTIC_STATE,
    pid=lambda: cfg.DIAGNOSTIC_PID,
    log=lambda: cfg.DIAGNOSTIC_LOG,
    files=lambda: (cfg.DIAGNOSTIC_STATE, cfg.DIAGNOSTIC_PID, cfg.DIAGNOSTIC_LOG),
    marker=lambda: (os.fsencode(str(cfg.DIAGNOSTICS)),),
    place="каталоге диагностики",
    extra=_diagnostic_payloads,
    tool_owned=True,
)

ROUTE_STORE = jobstore.JobStore(ROUTE)
TUNER_STORE = jobstore.JobStore(TUNER)
DIAGNOSTIC_STORE = jobstore.JobStore(DIAGNOSTIC)

# The probes call the helpers by name on every call (not the functions as they were at import).
COORDINATOR = coordinator.Coordinator(
    start_lock=JOB_START_LOCK,
    probes={
        "route": lambda: route_active(),
        "tuner": lambda: tuner_active(),
        "diagnostic": lambda: diagnostic_active(),
    },
    project_lock=lambda: cfg.PROJECT_LOCK_DIR,
)


def clear_job_files(directory, paths, place="каталоге задания"):
    """Create the private job directory and remove the previous job's files.

    Only regular files and symlinks are removed; anything else is refused.
    """
    jobstore.clear_files(directory, paths, place)


def route_process_alive(pid):
    return ROUTE_STORE.alive(pid)


def route_pid():
    return ROUTE_STORE.pid()


def route_active():
    pid = route_pid()
    return bool(pid and route_process_alive(pid))


def tuner_process_alive(pid):
    return TUNER_STORE.alive(pid)


def tuner_pid():
    return TUNER_STORE.pid()


def tuner_active():
    pid = tuner_pid()
    return bool(pid and tuner_process_alive(pid))


def diagnostic_process_alive(pid):
    return DIAGNOSTIC_STORE.alive(pid)


def diagnostic_pid():
    return DIAGNOSTIC_STORE.pid()


def diagnostic_active():
    pid = diagnostic_pid()
    return bool(pid and diagnostic_process_alive(pid))

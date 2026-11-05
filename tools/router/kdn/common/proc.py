"""Child processes of the panel and process-table checks of its job workers."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile


ROUTER_PATH = "/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
PROC_ROOT = Path("/proc")


def command_env():
    env = os.environ.copy()
    env["PATH"] = ROUTER_PATH
    return env


def stop_process_group(process, grace):
    """TERM the process group, wait `grace` seconds, then KILL it and reap the leader."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, AttributeError):
        process.terminate()
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            process.kill()
        process.wait()


def run_command(command, timeout, *, env=None):
    try:
        with tempfile.TemporaryFile(mode="w+b") as capture:
            process = subprocess.Popen(
                command,
                stdout=capture,
                stderr=subprocess.STDOUT,
                env={**command_env(), **(env or {})},
                start_new_session=True,
            )
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                stop_process_group(process, min(120, max(10, timeout // 2)))
            capture.flush()
            capture.seek(0)
            output = capture.read().decode("utf-8", errors="replace").strip()
        if timed_out:
            return {
                "ok": False,
                "code": 124,
                "output": f"Команда превысила таймаут; отправлен TERM для штатного отката.\n{output}".strip(),
            }
        return {
            "ok": process.returncode == 0,
            "code": process.returncode,
            "output": output,
        }
    except OSError as exc:
        return {"ok": False, "code": 127, "output": str(exc)}


def process_alive(pid, proc_root=None):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        root = PROC_ROOT if proc_root is None else proc_root
        state = (root / str(pid) / "stat").read_text(encoding="ascii").split()[2]
        return state != "Z"
    except (OSError, UnicodeError, IndexError):
        return True


def read_job_pid(path):
    """PID recorded by a panel job launcher, or None if missing/invalid."""
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    if not raw.isdigit() or int(raw) <= 1:
        return None
    return int(raw)


def job_command(pid, proc_root=None):
    """Argument list of a live (non-zombie) process, or None."""
    if not process_alive(pid, proc_root):
        return None
    try:
        root = PROC_ROOT if proc_root is None else proc_root
        return (root / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return None

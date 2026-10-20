#!/usr/bin/env python3
"""Run the existing Flowseal strategy translator locally on the router.

The job never edits persistent network configuration and never invokes XKeen.
It renders the same temporary nfqws2 runner used by the Windows tuner. The
runner's EXIT trap restores the original nfqws2 service on success, failure,
cancel, or panel disconnect.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[2]
WINDOWS_DIR = PROJECT_DIR / "tools" / "windows"
sys.path.insert(0, str(WINDOWS_DIR))

import zapret_tuner as tuner  # noqa: E402


TEST_ROOT = os.environ.get("KD_TUNER_TEST_ROOT", "")
LOCK_LOGICAL = "/opt/tmp/keenetic-discord-nfqws2.lock"
JOB_LOGICAL = "/opt/tmp/xkeen-zapret-tuner"
NFQWS_CONF_LOGICAL = "/opt/etc/nfqws2/nfqws2.conf"
RUNNER_TEMPLATE = WINDOWS_DIR / "router-candidate-runner.sh"


class JobCancelled(Exception):
    pass


def root_path(logical: str) -> Path:
    return Path(f"{TEST_ROOT}{logical}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def read_pid(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    return int(raw) if raw.isdigit() and int(raw) > 1 else None


def acquire_project_lock() -> Path:
    lock = root_path(LOCK_LOGICAL)
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        existing_pid = read_pid(lock / "pid")
        if existing_pid and process_alive(existing_pid):
            raise RuntimeError(
                f"another project operation is active (PID {existing_pid})"
            ) from None
        try:
            (lock / "pid").unlink()
        except FileNotFoundError:
            pass
        try:
            lock.rmdir()
        except OSError as error:
            raise RuntimeError(f"stale project lock is not empty: {lock}") from error
        lock.mkdir(mode=0o700)
    (lock / "pid").write_text(f"{os.getpid()}\n", encoding="ascii")
    os.chmod(lock / "pid", 0o600)
    return lock


def release_project_lock(lock: Path | None) -> None:
    if lock is None:
        return
    try:
        if read_pid(lock / "pid") == os.getpid():
            (lock / "pid").unlink(missing_ok=True)
            lock.rmdir()
    except OSError:
        pass


ROUTE_VALUES = {"direct", "zapret", "vless"}


def parse_active_routes(text: str) -> dict[str, str] | None:
    """Read the "# Active routes:" line written by apply-discord-nfqws2.sh.

    Returns {"discord-tcp", "discord-voice", "youtube"} -> route, or None when
    the line is missing or malformed. The legacy line "Discord=X, YouTube=Y."
    written before the TCP/Voice split applies X to both Discord routes.
    """
    match = re.search(r"^# Active routes: (.+)\.$", text, re.MULTILINE)
    if not match:
        return None
    values = {}
    for pair in match.group(1).split(", "):
        key, separator, value = pair.partition("=")
        if not separator or value not in ROUTE_VALUES:
            return None
        values[key] = value
    if set(values) == {"DiscordTCP", "DiscordVoice", "YouTube"}:
        return {
            "discord-tcp": values["DiscordTCP"],
            "discord-voice": values["DiscordVoice"],
            "youtube": values["YouTube"],
        }
    if set(values) == {"Discord", "YouTube"}:
        return {
            "discord-tcp": values["Discord"],
            "discord-voice": values["Discord"],
            "youtube": values["YouTube"],
        }
    return None


def recorded_route(service: str) -> str:
    config = root_path(NFQWS_CONF_LOGICAL)
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise RuntimeError(f"cannot read current nfqws2 config: {config}") from error
    routes = parse_active_routes(text)
    if routes is None:
        raise RuntimeError("current managed service routes cannot be determined")
    return routes[service]


def core_pids() -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for name in ("xray", "mihomo"):
        try:
            completed = subprocess.run(
                ["pidof", name],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        pids = [
            int(value)
            for value in completed.stdout.split()
            if value.isdigit()
        ]
        if pids:
            result[name] = sorted(pids)
    return result


class StateWriter:
    def __init__(self, job_dir: Path, initial: dict[str, Any]) -> None:
        self.job_dir = job_dir
        self.state_path = job_dir / "state.json"
        self.log_path = job_dir / "events.log"
        self.payload = initial
        self.write()

    def write(self, **changes: Any) -> None:
        self.payload.update(changes)
        self.payload["updated_utc"] = utc_now()
        atomic_json(self.state_path, self.payload)

    def log(self, line: str) -> None:
        cleaned = line.replace("\x00", "").rstrip("\r\n")
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(cleaned[:4000] + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--service",
        required=True,
        choices=("youtube", "discord-tcp", "discord-voice"),
    )
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--mix-level", choices=("off", "safe", "extended"), default="safe")
    parser.add_argument("--max-candidates", type=int, default=32)
    parser.add_argument("--search-seed", type=tuner.parse_search_seed)
    parser.add_argument("--http-timeout", type=int, default=6)
    parser.add_argument("--voice-duration", type=int, default=25)
    parser.add_argument("--client-ip")
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--source-file")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not re.fullmatch(r"[0-9a-f]{16}", args.job_id):
        raise ValueError("invalid job id")
    if not 1 <= args.max_candidates <= 64:
        raise ValueError("max-candidates must be between 1 and 64")
    if not 4 <= args.http_timeout <= 20:
        raise ValueError("http-timeout must be between 4 and 20")
    if not 10 <= args.voice_duration <= 60:
        raise ValueError("voice-duration must be between 10 and 60")
    if args.service == "discord-voice":
        if not args.client_ip:
            raise ValueError("client-ip is required for Discord Voice")
        address = ipaddress.ip_address(args.client_ip)
        if address.version != 4 or not address.is_private:
            raise ValueError("client-ip must be a private LAN IPv4")
    if args.source_file is not None and (
        len(args.source_file) > 160 or not tuner.SOURCE_NAME_RE.fullmatch(args.source_file)
    ):
        raise ValueError("source-file must name one general*.bat file")
    if args.source_dir and not TEST_ROOT:
        raise ValueError("source-dir is allowed only in an isolated test root")


def candidate_summary(
    candidates: list[tuner.Candidate],
) -> list[dict[str, Any]]:
    return [
        {
            "number": number,
            "candidate_id": candidate.candidate_id,
            "source_name": candidate.source_name,
            "family": candidate.family,
            "rank": candidate.rank,
        }
        for number, candidate in enumerate(candidates, 1)
    ]


def make_report(
    args: argparse.Namespace,
    commit: str,
    candidates: list[tuner.Candidate],
    found: tuner.Candidate | None,
    output: list[str],
) -> dict[str, Any]:
    return {
        "report_format": 1,
        "created_utc": utc_now(),
        "repository": tuner.DEFAULT_REPOSITORY,
        "ref": tuner.DEFAULT_REF,
        "commit": commit,
        "service": args.service,
        "router": "local-panel",
        "search_seed": args.search_seed,
        "source_file": args.source_file,
        "candidate_count": len(candidates),
        "found": {
            "candidate_id": found.candidate_id,
            "service": found.service,
            "source_name": found.source_name,
            "source_sha": found.source_sha,
            "source_url": found.source_url,
            "family": found.family,
            "args": list(found.args),
            "notes": list(found.notes),
            "rank": found.rank,
        } if found else None,
        "remote_output": output[-500:],
        "verification": tuner.verification_report(args.service, output),
    }


def parse_event(
    writer: StateWriter,
    line: str,
    candidates: list[tuner.Candidate],
) -> tuner.Candidate | None:
    if not line.startswith("EVENT|"):
        return None
    parts = line.split("|")
    event = parts[1] if len(parts) > 1 else ""
    if event == "CANDIDATE" and len(parts) >= 4:
        number = int(parts[2])
        writer.write(
            status="running",
            current_candidate=number,
            current_candidate_id=parts[3],
            needs_voice_verdict=False,
        )
    elif event == "PROBE_DETAIL":
        detail = tuner.parse_probe_event(line)
        if detail:
            writer.write(last_probe_detail=detail)
    elif event == "SUITE_RESULT" and len(parts) >= 8:
        result = {"candidate": int(parts[2]), "phase": parts[3], "round": int(parts[4]),
                  "verdict": parts[5], "successes": int(parts[6]), "total": int(parts[7])}
        writer.write(**({"baseline_result": result} if parts[3] == "baseline" else {"last_suite_result": result}))
    elif event == "VOICE_OBSERVATION" and len(parts) >= 5:
        writer.write(voice_observation={"outgoing_packets": int(parts[2]), "incoming_packets": int(parts[3]), "wan_match": parts[4] == "1"})
    elif event == "PROBE" and len(parts) >= 5:
        writer.write(
            last_probe={
                "candidate": int(parts[2]),
                "code": parts[3],
                "url": "|".join(parts[4:])[:500],
            }
        )
    elif event == "HTTP_RESULT" and len(parts) >= 5:
        writer.write(
            last_http_result={
                "candidate": int(parts[2]),
                "successes": int(parts[3]),
                "total": int(parts[4]),
            }
        )
    elif event == "VOICE_READY" and len(parts) >= 4:
        writer.write(
            status="voice_window",
            current_candidate=int(parts[2]),
            voice_duration=int(parts[3]),
            needs_voice_verdict=False,
        )
    elif event == "VOICE_VERDICT" and len(parts) >= 3:
        writer.write(
            status="awaiting_voice",
            current_candidate=int(parts[2]),
            needs_voice_verdict=True,
        )
    elif event == "START_FAILED":
        writer.write(last_error="|".join(parts[2:])[:500])
    elif event == "RESTORE_ERROR":
        writer.write(restore_error="|".join(parts[2:])[:500])
    elif event == "RESTORED":
        writer.write(nfqws_restored=parts[2] if len(parts) >= 3 else "unknown")
    elif event == "FOUND" and len(parts) >= 4:
        number = int(parts[2])
        if 1 <= number <= len(candidates):
            return candidates[number - 1]
    return None


def ignore_cancel_signals() -> None:
    """Cleanup must finish: a repeated Stop (SIGTERM) or Ctrl-C is ignored.

    Otherwise a second signal raises JobCancelled inside the handler that is
    restoring nfqws2, and the job's final state is never written.
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def stop_and_drain_runner(
    writer: StateWriter,
    process: subprocess.Popen[str],
    candidates: list[tuner.Candidate],
) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        remaining, _ = process.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        writer.log("ERROR|runner-did-not-exit-after-SIGTERM")
        process.kill()
        remaining, _ = process.communicate(timeout=10)
    for line in remaining.splitlines():
        writer.log(line)
        parse_event(writer, line, candidates)


def main() -> int:
    args = build_parser().parse_args()
    args.search_seed = tuner.resolve_search_seed(args.search_seed)
    job_dir = root_path(JOB_LOGICAL)
    job_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(job_dir, 0o700)
    writer = StateWriter(
        job_dir,
        {
            "format": 1,
            "job_id": args.job_id,
            "service": args.service,
            "status": "preparing",
            "created_utc": utc_now(),
            "pid": os.getpid(),
            "mix_level": args.mix_level,
            "max_candidates": args.max_candidates,
            "search_seed": args.search_seed,
            "source_file": args.source_file,
            "needs_voice_verdict": False,
            "result_available": False,
        },
    )
    lock: Path | None = None
    runner_process: subprocess.Popen[str] | None = None
    candidates: list[tuner.Candidate] = []
    xkeen_before = core_pids()

    def cancel_handler(_signum: int, _frame: object) -> None:
        raise JobCancelled()

    signal.signal(signal.SIGTERM, cancel_handler)
    signal.signal(signal.SIGINT, cancel_handler)

    try:
        validate_args(args)
        route = recorded_route(args.service)
        if route != "zapret":
            raise RuntimeError(
                f"{args.service} currently uses route={route}; switch it to zapret first"
            )
        lock = acquire_project_lock()
        writer.write(xkeen_pids_before=xkeen_before, route=route)

        if args.source_dir:
            sources, commit = tuner.load_local_sources(args.source_dir)
            writer.write(source_origin="fixture")
        elif root_path("/opt/etc/xkeen-web/flowseal-sources.json").exists():
            sources, commit = tuner.read_source_cache(root_path("/opt/etc/xkeen-web/flowseal-sources.json"))
            writer.write(source_origin="downloaded-cache")
        else:
            sources, commit = tuner.fetch_sources(
                tuner.DEFAULT_REPOSITORY,
                tuner.DEFAULT_REF,
            )
            writer.write(source_origin="github")
        if args.source_file:
            try:
                sources = tuner.select_source(sources, args.source_file)
            except ValueError as error:
                raise RuntimeError(str(error)) from error
        candidates = tuner.select_candidates(
            tuner.build_candidates(
                args.service,
                sources,
                args.mix_level,
                include_builtin=not args.source_file,
            ),
            args.max_candidates,
            args.search_seed,
        )
        if not candidates and args.source_file:
            raise RuntimeError(f"{args.source_file} has no {args.service} profile")
        if not candidates:
            raise RuntimeError("no safe candidates were generated")
        writer.write(
            commit=commit,
            candidate_count=len(candidates),
            candidates=candidate_summary(candidates),
        )

        template = RUNNER_TEMPLATE.read_text(encoding="utf-8")
        runner = tuner.render_runner(
            template,
            service=args.service,
            candidates=candidates,
            client_ip=args.client_ip or "127.0.0.1",
            voice_duration=args.voice_duration,
            http_timeout=args.http_timeout,
        )
        runner_path = job_dir / "runner.sh"
        runner_path.write_text(runner, encoding="utf-8")
        os.chmod(runner_path, 0o700)
        verdict_path = job_dir / "verdict.txt"
        verdict_path.unlink(missing_ok=True)

        environment = os.environ.copy()
        environment["TUNER_VERDICT_FILE"] = str(verdict_path)
        writer.write(status="running", started_utc=utc_now())
        runner_process = subprocess.Popen(
            ["/bin/sh", str(runner_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=environment,
        )
        writer.write(runner_pid=runner_process.pid)
        assert runner_process.stdout is not None

        found: tuner.Candidate | None = None
        output: list[str] = []
        for raw_line in runner_process.stdout:
            line = raw_line.rstrip("\r\n")
            output.append(line)
            writer.log(line)
            event_found = parse_event(writer, line, candidates)
            if event_found is not None:
                found = event_found
        return_code = runner_process.wait(timeout=40)
        if return_code != 0:
            raise RuntimeError(f"temporary nfqws2 runner exited with code {return_code}")
        if writer.payload.get("restore_error"):
            raise RuntimeError("nfqws2 restoration failed: " + str(writer.payload["restore_error"]))

        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            raise RuntimeError(
                f"XKeen core PID changed unexpectedly: {xkeen_before} -> {xkeen_after}"
            )
        report = make_report(args, commit, candidates, found, output)
        atomic_json(job_dir / "result-report.json", report)
        if found is None:
            writer.write(
                status="none",
                finished_utc=utc_now(),
                xkeen_pids_after=xkeen_after,
                needs_voice_verdict=False,
                verification=report["verification"],
            )
            return 0

        writer.write(
            status="found",
            finished_utc=utc_now(),
            xkeen_pids_after=xkeen_after,
            needs_voice_verdict=False,
            result_available=True,
            found={
                "candidate_id": found.candidate_id,
                "source_name": found.source_name,
                "family": found.family,
                "args": list(found.args),
                "notes": list(found.notes),
            },
            verification=report["verification"],
        )
        return 0
    except JobCancelled:
        ignore_cancel_signals()
        if runner_process is not None:
            stop_and_drain_runner(writer, runner_process, candidates)
        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            writer.write(
                status="error",
                finished_utc=utc_now(),
                error=(
                    "XKeen core PID changed unexpectedly during cancellation: "
                    f"{xkeen_before} -> {xkeen_after}"
                ),
                needs_voice_verdict=False,
                xkeen_pids_after=xkeen_after,
            )
            return 1
        writer.write(
            status="cancelled",
            finished_utc=utc_now(),
            needs_voice_verdict=False,
            xkeen_pids_after=xkeen_after,
        )
        return 130
    except Exception as error:
        ignore_cancel_signals()
        if runner_process is not None:
            stop_and_drain_runner(writer, runner_process, candidates)
        xkeen_after = core_pids()
        if xkeen_after != xkeen_before:
            error = RuntimeError(
                f"{error}; XKeen core PID changed unexpectedly: "
                f"{xkeen_before} -> {xkeen_after}"
            )
        writer.log(f"ERROR|{type(error).__name__}|{error}")
        writer.write(
            status="error",
            finished_utc=utc_now(),
            error=str(error)[:1000],
            needs_voice_verdict=False,
            xkeen_pids_after=xkeen_after,
        )
        return 1
    finally:
        release_project_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())

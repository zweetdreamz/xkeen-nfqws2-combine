"""Characterization unit tests for tools/router/zapret_autotune_job.py.

All filesystem paths are redirected into a temporary directory by patching
the module's TEST_ROOT (the same mechanism KD_TUNER_TEST_ROOT provides).
No network, no root, no real nfqws2 runner: subprocesses are faked.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
JOB_PATH = ROOT / "tools" / "router" / "zapret_autotune_job.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


JOB = load_module("autotune_job_units_module", JOB_PATH)
TUNER = JOB.tuner

SAMPLE = r"""@echo off
start winws.exe ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%ACTIVE_DISCORD_UDP.bin" --dpi-desync-repeats=6 --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=11 --dpi-desync-fake-tls=^!
"""

ROUTES_LINE = "# Active routes: Discord={discord}, YouTube={youtube}.\n"
SOURCE = TUNER.SourceFile(
    "general (ALT11).bat", "", "fixture-sha", "https://example.invalid/g.bat"
)


class FakeWriter:
    def __init__(self):
        self.payload = {}
        self.writes = []
        self.logs = []

    def write(self, **changes):
        self.writes.append(changes)
        self.payload.update(changes)

    def log(self, line):
        self.logs.append(line)


def parse_args(*argv):
    return JOB.build_parser().parse_args(list(argv))


class TempRootTestCase(unittest.TestCase):
    """Redirect every root_path() into a fresh temporary directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        patcher = mock.patch.object(JOB, "TEST_ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_conf(self, discord="zapret", youtube="zapret", extra=""):
        conf = self.root / "opt" / "etc" / "nfqws2" / "nfqws2.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(
            "NFQWS_ARGS=x\n" + extra
            + ROUTES_LINE.format(discord=discord, youtube=youtube),
            encoding="utf-8",
        )
        return conf

    @property
    def lock_dir(self):
        return self.root / "opt" / "tmp" / "keenetic-discord-nfqws2.lock"


class PathAndTimeTests(TempRootTestCase):
    def test_root_path_prefixes_test_root(self):
        self.assertEqual(
            JOB.root_path("/opt/tmp/x"), Path(f"{self.root}/opt/tmp/x")
        )
        with mock.patch.object(JOB, "TEST_ROOT", ""):
            self.assertEqual(JOB.root_path("/opt/tmp/x"), Path("/opt/tmp/x"))

    def test_utc_now_is_timezone_aware_iso(self):
        import datetime as dt

        parsed = dt.datetime.fromisoformat(JOB.utc_now())
        self.assertEqual(parsed.utcoffset(), dt.timedelta(0))


class ValidateArgsTests(unittest.TestCase):
    def test_valid_requests(self):
        JOB.validate_args(parse_args("--service", "youtube", "--job-id", "0123456789abcdef"))
        JOB.validate_args(
            parse_args(
                "--service", "discord-voice", "--job-id", "0123456789abcdef",
                "--client-ip", "192.168.1.5", "--max-candidates", "64",
                "--http-timeout", "20", "--voice-duration", "60",
            )
        )
        JOB.validate_args(
            parse_args(
                "--service", "discord-tcp", "--job-id", "fedcba9876543210",
                "--max-candidates", "1", "--http-timeout", "4",
                "--voice-duration", "10",
            )
        )

    def test_parser_defaults(self):
        args = parse_args("--service", "youtube", "--job-id", "0123456789abcdef")
        self.assertEqual(args.mix_level, "safe")
        self.assertEqual(args.max_candidates, 32)
        self.assertEqual(args.http_timeout, 6)
        self.assertEqual(args.voice_duration, 25)
        self.assertIsNone(args.search_seed)
        self.assertIsNone(args.client_ip)
        self.assertIsNone(args.source_dir)

    def test_rejections(self):
        job = "0123456789abcdef"
        cases = [
            (("--service", "youtube", "--job-id", "0123456789ABCDEF"), "invalid job id"),
            (("--service", "youtube", "--job-id", "0123456789abcde"), "invalid job id"),
            (("--service", "youtube", "--job-id", "../../etc/passwd"), "invalid job id"),
            (("--service", "youtube", "--job-id", job, "--max-candidates", "0"), "max-candidates"),
            (("--service", "youtube", "--job-id", job, "--max-candidates", "65"), "max-candidates"),
            (("--service", "youtube", "--job-id", job, "--http-timeout", "3"), "http-timeout"),
            (("--service", "youtube", "--job-id", job, "--http-timeout", "21"), "http-timeout"),
            (("--service", "youtube", "--job-id", job, "--voice-duration", "9"), "voice-duration"),
            (("--service", "youtube", "--job-id", job, "--voice-duration", "61"), "voice-duration"),
            (("--service", "discord-voice", "--job-id", job), "client-ip is required"),
            (("--service", "discord-voice", "--job-id", job, "--client-ip", "8.8.8.8"),
             "private LAN IPv4"),
            (("--service", "discord-voice", "--job-id", job, "--client-ip", "fd00::1"),
             "private LAN IPv4"),
            (("--service", "discord-voice", "--job-id", job, "--client-ip", "bogus"), ""),
        ]
        for argv, message in cases:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(ValueError, message):
                    JOB.validate_args(parse_args(*argv))

    def test_public_ip_is_fine_for_non_voice_services(self):
        JOB.validate_args(
            parse_args(
                "--service", "youtube", "--job-id", "0123456789abcdef",
                "--client-ip", "8.8.8.8",
            )
        )

    def test_source_dir_requires_test_root(self):
        args = parse_args(
            "--service", "youtube", "--job-id", "0123456789abcdef",
            "--source-dir", "/nonexistent",
        )
        self.assertEqual(args.source_dir, Path("/nonexistent"))
        with mock.patch.object(JOB, "TEST_ROOT", ""):
            with self.assertRaisesRegex(ValueError, "isolated test root"):
                JOB.validate_args(args)
        with mock.patch.object(JOB, "TEST_ROOT", "/tmp/isolated"):
            JOB.validate_args(args)

    def test_parser_rejects_bad_choices(self):
        for argv in (
            ("--service", "telegram", "--job-id", "x"),
            ("--service", "youtube"),
            ("--service", "youtube", "--job-id", "x", "--mix-level", "wild"),
            ("--service", "youtube", "--job-id", "x", "--search-seed", "-1"),
        ):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        parse_args(*argv)


class RecordedRouteTests(TempRootTestCase):
    def test_route_per_service(self):
        self.write_conf(discord="vless", youtube="zapret")
        self.assertEqual(JOB.recorded_route("youtube"), "zapret")
        self.assertEqual(JOB.recorded_route("discord-tcp"), "vless")
        self.assertEqual(JOB.recorded_route("discord-voice"), "vless")

    def test_split_discord_routes(self):
        conf = self.write_conf()
        conf.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.assertEqual(JOB.recorded_route("discord-tcp"), "direct")
        self.assertEqual(JOB.recorded_route("discord-voice"), "zapret")
        self.assertEqual(JOB.recorded_route("youtube"), "vless")

    def test_header_with_telegram(self):
        conf = self.write_conf()
        for telegram in ("direct", "zapret", "vless", "unmanaged"):
            with self.subTest(telegram=telegram):
                conf.write_text(
                    "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, "
                    f"Telegram={telegram}.\n",
                    encoding="utf-8",
                )
                self.assertEqual(JOB.recorded_route("discord-voice"), "zapret")
                self.assertEqual(JOB.parse_active_routes(conf.read_text())["telegram"], telegram)
        # "unmanaged" is valid for Telegram only.
        self.assertIsNone(JOB.parse_active_routes(
            "# Active routes: DiscordTCP=unmanaged, DiscordVoice=zapret, YouTube=vless.\n"
        ))

    def test_first_matching_line_wins(self):
        self.write_conf(extra="# Active routes: Discord=direct, YouTube=direct.\n")
        self.assertEqual(JOB.recorded_route("youtube"), "direct")

    def test_missing_config(self):
        with self.assertRaisesRegex(RuntimeError, "cannot read current nfqws2 config"):
            JOB.recorded_route("youtube")

    def test_unrecognized_routes(self):
        conf = self.write_conf()
        for text in (
            "# Active routes: Discord=zapret, YouTube=other.\n",
            "  # Active routes: Discord=zapret, YouTube=zapret.\n",
            "# Active routes: Discord=zapret, YouTube=zapret\n",
            "",
        ):
            with self.subTest(text=text):
                conf.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "cannot be determined"):
                    JOB.recorded_route("discord-tcp")


class PidTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "pid"

    def test_read_pid_variants(self):
        self.assertIsNone(JOB.read_pid(self.path))
        cases = {
            b"123\n": 123,
            b"  77  ": 77,
            b"2": 2,
            b"1": None,
            b"0": None,
            b"-5": None,
            b"abc": None,
            b"": None,
            b"12 34": None,
            b"\xff\xfe": None,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                self.assertEqual(JOB.read_pid(self.path), expected)

    def test_read_pid_on_directory_is_none(self):
        self.path.mkdir()
        self.assertIsNone(JOB.read_pid(self.path))

    def test_process_alive(self):
        self.assertTrue(JOB.process_alive(os.getpid()))
        with mock.patch.object(JOB.os, "kill", side_effect=ProcessLookupError):
            self.assertFalse(JOB.process_alive(4242))
        with mock.patch.object(JOB.os, "kill", return_value=None) as kill:
            self.assertTrue(JOB.process_alive(4242))
        kill.assert_called_once_with(4242, 0)


class ProjectLockTests(TempRootTestCase):
    def test_acquire_and_release(self):
        lock = JOB.acquire_project_lock()
        self.assertEqual(lock, self.lock_dir)
        self.assertTrue(lock.is_dir())
        self.assertEqual(JOB.read_pid(lock / "pid"), os.getpid())
        if os.name == "posix":
            self.assertEqual((lock / "pid").stat().st_mode & 0o777, 0o600)
        JOB.release_project_lock(lock)
        self.assertFalse(lock.exists())

    def test_second_acquire_while_owner_alive_fails(self):
        lock = JOB.acquire_project_lock()
        with self.assertRaisesRegex(RuntimeError, f"PID {os.getpid()}"):
            JOB.acquire_project_lock()
        self.assertEqual(JOB.read_pid(lock / "pid"), os.getpid())
        JOB.release_project_lock(lock)

    def test_stale_lock_with_dead_pid_is_reclaimed(self):
        self.lock_dir.mkdir(parents=True)
        (self.lock_dir / "pid").write_text("999999\n", encoding="ascii")
        with mock.patch.object(JOB, "process_alive", return_value=False) as alive:
            lock = JOB.acquire_project_lock()
        alive.assert_called_once_with(999999)
        self.assertEqual(JOB.read_pid(lock / "pid"), os.getpid())
        JOB.release_project_lock(lock)

    def test_stale_lock_without_pid_is_reclaimed(self):
        self.lock_dir.mkdir(parents=True)
        with mock.patch.object(JOB, "process_alive") as alive:
            lock = JOB.acquire_project_lock()
        alive.assert_not_called()
        self.assertEqual(JOB.read_pid(lock / "pid"), os.getpid())
        JOB.release_project_lock(lock)

    def test_stale_lock_with_garbage_pid_is_reclaimed(self):
        self.lock_dir.mkdir(parents=True)
        (self.lock_dir / "pid").write_text("garbage", encoding="ascii")
        lock = JOB.acquire_project_lock()
        self.assertEqual(JOB.read_pid(lock / "pid"), os.getpid())
        JOB.release_project_lock(lock)

    def test_stale_lock_with_extra_file_is_refused(self):
        self.lock_dir.mkdir(parents=True)
        (self.lock_dir / "pid").write_text("999999\n", encoding="ascii")
        (self.lock_dir / "other").write_text("x", encoding="ascii")
        with mock.patch.object(JOB, "process_alive", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "stale project lock is not empty"):
                JOB.acquire_project_lock()
        self.assertTrue((self.lock_dir / "other").exists())

    def test_release_ignores_foreign_or_missing_lock(self):
        JOB.release_project_lock(None)
        self.lock_dir.mkdir(parents=True)
        (self.lock_dir / "pid").write_text("999999\n", encoding="ascii")
        JOB.release_project_lock(self.lock_dir)
        self.assertTrue((self.lock_dir / "pid").exists())
        missing = self.root / "missing.lock"
        JOB.release_project_lock(missing)
        self.assertFalse(missing.exists())

    def test_release_swallows_os_errors(self):
        lock = JOB.acquire_project_lock()
        (lock / "extra").write_text("x", encoding="ascii")
        JOB.release_project_lock(lock)
        self.assertTrue(lock.is_dir())
        self.assertFalse((lock / "pid").exists())


class CorePidsTests(unittest.TestCase):
    def test_collects_sorted_numeric_pids(self):
        def fake_run(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 5)
            self.assertFalse(kwargs["check"])
            if command == ["pidof", "xray"]:
                return subprocess.CompletedProcess(command, 0, "30 4 junk\n", "")
            return subprocess.CompletedProcess(command, 1, "", "")

        with mock.patch.object(JOB.subprocess, "run", side_effect=fake_run):
            self.assertEqual(JOB.core_pids(), {"xray": [4, 30]})

    def test_tool_errors_are_skipped(self):
        responses = [
            OSError("no pidof"),
            subprocess.CompletedProcess(["pidof", "mihomo"], 0, "9\n", ""),
        ]
        with mock.patch.object(JOB.subprocess, "run", side_effect=responses):
            self.assertEqual(JOB.core_pids(), {"mihomo": [9]})
        with mock.patch.object(
            JOB.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(["pidof"], 5),
        ):
            self.assertEqual(JOB.core_pids(), {})


class AtomicJsonAndStateWriterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_atomic_json(self):
        path = self.dir / "a" / "b" / "state.json"
        JOB.atomic_json(path, {"text": "привет", "n": 1})
        raw = path.read_text(encoding="utf-8")
        self.assertTrue(raw.endswith("}\n"))
        self.assertIn("привет", raw)
        self.assertEqual(json.loads(raw), {"text": "привет", "n": 1})
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        JOB.atomic_json(path, {"n": 2})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"n": 2})
        self.assertEqual([p.name for p in path.parent.iterdir()], ["state.json"])

    def test_atomic_json_failure_leaves_no_temporary(self):
        path = self.dir / "state.json"
        JOB.atomic_json(path, {"n": 1})
        with self.assertRaises(TypeError):
            JOB.atomic_json(path, {"bad": object()})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"n": 1})
        self.assertEqual([p.name for p in self.dir.iterdir()], ["state.json"])

    def test_state_writer(self):
        job_dir = self.dir / "job"
        initial = {"status": "preparing"}
        writer = JOB.StateWriter(job_dir, initial)
        self.assertIs(writer.payload, initial)
        first = json.loads((job_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(first["status"], "preparing")
        self.assertIn("updated_utc", first)
        writer.write(status="running", current_candidate=2)
        state = json.loads((job_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "running")
        self.assertEqual(state["current_candidate"], 2)
        writer.log("first\x00line\r\n")
        writer.log("x" * 5000)
        writer.log("")
        lines = (job_dir / "events.log").read_text(encoding="utf-8").split("\n")
        self.assertEqual(lines[0], "firstline")
        self.assertEqual(len(lines[1]), 4000)
        self.assertEqual(lines[2:], ["", ""])


class VoiceAutoTests(TempRootTestCase):
    def test_voice_endpoint_validation(self):
        self.assertTrue(JOB.voice_endpoint_valid("162.159.130.234", 50007))
        self.assertTrue(JOB.voice_endpoint_valid("162.159.130.234", 19300))
        for ip, port in (
            ("192.168.2.1", 50007),
            ("10.0.0.1", 50007),
            ("2606:4700::1", 50007),
            ("162.159.130.234", 443),
            # Candidates never process ports above 50100.
            ("162.159.130.234", 50101),
            ("162.159.130.234", 65535),
            ("100.64.0.1", 50007),
            ("162.159.130.234", "50007"),
            ("162.159.130.234", True),
            ("not-an-ip", 50007),
            (None, 50007),
        ):
            with self.subTest(ip=ip, port=port):
                self.assertFalse(JOB.voice_endpoint_valid(ip, port))

    def test_endpoint_store_round_trip_and_rejections(self):
        self.assertIsNone(JOB.load_voice_endpoint())
        JOB.save_voice_endpoint({"ip": "162.159.130.234", "port": 50007, "outgoing_packets": 3})
        path = self.root / JOB.VOICE_ENDPOINT_LOGICAL.lstrip("/")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        loaded = JOB.load_voice_endpoint()
        self.assertEqual((loaded["ip"], loaded["port"]), ("162.159.130.234", 50007))
        self.assertIn("learned_utc", loaded)
        for text in ("[]", "{broken", '{"ip": "192.168.2.1", "port": 50007}', "x" * 5000):
            with self.subTest(text=text[:20]):
                path.write_text(text, encoding="utf-8")
                self.assertIsNone(JOB.load_voice_endpoint())

    def test_voice_auto_requires_discord_voice(self):
        args = JOB.build_parser().parse_args(
            ["--service", "youtube", "--job-id", "0123456789abcdef", "--voice-auto"]
        )
        with self.assertRaisesRegex(ValueError, "voice-auto"):
            JOB.validate_args(args)


class ParseEventTests(unittest.TestCase):
    def setUp(self):
        self.writer = FakeWriter()
        self.candidates = [
            TUNER.known_candidate("youtube", [SOURCE]),
            TUNER.known_candidate("discord-tcp", [SOURCE]),
        ]

    def parse(self, line):
        return JOB.parse_event(self.writer, line, self.candidates)

    def test_voice_auto_events(self):
        self.parse("EVENT|VOICE_ENDPOINT|162.159.130.234|50007|15|12")
        self.assertEqual(
            self.writer.payload["voice_endpoint_observed"],
            {"ip": "162.159.130.234", "port": 50007, "outgoing_packets": 15, "incoming_packets": 12},
        )
        self.parse("EVENT|VOICE_ENDPOINT|192.168.2.1|50007|15|12")
        self.assertEqual(self.writer.payload["voice_endpoint_observed"]["ip"], "162.159.130.234")
        self.parse("EVENT|VOICE_PROBE|active|3|1|1")
        self.parse("EVENT|VOICE_PROBE|raw|3|0|0")
        self.parse("EVENT|VOICE_PROBE|candidate-2|3|2|2")
        self.assertEqual(self.writer.payload["last_voice_probe"]["label"], "candidate-2")
        self.assertEqual(set(self.writer.payload["voice_calibration"]), {"active", "raw"})
        self.assertEqual(self.writer.payload["voice_calibration"]["raw"]["valid"], 0)
        self.parse("EVENT|VOICE_AUTO_MODE|auto|raw-no-reply")
        self.assertEqual(self.writer.payload["voice_auto_mode"], "auto")
        self.parse("EVENT|VOICE_AUTO|2|pass")
        self.assertEqual(self.writer.payload["last_voice_auto"], {"candidate": 2, "result": "pass"})
        self.parse("EVENT|VOICE_UNCONFIRMED|2")
        self.assertIs(self.writer.payload["voice_unconfirmed"], True)

    def test_non_event_and_unknown_lines_are_ignored(self):
        for line in ("hello", "EVENT", "event|FOUND|1", "EVENT|", "EVENT|UNKNOWN|1|2"):
            with self.subTest(line=line):
                self.assertIsNone(self.parse(line))
        self.assertEqual(self.writer.writes, [])

    def test_short_events_are_ignored(self):
        for line in (
            "EVENT|CANDIDATE|1",
            "EVENT|SUITE_RESULT|1|confirm|1|pass|4",
            "EVENT|VOICE_OBSERVATION|1|2",
            "EVENT|PROBE|1|200",
            "EVENT|HTTP_RESULT|1|2",
            "EVENT|VOICE_READY|1",
            "EVENT|VOICE_VERDICT",
            "EVENT|FOUND|1",
            "EVENT|PROBE_DETAIL|1|short",
        ):
            with self.subTest(line=line):
                self.assertIsNone(self.parse(line))
        self.assertEqual(self.writer.writes, [])

    def test_candidate(self):
        self.parse("EVENT|CANDIDATE|2|abc123")
        self.assertEqual(
            self.writer.writes,
            [{"voice_endpoint_observed": None, "status": "running", "current_candidate": 2,
              "current_candidate_id": "abc123", "needs_voice_verdict": False}],
        )

    def test_endpoint_of_a_rejected_candidate_is_not_kept(self):
        self.parse("EVENT|CANDIDATE|1|aaa")
        self.parse("EVENT|VOICE_ENDPOINT|162.159.130.234|50007|40|38")
        self.assertEqual(self.writer.payload["voice_endpoint_observed"]["port"], 50007)
        self.parse("EVENT|CANDIDATE|2|bbb")
        self.assertIsNone(self.writer.payload["voice_endpoint_observed"])

    def test_suite_results(self):
        self.parse("EVENT|SUITE_RESULT|0|baseline|1|fail|1|4")
        self.parse("EVENT|SUITE_RESULT|3|confirm|2|pass|4|4")
        self.assertEqual(
            self.writer.payload["baseline_result"],
            {"candidate": 0, "phase": "baseline", "round": 1, "verdict": "fail",
             "successes": 1, "total": 4},
        )
        self.assertEqual(
            self.writer.payload["last_suite_result"],
            {"candidate": 3, "phase": "confirm", "round": 2, "verdict": "pass",
             "successes": 4, "total": 4},
        )

    def test_voice_observation(self):
        self.parse("EVENT|VOICE_OBSERVATION|18|0|0")
        self.assertEqual(
            self.writer.payload["voice_observation"],
            {"outgoing_packets": 18, "incoming_packets": 0, "wan_match": False},
        )

    def test_probe_keeps_pipes_and_truncates(self):
        self.parse("EVENT|PROBE|4|200|https://a.invalid/x|y")
        self.assertEqual(
            self.writer.payload["last_probe"],
            {"candidate": 4, "code": "200", "url": "https://a.invalid/x|y"},
        )
        self.parse("EVENT|PROBE|4|000|" + "u" * 600)
        self.assertEqual(len(self.writer.payload["last_probe"]["url"]), 500)

    def test_probe_detail(self):
        self.parse("EVENT|PROBE_DETAIL|1|confirm|1|page|200|0.5|10|0|ok|https://u")
        self.assertEqual(self.writer.payload["last_probe_detail"]["url"], "https://u")
        self.writer.writes.clear()
        self.parse("EVENT|PROBE_DETAIL|x|confirm|1|page|200|0.5|10|0|ok|https://u")
        self.assertEqual(self.writer.writes, [])

    def test_http_result(self):
        self.parse("EVENT|HTTP_RESULT|2|3|4")
        self.assertEqual(
            self.writer.payload["last_http_result"],
            {"candidate": 2, "successes": 3, "total": 4},
        )

    def test_voice_ready_and_verdict(self):
        self.parse("EVENT|VOICE_READY|1|25")
        self.assertEqual(
            self.writer.writes[-1],
            {"status": "voice_window", "current_candidate": 1,
             "voice_duration": 25, "needs_voice_verdict": False},
        )
        self.parse("EVENT|VOICE_VERDICT|1")
        self.assertEqual(
            self.writer.writes[-1],
            {"status": "awaiting_voice", "current_candidate": 1,
             "needs_voice_verdict": True},
        )

    def test_error_and_restore_events(self):
        self.parse("EVENT|START_FAILED|nfqws2|exit|1")
        self.assertEqual(self.writer.payload["last_error"], "nfqws2|exit|1")
        self.parse("EVENT|START_FAILED")
        self.assertEqual(self.writer.payload["last_error"], "")
        self.parse("EVENT|RESTORE_ERROR|" + "e" * 600)
        self.assertEqual(self.writer.payload["restore_error"], "e" * 500)
        self.parse("EVENT|RESTORED|ok")
        self.assertEqual(self.writer.payload["nfqws_restored"], "ok")
        self.parse("EVENT|RESTORED")
        self.assertEqual(self.writer.payload["nfqws_restored"], "unknown")

    def test_found_selects_by_one_based_number(self):
        self.assertIs(self.parse("EVENT|FOUND|1|x"), self.candidates[0])
        self.assertIs(self.parse("EVENT|FOUND|2|x"), self.candidates[1])
        self.assertIsNone(self.parse("EVENT|FOUND|0|x"))
        self.assertIsNone(self.parse("EVENT|FOUND|3|x"))
        self.assertIsNone(self.parse("EVENT|FOUND|-1|x"))
        self.assertEqual(self.writer.writes, [])

    def test_non_numeric_fields_raise(self):
        with self.assertRaises(ValueError):
            self.parse("EVENT|CANDIDATE|x|id")


class SummaryAndReportTests(unittest.TestCase):
    def setUp(self):
        self.candidates = [
            TUNER.known_candidate("youtube", [SOURCE]),
            TUNER.known_candidate("discord-tcp", [SOURCE]),
        ]

    def test_candidate_summary(self):
        summary = JOB.candidate_summary(self.candidates)
        self.assertEqual(
            summary[1],
            {
                "number": 2,
                "candidate_id": self.candidates[1].candidate_id,
                "source_name": SOURCE.name,
                "family": self.candidates[1].family,
                "rank": 0,
            },
        )
        self.assertEqual([item["number"] for item in summary], [1, 2])
        self.assertEqual(JOB.candidate_summary([]), [])

    def test_make_report_without_found_truncates_output(self):
        args = parse_args(
            "--service", "discord-voice", "--job-id", "0123456789abcdef",
            "--search-seed", "9",
        )
        output = [f"line {index}" for index in range(600)]
        report = JOB.make_report(args, "c" * 40, self.candidates, None, output)
        self.assertIsNone(report["found"])
        self.assertEqual(report["remote_output"], output[-500:])
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual(report["router"], "local-panel")
        self.assertEqual(report["repository"], TUNER.DEFAULT_REPOSITORY)
        self.assertEqual(report["ref"], TUNER.DEFAULT_REF)
        self.assertEqual(report["search_seed"], 9)
        self.assertEqual(report["verification"]["method"], "manual-duplex-voice")
        json.dumps(report)

    def test_make_report_with_found(self):
        args = parse_args("--service", "youtube", "--job-id", "0123456789abcdef")
        found = self.candidates[0]
        report = JOB.make_report(args, "c", self.candidates, found, [])
        self.assertEqual(
            report["found"],
            {
                "candidate_id": found.candidate_id,
                "service": "youtube",
                "source_name": SOURCE.name,
                "source_sha": "fixture-sha",
                "source_url": SOURCE.url,
                "family": found.family,
                "args": list(found.args),
                "notes": list(found.notes),
                "rank": 0,
            },
        )
        self.assertIsNone(report["search_seed"])


class FakeRunner:
    """Stand-in for subprocess.Popen of the router runner."""

    def __init__(self, lines=(), returncode=0, remaining="", timeout_first=False):
        self.lines = list(lines)
        self.returncode_value = returncode
        self.remaining = remaining
        self.timeout_first = timeout_first
        self.pid = 4321
        self.terminated = False
        self.killed = False
        self.finished = False
        self.communicate_calls = []
        self.stdout = self._iter()

    def _iter(self):
        for line in self.lines:
            if isinstance(line, BaseException):
                raise line
            yield line
        self.finished = True

    def poll(self):
        return self.returncode_value if self.finished else None

    def wait(self, timeout=None):
        return self.returncode_value

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def communicate(self, timeout=None):
        self.communicate_calls.append(timeout)
        if self.timeout_first and len(self.communicate_calls) == 1:
            raise subprocess.TimeoutExpired("runner", timeout)
        return self.remaining, None


class StopAndDrainTests(unittest.TestCase):
    def test_terminates_running_process_and_parses_rest(self):
        writer = FakeWriter()
        process = FakeRunner(remaining="EVENT|RESTORED|ok\nplain\n")
        JOB.stop_and_drain_runner(writer, process, [])
        self.assertTrue(process.terminated)
        self.assertFalse(process.killed)
        self.assertEqual(process.communicate_calls, [40])
        self.assertEqual(writer.logs, ["EVENT|RESTORED|ok", "plain"])
        self.assertEqual(writer.payload["nfqws_restored"], "ok")

    def test_finished_process_is_not_terminated(self):
        process = FakeRunner()
        list(process.stdout)
        JOB.stop_and_drain_runner(FakeWriter(), process, [])
        self.assertFalse(process.terminated)

    def test_kills_after_timeout(self):
        writer = FakeWriter()
        process = FakeRunner(remaining="EVENT|RESTORED|forced\n", timeout_first=True)
        JOB.stop_and_drain_runner(writer, process, [])
        self.assertTrue(process.killed)
        self.assertEqual(process.communicate_calls, [40, 10])
        self.assertEqual(
            writer.logs,
            ["ERROR|runner-did-not-exit-after-SIGTERM", "EVENT|RESTORED|forced"],
        )


class MainTests(TempRootTestCase):
    JOB_ID = "0123456789abcdef"

    def setUp(self):
        super().setUp()
        self.sources = self.root / "fixture-sources"
        self.sources.mkdir()
        (self.sources / "general (ALT11).bat").write_text(SAMPLE, encoding="utf-8")
        self.job_dir = self.root / "opt" / "tmp" / "xkeen-zapret-tuner"
        self.popen_calls = []

    def run_main(self, runner, *extra, core=None, service="youtube", source_dir=True):
        argv = ["zapret_autotune_job.py", "--service", service, "--job-id",
                self.JOB_ID, "--search-seed", "123", "--max-candidates", "3", *extra]
        if source_dir:
            argv += ["--source-dir", str(self.sources)]

        def fake_popen(command, **kwargs):
            self.popen_calls.append((command, kwargs))
            return runner

        core_mock = mock.Mock(side_effect=core or [{}, {}])
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(JOB.signal, "signal") as signal_mock, \
                mock.patch.object(JOB.subprocess, "Popen", side_effect=fake_popen), \
                mock.patch.object(JOB, "core_pids", core_mock):
            code = JOB.main()
        self.signal_mock = signal_mock
        return code

    def state(self):
        return json.loads((self.job_dir / "state.json").read_text(encoding="utf-8"))

    def test_found_flow(self):
        self.write_conf()
        runner = FakeRunner(
            [
                "EVENT|CANDIDATE|1|id1\n",
                "EVENT|PROBE_DETAIL|1|confirm|1|page|200|0.5|10|0|ok|https://u\n",
                "EVENT|RESTORED|ok\n",
                "EVENT|FOUND|2|id2\r\n",
            ]
        )
        code = self.run_main(runner, core=[{"xray": [7]}, {"xray": [7]}])
        self.assertEqual(code, 0)
        state = self.state()
        self.assertEqual(state["status"], "found")
        self.assertTrue(state["result_available"])
        self.assertEqual(state["source_origin"], "fixture")
        self.assertEqual(state["route"], "zapret")
        self.assertEqual(state["candidate_count"], 3)
        self.assertEqual(state["search_seed"], 123)
        self.assertEqual(state["runner_pid"], 4321)
        self.assertEqual(state["xkeen_pids_before"], {"xray": [7]})
        self.assertEqual(state["xkeen_pids_after"], {"xray": [7]})
        self.assertEqual(state["found"]["candidate_id"], state["candidates"][1]["candidate_id"])
        self.assertEqual(state["nfqws_restored"], "ok")
        report = json.loads((self.job_dir / "result-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["found"]["candidate_id"], state["found"]["candidate_id"])
        self.assertEqual(len(report["verification"]["probes"]), 1)
        log = (self.job_dir / "events.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(log[-1], "EVENT|FOUND|2|id2")
        runner_script = (self.job_dir / "runner.sh").read_text(encoding="utf-8")
        self.assertNotIn("@@", runner_script)
        self.assertIn('CLIENT_IP="127.0.0.1"', runner_script)
        command, kwargs = self.popen_calls[0]
        self.assertEqual(command, ["/bin/sh", str(self.job_dir / "runner.sh")])
        self.assertEqual(
            kwargs["env"]["TUNER_VERDICT_FILE"], str(self.job_dir / "verdict.txt")
        )
        self.assertFalse(self.lock_dir.exists())
        handled = {call.args[0] for call in self.signal_mock.call_args_list}
        self.assertEqual(handled, {JOB.signal.SIGTERM, JOB.signal.SIGINT})
        handler = self.signal_mock.call_args_list[0].args[1]
        with self.assertRaises(JOB.JobCancelled):
            handler(JOB.signal.SIGTERM, None)

    def test_no_candidate_found(self):
        self.write_conf()
        (self.job_dir).mkdir(parents=True)
        (self.job_dir / "verdict.txt").write_text("yes", encoding="utf-8")
        code = self.run_main(FakeRunner(["EVENT|FOUND|9|x\n"]))
        self.assertEqual(code, 0)
        state = self.state()
        self.assertEqual(state["status"], "none")
        self.assertFalse(state["result_available"])
        self.assertIn("verification", state)
        self.assertFalse((self.job_dir / "verdict.txt").exists())
        self.assertTrue((self.job_dir / "result-report.json").exists())

    def test_route_not_zapret_is_error(self):
        self.write_conf(youtube="vless")
        code = self.run_main(FakeRunner())
        self.assertEqual(code, 1)
        state = self.state()
        self.assertEqual(state["status"], "error")
        self.assertIn("route=vless", state["error"])
        self.assertEqual(self.popen_calls, [])
        self.assertFalse(self.lock_dir.exists())
        log = (self.job_dir / "events.log").read_text(encoding="utf-8")
        self.assertIn("ERROR|RuntimeError|", log)

    def test_invalid_args_are_reported_in_state(self):
        self.write_conf()
        code = self.run_main(FakeRunner(), "--http-timeout", "99")
        self.assertEqual(code, 1)
        self.assertIn("http-timeout", self.state()["error"])

    def test_busy_lock_is_error_and_kept(self):
        self.write_conf()
        self.lock_dir.mkdir(parents=True)
        (self.lock_dir / "pid").write_text(f"{os.getpid()}\n", encoding="ascii")
        code = self.run_main(FakeRunner())
        self.assertEqual(code, 1)
        self.assertIn("another project operation is active", self.state()["error"])
        self.assertTrue((self.lock_dir / "pid").exists())

    def test_runner_failure_is_error(self):
        self.write_conf()
        runner = FakeRunner(["EVENT|CANDIDATE|1|x\n"], returncode=2)
        code = self.run_main(runner)
        self.assertEqual(code, 1)
        self.assertIn("exited with code 2", self.state()["error"])
        self.assertFalse(runner.terminated)
        self.assertFalse(self.lock_dir.exists())

    def test_restore_error_is_error(self):
        self.write_conf()
        code = self.run_main(FakeRunner(["EVENT|RESTORE_ERROR|disk full\n"]))
        self.assertEqual(code, 1)
        self.assertEqual(
            self.state()["error"], "nfqws2 restoration failed: disk full"
        )

    def test_core_pid_change_is_error(self):
        self.write_conf()
        code = self.run_main(
            FakeRunner(["EVENT|FOUND|1|x\n"]),
            core=[{"xray": [1]}, {"xray": [2]}, {"xray": [2]}],
        )
        self.assertEqual(code, 1)
        state = self.state()
        self.assertEqual(state["status"], "error")
        self.assertIn("XKeen core PID changed unexpectedly", state["error"])
        self.assertEqual(state["xkeen_pids_after"], {"xray": [2]})

    def test_cancellation_drains_runner(self):
        self.write_conf()
        runner = FakeRunner(
            ["EVENT|CANDIDATE|1|x\n", JOB.JobCancelled()],
            remaining="EVENT|RESTORED|ok\n",
        )
        code = self.run_main(runner)
        self.assertEqual(code, 130)
        state = self.state()
        self.assertEqual(state["status"], "cancelled")
        self.assertFalse(state["needs_voice_verdict"])
        self.assertEqual(state["nfqws_restored"], "ok")
        self.assertTrue(runner.terminated)
        self.assertFalse(self.lock_dir.exists())

    def test_repeated_cancel_during_drain_still_records_cancelled(self):
        """A second Stop (SIGTERM) while the runner restores nfqws2 is ignored."""
        self.write_conf()
        handlers = {}

        class SecondSignalRunner(FakeRunner):
            def communicate(self, timeout=None):
                handler = handlers.get(JOB.signal.SIGTERM)
                if callable(handler):
                    handler(JOB.signal.SIGTERM, None)
                return super().communicate(timeout)

        runner = SecondSignalRunner(
            ["EVENT|CANDIDATE|1|x\n", JOB.JobCancelled()],
            remaining="EVENT|RESTORED|ok\n",
        )
        argv = ["zapret_autotune_job.py", "--service", "youtube", "--job-id", self.JOB_ID,
                "--search-seed", "123", "--max-candidates", "3", "--source-dir", str(self.sources)]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(JOB.signal, "signal", side_effect=handlers.__setitem__), \
                mock.patch.object(JOB.subprocess, "Popen", return_value=runner), \
                mock.patch.object(JOB, "core_pids", mock.Mock(side_effect=[{}, {}])):
            code = JOB.main()
        self.assertEqual(code, 130)
        self.assertEqual(self.state()["status"], "cancelled")
        self.assertEqual(self.state()["nfqws_restored"], "ok")
        self.assertIs(handlers[JOB.signal.SIGTERM], JOB.signal.SIG_IGN)
        self.assertIs(handlers[JOB.signal.SIGINT], JOB.signal.SIG_IGN)
        self.assertFalse(self.lock_dir.exists())

    def test_cancellation_with_core_pid_change_is_error(self):
        self.write_conf()
        runner = FakeRunner([JOB.JobCancelled()])
        code = self.run_main(runner, core=[{}, {"mihomo": [5]}])
        self.assertEqual(code, 1)
        state = self.state()
        self.assertEqual(state["status"], "error")
        self.assertIn("during cancellation", state["error"])

    def test_cancellation_before_runner_start(self):
        self.write_conf()
        with mock.patch.object(JOB, "recorded_route", side_effect=JOB.JobCancelled()):
            code = self.run_main(FakeRunner())
        self.assertEqual(code, 130)
        self.assertEqual(self.state()["status"], "cancelled")
        self.assertEqual(self.popen_calls, [])

    def test_downloaded_cache_is_used_without_source_dir(self):
        self.write_conf()
        cache = self.root / "opt" / "etc" / "xkeen-web" / "flowseal-sources.json"
        TUNER.save_source_cache(
            cache,
            [TUNER.SourceFile("general (ALT11).bat", SAMPLE, "d" * 40, "https://x/g.bat")],
            "a" * 40,
        )
        code = self.run_main(FakeRunner(), source_dir=False)
        self.assertEqual(code, 0)
        state = self.state()
        self.assertEqual(state["source_origin"], "downloaded-cache")
        self.assertEqual(state["commit"], "a" * 40)

    def test_github_fallback_without_cache(self):
        self.write_conf()
        fetched = (
            [TUNER.SourceFile("general.bat", SAMPLE, "e" * 40, "https://x/g.bat")],
            "b" * 40,
        )
        with mock.patch.object(TUNER, "fetch_sources", return_value=fetched) as fetch:
            code = self.run_main(FakeRunner(), source_dir=False)
        self.assertEqual(code, 0)
        fetch.assert_called_once_with(TUNER.DEFAULT_REPOSITORY, TUNER.DEFAULT_REF)
        self.assertEqual(self.state()["source_origin"], "github")

    def test_no_candidates_is_error(self):
        self.write_conf()
        with mock.patch.object(TUNER, "select_candidates", return_value=[]):
            code = self.run_main(FakeRunner())
        self.assertEqual(code, 1)
        self.assertIn("no safe candidates", self.state()["error"])

    def test_voice_uses_client_ip(self):
        self.write_conf()
        code = self.run_main(
            FakeRunner(["EVENT|VOICE_VERDICT|1\n"]),
            "--client-ip", "192.168.2.50",
            service="discord-voice",
        )
        self.assertEqual(code, 0)
        runner_script = (self.job_dir / "runner.sh").read_text(encoding="utf-8")
        self.assertIn('CLIENT_IP="192.168.2.50"', runner_script)
        self.assertEqual(self.state()["status"], "none")


if __name__ == "__main__":
    unittest.main()

"""Tests of the tuner and diagnostic jobs of the panel: job state, launch, report sources and start races."""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import unittest
from unittest import mock

from panel_fixtures import REPO, PanelUnitCase


class TunerAndDiagnosticJobTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        tuner = self.root / "tuner"
        self.patch(
            TUNER_JOB_DIR=tuner,
            TUNER_STATE=tuner / "state.json",
            TUNER_RESULT=tuner / "result-report.json",
            TUNER_VERDICT=tuner / "verdict.txt",
            TUNER_PID=tuner / "panel-launch.pid",
        )
        self.tuner = tuner

    def write_tuner_state(self, state):
        self.tuner.mkdir(exist_ok=True)
        self.ns["TUNER_STATE"].write_text(json.dumps(state), encoding="utf-8")

    def test_submit_voice_verdict(self):
        submit = self.ns["submit_voice_verdict"]
        with self.patched(tuner_active=lambda: True):
            with self.assertRaises(FileNotFoundError):
                submit(True)
        self.write_tuner_state({"status": "awaiting_voice"})
        with self.patched(tuner_active=lambda: False):
            with self.assertRaisesRegex(RuntimeError, "сейчас ответ Voice не ожидается"):
                submit(True)
        self.write_tuner_state({"status": "running"})
        with self.patched(tuner_active=lambda: True):
            with self.assertRaisesRegex(RuntimeError, "сейчас ответ Voice не ожидается"):
                submit(True)
        self.write_tuner_state({"status": "awaiting_voice"})
        with self.patched(tuner_active=lambda: True):
            submit(True)
            self.assertEqual(self.ns["TUNER_VERDICT"].read_text(encoding="utf-8"), "yes\n")
            with self.assertRaisesRegex(RuntimeError, "ответ для этого кандидата уже отправлен"):
                submit(False)
            self.ns["TUNER_VERDICT"].unlink()
            submit(False)
            self.assertEqual(self.ns["TUNER_VERDICT"].read_text(encoding="utf-8"), "no\n")

    def test_tuner_status(self):
        status = self.ns["tuner_status"]()
        self.assertEqual(status["status"], "idle")
        self.assertFalse(status["active"])
        self.write_tuner_state({"status": "running", "service": "youtube"})
        (self.tuner / "events.log").write_text("a\nb\n", encoding="utf-8")
        status = self.ns["tuner_status"]()
        self.assertEqual(status["status"], "error")
        self.assertEqual(status["error"], "процесс подбора завершился неожиданно")
        self.assertEqual(status["log_tail"], ["a", "b"])
        self.write_tuner_state({"status": "found", "result_available": True})
        status = self.ns["tuner_status"]()
        self.assertEqual(status["status"], "found")
        self.assertTrue(status["result_available"])
        self.ns["TUNER_STATE"].write_text("nope", encoding="utf-8")
        self.assertEqual(self.ns["tuner_status"]()["status"], "error")

    def test_dead_job_in_any_non_terminal_state_is_reported_as_error(self):
        # B8/D8: "voice_watch" was missing from the stale-state set and locked the page.
        job = (REPO / "tools" / "router" / "zapret_autotune_job.py").read_text(encoding="utf-8")
        written = set(re.findall(r'status="([a-z_]+)"', job)) | set(re.findall(r'"status": "([a-z_]+)"', job))
        self.assertIn("voice_watch", written)
        terminal = self.ns["TERMINAL_TUNER_STATES"]
        for state in sorted(written - terminal) + ["cancelling", "some_future_state"]:
            with self.subTest(state=state):
                self.write_tuner_state({"status": state, "service": "discord-voice"})
                status = self.ns["tuner_status"]()
                self.assertEqual(status["status"], "error")
                self.assertFalse(status["active"])
        for state in sorted(written & terminal):
            with self.subTest(state=state):
                self.write_tuner_state({"status": state})
                self.assertEqual(self.ns["tuner_status"]()["status"], state)
        # The page no longer keeps its own list of active states.
        self.assertNotIn("activeTunerStates", self.ns["HTML"])

    def test_finished_baseline_check_keeps_its_verdict(self):
        # A baseline-only job ends in one of these; automation_check_service reads the verdict after the job exited,
        # so a dead process with one of them must not be turned into an error.
        for state in ("healthy", "unhealthy", "unstable"):
            with self.subTest(state=state):
                self.write_tuner_state({"status": state, "service": "youtube"})
                status = self.ns["tuner_status"]()
                self.assertEqual((status["status"], status["active"]), (state, False))
                self.assertNotIn("error", status)

    def test_cancel_tuner_job_terminates_the_process_group_and_marks_the_state(self):
        def cancel():
            """cancel_tuner_job with both signal calls stubbed (nothing real can be signalled); returns killpg."""
            store = self.ns.module("jobfiles").TUNER_STORE
            with mock.patch.object(store, "pid", return_value=4242), mock.patch.object(store, "alive", return_value=True), \
                    mock.patch.object(os, "killpg") as killpg, mock.patch.object(os, "kill") as kill:
                self.ns["cancel_tuner_job"]()
            kill.assert_not_called()
            return killpg

        self.write_tuner_state({"status": "running", "service": "youtube", "candidate_count": 3})
        (self.tuner / "job.id").write_text("a" * 16)
        killpg = cancel()
        killpg.assert_called_once_with(4242, signal.SIGTERM)
        self.assertEqual(json.loads(self.ns["TUNER_STATE"].read_text(encoding="utf-8")),
                         {"status": "running", "service": "youtube", "candidate_count": 3})
        self.assertTrue((self.tuner / "cancel.request").is_file())
        store = self.ns.module("jobfiles").TUNER_STORE
        with mock.patch.object(store, "pid", return_value=4242), mock.patch.object(store, "alive", return_value=True):
            self.assertEqual(self.ns["tuner_status"]()["status"], "cancelling")
        # A state file that cannot be read does not keep the job from being stopped.
        self.ns["TUNER_STATE"].write_text("nope", encoding="utf-8")
        killpg = cancel()
        killpg.assert_called_once_with(4242, signal.SIGTERM)
        self.assertEqual(self.ns["TUNER_STATE"].read_text(encoding="utf-8"), "nope")
        # Nor does one that is missing (OSError) or of the wrong kind (ValueError): empty, not an object.
        for content in (None, "", "[]"):
            with self.subTest(state=content):
                self.ns["TUNER_STATE"].unlink(missing_ok=True)
                if content is not None:
                    self.ns["TUNER_STATE"].write_text(content, encoding="utf-8")
                killpg = cancel()
                killpg.assert_called_once_with(4242, signal.SIGTERM)
                if content is None:
                    self.assertFalse(self.ns["TUNER_STATE"].exists())
                else:
                    self.assertEqual(self.ns["TUNER_STATE"].read_text(encoding="utf-8"), content)

    def test_cancel_jobs_without_active_process(self):
        with self.assertRaisesRegex(RuntimeError, "активного подбора нет"):
            self.ns["cancel_tuner_job"]()

    def test_clear_previous_tuner_job(self):
        self.tuner.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        (self.tuner / "state.json").symlink_to(outside)
        (self.tuner / "events.log").write_text("x", encoding="utf-8")
        (self.tuner / "verdict.txt").write_text("yes\n", encoding="utf-8")
        (self.tuner / "other.txt").write_text("x", encoding="utf-8")
        self.ns["clear_previous_tuner_job"]()
        self.assertEqual(sorted(path.name for path in self.tuner.iterdir()), ["other.txt"])
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.assertEqual(self.tuner.stat().st_mode & 0o777, 0o700)
        (self.tuner / "runner.sh").mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге задания"):
            self.ns["clear_previous_tuner_job"]()

    def test_start_tuner_job_requires_zapret_route(self):
        self.patch(tuner_active=lambda: False)
        cases = [
            ({"ok": False, "code": 1, "output": "engine failed"}, "engine failed"),
            ({"ok": False, "code": 1, "output": ""}, "не удалось прочитать маршруты"),
            ({"ok": True, "code": 0, "output": "youtube_route=vless\n"}, "youtube использует route=vless"),
            ({"ok": True, "code": 0, "output": "discord_route=zapret\n"}, "youtube использует route=unknown"),
        ]
        settings = {"service": "youtube", "mix_level": "safe", "max_candidates": 8, "client_ip": "", "search_seed": 1}
        for payload, message in cases:
            with self.subTest(payload=payload):
                with self.patched(run_command=lambda *_a, payload=payload, **_k: payload):
                    with self.assertRaisesRegex(RuntimeError, message):
                        self.ns["start_tuner_job"](settings)
        self.assertFalse(self.tuner.exists())
        with self.patched(tuner_active=lambda: True):
            with self.assertRaisesRegex(RuntimeError, "подбор уже выполняется"):
                self.ns["start_tuner_job"](settings)


class TunerSourceTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        self.patch(
            FLOWSEAL_SOURCE_CACHE=self.root / "flowseal-sources.json",
            TUNER_JOB_DIR=self.root / "tuner",
            TUNER_PID=self.root / "tuner" / "panel-launch.pid",
            TUNER_STATE=self.root / "tuner" / "state.json",
        )

    def test_sources_before_download(self):
        self.assertEqual(
            self.ns["tuner_sources"](),
            {"ok": True, "status": "never_downloaded", "commit": "", "sources": []},
        )

    def test_sources_lists_services_per_file(self):
        module = mock.Mock()
        files = [mock.Mock(), mock.Mock()]
        files[0].name, files[1].name = "general (ALT3).bat", "General.bat"
        module.read_source_cache.return_value = (files, "c" * 40)
        module.source_services.side_effect = lambda source: (
            ["discord-tcp", "youtube"] if source.name == "General.bat" else ["discord-voice"]
        )
        with self.patched(flowseal_source_module=lambda: module):
            payload = self.ns["tuner_sources"]()
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["commit"], "c" * 40)
        self.assertEqual(
            payload["sources"],
            [
                {"name": "general (ALT3).bat", "services": ["discord-voice"]},
                {"name": "General.bat", "services": ["discord-tcp", "youtube"]},
            ],
        )

    def test_sources_report_corrupt_cache(self):
        module = mock.Mock()
        module.read_source_cache.side_effect = RuntimeError("invalid Flowseal cache")
        with self.patched(flowseal_source_module=lambda: module):
            payload = self.ns["tuner_sources"]()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["sources"], [])
        self.assertIn("invalid Flowseal cache", payload["error"])

    def test_concurrent_first_load_returns_the_complete_module(self):
        # Page load requests /api/updates and /api/tuner/sources at once. The
        # module sits in sys.modules while it still executes; a second request
        # thread must wait for it instead of using the half-loaded module.
        name = "xkeen_flowseal_sources"
        tuner = self.root / "tools" / "windows" / "zapret_tuner.py"
        tuner.parent.mkdir(parents=True)
        tuner.write_text(
            "import sys\n"
            "sys.kdn_flowseal_gate.wait(5)\n"
            "def read_source_cache(path):\n"
            "    return [], 'c' * 40\n",
            encoding="utf-8",
        )
        gate = threading.Event()
        sys.kdn_flowseal_gate = gate
        self.addCleanup(delattr, sys, "kdn_flowseal_gate")
        saved = sys.modules.pop(name, None)

        def restore():
            sys.modules.pop(name, None)
            if saved is not None:
                sys.modules[name] = saved

        self.addCleanup(restore)
        self.patch(PROJECT_DIR=self.root)
        complete = {}

        def load(key):
            complete[key] = hasattr(self.ns["flowseal_source_module"](), "read_source_cache")

        first = threading.Thread(target=load, args=("first",))
        first.start()
        deadline = time.monotonic() + 5
        while name not in sys.modules and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn(name, sys.modules)
        second = threading.Thread(target=load, args=("second",))
        second.start()
        second.join(0.2)
        gate.set()
        first.join(5)
        second.join(5)
        self.assertEqual(complete, {"first": True, "second": True})

    def test_learned_voice_endpoint(self):
        path = self.root / "discord-voice-endpoint.json"
        self.patch(VOICE_ENDPOINT_FILE=path, NFQWS_CONFIG=self.root / "nfqws2.conf")
        self.assertIsNone(self.ns["learned_voice_endpoint"]())
        path.write_text(json.dumps({"ip": "162.159.130.234", "port": 50007, "learned_utc": "2026-10-20T10:00:00Z"}), encoding="utf-8")
        self.assertEqual(
            self.ns["learned_voice_endpoint"](),
            {"ip": "162.159.130.234", "port": 50007, "learned_utc": "2026-10-20T10:00:00Z"},
        )
        for data in ({"ip": "192.168.2.1", "port": 50007}, {"ip": "162.159.130.234", "port": 443},
                     {"ip": "162.159.130.234", "port": "50007"}, {"ip": 5, "port": 50007},
                     {"ip": 2728362730, "port": 50007}, {"ip": "162.159.130.234", "port": 50101}):
            with self.subTest(data=data):
                path.write_text(json.dumps(data), encoding="utf-8")
                self.assertIsNone(self.ns["learned_voice_endpoint"]())

    def voice_endpoint(self, port, config=None):
        path = self.root / "discord-voice-endpoint.json"
        path.write_text(json.dumps({"ip": "162.159.130.234", "port": port}), encoding="utf-8")
        nfqws = self.root / "nfqws2.conf"
        if config is not None:
            nfqws.write_text(config, encoding="utf-8")
        self.patch(VOICE_ENDPOINT_FILE=path, NFQWS_CONFIG=nfqws)
        return self.ns["learned_voice_endpoint"]()

    def test_voice_endpoint_in_wide_range_is_accepted(self):
        endpoint = self.voice_endpoint(60000, "# Discord UDP: strategy=flowseal, range=wide.\n")
        self.assertEqual(endpoint["port"], 60000)
        self.assertEqual(endpoint["ip"], "162.159.130.234")

    def test_voice_endpoint_outside_narrow_range_is_rejected(self):
        self.assertIsNone(self.voice_endpoint(60000, "# Discord UDP: strategy=flowseal, range=narrow.\n"))

    def test_voice_endpoint_range_follows_recorded_config(self):
        for config, port, accepted in (
            (None, 50100, True),
            (None, 50101, False),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", 65535, True),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", 19344, True),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", 49999, False),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", 443, False),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", 3478, False),
            ("# Discord UDP: strategy=flowseal, range=narrow.\n", 50100, True),
        ):
            with self.subTest(config=config, port=port):
                (self.root / "nfqws2.conf").unlink(missing_ok=True)
                endpoint = self.voice_endpoint(port, config)
                self.assertEqual(endpoint is not None, accepted)

    def test_start_tuner_job_voice_auto(self):
        (self.root / "tuner").mkdir()
        status = {"ok": True, "code": 0, "output": "discord_voice_route=zapret\n"}
        settings = {
            "service": "discord-voice", "mix_level": "off", "max_candidates": 4,
            "client_ip": "192.168.2.60", "search_seed": 5, "source_file": None, "voice_auto": True,
        }
        process = mock.Mock(pid=4321)
        endpoint = self.root / "discord-voice-endpoint.json"
        self.patch(VOICE_ENDPOINT_FILE=endpoint, tuner_active=lambda: False,
                   run_command=lambda *_a, **_k: status)
        with self.assertRaisesRegex(RuntimeError, "голосовой сервер ещё не сохранён"):
            self.ns["start_tuner_job"](settings)
        endpoint.write_text(json.dumps({"ip": "162.159.130.234", "port": 50007}), encoding="utf-8")
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.ns["start_tuner_job"](settings)
        self.assertEqual(popen.call_args.args[0][-1], "--voice-auto")

    def test_start_tuner_job_passes_selected_source_file(self):
        (self.root / "tuner").mkdir()
        status = {"ok": True, "code": 0, "output": "discord_voice_route=zapret\n"}
        settings = {
            "service": "discord-voice",
            "mix_level": "off",
            "max_candidates": 8,
            "client_ip": "192.168.2.60",
            "search_seed": 5,
            "source_file": "general (ALT3).bat",
        }
        process = mock.Mock(pid=4321)
        with self.patched(tuner_active=lambda: False, run_command=lambda *_a, **_k: status), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.assertEqual(self.ns["start_tuner_job"](settings), 4321)
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--service") + 1], "discord-voice")
        self.assertEqual(command[command.index("--client-ip") + 1], "192.168.2.60")
        self.assertEqual(command[-2:], ["--source-file", "general (ALT3).bat"])
        # Without a file the option is not passed at all.
        with self.patched(tuner_active=lambda: False, run_command=lambda *_a, **_k: status), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.ns["start_tuner_job"]({**settings, "source_file": None})
        self.assertNotIn("--source-file", popen.call_args.args[0])

    def launch_tuner(self, settings, *, legacy_status=False, **options):
        """start_tuner_job of a youtube request, the engine's commands recorded; returns (commands, Popen mock)."""
        (self.root / "tuner").mkdir(exist_ok=True)
        engine = self.root / "apply-discord-nfqws2.sh"
        calls = []

        def run_command(command, timeout, *, env=None):
            calls.append({"command": list(command), "timeout": timeout})
            if command[-2:] == ['--status', '--json']:
                if legacy_status:
                    return {'ok': False, 'code': 2, 'output': 'unknown argument: --json'}
                return {'ok': True, 'code': 0, 'output': json.dumps({'schema': 1, 'text': 'youtube_route=zapret\n'}, indent=2)}
            return {"ok": True, "code": 0, "output": "youtube_route=zapret\n"}

        self.patch(ENGINE=engine, tuner_active=lambda: False, run_command=run_command)
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.assertEqual(self.ns["start_tuner_job"](settings, **options), 4321)
        return calls, popen

    def test_start_tuner_job_reads_the_route_with_the_engine_status(self):
        settings = {"service": "youtube", "mix_level": "safe", "max_candidates": 4, "client_ip": "", "search_seed": 1}
        calls, _popen = self.launch_tuner(settings)
        self.assertEqual(calls, [{"command": ["/bin/sh", str(self.root / "apply-discord-nfqws2.sh"), "--status", "--json"],
                                  "timeout": 40}])

    def test_start_tuner_job_keeps_legacy_status_fallback(self):
        settings = {"service": "youtube", "mix_level": "safe", "max_candidates": 4, "client_ip": "", "search_seed": 1}
        calls, _popen = self.launch_tuner(settings, legacy_status=True)
        self.assertEqual([call['command'][2:] for call in calls], [['--status', '--json'], ['--status']])
        self.assertEqual([call['timeout'] for call in calls], [40, 40])

    def test_start_tuner_job_passes_baseline_only_to_the_job(self):
        settings = {"service": "youtube", "mix_level": "safe", "max_candidates": 4, "client_ip": "", "search_seed": 1}
        for options, expected in (({}, False), ({"baseline_only": False}, False), ({"baseline_only": True}, True)):
            with self.subTest(options=options):
                _calls, popen = self.launch_tuner(settings, **options)
                self.assertIs("--baseline-only" in popen.call_args.args[0], expected)


class JobStartRaceTests(PanelUnitCase):
    """A job start must not overlap with another start still in progress."""

    def setUp(self):
        super().setUp()
        tuner = self.root / "tuner"
        diagnostics = self.root / "diagnostics"
        self.patch(
            TUNER_JOB_DIR=tuner,
            TUNER_PID=tuner / "panel-launch.pid",
            TUNER_STATE=tuner / "state.json",
            DIAGNOSTIC_JOB_DIR=diagnostics,
            DIAGNOSTIC_PID=diagnostics / "panel-launch.pid",
            DIAGNOSTIC_STATE=diagnostics / "state.json",
            DIAGNOSTIC_LOG=diagnostics / "process.log",
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
        )

    def test_slow_status_does_not_hold_start_lock_and_start_rechecks_idle(self):
        status_requested = threading.Event()
        release_status = threading.Event()

        def slow_status(*_args, **_kwargs):
            self.assertFalse(self.ns["JOB_START_LOCK"].locked())
            status_requested.set()
            release_status.wait(5)
            return {"ok": True, "code": 0, "output": "youtube_route=zapret\n"}

        settings = {
            "service": "youtube",
            "mix_level": "safe",
            "max_candidates": 4,
            "client_ip": "",
            "search_seed": 1,
            "source_file": None,
        }
        process = mock.Mock(pid=4321)
        errors = []
        running = {"diagnostic": False}
        real_thread = threading.Thread  # the panel's reaper thread is mocked below

        def first_start():
            try:
                self.ns["start_tuner_job"](settings)
            except Exception as exc:  # surfaced through the assertion below
                errors.append(exc)

        def launched(*args, **kwargs):
            running["diagnostic"] = True
            return process

        with self.patched(run_command=slow_status, diagnostic_active=lambda: running["diagnostic"]), \
                mock.patch.object(self.ns["subprocess"], "Popen", side_effect=launched) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            worker = real_thread(target=first_start)
            worker.start()
            self.assertTrue(status_requested.wait(5))
            try:
                self.assertFalse(self.ns["JOB_START_LOCK"].locked())
                self.ns["start_diagnostic_job"]("health")
            finally:
                release_status.set()
                worker.join(5)
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "сначала завершите диагностику")
        self.assertEqual(popen.call_count, 1)


if __name__ == "__main__":
    unittest.main()

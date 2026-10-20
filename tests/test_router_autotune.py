from __future__ import annotations

import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_panel_namespace():
    installer = (
        ROOT / "tools" / "router" / "xkeen_control_script.sh"
    ).read_text(encoding="utf-8")
    source = installer.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF\n", 1)[0]
    namespace = {"__name__": "panel_autotune_test"}
    exec(compile(source, "app.py", "exec"), namespace)
    return namespace


class FakeWriter:
    def __init__(self):
        self.payload = {}

    def write(self, **changes):
        self.payload.update(changes)

    def log(self, line):
        self.payload.setdefault("logs", []).append(line)


class RouterAutotuneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.job = load_module(
            "router_autotune_test_module",
            ROOT / "tools" / "router" / "zapret_autotune_job.py",
        )
        cls.panel = load_panel_namespace()
        cls.source = cls.job.tuner.SourceFile(
            "general (ALT11).bat",
            "",
            "fixture-sha",
            "https://example.invalid/general-alt11.bat",
        )

    def test_panel_request_validation(self):
        youtube = self.panel["validate_tuner_request"](
            {
                "service": "youtube",
                "mix_level": "safe",
                "max_candidates": 16,
                "client_ip": "",
            }
        )
        self.assertEqual(youtube["service"], "youtube")
        self.assertIsInstance(youtube["search_seed"], int)
        maximum = self.panel["validate_tuner_request"](
            {
                "service": "youtube",
                "mix_level": "extended",
                "max_candidates": 64,
                "client_ip": "",
            }
        )
        self.assertEqual(maximum["max_candidates"], 64)
        seeded = self.panel["validate_tuner_request"](
            {
                "service": "youtube",
                "mix_level": "safe",
                "max_candidates": 16,
                "client_ip": "",
                "search_seed": "123456",
            }
        )
        self.assertEqual(seeded["search_seed"], 123456)

        voice = self.panel["validate_tuner_request"](
            {
                "service": "discord-voice",
                "mix_level": "off",
                "max_candidates": 8,
                "client_ip": "192.168.2.50",
            }
        )
        self.assertEqual(voice["client_ip"], "192.168.2.50")

    def test_panel_rejects_unbounded_voice_and_unknown_fields(self):
        with self.assertRaises(ValueError):
            self.panel["validate_tuner_request"](
                {
                    "service": "discord-voice",
                    "mix_level": "safe",
                    "max_candidates": 16,
                    "client_ip": "8.8.8.8",
                }
            )
        with self.assertRaises(ValueError):
            self.panel["validate_tuner_request"](
                {"service": "youtube", "unexpected": "value"}
            )
        with self.assertRaises(ValueError):
            self.panel["validate_tuner_request"](
                {"service": "youtube", "max_candidates": 65}
            )
        with self.assertRaises(ValueError):
            self.panel["validate_tuner_request"](
                {"service": "youtube", "search_seed": "4294967296"}
            )

    def test_runner_events_update_state_and_select_allowlisted_candidate(self):
        candidates = [self.job.tuner.known_candidate("youtube", [self.source])]
        writer = FakeWriter()
        self.assertIsNone(
            self.job.parse_event(
                writer,
                f"EVENT|CANDIDATE|1|{candidates[0].candidate_id}",
                candidates,
            )
        )
        self.assertEqual(writer.payload["status"], "running")
        found = self.job.parse_event(
            writer,
            f"EVENT|FOUND|1|{candidates[0].candidate_id}",
            candidates,
        )
        self.assertEqual(found, candidates[0])

    def test_router_report_is_accepted_by_panel_import_gate(self):
        candidates = [self.job.tuner.known_candidate("youtube", [self.source])]
        args = self.job.build_parser().parse_args(
            [
                "--service",
                "youtube",
                "--job-id",
                "1234567890abcdef",
                "--search-seed",
                "123456",
            ]
        )
        report = self.job.make_report(
            args,
            "fixture-commit",
            candidates,
            candidates[0],
            ["EVENT|FOUND|1|fixture"],
        )
        profile = self.panel["validate_report"](report)
        self.assertEqual(profile["candidate_id"], candidates[0].candidate_id)
        self.assertEqual(profile["service"], "youtube")
        self.assertEqual(profile["report"]["search_seed"], 123456)

    def test_parameter_sweep_report_is_accepted_by_panel_import_gate(self):
        candidates = self.job.tuner.build_candidates(
            "youtube",
            [self.source],
            "extended",
        )
        found = next(
            candidate
            for candidate in candidates
            if "| sweep " in candidate.family
            and "out-range=-d4" in candidate.family
        )
        candidate = dataclasses.asdict(found)
        candidate["args"] = list(found.args)
        candidate["notes"] = list(found.notes)
        profile = self.panel["validate_candidate"](candidate, {})
        self.assertEqual(profile["candidate_id"], found.candidate_id)

    def test_job_has_no_xkeen_control_command(self):
        source = (
            ROOT / "tools" / "router" / "zapret_autotune_job.py"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "tools" / "windows" / "router-candidate-runner.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn('["xkeen"', source.lower())
        self.assertNotIn("xkeen -", runner.lower())
        self.assertNotIn("s05xkeen", runner.lower())

    def test_probe_details_preserve_failure_and_round(self):
        writer = FakeWriter()
        self.job.parse_event(writer,
            "EVENT|PROBE_DETAIL|2|confirm|2|metadata|200|0.25|1024|0|invalid-metadata|https://example.invalid/", [])
        detail = writer.payload["last_probe_detail"]
        self.assertEqual(detail["phase"], "confirm")
        self.assertEqual(detail["status"], "invalid-metadata")
        self.assertEqual(detail["bytes"], 1024)
        self.job.parse_event(writer, "EVENT|SUITE_RESULT|0|baseline|1|fail|1|4", [])
        self.assertEqual(writer.payload["baseline_result"]["candidate"], 0)
        self.assertEqual(writer.payload["baseline_result"]["verdict"], "fail")

    def test_voice_observation_does_not_claim_automatic_audio(self):
        writer = FakeWriter()
        line = "EVENT|VOICE_OBSERVATION|18|12|1"
        self.job.parse_event(writer, line, [])
        self.assertTrue(writer.payload["voice_observation"]["wan_match"])
        report = self.job.tuner.verification_report("discord-voice", [line])
        self.assertEqual(report["method"], "manual-duplex-voice")
        self.assertFalse(report["voice_audio_automatic"])


if __name__ == "__main__":
    unittest.main()

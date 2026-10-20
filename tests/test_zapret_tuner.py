import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest
import tempfile
import json
from unittest import mock


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "windows"
    / "zapret_tuner.py"
)
SPEC = importlib.util.spec_from_file_location("zapret_tuner", MODULE_PATH)
assert SPEC and SPEC.loader
TUNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TUNER
SPEC.loader.exec_module(TUNER)


SAMPLE = r"""@echo off
start winws.exe ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%ACTIVE_DISCORD_UDP.bin" --dpi-desync-repeats=6 --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=11 --dpi-desync-fake-tls=^!
"""


class TunerTests(unittest.TestCase):
    def setUp(self):
        self.source = TUNER.SourceFile(
            "general (ALT11).bat",
            SAMPLE,
            "abc123",
            "https://example.invalid/general-alt11.bat",
        )
        self.profiles = TUNER.parse_profiles(self.source)

    def test_profile_roles(self):
        roles = [TUNER.profile_roles(profile) for profile in self.profiles]
        self.assertIn("youtube-quic", roles[0])
        self.assertIn("discord-voice", roles[1])
        self.assertIn("youtube", roles[2])
        self.assertIn("discord-tcp", roles[3])

    def test_youtube_translation_is_allowlisted(self):
        candidate = TUNER.translate_tls_profile(self.profiles[2], "youtube")
        self.assertIsNotNone(candidate)
        joined = " ".join(candidate.args)
        self.assertIn("--lua-desync=fake:blob=tls_clienthello", joined)
        self.assertIn("--lua-desync=multisplit:pos=1:seqovl=681", joined)
        self.assertIn("tcp_ts_up", joined)
        TUNER.validate_args(candidate.args)

    def test_tls_mod_keeps_allowlisted_sni(self):
        self.assertEqual(
            TUNER.safe_tls_mod("rnd,dupsid,sni=www.google.com"),
            "rnd,dupsid,sni=www.google.com",
        )
        self.assertEqual(
            TUNER.safe_tls_mod("rnd,unsafe=one;touch"),
            "rnd,dupsid",
        )

    def test_voice_translation_uses_verified_blob(self):
        candidate = TUNER.translate_voice_profile(self.profiles[1])
        self.assertIsNotNone(candidate)
        self.assertIn(
            "--lua-desync=fake:blob=discord_udp:repeats=6",
            candidate.args,
        )

    def test_build_candidates_keeps_verified_first(self):
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "extended"
        )
        self.assertGreater(len(candidates), 2)
        self.assertEqual(candidates[0].rank, 0)
        self.assertIn("tcp_seq=10000", candidates[0].command_line())

    def test_randomized_selection_is_reproducible_by_seed(self):
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "extended"
        )
        first = TUNER.select_candidates(candidates, 8, 123456)
        repeated = TUNER.select_candidates(candidates, 8, 123456)
        other = TUNER.select_candidates(candidates, 8, 654321)
        first_ids = [candidate.candidate_id for candidate in first]
        self.assertEqual(
            first_ids,
            [candidate.candidate_id for candidate in repeated],
        )
        self.assertNotEqual(
            first_ids,
            [candidate.candidate_id for candidate in other],
        )
        self.assertNotEqual(
            set(first_ids),
            {candidate.candidate_id for candidate in other},
        )

    def test_randomized_selection_keeps_extended_candidates_last(self):
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "extended"
        )
        candidates.append(dataclasses.replace(candidates[0], rank=300))
        selected = TUNER.select_candidates(candidates, len(candidates), 42)
        extended_seen = False
        for candidate in selected:
            if candidate.rank >= TUNER.DEFERRED_RANK:
                extended_seen = True
            elif extended_seen:
                self.fail("primary candidate appeared after extended pool")

    def test_safe_sweep_changes_one_bounded_axis(self):
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "safe"
        )
        sweeps = [candidate for candidate in candidates if "| sweep " in candidate.family]
        self.assertTrue(
            any("--out-range=-d4" in candidate.args for candidate in sweeps)
        )
        self.assertTrue(
            any("pos=midsld" in candidate.command_line() for candidate in sweeps)
        )
        self.assertTrue(
            any("seqovl=5" in candidate.command_line() for candidate in sweeps)
        )
        self.assertTrue(
            any("youtube_quic:repeats=6" in candidate.command_line() for candidate in sweeps)
        )
        self.assertLessEqual(len(sweeps), 8)

    def test_extended_sweep_is_curated_not_full_cartesian(self):
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "extended"
        )
        sweeps = [candidate for candidate in candidates if "| sweep " in candidate.family]
        self.assertTrue(
            any("pos=sniext+1" in candidate.command_line() for candidate in sweeps)
        )
        self.assertTrue(
            any(
                "repeats=11" in candidate.command_line()
                and "--out-range=-d2" in candidate.args
                for candidate in sweeps
            )
        )
        self.assertLess(len(candidates), 80)

    def test_voice_sweep_covers_repeats_and_packet_range(self):
        candidates = TUNER.build_candidates(
            "discord-voice", [self.source], "extended"
        )
        commands = [candidate.command_line() for candidate in candidates]
        self.assertTrue(any("repeats=2" in command for command in commands))
        self.assertTrue(any("--out-range=<n4" in command for command in commands))
        self.assertTrue(
            any(
                "repeats=11" in command and "--out-range=<n3" in command
                for command in commands
            )
        )
        # Bounded: 8 repeats x 4 ranges plus the single-axis sweep and exact profiles.
        self.assertLessEqual(len(candidates), 48)

    def test_runner_has_no_unresolved_markers(self):
        template = MODULE_PATH.with_name("router-candidate-runner.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("broad-discord-ip-selector-is-active", template)
        self.assertIn(r"zkeenip\.dat:discord", template)
        candidates = TUNER.build_candidates(
            "youtube", [self.source], "safe"
        )[:3]
        rendered = TUNER.render_runner(
            template,
            service="youtube",
            candidates=candidates,
            client_ip="127.0.0.1",
            voice_duration=25,
            http_timeout=8,
        )
        self.assertNotIn("@@", rendered)
        self.assertIn("runtime-only", rendered)

    def test_recommendation_names_bat_and_router_variable(self):
        candidate = TUNER.build_candidates(
            "youtube", [self.source], "safe"
        )[0]
        output = TUNER.router_recommendation(candidate)
        self.assertIn("general (ALT11).bat", output)
        self.assertIn("NFQWS_ARGS_CUSTOM", output)
        self.assertIn("set-zapret-mode.sh", output)


class SourceCacheTests(unittest.TestCase):
    def test_corruption_or_invalid_replacement_keeps_previous_copy(self):
        source = TUNER.SourceFile("general.bat", "@echo off", "d" * 40, "https://example.invalid/general.bat")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            TUNER.save_source_cache(path, [source], "a" * 40)
            sources, commit = TUNER.read_source_cache(path)
            self.assertEqual(commit, "a" * 40)
            self.assertEqual(sources[0].text, source.text)
            before = path.read_bytes()
            with self.assertRaises(RuntimeError):
                TUNER.save_source_cache(path, [dataclasses.replace(source, name="../general.bat")], "b" * 40)
            self.assertEqual(before, path.read_bytes())
            bad = json.loads(before)
            bad["sources"][0]["text"] = "changed"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "corrupt"):
                TUNER.read_source_cache(path)

    def test_fetch_root_is_pinned_to_resolved_commit(self):
        commit = "a" * 40
        root = [{"name": "general.bat", "sha": "b" * 40,
                 "download_url": "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/" + commit + "/general.bat"}]
        with mock.patch.object(TUNER, "github_json", side_effect=[{"sha": commit}, root]) as api:
            with mock.patch.object(TUNER, "download_text", return_value="@echo off"):
                _sources, result = TUNER.fetch_sources(TUNER.DEFAULT_REPOSITORY, "main")
        self.assertEqual(result, commit)
        self.assertIn("ref=" + commit, api.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()

"""Characterization unit tests for tools/windows/zapret_tuner.py helpers.

These tests pin the current behaviour of small parsing, translation,
validation and I/O helpers. They never touch the network and only write
inside temporary directories.
"""

import argparse
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "windows"
    / "zapret_tuner.py"
)
SPEC = importlib.util.spec_from_file_location("zapret_tuner_units", MODULE_PATH)
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

SOURCE = TUNER.SourceFile(
    "general (ALT11).bat",
    SAMPLE,
    "abc123",
    "https://example.invalid/general-alt11.bat",
)


def make_profile(*options, number=1, source=SOURCE):
    """Build a Profile from (name, value) pairs without parsing a BAT."""
    return TUNER.Profile(source, number, tuple(options))


def make_cli_args(*argv):
    return TUNER.parser().parse_args(list(argv))


class FakeResponse:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, limit: int) -> bytes:
        return self.data[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class PortAndValueHelperTests(unittest.TestCase):
    def test_has_port_handles_ranges_blanks_and_garbage(self):
        value = "80,443-445, ,x-y"
        self.assertTrue(TUNER.has_port(value, 80))
        self.assertTrue(TUNER.has_port(value, 443))
        self.assertTrue(TUNER.has_port(value, 444))
        self.assertTrue(TUNER.has_port(value, 445))
        self.assertFalse(TUNER.has_port(value, 446))
        self.assertFalse(TUNER.has_port(value, 81))
        self.assertFalse(TUNER.has_port("x-y", 1))
        self.assertFalse(TUNER.has_port("", 443))
        self.assertFalse(TUNER.has_port("500-400", 450))
        self.assertTrue(TUNER.has_port(" 443 ", 443))

    def test_clean_value_strips_quotes_and_normalizes(self):
        self.assertEqual(TUNER.clean_value('  "C:\\bin\\x.bin"  '), "C:/bin/x.bin")
        self.assertEqual(TUNER.clean_value("^!"), "!")
        self.assertEqual(TUNER.clean_value('"'), '"')
        self.assertEqual(TUNER.clean_value('""'), "")
        self.assertEqual(TUNER.clean_value('"abc'), '"abc')

    def test_normalize_batch_joins_caret_continuations(self):
        text = "a ^\r\nb ^  \nc\rd ^!"
        self.assertEqual(TUNER.normalize_batch(text), "a  b  c\nd !")

    def test_basename_from_bat(self):
        self.assertEqual(TUNER.basename_from_bat("%BIN%Sub\\TLS.BIN"), "tls.bin")
        self.assertEqual(
            TUNER.basename_from_bat("%LISTS%list-general.txt"),
            "list-general.txt",
        )
        self.assertEqual(TUNER.basename_from_bat("a/b/C.txt"), "c.txt")
        self.assertEqual(TUNER.basename_from_bat(""), "")

    def test_safe_marker(self):
        self.assertEqual(TUNER.safe_marker("  sniext+1 ", "d"), "sniext+1")
        self.assertEqual(TUNER.safe_marker("1,midsld", "d"), "1,midsld")
        self.assertEqual(TUNER.safe_marker("1;rm -rf", "d"), "d")
        self.assertEqual(TUNER.safe_marker("a b", "d"), "d")
        self.assertEqual(TUNER.safe_marker("", "d"), "d")

    def test_safe_tls_mod(self):
        self.assertEqual(TUNER.safe_tls_mod(""), "")
        self.assertEqual(
            TUNER.safe_tls_mod("rnd,rndsni,dupsid,padencap,none"),
            "rnd,rndsni,dupsid,padencap,none",
        )
        self.assertEqual(TUNER.safe_tls_mod(" rnd , sni=a.b "), "rnd,sni=a.b")
        self.assertEqual(TUNER.safe_tls_mod("sni=bad_host"), "rnd,dupsid")
        self.assertEqual(TUNER.safe_tls_mod("rnd,"), "rnd,dupsid")


class BlobMappingTests(unittest.TestCase):
    def test_map_tls_blob_defaults(self):
        self.assertEqual(TUNER.map_tls_blob(""), ("fake_default_tls", None))
        self.assertEqual(TUNER.map_tls_blob("!"), ("fake_default_tls", None))

    def test_map_tls_blob_hex(self):
        self.assertEqual(TUNER.map_tls_blob("0x0A0b"), ("0x0A0b", None))
        self.assertEqual(
            TUNER.map_tls_blob("0xZZ"),
            ("fake_default_tls", "invalid hex fake replaced"),
        )
        self.assertEqual(
            TUNER.map_tls_blob("0x"),
            ("fake_default_tls", "invalid hex fake replaced"),
        )

    def test_map_tls_blob_files(self):
        self.assertEqual(
            TUNER.map_tls_blob("%BIN%tls_clienthello_www_google_com.bin"),
            ("tls_clienthello", None),
        )
        self.assertEqual(
            TUNER.map_tls_blob("%BIN%stun.bin"),
            ("tls_clienthello", "stun.bin substituted with router Google TLS blob"),
        )
        self.assertEqual(
            TUNER.map_tls_blob("something"),
            ("fake_default_tls", "unsupported fake 'something' replaced"),
        )

    def test_map_pattern_blob(self):
        self.assertEqual(TUNER.map_pattern_blob(""), ("tls_clienthello", None))
        self.assertEqual(TUNER.map_pattern_blob("0xAB"), ("0xAB", None))
        self.assertEqual(
            TUNER.map_pattern_blob("0xZZ"),
            ("tls_clienthello", "0xzz substituted with router Google TLS blob"),
        )
        self.assertEqual(
            TUNER.map_pattern_blob("%BIN%tls_clienthello_www_google_com.bin"),
            ("tls_clienthello", None),
        )
        self.assertEqual(
            TUNER.map_pattern_blob("%BIN%Foo.bin"),
            ("tls_clienthello", "foo.bin substituted with router Google TLS blob"),
        )


class ProfileParsingTests(unittest.TestCase):
    def test_profile_accessors(self):
        profile = make_profile(
            ("filter-tcp", "443"),
            ("dpi-desync-fooling", "ts"),
            ("dpi-desync-fooling", "badseq"),
            ("flag", None),
        )
        self.assertEqual(profile.values("DPI-DESYNC-FOOLING"), ["ts", "badseq"])
        self.assertEqual(profile.last("dpi-desync-fooling"), "badseq")
        self.assertEqual(profile.last("missing", "dflt"), "dflt")
        self.assertEqual(profile.values("flag"), [])
        self.assertTrue(profile.has("FLAG"))
        self.assertFalse(profile.has("missing"))

    def test_parse_profiles_skips_leading_and_repeated_new(self):
        source = TUNER.SourceFile(
            "general.bat",
            '--new --filter-tcp=443 --Hostlist="%LISTS%x.txt" --flag --new --new '
            "--filter-udp=443",
            "",
            "",
        )
        profiles = TUNER.parse_profiles(source)
        self.assertEqual([profile.number for profile in profiles], [1, 2])
        self.assertEqual(
            profiles[0].options,
            (("filter-tcp", "443"), ("hostlist", "%LISTS%x.txt"), ("flag", None)),
        )
        self.assertEqual(profiles[1].options, (("filter-udp", "443"),))
        self.assertEqual(
            TUNER.parse_profiles(TUNER.SourceFile("e.bat", "@echo off", "", "")),
            [],
        )

    def test_profile_roles_for_hostlist_domains(self):
        on_80 = make_profile(
            ("filter-tcp", "80"),
            ("hostlist-domains", "Discord.Media"),
        )
        self.assertEqual(TUNER.profile_roles(on_80), {"discord-tcp"})
        on_443 = make_profile(
            ("filter-tcp", "443"),
            ("hostlist-domains", "discord.media"),
        )
        self.assertEqual(TUNER.profile_roles(on_443), {"discord-tcp"})
        unrelated = make_profile(("filter-tcp", "80"))
        self.assertEqual(TUNER.profile_roles(unrelated), set())
        stun = make_profile(("filter-udp", "3478"), ("filter-l7", "STUN"))
        self.assertEqual(TUNER.profile_roles(stun), {"discord-voice"})
        quic_without_fake = make_profile(("filter-udp", "443"))
        self.assertEqual(TUNER.profile_roles(quic_without_fake), set())


class FoolingTests(unittest.TestCase):
    def test_many_foolings_with_invalid_increment(self):
        profile = make_profile(
            ("dpi-desync-fooling", "ts,md5sig,BADSUM"),
            ("dpi-desync-fooling", "datanoack, badseq,autottl,hopbyhop"),
            ("dpi-desync-badseq-increment", "abc"),
        )
        params, notes = TUNER.fooling_params(profile)
        self.assertEqual(
            params,
            [
                "tcp_ts_up",
                "tcp_md5",
                "badsum",
                "tcp_flags_unset=ack",
                "tcp_seq=-10000",
            ],
        )
        self.assertEqual(
            notes,
            [
                "invalid badseq increment replaced with -10000",
                "ignored fooling: autottl,hopbyhop",
            ],
        )

    def test_badseq_increment_valid_and_default(self):
        explicit = make_profile(
            ("dpi-desync-fooling", "badseq"),
            ("dpi-desync-badseq-increment", "-5"),
        )
        self.assertEqual(TUNER.fooling_params(explicit), (["tcp_seq=-5"], []))
        default = make_profile(("dpi-desync-fooling", "badseq"))
        self.assertEqual(TUNER.fooling_params(default), (["tcp_seq=-10000"], []))
        self.assertEqual(TUNER.fooling_params(make_profile()), ([], []))

    def test_lua_function_drops_empty_params(self):
        self.assertEqual(
            TUNER.lua_function("fake", ["blob=x", "", "repeats=2"]),
            "--lua-desync=fake:blob=x:repeats=2",
        )
        self.assertEqual(TUNER.lua_function("fake", []), "--lua-desync=fake")


class TlsTranslationTests(unittest.TestCase):
    def test_unsupported_or_empty_chain_returns_none(self):
        self.assertIsNone(
            TUNER.translate_tls_profile(
                make_profile(("dpi-desync", "fake,syndata")), "youtube"
            )
        )
        self.assertIsNone(
            TUNER.translate_tls_profile(make_profile(), "youtube")
        )
        self.assertIsNone(
            TUNER.translate_tls_profile(
                make_profile(("dpi-desync", " , ")), "youtube"
            )
        )

    def test_fakedsplit_with_pattern_and_fooling(self):
        profile = make_profile(
            ("dpi-desync", "fakedsplit"),
            ("dpi-desync-split-pos", "2"),
            ("dpi-desync-fakedsplit-pattern", "%BIN%stun.bin"),
            ("dpi-desync-fooling", "md5sig"),
            number=3,
        )
        candidate = TUNER.translate_tls_profile(profile, "discord-tcp")
        self.assertIsNotNone(candidate)
        self.assertEqual(
            candidate.args,
            (
                "--filter-tcp=443",
                "--filter-l7=tls",
                "--hostlist=/opt/etc/nfqws2/lists/user.list",
                "--out-range=-d10",
                "--payload=tls_client_hello",
                "--lua-desync=fakedsplit:pos=2:pattern=tls_clienthello:tcp_md5",
            ),
        )
        self.assertEqual(candidate.family, "fakedsplit")
        self.assertEqual(candidate.rank, 103)
        self.assertEqual(candidate.service, "discord-tcp")
        self.assertEqual(
            candidate.notes,
            ("stun.bin substituted with router Google TLS blob",),
        )

    def test_fakedsplit_without_pattern_uses_default_position(self):
        profile = make_profile(("dpi-desync", "fakedsplit"))
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(candidate.args[-1], "--lua-desync=fakedsplit:pos=midsld")
        self.assertIn("--hostlist=/opt/etc/nfqws2/lists/youtube.list", candidate.args)

    def test_hostfakesplit_host_modifier(self):
        profile = make_profile(
            ("dpi-desync", "hostfakesplit"),
            ("dpi-desync-hostfakesplit-mod", "altorder=1,host=www.google.com"),
            ("dpi-desync-fooling", "ts"),
        )
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(
            candidate.args[-1],
            "--lua-desync=hostfakesplit:host=www.google.com:tcp_ts_up",
        )
        no_host = make_profile(
            ("dpi-desync", "hostfakesplit"),
            ("dpi-desync-hostfakesplit-mod", "altorder=1"),
        )
        self.assertEqual(
            TUNER.translate_tls_profile(no_host, "youtube").args[-1],
            "--lua-desync=hostfakesplit",
        )

    def test_fake_and_multidisorder_options(self):
        profile = make_profile(
            ("dpi-desync", "FAKE,multidisorder"),
            ("dpi-desync-repeats", "x"),
            ("dpi-desync-fake-tls", "%BIN%a.bin"),
            ("dpi-desync-fake-tls", "0xZZ"),
            ("dpi-desync-fake-tls-mod", "none"),
            ("dpi-desync-split-pos", "1;rm"),
        )
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(
            candidate.args[-2:],
            (
                "--lua-desync=fake:blob=fake_default_tls",
                "--lua-desync=multidisorder:pos=midsld",
            ),
        )
        self.assertEqual(candidate.family, "fake+multidisorder")
        self.assertEqual(
            candidate.notes,
            (
                "invalid hex fake replaced",
                "multiple BAT fake replacements collapsed to the last TLS fake",
            ),
        )

    def test_fake_tls_mod_is_sanitized(self):
        profile = make_profile(
            ("dpi-desync", "fake"),
            ("dpi-desync-repeats", "4"),
            ("dpi-desync-fake-tls-mod", "rnd,evil"),
        )
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(
            candidate.args[-1],
            "--lua-desync=fake:blob=fake_default_tls:repeats=4:tls_mod=rnd,dupsid",
        )

    def test_multisplit_without_numeric_seqovl_has_no_pattern(self):
        profile = make_profile(
            ("dpi-desync", "multisplit"),
            ("dpi-desync-split-seqovl", "abc"),
            ("dpi-desync-split-seqovl-pattern", "%BIN%stun.bin"),
        )
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(candidate.args[-1], "--lua-desync=multisplit:pos=midsld")
        self.assertEqual(candidate.notes, ())

    def test_duplicate_notes_are_collapsed(self):
        profile = make_profile(
            ("dpi-desync", "multisplit,fakedsplit"),
            ("dpi-desync-split-seqovl", "2"),
            ("dpi-desync-split-seqovl-pattern", "%BIN%stun.bin"),
            ("dpi-desync-fakedsplit-pattern", "%BIN%stun.bin"),
        )
        candidate = TUNER.translate_tls_profile(profile, "youtube")
        self.assertEqual(
            candidate.notes,
            ("stun.bin substituted with router Google TLS blob",),
        )


class VoiceTranslationTests(unittest.TestCase):
    def test_non_fake_chain_returns_none(self):
        self.assertIsNone(
            TUNER.translate_voice_profile(make_profile(("dpi-desync", "fake,split")))
        )
        self.assertIsNone(TUNER.translate_voice_profile(make_profile()))

    def test_bad_repeats_and_unsafe_ports_use_defaults(self):
        profile = make_profile(
            ("dpi-desync", "fake"),
            ("dpi-desync-repeats", "many"),
            ("filter-udp", "443;x"),
            ("dpi-desync-fake-stun", "%BIN%stun.bin"),
            number=4,
        )
        candidate = TUNER.translate_voice_profile(profile)
        self.assertEqual(
            candidate.args,
            (
                "--filter-udp=443,3478-3481,5349,19294-19344,50000-50100",
                "--filter-l7=stun,discord",
                "--out-range=<n2",
                "--payload=stun,discord_ip_discovery",
                "--lua-desync=fake:blob=discord_udp:repeats=6",
            ),
        )
        self.assertEqual(candidate.service, "discord-voice")
        self.assertEqual(candidate.family, "fake-udp")
        self.assertEqual(candidate.rank, 104)
        self.assertEqual(
            candidate.notes,
            ("BAT UDP fake substituted with verified ACTIVE_DISCORD_UDP.bin",),
        )

    def test_verified_blob_and_custom_ports(self):
        profile = make_profile(
            ("dpi-desync", "fake"),
            ("filter-udp", "50000-50100"),
            ("dpi-desync-repeats", "3"),
            ("dpi-desync-fake-discord", "%BIN%ACTIVE_DISCORD_UDP.bin"),
        )
        candidate = TUNER.translate_voice_profile(profile)
        self.assertEqual(candidate.args[0], "--filter-udp=50000-50100")
        self.assertEqual(
            candidate.args[-1], "--lua-desync=fake:blob=discord_udp:repeats=3"
        )
        self.assertEqual(candidate.notes, ())

    def test_youtube_quic_for_source(self):
        self.assertEqual(
            TUNER.youtube_quic_for_source([]), ("--new", *TUNER.NATIVE_QUIC)
        )
        quic = make_profile(
            ("filter-udp", "443"),
            ("dpi-desync-fake-quic", "%BIN%q.bin"),
            ("dpi-desync-repeats", "abc"),
        )
        self.assertEqual(
            TUNER.youtube_quic_for_source([make_profile(("filter-tcp", "80")), quic])[-1],
            "--lua-desync=fake:blob=youtube_quic:repeats=6",
        )


class CandidateHelperTests(unittest.TestCase):
    def test_validate_args(self):
        TUNER.validate_args(["--new", "--filter-tcp=443", "--out-range=<n2"])
        for token in ("--filter-tcp=443;id", "--flag", "--Upper=1", "plain", "--x= y"):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    TUNER.validate_args([token])

    def test_make_candidate_id_is_stable_sha_prefix(self):
        args = ("--filter-tcp=443",)
        candidate = TUNER.make_candidate(
            service="youtube", source=SOURCE, family="f", args=args, rank=5
        )
        expected = hashlib.sha256(
            "\n".join(("youtube", SOURCE.name, "f", *args)).encode("utf-8")
        ).hexdigest()[:12]
        self.assertEqual(candidate.candidate_id, expected)
        self.assertEqual(candidate.source_sha, "abc123")
        self.assertEqual(candidate.command_line(), "--filter-tcp=443")
        with self.assertRaises(ValueError):
            TUNER.make_candidate(
                service="youtube", source=SOURCE, family="f", args=("bad",), rank=5
            )

    def test_known_candidate_variants(self):
        builtin = TUNER.known_candidate("youtube", [])
        self.assertEqual(builtin.source_name, "built-in")
        self.assertEqual(builtin.rank, 0)
        self.assertIn("--new", builtin.args)
        other = TUNER.SourceFile("general.bat", "", "s", "u")
        alt = TUNER.SourceFile("GENERAL (ALT11).BAT", "", "s2", "u2")
        self.assertEqual(
            TUNER.known_candidate("discord-tcp", [other, alt]).source_name,
            "GENERAL (ALT11).BAT",
        )
        tcp = TUNER.known_candidate("discord-tcp", [other])
        self.assertEqual(tcp.source_name, "general.bat")
        self.assertNotIn("--new", tcp.args)
        self.assertIn("--hostlist=/opt/etc/nfqws2/lists/user.list", tcp.args)
        voice = TUNER.known_candidate("discord-voice", [other])
        self.assertEqual(voice.family, "Flowseal ACTIVE_DISCORD_UDP")
        self.assertEqual(voice.args[-1], "--lua-desync=fake:blob=discord_udp:repeats=6")

    def test_split_components_for_discord_tcp(self):
        native = TUNER.known_candidate("discord-tcp", [SOURCE])
        base, fake, split = TUNER.split_components(native)
        self.assertEqual(fake, TUNER.NATIVE_FAKE)
        self.assertEqual(split, TUNER.NATIVE_SPLIT)
        self.assertEqual(
            base,
            [
                "--filter-tcp=443",
                "--filter-l7=tls",
                "--hostlist=/opt/etc/nfqws2/lists/user.list",
                "--out-range=-d10",
                "--payload=tls_client_hello",
            ],
        )
        voice = TUNER.known_candidate("discord-voice", [SOURCE])
        _base, _fake, voice_split = TUNER.split_components(voice)
        self.assertIsNone(voice_split)

    def test_candidate_source_rebuilds_metadata(self):
        native = TUNER.known_candidate("discord-tcp", [SOURCE])
        self.assertEqual(
            TUNER.candidate_source(native),
            TUNER.SourceFile(SOURCE.name, "", SOURCE.sha, SOURCE.url),
        )


class ArgsEditingTests(unittest.TestCase):
    ARGS = (
        "--filter-tcp=443",
        "--out-range=-d10",
        "--lua-desync=fake:blob=x:repeats=6",
        "--lua-desync=multisplit:pos=1",
        "--new",
        "--filter-udp=443",
        "--out-range=-d10",
        "--lua-desync=fake:blob=q:repeats=11",
    )

    def test_profile_section(self):
        self.assertEqual(TUNER.profile_section(["a", "b"], "tcp"), (0, 2))
        self.assertEqual(TUNER.profile_section(["a", "b"], "udp"), (0, 0))
        self.assertEqual(TUNER.profile_section(["a", "b"], "all"), (0, 2))
        self.assertEqual(TUNER.profile_section(["a", "--new", "b"], "tcp"), (0, 1))
        self.assertEqual(TUNER.profile_section(["a", "--new", "b"], "udp"), (2, 3))
        self.assertEqual(TUNER.profile_section(["a", "--new", "b"], "all"), (0, 3))
        self.assertEqual(TUNER.profile_section(["a", "--new", "b"], "bogus"), (0, 0))
        self.assertEqual(TUNER.profile_section(["a", "--new"], "udp"), (2, 2))

    def test_replace_profile_option(self):
        self.assertIsNone(
            TUNER.replace_profile_option(self.ARGS, "--out-range=", "-d10", section="tcp")
        )
        self.assertIsNone(
            TUNER.replace_profile_option(self.ARGS, "--missing=", "1", section="all")
        )
        self.assertIsNone(
            TUNER.replace_profile_option(self.ARGS, "--out-range=", "-d4", section="bogus")
        )
        changed = TUNER.replace_profile_option(
            self.ARGS, "--out-range=", "-d4", section="tcp"
        )
        self.assertEqual(changed[1], "--out-range=-d4")
        self.assertEqual(changed[6], "--out-range=-d10")
        udp = TUNER.replace_profile_option(
            self.ARGS, "--out-range=", "-d4", section="udp"
        )
        self.assertEqual(udp[1], "--out-range=-d10")
        self.assertEqual(udp[6], "--out-range=-d4")
        self.assertIsInstance(changed, tuple)

    def test_replace_lua_parameter(self):
        self.assertIsNone(
            TUNER.replace_lua_parameter(
                self.ARGS, {"fake"}, "repeats", "6", section="tcp"
            )
        )
        self.assertIsNone(
            TUNER.replace_lua_parameter(
                self.ARGS, {"hostfakesplit"}, "repeats", "6", section="all"
            )
        )
        replaced = TUNER.replace_lua_parameter(
            self.ARGS, {"fake"}, "repeats", "2", section="tcp"
        )
        self.assertEqual(replaced[2], "--lua-desync=fake:blob=x:repeats=2")
        self.assertEqual(replaced[7], self.ARGS[7])
        udp = TUNER.replace_lua_parameter(
            self.ARGS, {"fake"}, "repeats", "3", section="udp"
        )
        self.assertEqual(udp[2], self.ARGS[2])
        self.assertEqual(udp[7], "--lua-desync=fake:blob=q:repeats=3")
        appended = TUNER.replace_lua_parameter(
            self.ARGS, {"fake"}, "tcp_seq", "-1", section="tcp"
        )
        self.assertEqual(appended[2], "--lua-desync=fake:blob=x:repeats=6:tcp_seq=-1")

    def test_replace_lua_parameter_required_companion(self):
        added = TUNER.replace_lua_parameter(
            self.ARGS,
            {"multisplit"},
            "seqovl",
            "5",
            section="tcp",
            required_companion=("seqovl_pattern", "tls_clienthello"),
        )
        self.assertEqual(
            added[3],
            "--lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=tls_clienthello",
        )
        existing = (
            "--lua-desync=multisplit:pos=1:seqovl=1:seqovl_pattern=custom",
        )
        kept = TUNER.replace_lua_parameter(
            existing,
            {"multisplit"},
            "seqovl",
            "5",
            section="tcp",
            required_companion=("seqovl_pattern", "tls_clienthello"),
        )
        self.assertEqual(
            kept, ("--lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=custom",)
        )

    def test_mutate_tls_recipe(self):
        self.assertIsNone(TUNER.mutate_tls_recipe(self.ARGS))
        self.assertIsNone(
            TUNER.mutate_tls_recipe(self.ARGS, out_range="-d10", repeats="6")
        )
        self.assertIsNone(TUNER.mutate_tls_recipe(self.ARGS, quic_repeats="11"))
        no_split = ("--filter-tcp=443", "--lua-desync=fake:blob=x")
        self.assertIsNone(TUNER.mutate_tls_recipe(no_split, seqovl="5", position="2"))
        changed = TUNER.mutate_tls_recipe(
            self.ARGS,
            out_range="-d4",
            repeats="6",
            tcp_seq="-10000",
            position="midsld",
            seqovl="5",
            quic_repeats="3",
        )
        self.assertEqual(
            changed,
            (
                "--filter-tcp=443",
                "--out-range=-d4",
                "--lua-desync=fake:blob=x:repeats=6:tcp_seq=-10000",
                "--lua-desync=multisplit:pos=midsld:seqovl=5:"
                "seqovl_pattern=tls_clienthello",
                "--new",
                "--filter-udp=443",
                "--out-range=-d10",
                "--lua-desync=fake:blob=q:repeats=3",
            ),
        )

    def test_add_sweep_candidate_skips_unchanged(self):
        native = TUNER.known_candidate("discord-tcp", [SOURCE])
        result = []
        TUNER.add_sweep_candidate(result, native, None, "x", 1)
        TUNER.add_sweep_candidate(result, native, native.args, "x", 1)
        self.assertEqual(result, [])
        changed = TUNER.mutate_tls_recipe(native.args, out_range="-d4")
        TUNER.add_sweep_candidate(result, native, changed, "range", 7)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].family, native.family + " | sweep range")
        self.assertEqual(result[0].rank, 7)
        self.assertEqual(result[0].notes[-1], "curated parameter sweep: range")
        self.assertEqual(result[0].source_name, SOURCE.name)


class CandidateBuildingTests(unittest.TestCase):
    def test_off_level_produces_no_sweeps_or_mixes(self):
        self.assertEqual(
            TUNER.parameter_sweep_candidates("youtube", [], [SOURCE], "off"), []
        )
        self.assertEqual(TUNER.mixed_candidates("youtube", [], [SOURCE], "off"), [])
        self.assertEqual(
            TUNER.mixed_candidates("discord-voice", [], [SOURCE], "extended"), []
        )

    def test_voice_safe_sweep_is_five_variants(self):
        sweeps = TUNER.parameter_sweep_candidates(
            "discord-voice", [], [SOURCE], "safe"
        )
        self.assertEqual(
            [candidate.family.split("| sweep ")[1] for candidate in sweeps],
            [
                "voice repeats=2",
                "voice repeats=3",
                "voice repeats=11",
                "voice out-range=<n3",
                "voice out-range=<n4",
            ],
        )
        self.assertEqual([candidate.rank for candidate in sweeps], [20, 21, 22, 23, 24])

    def test_off_build_contains_known_and_exact_only(self):
        candidates = TUNER.build_candidates("discord-tcp", [SOURCE], "off")
        self.assertEqual(candidates[0].rank, 0)
        self.assertTrue(all("| sweep " not in c.family for c in candidates))
        self.assertTrue(all(c.rank < 140 for c in candidates))
        self.assertEqual(len({c.args for c in candidates}), len(candidates))
        ranks = [c.rank for c in candidates]
        self.assertEqual(ranks, sorted(ranks))

    def test_select_candidates(self):
        candidates = TUNER.build_candidates("discord-tcp", [SOURCE], "safe")
        extended = dataclasses.replace(candidates[0], candidate_id="ext", rank=250)
        pool = [*candidates, extended]
        with self.assertRaises(ValueError):
            TUNER.select_candidates(pool, 0, 1)
        first = TUNER.select_candidates(pool, 3, 7)
        self.assertEqual(len(first), 3)
        self.assertEqual(
            [c.candidate_id for c in first],
            [c.candidate_id for c in TUNER.select_candidates(pool, 3, 7)],
        )
        everything = TUNER.select_candidates(pool, 1000, 7)
        self.assertEqual(len(everything), len(pool))
        self.assertEqual(everything[-1].candidate_id, "ext")
        self.assertEqual(
            sorted(c.candidate_id for c in everything),
            sorted(c.candidate_id for c in pool),
        )

    def test_resolve_search_seed(self):
        self.assertEqual(TUNER.resolve_search_seed(5), 5)
        self.assertEqual(TUNER.resolve_search_seed(0), 0)
        with mock.patch.object(TUNER.secrets, "randbits", return_value=99) as bits:
            self.assertEqual(TUNER.resolve_search_seed(None), 99)
        bits.assert_called_once_with(32)

    def test_parse_search_seed(self):
        self.assertEqual(TUNER.parse_search_seed("0"), 0)
        self.assertEqual(TUNER.parse_search_seed("4294967295"), 4294967295)
        for value in ("abc", "1.5", "", "-1", "4294967296", "0x10"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    TUNER.parse_search_seed(value)


class RunnerRenderingTests(unittest.TestCase):
    def test_candidate_data_is_numbered_base64(self):
        native = TUNER.known_candidate("discord-voice", [SOURCE])
        data = TUNER.candidate_data([native, native])
        lines = data.split("\n")
        self.assertEqual(len(lines), 2)
        number, candidate_id, encoded = lines[1].split("|")
        self.assertEqual(number, "2")
        self.assertEqual(candidate_id, native.candidate_id)
        import base64

        self.assertEqual(base64.b64decode(encoded).decode("utf-8"), native.command_line())
        self.assertEqual(TUNER.candidate_data([]), "")

    def test_render_runner_replaces_markers_and_rejects_unknown(self):
        template = "@@SERVICE@@ @@CLIENT_IP@@ @@VOICE_DURATION@@ @@HTTP_TIMEOUT@@ @@MIN_HTTP_SUCCESS@@\n@@CANDIDATE_DATA@@"
        rendered = TUNER.render_runner(
            template,
            service="youtube",
            candidates=[],
            client_ip="10.0.0.2",
            voice_duration=30,
            http_timeout=9,
        )
        self.assertEqual(rendered, "youtube 10.0.0.2 30 9 3\n")
        with self.assertRaisesRegex(RuntimeError, "unresolved"):
            TUNER.render_runner(
                template + "@@OTHER@@",
                service="youtube",
                candidates=[],
                client_ip="10.0.0.2",
                voice_duration=30,
                http_timeout=9,
            )


class ProbeEventTests(unittest.TestCase):
    def test_parse_probe_event_keeps_pipes_in_url(self):
        line = (
            "EVENT|PROBE_DETAIL|2|confirm|3|metadata|200|0.25|1024.7|0|ok|"
            "https://example.invalid/a?x=1|y"
        )
        self.assertEqual(
            TUNER.parse_probe_event(line),
            {
                "candidate": 2,
                "phase": "confirm",
                "round": 3,
                "role": "metadata",
                "http_code": "200",
                "seconds": 0.25,
                "bytes": 1024,
                "exit_code": 0,
                "status": "ok",
                "url": "https://example.invalid/a?x=1|y",
            },
        )

    def test_parse_probe_event_truncates_url(self):
        line = "EVENT|PROBE_DETAIL|1|p|1|r|000|1|0|7|timeout|" + "u" * 600
        self.assertEqual(len(TUNER.parse_probe_event(line)["url"]), 500)

    def test_parse_probe_event_rejects_malformed(self):
        for line in (
            "EVENT|PROBE_DETAIL|x|p|1|r|200|0.1|1|0|ok|u",
            "EVENT|PROBE_DETAIL|1|p|1|r|200|fast|1|0|ok|u",
            "EVENT|PROBE_DETAIL|1|p|1|r|200|0.1|1|0|ok",
            "EVENT|PROBE|1|p|1|r|200|0.1|1|0|ok|u",
            "NOISE|PROBE_DETAIL|1|p|1|r|200|0.1|1|0|ok|u",
            "",
        ):
            with self.subTest(line=line):
                self.assertIsNone(TUNER.parse_probe_event(line))

    def test_verification_report(self):
        output = [
            "EVENT|PROBE_DETAIL|1|p|1|r|200|0.1|1|0|ok|u",
            "EVENT|PROBE_DETAIL|bad",
            "EVENT|SUITE_RESULT|1|confirm|1|pass|4|4",
            "EVENT|VOICE_OBSERVATION|1|2|1",
            "noise",
        ]
        report = TUNER.verification_report("youtube", output)
        self.assertEqual(report["method"], "router-http-content-two-rounds")
        self.assertFalse(report["quic_verified"])
        self.assertFalse(report["video_playback_verified"])
        self.assertEqual(len(report["probes"]), 1)
        self.assertEqual(report["suite_results"], [output[2]])
        self.assertEqual(report["voice_observations"], [output[3]])


class RecommendationTests(unittest.TestCase):
    def test_router_recommendation_per_service(self):
        expectations = {
            "youtube": ("NFQWS_ARGS_CUSTOM", "YouTube only: sh set-zapret-mode.sh youtube"),
            "discord-voice": ("NFQWS_ARGS_UDP", "Discord only: sh set-zapret-mode.sh discord"),
            "discord-tcp": (
                'NFQWS_ARGS (with NFQWS_EXTRA_ARGS="$MODE_LIST")',
                "Discord only: sh set-zapret-mode.sh discord",
            ),
        }
        for service, (variable, route) in expectations.items():
            with self.subTest(service=service):
                candidate = TUNER.known_candidate(service, [SOURCE])
                output = TUNER.router_recommendation(candidate)
                self.assertIn(f"Рекомендуемое значение {variable}:", output)
                self.assertIn(route, output)
                self.assertIn("Both services: sh set-zapret-mode.sh both", output)
                self.assertIn("Git blob SHA: abc123", output)
                self.assertIn("-----\n" + "\n".join(candidate.args) + "\n-----", output)
        builtin = TUNER.known_candidate("youtube", [])
        self.assertIn("Git blob SHA: built-in", TUNER.router_recommendation(builtin))

    def test_print_candidate(self):
        candidate = TUNER.known_candidate("discord-tcp", [SOURCE])
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            TUNER.print_candidate(candidate, 3)
            TUNER.print_candidate(dataclasses.replace(candidate, notes=()))
        lines = stream.getvalue().splitlines()
        self.assertEqual(
            lines[0],
            f"03. {SOURCE.name} | {candidate.family} | id={candidate.candidate_id}",
        )
        self.assertEqual(lines[1], "    current known-good TCP family")
        self.assertEqual(
            lines[2], f"{SOURCE.name} | {candidate.family} | id={candidate.candidate_id}"
        )
        self.assertEqual(len(lines), 3)


class CliTests(unittest.TestCase):
    def test_ssh_command_defaults(self):
        args = argparse.Namespace(
            ssh="ssh", ssh_key=None, ssh_port=22, user="root", router="192.168.2.1"
        )
        command = TUNER.ssh_command(args)
        self.assertEqual(command[:2], ["ssh", "-T"])
        self.assertIn("StrictHostKeyChecking=accept-new", command)
        self.assertNotIn("-i", command)
        self.assertNotIn("-p", command)
        self.assertEqual(command[-2], "root@192.168.2.1")
        self.assertIn("base64 -d", command[-1])
        self.assertIn("trap 'rm -f \"$f\"' EXIT HUP INT TERM", command[-1])

    def test_ssh_command_key_and_port(self):
        args = argparse.Namespace(
            ssh="ssh.exe", ssh_key="~/id_test", ssh_port=2222, user="admin", router="r"
        )
        command = TUNER.ssh_command(args)
        key_index = command.index("-i")
        self.assertEqual(
            command[key_index + 1], str(Path("~/id_test").expanduser())
        )
        port_index = command.index("-p")
        self.assertEqual(command[port_index + 1], "2222")
        self.assertLess(key_index, port_index)
        self.assertEqual(command[-2], "admin@r")

    def test_parser_defaults(self):
        args = make_cli_args("youtube")
        self.assertEqual(args.router, "192.168.2.1")
        self.assertEqual(args.ssh, "ssh.exe")
        self.assertEqual(args.max_candidates, 32)
        self.assertEqual(args.mix_level, "safe")
        self.assertIsNone(args.search_seed)
        self.assertEqual(args.repository, TUNER.DEFAULT_REPOSITORY)
        TUNER.validate_cli(args)

    def test_validate_cli_rejections(self):
        cases = [
            ("discord-voice",),
            ("discord-voice", "--client-ip", "not-an-ip"),
            ("discord-voice", "--client-ip", "::1"),
            ("youtube", "--voice-duration", "4"),
            ("youtube", "--voice-duration", "61"),
            ("youtube", "--http-timeout", "3"),
            ("youtube", "--http-timeout", "31"),
            ("youtube", "--max-candidates", "0"),
            ("youtube", "--max-candidates", "101"),
            ("youtube", "--ssh-port", "0"),
            ("youtube", "--ssh-port", "65536"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit):
                    TUNER.validate_cli(make_cli_args(*argv))

    def test_validate_cli_accepts_bounds(self):
        for argv in (
            ("discord-voice", "--client-ip", "10.0.0.5"),
            ("youtube", "--voice-duration", "5", "--http-timeout", "30"),
            ("youtube", "--voice-duration", "60", "--http-timeout", "4"),
            ("youtube", "--max-candidates", "1", "--ssh-port", "1"),
            ("youtube", "--max-candidates", "100", "--ssh-port", "65535"),
        ):
            with self.subTest(argv=argv):
                self.assertIsNone(TUNER.validate_cli(make_cli_args(*argv)))

    def test_parser_rejects_bad_seed(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                make_cli_args("youtube", "--search-seed", "-5")


class LocalSourceTests(unittest.TestCase):
    def test_load_local_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "general.bat").write_bytes(b"\xef\xbb\xbf@echo off\r\n")
            (root / "general (ALT).bat").write_bytes(b"rem alt\n")
            (root / "service.bat").write_bytes(b"ignored")
            sources, aggregate = TUNER.load_local_sources(root)
            self.assertEqual(
                [source.name for source in sources],
                ["general (ALT).bat", "general.bat"],
            )
            self.assertEqual(sources[1].text, "@echo off\r\n")
            self.assertEqual(
                sources[1].sha,
                hashlib.sha256(b"\xef\xbb\xbf@echo off\r\n").hexdigest(),
            )
            self.assertEqual(sources[0].url, str((root / "general (ALT).bat").resolve()))
            self.assertEqual(
                aggregate,
                hashlib.sha256(
                    (sources[0].sha + sources[1].sha).encode("ascii")
                ).hexdigest(),
            )

    def test_load_local_sources_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "no general\\*.bat"):
                TUNER.load_local_sources(Path(directory))


class SourceCacheRejectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.path = self.directory / "cache" / "sources.json"
        self.source = TUNER.SourceFile(
            "general (ALT11).bat", "@echo off", "d" * 40, "https://example.invalid/g.bat"
        )
        TUNER.save_source_cache(self.path, [self.source], "a" * 40)
        self.valid = json.loads(self.path.read_text(encoding="utf-8"))

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def test_round_trip_and_file_mode(self):
        sources, commit = TUNER.read_source_cache(self.path)
        self.assertEqual(sources, [self.source])
        self.assertEqual(commit, "a" * 40)
        self.assertEqual(self.valid["format"], 1)
        self.assertEqual(self.valid["repository"], TUNER.DEFAULT_REPOSITORY)
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            [p.name for p in self.path.parent.iterdir()], ["sources.json"]
        )

    def test_symlink_is_rejected(self):
        link = self.directory / "link.json"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available")
        with self.assertRaisesRegex(RuntimeError, "unsafe or oversized"):
            TUNER.read_source_cache(link)

    def test_top_level_rejections(self):
        cases = {
            "invalid Flowseal cache": [
                dict(self.valid, format=2),
                dict(self.valid, repository="other/repo"),
            ],
            "invalid cached commit": [
                dict(self.valid, commit="A" * 40),
                dict(self.valid, commit="a" * 39),
                dict(self.valid, commit=123),
            ],
            "invalid cached sources": [
                dict(self.valid, sources=[]),
                dict(self.valid, sources="x"),
                dict(self.valid, sources=self.valid["sources"] * 65),
            ],
            "invalid cached source$": [dict(self.valid, sources=["x"])],
        }
        for message, payloads in cases.items():
            for payload in payloads:
                with self.subTest(message=message):
                    self.write(payload)
                    with self.assertRaisesRegex(RuntimeError, message):
                        TUNER.read_source_cache(self.path)
        self.write(["not", "a", "dict"])
        with self.assertRaisesRegex(RuntimeError, "invalid Flowseal cache"):
            TUNER.read_source_cache(self.path)

    def test_source_entry_rejections(self):
        item = self.valid["sources"][0]
        variants = [
            dict(item, sha256="0" * 64),
            dict(item, name="evil.bat"),
            dict(item, name="general/../x.bat"),
            dict(item, name="general" + "a" * 160 + ".bat"),
            dict(item, sha="D" * 40),
            dict(item, sha="d" * 39),
            dict(item, url=123),
            dict(item, url="u" * 1001),
            dict(item, text=None),
        ]
        for variant in variants:
            with self.subTest(variant={k: str(v)[:20] for k, v in variant.items()}):
                self.write(dict(self.valid, sources=[variant]))
                with self.assertRaisesRegex(RuntimeError, "corrupt cached source"):
                    TUNER.read_source_cache(self.path)

    def test_duplicate_names_are_rejected(self):
        item = self.valid["sources"][0]
        self.write(dict(self.valid, sources=[item, dict(item)]))
        with self.assertRaisesRegex(RuntimeError, "corrupt cached source"):
            TUNER.read_source_cache(self.path)

    def test_case_insensitive_name_pattern_is_accepted(self):
        item = dict(self.valid["sources"][0], name="GENERAL_2.BAT")
        self.write(dict(self.valid, sources=[item]))
        sources, _commit = TUNER.read_source_cache(self.path)
        self.assertEqual(sources[0].name, "GENERAL_2.BAT")


class NetworkWrapperTests(unittest.TestCase):
    def test_github_json_parses_and_sets_headers(self):
        with mock.patch.object(
            TUNER.urllib.request, "urlopen", return_value=FakeResponse(b'{"sha": "x"}')
        ) as urlopen:
            self.assertEqual(TUNER.github_json("https://api.invalid/x"), {"sha": "x"})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.invalid/x")
        self.assertEqual(request.get_header("User-agent"), "keenetic-zapret-tuner/1.0")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 30)

    def test_github_json_size_limit(self):
        big = b" " * (4 * 1024 * 1024 + 1)
        with mock.patch.object(
            TUNER.urllib.request, "urlopen", return_value=FakeResponse(big)
        ):
            with self.assertRaisesRegex(RuntimeError, "exceeds 4 MiB"):
                TUNER.github_json("https://api.invalid/x")

    def test_download_text(self):
        with mock.patch.object(
            TUNER.urllib.request,
            "urlopen",
            return_value=FakeResponse(b"\xef\xbb\xbf@echo \xff"),
        ):
            self.assertEqual(TUNER.download_text("https://raw.invalid/x"), "@echo \ufffd")
        with mock.patch.object(
            TUNER.urllib.request, "urlopen", return_value=FakeResponse(b"x" * 262145)
        ):
            with self.assertRaisesRegex(RuntimeError, "exceeds 256 KiB"):
                TUNER.download_text("https://raw.invalid/x")

    def test_fetch_sources_errors(self):
        commit = {"sha": "a" * 40}
        cases = [
            ([[]], "no commit SHA"),
            ([{"sha": 5}], "no commit SHA"),
            ([{"sha": "nothex"}], "invalid GitHub commit SHA"),
            ([commit, {"not": "list"}], "not a list"),
            ([commit, ["junk", {"name": "readme.md", "sha": "s", "download_url": "u"}]],
             "no general"),
        ]
        for responses, message in cases:
            with self.subTest(message=message):
                with mock.patch.object(TUNER, "github_json", side_effect=responses):
                    with self.assertRaisesRegex(RuntimeError, message):
                        TUNER.fetch_sources("o/r", "main")

    def test_fetch_sources_filters_sorts_and_limits(self):
        commit = {"sha": "a" * 40}
        root = [
            {"name": "general_b.bat", "sha": "1" * 40, "download_url": "https://x/b"},
            {"name": "General_A.BAT", "sha": "2" * 40, "download_url": "https://x/a"},
            {"name": "general_c.bat", "sha": None, "download_url": "https://x/c"},
            {"name": "service.bat", "sha": "3", "download_url": "https://x/s"},
        ]
        with mock.patch.object(TUNER, "github_json", side_effect=[commit, root]) as api:
            with mock.patch.object(TUNER, "download_text", side_effect=lambda url: url) as dl:
                sources, result = TUNER.fetch_sources("o w/r", "feature/x")
        self.assertEqual(result, "a" * 40)
        self.assertEqual([s.name for s in sources], ["General_A.BAT", "general_b.bat"])
        self.assertEqual(sources[0].text, "https://x/a")
        self.assertEqual(dl.call_count, 2)
        self.assertEqual(
            api.call_args_list[0].args[0],
            "https://api.github.com/repos/o%20w/r/commits/feature%2Fx",
        )
        many = [
            {"name": f"general{i}.bat", "sha": "5" * 40, "download_url": "u"}
            for i in range(65)
        ]
        with mock.patch.object(TUNER, "github_json", side_effect=[commit, many]):
            with mock.patch.object(TUNER, "download_text", return_value=""):
                with self.assertRaisesRegex(RuntimeError, "limit 64"):
                    TUNER.fetch_sources("o/r", "main")


class FetchCacheRoundTripTests(unittest.TestCase):
    """Whatever fetch_sources() returns must be storable in the cache."""

    def test_unicode_names_round_trip_and_unsafe_entries_are_skipped(self):
        commit = {"sha": "A" * 40}
        root = [
            {"name": "general (МГТС).bat", "sha": "b" * 40, "download_url": "https://x/m"},
            {"name": "general (ALT).bat", "sha": "c" * 40, "download_url": "https://x/a"},
            {"name": "general;rm.bat", "sha": "d" * 40, "download_url": "https://x/r"},
            {"name": "general (BAD SHA).bat", "sha": "nope", "download_url": "https://x/s"},
        ]
        with mock.patch.object(TUNER, "github_json", side_effect=[commit, root]), \
                mock.patch.object(TUNER, "download_text", side_effect=lambda url: f"rem {url}\n"):
            sources, fetched_commit = TUNER.fetch_sources("o/r", "main")
        self.assertEqual(fetched_commit, "a" * 40)
        self.assertEqual([s.name for s in sources], ["general (ALT).bat", "general (МГТС).bat"])
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "flowseal-sources.json"
            TUNER.save_source_cache(cache, sources, fetched_commit)
            cached, cached_commit = TUNER.read_source_cache(cache)
        self.assertEqual(cached_commit, "a" * 40)
        self.assertEqual([s.name for s in cached], [s.name for s in sources])
        self.assertTrue(TUNER.SOURCE_NAME_RE.fullmatch("general (МГТС).bat"))
        self.assertEqual(TUNER.select_source(cached, "GENERAL (мгтс).BAT")[0].name, "general (МГТС).bat")


class MixedCandidateTests(unittest.TestCase):
    """Component mixes must keep the YouTube TCP and QUIC sections apart."""

    def sources(self):
        alt = SAMPLE.replace("--dpi-desync-repeats=8", "--dpi-desync-repeats=4")
        return [
            SOURCE,
            TUNER.SourceFile("general (ALT2).bat", alt, "def456", "https://example.invalid/alt2.bat"),
        ]

    def test_split_components_ignores_quic_section(self):
        candidate = TUNER.known_candidate("youtube", [SOURCE])
        base, fake, split = TUNER.split_components(candidate)
        self.assertEqual(fake, TUNER.NATIVE_FAKE)
        self.assertEqual(split, TUNER.NATIVE_SPLIT)
        self.assertEqual(base, list(candidate.args[: candidate.args.index("--new")][:5]))
        self.assertFalse(any("udp" in token or "quic" in token for token in base))

    def test_youtube_mixes_have_no_quic_tokens_in_tcp_section(self):
        for level in ("safe", "extended"):
            mixes = TUNER.mixed_candidates(
                "youtube",
                [
                    candidate
                    for candidate in TUNER.build_candidates("youtube", self.sources(), "off")
                    if candidate.rank != 0
                ],
                self.sources(),
                level,
            )
            self.assertTrue(mixes, level)
            for candidate in mixes:
                with self.subTest(level=level, family=candidate.family):
                    self.assertIn("--new", candidate.args)
                    tcp = candidate.args[: candidate.args.index("--new")]
                    quic = candidate.args[candidate.args.index("--new"):]
                    self.assertFalse(
                        [token for token in tcp if "udp" in token or "quic" in token],
                        candidate.args,
                    )
                    self.assertIn("--filter-tcp=443", tcp)
                    self.assertIn("--filter-udp=443", quic)


class SourceSelectionTests(unittest.TestCase):
    def test_select_source_is_case_insensitive(self):
        other = TUNER.SourceFile("general (ALT3).bat", SAMPLE, "def456", "u")
        self.assertEqual(TUNER.select_source([SOURCE, other], "GENERAL (alt3).BAT"), [other])
        with self.assertRaisesRegex(ValueError, "not found"):
            TUNER.select_source([SOURCE], "general (ALT9).bat")

    def test_build_candidates_without_builtin(self):
        with_builtin = TUNER.build_candidates("discord-tcp", [SOURCE], "off")
        without = TUNER.build_candidates("discord-tcp", [SOURCE], "off", include_builtin=False)
        builtin = TUNER.known_candidate("discord-tcp", [SOURCE])
        self.assertIn(builtin.args, [candidate.args for candidate in with_builtin])
        self.assertNotIn(builtin.args, [candidate.args for candidate in without])
        self.assertTrue(without)
        self.assertTrue(all(candidate.source_name == SOURCE.name for candidate in without))

    def test_identical_profiles_are_tested_once_and_named(self):
        # Flowseal BATs often share a profile: one candidate, all names kept.
        copies = [
            TUNER.SourceFile(name, SOURCE.text, SOURCE.sha, SOURCE.url)
            for name in ("general (ALT2).bat", "general.bat")
        ]
        candidates = TUNER.build_candidates(
            "discord-voice", [SOURCE, *copies], "off", include_builtin=False
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].source_name, "general (ALT11).bat")
        self.assertEqual(candidates[0].also_from, ("general (ALT2).bat", "general.bat"))
        single = TUNER.build_candidates("discord-voice", [SOURCE], "off", include_builtin=False)
        self.assertEqual(single[0].also_from, ())

    def test_source_services(self):
        self.assertEqual(
            TUNER.source_services(SOURCE), ["discord-tcp", "discord-voice", "youtube"]
        )
        empty = TUNER.SourceFile("general (EMPTY).bat", "@echo off\n", "0", "u")
        self.assertEqual(TUNER.source_services(empty), [])

    def test_source_name_pattern(self):
        for name in ("general.bat", "general (ALT11).bat", "General_FAKE-2.BAT"):
            self.assertTrue(TUNER.SOURCE_NAME_RE.fullmatch(name), name)
        for name in ("service.bat", "general/../x.bat", "general;rm.bat", "general.cmd"):
            self.assertFalse(TUNER.SOURCE_NAME_RE.fullmatch(name), name)


class ReportTests(unittest.TestCase):
    def test_write_report(self):
        candidate = TUNER.known_candidate("discord-tcp", [SOURCE])
        args = argparse.Namespace(
            repository="o/r",
            ref="main",
            service="discord-tcp",
            router="192.168.2.1",
            search_seed=42,
            source_file="general (ALT11).bat",
        )
        output = ["EVENT|PROBE_DETAIL|1|p|1|r|200|0.1|1|0|ok|u", "EVENT|FOUND|1|x"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"
            TUNER.write_report(
                path,
                args=args,
                commit="c" * 40,
                candidates=[candidate, candidate],
                found=candidate,
                output=output,
            )
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["report_format"], 1)
        self.assertEqual(report["repository"], "o/r")
        self.assertEqual(report["router"], "192.168.2.1")
        self.assertEqual(report["search_seed"], 42)
        self.assertEqual(report["source_file"], "general (ALT11).bat")
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual(report["found"]["candidate_id"], candidate.candidate_id)
        self.assertEqual(report["found"]["args"], list(candidate.args))
        self.assertEqual(report["remote_output"], output)
        self.assertEqual(len(report["verification"]["probes"]), 1)
        self.assertIn("created_utc", report)

    def test_write_report_without_found(self):
        args = argparse.Namespace(
            repository="o/r", ref="main", service="discord-voice",
            router="r", search_seed=1, source_file=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            TUNER.write_report(
                path, args=args, commit="c", candidates=[], found=None, output=[]
            )
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsNone(report["found"])
        self.assertIsNone(report["source_file"])
        self.assertEqual(report["verification"]["method"], "manual-duplex-voice")


class FakeProcess:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.stdin = mock.Mock()
        self.returncode = returncode
        self.terminate = mock.Mock()

    def wait(self, timeout=None):
        return self.returncode


class RunRemoteTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(
            ssh="ssh", ssh_key=None, ssh_port=22, user="root",
            router="192.168.2.1", voice_duration=25,
        )
        self.candidates = [TUNER.known_candidate("discord-voice", [SOURCE])]

    def run_remote(self, lines, returncode=0, answer="n"):
        process = FakeProcess(lines, returncode)
        with mock.patch.object(TUNER.subprocess, "Popen", return_value=process) as popen, \
                mock.patch("builtins.input", return_value=answer), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = TUNER.run_remote(self.args, "echo runner", self.candidates)
        return result, process, popen, stdout.getvalue()

    def test_voice_flow_and_found(self):
        lines = [
            "hello\n",
            "EVENT|VOICE_READY|1|17\n",
            "EVENT|VOICE_READY|1\n",
            "EVENT|VOICE_VERDICT|1\n",
            "EVENT|FOUND|2\n",
            "EVENT|FOUND|1\r\n",
        ]
        (found, output), process, popen, stdout = self.run_remote(lines, answer=" Да ")
        self.assertEqual(found, self.candidates[0])
        self.assertEqual(output[0], "hello")
        self.assertEqual(output[-1], "EVENT|FOUND|1")
        self.assertIn("в течение 17 секунд", stdout)
        self.assertIn("в течение 25 секунд", stdout)
        import base64

        payload = process.stdin.write.call_args_list[0].args[0]
        self.assertEqual(base64.b64decode(payload.strip()).decode(), "echo runner")
        self.assertEqual(process.stdin.write.call_args_list[1].args[0], "yes\n")
        process.stdin.close.assert_called_once()
        self.assertEqual(popen.call_args.args[0], TUNER.ssh_command(self.args))

    def test_negative_verdict_and_no_found(self):
        (found, _output), process, _popen, _stdout = self.run_remote(
            ["EVENT|VOICE_VERDICT|1\n", "EVENT\n"], answer="maybe"
        )
        self.assertIsNone(found)
        self.assertEqual(process.stdin.write.call_args_list[1].args[0], "no\n")

    def test_errors(self):
        with self.assertRaisesRegex(RuntimeError, "exited with code 5"):
            self.run_remote([], returncode=5)
        with self.assertRaisesRegex(RuntimeError, "restoration failed"):
            self.run_remote(["EVENT|RESTORE_ERROR|boom\n"])

    def test_keyboard_interrupt_terminates_ssh(self):
        def lines():
            yield "x\n"
            raise KeyboardInterrupt

        process = FakeProcess(lines())
        with mock.patch.object(TUNER.subprocess, "Popen", return_value=process), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                TUNER.run_remote(self.args, "r", self.candidates)
        process.terminate.assert_called_once()
        process.stdin.close.assert_called_once()


class MainTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.sources = self.root / "src"
        self.sources.mkdir()
        (self.sources / "general (ALT11).bat").write_text(SAMPLE, encoding="utf-8")

    def main(self, *argv, **patches):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(TUNER, name, value))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = TUNER.main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_plan_only_writes_report(self):
        report = self.root / "out" / "plan.json"
        code, stdout, _ = self.main(
            "youtube", "--source-dir", str(self.sources), "--plan-only",
            "--max-candidates", "4", "--search-seed", "7", "--report", str(report),
        )
        self.assertEqual(code, 0)
        self.assertIn("seed: 7.", stdout)
        self.assertIn("кандидатов: 4", stdout)
        self.assertIn("Plan-only", stdout)
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["candidate_count"], 4)
        self.assertEqual(data["search_seed"], 7)
        self.assertIsNone(data["found"])

    def test_plan_only_with_selected_source_file(self):
        (self.sources / "general (ALT3).bat").write_text(SAMPLE, encoding="utf-8")
        report = self.root / "plan.json"
        code, stdout, _ = self.main(
            "discord-voice", "--source-dir", str(self.sources), "--plan-only",
            "--mix-level", "off", "--source-file", "general (alt3).bat",
            "--client-ip", "192.168.2.60",
            "--search-seed", "3", "--report", str(report),
        )
        self.assertEqual(code, 0)
        self.assertIn("BAT-файлов: 1", stdout)
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["source_file"], "general (alt3).bat")
        # Only the translated ALT3 profile: the router built-in is skipped.
        self.assertEqual(data["candidate_count"], 1)
        self.assertNotIn("Flowseal ACTIVE_DISCORD_UDP", stdout)

    def test_unknown_or_empty_source_file_returns_one(self):
        code, _stdout, stderr = self.main(
            "youtube", "--source-dir", str(self.sources), "--plan-only",
            "--source-file", "general (missing).bat",
        )
        self.assertEqual(code, 1)
        self.assertIn("not found", stderr)
        # Only the TCP/Google profile of the sample: nothing for Discord Voice.
        voiceless = "@echo off\nstart winws.exe ^\n" + SAMPLE.splitlines()[4].removesuffix(" --new ^") + "\n"
        (self.sources / "general (FAKE).bat").write_text(voiceless, encoding="utf-8")
        code, _stdout, stderr = self.main(
            "discord-voice", "--source-dir", str(self.sources), "--plan-only",
            "--source-file", "general (FAKE).bat", "--client-ip", "192.168.2.60",
        )
        self.assertEqual(code, 1)
        self.assertIn("нет профиля", stderr)

    def test_plan_only_without_report(self):
        code, stdout, _ = self.main(
            "discord-tcp", "--source-dir", str(self.sources), "--plan-only",
            "--search-seed", "1",
        )
        self.assertEqual(code, 0)
        self.assertIn("01. ", stdout)

    def test_source_errors_return_one(self):
        empty = self.root / "empty"
        empty.mkdir()
        code, _stdout, stderr = self.main("youtube", "--source-dir", str(empty))
        self.assertEqual(code, 1)
        self.assertIn("ERROR", stderr)
        code, stdout, stderr = self.main(
            "youtube",
            fetch_sources=mock.Mock(side_effect=OSError("offline")),
        )
        self.assertEqual(code, 1)
        self.assertIn("offline", stderr)
        self.assertIn(TUNER.DEFAULT_REPOSITORY, stdout)

    def test_confirmation_declined(self):
        with mock.patch("builtins.input", return_value="yes"):
            code, stdout, _ = self.main(
                "youtube", "--source-dir", str(self.sources), "--search-seed", "1",
            )
        self.assertEqual(code, 2)
        self.assertIn("Отменено.", stdout)

    def test_remote_found_writes_report(self):
        report = self.root / "found.json"
        captured = {}

        def fake_remote(args, runner, candidates):
            captured["runner"] = runner
            return candidates[0], ["EVENT|FOUND|1|x"]

        with mock.patch("builtins.input", return_value="YES"):
            code, stdout, _ = self.main(
                "discord-voice", "--source-dir", str(self.sources),
                "--client-ip", "192.168.2.50", "--search-seed", "3",
                "--report", str(report), run_remote=fake_remote,
            )
        self.assertEqual(code, 0)
        self.assertIn("НАЙДЕН ПРОХОДНОЙ КАНДИДАТ", stdout)
        self.assertIn("NFQWS_ARGS_UDP", stdout)
        self.assertNotIn("@@", captured["runner"])
        self.assertIn('CLIENT_IP="192.168.2.50"', captured["runner"])
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["remote_output"], ["EVENT|FOUND|1|x"])
        self.assertIsNotNone(data["found"])

    def test_remote_not_found_and_failure(self):
        code, stdout, _ = self.main(
            "youtube", "--source-dir", str(self.sources), "--yes-router",
            "--search-seed", "3", run_remote=mock.Mock(return_value=(None, [])),
        )
        self.assertEqual(code, 3)
        self.assertIn("Проходной кандидат не найден", stdout)
        code, _stdout, stderr = self.main(
            "youtube", "--source-dir", str(self.sources), "--yes-router",
            "--search-seed", "3",
            run_remote=mock.Mock(side_effect=RuntimeError("ssh down")),
        )
        self.assertEqual(code, 1)
        self.assertIn("ssh down", stderr)

    def test_invalid_cli_exits_before_work(self):
        with self.assertRaises(SystemExit):
            self.main("discord-voice", "--source-dir", str(self.sources))


if __name__ == "__main__":
    unittest.main()

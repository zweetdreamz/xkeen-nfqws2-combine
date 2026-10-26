"""Characterization tests for the web panel backend (xkeen_control_script.sh).

The panel source is extracted by ``panel_loader`` and executed into a fresh
namespace. Functions resolve globals from that namespace, so tests patch
path constants and helpers with ``mock.patch.dict(ns, {...})`` and keep every
file operation inside a TemporaryDirectory. Nothing here runs router
commands, touches /opt, needs root or uses the network beyond 127.0.0.1.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from panel_loader import load_panel_namespace


VALID_ARGS = {
    "youtube": [
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
        "--payload=tls_client_hello",
        "--lua-desync=multisplit:pos=1",
        "--new",
        "--filter-udp=443",
        "--filter-l7=quic",
        "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
        "--payload=quic_initial",
        "--lua-desync=fake:blob=quic_google:repeats=6",
    ],
    "discord-tcp": [
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist=/opt/etc/nfqws2/lists/user.list",
        "--payload=tls_client_hello",
        "--lua-desync=multisplit:pos=1",
    ],
    "discord-voice": [
        "--filter-udp=50000-50100",
        "--filter-l7=stun,discord",
        "--payload=stun,discord_ip_discovery",
        "--lua-desync=fake:blob=discord_udp:repeats=6",
    ],
}


def expected_candidate_id(service, source_name, family, args):
    serialized = "\n".join((service, source_name, family, *args))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]


_DEFAULT = object()


def make_candidate(service="discord-tcp", args=_DEFAULT, **overrides):
    candidate = {
        "service": service,
        "source_name": "general (ALT).bat",
        "source_sha": "a" * 40,
        "source_url": "https://example.invalid/general.bat",
        "family": "fixture-family",
        "rank": 3,
        "notes": ["fixture note"],
        "args": (
            list(VALID_ARGS.get(service, VALID_ARGS["discord-tcp"]))
            if args is _DEFAULT
            else (list(args) if isinstance(args, list) else args)
        ),
    }
    candidate.update(overrides)
    if "candidate_id" not in overrides:
        try:
            candidate["candidate_id"] = expected_candidate_id(
                candidate["service"],
                candidate["source_name"],
                candidate["family"],
                candidate["args"],
            )
        except TypeError:
            candidate["candidate_id"] = "0" * 12
    return candidate


def make_report(service="discord-tcp", candidate=None, **overrides):
    report = {
        "report_format": 1,
        "created_utc": "2026-08-15T00:00:00Z",
        "repository": "fixture/repository",
        "ref": "main",
        "commit": "abc1234",
        "search_seed": 42,
        "service": service,
        "found": candidate if candidate is not None else make_candidate(service),
    }
    report.update(overrides)
    return report


class PanelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_panel_namespace("panel_units_test")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def patch(self, **values):
        patcher = mock.patch.dict(self.ns, values)
        patcher.start()
        self.addCleanup(patcher.stop)

    def profile(self, service="discord-tcp"):
        return self.ns["validate_report"](make_report(service))


class ParsingHelpersTests(PanelTestCase):
    def test_parse_status_keeps_only_allowlisted_keys(self):
        text = (
            "discord_route=zapret\n"
            "youtube_route=vless\n"
            "telegram_route=unmanaged\n"
            "xkeen_runtime=running\n"
            "nfqws_runtime=stopped\n"
            "script_version=6.4=beta\n"
            "unknown_key=value\n"
            "no separator here\n"
            "=empty-key\n"
        )
        self.assertEqual(
            self.ns["parse_status"](text),
            {
                "discord_route": "zapret",
                "youtube_route": "vless",
                "telegram_route": "unmanaged",
                "xkeen_runtime": "running",
                "nfqws_runtime": "stopped",
                "script_version": "6.4=beta",
            },
        )
        self.assertEqual(self.ns["parse_status"](""), {})

    def test_parse_status_last_duplicate_wins(self):
        self.assertEqual(
            self.ns["parse_status"]("discord_route=direct\ndiscord_route=zapret"),
            {"discord_route": "zapret"},
        )

    def test_private_client(self):
        cases = {
            "192.168.2.10": True,
            "10.0.0.1": True,
            "172.16.5.4": True,
            "127.0.0.1": True,
            "::1": True,
            "fd00::1": True,
            "8.8.8.8": False,
            "2001:4860:4860::8888": False,
            "not-an-ip": False,
            "": False,
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertIs(self.ns["private_client"](address), expected)

    def test_bounded_text(self):
        bounded = self.ns["bounded_text"]
        self.assertEqual(bounded("abc", "f", 3), "abc")
        self.assertEqual(bounded("", "f", 3), "")
        with self.assertRaisesRegex(ValueError, "некорректное поле f"):
            bounded("abcd", "f", 3)
        for value in (None, 5, b"abc", ["a"]):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "некорректное поле f"):
                    bounded(value, "f", 10)
        for value in ("a\nb", "a\rb"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "некорректное поле f"):
                    bounded(value, "f", 10)
        with self.assertRaisesRegex(ValueError, "пустое поле f"):
            bounded("", "f", 10, allow_empty=False)

    def test_voice_ports_allowed(self):
        allowed = self.ns["voice_ports_allowed"]
        for value in (
            "443",
            "3478",
            "3478-3481",
            "3479-3480",
            "5349",
            "19294-19344",
            "19300",
            "50000-65535",
            "60000",
            "443,3478-3481,50000-65535",
        ):
            with self.subTest(value=value):
                self.assertTrue(allowed(value))
        for value in (
            "",
            "80",
            "443-444",
            "3477-3481",
            "3478-3482",
            "5350",
            "19293-19344",
            "49999-65535",
            "50000-65536",
            "3481-3478",
            "abc",
            "1-2-3",
            "443,80",
            "443,",
            " 443",
        ):
            with self.subTest(value=value):
                self.assertFalse(allowed(value))
        # The narrow range ends at 50100, as the engine's VOICE_HIGH.
        self.assertTrue(allowed("19294-19344,50000-50100", 50100))
        self.assertFalse(allowed("50000-50101", 50100))
        self.assertFalse(allowed("60000", 50100))

    def test_route_stage_empty_output_is_preflight(self):
        for operation in ("switch", "rollback"):
            with self.subTest(operation=operation):
                self.assertEqual(
                    self.ns["route_stage"]("", operation),
                    ("preflight", "Проверка конфигурации", 10),
                )

    def test_route_stage_switch_sequence(self):
        stage = self.ns["route_stage"]
        output = "Snapshot created: /x\n"
        self.assertEqual(stage(output, "switch")[0], "snapshot")
        output += "Patching Mihomo config\n"
        self.assertEqual(stage(output, "switch"), ("config", "Запись конфигурации", 45))
        output += "Restarting XKeen...\n"
        self.assertEqual(stage(output, "switch"), ("xray", "Перезапуск XKeen/Xray", 65))
        output += "Restarting nfqws2 only\n"
        self.assertEqual(stage(output, "switch"), ("nfqws", "Перезапуск nfqws2", 82))

    def test_route_stage_rollback_sequence(self):
        stage = self.ns["route_stage"]
        output = "Rescue snapshot of current state: /x\n"
        self.assertEqual(stage(output, "rollback"), ("snapshot", "Rescue snapshot", 30))
        output += "Restoring /opt/etc/xray\n"
        self.assertEqual(stage(output, "rollback"), ("restore", "Восстановление файлов", 58))
        output += "Restore complete: /x\n"
        self.assertEqual(
            stage(output, "rollback"),
            ("verify", "Проверка восстановленного состояния", 92),
        )

    def test_route_stage_ignores_markers_of_other_operation(self):
        stage = self.ns["route_stage"]
        self.assertEqual(
            stage("Restarting XKeen...\nStarted NFQWS2 service", "rollback")[0],
            "preflight",
        )
        self.assertEqual(stage("Restoring\nRestore complete: /x", "switch")[0], "preflight")
        # "Snapshot created:" is shared by both operations.
        self.assertEqual(stage("Snapshot created: /x", "rollback"), ("snapshot", "Создание snapshot", 25))

    def test_validate_route(self):
        validate = self.ns["validate_route"]
        for service in ("discord-tcp", "discord-voice", "discord", "youtube"):
            for mode in ("direct", "zapret", "vpn"):
                self.assertEqual(validate(service, mode), (service, mode))
        for mode in ("direct", "vpn", "ws", "unmanaged"):
            self.assertEqual(validate("telegram", mode), ("telegram", mode))
        # Telegram is blocked by IP; the Zapret mode was removed.
        with self.assertRaisesRegex(ValueError, "Zapret для Telegram удалён"):
            validate("telegram", "zapret")
        with self.assertRaisesRegex(ValueError, "неподдерживаемый сервис"):
            validate("discord-video", "direct")
        with self.assertRaisesRegex(ValueError, "неподдерживаемый маршрут"):
            validate("youtube", "vless")
        for service in ("discord-tcp", "discord-voice", "discord", "youtube"):
            with self.subTest(service=service):
                with self.assertRaisesRegex(ValueError, "неподдерживаемый маршрут"):
                    validate(service, "unmanaged")

    def test_history_path(self):
        self.patch(ROUTE_HISTORY_DIR=self.root / "history")
        job_id = "0123456789abcdef"
        self.assertEqual(self.ns["history_path"](job_id), self.root / "history" / f"{job_id}.json")
        for bad in (
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "../../etc/passwd",
            "0123456789abcdeg",
            "",
            None,
            123,
        ):
            with self.subTest(job_id=bad):
                with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
                    self.ns["history_path"](bad)

    def test_utc_now_format(self):
        self.assertRegex(self.ns["utc_now"](), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CandidateValidationTests(PanelTestCase):
    def validate(self, candidate, report=None):
        return self.ns["validate_candidate"](candidate, report if report is not None else {})

    def assertRejected(self, pattern, candidate, report=None):
        with self.assertRaisesRegex(ValueError, pattern):
            self.validate(candidate, report)

    def test_telegram_profiles_are_no_longer_accepted(self):
        args = [
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list",
            "--payload=tls_client_hello",
            "--lua-desync=fake:blob=tls_clienthello_www_google_com:repeats=6",
        ]
        self.assertRejected("неподдерживаемый сервис", make_candidate("telegram", args=args))
        # The MTProto ipset is not a profile option any more.
        tcp = VALID_ARGS["discord-tcp"] + ["--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list"]
        self.assertRejected("неподдерживаемая опция: --ipset", make_candidate("discord-tcp", args=tcp))

    def test_accepts_each_service(self):
        for service in ("youtube", "discord-tcp", "discord-voice"):
            with self.subTest(service=service):
                candidate = make_candidate(service)
                profile = self.validate(candidate, make_report(service, candidate))
                self.assertEqual(profile["format"], 1)
                self.assertEqual(profile["service"], service)
                self.assertEqual(profile["candidate_id"], candidate["candidate_id"])
                self.assertEqual(profile["args"], candidate["args"])
                self.assertEqual(profile["notes"], ["fixture note"])
                self.assertEqual(profile["rank"], 3)
                self.assertEqual(
                    profile["report"],
                    {
                        "repository": "fixture/repository",
                        "ref": "main",
                        "commit": "abc1234",
                        "created_utc": "2026-08-15T00:00:00Z",
                        "search_seed": 42,
                    },
                )

    def test_report_metadata_defaults_to_empty(self):
        profile = self.validate(make_candidate(), {})
        self.assertEqual(
            profile["report"],
            {"repository": "", "ref": "", "commit": "", "created_utc": "", "search_seed": None},
        )

    def test_accepts_boundary_values(self):
        for rank in (0, 100000):
            with self.subTest(rank=rank):
                self.assertEqual(self.validate(make_candidate(rank=rank))["rank"], rank)
        for seed in (0, 4294967295):
            with self.subTest(seed=seed):
                profile = self.validate(make_candidate(), {"search_seed": seed})
                self.assertEqual(profile["report"]["search_seed"], seed)
        self.assertEqual(self.validate(make_candidate(notes=[]))["notes"], [])
        self.assertEqual(self.validate(make_candidate(notes=["n"] * 20))["notes"], ["n"] * 20)
        self.assertEqual(self.validate(make_candidate(source_sha=""))["source_sha"], "")
        self.assertEqual(self.validate(make_candidate(source_url=""))["source_url"], "")
        voice = make_candidate(
            "discord-voice",
            args=[
                "--filter-udp=443,3478-3481,5349,19294-19344",
                "--filter-l7=stun,discord",
                "--payload=stun,discord_ip_discovery",
                "--lua-desync=fake:blob=discord_udp:repeats=99",
            ],
        )
        self.assertEqual(self.validate(voice)["service"], "discord-voice")

    def test_rejects_non_dict_and_unknown_service(self):
        for value in (None, [], "candidate", 1):
            with self.subTest(value=value):
                self.assertRejected("нет найденного кандидата", value)
        self.assertRejected("неподдерживаемый сервис", make_candidate(service="whatsapp"))
        self.assertRejected("неподдерживаемый сервис", {"args": []})

    def test_rejects_bad_text_fields(self):
        cases = [
            ({"source_name": None}, "некорректное поле source_name"),
            ({"source_name": ""}, "пустое поле source_name"),
            ({"source_name": "x" * 161}, "некорректное поле source_name"),
            ({"source_sha": "x" * 129}, "некорректное поле source_sha"),
            ({"source_url": "https://a\nb"}, "некорректное поле source_url"),
            ({"family": ""}, "пустое поле family"),
            ({"family": "x" * 241}, "некорректное поле family"),
            ({"candidate_id": ""}, "пустое поле candidate_id"),
            ({"candidate_id": "0" * 13}, "некорректное поле candidate_id"),
            ({"candidate_id": "ABCDEF012345"}, "некорректный candidate_id"),
            ({"candidate_id": "0123456789ag"}, "некорректный candidate_id"),
        ]
        for overrides, pattern in cases:
            with self.subTest(overrides=overrides):
                self.assertRejected(pattern, make_candidate(**overrides))

    def test_rejects_bad_rank_and_notes(self):
        for rank in (True, False, -1, 100001, "1", 1.0, None):
            with self.subTest(rank=rank):
                self.assertRejected("некорректный rank", make_candidate(rank=rank))
        for notes in ("note", None, {"a": 1}, ["n"] * 21):
            with self.subTest(notes=notes):
                self.assertRejected("некорректные notes", make_candidate(notes=notes))
        for notes in ([1], ["a\nb"], ["x" * 501]):
            with self.subTest(notes=notes):
                self.assertRejected("некорректное поле notes", make_candidate(notes=notes))

    def test_rejects_bad_args_container_and_tokens(self):
        base = VALID_ARGS["discord-tcp"]
        for args in ("--filter-tcp=443", None, [], ["--payload=tls_client_hello"] * 41):
            with self.subTest(args=args):
                self.assertRejected("некорректный список args", make_candidate(args=args))
        token_cases = [
            ("", "пустое поле args"),
            (5, "некорректное поле args"),
            ("--payload=" + "a" * 600, "некорректное поле args"),
            ("--filter-tcp=443 80", "небезопасный токен"),
            ("--filter-tcp=443;reboot", "небезопасный токен"),
            ("--Filter-tcp=443", "небезопасный токен"),
            ("filter-tcp=443", "небезопасный токен"),
            ("--filter-tcp", "небезопасный токен"),
            ("--dpi-desync=fake", "неподдерживаемая опция: --dpi-desync"),
            ("--lua-desync=evil:blob=x", "неподдерживаемая Lua-стратегия"),
            ("--lua-desync=fakeX", "неподдерживаемая Lua-стратегия"),
        ]
        for token, pattern in token_cases:
            with self.subTest(token=token):
                self.assertRejected(pattern, make_candidate(args=[*base, token]))

    def test_rejects_youtube_scope_violations(self):
        base = VALID_ARGS["youtube"]
        without_new = [token for token in base if token != "--new"]
        cases = [
            (without_new, "неполный YouTube TCP/QUIC профиль"),
            ([*base, "--new", "--filter-tcp=443"], "неполный YouTube TCP/QUIC профиль"),
            ([token for token in base if token != "--payload=quic_initial"], "неполный YouTube"),
            ([*base, "--filter-tcp=80"], "YouTube профиль выходит за TCP/UDP 443"),
            ([*base, "--filter-udp=50000"], "YouTube профиль выходит за TCP/UDP 443"),
            ([*base, "--filter-l7=http"], "лишний L7-фильтр YouTube"),
            ([*base, "--hostlist=/opt/etc/nfqws2/lists/other.list"], "лишний hostlist YouTube"),
            ([*base, "--lua-desync=fake:blob=discord_x"], "YouTube профиль пересекается с Discord"),
        ]
        for args, pattern in cases:
            with self.subTest(args=args[-1]):
                self.assertRejected(pattern, make_candidate("youtube", args=args))

    def test_rejects_discord_tcp_scope_violations(self):
        base = VALID_ARGS["discord-tcp"]
        cases = [
            ([*base, "--new"], "неполный Discord TCP профиль"),
            (base[1:], "неполный Discord TCP профиль"),
            ([*base, "--filter-tcp=80"], "Discord TCP профиль выходит за TCP 443"),
            ([*base, "--filter-udp=443"], "Discord TCP профиль выходит за TCP 443"),
            ([*base, "--filter-l7=quic"], "лишний L7-фильтр Discord TCP"),
            ([*base, "--hostlist=/opt/etc/nfqws2/lists/youtube.list"], "лишний hostlist Discord TCP"),
            ([*base, "--lua-desync=fake:blob=youtube_tls"], "пересекается с другим семейством"),
            ([*base, "--lua-desync=fake:blob=discord_udp"], "пересекается с другим семейством"),
        ]
        for args, pattern in cases:
            with self.subTest(args=args[-1]):
                self.assertRejected(pattern, make_candidate("discord-tcp", args=args))

    def test_rejects_discord_voice_scope_violations(self):
        base = VALID_ARGS["discord-voice"]

        def replace(index, token):
            args = list(base)
            args[index] = token
            return args

        cases = {
            "new": [*base, "--new"],
            "two-udp": [*base, "--filter-udp=443"],
            "no-udp": base[1:],
            "bad-ports": replace(0, "--filter-udp=80"),
            "tcp": [*base, "--filter-tcp=443"],
            "hostlist": [*base, "--hostlist=/opt/etc/nfqws2/lists/user.list"],
            "l7": replace(1, "--filter-l7=stun"),
            "payload": replace(2, "--payload=stun"),
            "two-lua": [*base, "--lua-desync=fake:blob=discord_udp:repeats=2"],
            "repeats-zero": replace(3, "--lua-desync=fake:blob=discord_udp:repeats=0"),
            "repeats-100": replace(3, "--lua-desync=fake:blob=discord_udp:repeats=100"),
            "other-blob": replace(3, "--lua-desync=fake:blob=stun:repeats=6"),
            "multisplit": replace(3, "--lua-desync=multisplit:pos=1"),
        }
        for name, args in cases.items():
            with self.subTest(case=name):
                self.assertRejected(
                    "Discord Voice профиль выходит за безопасные UDP-границы",
                    make_candidate("discord-voice", args=args),
                )

    def test_voice_ports_follow_the_recorded_udp_range(self):
        # D11: the engine accepts 50000-65535 only with range=wide.
        conf = self.root / "nfqws2.conf"
        self.patch(NFQWS_CONFIG=conf)
        wide = make_report("discord-voice", make_candidate(
            "discord-voice", args=["--filter-udp=50000-65535"] + VALID_ARGS["discord-voice"][1:],
        ))
        for text, accepted in (
            ("", False),
            ("# Discord UDP: strategy=flowseal, range=narrow.\nUDP_PORTS=50000:65535\n", False),
            ("# Discord UDP: strategy=flowseal, range=wide.\n", True),
            # Configs without the line: inferred from UDP_PORTS like the engine.
            ("UDP_PORTS=443,19294:19344,50000:65535\n", True),
            ("UDP_PORTS=443,19294:19344,50000:50100\n", False),
        ):
            with self.subTest(text=text):
                conf.write_text(text, encoding="utf-8")
                if accepted:
                    self.assertEqual(self.ns["validate_report"](wide)["service"], "discord-voice")
                else:
                    with self.assertRaisesRegex(ValueError, "range=narrow"):
                        self.ns["validate_report"](wide)
                self.assertEqual(self.ns["validate_report"](make_report("discord-voice"))["service"], "discord-voice")
        conf.unlink()
        with self.assertRaisesRegex(ValueError, r"range=narrow \(до 50100\)"):
            self.ns["validate_report"](wide)

    def test_rejects_candidate_id_mismatch(self):
        candidate = make_candidate(candidate_id="0" * 12)
        self.assertRejected("candidate_id не соответствует содержимому", candidate)
        tampered = make_candidate()
        tampered["family"] = "other-family"
        self.assertRejected("candidate_id не соответствует содержимому", tampered)

    def test_rejects_bad_report_metadata(self):
        candidate = make_candidate()
        for field, limit in (("repository", 200), ("ref", 200), ("commit", 128), ("created_utc", 80)):
            with self.subTest(field=field):
                self.assertRejected(f"некорректное поле {field}", candidate, {field: "x" * (limit + 1)})
                self.assertRejected(f"некорректное поле {field}", candidate, {field: "a\nb"})
                self.assertRejected(f"некорректное поле {field}", candidate, {field: None})
        for seed in (True, -1, 4294967296, "5", 1.5):
            with self.subTest(seed=seed):
                self.assertRejected("некорректный search_seed", candidate, {"search_seed": seed})

    def test_validate_report(self):
        validate = self.ns["validate_report"]
        for value in ([], "report", None, 1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "корень отчёта должен быть JSON-объектом"):
                    validate(value)
        for version in (2, 0, "1", None):
            with self.subTest(report_format=version):
                with self.assertRaisesRegex(ValueError, "неподдерживаемая версия отчёта"):
                    validate(make_report(report_format=version))
        report = make_report()
        del report["report_format"]
        self.assertEqual(validate(report)["service"], "discord-tcp")
        with self.assertRaisesRegex(ValueError, "сервис отчёта не совпадает с кандидатом"):
            validate(dict(make_report("discord-tcp"), service="youtube"))
        missing_service = make_report()
        del missing_service["service"]
        with self.assertRaisesRegex(ValueError, "сервис отчёта не совпадает"):
            validate(missing_service)
        with self.assertRaisesRegex(ValueError, "нет найденного кандидата"):
            validate(make_report(found=None))

    def test_validate_report_survives_json_round_trip(self):
        report = json.loads(json.dumps(make_report("youtube")))
        profile = self.ns["validate_report"](report)
        again = self.ns["validate_candidate"](profile, profile["report"])
        self.assertEqual(again, profile)


class TunerRequestTests(PanelTestCase):
    def validate(self, body):
        return self.ns["validate_tuner_request"](body)

    def assertRejected(self, pattern, body):
        with self.assertRaisesRegex(ValueError, pattern):
            self.validate(body)

    def test_defaults(self):
        with mock.patch.object(self.ns["secrets"], "randbits", return_value=777) as randbits:
            settings = self.validate({"service": "youtube"})
        randbits.assert_called_once_with(32)
        self.assertEqual(
            settings,
            {
                "service": "youtube",
                "mix_level": "safe",
                "max_candidates": 32,
                "client_ip": "",
                "search_seed": 777,
                "source_file": None,
                "voice_auto": False,
                "voice_traffic": False,
            },
        )

    def test_explicit_values(self):
        settings = self.validate(
            {
                "service": "discord-voice",
                "mix_level": "extended",
                "max_candidates": 64,
                "client_ip": "192.168.2.10",
                "search_seed": "4294967295",
            }
        )
        self.assertEqual(
            settings,
            {
                "service": "discord-voice",
                "mix_level": "extended",
                "max_candidates": 64,
                "client_ip": "192.168.2.10",
                "search_seed": 4294967295,
                "source_file": None,
                "voice_auto": False,
                "voice_traffic": False,
            },
        )
        for mix in ("off", "safe", "extended"):
            self.assertEqual(self.validate({"service": "discord-tcp", "mix_level": mix, "search_seed": 0})["mix_level"], mix)
        self.assertEqual(self.validate({"service": "youtube", "max_candidates": 1, "search_seed": 5})["max_candidates"], 1)

    def test_source_file(self):
        body = {"service": "youtube", "search_seed": 1}
        self.assertEqual(
            self.validate({**body, "source_file": "general (ALT3).bat"})["source_file"],
            "general (ALT3).bat",
        )
        self.assertIsNone(self.validate({**body, "source_file": ""})["source_file"])
        self.assertIsNone(self.validate({**body, "source_file": None})["source_file"])
        for bad in ("service.bat", "../general.bat", "general;x.bat", "general" + "a" * 160 + ".bat", 5, ["general.bat"]):
            with self.subTest(bad=bad):
                self.assertRejected("general\\*\\.bat", {**body, "source_file": bad})

    def test_voice_auto(self):
        body = {"service": "discord-voice", "client_ip": "192.168.2.10", "search_seed": 1}
        self.assertIs(self.validate({**body, "voice_auto": True})["voice_auto"], True)
        self.assertRejected("true или false", {**body, "voice_auto": "yes"})
        self.assertRejected("только для Discord Voice", {"service": "youtube", "voice_auto": True})

    def test_voice_traffic(self):
        body = {"service": "discord-voice", "client_ip": "192.168.2.10", "search_seed": 1}
        self.assertIs(self.validate({**body, "voice_traffic": True})["voice_traffic"], True)
        self.assertRejected("true или false", {**body, "voice_traffic": 1})
        self.assertRejected("только для Discord Voice", {"service": "youtube", "voice_traffic": True})
        self.assertRejected("один способ", {**body, "voice_traffic": True, "voice_auto": True})

    def test_empty_seed_is_randomized(self):
        with mock.patch.object(self.ns["secrets"], "randbits", return_value=9):
            self.assertEqual(self.validate({"service": "youtube", "search_seed": ""})["search_seed"], 9)
            self.assertEqual(self.validate({"service": "youtube", "search_seed": None})["search_seed"], 9)

    def test_rejections(self):
        cases = [
            ([], "ожидается JSON-объект"),
            ("youtube", "ожидается JSON-объект"),
            ({"service": "youtube", "extra": 1}, "неизвестные параметры подбора"),
            ({}, "неподдерживаемый сервис"),
            ({"service": "whatsapp"}, "неподдерживаемый сервис"),
            # Telegram autotune was removed with its Zapret mode.
            ({"service": "telegram"}, "неподдерживаемый сервис"),
            ({"service": "youtube", "mix_level": "max"}, "неподдерживаемый уровень смешивания"),
            ({"service": "youtube", "max_candidates": 0}, "число кандидатов"),
            ({"service": "youtube", "max_candidates": 65}, "число кандидатов"),
            ({"service": "youtube", "max_candidates": True}, "число кандидатов"),
            ({"service": "youtube", "max_candidates": "8"}, "число кандидатов"),
            ({"service": "youtube", "max_candidates": 8.0}, "число кандидатов"),
            ({"service": "youtube", "client_ip": 5}, "некорректный client_ip"),
            ({"service": "discord-voice", "client_ip": "1" * 46}, "некорректный client_ip"),
            ({"service": "discord-voice"}, "для Voice нужен LAN IPv4 компьютера"),
            ({"service": "discord-voice", "client_ip": "pc.lan"}, "для Voice нужен LAN IPv4 компьютера"),
            ({"service": "discord-voice", "client_ip": "8.8.8.8"}, "для Voice нужен частный LAN IPv4"),
            ({"service": "discord-voice", "client_ip": "fd00::1"}, "для Voice нужен частный LAN IPv4"),
            ({"service": "youtube", "client_ip": "192.168.2.10"}, "client_ip допустим только для Discord Voice"),
            ({"service": "discord-tcp", "client_ip": "192.168.2.10"}, "client_ip допустим только"),
            ({"service": "youtube", "search_seed": -1}, "seed должен быть"),
            ({"service": "youtube", "search_seed": "-1"}, "seed должен быть"),
            ({"service": "youtube", "search_seed": "12a"}, "seed должен быть"),
            ({"service": "youtube", "search_seed": 4294967296}, "seed должен быть"),
            ({"service": "youtube", "search_seed": "4294967296"}, "seed должен быть"),
            ({"service": "youtube", "search_seed": True}, "seed должен быть"),
            ({"service": "youtube", "search_seed": 1.0}, "seed должен быть"),
        ]
        for body, pattern in cases:
            with self.subTest(body=body):
                self.assertRejected(pattern, body)


class FileHelperTests(PanelTestCase):
    def test_safe_json_file(self):
        safe = self.ns["safe_json_file"]
        good = self.root / "good.json"
        good.write_text('{"a": 1}', encoding="utf-8")
        self.assertEqual(safe(good), {"a": 1})

        link = self.root / "link.json"
        link.symlink_to(good)
        with self.assertRaisesRegex(ValueError, "необычный тип файла"):
            safe(link)
        with self.assertRaisesRegex(ValueError, "необычный тип файла"):
            safe(self.root)

        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "некорректный размер файла"):
            safe(empty)
        with self.assertRaisesRegex(ValueError, "некорректный размер файла"):
            safe(good, maximum=3)
        self.assertEqual(safe(good, maximum=good.stat().st_size), {"a": 1})

        listing = self.root / "list.json"
        listing.write_text("[1, 2]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ожидается JSON-объект"):
            safe(listing)

        broken = self.root / "broken.json"
        broken.write_text("{nope", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            safe(broken)
        with self.assertRaises(FileNotFoundError):
            safe(self.root / "missing.json")

    def test_atomic_text_creates_and_replaces(self):
        target = self.root / "nested" / "dir" / "state.json"
        self.ns["atomic_text"](target, "first\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.ns["atomic_text"](target, "second\n", mode=0o644)
        self.assertEqual(target.read_text(encoding="utf-8"), "second\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(path.name for path in target.parent.iterdir()), ["state.json"])

    def test_atomic_text_replaces_symlink_instead_of_following_it(self):
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        target = self.root / "target.txt"
        target.symlink_to(outside)
        self.ns["atomic_text"](target, "new\n")
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_current_routes_fast(self):
        config = self.root / "nfqws2.conf"
        self.patch(NFQWS_CONFIG=config)
        unknown = {
            "discord-tcp": "unknown",
            "discord-voice": "unknown",
            "youtube": "unknown",
            "telegram": "unknown",
        }
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# nothing here\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# Active routes: Discord=vpn, YouTube=zapret.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text(
            "NFQWS_ARGS=x\n# Active routes: Discord=zapret, YouTube=vless.\nother\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.ns["current_routes_fast"](),
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "vless", "telegram": "unmanaged"},
        )
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.ns["current_routes_fast"](),
            {"discord-tcp": "direct", "discord-voice": "zapret", "youtube": "vless", "telegram": "unmanaged"},
        )
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=zapret.\n",
            encoding="utf-8",
        )
        # Zapret is no longer selectable for Telegram, but an old header still reads.
        self.assertEqual(self.ns["current_routes_fast"]()["telegram"], "zapret")
        # Only Telegram may be unmanaged.
        config.write_text(
            "# Active routes: DiscordTCP=unmanaged, DiscordVoice=zapret, YouTube=vless, Telegram=direct.\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=proxy.\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# Active routes: DiscordTCP=direct, YouTube=vless.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("  # Active routes: Discord=direct, YouTube=direct.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)

    def test_route_pid_parsing(self):
        pid_file = self.root / "worker.pid"
        self.patch(ROUTE_PID=pid_file)
        self.assertIsNone(self.ns["route_pid"]())
        for raw, expected in (("123\n", 123), ("  456  ", 456), ("1", None), ("0", None), ("-5", None), ("abc", None), ("", None)):
            with self.subTest(raw=raw):
                pid_file.write_text(raw, encoding="ascii")
                self.assertEqual(self.ns["route_pid"](), expected)

    def test_process_alive(self):
        self.assertTrue(self.ns["process_alive"](os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        self.assertFalse(self.ns["process_alive"](child.pid))

    def test_route_process_alive_requires_route_job_cmdline(self):
        self.patch(__file__=str(self.root / "app.py"))
        self.assertFalse(self.ns["route_process_alive"](os.getpid()))
        self.assertFalse(self.ns["tuner_process_alive"](os.getpid()))
        self.assertFalse(self.ns["diagnostic_process_alive"](os.getpid()))


class SnapshotTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.snapshots = self.root / "snapshots"
        self.snapshots.mkdir()
        self.patch(SNAPSHOT_DIR=self.snapshots)

    def make_snapshot(self, parent, name, manifest=True, state=True):
        path = parent / name
        path.mkdir(parents=True)
        if state:
            (path / "STATE.tsv").write_text("PURPOSE\tpre-apply\n", encoding="utf-8")
        if manifest:
            (path / "MANIFEST").write_text("fixture\n", encoding="utf-8")
        return path

    def test_safe_snapshot_accepts_valid_directory(self):
        path = self.make_snapshot(self.snapshots, "20260815-010203-42")
        self.assertTrue(self.ns["safe_snapshot"](path))

    def test_safe_snapshot_rejections(self):
        safe = self.ns["safe_snapshot"]
        valid = self.make_snapshot(self.snapshots, "valid-1")
        link = self.snapshots / "link-1"
        link.symlink_to(valid, target_is_directory=True)
        self.assertFalse(safe(link))

        elsewhere = self.make_snapshot(self.root / "elsewhere", "valid-2")
        self.assertFalse(safe(elsewhere))
        nested = self.make_snapshot(valid, "nested-3")
        self.assertFalse(safe(nested))

        self.assertFalse(safe(self.make_snapshot(self.snapshots, "no-manifest", manifest=False)))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "no-state", state=False)))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "bad_name")))
        self.assertFalse(safe(self.make_snapshot(self.snapshots, "bad.name")))
        self.assertFalse(safe(self.snapshots / "missing"))

        regular = self.snapshots / "regular-file"
        regular.write_text("x", encoding="utf-8")
        self.assertFalse(safe(regular))

        (valid / "MANIFEST").unlink()
        (valid / "MANIFEST").mkdir()
        self.assertFalse(safe(valid))

    def test_safe_snapshot_missing_snapshot_dir(self):
        path = self.make_snapshot(self.snapshots, "valid-1")
        self.patch(SNAPSHOT_DIR=self.root / "absent")
        self.assertFalse(self.ns["safe_snapshot"](path))

    def test_parse_snapshot_from_output(self):
        parse = self.ns["parse_snapshot_from_output"]
        snapshot = self.make_snapshot(self.snapshots, "20260815-010203-42")
        self.assertEqual(parse(f"Snapshot created: {snapshot}\nApply complete."), str(snapshot))
        self.assertEqual(
            parse(f"log\nRescue snapshot of current state: {snapshot}\nRestore complete: x"),
            str(snapshot),
        )
        self.assertEqual(parse(f"Snapshot created: {snapshot}/STATE.tsv"), str(snapshot))

    def test_parse_snapshot_from_output_rejections(self):
        parse = self.ns["parse_snapshot_from_output"]
        outside = self.make_snapshot(self.root / "other", "20260815-010203-42")
        self.assertEqual(parse(f"Snapshot created: {outside}"), "")
        self.assertEqual(parse("Apply complete."), "")
        self.assertEqual(parse(""), "")
        self.assertEqual(parse(f"Snapshot: {self.snapshots}/20260815-010203-42"), "")
        self.assertEqual(parse(f"Snapshot created: {self.snapshots}/missing-1"), "")
        broken = self.make_snapshot(self.snapshots, "broken-1", manifest=False)
        self.assertEqual(parse(f"Snapshot created: {broken}"), "")
        self.assertEqual(parse(f"Snapshot created: {self.snapshots}/../etc"), "")


class RouteJobTests(PanelTestCase):
    JOB_ID = "0123456789abcdef"

    def setUp(self):
        super().setUp()
        job_dir = self.root / "route-job"
        self.patch(
            ROUTE_JOB_DIR=job_dir,
            ROUTE_STATE=job_dir / "state.json",
            ROUTE_PID=job_dir / "worker.pid",
            ROUTE_LOG=job_dir / "process.log",
            ROUTE_APPLY_LOG=job_dir / "apply.log",
            ROUTE_HISTORY_DIR=self.root / "history",
            SNAPSHOT_DIR=self.root / "snapshots",
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            __file__=str(self.root / "app.py"),
        )
        self.job_dir = job_dir

    def write_state(self, state):
        self.job_dir.mkdir(parents=True, exist_ok=True)
        self.ns["ROUTE_STATE"].write_text(json.dumps(state), encoding="utf-8")

    def read_state(self):
        return json.loads(self.ns["ROUTE_STATE"].read_text(encoding="utf-8"))

    def test_update_route_state(self):
        update = self.ns["update_route_state"]
        self.assertFalse(update(self.JOB_ID, status="running"))
        self.write_state({"job_id": "ffffffffffffffff", "status": "queued"})
        self.assertFalse(update(self.JOB_ID, status="running"))
        self.assertEqual(self.read_state(), {"job_id": "ffffffffffffffff", "status": "queued"})
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        self.assertTrue(update(self.JOB_ID, status="running", progress=10))
        self.assertEqual(self.read_state(), {"job_id": self.JOB_ID, "status": "running", "progress": 10})
        self.ns["ROUTE_STATE"].write_text("{broken", encoding="utf-8")
        self.assertFalse(update(self.JOB_ID, status="running"))

    def test_history_write_update_and_read(self):
        entry = {"job_id": self.JOB_ID, "status": "running", "created_utc": "2026-08-15T00:00:00Z"}
        self.ns["write_history"](entry)
        path = self.root / "history" / f"{self.JOB_ID}.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), entry)
        self.assertEqual((self.root / "history").stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.ns["update_history"](self.JOB_ID, status="completed"))
        self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["status"], "completed")
        self.assertFalse(self.ns["update_history"]("ffffffffffffffff", status="x"))
        self.assertFalse(self.ns["update_history"]("not-a-job", status="x"))
        with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
            self.ns["write_history"]({"job_id": "../x"})

    def test_history_id_mismatch(self):
        other = "ffffffffffffffff"
        history = self.root / "history"
        history.mkdir()
        (history / f"{other}.json").write_text(json.dumps({"job_id": self.JOB_ID}), encoding="utf-8")
        self.assertFalse(self.ns["update_history"](other, status="x"))
        with self.assertRaisesRegex(ValueError, "ID записи истории не совпадает"):
            self.ns["read_history_item"](other)

    def test_route_history_reports_corrupt_entries(self):
        history = self.root / "history"
        history.mkdir()
        (history / "aaaaaaaaaaaaaaaa.json").write_text(
            json.dumps({"job_id": "aaaaaaaaaaaaaaaa", "created_utc": "2026-08-15T01:00:00Z", "snapshot": ""}),
            encoding="utf-8",
        )
        (history / "bbbbbbbbbbbbbbbb.json").write_text(json.dumps({"job_id": "cccccccccccccccc"}), encoding="utf-8")
        (history / "dddddddddddddddd.json").write_text("{broken", encoding="utf-8")
        (history / "ignored.json").write_text("{}", encoding="utf-8")
        items = {item["job_id"]: item for item in self.ns["route_history"]()}
        self.assertEqual(set(items), {"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "dddddddddddddddd"})
        self.assertFalse(items["aaaaaaaaaaaaaaaa"]["rollback_available"])
        for job_id in ("bbbbbbbbbbbbbbbb", "dddddddddddddddd"):
            self.assertEqual(items[job_id]["status"], "error")
            self.assertFalse(items[job_id]["rollback_available"])
            self.assertIn("история повреждена", items[job_id]["error"])
        self.assertIn("ID файла не совпадает", items["bbbbbbbbbbbbbbbb"]["error"])

    def test_route_history_keeps_newest_entries_beyond_200_files(self):
        history = self.root / "history"
        history.mkdir()
        for index in range(210):
            job_id = f"{index:016x}"
            path = history / f"{job_id}.json"
            path.write_text(
                json.dumps({"job_id": job_id, "created_utc": f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z"}),
                encoding="utf-8",
            )
            os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))

        class OldestFirst:
            """glob() order is arbitrary; return the oldest files first."""

            def glob(self, pattern):
                return sorted(history.glob(pattern))

        self.patch(ROUTE_HISTORY_DIR=OldestFirst())
        items = self.ns["route_history"]()
        self.assertEqual(len(items), self.ns["MAX_HISTORY_ITEMS"])
        self.assertEqual(items[0]["job_id"], f"{209:016x}")
        self.assertEqual(items[-1]["job_id"], f"{210 - self.ns['MAX_HISTORY_ITEMS']:016x}")

    def test_route_history_missing_directory(self):
        self.assertEqual(self.ns["route_history"](), [])

    def test_route_status_idle_without_state(self):
        status = self.ns["route_status"]()
        self.assertEqual(
            status,
            {"ok": True, "status": "idle", "active": False, "output": "", "log_tail": []},
        )

    def test_route_status_marks_stale_running_job_failed(self):
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running"})
        self.write_state({"job_id": self.JOB_ID, "status": "running", "progress": 45})
        self.ns["ROUTE_APPLY_LOG"].write_text("line 1\n" + "x" * 1500 + "\n", encoding="utf-8")
        status = self.ns["route_status"]()
        self.assertTrue(status["ok"])
        self.assertFalse(status["active"])
        self.assertEqual(status["status"], "failed")
        self.assertIs(status["result_ok"], False)
        self.assertEqual(status["error"], "процесс переключения завершился неожиданно")
        self.assertEqual(status["log_tail"], ["line 1", "x" * 1000])
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(history["status"], "failed")
        self.assertIs(history["result_ok"], False)
        self.assertEqual(history["error"], "процесс переключения завершился неожиданно")
        self.assertIn("finished_utc", history)

    def test_route_status_keeps_existing_error_and_ignores_pid_of_other_process(self):
        self.write_state({"job_id": self.JOB_ID, "status": "queued", "error": "boom"})
        self.ns["ROUTE_PID"].write_text(f"{os.getpid()}\n", encoding="ascii")
        status = self.ns["route_status"]()
        self.assertFalse(status["active"])
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["error"], "boom")

    def test_route_status_completed_and_corrupt_state(self):
        self.write_state({"job_id": self.JOB_ID, "status": "completed", "ok": False})
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "completed")
        self.assertTrue(status["ok"])
        self.ns["ROUTE_STATE"].write_text("[]", encoding="utf-8")
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "error")
        self.assertIn("state:", status["error"])
        link_target = self.root / "outside.log"
        link_target.write_text("secret\n", encoding="utf-8")
        self.ns["ROUTE_APPLY_LOG"].symlink_to(link_target)
        self.assertEqual(self.ns["route_status"]()["log_tail"], [])

    def test_clear_previous_route_job_removes_files_and_symlinks(self):
        self.job_dir.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        self.ns["ROUTE_STATE"].symlink_to(outside)
        self.ns["ROUTE_PID"].write_text("123\n", encoding="ascii")
        self.ns["ROUTE_APPLY_LOG"].symlink_to(self.root / "dangling")
        keep = self.job_dir / "unrelated.txt"
        keep.write_text("x", encoding="utf-8")
        self.ns["clear_previous_route_job"]()
        for name in ("ROUTE_STATE", "ROUTE_PID", "ROUTE_LOG", "ROUTE_APPLY_LOG"):
            self.assertFalse(os.path.lexists(self.ns[name]), name)
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.assertTrue(keep.exists())
        self.assertEqual(self.job_dir.stat().st_mode & 0o777, 0o700)

    def test_clear_previous_route_job_creates_directory(self):
        self.ns["clear_previous_route_job"]()
        self.assertTrue(self.job_dir.is_dir())

    def test_clear_previous_route_job_refuses_directory(self):
        self.job_dir.mkdir()
        self.ns["ROUTE_LOG"].mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге задания"):
            self.ns["clear_previous_route_job"]()
        self.assertTrue(self.ns["ROUTE_LOG"].is_dir())

    def test_ensure_route_job_available(self):
        ensure = self.ns["ensure_route_job_available"]
        idle = {"tuner_active": lambda: False, "diagnostic_active": lambda: False, "route_active": lambda: False}
        with mock.patch.dict(self.ns, idle):
            ensure()
        for name, message in (
            ("tuner_active", "во время подбора"),
            ("diagnostic_active", "во время диагностики"),
            ("route_active", "уже выполняется"),
        ):
            with self.subTest(active=name):
                with mock.patch.dict(self.ns, {**idle, name: lambda: True}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        ensure()

    def test_start_route_job_builds_state(self):
        captured = []

        def fake_launch(state, worker_args):
            captured.append((dict(state), list(worker_args)))
            return state

        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            current_routes_fast=lambda: {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
            launch_route_worker=fake_launch,
        )
        state = self.ns["start_route_job"]("discord-voice", "vpn")
        self.assertRegex(state["job_id"], r"^[0-9a-f]{16}$")
        self.assertEqual(state["operation"], "switch")
        self.assertEqual(state["status"], "queued")
        self.assertEqual(
            state["before_routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
        )
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "zapret", "discord-voice": "vless", "youtube": "direct"},
        )
        self.assertEqual(captured[0][1], ["switch", "discord-voice", "vpn"])
        state = self.ns["start_route_job"]("youtube", "zapret")
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "zapret"},
        )
        # The "discord" shorthand switches both Discord routes.
        state = self.ns["start_route_job"]("discord", "direct")
        self.assertEqual(
            state["requested_routes"],
            {"discord-tcp": "direct", "discord-voice": "direct", "youtube": "direct"},
        )
        with self.assertRaises(ValueError):
            self.ns["start_route_job"]("discord-tcp", "custom")
        self.assertEqual(len(captured), 3)

    def test_start_history_rollback_validation(self):
        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            launch_route_worker=lambda state, args: (state, args),
        )
        rollback = self.ns["start_history_rollback"]
        with self.assertRaises(FileNotFoundError):
            rollback(self.JOB_ID)
        with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
            rollback("bad")
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running"})
        with self.assertRaisesRegex(ValueError, "только для завершённой или прерванной операции"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "failed"})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "completed", "snapshot": ""})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "completed", "snapshot": 5})
        with self.assertRaisesRegex(ValueError, "snapshot этой операции отсутствует"):
            rollback(self.JOB_ID)
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["write_history"](
            {
                "job_id": self.JOB_ID,
                "status": "completed",
                "snapshot": str(snapshot),
                "before_routes": {"discord": "direct", "youtube": "direct"},
            }
        )
        state, args = rollback(self.JOB_ID)
        self.assertEqual(state["operation"], "rollback")
        self.assertEqual(state["rollback_of"], self.JOB_ID)
        self.assertEqual(state["target_snapshot"], str(snapshot))
        self.assertEqual(state["requested_routes"], {"discord": "direct", "youtube": "direct"})
        self.assertEqual(args, ["rollback", self.JOB_ID, str(snapshot)])
        # D10: an interrupted (failed) operation with its snapshot can be rolled back.
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "failed", "snapshot": str(snapshot)})
        state, args = rollback(self.JOB_ID)
        self.assertEqual(args, ["rollback", self.JOB_ID, str(snapshot)])

    def test_route_status_keeps_snapshot_of_a_job_that_died(self):
        # D10: the worker died after "Snapshot created:"; the snapshot is kept,
        # the failure is recorded once and rollback becomes available.
        snapshot = self.root / "snapshots" / "20261022-001904-29825"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "running", "created_utc": "2026-10-22T00:19:00Z"})
        self.write_state({"job_id": self.JOB_ID, "status": "running", "progress": 65})
        self.ns["ROUTE_APPLY_LOG"].write_text(
            f"Snapshot created: {snapshot}\nPatching Xray routing: x\nRestarting XKeen...\n", encoding="utf-8",
        )
        status = self.ns["route_status"]()
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["snapshot"], str(snapshot))
        state = self.read_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["snapshot"], str(snapshot))
        self.assertFalse(state["active"])
        [item] = self.ns["route_history"]()
        self.assertEqual(item["status"], "failed")
        self.assertEqual(item["snapshot"], str(snapshot))
        self.assertTrue(item["rollback_available"])
        self.assertIn("Snapshot created:", item["output_tail"])
        finished = item["finished_utc"]
        with mock.patch.dict(self.ns, {"utc_now": lambda: "2099-01-01T00:00:00Z"}):
            self.assertEqual(self.ns["route_status"]()["finished_utc"], finished)
        self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["finished_utc"], finished)

    def test_route_status_does_not_fail_a_job_that_is_being_started(self):
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        with self.ns["JOB_START_LOCK"]:
            self.assertEqual(self.ns["route_status"]()["status"], "queued")
        self.assertEqual(self.read_state()["status"], "queued")
        self.assertEqual(self.ns["route_status"]()["status"], "failed")

    def test_launch_route_worker_writes_state_history_and_pid(self):
        process = mock.Mock(pid=4321)
        state = {
            "ok": True,
            "job_id": self.JOB_ID,
            "operation": "switch",
            "status": "queued",
            "stage_label": "В очереди",
            "progress": 0,
            "active": True,
            "output": "",
            "created_utc": "2026-08-15T00:00:00Z",
        }
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen:
            result = self.ns["launch_route_worker"](dict(state), ["switch", "discord", "vpn"])
        command = popen.call_args.args[0]
        self.assertEqual(
            command,
            [sys.executable, str(self.root / "app.py"), "--route-job", self.JOB_ID, "switch", "discord", "vpn"],
        )
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(result["pid"], 4321)
        self.assertEqual(self.ns["ROUTE_PID"].read_text(encoding="ascii"), "4321\n")
        self.assertEqual(self.read_state()["status"], "queued")
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(
            history,
            {
                "job_id": self.JOB_ID,
                "operation": "switch",
                "status": "queued",
                "created_utc": "2026-08-15T00:00:00Z",
            },
        )

    def test_launch_route_worker_records_spawn_failure(self):
        state = {"job_id": self.JOB_ID, "status": "queued"}
        with mock.patch.object(self.ns["subprocess"], "Popen", side_effect=OSError("no exec")):
            with self.assertRaisesRegex(OSError, "no exec"):
                self.ns["launch_route_worker"](dict(state), ["switch", "discord", "vpn"])
        saved = self.read_state()
        self.assertEqual(saved["status"], "failed")
        self.assertIs(saved["active"], False)
        self.assertEqual(saved["error"], "no exec")
        history = self.ns["read_history_item"](self.JOB_ID)
        self.assertEqual(history["status"], "failed")
        self.assertFalse(self.ns["ROUTE_PID"].exists())

    def test_run_route_job_rejects_bad_arguments(self):
        for operation, subject, target in (
            ("bogus", "discord", "vpn"),
            ("switch", "discord", "custom"),
            ("rollback", "bad-id", "/x"),
            ("rollback", "ffffffffffffffff", str(self.root / "snapshots" / "missing")),
        ):
            with self.subTest(operation=operation, subject=subject, target=target):
                self.ns["write_history"]({"job_id": self.JOB_ID, "status": "queued"})
                self.write_state({"job_id": self.JOB_ID, "status": "queued"})
                with mock.patch.dict(self.ns, {"run_route_command": mock.Mock(side_effect=AssertionError)}):
                    code = self.ns["run_route_job"](self.JOB_ID, operation, subject, target)
                self.assertEqual(code, 2)
                state = self.read_state()
                self.assertEqual(state["status"], "failed")
                self.assertEqual(state["stage"], "failed")
                self.assertEqual(state["stage_label"], "Ошибка запуска")
                self.assertEqual(self.ns["read_history_item"](self.JOB_ID)["status"], "failed")

    def test_run_route_job_stops_when_state_belongs_to_other_job(self):
        self.write_state({"job_id": "ffffffffffffffff", "status": "queued"})
        runner = mock.Mock(side_effect=AssertionError("must not run"))
        with mock.patch.dict(self.ns, {"run_route_command": runner}):
            self.assertEqual(self.ns["run_route_job"](self.JOB_ID, "switch", "discord", "vpn"), 2)
        runner.assert_not_called()

    def test_run_route_job_switch_success_and_failure(self):
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.ns["NFQWS_CONFIG"].write_text("# Active routes: Discord=vless, YouTube=direct.\n", encoding="utf-8")
        for ok, code, status, label in ((True, 0, "completed", "Готово"), (False, 3, "failed", "Ошибка и откат")):
            with self.subTest(ok=ok):
                self.ns["write_history"]({"job_id": self.JOB_ID, "status": "queued"})
                self.write_state({"job_id": self.JOB_ID, "status": "queued"})
                runner = mock.Mock(return_value={"ok": ok, "code": code, "output": f"Snapshot created: {snapshot}\ndone"})
                with mock.patch.dict(self.ns, {"run_route_command": runner}):
                    result = self.ns["run_route_job"](self.JOB_ID, "switch", "discord", "vpn")
                self.assertEqual(result, code)
                command, job_id, operation = runner.call_args.args
                self.assertEqual(command[0], "/bin/sh")
                self.assertEqual(command[2:], ["discord", "vpn", "--core", "auto", "--yes-router"])
                self.assertEqual((job_id, operation), (self.JOB_ID, "switch"))
                state = self.read_state()
                self.assertEqual(state["status"], status)
                self.assertEqual(state["stage_label"], label)
                self.assertEqual(state["progress"], 100)
                self.assertEqual(state["snapshot"], str(snapshot))
                self.assertEqual(
                    state["after_routes"],
                    {"discord-tcp": "vless", "discord-voice": "vless", "youtube": "direct", "telegram": "unmanaged"},
                )
                self.assertIn("started_utc", state)
                history = self.ns["read_history_item"](self.JOB_ID)
                self.assertEqual(history["status"], status)
                self.assertEqual(history["code"], code)
                self.assertTrue(history["output_tail"].endswith("done"))

    def test_run_route_command_tracks_stage_and_exit_code(self):
        self.job_dir.mkdir()
        self.write_state({"job_id": self.JOB_ID, "status": "running"})
        script = (
            "import sys, time; print('Snapshot created: /fixture', flush=True); "
            "time.sleep(1.5); print('done'); sys.exit(3)"
        )
        result = self.ns["run_route_command"]([sys.executable, "-c", script], self.JOB_ID, "switch")
        self.assertEqual(result, {"ok": False, "code": 3, "output": "Snapshot created: /fixture\ndone"})
        state = self.read_state()
        self.assertEqual((state["stage"], state["progress"]), ("snapshot", 25))
        self.assertEqual(
            self.ns["ROUTE_APPLY_LOG"].read_text(encoding="utf-8").strip(),
            "Snapshot created: /fixture\ndone",
        )

    def test_run_route_command_timeout_terminates_process(self):
        self.job_dir.mkdir()
        result = self.ns["run_route_command"](
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
            self.JOB_ID,
            "switch",
            timeout=0,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertTrue(result["output"].startswith("Команда превысила таймаут"))
        self.assertIn("started", result["output"])

    def test_run_route_job_rollback_command(self):
        snapshot = self.root / "snapshots" / "20260815-010203-42"
        snapshot.mkdir(parents=True)
        (snapshot / "STATE.tsv").write_text("x\n", encoding="utf-8")
        (snapshot / "MANIFEST").write_text("x\n", encoding="utf-8")
        self.write_state({"job_id": self.JOB_ID, "status": "queued"})
        runner = mock.Mock(return_value={"ok": True, "code": 0, "output": ""})
        with mock.patch.dict(self.ns, {"run_route_command": runner}):
            self.assertEqual(self.ns["run_route_job"](self.JOB_ID, "rollback", "ffffffffffffffff", str(snapshot)), 0)
        command = runner.call_args.args[0]
        self.assertEqual(command[2:], ["--rollback-snapshot", str(snapshot), "--yes-router"])
        self.assertEqual(self.read_state()["snapshot"], "")


class TunerAndDiagnosticJobTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        tuner = self.root / "tuner"
        diagnostics = self.root / "diagnostics"
        self.patch(
            TUNER_JOB_DIR=tuner,
            TUNER_STATE=tuner / "state.json",
            TUNER_RESULT=tuner / "result-report.json",
            TUNER_VERDICT=tuner / "verdict.txt",
            TUNER_PID=tuner / "panel-launch.pid",
            DIAGNOSTIC_JOB_DIR=diagnostics,
            DIAGNOSTIC_STATE=diagnostics / "state.json",
            DIAGNOSTIC_PID=diagnostics / "panel-launch.pid",
            DIAGNOSTIC_LOG=diagnostics / "process.log",
        )
        self.tuner = tuner
        self.diagnostics = diagnostics

    def write_tuner_state(self, state):
        self.tuner.mkdir(exist_ok=True)
        self.ns["TUNER_STATE"].write_text(json.dumps(state), encoding="utf-8")

    def test_submit_voice_verdict(self):
        submit = self.ns["submit_voice_verdict"]
        with mock.patch.dict(self.ns, {"tuner_active": lambda: True}):
            with self.assertRaises(FileNotFoundError):
                submit(True)
        self.write_tuner_state({"status": "awaiting_voice"})
        with mock.patch.dict(self.ns, {"tuner_active": lambda: False}):
            with self.assertRaisesRegex(RuntimeError, "сейчас ответ Voice не ожидается"):
                submit(True)
        self.write_tuner_state({"status": "running"})
        with mock.patch.dict(self.ns, {"tuner_active": lambda: True}):
            with self.assertRaisesRegex(RuntimeError, "сейчас ответ Voice не ожидается"):
                submit(True)
        self.write_tuner_state({"status": "awaiting_voice"})
        with mock.patch.dict(self.ns, {"tuner_active": lambda: True}):
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

    def test_cancel_jobs_without_active_process(self):
        with self.assertRaisesRegex(RuntimeError, "активного подбора нет"):
            self.ns["cancel_tuner_job"]()
        with self.assertRaisesRegex(RuntimeError, "активной диагностики нет"):
            self.ns["cancel_diagnostic_job"]()

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

    def test_clear_previous_diagnostic_job(self):
        self.diagnostics.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        self.ns["DIAGNOSTIC_STATE"].symlink_to(outside)
        self.ns["DIAGNOSTIC_LOG"].write_text("x", encoding="utf-8")
        (self.diagnostics / "payload-12.bin").write_bytes(b"x")
        (self.diagnostics / "payload-x.bin").write_bytes(b"x")
        (self.diagnostics / "payload-7.bin").symlink_to(outside)
        self.ns["clear_previous_diagnostic_job"]()
        self.assertEqual(
            sorted(path.name for path in self.diagnostics.iterdir()),
            ["payload-7.bin", "payload-x.bin"],
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.ns["DIAGNOSTIC_PID"].mkdir()
        with self.assertRaisesRegex(RuntimeError, "необычный объект в каталоге диагностики"):
            self.ns["clear_previous_diagnostic_job"]()

    def test_diagnostic_status_marks_stale_health_job_as_error(self):
        self.diagnostics.mkdir()
        self.ns["DIAGNOSTIC_STATE"].write_text(
            json.dumps({"kind": "health", "status": "running", "results": [{"name": "x"}]}),
            encoding="utf-8",
        )
        status = self.ns["diagnostic_status"]()
        self.assertEqual(status["status"], "error")
        self.assertEqual(status["error"], "процесс диагностики завершился неожиданно")
        self.assertFalse(status["active"])
        saved = json.loads(self.ns["DIAGNOSTIC_STATE"].read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "error")
        self.ns["DIAGNOSTIC_STATE"].write_text("[]", encoding="utf-8")
        status = self.ns["diagnostic_status"]()
        self.assertEqual(status["status"], "error")
        self.assertIn("state:", status["error"])

    def test_start_diagnostic_job_guards(self):
        start = self.ns["start_diagnostic_job"]
        idle = {"tuner_active": lambda: False, "diagnostic_active": lambda: False, "route_active": lambda: False}
        for name, message in (
            ("diagnostic_active", "диагностика уже выполняется"),
            ("tuner_active", "сначала завершите автоподбор"),
            ("route_active", "сначала завершите переключение маршрута"),
        ):
            with self.subTest(active=name):
                with mock.patch.dict(self.ns, {**idle, name: lambda: True}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        start("health")
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            start("unknown")

    def test_start_diagnostic_job_launches_worker(self):
        process = mock.Mock(pid=999)
        self.patch(
            tuner_active=lambda: False,
            diagnostic_active=lambda: False,
            route_active=lambda: False,
            DIAGNOSTICS=self.root / "xkeen_diagnostics.py",
        )
        with mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen:
            state = self.ns["start_diagnostic_job"]("health")
        command = popen.call_args.args[0]
        self.assertEqual(command[:4], [sys.executable, str(self.root / "xkeen_diagnostics.py"), "--kind", "health"])
        self.assertEqual(command[4:], ["--job-id", state["job_id"]])
        self.assertEqual(state["pid"], 999)
        self.assertEqual(self.ns["DIAGNOSTIC_PID"].read_text(encoding="ascii"), "999\n")
        saved = json.loads(self.ns["DIAGNOSTIC_STATE"].read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "queued")
        self.assertEqual(saved["kind"], "health")

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
                with mock.patch.dict(self.ns, {"run_command": lambda *_a, payload=payload, **_k: payload}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        self.ns["start_tuner_job"](settings)
        self.assertFalse(self.tuner.exists())
        with mock.patch.dict(self.ns, {"tuner_active": lambda: True}):
            with self.assertRaisesRegex(RuntimeError, "подбор уже выполняется"):
                self.ns["start_tuner_job"](settings)


class TunerSourceTests(PanelTestCase):
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
        with mock.patch.dict(self.ns, {"flowseal_source_module": lambda: module}):
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
        with mock.patch.dict(self.ns, {"flowseal_source_module": lambda: module}):
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
        self.patch(VOICE_ENDPOINT_FILE=path)
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
        with mock.patch.dict(self.ns, {"tuner_active": lambda: False, "run_command": lambda *_a, **_k: status}), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.assertEqual(self.ns["start_tuner_job"](settings), 4321)
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--service") + 1], "discord-voice")
        self.assertEqual(command[command.index("--client-ip") + 1], "192.168.2.60")
        self.assertEqual(command[-2:], ["--source-file", "general (ALT3).bat"])
        # Without a file the option is not passed at all.
        with mock.patch.dict(self.ns, {"tuner_active": lambda: False, "run_command": lambda *_a, **_k: status}), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            self.ns["start_tuner_job"]({**settings, "source_file": None})
        self.assertNotIn("--source-file", popen.call_args.args[0])


class MalformedStoredDataTests(PanelTestCase):
    """Valid-JSON but wrongly shaped files must not crash the panel."""

    def test_imported_profile_that_is_not_an_object(self):
        imported = self.root / "imported"
        imported.mkdir()
        (imported / "youtube.json").write_text("[]", encoding="utf-8")
        (imported / "discord-tcp.json").write_text('{"format": 1, "report": []}', encoding="utf-8")
        self.patch(IMPORTED_PROFILE_DIR=imported)
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertFalse(items["youtube"]["installed"])
        self.assertIn("error", items["youtube"])
        self.assertFalse(items["discord-tcp"]["installed"])
        self.assertIn("error", items["discord-tcp"])

    def test_report_metadata_must_be_an_object(self):
        report = make_report("youtube")
        report["found"]["candidate_id"] = report["found"]["candidate_id"]
        with self.assertRaisesRegex(ValueError, "report"):
            self.ns["validate_candidate"](report["found"], [])

    def test_route_history_with_non_string_dates(self):
        history = self.root / "history"
        history.mkdir()
        for job_id, created in (("aaaaaaaaaaaaaaaa", 5), ("bbbbbbbbbbbbbbbb", "2026-01-01T00:00:00Z"), ("cccccccccccccccc", None)):
            (history / f"{job_id}.json").write_text(
                json.dumps({"job_id": job_id, "created_utc": created}), encoding="utf-8"
            )
        self.patch(ROUTE_HISTORY_DIR=history, SNAPSHOT_DIR=self.root / "snapshots")
        items = self.ns["route_history"]()
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["job_id"], "bbbbbbbbbbbbbbbb")

    def test_config_health_with_wrongly_shaped_routing(self):
        self.patch(
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            XRAY_CONFIG_DIR=self.root,
            DISCORD_LIST=self.root / "user.list",
            DIAGNOSTICS=DIAGNOSTICS_MODULE,
        )
        for routing in ({"routing": []}, {"routing": {"rules": "x"}}):
            with self.subTest(routing=routing):
                (self.root / "05_routing.json").write_text(json.dumps(routing), encoding="utf-8")
                with mock.patch.dict(self.ns, {"run_command": lambda *_a, **_k: {"ok": True, "code": 0, "output": "1"}}):
                    health = self.ns["config_health"]()
                self.assertFalse(health["all_ok"])

    def test_flowseal_update_with_wrongly_shaped_commit(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"sha": "a" * 40, "commit": []}
        ).encode("utf-8")
        module = mock.Mock()
        module.read_source_cache.return_value = ([], "a" * 40)
        self.patch(
            FLOWSEAL_SOURCE_CACHE=self.root / "flowseal-sources.json",
            FLOWSEAL_UPDATE_STATE=self.root / "flowseal-update.json",
            flowseal_source_module=lambda: module,
        )
        with mock.patch.object(self.ns["urllib"].request, "urlopen", return_value=response):
            payload = self.ns["check_flowseal_update"]()
        self.assertEqual(payload["status"], "up_to_date")
        self.assertEqual(payload["latest_date"], "")


class JobStartRaceTests(PanelTestCase):
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

    def test_starts_are_refused_while_a_tuner_start_waits_for_status(self):
        status_requested = threading.Event()
        release_status = threading.Event()

        def slow_status(*_args, **_kwargs):
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
        real_thread = threading.Thread  # the panel's reaper thread is mocked below

        def first_start():
            try:
                self.ns["start_tuner_job"](settings)
            except Exception as exc:  # surfaced through the assertion below
                errors.append(exc)

        with mock.patch.dict(self.ns, {"run_command": slow_status}), \
                mock.patch.object(self.ns["subprocess"], "Popen", return_value=process) as popen, \
                mock.patch.object(self.ns["threading"], "Thread"):
            worker = real_thread(target=first_start)
            worker.start()
            self.assertTrue(status_requested.wait(5))
            try:
                with self.assertRaisesRegex(RuntimeError, "уже запускается"):
                    self.ns["start_tuner_job"](settings)
                with self.assertRaisesRegex(RuntimeError, "уже запускается"):
                    self.ns["start_diagnostic_job"]("health")
                with self.assertRaisesRegex(RuntimeError, "уже запускается"):
                    self.ns["start_route_job"]("youtube", "vpn")
            finally:
                release_status.set()
                worker.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(popen.call_count, 1)


class ProfileStoreTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.imported = self.root / "imported"
        self.versions = self.root / "versions"
        self.patch(IMPORTED_PROFILE_DIR=self.imported, PROFILE_VERSION_DIR=self.versions)

    def install(self, service, data, name=None):
        self.imported.mkdir(exist_ok=True)
        path = self.imported / f"{name or service}.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def add_version(self, service, profile, stamp="20260815T020304Z", reason="applied", candidate_id=None, suffix=""):
        directory = self.versions / service
        directory.mkdir(parents=True, exist_ok=True)
        version_id = f"{stamp}-{candidate_id or profile['candidate_id']}-{reason}-123{suffix}"
        (directory / f"{version_id}.json").write_text(json.dumps(profile), encoding="utf-8")
        return version_id

    def test_imported_profiles_empty(self):
        self.assertEqual(
            self.ns["imported_profiles"](),
            [
                {"service": "youtube", "installed": False},
                {"service": "discord-tcp", "installed": False},
                {"service": "discord-voice", "installed": False},
            ],
        )

    def test_imported_profiles_installed_and_errors(self):
        tcp = self.profile("discord-tcp")
        self.install("discord-tcp", tcp)
        self.install("youtube", tcp)
        voice = self.profile("discord-voice")
        voice["format"] = 2
        self.install("discord-voice", voice)
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        installed = items["discord-tcp"]
        self.assertTrue(installed["installed"])
        self.assertEqual(installed["candidate_id"], tcp["candidate_id"])
        self.assertEqual(installed["family"], "fixture-family")
        self.assertEqual(installed["source_name"], "general (ALT).bat")
        self.assertEqual(installed["commit"], "abc1234")
        self.assertEqual(installed["created_utc"], "2026-08-15T00:00:00Z")
        self.assertRegex(installed["installed_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertNotIn("error", installed)
        for service in ("youtube", "discord-voice"):
            self.assertFalse(items[service]["installed"])
            self.assertEqual(items[service]["error"], "Некорректный профиль: неверный сервис")

    def test_imported_profiles_unusual_files(self):
        tcp = self.profile("discord-tcp")
        real = self.install("real", tcp)
        self.imported.joinpath("discord-tcp.json").symlink_to(real)
        self.install("youtube", "{broken")
        self.imported.joinpath("discord-voice.json").mkdir()
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertIn("необычный тип файла", items["discord-tcp"]["error"])
        self.assertIn("необычный тип файла", items["discord-voice"]["error"])
        self.assertTrue(items["youtube"]["error"].startswith("Некорректный профиль:"))
        self.assertFalse(any(item["installed"] for item in items.values()))

    def test_imported_profiles_too_large(self):
        self.patch(MAX_REPORT_BYTES=10)
        self.install("youtube", self.profile("youtube"))
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertEqual(items["youtube"]["error"], "Некорректный профиль: файл слишком велик")

    def test_profile_versions_without_directory(self):
        self.assertEqual(self.ns["profile_versions"](), [])

    def test_profile_versions_sorting_and_active(self):
        tcp = self.profile("discord-tcp")
        youtube = self.profile("youtube")
        self.install("discord-tcp", tcp)
        old = self.add_version("discord-tcp", tcp, stamp="20260101T000000Z", reason="replaced")
        new = self.add_version("youtube", youtube, stamp="20260901T120000Z", reason="cleared", suffix="-2")
        versions = self.ns["profile_versions"]()
        self.assertEqual([item["id"] for item in versions], [new, old])
        self.assertEqual(versions[0]["service"], "youtube")
        self.assertEqual(versions[0]["reason"], "cleared")
        self.assertEqual(versions[0]["created_utc"], "2026-09-01T12:00:00Z")
        self.assertFalse(versions[0]["active"])
        self.assertEqual(versions[1]["reason"], "replaced")
        self.assertTrue(versions[1]["active"])
        self.assertEqual(versions[1]["commit"], "abc1234")

    def test_profile_versions_skip_invalid_entries(self):
        tcp = self.profile("discord-tcp")
        directory = self.versions / "discord-tcp"
        directory.mkdir(parents=True)
        (directory / "not-a-version.json").write_text(json.dumps(tcp), encoding="utf-8")
        (directory / f"20260815T020304Z-{tcp['candidate_id']}-deleted-1.json").write_text(json.dumps(tcp), encoding="utf-8")
        self.add_version("discord-tcp", tcp, candidate_id="0" * 12)
        self.add_version("youtube", tcp)
        (directory / f"20260815T020304Z-{'a' * 12}-applied-9.json").write_text("{broken", encoding="utf-8")
        (directory / f"20260815T020304Z-{'b' * 12}-applied-9.json").write_text("[]", encoding="utf-8")
        tampered = dict(tcp, family="tampered")
        self.add_version("discord-tcp", tampered, stamp="20260816T000000Z")
        self.assertEqual(self.ns["profile_versions"](), [])

    def test_profile_version_path_validation(self):
        tcp = self.profile("discord-tcp")
        version_id = self.add_version("discord-tcp", tcp)
        path, profile = self.ns["profile_version_path"]("discord-tcp", version_id)
        self.assertEqual(path, self.versions / "discord-tcp" / f"{version_id}.json")
        self.assertEqual(profile["candidate_id"], tcp["candidate_id"])
        with self.assertRaisesRegex(ValueError, "неподдерживаемый сервис"):
            self.ns["profile_version_path"]("discord", version_id)
        for bad in ("../x", version_id + ".json", "20260815T020304Z-abc-applied-1", ""):
            with self.subTest(version_id=bad):
                with self.assertRaisesRegex(ValueError, "некорректный ID версии"):
                    self.ns["profile_version_path"]("discord-tcp", bad)
        with self.assertRaises(FileNotFoundError):
            self.ns["profile_version_path"]("youtube", version_id)
        link_id = f"20260815T020304Z-{tcp['candidate_id']}-applied-777"
        (self.versions / "discord-tcp" / f"{link_id}.json").symlink_to(path)
        with self.assertRaisesRegex(ValueError, "необычный файл версии"):
            self.ns["profile_version_path"]("discord-tcp", link_id)
        wrong_id = self.add_version("youtube", tcp)
        with self.assertRaisesRegex(ValueError, "сервис версии не совпадает"):
            self.ns["profile_version_path"]("youtube", wrong_id)


REPO = Path(__file__).resolve().parents[1]
DIAGNOSTICS_MODULE = REPO / "tools" / "router" / "xkeen_diagnostics.py"
VOICE_RULE_PORTS = "3478-3481,5349,19294-19344,50000-50100"


def engine_rules(tcp=True, voice=True, youtube=True, voice_ports=VOICE_RULE_PORTS):
    """Xray rules as patch_xray writes them for the -direct routes."""
    rules = []
    if tcp:
        rules.append({"type": "field", "outboundTag": "discord-direct", "domain": ["domain:discord.com"]})
    if voice:
        rules.append({"type": "field", "outboundTag": "discord-direct", "network": "udp", "port": voice_ports})
    if youtube:
        rules.append({"type": "field", "outboundTag": "youtube-direct", "domain": ["domain:youtube.com"]})
    return rules


def freedom_outbounds(*tags, **changes):
    return {"outbounds": [dict({"tag": tag, "protocol": "freedom", "settings": {}}, **changes.get(tag, {})) for tag in tags]}


def iptables_save(tcp="443", udp="19294:19344,50000:50100", counters=True, jumps=1):
    """iptables-save -c -t mangle as the nfqws2-keenetic init builds it."""
    prefix = "[12:3456] " if counters else ""
    nfqueue = "-j NFQUEUE --queue-num 300 --queue-bypass"
    mark = "-m mark ! --mark 0x40000000/0x40000000"
    lines = ["*mangle"]
    lines += [f"{prefix}-A POSTROUTING -j nfqws_post"] * jumps + [f"{prefix}-A PREROUTING -j nfqws_pre"] * jumps
    lines += [
        f"{prefix}-A nfqws_post -o eth3 -p udp {mark} -m multiport --dports {udp} -m connbytes --connbytes 1:15 "
        f"--connbytes-mode packets --connbytes-dir original {nfqueue}",
        f"{prefix}-A nfqws_post -o eth3 -p tcp {mark} -m multiport --dports {tcp} -m connbytes --connbytes 1:15 "
        f"--connbytes-mode packets --connbytes-dir original {nfqueue}",
        f"{prefix}-A nfqws_post -o eth3 -p tcp {mark} -m multiport --dports {tcp} -m tcp --tcp-flags FIN FIN {nfqueue}",
        f"{prefix}-A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN",
        f"{prefix}-A nfqws_pre -i eth3 -p udp {mark} -m multiport --sports {udp} -m connbytes --connbytes 1:15 "
        f"--connbytes-mode packets --connbytes-dir reply {nfqueue}",
        f"{prefix}-A nfqws_pre -i eth3 -p tcp {mark} -m multiport --sports {tcp} -m connbytes --connbytes 1:15 "
        f"--connbytes-mode packets --connbytes-dir reply {nfqueue}",
        "COMMIT",
    ]
    return "\n".join(lines) + "\n"


HEALTHY_CONF = """\
# BEGIN keenetic-discord-nfqws2
# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=direct.
# Discord UDP: strategy=flowseal, range=narrow.
NFQWS_ARGS_UDP="--filter-udp=19294-19344,50000-50100
--filter-l7=stun,discord
--payload=stun,discord_ip_discovery
--lua-desync=fake:blob=discord_udp:repeats=6"
NFQWS_ARGS="--filter-tcp=443 --filter-l7=tls --lua-desync=multisplit:pos=1"
NFQWS_EXTRA_ARGS="--hostlist=/opt/etc/nfqws2/lists/user.list"
TCP_PORTS=443
UDP_PORTS=19294:19344,50000:50100
# END keenetic-discord-nfqws2
"""

# The 3.1.0/3.1.1 incident: YouTube=zapret with its QUIC profile, but
# UDP_PORTS (and the live NFQUEUE rule) hold only the Voice ports.
INCIDENT_CONF = """\
# BEGIN keenetic-discord-nfqws2
# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=direct.
# Discord UDP: strategy=flowseal, range=narrow.
NFQWS_ARGS_UDP="--filter-udp=19294-19344,50000-50100
--filter-l7=stun,discord
--payload=stun,discord_ip_discovery
--lua-desync=fake:blob=discord_udp:repeats=6"
NFQWS_EXTRA_ARGS="--hostlist=/opt/etc/nfqws2/lists/user.list"
NFQWS_ARGS_CUSTOM=""
if [ -n "$NFQWS_ARGS_CUSTOM" ]; then
  NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--new"
fi
NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=tls_client_hello
--lua-desync=multisplit:pos=1
--new
--filter-udp=443 --filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=11"
NFQWS_ARGS="--filter-tcp=443 --filter-l7=tls --lua-desync=multisplit:pos=1"
TCP_PORTS=443
UDP_PORTS={udp}
# END keenetic-discord-nfqws2
"""


class ConfigHealthTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.xray = self.root / "xray"
        self.xray.mkdir()
        self.patch(
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            XRAY_CONFIG_DIR=self.xray,
            DISCORD_LIST=self.root / "user.list",
            DIAGNOSTICS=DIAGNOSTICS_MODULE,
            ENGINE=self.root / "missing-engine.sh",
            QUIC_PROBE=self.root / "missing-quic_probe.py",
            TELEGRAM_WS_PIDFILE=self.root / "kdn-telegram-ws.pid",
        )
        self.iptables = iptables_save()
        self.commands = []

    def fake_run(self, command, timeout):
        self.commands.append(command)
        name = Path(command[0]).name
        if name == "iptables-save":
            return {"ok": True, "code": 0, "output": self.iptables}
        return {"ok": True, "code": 0, "output": "1"}

    def write_routing(self, rules, name="05_routing.json"):
        (self.xray / name).write_text(json.dumps({"routing": {"rules": rules}}), encoding="utf-8")

    def write_outbounds(self, *tags, **changes):
        (self.xray / "04_outbounds.json").write_text(json.dumps(freedom_outbounds(*tags, **changes)), encoding="utf-8")

    def healthy_tree(self, conf=HEALTHY_CONF):
        self.ns["NFQWS_CONFIG"].write_text(conf, encoding="utf-8")
        self.ns["DISCORD_LIST"].write_text("discord.com\n", encoding="utf-8")
        self.write_routing(engine_rules() + ["junk"])
        self.write_outbounds("discord-direct", "youtube-direct")

    def health(self, run=None):
        with mock.patch.dict(self.ns, {"run_command": run or self.fake_run}):
            return self.ns["config_health"]()

    def checks(self, run=None):
        return {check["name"]: check for check in self.health(run)["checks"]}

    def test_all_checks_pass_for_consistent_zapret_and_direct_routes(self):
        self.healthy_tree()
        health = self.health()
        self.assertEqual(
            self.commands,
            [["pidof", "xray"], ["pidof", "nfqws2"], ["iptables-save", "-c", "-t", "mangle"]],
        )
        self.assertTrue(health["all_ok"], health)
        self.assertEqual(
            health["routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct", "telegram": "unmanaged"},
        )
        self.assertEqual(
            [check["name"] for check in health["checks"]],
            [
                "Xray", "nfqws2", "YouTube route", "Discord TCP route", "Discord Voice route", "Telegram route",
                "Xray outbounds", "nfqws2: порты профилей в очереди", "nfqws2: порты без профиля",
                "NFQUEUE: порты", "NFQUEUE: переходы",
            ],
        )
        self.assertTrue(all(check["status"] == "ok" for check in health["checks"]), health["checks"])
        # An engine without --check-config: the built-in check says so.
        self.assertIn("встроенная проверка (движок не найден)", health["checks"][7]["detail"])

    def test_routing_with_comments_is_read(self):
        # Xray accepts JSONC; the engine strips comments, so must the panel.
        self.ns["NFQWS_CONFIG"].write_text(
            "# Active routes: DiscordTCP=vless, DiscordVoice=vless, YouTube=direct.\n",
            encoding="utf-8",
        )
        (self.xray / "05_routing.json").write_text(
            '// managed by XKeen\n{"routing": {"rules": [/* first */ {"outboundTag": "youtube-direct"}]}}',
            encoding="utf-8",
        )
        checks = self.checks()
        self.assertNotIn("Xray routing", checks)
        self.assertTrue(checks["YouTube route"]["ok"], checks["YouTube route"])

    def test_discord_voice_route_is_checked_separately(self):
        self.ns["NFQWS_CONFIG"].write_text(
            "# Active routes: DiscordTCP=vless, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.write_routing(engine_rules(tcp=False, youtube=False))
        checks = self.checks()
        self.assertTrue(checks["Discord TCP route"]["ok"])
        # Voice is zapret, but the nfqws2 config has no Voice profile.
        self.assertFalse(checks["Discord Voice route"]["ok"])
        self.assertEqual(checks["Discord Voice route"]["detail"], "route=zapret, nfqws=off")

    def test_voice_route_needs_its_own_udp_rule(self):
        # D5: the Discord TCP domain rule does not send Voice UDP direct.
        self.healthy_tree()
        self.write_routing(engine_rules(voice=False))
        health = self.health()
        checks = {check["name"]: check for check in health["checks"]}
        self.assertFalse(health["all_ok"])
        self.assertFalse(checks["Discord Voice route"]["ok"])
        self.assertIn("Xray=vless", checks["Discord Voice route"]["detail"])
        self.assertTrue(checks["Discord TCP route"]["ok"])
        # A Voice rule that misses the ports of the Voice profile.
        self.write_routing(engine_rules(voice_ports="3478-3481,5349,19294-19344"))
        checks = self.checks()
        self.assertFalse(checks["Discord Voice route"]["ok"])
        self.assertIn("без портов 50000-50100", checks["Discord Voice route"]["detail"])

    def test_routing_file_is_the_last_one_with_a_routing_object(self):
        # D6: Xray uses 06_routing_user.json; the project rules in 05 do not apply.
        self.healthy_tree()
        (self.xray / "06_routing_user.json").write_text(
            json.dumps({"routing": {"rules": [{"outboundTag": "vless-reality", "network": "tcp,udp"}]}}),
            encoding="utf-8",
        )
        (self.xray / "07_inbounds.json").write_text(json.dumps({"inbounds": []}), encoding="utf-8")
        health = self.health()
        checks = {check["name"]: check for check in health["checks"]}
        self.assertFalse(health["all_ok"])
        for name in ("Discord TCP route", "Discord Voice route"):
            self.assertFalse(checks[name]["ok"], name)
            self.assertIn("Xray=vless", checks[name]["detail"])

    def test_routing_object_must_exist(self):
        self.healthy_tree()
        for routing in ({"routing": []}, {"inbounds": []}):
            with self.subTest(routing=routing):
                (self.xray / "05_routing.json").write_text(json.dumps(routing), encoding="utf-8")
                checks = self.checks()
                self.assertFalse(checks["Xray routing"]["ok"])
                self.assertIn("нет файла с объектом routing", checks["Xray routing"]["detail"])

    def test_project_outbounds_must_exist_and_go_straight_out(self):
        # D7: Xray sends a rule with a missing tag to the first (VPN) outbound.
        self.healthy_tree()
        self.write_outbounds("discord-direct")
        checks = self.checks()
        self.assertFalse(checks["Xray outbounds"]["ok"])
        self.assertIn("youtube-direct: outbound не найден", checks["Xray outbounds"]["detail"])
        self.write_outbounds(
            "discord-direct", "youtube-direct",
            **{"youtube-direct": {"streamSettings": {"sockopt": {"dialerProxy": "vless-reality"}}}},
        )
        checks = self.checks()
        self.assertFalse(checks["Xray outbounds"]["ok"])
        self.assertIn("dialerProxy=vless-reality", checks["Xray outbounds"]["detail"])
        self.write_outbounds("discord-direct", "youtube-direct", **{"youtube-direct": {"protocol": "vless"}})
        self.assertIn("нужен freedom", self.checks()["Xray outbounds"]["detail"])

    def test_incident_udp_ports_without_443_fail(self):
        # D1/E17: YouTube QUIC profile with UDP_PORTS that hold only the Voice ports.
        self.healthy_tree(INCIDENT_CONF.replace("{udp}", "19294:19344,50000:50100"))
        self.ns["DISCORD_LIST"].write_text("discord.com\n", encoding="utf-8")
        self.write_routing(engine_rules() + [{"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct"},
                                             {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-direct"}])
        self.write_outbounds("discord-direct", "youtube-direct", "telegram-direct")
        health = self.health()
        checks = {check["name"]: check for check in health["checks"]}
        self.assertFalse(health["all_ok"])
        self.assertTrue(checks["YouTube route"]["ok"])
        self.assertFalse(checks["nfqws2: порты профилей в очереди"]["ok"])
        self.assertIn("UDP 443 нет в UDP_PORTS", checks["nfqws2: порты профилей в очереди"]["detail"])
        self.assertFalse(checks["YouTube QUIC (UDP 443)"]["ok"])
        self.assertIn("без 443", checks["YouTube QUIC (UDP 443)"]["detail"])
        # The live QUIC probe is optional until quic_probe.py is installed.
        self.assertEqual(checks["YouTube QUIC с роутера"]["status"], "warn")

    def test_conf_with_443_but_stale_nfqueue_rules_fail(self):
        # D1: nfqws2 was not restarted after UDP_PORTS gained 443.
        self.healthy_tree(INCIDENT_CONF.replace("{udp}", "443,19294:19344,50000:50100"))
        self.write_routing(engine_rules() + [{"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct"},
                                             {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-direct"}])
        self.write_outbounds("discord-direct", "youtube-direct", "telegram-direct")
        self.iptables = iptables_save(udp="19294:19344,50000:50100")
        health = self.health()
        checks = {check["name"]: check for check in health["checks"]}
        self.assertTrue(checks["nfqws2: порты профилей в очереди"]["ok"])
        self.assertTrue(checks["YouTube QUIC (UDP 443)"]["ok"], checks["YouTube QUIC (UDP 443)"])
        self.assertFalse(health["all_ok"])
        self.assertFalse(checks["NFQUEUE: порты"]["ok"])
        self.assertIn("nfqws_post UDP без 443", checks["NFQUEUE: порты"]["detail"])
        self.assertIn("не перезапущен", checks["NFQUEUE: порты"]["detail"])
        self.iptables = iptables_save(udp="443,19294:19344,50000:50100")
        self.assertTrue(self.health()["all_ok"])

    def test_engine_check_config_lines_are_shown(self):
        self.healthy_tree()
        engine = self.root / "engine.sh"
        engine.write_text("#!/bin/sh\n", encoding="utf-8")
        engine_output = (
            "CHECK|ok|port-coverage|every filter port is queued\n"
            "CHECK|warn|unhandled-ports|TCP 80 queued without a profile\n"
            "CHECK|error|empty-hostlist|youtube.list has no entries\n"
        )

        def run(command, timeout):
            if command[-1:] == ["--check-config"]:
                self.assertEqual(command, ["/bin/sh", str(engine), "--check-config"])
                return {"ok": False, "code": 1, "output": engine_output}
            return self.fake_run(command, timeout)

        with mock.patch.dict(self.ns, {"ENGINE": engine}):
            health = self.health(run)
        checks = {check["name"]: check for check in health["checks"]}
        self.assertEqual(checks["nfqws2: порты профилей в очереди"]["detail"], "every filter port is queued")
        self.assertEqual(checks["nfqws2: порты без профиля"]["status"], "warn")
        self.assertTrue(checks["nfqws2: порты без профиля"]["ok"])
        self.assertFalse(checks["nfqws2: пустые hostlist"]["ok"])
        self.assertFalse(health["all_ok"])

        # An older engine answers with usage: the built-in check runs instead.
        def old_engine(command, timeout):
            if command[-1:] == ["--check-config"]:
                return {"ok": False, "code": 2, "output": "ERROR: unknown argument: --check-config\nUsage: ..."}
            return self.fake_run(command, timeout)

        with mock.patch.dict(self.ns, {"ENGINE": engine}):
            checks = self.checks(old_engine)
        self.assertIn("движок без --check-config", checks["nfqws2: порты профилей в очереди"]["detail"])
        self.assertNotIn("nfqws2: пустые hostlist", checks)

    def test_quic_probe_result_is_labelled_as_a_router_check(self):
        self.healthy_tree(INCIDENT_CONF.replace("{udp}", "443,19294:19344,50000:50100"))
        self.write_routing(engine_rules() + [{"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct"},
                                             {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-direct"}])
        self.write_outbounds("discord-direct", "youtube-direct", "telegram-direct")
        self.iptables = iptables_save(udp="443,19294:19344,50000:50100")
        probe = self.root / "quic_probe.py"
        probe.write_text("# stub\n", encoding="utf-8")
        answers = {"status": "no-reply"}

        def run(command, timeout):
            if command[1:2] == [str(probe)]:
                self.assertEqual(command[2:], ["www.youtube.com", "--timeout", "2", "--tries", "2", "--label", "health"])
                status = answers["status"]
                return {
                    "ok": status == "ok", "code": 0 if status == "ok" else 1,
                    "output": f"EVENT|QUIC|health|www.youtube.com|142.250.74.110|{status}|{38 if status == 'ok' else -1}\n",
                }
            return self.fake_run(command, timeout)

        with mock.patch.dict(self.ns, {"QUIC_PROBE": probe}):
            health = self.health(run)
            check = {item["name"]: item for item in health["checks"]}["YouTube QUIC с роутера"]
            self.assertFalse(check["ok"])
            self.assertFalse(health["all_ok"])
            self.assertIn("с самого роутера", check["detail"])
            answers["status"] = "ok"
            health = self.health(run)
            check = {item["name"]: item for item in health["checks"]}["YouTube QUIC с роутера"]
            self.assertTrue(check["ok"])
            self.assertIn("142.250.74.110", check["detail"])
            self.assertTrue(health["all_ok"], health["checks"])

    def telegram_checks(self, route, rules, profile):
        self.ns["NFQWS_CONFIG"].write_text(
            f"# Active routes: DiscordTCP=vless, DiscordVoice=vless, YouTube=vless, Telegram={route}.\n"
            + ("--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list\n" if profile else ""),
            encoding="utf-8",
        )
        self.write_routing(rules)
        return self.checks()["Telegram route"]

    def test_telegram_route_is_checked(self):
        managed = lambda outbound: [  # noqa: E731
            {"ruleTag": "kdn-telegram-domain", "outboundTag": outbound, "domain": ["ext:geosite_v2fly.dat:telegram"]},
            {"ruleTag": "kdn-telegram-ip", "outboundTag": outbound, "ip": ["ext:geoip_v2fly.dat:telegram"]},
        ]
        user_rule = {"outboundTag": "direct", "domain": ["domain:t.me"]}
        cases = (
            ("unmanaged", [user_rule], False, True),
            ("unmanaged", managed("telegram-direct"), False, False),
            ("unmanaged", [], True, False),
            ("direct", managed("telegram-direct"), False, True),
            ("direct", managed("telegram-direct"), True, False),
            # Zapret was removed: a recorded header is never healthy.
            ("zapret", managed("telegram-direct"), True, False),
            ("zapret", managed("telegram-direct"), False, False),
            ("vless", managed("vless-reality"), False, True),
            ("vless", managed("vless-reality"), True, False),
            ("vless", managed("telegram-direct"), False, False),
            ("direct", managed("vless-reality"), False, False),
        )
        for route, rules, profile, expected in cases:
            with self.subTest(route=route, rules=len(rules), profile=profile):
                self.assertEqual(self.telegram_checks(route, rules, profile)["ok"], expected)

    def test_recorded_telegram_zapret_is_reported_unhealthy(self):
        rules = [
            {"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct", "domain": ["x"]},
            {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-direct", "ip": ["y"]},
        ]
        check = self.telegram_checks("zapret", rules, True)
        self.assertFalse(check["ok"])
        self.assertEqual(check["detail"], "route=zapret (режим удалён, выберите другой)")

    def test_telegram_ws_route_needs_its_rules_and_relay(self):
        ws_rules = [
            {"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct", "domain": ["x"]},
            {"ruleTag": "kdn-telegram-sniffed", "outboundTag": "telegram-direct", "protocol": ["tls"]},
            {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-ws", "network": "tcp"},
            {"ruleTag": "kdn-telegram-udp", "outboundTag": "telegram-direct", "network": "udp"},
        ]
        for rules, running, expected in (
            (ws_rules, True, True),
            (ws_rules, False, False),
            (ws_rules[:2] + ws_rules[3:], True, False),
            ([dict(rule, outboundTag="telegram-direct") for rule in ws_rules], True, False),
        ):
            status = (running, "работает" if running else "не запущен")
            with self.subTest(rules=len(rules), running=running), \
                    mock.patch.dict(self.ns, {"telegram_ws_status": lambda status=status: status}):
                self.assertEqual(self.telegram_checks("ws", rules, True)["ok"], expected)

    def test_telegram_ws_status_needs_the_relay_process_and_its_port(self):
        # D9: a pidfile alone (or a reused PID) does not prove that the relay works.
        pidfile = self.ns["TELEGRAM_WS_PIDFILE"]
        status = self.ns["telegram_ws_status"]
        running, detail = status()
        self.assertFalse(running)
        self.assertIn("нет pid-файла", detail)
        pidfile.write_text(f"{os.getpid()}\n", encoding="ascii")
        running, detail = status()
        self.assertFalse(running)
        self.assertIn("не telegram_ws_relay.py", detail)
        pidfile.write_text("1\n", encoding="ascii")
        self.assertFalse(status()[0])

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        relay = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", "telegram_ws_relay.py"],
        )
        self.addCleanup(relay.wait)
        self.addCleanup(relay.kill)
        pidfile.write_text(f"{relay.pid}\n", encoding="ascii")
        port = listener.getsockname()[1]
        with mock.patch.dict(self.ns, {"TELEGRAM_WS_PORT": port}):
            running, detail = status()
            self.assertTrue(running, detail)
            listener.close()
            running, detail = status()
        self.assertFalse(running)
        self.assertIn("не принимает соединения", detail)

    def test_telegram_ws_outbound_must_redirect_to_the_relay(self):
        ws_rules = [
            {"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct", "domain": ["x"]},
            {"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-ws", "network": "tcp"},
        ]
        self.ns["NFQWS_CONFIG"].write_text(
            "# Active routes: DiscordTCP=vless, DiscordVoice=vless, YouTube=vless, Telegram=ws.\n", encoding="utf-8",
        )
        self.write_routing(ws_rules)
        for redirect, ok in (("127.0.0.1:18443", True), ("127.0.0.1:1080", False)):
            with self.subTest(redirect=redirect):
                self.write_outbounds("telegram-direct", "telegram-ws", **{"telegram-ws": {"settings": {"redirect": redirect}}})
                self.assertEqual(self.checks()["Xray outbounds"]["ok"], ok)

    def test_missing_files_and_processes_fail(self):
        health = self.health(lambda *_a, **_k: {"ok": False, "code": 1, "output": ""})
        self.assertFalse(health["all_ok"])
        checks = {check["name"]: check for check in health["checks"]}
        self.assertEqual(
            list(checks),
            [
                "Xray",
                "nfqws2",
                "nfqws2 config",
                "Xray routing",
                "YouTube route",
                "Discord TCP route",
                "Discord Voice route",
                "Telegram route",
                "Xray outbounds",
            ],
        )
        self.assertFalse(any(check["ok"] for name, check in checks.items() if name != "Xray outbounds"))
        self.assertEqual(checks["Xray"]["detail"], "процесс не найден")
        self.assertEqual(checks["YouTube route"]["detail"], "route=unknown, nfqws=off")

    def test_missing_diagnostics_module_is_reported(self):
        self.healthy_tree()
        with mock.patch.dict(self.ns, {"DIAGNOSTICS": self.root / "missing.py", "DIAGNOSTICS_MODULES": {}}):
            health = self.health()
        self.assertFalse(health["all_ok"])
        self.assertEqual(health["checks"][-1]["name"], "Модуль проверок")


class HttpLayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_panel_namespace("panel_http_test")
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        cls.root = root

        def forbidden(*_args, **_kwargs):
            raise AssertionError("router command must not run in tests")

        cls.ns.update(
            BIND_HOST="127.0.0.1",
            run_command=forbidden,
            apply_profile=forbidden,
            PROJECT_DIR=root / "project",
            ENGINE=root / "project" / "apply-discord-nfqws2.sh",
            SERVICE_SWITCH=root / "project" / "set-service-route.sh",
            AUTOTUNER=root / "project" / "zapret_autotune_job.py",
            DIAGNOSTICS=root / "project" / "xkeen_diagnostics.py",
            DISCORD_CACHE_HELPER=root / "project" / "reset-discord-cache.ps1",
            BROWSER_DIAGNOSTICS=root / "project" / "browser-diagnostics.js",
            XKEEN=str(root / "xkeen"),
            IMPORTED_PROFILE_DIR=root / "imported",
            PROFILE_VERSION_DIR=root / "versions",
            NFQWS_CONFIG=root / "nfqws2.conf",
            DISCORD_LIST=root / "user.list",
            XRAY_CONFIG_DIR=root / "xray",
            IMPORT_ROLLBACK_POINTER=root / "rollback.ptr",
            TUNER_JOB_DIR=root / "tuner",
            TUNER_STATE=root / "tuner" / "state.json",
            TUNER_RESULT=root / "tuner" / "result-report.json",
            TUNER_VERDICT=root / "tuner" / "verdict.txt",
            TUNER_PID=root / "tuner" / "panel-launch.pid",
            DIAGNOSTIC_JOB_DIR=root / "diagnostics",
            DIAGNOSTIC_STATE=root / "diagnostics" / "state.json",
            DIAGNOSTIC_PID=root / "diagnostics" / "panel-launch.pid",
            DIAGNOSTIC_LOG=root / "diagnostics" / "process.log",
            ROUTE_JOB_DIR=root / "route",
            ROUTE_STATE=root / "route" / "state.json",
            ROUTE_PID=root / "route" / "worker.pid",
            ROUTE_LOG=root / "route" / "process.log",
            ROUTE_APPLY_LOG=root / "route" / "apply.log",
            ROUTE_HISTORY_DIR=root / "history",
            SNAPSHOT_DIR=root / "snapshots",
            FLOWSEAL_UPDATE_STATE=root / "flowseal-update.json",
            FLOWSEAL_SOURCE_CACHE=root / "flowseal-sources.json",
            __file__=str(root / "app.py"),
        )
        handler = cls.ns["Handler"]
        handler.log_message = lambda *_args: None
        cls.server = cls.ns["ThreadingHTTPServer"](("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        cls.ns["PORT"] = cls.port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            return response, data
        finally:
            connection.close()

    def post(self, path, payload=None, *, raw=None, headers=None):
        body = raw if raw is not None else json.dumps({} if payload is None else payload).encode("utf-8")
        merged = {"X-XKeen-Control": "1", "Content-Type": "application/json"}
        merged.update(headers or {})
        return self.request("POST", path, body=body, headers=merged)

    def assertJsonError(self, response, data, status, fragment):
        self.assertEqual(response.status, status, data)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        payload = json.loads(data.decode("utf-8"))
        self.assertIs(payload["ok"], False)
        self.assertIn(fragment, payload["error"])
        return payload

    def test_get_root_returns_html_with_security_headers(self):
        response, data = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(int(response.getheader("Content-Length")), len(data))
        self.assertTrue(data.startswith(b"<!doctype html>"))
        page = data.decode("utf-8")
        self.assertIn('id="service-configs"', page)
        self.assertEqual(page.count('<details class="service-config"'), 4)
        self.assertNotIn("__SERVICE_CONFIG_", page)

    def test_unknown_get_is_404(self):
        response, data = self.request("GET", "/api/nope")
        self.assertJsonError(response, data, 404, "unknown endpoint")
        response, data = self.request("GET", "/?x=1")
        self.assertJsonError(response, data, 404, "unknown endpoint")

    def test_get_rejects_client_outside_lan(self):
        with mock.patch.dict(self.ns, {"private_client": lambda _address: False}):
            response, data = self.request("GET", "/")
        self.assertJsonError(response, data, 403, "client is outside LAN")

    def test_get_status_without_engine_is_500(self):
        response, data = self.request("GET", "/api/status")
        self.assertJsonError(response, data, 500, "project script not found")

    def test_get_download_missing_helper_is_404(self):
        response, data = self.request("GET", "/tools/reset-discord-cache.ps1")
        self.assertEqual(response.status, 404)
        self.assertIs(json.loads(data)["ok"], False)

    def test_get_download_helper(self):
        helper = self.root / "helper.ps1"
        helper.write_text("Write-Host 'ok'\n", encoding="utf-8")
        with mock.patch.dict(self.ns, {"DISCORD_CACHE_HELPER": helper}):
            response, data = self.request("GET", "/tools/reset-discord-cache.ps1")
        self.assertEqual(response.status, 200)
        self.assertEqual(
            response.getheader("Content-Disposition"),
            'attachment; filename="reset-discord-cache.ps1"',
        )
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(data, "Write-Host 'ok'\n".encode("utf-8-sig"))

    def test_get_read_only_endpoints(self):
        response, data = self.request("GET", "/api/history")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(data), {"ok": True, "items": []})
        response, data = self.request("GET", "/api/profile-versions")
        self.assertEqual(json.loads(data), {"ok": True, "versions": []})
        response, data = self.request("GET", "/api/imported")
        payload = json.loads(data)
        self.assertFalse(payload["rollback_available"])
        self.assertEqual([item["service"] for item in payload["profiles"]], ["youtube", "discord-tcp", "discord-voice"])
        response, data = self.request("GET", "/api/route/status")
        self.assertEqual(json.loads(data)["status"], "idle")
        response, data = self.request("GET", "/api/tuner/status")
        self.assertEqual(json.loads(data)["status"], "idle")
        response, data = self.request("GET", "/api/diagnostics/status")
        self.assertEqual(json.loads(data)["status"], "idle")

    def test_post_without_control_header_is_403(self):
        response, data = self.request(
            "POST",
            "/api/import/validate",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertJsonError(response, data, 403, "control header missing")
        response, data = self.post("/api/import/validate", headers={"X-XKeen-Control": "yes"})
        self.assertJsonError(response, data, 403, "control header missing")

    def test_post_with_wrong_host_is_403(self):
        for host in ("evil.example", f"127.0.0.1:{self.port + 1}", "localhost", f"localhost:{self.port}"):
            with self.subTest(host=host):
                response, data = self.post("/api/import/validate", headers={"Host": host})
                self.assertJsonError(response, data, 403, "unexpected Host header")

    def test_post_with_bare_bind_host_passes_host_check(self):
        response, data = self.post("/api/nope", headers={"Host": "127.0.0.1"})
        self.assertJsonError(response, data, 404, "unknown action")

    def test_post_with_foreign_origin_is_403(self):
        for origin in ("http://evil.example", f"http://127.0.0.1:{self.port + 1}", "null"):
            with self.subTest(origin=origin):
                response, data = self.post("/api/import/validate", headers={"Origin": origin})
                self.assertJsonError(response, data, 403, "cross-origin request denied")

    def test_post_with_same_origin_is_accepted(self):
        response, data = self.post(
            "/api/import/validate",
            make_report("youtube"),
            headers={"Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(response.status, 200, data)
        payload = json.loads(data)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["profile"]["service"], "youtube")

    def test_post_rejects_client_outside_lan(self):
        with mock.patch.dict(self.ns, {"private_client": lambda _address: False}):
            response, data = self.post("/api/import/validate")
        self.assertJsonError(response, data, 403, "client is outside LAN")

    def test_post_with_wrong_content_type_is_400(self):
        for content_type in ("text/plain", "application/x-www-form-urlencoded", "application/json-patch+json"):
            with self.subTest(content_type=content_type):
                response, data = self.post("/api/import/validate", headers={"Content-Type": content_type})
                self.assertJsonError(response, data, 400, "ожидается Content-Type: application/json")

    def test_post_content_type_parameters_and_case_are_accepted(self):
        response, data = self.post(
            "/api/import/validate",
            make_report("discord-tcp"),
            headers={"Content-Type": "Application/JSON; charset=utf-8"},
        )
        self.assertEqual(response.status, 200, data)

    def test_post_with_bad_content_length_is_400(self):
        for length in ("abc", "-1", "1.5", ""):
            with self.subTest(length=length):
                response, data = self.post("/api/import/validate", raw=b"{}", headers={"Content-Length": length})
                self.assertJsonError(response, data, 400, "некорректный Content-Length")

    def test_post_with_oversized_content_length_is_400(self):
        response, data = self.post(
            "/api/import/validate",
            raw=b"{}",
            headers={"Content-Length": str(512 * 1024 + 1)},
        )
        self.assertJsonError(response, data, 400, "JSON превышает 512 КиБ")

    def test_post_with_invalid_json_is_400(self):
        for raw in (b"{bad", b"", b"\xff\xfe", b"{\"a\": 1}}"):
            with self.subTest(raw=raw):
                response, data = self.post("/api/import/validate", raw=raw)
                self.assertJsonError(response, data, 400, "некорректный JSON")

    def test_unexpected_handler_errors_return_json_500(self):
        def boom(*_args, **_kwargs):
            raise AttributeError("unexpected")

        with mock.patch.dict(self.ns, {"tuner_status": boom, "tuner_sources": boom}):
            for path in ("/api/tuner/status", "/api/tuner/sources"):
                with self.subTest(path=path):
                    response, data = self.request("GET", path)
                    self.assertJsonError(response, data, 500, "внутренняя ошибка панели")
        # The server keeps serving after the failure.
        response, _data = self.request("GET", "/")
        self.assertEqual(response.status, 200)

    def test_post_with_deeply_nested_json_is_400(self):
        raw = (b"[" * 100000) + (b"]" * 100000)
        response, data = self.post("/api/import/validate", raw=raw)
        self.assertJsonError(response, data, 400, "некорректный JSON")

    def test_unknown_post_is_404(self):
        for path in ("/api/nope", "/", "/api/import/clear/whatsapp", "/api/route/discord"):
            with self.subTest(path=path):
                response, data = self.post(path)
                self.assertJsonError(response, data, 404, "unknown action")

    def test_route_post_with_unknown_mode_or_service_is_404(self):
        starter = mock.Mock(side_effect=AssertionError("must not start"))
        with mock.patch.dict(self.ns, {"start_route_job": starter}):
            for path in ("/api/route/discord/custom", "/api/route/discord/vless", "/api/route/whatsapp/vpn"):
                with self.subTest(path=path):
                    response, data = self.post(path)
                    self.assertJsonError(response, data, 404, "unknown action")
        starter.assert_not_called()

    def test_route_post_starts_job_and_maps_errors(self):
        starter = mock.Mock(return_value={"ok": True, "job_id": "0123456789abcdef", "status": "queued"})
        with mock.patch.dict(self.ns, {"start_route_job": starter}):
            response, data = self.post("/api/route/youtube/vpn")
        self.assertEqual(response.status, 202, data)
        self.assertEqual(json.loads(data)["job_id"], "0123456789abcdef")
        starter.assert_called_once_with("youtube", "vpn")
        for exc, status in ((RuntimeError("busy"), 409), (ValueError("bad"), 400), (OSError("io"), 400)):
            with self.subTest(exc=exc):
                with mock.patch.dict(self.ns, {"start_route_job": mock.Mock(side_effect=exc)}):
                    response, data = self.post("/api/route/discord/direct")
                self.assertJsonError(response, data, status, str(exc))

    def test_route_post_rejects_telegram_zapret(self):
        response, data = self.post("/api/route/telegram/zapret")
        self.assertJsonError(response, data, 400, "Zapret для Telegram удалён")

    def test_import_validate_rejects_invalid_report(self):
        response, data = self.post("/api/import/validate", {"report_format": 2})
        self.assertJsonError(response, data, 400, "неподдерживаемая версия отчёта")
        response, data = self.post("/api/import/validate", [1, 2])
        self.assertJsonError(response, data, 400, "корень отчёта")

    def test_import_apply_is_blocked_while_jobs_run(self):
        report = make_report("discord-tcp")
        for name in ("tuner_active", "route_active", "diagnostic_active"):
            with self.subTest(active=name):
                with mock.patch.dict(self.ns, {name: lambda: True}):
                    response, data = self.post("/api/import/apply", report)
                self.assertJsonError(response, data, 409, "профиль нельзя применять")

    def test_diagnostic_targets_come_from_the_shared_module(self):
        with mock.patch.dict(self.ns, {"DIAGNOSTICS": DIAGNOSTICS_MODULE, "DIAGNOSTICS_MODULES": {}}):
            response, data = self.request("GET", "/api/diagnostics/targets")
            self.assertEqual(response.status, 200)
            payload = json.loads(data)
            self.assertIn({"name": "DiscordMain", "url": "https://discord.com"}, payload["standard"])
            self.assertEqual(len(payload["dpi"]), 12)
            # Loaded once and reused by the post-apply check.
            self.assertEqual(list(self.ns["DIAGNOSTICS_MODULES"]), [str(DIAGNOSTICS_MODULE)])

    def test_successful_nfqws2_changes_return_the_post_apply_check(self):
        # D3: import, clear, rollback, version and tuner apply run the check, errors do not.
        health = {"ok": True, "checks": [{"name": "fixture", "ok": False, "status": "error", "detail": "x"}], "all_ok": False}
        calls = []

        def command(ok):
            return lambda *_args, **_kwargs: {"ok": ok, "code": 0 if ok else 1, "output": "engine"}

        def checked():
            calls.append(1)
            return health

        report = make_report("discord-tcp")
        cases = (
            ("/api/import/apply", report, "apply_profile"),
            ("/api/import/clear/youtube", {}, "run_command"),
            ("/api/import/rollback", {}, "run_command"),
        )
        for ok in (True, False):
            for path, body, runner in cases:
                with self.subTest(path=path, ok=ok), mock.patch.dict(self.ns, {
                    runner: command(ok), "config_health": checked,
                    "tuner_active": lambda: False, "route_active": lambda: False, "diagnostic_active": lambda: False,
                }):
                    calls.clear()
                    response, data = self.post(path, body)
                    payload = json.loads(data)
                    self.assertEqual(response.status, 200 if ok else 500)
                    if ok:
                        self.assertEqual(payload["health"], health)
                        self.assertEqual(calls, [1])
                    else:
                        self.assertNotIn("health", payload)
                        self.assertEqual(calls, [])
        # Version and tuner apply go through the same wrapper as the import.
        source = (REPO / "tools" / "router" / "xkeen_control_script.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count("payload = with_post_checks(apply_profile(profile))"), 3)
        self.assertNotIn("payload = apply_profile(profile)", source)
        # A failing check does not turn a completed change into an error.
        with mock.patch.dict(self.ns, {
            "apply_profile": command(True), "config_health": lambda: 1 / 0,
            "tuner_active": lambda: False, "route_active": lambda: False, "diagnostic_active": lambda: False,
        }):
            response, data = self.post("/api/import/apply", report)
        self.assertEqual(response.status, 200)
        self.assertIn("ZeroDivisionError", json.loads(data)["health_error"])

    def test_tuner_verdict_body_validation(self):
        for body in ({}, {"works": "yes"}, {"works": True, "extra": 1}, [True]):
            with self.subTest(body=body):
                response, data = self.post("/api/tuner/verdict", body)
                self.assertJsonError(response, data, 400, "bool-параметр works")
        response, data = self.post("/api/tuner/verdict", {"works": True})
        self.assertEqual(response.status, 409, data)

    def test_tuner_start_without_autotuner_is_500(self):
        response, data = self.post("/api/tuner/start", {"service": "youtube"})
        self.assertJsonError(response, data, 500, "autotuner not found")

    def test_diagnostics_start_without_script_is_500(self):
        response, data = self.post("/api/diagnostics/start/health")
        self.assertJsonError(response, data, 500, "diagnostics not found")

    def test_cancel_endpoints_without_active_jobs_are_409(self):
        response, data = self.post("/api/tuner/cancel")
        self.assertJsonError(response, data, 409, "активного подбора нет")
        response, data = self.post("/api/diagnostics/cancel")
        self.assertJsonError(response, data, 409, "активной диагностики нет")

    def test_history_rollback_with_bad_id_is_400(self):
        response, data = self.post("/api/history/rollback/not-an-id")
        self.assertJsonError(response, data, 400, "некорректный ID операции")

    def test_profile_apply_with_bad_version_is_400(self):
        response, data = self.post("/api/profiles/apply/youtube/bad-version")
        self.assertJsonError(response, data, 400, "некорректный ID версии")

    def test_xkeen_actions_are_blocked_while_jobs_run(self):
        for name in ("tuner_active", "route_active", "diagnostic_active"):
            with self.subTest(active=name):
                with mock.patch.dict(self.ns, {name: lambda: True}):
                    response, data = self.post("/api/xkeen/restart")
                self.assertJsonError(response, data, 409, "XKeen нельзя менять")


if __name__ == "__main__":
    unittest.main()

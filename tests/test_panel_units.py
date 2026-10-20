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
import subprocess
import sys
import tempfile
import threading
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
        "--filter-udp=50000-65535",
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
        with self.assertRaisesRegex(ValueError, "неподдерживаемый сервис"):
            validate("discord-video", "direct")
        with self.assertRaisesRegex(ValueError, "неподдерживаемый маршрут"):
            validate("youtube", "vless")

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
        self.assertRejected("неподдерживаемый сервис", make_candidate(service="telegram"))
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
            },
        )
        for mix in ("off", "safe", "extended"):
            self.assertEqual(self.validate({"service": "discord-tcp", "mix_level": mix, "search_seed": 0})["mix_level"], mix)
        self.assertEqual(self.validate({"service": "youtube", "max_candidates": 1, "search_seed": 5})["max_candidates"], 1)

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
        unknown = {"discord-tcp": "unknown", "discord-voice": "unknown", "youtube": "unknown"}
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
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "vless"},
        )
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.ns["current_routes_fast"](),
            {"discord-tcp": "direct", "discord-voice": "zapret", "youtube": "vless"},
        )
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
        self.ns["write_history"]({"job_id": self.JOB_ID, "status": "failed"})
        with self.assertRaisesRegex(ValueError, "только для завершённой операции"):
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
                    {"discord-tcp": "vless", "discord-voice": "vless", "youtube": "direct"},
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
                with mock.patch.dict(self.ns, {"run_command": lambda *_a, **_k: payload}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        self.ns["start_tuner_job"](settings)
        self.assertFalse(self.tuner.exists())
        with mock.patch.dict(self.ns, {"tuner_active": lambda: True}):
            with self.assertRaisesRegex(RuntimeError, "подбор уже выполняется"):
                self.ns["start_tuner_job"](settings)


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


class ConfigHealthTests(PanelTestCase):
    def setUp(self):
        super().setUp()
        self.patch(
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            XRAY_ROUTING=self.root / "05_routing.json",
            DISCORD_LIST=self.root / "user.list",
        )

    def test_all_checks_pass_for_consistent_zapret_and_direct_routes(self):
        self.ns["NFQWS_CONFIG"].write_text(
            "# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=direct.\n"
            "NFQWS_ARGS_UDP=\"--filter-udp=443 --filter-l7=stun,discord\"\n",
            encoding="utf-8",
        )
        self.ns["DISCORD_LIST"].write_text("discord.com\n", encoding="utf-8")
        self.ns["XRAY_ROUTING"].write_text(
            json.dumps({"routing": {"rules": [{"outboundTag": "youtube-direct"}, {"outboundTag": "discord-direct"}, "junk"]}}),
            encoding="utf-8",
        )
        commands = []

        def fake_run(command, timeout):
            commands.append(command)
            return {"ok": True, "code": 0, "output": "1"}

        with mock.patch.dict(self.ns, {"run_command": fake_run}):
            health = self.ns["config_health"]()
        self.assertEqual(commands, [["pidof", "xray"], ["pidof", "nfqws2"]])
        self.assertTrue(health["all_ok"], health)
        self.assertEqual(
            health["routes"],
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "direct"},
        )
        self.assertEqual(
            [check["name"] for check in health["checks"]],
            ["Xray", "nfqws2", "YouTube route", "Discord TCP route", "Discord Voice route"],
        )

    def test_discord_voice_route_is_checked_separately(self):
        self.ns["NFQWS_CONFIG"].write_text(
            "# Active routes: DiscordTCP=vless, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.ns["XRAY_ROUTING"].write_text(
            json.dumps({"routing": {"rules": [{"outboundTag": "discord-direct"}]}}),
            encoding="utf-8",
        )
        with mock.patch.dict(self.ns, {"run_command": lambda *_a, **_k: {"ok": True, "code": 0, "output": "1"}}):
            checks = {check["name"]: check for check in self.ns["config_health"]()["checks"]}
        self.assertTrue(checks["Discord TCP route"]["ok"])
        # Voice is zapret, but the nfqws2 config has no Voice profile.
        self.assertFalse(checks["Discord Voice route"]["ok"])
        self.assertEqual(checks["Discord Voice route"]["detail"], "route=zapret, nfqws=off")

    def test_missing_files_and_processes_fail(self):
        with mock.patch.dict(self.ns, {"run_command": lambda *_a, **_k: {"ok": False, "code": 1, "output": ""}}):
            health = self.ns["config_health"]()
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
            ],
        )
        self.assertFalse(any(check["ok"] for check in checks.values()))
        self.assertEqual(checks["Xray"]["detail"], "процесс не найден")
        self.assertEqual(checks["YouTube route"]["detail"], "route=unknown, nfqws=off")


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
            XRAY_ROUTING=root / "05_routing.json",
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
        self.assertEqual(data.decode("utf-8"), self.ns["HTML"])

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

    def test_unknown_post_is_404(self):
        for path in ("/api/nope", "/", "/api/import/clear/telegram", "/api/route/discord"):
            with self.subTest(path=path):
                response, data = self.post(path)
                self.assertJsonError(response, data, 404, "unknown action")

    def test_route_post_with_unknown_mode_or_service_is_404(self):
        starter = mock.Mock(side_effect=AssertionError("must not start"))
        with mock.patch.dict(self.ns, {"start_route_job": starter}):
            for path in ("/api/route/discord/custom", "/api/route/discord/vless", "/api/route/telegram/vpn"):
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

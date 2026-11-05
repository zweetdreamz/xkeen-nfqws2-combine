"""Tests of the validation of the panel input: autotune candidates, reports and tuner start requests."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from panel_fixtures import VALID_ARGS, PanelUnitCase, make_candidate, make_report


class CandidateValidationTests(PanelUnitCase):
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


class TunerRequestTests(PanelUnitCase):
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


if __name__ == "__main__":
    unittest.main()

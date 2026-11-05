"""Characterization unit tests for tools/router/xkeen_diagnostics.py.

These tests pin the current behaviour of the read-only diagnostics helper
without touching the network, requiring root, or writing outside temporary
directories. Every external command, DNS lookup and disk query is mocked.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools" / "router" / "xkeen_diagnostics.py"
    spec = importlib.util.spec_from_file_location("xkeen_diagnostics_units", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecordingWriter:
    def __init__(self):
        self.calls = []

    def write(self, **changes):
        self.calls.append(changes)


def completed(returncode: int, stdout: bytes) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout)


def write_file(base: Path, logical: str, content: str) -> Path:
    path = base / logical.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def wait_for_cmdline(pid: int, timeout: float = 5.0) -> None:
    """Wait until /proc/<pid>/cmdline is non-empty: right after Popen it can still be empty on a loaded host."""
    path = Path(f"/proc/{pid}/cmdline")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if path.read_bytes():
                return
        except OSError:
            pass
        time.sleep(0.001)
    raise AssertionError(f"{path} stayed empty for {timeout} s")


VOICE_RULE_PORTS = "3478-3481,5349,19294-19344,50000-50100"


def engine_rules(tags, voice_ports=VOICE_RULE_PORTS):
    """Xray rules as patch_xray writes them, for a set of -direct tags."""
    rules = []
    if "discord-direct" in tags:
        rules.append({"type": "field", "outboundTag": "discord-direct", "domain": ["domain:discord.com"]})
        rules.append({"type": "field", "outboundTag": "discord-direct", "network": "udp", "port": voice_ports})
    if "youtube-direct" in tags:
        rules.append({"type": "field", "outboundTag": "youtube-direct", "domain": ["domain:youtube.com"]})
    if "telegram-ws" in tags:
        rules.append({"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct", "domain": ["x"]})
        rules.append({"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-ws", "network": "tcp"})
    elif "telegram-direct" in tags:
        rules.append({"ruleTag": "kdn-telegram-domain", "outboundTag": "telegram-direct", "domain": ["x"]})
        rules.append({"ruleTag": "kdn-telegram-ip", "outboundTag": "telegram-direct", "ip": ["y"]})
    return rules


HEALTHY_ROUTING = {"routing": {"rules": engine_rules({"discord-direct", "youtube-direct"}) + ["not-a-dict-is-ignored"]}}
HEALTHY_OUTBOUNDS = {"outbounds": [
    {"tag": "vless-reality", "protocol": "vless", "streamSettings": {"sockopt": {"dialerProxy": "x"}}},
    {"tag": "discord-direct", "protocol": "freedom", "settings": {}},
    {"tag": "youtube-direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"mark": 255}}},
]}
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
IPV6_ENABLED=0
ISP_INTERFACE="eth3"
# END keenetic-discord-nfqws2
"""
# The 3.1.0/3.1.1 incident: YouTube=zapret and its QUIC profile, but UDP_PORTS
# (and the live NFQUEUE rule) hold only the Discord Voice ports.
INCIDENT_CONF = HEALTHY_CONF.replace("YouTube=direct", "YouTube=zapret").replace(
    "UDP_PORTS=19294:19344,50000:50100", "UDP_PORTS={udp}"
).replace(
    'NFQWS_ARGS="',
    'NFQWS_ARGS_CUSTOM="--filter-tcp=443 --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/youtube.list\n'
    "--lua-desync=multisplit:pos=1 --new\n"
    "--filter-udp=443 --filter-l7=quic --hostlist=/opt/etc/nfqws2/lists/youtube.list\n"
    '--payload=quic_initial --lua-desync=fake:blob=youtube_quic:repeats=11"\nNFQWS_ARGS="',
)


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


def build_healthy_tree(base: Path, module, conf: str = HEALTHY_CONF) -> None:
    write_file(base, module.NFQWS_CONFIG_LOGICAL, conf)
    write_file(base, module.DISCORD_LIST_LOGICAL, "# comment\ndiscord.com\ndiscord.gg\n")
    write_file(base, module.YOUTUBE_LIST_LOGICAL, "# only a comment\n")
    write_file(base, module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", json.dumps(HEALTHY_ROUTING))
    write_file(base, module.XRAY_CONFIG_DIR_LOGICAL + "/04_outbounds.json", json.dumps(HEALTHY_OUTBOUNDS))
    write_file(base, "/proc/meminfo", "MemTotal:  262144 kB\nMemAvailable:  131072 kB\nBroken:\n")
    write_file(base, "/proc/sys/net/netfilter/nf_conntrack_count", "100\n")
    write_file(base, "/proc/sys/net/netfilter/nf_conntrack_max", "1000\n")


ENGINE_WITHOUT_CHECK = "ERROR: unknown argument: --check-config\nUsage: sh apply-discord-nfqws2.sh [options]"


def healthy_run(pids=None, iptables=None, engine_output=ENGINE_WITHOUT_CHECK, ipv6_route="", curl=None):
    pids = {"xray": "101", "nfqws2": "202"} if pids is None else pids
    iptables = iptables_save() if iptables is None else iptables

    def fake_run(command, timeout, extra_env=None):
        name = Path(command[0]).name
        if name == "pidof":
            value = pids.get(command[1])
            return {"ok": value is not None, "code": 0 if value else 1, "output": value or ""}
        if name == "xray":
            return {"ok": True, "code": 0, "output": "Configuration OK"}
        if name == "iptables-save":
            return {"ok": True, "code": 0, "output": iptables}
        if name == "ip":
            if command[1] == "-6":
                return {"ok": True, "code": 0, "output": ipv6_route}
            return {"ok": True, "code": 0, "output": "default via 192.0.2.1 dev eth3"}
        if name == "sh" and command[-1] == "--check-config":
            return {"ok": False, "code": 2, "output": engine_output}
        if name == "curl":
            if curl is not None:
                return curl(command)
            return {"ok": True, "code": 0, "output": "__XKSNI__200"}
        raise AssertionError(f"unexpected command {command}")

    return fake_run


class DiagnosticsUnitBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def setUp(self):
        self.module.CANCELLED.clear()
        self.addCleanup(self.module.CANCELLED.clear)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)


class ParseRoutesTests(DiagnosticsUnitBase):
    def test_valid_header_is_parsed_anywhere_in_multiline_text(self):
        text = "line\n# Active routes: DiscordTCP=vless, DiscordVoice=direct, YouTube=zapret.\nmore"
        self.assertEqual(tuple(self.module.parse_routes(text)), ("vless", "direct", "zapret"))

    def test_legacy_header_applies_discord_route_to_tcp_and_voice(self):
        text = "line\n# Active routes: Discord=vless, YouTube=zapret.\nmore"
        self.assertEqual(tuple(self.module.parse_routes(text)), ("vless", "vless", "zapret"))

    def test_garbage_or_unknown_modes_return_unknown(self):
        for text in (
            "",
            "garbage",
            "# Active routes: Discord=proxy, YouTube=direct.",
            "# Active routes: Discord=direct, YouTube=direct",  # missing final dot
            "  # Active routes: Discord=direct, YouTube=direct.",  # not at line start
            "# Active routes: DiscordTCP=direct, YouTube=direct.",  # Voice missing
            "# Active routes: DiscordTCP=direct, DiscordVoice=vpn, YouTube=direct.",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.module.parse_routes(text), ("unknown", "unknown", "unknown"))


class JsoncTests(DiagnosticsUnitBase):
    def test_comments_are_removed_outside_strings(self):
        text = '// head\n{"a": "http://x//y", /* c */ "b": "q\\"//z", "c": 1 // tail\n}'
        self.assertEqual(
            json.loads(self.module.strip_json_comments(text)),
            {"a": "http://x//y", "b": 'q"//z', "c": 1},
        )
        self.assertEqual(self.module.strip_json_comments('{"s":"/* kept */"}'), '{"s":"/* kept */"}')
        self.assertEqual(self.module.strip_json_comments("/* unterminated"), " ")

    def test_upgrade_findings_read_jsonc(self):
        files = {
            "04_outbounds.json": '// JSONC\n{"outbounds": [{"tag": "direct", "protocol": "freedom",'
            ' "streamSettings": {"sockopt": {"addressPortStrategy": "SrvPortOnly"}}}]}',
            "05_commented.json": '{/* "proxySettings": {} */ "outbounds": []}',
        }
        self.assertEqual(
            self.module.xray_upgrade_findings(files),
            ["04_outbounds.json: freedom direct sockopt.addressPortStrategy"],
        )


class XrayUpgradeTests(DiagnosticsUnitBase):
    def test_only_real_outbound_fields_are_migration_findings(self):
        files = {'notes.json': json.dumps({'notes': {'proxySettings': {}}, 'outbounds': []}),
                 'bom.json': '\ufeff// header\n{"outbounds": []}',
                 'types.json': '{"outbounds": null}'}
        self.assertEqual(self.module.xray_upgrade_findings(files), [])

    def test_malformed_json_does_not_claim_compatibility_or_echo_contents(self):
        findings = self.module.xray_upgrade_findings({'broken.json': '{"secret":"PRIVATE_SENTINEL"'})
        self.assertEqual(len(findings), 1)
        self.assertIn('совместимость не подтверждена', findings[0])
        self.assertNotIn('PRIVATE_SENTINEL', findings[0])

    def test_clean_configs(self):
        files = {
            "04_outbounds.json": json.dumps({"outbounds": [
                {"tag": "direct", "protocol": "freedom", "streamSettings": {"sockopt": {"mark": 255}}},
                {"tag": "vless", "protocol": "vless", "streamSettings": {"sockopt": {"dialerProxy": "x"}}},
            ]}),
            "05_routing.json": "// comment makes this JSONC\n{}",
        }
        self.assertEqual(self.module.xray_upgrade_findings(files), [])

    def test_removed_and_fatal_settings(self):
        files = {
            "04_outbounds.json": json.dumps({"outbounds": [
                {"tag": "direct", "protocol": "freedom",
                 "streamSettings": {"sockopt": {"addressPortStrategy": "SrvPortOnly"}}},
                {"tag": "chain", "protocol": "vless", "proxySettings": {"tag": "direct"}},
                "junk",
            ]}),
            "06_jsonc.json": '// JSONC\n{"outbounds": [{"proxySettings": {}}]}',
            "07_list.json": "[]",
        }
        self.assertEqual(
            self.module.xray_upgrade_findings(files),
            [
                "04_outbounds.json: proxySettings → sockopt.dialerProxy",
                "04_outbounds.json: freedom direct sockopt.addressPortStrategy",
                "06_jsonc.json: proxySettings → sockopt.dialerProxy",
            ],
        )


class RouteConsistencyTests(DiagnosticsUnitBase):
    def test_vless_mode_does_not_require_direct_tags(self):
        config = "# Active routes: Discord=vless, YouTube=vless."
        checks = self.module.route_consistency(config, engine_rules(set()), "")
        self.assertEqual([c["status"] for c in checks], ["ok", "ok", "ok"])
        self.assertEqual(
            [c["name"] for c in checks],
            ["YouTube route", "Discord TCP route", "Discord Voice route"],
        )
        self.assertEqual(checks[0]["detail"], "route=vless, nfqws=off")

    def test_zapret_mode_requires_active_hostlist_and_tag(self):
        config = (
            "# Active routes: Discord=zapret, YouTube=zapret.\n"
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list\n"
            "--filter-l7=stun,discord"
        )
        tags = {"discord-direct", "youtube-direct"}
        checks = self.module.route_consistency(config, engine_rules(tags), "discord.com\n")
        self.assertEqual([c["status"] for c in checks], ["ok", "ok", "ok"])
        self.assertEqual(checks[1]["detail"], "route=zapret, nfqws=on")

        # Whitespace-only Discord list means nfqws is not active for Discord TCP.
        checks = self.module.route_consistency(config, engine_rules(tags), "  \n")
        self.assertEqual([c["status"] for c in checks], ["ok", "error", "ok"])

    def test_unknown_routes_are_errors(self):
        checks = self.module.route_consistency("garbage", engine_rules({"discord-direct", "youtube-direct"}), "")
        self.assertEqual([c["status"] for c in checks], ["error", "error", "error", "error"])
        self.assertEqual(checks[0]["detail"], "route=unknown, nfqws=off")


class TelegramRouteTests(DiagnosticsUnitBase):
    HEADER = "# Active routes: DiscordTCP=vless, DiscordVoice=vless, YouTube=vless, Telegram={}.\n"
    PROFILE = "--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list\n"

    def telegram_check(self, route, tags, profile=False):
        config = self.HEADER.format(route) + (self.PROFILE if profile else "")
        checks = self.module.route_consistency(config, engine_rules(tags), "")
        return [check for check in checks if check["name"] == "Telegram route"]

    def test_header_with_telegram_is_parsed(self):
        # Zapret is no longer a Telegram mode, but old headers still parse.
        text = self.HEADER.format("zapret")
        self.assertEqual(self.module.parse_routes(text), ("vless", "vless", "vless"))
        self.assertEqual(self.module.telegram_route(text), "zapret")
        self.assertEqual(self.module.telegram_route("# Active routes: Discord=vless, YouTube=vless."), "unmanaged")
        self.assertEqual(self.module.telegram_route("garbage"), "unknown")
        self.assertEqual(self.module.telegram_route(self.HEADER.format("proxy")), "unknown")

    def test_unmanaged_adds_no_check_unless_profile_is_left(self):
        self.assertEqual(self.telegram_check("unmanaged", set()), [])
        [check] = self.telegram_check("unmanaged", set(), profile=True)
        self.assertEqual((check["status"], check["detail"]), ("error", "route=unmanaged, nfqws=on"))

    def test_managed_routes(self):
        for route, tags, profile, status in (
            ("direct", {"telegram-direct"}, False, "ok"),
            ("direct", set(), False, "error"),
            ("direct", {"telegram-direct"}, True, "error"),
            ("zapret", {"telegram-direct"}, True, "error"),
            ("zapret", {"telegram-direct"}, False, "error"),
            ("vless", set(), False, "ok"),
            ("vless", set(), True, "error"),
            ("ws", {"telegram-direct", "telegram-ws"}, True, "ok"),
            ("ws", {"telegram-direct"}, True, "error"),
            ("ws", {"telegram-direct", "telegram-ws"}, False, "error"),
        ):
            with self.subTest(route=route, tags=tags, profile=profile):
                [check] = self.telegram_check(route, tags, profile)
                self.assertEqual(check["status"], status)

    def test_recorded_zapret_route_is_an_error(self):
        # Left by an older apply or restored from an old snapshot.
        for profile in (True, False):
            with self.subTest(profile=profile):
                [check] = self.telegram_check("zapret", {"telegram-direct"}, profile)
                self.assertEqual(
                    (check["status"], check["detail"]),
                    ("error", "route=zapret (режим удалён, выберите другой)"),
                )

    def test_ws_route_must_not_keep_the_mtproto_ipset(self):
        config = (self.HEADER.format("ws") + self.PROFILE
                  + "--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list\n")
        [check] = [c for c in self.module.route_consistency(config, engine_rules({"telegram-direct", "telegram-ws"}), "")
                   if c["name"] == "Telegram route"]
        self.assertEqual(check["status"], "error")


class SummaryTests(DiagnosticsUnitBase):
    def test_health_counts_unknown_and_missing_status_as_error(self):
        results = [
            {"status": "ok"},
            {"status": "ok"},
            {"status": "warn"},
            {"status": "error"},
            {"status": "weird"},
            {},
        ]
        self.assertEqual(
            self.module.summary("health", results),
            {"ok": 2, "warn": 1, "error": 3, "unsupported": 0, "likely_blocked": 0},
        )

    def test_standard_counts_checks_pings_and_errors(self):
        results = [
            {
                "name": "url",
                "kind": "url",
                "checks": [
                    {"status": "ok"},
                    {"status": "unsupported"},
                    {"status": "error"},
                ],
            },
            {"name": "ping-ok", "kind": "ping", "ping": {"status": "ok"}},
            {"name": "ping-timeout", "kind": "ping", "ping": {"status": "timeout"}},
            {"name": "dns", "kind": "url", "error": "DNS timeout"},
            {"name": "bogus", "kind": "url", "checks": [{"status": "mystery"}, {}]},
        ]
        self.assertEqual(
            self.module.summary("standard", results),
            {"ok": 2, "warn": 1, "error": 4, "unsupported": 1, "likely_blocked": 0},
        )

    def test_dpi_counts_likely_blocked(self):
        results = [
            {"id": "A", "checks": [{"status": "likely_blocked"}, {"status": "ok"}, {"status": "fail"}]},
        ]
        counts = self.module.summary("dpi", results)
        self.assertEqual(counts["likely_blocked"], 1)
        self.assertEqual(counts["ok"], 1)
        self.assertEqual(counts["error"], 1)


class FileHelperTests(DiagnosticsUnitBase):
    def test_safe_read_returns_regular_file_text(self):
        path = self.tmp / "file.txt"
        path.write_bytes("привет\n".encode("utf-8") + b"\xff")
        self.assertEqual(self.module.safe_read(path), "привет\n�")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_safe_read_rejects_symlink(self):
        target = self.tmp / "target.txt"
        target.write_text("data", encoding="utf-8")
        link = self.tmp / "link.txt"
        try:
            link.symlink_to(target)
        except OSError as exc:  # pragma: no cover - e.g. unprivileged Windows
            self.skipTest(f"cannot create symlink: {exc}")
        with self.assertRaisesRegex(ValueError, "unsafe file"):
            self.module.safe_read(link)

    def test_safe_read_rejects_oversized_file_and_directory(self):
        path = self.tmp / "big.txt"
        path.write_text("x" * 11, encoding="utf-8")
        self.assertEqual(self.module.safe_read(path, 11), "x" * 11)
        with self.assertRaisesRegex(ValueError, "unsafe file"):
            self.module.safe_read(path, 10)
        with self.assertRaisesRegex(ValueError, "unsafe file"):
            self.module.safe_read(self.tmp)

    def test_safe_read_missing_file_raises_oserror(self):
        with self.assertRaises(FileNotFoundError):
            self.module.safe_read(self.tmp / "missing")

    def test_atomic_json_creates_private_parent_and_replaces(self):
        path = self.tmp / "nested" / "state.json"
        self.module.atomic_json(path, {"a": 1})
        self.module.atomic_json(path, {"a": 2})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 2})
        self.assertTrue(path.read_text(encoding="utf-8").endswith("\n"))
        self.assertEqual([item.name for item in path.parent.iterdir()], ["state.json"])
        if os.name != "nt":
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_atomic_json_rejects_oversized_state_without_writing(self):
        path = self.tmp / "state.json"
        with mock.patch.object(self.module, "STATE_LIMIT", 16):
            with self.assertRaisesRegex(RuntimeError, "exceeds 512 KiB"):
                self.module.atomic_json(path, {"payload": "x" * 64})
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_state_writer_merges_changes(self):
        path = self.tmp / "jobs" / "state.json"
        with mock.patch.object(self.module, "STATE_PATH", path):
            writer = self.module.StateWriter({"status": "running", "progress": 1})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "running")
            writer.write(progress=50, extra="x")
        state = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(state, {"status": "running", "progress": 50, "extra": "x"})

    def test_root_path_honours_test_root(self):
        with mock.patch.object(self.module, "TEST_ROOT", ""):
            self.assertEqual(self.module.root_path("/opt/etc/x"), Path("/opt/etc/x"))
        with mock.patch.object(self.module, "TEST_ROOT", str(self.tmp)):
            self.assertEqual(self.module.root_path("/opt/etc/x"), self.tmp / "opt" / "etc" / "x")

    def test_make_check_truncates_detail(self):
        check = self.module.make_check("n", "ok", "d" * 2000)
        self.assertEqual(len(check["detail"]), 1000)


class RunTests(DiagnosticsUnitBase):
    def test_run_success_and_failure_with_real_interpreter(self):
        result = self.module.run([sys.executable, "-c", "print(' hi ')"], 30)
        self.assertEqual(result, {"ok": True, "code": 0, "output": "hi"})
        result = self.module.run([sys.executable, "-c", "import sys; print('bad'); sys.exit(3)"], 30)
        self.assertEqual(result, {"ok": False, "code": 3, "output": "bad"})

    def test_run_missing_binary_returns_127(self):
        result = self.module.run([str(self.tmp / "no-such-binary")], 5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 127)

    def test_run_timeout_returns_124_with_partial_output(self):
        error = subprocess.TimeoutExpired(cmd=["x"], timeout=1, output=b"partial\n")
        with mock.patch.object(self.module.subprocess, "run", side_effect=error):
            result = self.module.run(["x"], 1)
        self.assertEqual(result, {"ok": False, "code": 124, "output": "timeout\npartial"})

    def test_run_timeout_without_output(self):
        error = subprocess.TimeoutExpired(cmd=["x"], timeout=1, output=None)
        with mock.patch.object(self.module.subprocess, "run", side_effect=error):
            result = self.module.run(["x"], 1)
        self.assertEqual(result["output"], "timeout")

    def test_run_truncates_output_and_passes_safe_options(self):
        with mock.patch.object(self.module.subprocess, "run", return_value=completed(0, b"a" * 13000)) as runner:
            result = self.module.run(["x", "y"], 7)
        self.assertEqual(len(result["output"]), 12000)
        kwargs = runner.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 7)
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["env"]["PATH"].startswith("/opt/bin:/opt/sbin"))

    def test_run_refuses_after_cancellation(self):
        self.module.CANCELLED.set()
        with mock.patch.object(self.module.subprocess, "run") as runner:
            with self.assertRaises(InterruptedError):
                self.module.run(["x"], 1)
        runner.assert_not_called()

    def test_handle_signal_sets_cancelled(self):
        self.module.handle_signal(15, None)
        self.assertTrue(self.module.CANCELLED.is_set())

    def test_command_path_falls_back_to_name(self):
        with mock.patch.object(self.module.shutil, "which", return_value=None):
            self.assertEqual(self.module.command_path("pidof"), "pidof")
        with mock.patch.object(self.module.shutil, "which", return_value="/opt/bin/pidof"):
            self.assertEqual(self.module.command_path("pidof"), "/opt/bin/pidof")

    def test_process_ids(self):
        with mock.patch.object(self.module, "run", return_value={"ok": True, "code": 0, "output": "12 34 x"}):
            self.assertEqual(self.module.process_ids("xray"), [12, 34])
        with mock.patch.object(self.module, "run", return_value={"ok": False, "code": 1, "output": "99"}):
            self.assertEqual(self.module.process_ids("xray"), [])


def addrinfo(*addresses):
    return [(2, 1, 6, "", (address, 443)) for address in addresses]


class ResolvePublicTests(DiagnosticsUnitBase):
    def test_public_answers_are_sorted_and_limited(self):
        answers = addrinfo("8.8.8.8", "1.1.1.1", "1.0.0.1", "8.8.4.4", "9.9.9.9", "1.1.1.1")
        with mock.patch.object(self.module.socket, "getaddrinfo", return_value=answers):
            self.assertEqual(
                self.module.resolve_public("example.com"),
                (True, "1.0.0.1, 1.1.1.1, 8.8.4.4, 8.8.8.8"),
            )

    def test_private_and_invalid_answers_are_rejected(self):
        with mock.patch.object(self.module.socket, "getaddrinfo", return_value=addrinfo("10.0.0.1", "1.1.1.1", "bogus")):
            okay, detail = self.module.resolve_public("example.com")
        self.assertFalse(okay)
        self.assertEqual(detail, "private/unexpected DNS answer: 10.0.0.1, bogus")

    def test_resolver_error_and_empty_answer(self):
        with mock.patch.object(self.module.socket, "getaddrinfo", side_effect=OSError("no such host")):
            self.assertEqual(self.module.resolve_public("example.com"), (False, "no such host"))
        with mock.patch.object(self.module.socket, "getaddrinfo", return_value=[]):
            self.assertEqual(self.module.resolve_public("example.com"), (False, "no addresses"))

    def test_resolver_timeout(self):
        class EmptyQueue:
            def __init__(self, maxsize=0):
                pass

            def put(self, _item):
                pass

            def get(self, timeout=None):
                raise queue.Empty

        with mock.patch.object(self.module.socket, "getaddrinfo", return_value=addrinfo("1.1.1.1")):
            with mock.patch.object(self.module.queue, "Queue", EmptyQueue):
                self.assertEqual(self.module.resolve_public("example.com"), (False, "DNS timeout (4s)"))


class ProbeTests(DiagnosticsUnitBase):
    def test_curl_probe_unsupported_and_error(self):
        unsupported = {"ok": False, "code": 4, "output": "curl: option --tlsv1.3: Unknown option"}
        with mock.patch.object(self.module, "run", return_value=unsupported):
            result = self.module.curl_probe("https://x", "TLS1.3", [], 5)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["http_code"], "000")
        self.assertEqual(result["time"], -1.0)
        self.assertEqual(result["exit_code"], 4)

        failed = {"ok": False, "code": 28, "output": "timeout\n__XKRES__000|5.0|"}
        with mock.patch.object(self.module, "run", return_value=failed):
            result = self.module.curl_probe("https://x", "HTTP/1.1", [], 5)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["time"], 5.0)
        self.assertIn("timeout", result["detail"])

    def test_curl_probe_zero_code_with_success_exit_is_error(self):
        with mock.patch.object(self.module, "run", return_value={"ok": True, "code": 0, "output": "__XKRES__000|0.1|"}):
            self.assertEqual(self.module.curl_probe("https://x", "HTTP/1.1", [], 5)["status"], "error")

    def test_ping_probe(self):
        with mock.patch.object(self.module, "run", return_value={"ok": True, "code": 0, "output": "64 bytes: time=12.5 ms"}):
            self.assertEqual(self.module.ping_probe("1.1.1.1"), {"status": "ok", "time_ms": 12.5})
        with mock.patch.object(self.module, "run", return_value={"ok": False, "code": 1, "output": "100% loss"}):
            self.assertEqual(self.module.ping_probe("1.1.1.1"), {"status": "timeout", "time_ms": None})

    def test_standard_target_ping_and_url(self):
        ping = {"status": "ok", "time_ms": 1.0}
        with mock.patch.object(self.module, "ping_probe", return_value=ping):
            result = self.module.standard_target("DNS", "PING:1.1.1.1")
            self.assertEqual(result, {"name": "DNS", "target": "1.1.1.1", "kind": "ping", "ping": ping})

            probe = {"status": "ok"}
            with mock.patch.object(self.module, "resolve_public", return_value=(True, "1.2.3.4")):
                with mock.patch.object(self.module, "curl_probe", return_value=probe) as curl:
                    result = self.module.standard_target("API", "https://discord.com/api/v10/gateway")
        self.assertEqual(result["host"], "discord.com")
        self.assertEqual(result["dns"], {"status": "ok", "detail": "1.2.3.4"})
        self.assertEqual(len(result["checks"]), 3)
        self.assertEqual([call.args[1] for call in curl.call_args_list], ["HTTP/1.1", "TLS1.2", "TLS1.3"])

    def test_run_standard_orders_results_and_captures_exceptions(self):
        targets = (("A", "PING:1.1.1.1"), ("B", "https://b.example"), ("C", "https://c.example"))

        def fake_target(name, value):
            if name == "B":
                raise RuntimeError("boom")
            return {"name": name, "kind": "ping", "ping": {"status": "ok"}}

        writer = RecordingWriter()
        with mock.patch.object(self.module, "STANDARD_TARGETS", targets):
            with mock.patch.object(self.module, "standard_target", side_effect=fake_target):
                results = self.module.run_standard(writer)
        self.assertEqual([item["name"] for item in results], ["A", "B", "C"])
        self.assertEqual(results[1], {"name": "B", "kind": "error", "error": "boom"})
        self.assertEqual(len(writer.calls), 3)
        self.assertEqual(writer.calls[-1]["progress"], 95)

    def test_run_standard_stops_when_cancelled(self):
        def fake_target(name, value):
            self.module.CANCELLED.set()
            return {"name": name}

        with mock.patch.object(self.module, "STANDARD_TARGETS", (("A", "PING:1.1.1.1"),)):
            with mock.patch.object(self.module, "standard_target", side_effect=fake_target):
                with self.assertRaises(InterruptedError):
                    self.module.run_standard(RecordingWriter())

    def test_dpi_probe_and_target(self):
        payload = self.tmp / "payload.bin"
        output = {"ok": True, "code": 0, "output": "__XKDPI__200|65536|1024|0.5|203.0.113.5"}
        with mock.patch.object(self.module, "run", return_value=output) as runner:
            result = self.module.dpi_probe("example.com", "HTTP/1.1", ["--http1.1"], payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["uploaded"], result["downloaded"], result["remote_ip"]), (65536, 1024, "203.0.113.5"))
        self.assertEqual(result["detail"], "")
        command = runner.call_args.args[0]
        self.assertIn(f"@{payload}", command)
        self.assertEqual(command[-1], "https://example.com")

        with mock.patch.object(self.module, "run", return_value={"ok": False, "code": 7, "output": "refused"}):
            result = self.module.dpi_probe("example.com", "HTTP/1.1", [], payload)
        self.assertEqual((result["status"], result["http_code"], result["time"]), ("fail", "000", -1.0))

        with mock.patch.object(self.module, "resolve_public", return_value=(False, "nx")):
            result = self.module.dpi_target("ID", "Prov", "example.com", payload)
        self.assertEqual(result["error"], "nx")
        with mock.patch.object(self.module, "resolve_public", return_value=(True, "1.2.3.4")):
            with mock.patch.object(self.module, "dpi_probe", return_value={"status": "ok"}):
                result = self.module.dpi_target("ID", "Prov", "example.com", payload)
        self.assertEqual(len(result["checks"]), 3)
        self.assertEqual(result["dns"]["status"], "ok")

    def test_dpi_marker_and_classification_edges(self):
        self.assertIsNone(self.module.parse_dpi_marker("no marker"))
        parsed = ("000", 65536, 0, 2.0, "")
        # Not long enough to count as a stall.
        self.assertEqual(self.module.classify_dpi(28, parsed, "", 6), "fail")
        # Data downloaded means not a stall even when slow.
        self.assertEqual(self.module.classify_dpi(28, ("000", 1, 1, 6.0, ""), "", 6), "fail")
        self.assertEqual(self.module.classify_dpi(0, None, "", 6), "fail")


HEALTHY_NAMES = [
    "Xray",
    "nfqws2",
    "Управляемые маршруты",
    "Discord hostlist",
    "YouTube hostlist",
    "Xray routing",
    "Xray outbounds",
    "Xray 26.10+ совместимость",
    "YouTube route",
    "Discord TCP route",
    "Discord Voice route",
    "nfqws2: порты профилей в очереди",
    "nfqws2: порты без профиля",
    "Xray config test",
    "NFQUEUE: порты",
    "NFQUEUE: переходы",
    "NFQUEUE: счётчики",
    "IPv4 WAN route",
    "IPv6 и nfqws2",
    "DNS discord.com",
    "DNS www.youtube.com",
    "SNI/IP discord.com (с роутера)",
    "SNI/IP www.youtube.com (с роутера)",
    "Свободное место /opt",
    "Доступная память",
    "Conntrack",
    "Project lock",
    "Другие DPI bypass",
]


class RunHealthTests(DiagnosticsUnitBase):
    def run_health(self, fake_run, resolve=(True, "1.1.1.1"), disk=None, doh=None, probe=None):
        disk = disk or SimpleNamespace(total=1000 * 1024 * 1024, used=0, free=500 * 1024 * 1024)
        disk_kwargs = {"side_effect": disk} if isinstance(disk, Exception) else {"return_value": disk}
        doh = doh or (lambda host, _name, _ip: ["1.1.1.1"])
        writer = RecordingWriter()
        with mock.patch.object(self.module, "TEST_ROOT", str(self.tmp)), \
                mock.patch.object(self.module, "run", side_effect=fake_run), \
                mock.patch.object(self.module, "resolve_public", return_value=resolve), \
                mock.patch.object(self.module, "doh_resolve", side_effect=doh), \
                mock.patch.object(self.module, "QUIC_PROBE_PATH", probe or self.tmp / "missing-quic_probe.py"), \
                mock.patch.object(self.module.shutil, "disk_usage", **disk_kwargs) as disk_usage:
            checks = self.module.run_health(writer)
        disk_usage.assert_called_once_with(self.tmp / "opt")
        return checks, writer

    def by_name(self, *args, **kwargs):
        checks, _writer = self.run_health(*args, **kwargs)
        return {check["name"]: check for check in checks}

    def test_healthy_fixture_tree_is_all_ok(self):
        build_healthy_tree(self.tmp, self.module)
        checks, writer = self.run_health(healthy_run())
        self.assertEqual([check["name"] for check in checks], HEALTHY_NAMES)
        bad = [check for check in checks if check["status"] != "ok"]
        self.assertEqual(bad, [])
        by_name = {check["name"]: check["detail"] for check in checks}
        self.assertEqual(by_name["Xray"], "PID: [101]")
        self.assertEqual(
            by_name["Управляемые маршруты"],
            "Discord TCP=zapret, Discord Voice=zapret, YouTube=direct, Telegram=unmanaged",
        )
        self.assertEqual(by_name["Discord hostlist"], "2 записей; route=zapret")
        self.assertEqual(by_name["YouTube hostlist"], "0 записей; route=не zapret")
        self.assertEqual(by_name["Xray routing"], "05_routing.json: service-direct rules согласованы")
        self.assertEqual(by_name["Xray outbounds"], "freedom без прокси: discord-direct, youtube-direct")
        self.assertEqual(by_name["Xray config test"], "Configuration OK")
        self.assertIn("движок без --check-config", by_name["nfqws2: порты профилей в очереди"])
        self.assertEqual(
            by_name["NFQUEUE: счётчики"],
            "исх. UDP 19294-19344,50000-50100: 12 пак.; исх. TCP 443: 24 пак.; "
            "ответы UDP 19294-19344,50000-50100: 12 пак.; ответы TCP 443: 12 пак.",
        )
        self.assertEqual(by_name["DNS discord.com"], "роутер: 1.1.1.1; DoH Yandex: 1.1.1.1; DoH Google: 1.1.1.1")
        self.assertEqual(by_name["Доступная память"], "128 MiB")
        self.assertEqual(by_name["Conntrack"], "100/1000 (10.0%)")
        self.assertEqual(by_name["Свободное место /opt"], "500 MiB (50.0%)")
        self.assertEqual(len(writer.calls), len(checks))
        self.assertEqual(writer.calls[0]["progress"], 8)
        self.assertEqual(writer.calls[-1]["progress"], 89)

    def test_engine_check_config_lines_are_shown(self):
        # D1: the engine's invariant check, one item per CHECK line.
        build_healthy_tree(self.tmp, self.module)
        engine = (
            "CHECK|ok|port-coverage|all filter ports are queued\n"
            "CHECK|error|listless-profile|profile 3 has --lua-desync without a hostlist\n"
            "CHECK|warn|some-new-check|details\n"
        )
        seen = []
        base = healthy_run(engine_output=engine)

        def fake_run(command, timeout, extra_env=None):
            if command[-1:] == ["--check-config"]:
                seen.append((command, extra_env))
            return base(command, timeout)

        checks = self.by_name(fake_run)
        [(command, extra_env)] = seen
        self.assertEqual(command, ["/bin/sh", str(self.module.ENGINE_PATH), "--check-config"])
        # The engine reads the same test tree.
        self.assertEqual(extra_env, {"KD_TEST_ROOT": str(self.tmp)})
        self.assertEqual(checks["nfqws2: порты профилей в очереди"]["detail"], "all filter ports are queued")
        self.assertEqual(checks["nfqws2: профили без hostlist"]["status"], "error")
        self.assertEqual(checks["nfqws2: some-new-check"]["status"], "warn")
        self.assertNotIn("nfqws2: порты без профиля", checks)

    def test_incident_youtube_quic_port_missing_is_an_error(self):
        # D1/E17: the 3.1.0 output (UDP_PORTS without 443) with the incident's live rules.
        build_healthy_tree(self.tmp, self.module, INCIDENT_CONF.replace("{udp}", "19294:19344,50000:50100"))
        write_file(self.tmp, self.module.YOUTUBE_LIST_LOGICAL, "youtube.com\n")
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["YouTube route"]["status"], "ok")
        coverage = checks["nfqws2: порты профилей в очереди"]
        self.assertEqual(coverage["status"], "error")
        self.assertIn("UDP 443 нет в UDP_PORTS", coverage["detail"])
        self.assertEqual(checks["YouTube QUIC (UDP 443)"]["status"], "error")
        self.assertIn("443", checks["YouTube QUIC (UDP 443)"]["detail"])
        # The live QUIC probe is offered for YouTube=zapret; missing probe file -> warning.
        self.assertEqual(checks["YouTube QUIC с роутера"]["status"], "warn")
        # The 3.1.1 output passes.
        build_healthy_tree(self.tmp, self.module, INCIDENT_CONF.replace("{udp}", "443,19294:19344,50000:50100"))
        checks = self.by_name(healthy_run(iptables=iptables_save(udp="443,19294:19344,50000:50100")))
        self.assertEqual(checks["nfqws2: порты профилей в очереди"]["status"], "ok")
        self.assertEqual(checks["YouTube QUIC (UDP 443)"]["status"], "ok")
        self.assertEqual(checks["NFQUEUE: порты"]["status"], "ok")

    def test_stale_nfqueue_rules_are_an_error(self):
        # D1: the config has 443, the live rules do not (nfqws2 not restarted).
        build_healthy_tree(self.tmp, self.module, INCIDENT_CONF.replace("{udp}", "443,19294:19344,50000:50100"))
        write_file(self.tmp, self.module.YOUTUBE_LIST_LOGICAL, "youtube.com\n")
        checks = self.by_name(healthy_run(iptables=iptables_save(udp="19294:19344,50000:50100")))
        self.assertEqual(checks["nfqws2: порты профилей в очереди"]["status"], "ok")
        self.assertEqual(checks["NFQUEUE: порты"]["status"], "error")
        self.assertIn("nfqws_post UDP без 443", checks["NFQUEUE: порты"]["detail"])
        self.assertIn("nfqws_pre UDP без 443", checks["NFQUEUE: порты"]["detail"])

    def test_nfqueue_jumps_must_exist_exactly_once(self):
        build_healthy_tree(self.tmp, self.module)
        for jumps, status in ((0, "error"), (2, "warn"), (1, "ok")):
            with self.subTest(jumps=jumps):
                checks = self.by_name(healthy_run(iptables=iptables_save(jumps=jumps)))
                self.assertEqual(checks["NFQUEUE: переходы"]["status"], status)
        checks = self.by_name(healthy_run(iptables=iptables_save(counters=False)))
        self.assertIn("UDP 19294-19344,50000-50100: ? пак.", checks["NFQUEUE: счётчики"]["detail"])

    def test_ipv6_default_route_with_ipv6_off_is_a_warning(self):
        build_healthy_tree(self.tmp, self.module)
        checks = self.by_name(healthy_run(ipv6_route="default via fe80::1 dev eth3 proto ra metric 1024"))
        self.assertEqual(checks["IPv6 и nfqws2"]["status"], "warn")
        self.assertIn("мимо nfqws2", checks["IPv6 и nfqws2"]["detail"])
        # A default route through another interface (not the WAN of nfqws2) is not.
        checks = self.by_name(healthy_run(ipv6_route="default via fe80::1 dev br0"))
        self.assertEqual(checks["IPv6 и nfqws2"]["status"], "ok")
        # With IPv6 on, the ip6tables rules are checked as well.
        build_healthy_tree(self.tmp, self.module, HEALTHY_CONF.replace("IPV6_ENABLED=0", "IPV6_ENABLED=1"))
        base = healthy_run(ipv6_route="default via fe80::1 dev eth3")
        tools = []

        def fake_run(command, timeout, extra_env=None):
            if Path(command[0]).name == "ip6tables-save":
                tools.append(command)
                return {"ok": True, "code": 0, "output": iptables_save(udp="19294:19344")}
            return base(command, timeout)

        checks = self.by_name(fake_run)
        self.assertEqual(checks["IPv6 и nfqws2"]["status"], "ok")
        self.assertEqual(tools[0][1:], ["-c", "-t", "mangle"])
        self.assertEqual(checks["NFQUEUE IPv6: порты"]["status"], "error")
        self.assertEqual(checks["NFQUEUE: порты"]["status"], "ok")

    def test_routing_file_is_the_last_one_with_a_routing_object(self):
        # D6: a later routing file replaces 05_routing.json in Xray.
        build_healthy_tree(self.tmp, self.module)
        write_file(
            self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/06_routing_user.json",
            json.dumps({"routing": {"rules": [{"outboundTag": "vless-reality"}]}}),
        )
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/07_policy.json", '{"policy": {}}')
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Xray routing"]["status"], "error")
        self.assertTrue(checks["Xray routing"]["detail"].startswith("06_routing_user.json: missing: "))
        self.assertEqual(checks["Discord TCP route"]["status"], "error")
        self.assertEqual(checks["Discord Voice route"]["status"], "error")

    def test_project_outbounds_are_checked(self):
        # D7: a missing or proxied -direct outbound sends the service through the VPN.
        build_healthy_tree(self.tmp, self.module)
        outbounds = [item for item in HEALTHY_OUTBOUNDS["outbounds"] if item["tag"] != "youtube-direct"]
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/04_outbounds.json", json.dumps({"outbounds": outbounds}))
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Xray outbounds"]["status"], "error")
        self.assertIn("youtube-direct: outbound не найден", checks["Xray outbounds"]["detail"])
        proxied = outbounds + [{"tag": "youtube-direct", "protocol": "freedom",
                                "streamSettings": {"sockopt": {"dialerProxy": "vless-reality"}}}]
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/04_outbounds.json", json.dumps({"outbounds": proxied}))
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Xray outbounds"]["status"], "error")
        self.assertIn("dialerProxy=vless-reality", checks["Xray outbounds"]["detail"])
        # Any rule that points to an undefined tag is a warning.
        routing = {"routing": {"rules": HEALTHY_ROUTING["routing"]["rules"] + [{"outboundTag": "typo"}]}}
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", json.dumps(routing))
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/04_outbounds.json", json.dumps(HEALTHY_OUTBOUNDS))
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Xray outbounds"]["status"], "warn")
        self.assertIn("typo", checks["Xray outbounds"]["detail"])

    def test_telegram_ws_relay_is_checked(self):
        # D9: the relay must be our process and accept connections on its port.
        conf = HEALTHY_CONF.replace("YouTube=direct.", "YouTube=direct, Telegram=ws.").replace(
            'NFQWS_ARGS="', 'NFQWS_ARGS_CUSTOM="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list"\nNFQWS_ARGS="'
        )
        build_healthy_tree(self.tmp, self.module, conf)
        routing = {"routing": {"rules": engine_rules({"discord-direct", "youtube-direct", "telegram-ws"})}}
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", json.dumps(routing))
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Telegram route"]["status"], "ok")
        self.assertEqual(checks["Telegram WS relay"]["status"], "error")
        self.assertIn("нет pid-файла", checks["Telegram WS relay"]["detail"])
        # Another live process: a child with a command line of its own, not the runner, whose arguments are not ours.
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "other_process.py"])
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        wait_for_cmdline(other.pid)
        pidfile = write_file(self.tmp, self.module.TELEGRAM_WS_PIDFILE_LOGICAL, f"{other.pid}\n")
        checks = self.by_name(healthy_run())
        self.assertIn("не telegram_ws_relay.py", checks["Telegram WS relay"]["detail"])

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        relay = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "telegram_ws_relay.py"])
        self.addCleanup(relay.wait)
        self.addCleanup(relay.kill)
        wait_for_cmdline(relay.pid)
        pidfile.write_text(f"{relay.pid}\n", encoding="ascii")
        with mock.patch.object(self.module, "TELEGRAM_WS_PORT", listener.getsockname()[1]):
            checks = self.by_name(healthy_run())
            self.assertEqual(checks["Telegram WS relay"]["status"], "ok", checks["Telegram WS relay"])
            listener.close()
            checks = self.by_name(healthy_run())
        self.assertEqual(checks["Telegram WS relay"]["status"], "error")
        self.assertIn("не принимает соединения", checks["Telegram WS relay"]["detail"])

    def test_live_quic_probe_from_the_router(self):
        build_healthy_tree(self.tmp, self.module, INCIDENT_CONF.replace("{udp}", "443,19294:19344,50000:50100"))
        write_file(self.tmp, self.module.YOUTUBE_LIST_LOGICAL, "youtube.com\n")
        probe = write_file(self.tmp, "/project/tools/router/quic_probe.py", "# stub\n")
        base = healthy_run(iptables=iptables_save(udp="443,19294:19344,50000:50100"))
        answers = {}

        def fake_run(command, timeout, extra_env=None):
            if command[1:2] == [str(probe)]:
                answers["command"] = command
                status = answers["status"]
                return {"ok": status == "ok", "code": 0 if status == "ok" else 1,
                        "output": f"EVENT|QUIC|health|www.youtube.com|142.250.74.110|{status}|41\n"}
            return base(command, timeout)

        for status, expected in (("ok", "ok"), ("no-reply", "warn"), ("dns-error", "warn")):
            answers["status"] = status
            with self.subTest(status=status):
                checks, _writer = self.run_health(fake_run, probe=probe)
                check = {item["name"]: item for item in checks}["YouTube QUIC с роутера"]
                self.assertEqual(check["status"], expected)
                self.assertIn("www.youtube.com", check["detail"])
        self.assertEqual(answers["command"][2:], ["www.youtube.com", "--timeout", "2", "--tries", "2", "--label", "health"])
        self.assertIn("с самого роутера", self.module.quic_live_check(lambda *_: {"output": "EVENT|QUIC|h|www.youtube.com|1.2.3.4|ok|5"}, probe)["detail"])

    def test_dns_check_compares_with_doh(self):
        build_healthy_tree(self.tmp, self.module)
        # A non-public answer can also be intentional FakeDNS; don't infer provider blocking.
        checks = self.by_name(healthy_run(), resolve=(False, "private/unexpected DNS answer: 10.0.0.1"))
        self.assertEqual(checks["DNS discord.com"]["status"], "warn")
        self.assertIn("причина различий не подтверждена", checks["DNS discord.com"]["detail"])
        # Different addresses are only a note: CDNs answer by location.
        checks = self.by_name(healthy_run(), doh=lambda host, name, ip: ["162.159.128.233"])
        self.assertEqual(checks["DNS discord.com"]["status"], "ok")
        self.assertIn("не совпадают с DoH", checks["DNS discord.com"]["detail"])

        def unreachable(host, name, ip):
            raise OSError("timed out")

        checks = self.by_name(healthy_run(), doh=unreachable)
        self.assertEqual(checks["DNS discord.com"]["status"], "ok")
        self.assertIn("DoH недоступен", checks["DNS discord.com"]["detail"])

    def test_sni_control_probe_cannot_prove_sni_or_ip_block(self):
        build_healthy_tree(self.tmp, self.module)
        calls = []

        def curl(answers):
            def answer(command):
                calls.append(command)
                swapped = "--connect-to" in command
                ok = answers[swapped]
                return {"ok": ok, "code": 0 if ok else 28, "output": "__XKSNI__200" if ok else "timeout"}
            return answer

        checks = self.by_name(healthy_run(curl=curl({False: False, True: True})))
        self.assertEqual(checks["SNI/IP discord.com (с роутера)"]["status"], "warn")
        self.assertIn("не доказательство блокировки", checks["SNI/IP discord.com (с роутера)"]["detail"])
        self.assertIn(["--connect-to", "ya.ru:443:discord.com:443"], [c[i:i + 2] for c in calls for i in range(len(c))])
        checks = self.by_name(healthy_run(curl=curl({False: False, True: False})))
        self.assertEqual(checks["SNI/IP discord.com (с роутера)"]["status"], "warn")
        self.assertIn("причина не определена", checks["SNI/IP discord.com (с роутера)"]["detail"])
        # Services routed through the VPN are not probed from the router.
        build_healthy_tree(self.tmp, self.module, HEALTHY_CONF.replace("YouTube=direct", "YouTube=vless"))
        checks = self.by_name(healthy_run())
        self.assertNotIn("SNI/IP www.youtube.com (с роутера)", checks)

    def test_rival_bypass_tools_on_the_router(self):
        build_healthy_tree(self.tmp, self.module)
        for pid, comm, cmdline in (
            ("202", "nfqws2", b"/opt/usr/bin/nfqws2\0--qnum=300\0"),
            ("300", "nfqws2", b"/opt/usr/bin/nfqws2\0--dry-run\0"),
            ("301", "nfqws2", b"/opt/usr/bin/nfqws2\0--intercept=0\0"),
            ("400", "byedpi", b"byedpi\0"),
            ("401", "winws", b"winws\0"),
        ):
            write_file(self.tmp, f"/proc/{pid}/comm", comm + "\n")
            (self.tmp / "proc" / pid / "cmdline").write_bytes(cmdline)
        write_file(self.tmp, self.module.NFQWS_PIDFILE_LOGICAL, "202\n")
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Другие DPI bypass"]["status"], "warn")
        self.assertEqual(checks["Другие DPI bypass"]["detail"], "byedpi")
        write_file(self.tmp, "/proc/500/comm", "nfqws2\n")
        (self.tmp / "proc" / "500" / "cmdline").write_bytes(b"/tmp/nfqws2\0--qnum=200\0")
        checks = self.by_name(healthy_run())
        self.assertEqual(checks["Другие DPI bypass"]["detail"], "byedpi, ещё один nfqws2 (не наш)")

    def test_empty_tree_reports_errors_and_warnings(self):
        def failing_run(command, timeout, extra_env=None):
            return {"ok": False, "code": 1, "output": ""}

        write_file(self.tmp, "/proc/77/comm", "tpws\n")
        lock = write_file(self.tmp, self.module.PROJECT_LOCK_LOGICAL, "")
        checks, _writer = self.run_health(failing_run, resolve=(False, "DNS timeout (4s)"), disk=OSError("no disk"))
        by_name = {check["name"]: check for check in checks}
        self.assertNotIn("Управляемые маршруты", by_name)
        expected = {
            "Xray": "error",
            "nfqws2": "error",
            "Конфигурация nfqws2": "error",
            "Discord hostlist": "warn",
            "YouTube hostlist": "warn",
            "Xray routing": "error",
            "Xray outbounds": "ok",
            "YouTube route": "error",
            "Discord TCP route": "error",
            "Discord Voice route": "error",
            "Telegram route": "error",
            "Xray config test": "error",
            "NFQUEUE": "error",
            "IPv4 WAN route": "error",
            "IPv6 и nfqws2": "ok",
            "DNS discord.com": "warn",  # independent DoH answers: local failure is not proven provider blocking
            "DNS www.youtube.com": "warn",
            "Свободное место /opt": "error",
            "Доступная память": "warn",
            "Conntrack": "warn",
            "Project lock": "warn",
            "Другие DPI bypass": "warn",
        }
        self.assertEqual({name: check["status"] for name, check in by_name.items()}, expected)
        self.assertEqual(by_name["Xray"]["detail"], "процесс не найден")
        self.assertEqual(by_name["IPv4 WAN route"]["detail"], "default route отсутствует")
        self.assertEqual(by_name["Другие DPI bypass"]["detail"], "zapret (tpws)")
        self.assertIn(str(lock), by_name["Project lock"]["detail"])
        self.assertEqual(by_name["Свободное место /opt"]["detail"], "no disk")

    def test_zapret_route_with_empty_hostlists_and_bad_routing(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(self.tmp, self.module.NFQWS_CONFIG_LOGICAL, "# Active routes: Discord=zapret, YouTube=zapret.\n")
        write_file(self.tmp, self.module.DISCORD_LIST_LOGICAL, "")
        (self.tmp / self.module.YOUTUBE_LIST_LOGICAL.lstrip("/")).unlink()
        write_file(
            self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json",
            json.dumps({"routing": {"rules": engine_rules({"youtube-direct"})}}),
        )
        checks, _writer = self.run_health(healthy_run({"xray": "1 2", "nfqws2": "3"}))
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Xray"]["status"], "error")
        self.assertEqual(by_name["Xray"]["detail"], "PID: [1, 2]")
        self.assertEqual(by_name["Discord hostlist"]["status"], "error")
        self.assertEqual(by_name["YouTube hostlist"]["status"], "error")
        self.assertEqual(by_name["Xray routing"]["status"], "error")
        self.assertEqual(by_name["Xray routing"]["detail"], "05_routing.json: missing: discord-direct")
        # YouTube nfqws hostlist flag is absent from the config, so zapret is inconsistent.
        self.assertEqual(by_name["YouTube route"]["status"], "error")
        self.assertEqual(by_name["Discord TCP route"]["status"], "error")
        # The Voice profile is missing from the config while its route is zapret.
        self.assertEqual(by_name["Discord Voice route"]["status"], "error")

    def test_xray_upgrade_check_reports_removed_settings(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(
            self.tmp,
            "/opt/etc/xray/configs/03_outbounds.json",
            json.dumps({"outbounds": [{"tag": "a", "protocol": "vless", "proxySettings": {"tag": "b"}}]}),
        )
        checks, _writer = self.run_health(healthy_run())
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Xray 26.10+ совместимость"]["status"], "error")
        self.assertIn("03_outbounds.json: proxySettings", by_name["Xray 26.10+ совместимость"]["detail"])

    def test_vless_routes_need_no_direct_tags(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(self.tmp, self.module.NFQWS_CONFIG_LOGICAL, "# Active routes: Discord=vless, YouTube=vless.\n")
        write_file(self.tmp, self.module.DISCORD_LIST_LOGICAL, "")
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", json.dumps({"routing": {}}))
        checks, _writer = self.run_health(healthy_run())
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Xray routing"]["status"], "ok")
        self.assertEqual(by_name["Xray routing"]["detail"], "05_routing.json: service-direct rules согласованы")
        self.assertEqual(by_name["YouTube route"]["status"], "ok")
        self.assertEqual(by_name["Discord TCP route"]["status"], "ok")
        self.assertEqual(by_name["Discord Voice route"]["status"], "ok")

    def test_recorded_telegram_zapret_needs_no_direct_tag(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(
            self.tmp,
            self.module.NFQWS_CONFIG_LOGICAL,
            "# Active routes: Discord=vless, YouTube=vless, Telegram=zapret.\n",
        )
        write_file(self.tmp, self.module.DISCORD_LIST_LOGICAL, "")
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", json.dumps({"routing": {}}))
        checks, _writer = self.run_health(healthy_run())
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Xray routing"]["status"], "ok")
        self.assertIn("Telegram=zapret", by_name["Управляемые маршруты"]["detail"])
        self.assertEqual(by_name["Telegram route"]["status"], "error")
        self.assertIn("режим удалён", by_name["Telegram route"]["detail"])

    def test_invalid_routing_json_is_reported(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(self.tmp, self.module.XRAY_CONFIG_DIR_LOGICAL + "/05_routing.json", "{not json")
        checks, _writer = self.run_health(healthy_run())
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Xray routing"]["status"], "error")
        # Without parsed tags, direct routes are inconsistent.
        self.assertEqual(by_name["YouTube route"]["status"], "error")

    def test_xray_test_failure_reports_tail_of_output(self):
        build_healthy_tree(self.tmp, self.module)
        base = healthy_run()
        calls = []

        def fake_run(command, timeout, extra_env=None):
            if Path(command[0]).name == "xray":
                calls.append((command, timeout, extra_env))
                return {"ok": False, "code": 23, "output": "x" * 600 + "END"}
            return base(command, timeout)

        checks, _writer = self.run_health(fake_run)
        detail = {check["name"]: check for check in checks}["Xray config test"]
        self.assertEqual(detail["status"], "error")
        self.assertEqual(len(detail["detail"]), 500)
        self.assertTrue(detail["detail"].endswith("END"))
        (command, timeout, extra_env), = calls
        self.assertEqual(Path(command[0]).name, "xray")
        self.assertEqual(command[1:4], ["run", "-test", "-confdir"])
        self.assertEqual(command[4], str(self.tmp / "opt" / "etc" / "xray" / "configs"))
        self.assertEqual(command[5:], ["-format", "json"])
        self.assertEqual(timeout, 60)
        self.assertEqual(extra_env, {"XRAY_LOCATION_ASSET": str(self.tmp / "opt" / "etc" / "xray" / "dat")})

    def test_xray_test_never_calls_xkeen_xtest(self):
        build_healthy_tree(self.tmp, self.module)
        base = healthy_run()
        commands = []

        def fake_run(command, timeout, extra_env=None):
            commands.append(command)
            return base(command, timeout)

        checks, _writer = self.run_health(fake_run)
        # xkeen -xtest exits 0 whatever the configuration is: it proves nothing.
        self.assertFalse([command for command in commands if "-xtest" in command])
        self.assertEqual(sum(Path(command[0]).name == "xray" for command in commands), 1)
        self.assertEqual({check["name"]: check for check in checks}["Xray config test"]["status"], "ok")

    def test_resource_thresholds(self):
        cases = (
            # (free MiB of 1000, MemAvailable kB, conntrack count of 1000, expected statuses)
            (100, 65536, 699, ("ok", "ok", "ok")),
            (99, 65535, 700, ("warn", "warn", "warn")),
            (50, 32768, 899, ("warn", "warn", "warn")),
            (49, 32767, 900, ("error", "error", "error")),
        )
        build_healthy_tree(self.tmp, self.module)
        for free, memory, count, expected in cases:
            with self.subTest(free=free, memory=memory, count=count):
                write_file(self.tmp, "/proc/meminfo", f"MemFree: 1 kB\nMemAvailable: {memory} kB\n")
                write_file(self.tmp, "/proc/sys/net/netfilter/nf_conntrack_count", f"{count}\n")
                disk = SimpleNamespace(total=1000, used=0, free=free)
                checks, _writer = self.run_health(healthy_run(), disk=disk)
                by_name = {check["name"]: check["status"] for check in checks}
                self.assertEqual(
                    (by_name["Свободное место /opt"], by_name["Доступная память"], by_name["Conntrack"]),
                    expected,
                )

    def test_meminfo_falls_back_to_memfree_and_zero_conntrack_max(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(self.tmp, "/proc/meminfo", "MemFree: 40000 kB\n")
        write_file(self.tmp, "/proc/sys/net/netfilter/nf_conntrack_max", "0\n")
        checks, _writer = self.run_health(healthy_run())
        by_name = {check["name"]: check for check in checks}
        self.assertEqual(by_name["Доступная память"]["status"], "warn")
        self.assertEqual(by_name["Conntrack"]["status"], "error")
        self.assertEqual(by_name["Conntrack"]["detail"], "100/0 (100.0%)")

    def test_non_numeric_conntrack_is_warning(self):
        build_healthy_tree(self.tmp, self.module)
        write_file(self.tmp, "/proc/sys/net/netfilter/nf_conntrack_count", "lots\n")
        checks, _writer = self.run_health(healthy_run())
        self.assertEqual({check["name"]: check["status"] for check in checks}["Conntrack"], "warn")


class MainTests(DiagnosticsUnitBase):
    JOB_ID = "0123456789abcdef"

    def setUp(self):
        super().setUp()
        from kdn.common import xkeen
        target = mock.patch.object(xkeen, "require", return_value="2.1")
        target.start()
        self.addCleanup(target.stop)
        self.state_path = self.tmp / "opt" / "tmp" / "xkeen-diagnostics" / "state.json"
        for patcher in (
            mock.patch.object(self.module, "STATE_PATH", self.state_path),
            mock.patch.object(self.module.signal, "signal"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def test_rejects_invalid_job_id_and_kind(self):
        with self.assertRaisesRegex(SystemExit, "invalid job id"):
            self.module.main(["--kind", "health", "--job-id", "XYZ"])
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            self.module.main(["--kind", "dpi", "--job-id", self.JOB_ID])
        self.assertFalse(self.state_path.exists())

    def test_health_completes_and_writes_summary(self):
        results = [{"name": "a", "status": "ok"}, {"name": "b", "status": "warn"}]
        with mock.patch.object(self.module, "run_health", return_value=results) as health:
            self.assertEqual(self.module.main(["--kind", "health", "--job-id", self.JOB_ID]), 0)
        health.assert_called_once()
        self.assertEqual(self.module.signal.signal.call_count, 2)
        state = self.state()
        self.assertEqual(state["status"], "completed")
        self.assertFalse(state["active"])
        self.assertEqual(state["progress"], 100)
        self.assertEqual(state["job_id"], self.JOB_ID)
        self.assertEqual(state["kind"], "health")
        self.assertEqual(state["results"], results)
        self.assertEqual(state["summary"]["ok"], 1)
        self.assertEqual(state["summary"]["warn"], 1)
        self.assertIn("finished_utc", state)
        self.assertEqual(state["source"]["flowseal_commit"], "176f56dc3f11ce5915c26abcdde903f93d835b64")

    def test_health_end_to_end_with_fixture_tree(self):
        build_healthy_tree(self.tmp, self.module)
        disk = SimpleNamespace(total=100, used=0, free=50)
        with mock.patch.object(self.module, "TEST_ROOT", str(self.tmp)), \
                mock.patch.object(self.module, "run", side_effect=healthy_run()), \
                mock.patch.object(self.module, "resolve_public", return_value=(True, "1.1.1.1")), \
                mock.patch.object(self.module, "doh_resolve", return_value=["1.1.1.1"]), \
                mock.patch.object(self.module.shutil, "disk_usage", return_value=disk):
            self.assertEqual(self.module.main(["--kind", "health", "--job-id", self.JOB_ID]), 0)
        state = self.state()
        self.assertEqual(state["status"], "completed")
        self.assertEqual(len(state["results"]), 28)
        self.assertEqual(state["summary"], {"ok": 28, "warn": 0, "error": 0, "unsupported": 0, "likely_blocked": 0})
        if os.name != "nt":
            self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)

    def test_cancellation_during_or_after_run(self):
        with mock.patch.object(self.module, "run_health", side_effect=InterruptedError("stop")):
            self.assertEqual(self.module.main(["--kind", "health", "--job-id", self.JOB_ID]), 130)
        self.assertEqual(self.state()["status"], "cancelled")
        self.assertFalse(self.state()["active"])

        def cancel(_writer):
            self.module.CANCELLED.set()
            return []

        with mock.patch.object(self.module, "run_health", side_effect=cancel):
            self.assertEqual(self.module.main(["--kind", "health", "--job-id", self.JOB_ID]), 130)
        self.assertEqual(self.state()["status"], "cancelled")

    def test_unexpected_error_is_recorded(self):
        with mock.patch.object(self.module, "run_health", side_effect=RuntimeError("e" * 2000)):
            self.assertEqual(self.module.main(["--kind", "health", "--job-id", self.JOB_ID]), 1)
        state = self.state()
        self.assertEqual(state["status"], "error")
        self.assertEqual(len(state["error"]), 1000)
        self.assertFalse(state["active"])


if __name__ == "__main__":
    unittest.main()

"""Tests of the configuration health check of the panel (kdn.web.domain.health)."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

from panel_fixtures import DIAGNOSTICS_MODULE, PanelUnitCase


def wait_for_cmdline(pid, timeout=5.0):
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


class ConfigHealthTests(PanelUnitCase):
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
        with self.patched(run_command=run or self.fake_run):
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

        with self.patched(ENGINE=engine):
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

        with self.patched(ENGINE=engine):
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

        with self.patched(QUIC_PROBE=probe):
            health = self.health(run)
            check = {item["name"]: item for item in health["checks"]}["YouTube QUIC с роутера"]
            self.assertTrue(check["ok"])
            self.assertEqual(check["status"], 'warn')
            self.assertTrue(health["all_ok"])
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
                    self.patched(telegram_ws_status=lambda status=status: status):
                self.assertEqual(self.telegram_checks("ws", rules, True)["ok"], expected)

    def test_telegram_ws_status_needs_the_relay_process_and_its_port(self):
        # D9: a pidfile alone (or a reused PID) does not prove that the relay works.
        pidfile = self.ns["TELEGRAM_WS_PIDFILE"]
        status = self.ns["telegram_ws_status"]
        running, detail = status()
        self.assertFalse(running)
        self.assertIn("нет pid-файла", detail)
        # Another live process: a child with a command line of its own, not the runner, whose arguments are not ours.
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "other_process.py"])
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        wait_for_cmdline(other.pid)
        pidfile.write_text(f"{other.pid}\n", encoding="ascii")
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
        wait_for_cmdline(relay.pid)
        pidfile.write_text(f"{relay.pid}\n", encoding="ascii")
        port = listener.getsockname()[1]
        with self.patched(TELEGRAM_WS_PORT=port):
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
        with self.patched(DIAGNOSTICS=self.root / "missing.py", DIAGNOSTICS_MODULES={}):
            health = self.health()
        self.assertFalse(health["all_ok"])
        self.assertEqual(health["checks"][-1]["name"], "Модуль проверок")


if __name__ == "__main__":
    unittest.main()

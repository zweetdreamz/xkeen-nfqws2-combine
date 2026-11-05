"""Health checks of the configuration: processes, Xray routing, nfqws2.conf and the Telegram WS relay."""

import sys

from kdn.common import proc
from kdn.web.infra import config as cfg
from kdn.web.infra import toolmods
from kdn.web.infra import engine


def config_health():
    engine.require_supported_target()
    routes = engine.current_routes_fast()
    checks = []

    def add(name, passed, detail, status=None):
        level = status or ("ok" if passed else "error")
        checks.append({"name": name, "ok": level != "error", "status": level, "detail": detail})

    def add_check(check):
        add(check["name"], check["status"] != "error", check["detail"], check["status"])

    def result():
        return {"ok": True, "routes": routes, "checks": checks, "all_ok": all(item["ok"] for item in checks)}

    xray_running = engine.process_running("xray")
    nfqws_running = engine.process_running("nfqws2")
    add("Xray", xray_running, "процесс запущен" if xray_running else "процесс не найден")
    add("nfqws2", nfqws_running, "процесс запущен" if nfqws_running else "процесс не найден")
    try:
        nfqws_text = cfg.NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        nfqws_text = ""
        add("nfqws2 config", False, str(exc))
    try:
        diagnostics = toolmods.diagnostics_module()
    except Exception as exc:  # a broken or missing module must not hide the other checks
        add("Модуль проверок", False, f"{cfg.DIAGNOSTICS}: {type(exc).__name__}: {exc}"[:500])
        return result()

    xray_files = diagnostics.read_xray_files(cfg.XRAY_CONFIG_DIR)
    active_routing = diagnostics.find_xray_routing_file(cfg.XRAY_CONFIG_DIR, xray_files)
    routing = {}
    rules = []
    if active_routing is None:
        add("Xray routing", False, f"нет файла с объектом routing в {cfg.XRAY_CONFIG_DIR}")
    else:
        routing_path, routing = active_routing
        rules = routing.get("rules", [])
        if not isinstance(rules, list):
            add("Xray routing", False, f"routing.rules не является списком: {routing_path}")
            rules = []

    try:
        discord_list = cfg.DISCORD_LIST.read_text(encoding="utf-8", errors="replace")
    except OSError:
        discord_list = ""
    # YouTube, Discord TCP and Voice: the predicates of the engine's --status.
    for check in diagnostics.route_consistency(nfqws_text, rules, discord_list, telegram=False):
        add_check(check)

    telegram = routes["telegram"]
    telegram_profile = "--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list" in nfqws_text
    telegram_rules = [
        rule for rule in rules
        if isinstance(rule, dict) and str(rule.get("ruleTag", "")).startswith("kdn-telegram")
    ]
    detail = f"route={telegram}, rules={len(telegram_rules)}, nfqws={'on' if telegram_profile else 'off'}"
    if telegram == "unmanaged":
        telegram_ok = not telegram_rules and not telegram_profile
    elif telegram == "zapret":
        # Recorded by an older apply or an old snapshot; the mode no longer exists.
        telegram_ok = False
        detail = "route=zapret (режим удалён, выберите другой)"
    elif telegram == "ws":
        # Four rules: domains, sniffed TLS/HTTP and UDP direct; MTProto to the relay.
        outbounds = sorted(str(rule.get("outboundTag")) for rule in telegram_rules)
        relay_running, relay_detail = telegram_ws_status()
        telegram_ok = (
            outbounds == ["telegram-direct"] * 3 + ["telegram-ws"]
            and telegram_profile
            and "--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list" not in nfqws_text
            and relay_running
        )
        add("Telegram WS relay", relay_running, relay_detail)
    else:
        expected_outbound = "telegram-direct" if telegram == "direct" else None
        telegram_ok = (
            telegram in {"direct", "vless"}
            and len(telegram_rules) == 2
            and all(
                (rule.get("outboundTag") == expected_outbound)
                if expected_outbound
                else rule.get("outboundTag") != "telegram-direct"
                for rule in telegram_rules
            )
            and not telegram_profile
        )
    add("Telegram route", telegram_ok, detail)
    add_check(diagnostics.outbound_checks(rules, routing, diagnostics.xray_outbounds(xray_files), cfg.TELEGRAM_WS_PORT))

    if nfqws_text:
        # nfqws2.conf invariants: the engine's --check-config (or a fallback) and YouTube QUIC.
        for check in diagnostics.config_invariant_checks(nfqws_text, proc.run_command, cfg.ENGINE):
            add_check(check)
        values = diagnostics.parse_shell_values(nfqws_text)
        firewall = proc.run_command(["iptables-save", "-c", "-t", "mangle"], timeout=15)
        if not firewall["ok"]:
            firewall = proc.run_command(["iptables-save", "-t", "mangle"], timeout=15)
        if firewall["ok"]:
            for check in diagnostics.nfqueue_live_checks(firewall.get("output", ""), values, counters=False):
                add_check(check)
        else:
            add("NFQUEUE", False, (firewall.get("output") or "iptables-save не выполнен")[-500:])
        if routes["youtube"] == "zapret":
            add_check(diagnostics.quic_live_check(proc.run_command, cfg.QUIC_PROBE, sys.executable))
    return result()


def telegram_ws_status():
    """(running, detail) of the Telegram WS relay: its own pidfile process and a TCP connect."""
    try:
        return toolmods.diagnostics_module().telegram_relay_status(cfg.TELEGRAM_WS_PIDFILE, cfg.TELEGRAM_WS_PORT)
    except Exception as exc:  # the module is optional for this single check
        return False, f"проверка недоступна: {type(exc).__name__}: {exc}"[:500]

"""The two legacy plan texts, without executing shell or touching router state."""

from kdn.engine import config


def render(resolved):
    udp = config.UDP_PORTS_WIDE if resolved.wide_udp else config.UDP_PORTS_FLOWSEAL
    if resolved.standalone:
        return f'''План standalone-установки Zapret:
0. Целевые режимы nfqws2: {resolved.routes_summary()}.
1. Не искать, не читать, не настраивать и не перезапускать XKeen/Xray/Mihomo.
2. Создать scoped snapshot только для nfqws2, его Entware-пакетов и hooks.
3. Установить отсутствующие зависимости и nfqws2-keenetic.
4. Настроить hostlist и отдельные TCP/QUIC/Discord Voice профили,
   Discord UDP={udp}, UDP strategy={resolved.udp_strategy},
   WAN={resolved.wan_interface_requested or 'auto'}.
5. Определить IPv4/IPv6 WAN по системным маршрутам, перезапустить и проверить
   только nfqws2. При ошибке автоматически восстановить scoped snapshot.

Применение:
  sh apply-discord-nfqws2.sh --apply --standalone-zapret --yes-router

Откат одной командой:
  sh apply-discord-nfqws2.sh --rollback-latest --yes-router
'''
    return f'''План изменений на роутере:
0. Целевые маршруты: {resolved.routes_summary()}.
1. До любых изменений создать полный снимок состояния.
2. Сохранить неизменяемый baseline при первом запуске и отдельный latest-preapply.
3. Учесть XKeen core={resolved.core_requested} и безопасно прочитать:
   - -status, -cp, -cpe, -tp;
   - name_client, proxy_dns, proxy_router, ipv6_support, DSCP и автозапуск
     из /opt/etc/init.d/S05xkeen;
   - фактические Hybrid/TProxy/Redirect, policy mark и donor-порты из
     /opt/etc/ndm/netfilter.d/proxy.sh.
4. Сохранить /opt/etc/xkeen, Xray/Mihomo, nfqws2, hooks, cron, opkg feed,
   состояние пакетов, служб и runtime IPv6.
5. Для Xray:
   - добавить нужные outbound discord-direct/youtube-direct;
   - согласовать их sockopt.mark с proxy_router/существующим Freedom
     (явно: {resolved.direct_mark_requested or 'auto'});
   - поставить управляемые Discord/YouTube rules первыми;
   - оставить YouTube IP-категории на исходном proxy outbound;
   - включить необходимый sniffing для redirect/tproxy;
   - закрыть world-writable права JSON до 0600;
   - проверить конфигурацию через xray -test.
   Для Mihomo:
   - поставить выбранные Discord/YouTube DIRECT rules первыми;
   - проверить конфигурацию через xkeen -mtest.
6. Если XKeen уже ограничен port_proxying.lst, добавить только нужные порты,
   не удаляя существующие. Конфликт с port_exclude.lst остановит preflight.
7. Установить отсутствующие зависимости и nfqws2-keenetic без обновления
   уже установленных пакетов.
8. Настроить независимые nfqws2 hostlist/profile для активных сервисов,
   Discord UDP={udp}, UDP strategy={resolved.udp_strategy},
   WAN={resolved.wan_interface_requested or 'auto'}. IPv6 включить для
   nfqws2 только при ipv6_support=on и реально доступном IPv6 WAN-маршруте.
9. Проверить конфиги и службы. При любой ошибке автоматически откатить apply.

Откат исходного состояния одной командой:
  sh apply-discord-nfqws2.sh --rollback --yes-router
'''


def run(ctx):
    if not ctx.paths.test_root:
        if ctx.resolved.standalone or ctx.resolved.core_requested not in ('auto', 'xray'):
            ctx.console.err('ERROR: new installations support only integrated XKeen2.1+/Xray.')
            return 1
        ctx.console.out('План native apply для XKeen2.1+ (2.x), только Xray:\n'
                        '1. Проверить версию, RCI, policy marks, WAN и будущий Xray confdir.\n'
                        '2. Под project lock сохранить baseline, full rescue и latest cue.\n'
                        '3. Подготовить порты/feed/пакеты и отдельные nfqws списки/профили.\n'
                        '4. Проверить pinned nfqws Lua в shadow root; записать файлы.\n'
                        '5. Restart on, проверка daemon PID Xray и nfqws argv/queue/firewall.\n'
                        '6. При ошибке/отмене — rollback; commit только после проверок.\n'
                        'Маршруты: ' + ctx.resolved.routes_summary() + '\n'
                        'Применение: sh apply-discord-nfqws2.sh --apply --yes-router\n'
                        'Откат: sh apply-discord-nfqws2.sh --rollback-latest --yes-router')
        return 0
    # Frozen legacy text is retained only for historical disposable-root vectors.
    ctx.console.out(render(ctx.resolved), end='')
    return 0

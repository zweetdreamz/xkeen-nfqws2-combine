# Telegram

Telegram — четвёртый сервис проекта. Вся настройка выполняется на роутере;
на телефонах и компьютерах ничего настраивать не нужно (ни прокси, ни
секретов). Исследование вариантов и причины выбора описаны в
[TELEGRAM-RESEARCH.md](TELEGRAM-RESEARCH.md).

## Режимы

| Режим | Xray | Mihomo | nfqws2 |
|---|---|---|---|
| `unmanaged` (по умолчанию, «Выкл» в панели) | правил проекта нет | правил проекта нет | профиля нет |
| `direct` | два правила в freedom outbound `telegram-direct` | `DOMAIN-SUFFIX`/`IP-CIDR … ,DIRECT` | профиля нет |
| `zapret` | как `direct` | как `direct` | TLS-профиль по hostlist и MTProto-профиль по ipset |
| `vpn` / `vless` | два правила в proxy outbound | обычные правила пользователя | профиля нет |

Telegram включается только явно. Пока маршрут `unmanaged`, проект Telegram
не трогает: его трафик идёт по правилам пользователя в XKeen. Существующие
установки после обновления остаются в `unmanaged`.

```sh
sh set-service-route.sh telegram direct    --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram zapret    --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram vpn       --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram unmanaged --core auto --wan-interface eth3 --yes-router
```

Низкоуровневый флаг: `--telegram-route direct|zapret|vless|unmanaged`. Без
флага apply сохраняет записанный маршрут, поэтому preset
`set-zapret-mode.sh` и переключение других сервисов Telegram не меняют.
`--status` печатает `telegram_route=`; в `nfqws2.conf` маршрут записан в
строке `# Active routes: …, Telegram=X.`.

## Что выбирается

- Домены: категория `ext:geosite_v2fly.dat:telegram` (21 домен: t.me,
  telegram.org, telesco.pe, cdn-telegram.org, telegra.ph…), копия —
  `config/telegram-user.list`.
- Сети дата-центров: `ext:geoip_v2fly.dat:telegram` (8 IPv4 и 4 IPv6),
  копия — `config/telegram-ip.list`. Категория `zkeenip.dat:telegram` не
  используется: в ней есть чужая сеть 194.221.0.0/16.
- Порты MTProto: TCP 80, 443, 5222. Если `port_proxying.lst` XKeen
  ограничен, проект добавляет в свой блок `5222`, пока Telegram управляется.

`tests/test_telegram_lists.py` сверяет списки в `config/` с `.dat` из
каталога `dat/`; после обновления `.dat` списки нужно обновить вместе с ним.

## Xray

Оба правила проекта помечены `"ruleTag": "kdn-telegram"` и ставятся сразу
после правил Discord и YouTube:

```json
{"type":"field","ruleTag":"kdn-telegram","inboundTag":["redirect","tproxy"],
 "outboundTag":"telegram-direct","domain":["ext:geosite_v2fly.dat:telegram"]}
{"type":"field","ruleTag":"kdn-telegram","inboundTag":["redirect","tproxy"],
 "outboundTag":"telegram-direct","ip":["ext:geoip_v2fly.dat:telegram"]}
```

Каждый apply удаляет только правила с этим `ruleTag` и строит их заново.
Собственные правила пользователя для Telegram (например,
`domain:web.telegram.org` в proxy) не меняются; так как правила проекта
стоят выше, при `direct`/`zapret`/`vpn` выигрывают они. Outbound
`04_telegram_nfqws2_outbound.json` (`telegram-direct`, freedom с меткой
direct) существует только в режимах `direct` и `zapret`.

## Mihomo

В `direct` и `zapret` проект добавляет `DOMAIN-SUFFIX,<домен>,DIRECT`,
`IP-CIDR,<сеть>,DIRECT,no-resolve` и `IP-CIDR6,…`. Правила удаляются по
точному совпадению текста, поэтому при переходе в `vpn` или `unmanaged`
пропадёт и пользовательское правило, совпадающее с ними символ в символ.

## nfqws2 (режим Zapret)

В `NFQWS_ARGS_CUSTOM` добавляются два профиля:

```text
--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/telegram.list
--out-range=-d10 --payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
--new
--filter-tcp=80,443,5222
--ipset=/opt/etc/nfqws2/lists/telegram-ip.list
--filter-l7=mtproto
--out-range=-d10 --payload=mtproto_initial
--lua-desync=fake:blob=tls_clienthello:repeats=6
--lua-desync=multisplit:pos=1
```

Первый профиль повторяет TLS-стратегию YouTube для сайта и CDN. Второй
обрабатывает только начало MTProto-соединения к сетям Telegram (zapret2
распознаёт obfuscated2-init с 0.1.2). `TCP_PORTS` при этом расширяется на
80 и 5222; фильтр `NFQWS_ARGS` Discord не меняется. Файлы
`telegram.list` и `telegram-ip.list` пишутся всегда, без профиля они ни на
что не влияют.

## Ограничения

- MTProto-стратегия Zapret — отправная точка, на реальной блокировке она не
  проверена. Если приложение не подключается, используйте `vpn`.
  Автоподбор Telegram не поддерживает: HTTP-проба не проверяет MTProto.
- Звонки Telegram идут по UDP на другие адреса. В `direct`/`zapret` они не
  обрабатываются и, скорее всего, не работают; в `vpn` работают, если VLESS
  передаёт UDP.
- IPv6-сети в nfqws2 не обрабатываются, пока IPv6 в nfqws2 выключен.
- `ruleTag` поддерживается Xray давно, но конфигурация проверена только на
  тестовом стенде, не на роутере.
- Прозрачный WS-proxy (вариант на основе tg-ws-proxy) не реализован; см.
  исследование.

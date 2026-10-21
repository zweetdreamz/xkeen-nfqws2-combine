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
| `vpn` / `vless` | два правила в proxy outbound | обычные правила пользователя | профиля нет |
| `ws` | четыре правила: MTProto в ретранслятор `telegram-ws`, остальное в `telegram-direct` | не поддерживается | только TLS-профиль по hostlist |

Telegram включается только явно. Пока маршрут `unmanaged`, проект Telegram
не трогает: его трафик идёт по правилам пользователя в XKeen. Существующие
установки после обновления остаются в `unmanaged`.

Режима `zapret` у Telegram нет. Он был, но на роутере с блокировкой Telegram
не заработал: провайдер не пропускал даже TCP-соединения к адресам
дата-центров, а nfqws2 меняет только содержимое уже установленного
соединения. `--telegram-route zapret` и `set-service-route.sh telegram zapret`
дают ошибку. Если в `nfqws2.conf` записан `Telegram=zapret` (установка
старой версии или откат к старому снимку), следующий apply переводит Telegram
в `direct` с предупреждением: правила Xray у этих режимов одинаковые. Тот же
apply удаляет оставшиеся от режима `kdn-telegram-ip.list` и
`imported-profiles/telegram.json`.

```sh
sh set-service-route.sh telegram direct    --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram vpn       --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram ws        --core xray --wan-interface eth3 --yes-router
sh set-service-route.sh telegram unmanaged --core auto --wan-interface eth3 --yes-router
```

Низкоуровневый флаг: `--telegram-route direct|vless|ws|unmanaged`. Без
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

`tests/test_telegram_lists.py` сверяет списки в `config/` с `.dat`. Файлы
`.dat` в Git не хранятся: тест ищет их в `$KD_DAT_DIR`, в локальном `dat/`
или в `/opt/etc/xray/dat` на роутере и без них пропускает сверку. После
обновления `.dat` списки нужно обновить вместе с ним.

## Xray

Правила проекта помечены `ruleTag` `kdn-telegram-domain` и `kdn-telegram-ip`
и ставятся сразу после правил Discord и YouTube. Теги разные: Xray не
запускается, если два правила имеют одинаковый `ruleTag`
(`duplicate ruleTag`).

```json
{"type":"field","ruleTag":"kdn-telegram-domain","inboundTag":["redirect","tproxy"],
 "outboundTag":"telegram-direct","domain":["ext:geosite_v2fly.dat:telegram"]}
{"type":"field","ruleTag":"kdn-telegram-ip","inboundTag":["redirect","tproxy"],
 "outboundTag":"telegram-direct","ip":["ext:geoip_v2fly.dat:telegram"]}
```

Каждый apply удаляет только правила, чей `ruleTag` начинается с
`kdn-telegram`, и строит их заново.
Собственные правила пользователя для Telegram (например,
`domain:web.telegram.org` в proxy) не меняются; так как правила проекта
стоят выше, при `direct`/`zapret`/`vpn` выигрывают они. Outbound
`04_telegram_nfqws2_outbound.json` (`telegram-direct`, freedom с меткой
direct) существует только в режимах `direct` и `zapret`.

## Режим WS

Режим `ws` повторяет идею [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy),
но прозрачно, на роутере: клиентам не нужен ни прокси, ни секрет. Приложение
Telegram подключается к дата-центру как обычно, а роутер передаёт это
MTProto-соединение внутри WebSocket на `kws{N}.web.telegram.org/apiws`, как
это делает Telegram Web. Для DPI такое соединение выглядит как обычный HTTPS
к web.telegram.org.

Как это устроено:

1. Xray разделяет трафик Telegram четырьмя правилами:

   | `ruleTag` | Что | Куда |
   |---|---|---|
   | `kdn-telegram-domain` | домены Telegram | `telegram-direct` |
   | `kdn-telegram-sniffed` | сети Telegram, распознанные как TLS/HTTP/QUIC | `telegram-direct` |
   | `kdn-telegram-ip` | остальной TCP к сетям Telegram (MTProto) | `telegram-ws` |
   | `kdn-telegram-udp` | UDP к сетям Telegram | `telegram-direct` |

   `telegram-ws` — freedom outbound с `redirect` на `127.0.0.1:18443`.
   Сайты и CDN идут напрямую через TLS-профиль nfqws2, как в `zapret`.
2. На `127.0.0.1:18443` работает `tools/router/telegram_ws_relay.py`
   (python3 из Entware, без дополнительных пакетов) как служба
   `/opt/etc/init.d/S99kdn-telegram-ws`; лог —
   `/opt/var/log/kdn-telegram-ws.log` (до 256 КиБ плюс одна старая копия).
3. Ретранслятор читает 64-байтный заголовок obfuscated2. Ключи этого
   заголовка лежат в нём самом, поэтому номер дата-центра (байты 60–61,
   отрицательный — медиа) читается без секрета. Затем поток без изменений
   передаётся в WebSocket: для медиа сначала `kws{N}-1`, для DC2 и DC4 —
   адрес 149.154.167.220, как в tg-ws-proxy.
4. Если WebSocket не открылся, соединение идёт к дата-центру напрямую по TCP
   (без обхода). Соединения без заголовка MTProto закрываются: их адрес
   назначения ретранслятору неизвестен.

Ограничения режима: только Xray (Mihomo и `--standalone-zapret` дают
ошибку); звонки по UDP не проходят через WebSocket; приложение, которое
подключается через свой MTProxy, ретранслятором не обрабатывается. Служба
создаётся при переходе в `ws`, удаляется при выходе из него и
восстанавливается или останавливается при откате.

## Mihomo

В `direct` проект добавляет `DOMAIN-SUFFIX,<домен>,DIRECT`,
`IP-CIDR,<сеть>,DIRECT,no-resolve` и `IP-CIDR6,…`. Пометить их, как в Xray,
нельзя, поэтому они удаляются по точному совпадению текста и только тогда,
когда Telegram управлялся до этого apply (`direct` или прежний `zapret`) или
управляется сейчас. Пока Telegram остаётся `unmanaged` или `vpn`,
пользовательские правила Mihomo для Telegram не трогаются; при выходе из
`direct` пропадёт и пользовательское правило, совпадающее с правилом проекта
символ в символ.

## nfqws2

Профиль Telegram в nfqws2 есть только в режиме `ws`: TLS-стратегия YouTube
для сайта и CDN по `kdn-telegram.list` (см. «Режим WS»). Fake-пакет —
собственный blob `telegram_tls` (файл пакета `tls_clienthello.bin`,
проверяется SHA-256). `kdn-telegram.list` пишется всегда, без профиля он ни
на что не влияет; префикс `kdn-` не даёт затереть собственный список
пользователя с именем `telegram.list`.

Автоподбора для Telegram нет: подбирать стратегию бесполезно, пока
провайдер блокирует адреса Telegram. `tools/router/telegram_mtproto.py`
остался как ручная проверка: `python3 tools/router/telegram_mtproto.py
--label raw --timeout 5` показывает, отвечает ли каждый дата-центр на
MTProto-рукопожатие с роутера.

## Ограничения

- Если провайдер блокирует адреса Telegram, `direct` не работает; используйте
  `ws` или `vpn`.
- Звонки Telegram идут по UDP на другие адреса. В `direct`/`ws` они не
  обрабатываются и, скорее всего, не работают; в `vpn` работают, если VLESS
  передаёт UDP.
- IPv6-сети в nfqws2 не обрабатываются, пока IPv6 в nfqws2 выключен.
- `ruleTag` поддерживается Xray давно, но конфигурация проверена только на
  тестовом стенде, не на роутере.
- Режим `ws` проверен на тестовом стенде с настоящим Xray и поддельными
  серверами WebSocket; с настоящими серверами Telegram из стенда он не
  проверялся. Если в `ws` приложение не подключается, смотрите лог
  ретранслятора: строки `via WebSocket` — WebSocket работает, строки
  `direct to` — WebSocket недоступен и соединение идёт напрямую.

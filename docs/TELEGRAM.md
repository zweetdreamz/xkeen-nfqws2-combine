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

## Mihomo

В `direct` и `zapret` проект добавляет `DOMAIN-SUFFIX,<домен>,DIRECT`,
`IP-CIDR,<сеть>,DIRECT,no-resolve` и `IP-CIDR6,…`. Пометить их, как в Xray,
нельзя, поэтому они удаляются по точному совпадению текста и только тогда,
когда Telegram управлялся до этого apply (`direct`/`zapret`) или управляется
сейчас. Пока Telegram остаётся `unmanaged` или `vpn`, пользовательские
правила Mihomo для Telegram не трогаются; при выходе из `direct`/`zapret`
пропадёт и пользовательское правило, совпадающее с правилом проекта символ
в символ.

## nfqws2 (режим Zapret)

В `NFQWS_ARGS_CUSTOM` добавляются два профиля:

```text
--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list
--out-range=-d10 --payload=tls_client_hello
--lua-desync=fake:blob=telegram_tls:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=telegram_tls:tcp_ts_up
--new
--filter-tcp=80,443,5222
--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list
--filter-l7=mtproto
--out-range=-d10 --payload=mtproto_initial
--lua-desync=fake:blob=telegram_tls:repeats=6
--lua-desync=multisplit:pos=1
```

Первый профиль повторяет TLS-стратегию YouTube для сайта и CDN. Второй
обрабатывает только начало MTProto-соединения к сетям Telegram (zapret2
распознаёт obfuscated2-init с 0.1.2). `TCP_PORTS` при этом расширяется на
80 и 5222; фильтр `NFQWS_ARGS` Discord не меняется. Fake-пакет —
собственный blob `telegram_tls` (файл пакета `tls_clienthello.bin`,
проверяется SHA-256), поэтому профиль не зависит от того, регистрирует ли
конфиг пакета `tls_clienthello`. Файлы
`kdn-telegram.list` и `kdn-telegram-ip.list` пишутся всегда, без профиля они ни на
что не влияют; префикс `kdn-` не даёт затереть собственные списки
пользователя с именем `telegram.list`.

## Автоподбор Zapret

Во вкладке **Автоподбор** есть сервис **Telegram** (Telegram должен быть в
режиме Zapret). Кандидат — TLS-стратегия, применённая к обоим профилям:
сайту по `kdn-telegram.list` и MTProto по `kdn-telegram-ip.list`, как
штатный конфиг пакета применяет стратегии к `http,tls,mtproto`. Источники:
профиль проекта по умолчанию, стратегии Discord TCP из BAT-файлов Flowseal и
их вариации `Safe`/`Extended`; выбранный BAT-файл работает как у других
сервисов. Все кандидаты проверены запуском nfqws2 v1.0.5.2 (ядро пакета
1.3.1).

Проверки с роутера, два прохода на кандидата:

- HTTPS к `telegram.org`, `web.telegram.org` и картинке CDN — нужно 2 из 3;
- MTProto-рукопожатие (`req_pq_multi` → `resPQ`) с пятью дата-центрами
  через obfuscated2, как у приложения, — нужно не меньше двух ответов
  (`tools/router/telegram_mtproto.py`, AES на чистом Python).

Перед кандидатами выполняется калибровка: рукопожатие при остановленном
nfqws2. Если дата-центры отвечают и без обхода, MTProto у провайдера не
блокируется; если не отвечают ни без обхода, ни с одним кандидатом, панель
советует проверить сеть роутера. Найденный профиль применяется кнопкой
**Применить найденный профиль** и хранится как
`imported-profiles/telegram.json`; движок принимает только две части (TLS по
`kdn-telegram.list`, MTProto по `kdn-telegram-ip.list`), `--ipset` разрешён
лишь в профиле Telegram.

## Ограничения

- MTProto-стратегия Zapret — отправная точка, на реальной блокировке она не
  проверена. Если приложение не подключается, используйте `vpn`.
  Автоподбор проверяет MTProto-рукопожатие, но не звонки и не загрузку медиа.
- Звонки Telegram идут по UDP на другие адреса. В `direct`/`zapret` они не
  обрабатываются и, скорее всего, не работают; в `vpn` работают, если VLESS
  передаёт UDP.
- IPv6-сети в nfqws2 не обрабатываются, пока IPv6 в nfqws2 выключен.
- `ruleTag` поддерживается Xray давно, но конфигурация проверена только на
  тестовом стенде, не на роутере.
- Прозрачный WS-proxy (вариант на основе tg-ws-proxy) не реализован; см.
  исследование.

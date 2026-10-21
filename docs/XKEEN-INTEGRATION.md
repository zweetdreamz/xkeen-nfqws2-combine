# Интеграция с XKeen

Этот документ описывает, что управляющий скрипт читает и меняет в
XKeen/Xray/Mihomo. Путь пакета отдельно разобран в
[`XKEEN-DIRECT-ZAPRET.md`](XKEEN-DIRECT-ZAPRET.md).

## Три режима сервиса

Режим выбирается отдельно для каждого сервиса: Discord TCP (домены
Discord, TCP/TLS и QUIC), Discord Voice (Voice/STUN UDP-порты), YouTube и
Telegram. Telegram дополнительно может быть `unmanaged`: тогда проект не
добавляет для него правил, или `ws`: MTProto уходит в outbound `telegram-ws`
(freedom с `redirect` на ретранслятор `127.0.0.1:18443`, служба
`S99kdn-telegram-ws`). Правила Telegram помечены
`ruleTag` `kdn-telegram-domain`, `kdn-telegram-ip`, а в `ws` ещё
`kdn-telegram-sniffed` и `kdn-telegram-udp` (уникальные: Xray не
принимает повторяющиеся теги), проект меняет только их; outbound —
`04_telegram_nfqws2_outbound.json` (`telegram-direct`), порт 5222 добавляется
в ограниченный `port_proxying.lst`. Подробно — [TELEGRAM.md](TELEGRAM.md).

### VLESS

XKeen отправляет сервис в существующий proxy outbound. Домашний
WAN видит соединение к proxy-серверу, поэтому локальный nfqws2 не может
обрабатывать исходный TLS/QUIC сервиса.

### DIRECT → nfqws2

```text
LAN → XKeen inbound → service-direct → WAN POSTROUTING → nfqws2
```

В этом режиме Xray/Mihomo создаёт прямое соединение, а nfqws2 модифицирует его
перед выходом к провайдеру.

### DIRECT без nfqws2

Core использует тот же `service-direct`, но hostlist/профиль выбранного
сервиса в nfqws2 отключён. Это отдельный режим `direct`; он полезен как
контрольная проверка или когда провайдер не требует desync.

## Что скрипт читает и сохраняет

Из `/opt/etc/init.d/S05xkeen`:

- `name_client`, policy/table;
- `proxy_dns`, `proxy_router`;
- DSCP;
- IPv4/IPv6 и `ipv6_support`;
- автозапуск, задержки и backup-флаги.

Из `/opt/etc/ndm/netfilter.d/proxy.sh`:

- фактический `mode_proxy`;
- `policy_mark`;
- donor/exclude-порты;
- DNS runtime;
- DSCP и поддержка iptables/ip6tables.

В snapshot также входят:

- `/opt/etc/xkeen`;
- конфиги Xray и Mihomo;
- init scripts, netfilter hooks и cron;
- nfqws2, opkg feed/indexes и состояния служб;
- runtime-состояние IPv6.

Параметры сохраняются для проверки и отката, но `proxy_dns`,
`proxy_router`, DSCP и IPv6 XKeen проект сам не переключает.

## Безопасные команды чтения

```sh
xkeen -v
xkeen -status
xkeen -cp
xkeen -cpe
xkeen -tp
xkeen -xtest
```

В установленном XKeen 2.0 не использовать как статус:

```text
xkeen -dns
xkeen -pr
xkeen -ipv6
xkeen -dscp
```

Это переключатели. Ключ `xkeen -pbr` в установленной версии отсутствует;
policy routing читается из runtime-hook, `ip rule` и Keenetic policy.

## Xray

Для активного zapret-режима скрипт:

1. создаёт отдельный Freedom outbound `discord-direct`, `youtube-direct`
   и/или `telegram-direct` (Telegram в `direct`/`ws`);
2. не переиспользует обычный пользовательский `direct`, в котором могут быть
   bind/interface/mark;
3. переносит подходящие доменные `.dat` selectors из proxy rules в первые
   управляемые rules;
4. удаляет перенесённые домены и небезопасные Discord IP selectors, сохраняя
   остаток смешанного правила;
5. включает необходимый sniffing для `redirect`/`tproxy`;
6. проверяет результат через `xkeen -xtest`;
7. закрывает Xray JSON до `0600`.

Discord TCP переносит только доменную категорию:

```text
ext:geosite_v2fly.dat:discord
```

Discord Voice — отдельное правило по UDP-портам:

```text
3478-3481,5349,19294-19344,50000-50100
```

С `--wide-udp` последний диапазон — `50000-65535`.

Маршруты независимы. Доменное правило ведёт в `discord-direct` при Discord
TCP = `direct`/`zapret` и в proxy outbound при `vless`. Правило UDP-портов
создаётся только при Voice = `direct`/`zapret`; при `vless` его нет, и голос
идёт по обычной proxy-маршрутизации XKeen, как в прежнем режиме Discord VPN.
Outbound `discord-direct` существует, если хотя бы один маршрут Discord не
`vless`.

`ext:zkeenip.dat:discord` удаляется из управляемой маршрутизации. В проверенной
базе эта категория содержит общие диапазоны Cloudflare и Google, поэтому
IP-маршрутизация Discord может перехватывать ChatGPT и другие посторонние
сервисы.

YouTube также переносит только доменные:

```text
ext:zkeen.dat:youtube
ext:geosite_v2fly.dat:youtube
```

YouTube/Google IP selectors остаются в исходном proxy-правиле.

Если `proxy_router=off` и существующий Freedom не имеет mark, direct выходит
через default WAN. `--direct-mark` предназначен только для явной
multi-WAN/PBR-схемы.

## Mihomo

Скрипт добавляет управляемые `DIRECT` rules в начало списка: домены Discord
при Discord TCP ≠ `vless`, UDP-порты Voice при Discord Voice ≠ `vless`, домены
YouTube при YouTube ≠ `vless`, домены и сети Telegram (`DOMAIN-SUFFIX`,
`IP-CIDR`, `IP-CIDR6`) при Telegram `direct`. Затем
запускает `xkeen -mtest`. YAML пересобирается через `yq`, поэтому формат и
комментарии могут нормализоваться; baseline хранит исходный файл.

## Порты XKeen

Если `port_proxying.lst` уже непустой, в помеченный блок добавляются нужные
порты без удаления пользовательских строк.

Если список пуст, он не ограничивает donor-порты и не меняется. Пересечение
активного `port_exclude.lst` с обязательными портами останавливает preflight:
ослаблять пользовательские исключения автоматически нельзя.

## IPv6

Переключатель XKeen сохраняется. `IPV6_ENABLED=1` для nfqws2 разрешается
только если:

1. `ipv6_support=on`;
2. route lookup нашёл usable IPv6 WAN;
3. маршрут не является `unreachable ... dev lo`.

На проверенном роутере второй пункт не выполняется, поэтому nfqws2 IPv6
выключен.

## Применение

Read-only:

```sh
sh apply-discord-nfqws2.sh --preflight --core auto --wan-interface eth3
sh scripts/diagnose-xkeen-router.sh
```

Выбор режима:

```sh
sh set-zapret-mode.sh both --core auto --wan-interface eth3 --yes-router
```

Точечно для одного сервиса:

```sh
sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-tcp zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-voice vpn --core auto --wan-interface eth3 --yes-router
```

`discord` вместо `discord-tcp`/`discord-voice` переключает оба маршрута
Discord. Режимы остальных сервисов сохраняются.

Откат:

```sh
sh rollback-last-change.sh
sh rollback-to-baseline.sh
```

# Режимы, флаги и handoff

Этот файл — краткий технический контекст для следующего оператора или агента.

## Цель и границы

```text
LAN → XKeen/Xray → VLESS
                 ↘ service-direct → [NFQUEUE/nfqws2] → WAN
```

Discord и YouTube переключаются независимо между `direct`, `zapret` и
`vless`. Скрипт не должен без отдельного
решения пользователя менять DNS, `proxy_router`, DSCP, IPv6 XKeen, общие
policy marks или hardware offload.

## Проверенное состояние на 15.08.2026

| Поле | Значение |
|---|---|
| Роутер | Keenetic Giga KN-1011, KeeneticOS 5.0.12 |
| XKeen/core | XKeen 2.0, Xray 26.7.28, Hybrid |
| WAN | `eth3` |
| nfqws2 | пакет 1.2.4, NFQUEUE 300 |
| Скрипт на роутере и в рабочей папке | 3.0.0 |
| Активный режим | `both` |
| Discord UDP | `flowseal`, узкий диапазон |
| IPv6 nfqws2 | `off`: usable IPv6 WAN route отсутствует |
| Runtime | Xray и nfqws2 запущены |
| Web-панель | `192.168.2.1:8088`, listener только на LAN |

Discord:

- Xray использует `discord-direct`;
- DIRECT выбирает `ext:geosite_v2fly.dat:discord`;
- `ext:zkeenip.dat:discord` не используется из-за пересечения с общими
  сетями Cloudflare и Google;
- Voice дополнительно выбирается по UDP-портам;
- живой тест видел `discord.media` на портах `19300`, `19305`, `19308`,
  прямой WAN и ответы клиенту.

YouTube:

- Xray использует `youtube-direct`;
- DIRECT выбирают только `ext:zkeen.dat:youtube` и
  `ext:geosite_v2fly.dat:youtube`;
- `ext:zkeenip.dat:youtube` и Google IP-категории остаются через VLESS;
- TCP/TLS и HTTP 200 подтверждены, QUIC требует отдельного клиентского теста.

Не фиксировать в документации имя `latest-preapply`: оно меняется после
каждого применения. Смотреть через `--show-snapshots`.

## Четыре режима

```sh
cd /opt/root/keenetic-discord-nfqws2

sh set-zapret-mode.sh discord --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh youtube --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh both    --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh vless   --core auto --wan-interface eth3 --yes-router
```

| Preset | Discord | YouTube |
|---|---|---|
| `discord` | zapret | VLESS |
| `youtube` | VLESS | zapret |
| `both` | zapret | zapret |
| `vless` | VLESS | VLESS |

Это быстрые preset для комбинаций Zapret/VPN. Точечно переключить один сервис
в любой из трёх режимов:

```sh
sh set-service-route.sh discord direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube vpn    --core auto --wan-interface eth3 --yes-router
```

| Режим | Core route | nfqws2 сервиса |
|---|---|---|
| `direct` | service-direct | выключен |
| `zapret` | service-direct | включён |
| `vpn` / `vless` | proxy outbound | выключен |

Wrapper сначала читает `--status` и сохраняет режим второго сервиса. Если
состояние определить нельзя, он завершится без изменений.

Низкоуровневый эквивалент:

```text
--discord-route direct|zapret|vless
--youtube-route direct|zapret|vless
--proxy-outbound TAG
```

`--proxy-outbound` обычно не нужен: Xray proxy tag определяется из исходных
правил.

## Режимы выполнения

| Флаг | Действие | Меняет роутер |
|---|---|---:|
| `--print-plan` | Печатает план | Нет |
| `--preflight` | Проверяет core, WAN, зависимости и конфликты | Нет |
| `--status` | Показывает проект и runtime | Нет |
| `--show-snapshots` | Показывает baseline/latest | Нет |
| `--snapshot-baseline --yes-router` | Создаёт первый baseline | Только snapshot |
| `--apply --yes-router` | Транзакционно применяет | Да |
| `--apply-import-profile FILE --yes-router` | Устанавливает профиль тюнера | Только nfqws2 |
| `--clear-imported-profile SERVICE --yes-router` | Возвращает встроенный профиль | Только nfqws2 |
| `--rollback-import --yes-router` | Откатывает последнюю операцию профиля | Только nfqws2 |
| `--rollback-snapshot PATH --yes-router` | Возвращает выбранный проверенный snapshot | Да |
| `--rollback-latest --yes-router` | Возвращает pre-apply | Да |
| `--rollback --yes-router` | Возвращает baseline | Да |

Короткий откат:

```sh
sh rollback-last-change.sh
sh rollback-to-baseline.sh
```

Перед каждым `apply` создаётся `latest-preapply`; ошибка вызывает
автоматический rollback. Перед ручным rollback создаётся rescue snapshot.

Три режима импорта используют отдельные снимки
`/opt/etc/keenetic-discord-nfqws2/nfqws-import-snapshots`. Они не вызывают
полный rollback и никогда не останавливают/перезапускают Xkeen. Меняется и
перезапускается только `nfqws2`.

`--rollback-snapshot` нужен истории web-панели. Путь обязан указывать на один
обычный каталог непосредственно внутри управляемого `snapshots`, пройти
проверку manifest/checksum и не быть symlink. Перед восстановлением также
создаётся rescue snapshot.

Применённые профили архивируются с UTC-датой в
`/opt/etc/nfqws2/profile-versions/<service>`. Повторное применение версии
использует тот же строгий импорт и focused snapshot только для `nfqws2`.

## Параметры применения

### Core

```text
--core auto|xray|mihomo
```

- `auto` читает активный `name_client`;
- Xray: отдельные Freedom outbounds, первые routing rules, `xkeen -xtest`;
- Mihomo: первые `DIRECT` rules, `xkeen -mtest`.

### Discord UDP

```text
--udp-strategy flowseal|legacy
--wide-udp
```

Штатно:

```text
flowseal
L7: stun,discord
payload: stun,discord_ip_discovery
fake blob: discord_udp
repeats: 6
UDP: 443,3478-3481,5349,19294-19344,50000-50100
```

Blob `config/blobs/ACTIVE_DISCORD_UDP.bin` закреплён SHA-256:

```text
2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf
```

`legacy` оставлен для A/B. `--wide-udp` заменяет `50000-50100` на
`50000-65535` сразу во всех слоях и без диагностики не рекомендуется.

### WAN и mark

```text
--wan-interface eth3
--direct-mark DECIMAL_NUMBER
```

Явный mark нужен только при специальной multi-WAN/PBR-схеме. Сейчас
`proxy_router=off`, поэтому direct использует default WAN без него.

## Действующие nfqws2-профили

### Discord TCP/QUIC

Базовые профили установленного nfqws2 ограничены
`/opt/etc/nfqws2/lists/user.list`:

- TCP/HTTP/TLS — адаптивная `circular`-стратегия;
- QUIC — `quic_initial`, `repeats=11`;
- IPSet выключен, режим hostlist — `MODE_LIST`.

### YouTube TCP/TLS

```text
--filter-tcp=443
--filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
```

### YouTube QUIC

```text
--filter-udp=443
--filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=11
```

Перед первым реальным профилем не должно быть пустого ведущего `--new`.
Иначе пустой профиль №1 совпадает с трафиком раньше hostlist-профилей.

## Переменные nfqws2

Файл: `/opt/etc/nfqws2/nfqws2.conf`.

| Переменная | Назначение |
|---|---|
| `NFQWS_BASE_ARGS` | Lua-библиотеки и blobs |
| `NFQWS_ARGS` | базовый TCP |
| `NFQWS_ARGS_QUIC` | базовый QUIC |
| `NFQWS_ARGS_UDP` | Discord Voice/STUN |
| `NFQWS_ARGS_CUSTOM` | изолированные сервисные профили |
| `NFQWS_EXTRA_ARGS` | hostlist mode |
| `NFQWS_ARGS_IPSET` | IP-наборы; сейчас пусто |
| `TCP_PORTS`, `UDP_PORTS` | Netfilter |
| `ISP_INTERFACE` | WAN |
| `IPV6_ENABLED` | IPv6 nfqws2 |
| `POLICY_NAME`, `POLICY_EXCLUDE` | привязка к Keenetic policy |
| `NFQUEUE_NUM` | очередь |

Проект использует `MODE_LIST`. `MODE_AUTO` и `MODE_ALL` расширяют охват и не
являются штатными.

## XKeen: что безопасно читать

```sh
xkeen -v
xkeen -status
xkeen -cp
xkeen -cpe
xkeen -tp
xkeen -xtest
```

Не использовать как read-only:

```text
xkeen -dns
xkeen -pr
xkeen -ipv6
xkeen -dscp
```

В установленной версии это переключатели. Проект читает их состояние из
`S05xkeen`, runtime-hook, `ip rule` и Keenetic policy.

## Безопасный следующий эксперимент

1. `--preflight` и `--show-snapshots`.
2. Изменить только TCP, QUIC, UDP strategy или диапазон — один параметр.
3. Проверить нужный клиент и NFQUEUE counters.
4. При ухудшении выполнить `sh rollback-last-change.sh`.
5. Постоянный результат внести в генератор и прогнать тесты.

Временный перебор доступен:

- во вкладке **Автоподбор** панели `http://192.168.2.1:8088`;
- из Windows через
  [`../tools/windows/README.md`](../tools/windows/README.md).

Оба варианта используют один allowlist-переводчик Flowseal → nfqws2, не
исполняют BAT и не записывают постоянный конфиг во время проверки. Панель
блокирует остальные изменения до завершения задания. Найденный профиль
применяется отдельным подтверждением с focused snapshot только для `nfqws2`.
Кнопка проверки Flowseal скачивает новый набор стратегий в
`/opt/etc/xkeen-web/flowseal-sources.json`, не запуская подбор. Скачанная копия
используется следующими запусками панели; при совпадении commit выводится
**Актуально**. Рабочий профиль сам не заменяется.

Глубина управляется `--mix-level`:

- `off` — встроенный вариант и прямой перевод BAT;
- `safe` — одно изменение `repeats`, `out-range`, TCP `pos/seq` или QUIC
  repeats на кандидата;
- `extended` — дополнительные документированные значения, несколько
  составных рецептов и ограниченное смешивание BAT-компонентов.

Порядок не фиксирован: без `--search-seed` каждый прогон получает новый
32-битный seed. Основной allowlist-пул перемешивается отдельно от отложенных
кандидатов с rank 200+, а лимит применяется после перемешивания. Поэтому
короткие прогоны могут охватывать разные подмножества. Seed сохраняется в
отчёте; одинаковые seed, Flowseal commit, `mix-level` и лимит воспроизводят
тот же путь.

Router-панель допускает максимум 64 кандидата. Повышать предел стоит только
после неудачи короткой проверки: длительность растёт почти линейно.

## Важные файлы

```text
apply-discord-nfqws2.sh       генератор, apply, snapshots и rollback
set-zapret-mode.sh            четыре режима
set-service-route.sh           direct/zapret/vpn для одного сервиса
apply-youtube-nfqws2.sh       launcher режима YouTube-only
rollback-last-change.sh       последний pre-apply
rollback-to-baseline.sh       исходный baseline
scripts/diagnose-*.sh         read-only диагностика
config/*.list                 локальные hostlist
config/blobs/                 закреплённые blobs
tools/windows/                временный подбор стратегий
```

## Остаточные ограничения

- Voice DIRECT частично опирается на порты и может захватить другой UDP.
- YouTube IP-категории намеренно не выводятся из VLESS.
- WinDivert/winws и NFQUEUE/nfqws2 имеют разные модели; перенос стратегий
  требует адаптации.
- Hardware offload проект не переключает.
- Baseline rollback заменяет управляемые каталоги; rescue snapshot сохраняет
  состояние перед откатом.

# Режимы, флаги и handoff

Этот файл — краткий технический контекст для следующего оператора или агента.

## Цель и границы

```text
LAN → XKeen/Xray → VLESS
                 ↘ service-direct → [NFQUEUE/nfqws2] → WAN
```

Discord TCP, Discord Voice, YouTube и Telegram переключаются независимо
между `direct`, `zapret` и `vless`; у Telegram вместо `zapret` есть `ws`
и ещё `unmanaged` (по умолчанию). Скрипт не должен без отдельного
решения пользователя менять DNS, `proxy_router`, DSCP, IPv6 XKeen, общие
policy marks или hardware offload.

## Проверенное состояние на 15.08.2026

| Поле | Значение |
|---|---|
| Роутер | Keenetic Giga KN-1011, KeeneticOS 5.0.12 |
| XKeen/core | XKeen 2.0, Xray 26.10.17, Hybrid |
| WAN | `eth3` |
| nfqws2 | пакет 1.2.4, NFQUEUE 300 (20.10.2026 обновлён до 1.3.1) |
| Скрипт на роутере и в рабочей папке | 3.1.0 |
| Активный режим | Discord TCP/Voice и YouTube `zapret`, Telegram `ws` |
| Discord UDP | `flowseal`, узкий диапазон |
| IPv6 nfqws2 | `off`: usable IPv6 WAN route отсутствует |
| Runtime | Xray и nfqws2 запущены |
| Web-панель | `192.168.2.1:8088`, listener только на LAN |

Discord:

- Xray использует `discord-direct`;
- Discord TCP (TCP/TLS и QUIC) выбирает `ext:geosite_v2fly.dat:discord`;
- `ext:zkeenip.dat:discord` не используется из-за пересечения с общими
  сетями Cloudflare и Google;
- Discord Voice — отдельный маршрут по UDP-портам
  `3478-3481,5349,19294-19344,50000-50100`;
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

В preset «Discord» означает сразу Discord TCP и Discord Voice.

| Preset | Discord | YouTube |
|---|---|---|
| `discord` | zapret | VLESS |
| `youtube` | VLESS | zapret |
| `both` | zapret | zapret |
| `vless` | VLESS | VLESS |

Это быстрые preset для комбинаций Zapret/VPN. Точечно переключить один сервис
в любой из трёх режимов:

```sh
sh set-service-route.sh discord-tcp direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-tcp zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-tcp vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh discord-voice direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-voice zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-voice vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube vpn    --core auto --wan-interface eth3 --yes-router
```

`SERVICE` — `discord-tcp`, `discord-voice`, `discord` (оба маршрута Discord),
`youtube` или `telegram`. Только для `telegram` есть ещё режим `unmanaged`:
правила проекта убираются, Telegram идёт по правилам пользователя
(см. [TELEGRAM.md](TELEGRAM.md)).

| Сервис | Core route | nfqws2 |
|---|---|---|
| Discord TCP | доменное правило `ext:geosite_v2fly.dat:discord` | hostlist `user.list`, `NFQWS_ARGS`, `TCP_PORTS` |
| Discord Voice | правило UDP-портов Voice/STUN | `NFQWS_ARGS_UDP`, `UDP_PORTS`, blob `discord_udp` |
| YouTube | доменные правила YouTube | `youtube.list` в `NFQWS_ARGS_CUSTOM` |
| Telegram | правила с `ruleTag` `kdn-telegram-*` (домены и IP v2fly) | в `ws`: `kdn-telegram.list` в `NFQWS_ARGS_CUSTOM` |

| Режим | Core route | nfqws2 сервиса |
|---|---|---|
| `direct` | service-direct | выключен |
| `zapret` | service-direct | включён |
| `vpn` / `vless` | proxy outbound | выключен |

При Voice = `vpn` правило UDP-портов Discord не создаётся: голос идёт по
обычной proxy-маршрутизации XKeen, как в прежнем Discord VPN. Outbound
`discord-direct` существует, если хотя бы один маршрут Discord не `vpn`.

Wrapper сначала читает `--status` и сохраняет режимы остальных сервисов. Если
состояние определить нельзя, он завершится без изменений. Оба wrapper
(`set-service-route.sh` и `set-zapret-mode.sh`) также передают в apply
записанные `udp_range` и `udp_strategy` (`--wide-udp`/`--narrow-udp`,
`--udp-strategy`) перед опциями вызова, поэтому явные опции побеждают.

Низкоуровневый эквивалент:

```text
--discord-tcp-route direct|zapret|vless
--discord-voice-route direct|zapret|vless
--discord-route direct|zapret|vless      сокращение: оба маршрута Discord
--youtube-route direct|zapret|vless
--telegram-route direct|vless|ws|unmanaged без флага: записанный маршрут
--proxy-outbound TAG
```

`--status` печатает `discord_tcp_route=`, `discord_voice_route=`,
`youtube_route=` и `telegram_route=`. Поле `discord_route=` оставлено для старых читателей: оно
равно общему значению или `mixed`, если маршруты TCP и Voice различаются.
`udp_strategy=flowseal|legacy` и `udp_range=narrow|wide` показывают
записанные настройки Discord UDP (`unknown`, если `nfqws2.conf` нет).

Применённые маршруты записываются в `nfqws2.conf`:

```text
# Active routes: DiscordTCP=X, DiscordVoice=Y, YouTube=Z, Telegram=T.
# Discord UDP: strategy=flowseal|legacy, range=narrow|wide.
```

Прежняя строка `Discord=X, YouTube=Y.` по-прежнему читается: X относится к
обоим маршрутам Discord. Поэтому после обновления скриптов повторный apply не
нужен.

`--proxy-outbound` обычно не нужен: Xray proxy tag определяется из исходных
правил.

## Режимы выполнения

| Флаг | Действие | Меняет роутер |
|---|---|---:|
| `--print-plan` | Печатает план | Нет |
| `--preflight` | Проверяет core, WAN, зависимости и конфликты | Нет |
| `--status` | Показывает проект и runtime | Нет |
| `--show-snapshots` | Показывает baseline, XKeen baseline (если есть) и latest | Нет |
| `--snapshot-baseline --yes-router` | Создаёт первый baseline | Только snapshot |
| `--apply --yes-router` | Транзакционно применяет | Да |
| `--apply-import-profile FILE --yes-router` | Устанавливает профиль тюнера | Только nfqws2 |
| `--clear-imported-profile SERVICE --yes-router` | Возвращает встроенный профиль | Только nfqws2 |
| `--rollback-import --yes-router` | Откатывает последнюю операцию профиля | Только nfqws2 |
| `--rollback-snapshot PATH --yes-router` | Возвращает выбранный проверенный snapshot | Да |
| `--rollback-latest --yes-router` | Возвращает pre-apply | Да |
| `--rollback --yes-router` | Возвращает XKeen baseline (если есть), затем baseline | Да |

Короткий откат:

```sh
sh rollback-last-change.sh
sh rollback-to-baseline.sh
```

Перед каждым `apply` создаётся `latest-preapply`; ошибка вызывает
автоматический rollback. Перед ручным rollback создаётся rescue snapshot.

Baseline после standalone-установки: если первый baseline создан с
`--standalone-zapret`, он содержит только пути nfqws2. Первый
интегрированный apply над ним сохраняет свой pre-apply snapshot как XKeen
baseline в `/opt/etc/keenetic-discord-nfqws2/baseline-xkeen.ptr` и печатает
`XKeen baseline recorded`. `--rollback` тогда создаёт один rescue snapshot,
восстанавливает XKeen baseline, затем nfqws2-baseline. С
`--standalone-zapret` такой откат отклоняется.

Восстановление пакетов: если отслеживаемый пакет после snapshot обновлён
через `opkg upgrade`, откат печатает `WARNING ... opkg cannot downgrade it` и
продолжается — понизить версию opkg не может. Ошибкой остаются только
неудачные `opkg install`/`opkg remove`.

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
--wide-udp      Voice-порты 50000-65535
--narrow-udp    обратно 50000-50100 (по умолчанию)
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

Выбор записывается в управляемый блок `nfqws2.conf` строкой
`# Discord UDP:` и сохраняется wrapper-скриптами.
Прямой вызов `apply-discord-nfqws2.sh --apply` без этих флагов берёт
значения по умолчанию (`flowseal`, узкий диапазон). Для конфига без этой
строки настройки выводятся из `UDP_PORTS` и blob `discord_udp`.

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

Подбор требует маршрута `Zapret` у подбираемого сервиса (`discord-tcp`,
`discord-voice` или `youtube`).

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

Один BAT-файл можно выбрать полем **BAT-файл Flowseal** панели (список из
скачанного набора, `GET /api/tuner/sources`), `--source-file` Windows-тюнера
или `--source-file` в `zapret_autotune_job.py`. Имя сравнивается без учёта
регистра. Тогда проверяются только переведённые профили этого файла: без
встроенного профиля и смешивания. `safe`/`extended` добавляют только
вариации параметров файла для TCP-сервисов; для Voice остаётся прямой
перевод. Отчёт записывает `source_file`.

Проверка Discord Voice по трафику клиента (`--voice-traffic` у
`zapret_autotune_job.py`, режим **По трафику Discord** в панели) оценивает
кандидатов по `EVENT|VOICE_TRAFFIC` диагностики: пользователь один раз
заходит в голосовой канал, Discord сам переподключается.

Проверка пакетом с роутера (`--voice-auto`, режим **Пакетом с роутера**)
требует сохранённого голосового сервера
`/opt/etc/xkeen-web/discord-voice-endpoint.json`. Его записывает задание после
ручной Voice-проверки с ответом **Да** (из `EVENT|VOICE_ENDPOINT`
`diagnose-discord-voice.sh`). Runner калибрует пробу
(`tools/router/discord_voice_probe.py`) с активным профилем и при
остановленном nfqws2: ответ без обхода переводит все кандидаты на ручную
проверку. Иначе кандидат без ответа отбрасывается, с ответом — ждёт
подтверждения звука; если ответа пользователя нет за
`TUNER_VERDICT_TIMEOUT` (300 с), профиль остаётся найденным, но
неподтверждённым. Windows-тюнер проверяет Voice только
вручную. Подробности —
[`../tools/router/README.md`](../tools/router/README.md#проверка-discord-voice-пакетом-с-роутера).

Router-панель допускает максимум 64 кандидата. Повышать предел стоит только
после неудачи короткой проверки: длительность растёт почти линейно.

## Важные файлы

```text
apply-discord-nfqws2.sh       генератор, apply, snapshots и rollback
set-zapret-mode.sh            четыре режима
set-service-route.sh          direct/zapret/vpn для одного сервиса
apply-youtube-nfqws2.sh       launcher режима YouTube-only
rollback-last-change.sh       последний pre-apply
rollback-to-baseline.sh       исходный baseline
scripts/diagnose-*.sh         read-only диагностика
config/*.list                 локальные hostlist
config/blobs/                 закреплённые blobs
tools/windows/                временный подбор стратегий
tools/router/discord_voice_probe.py  проба Discord IP Discovery для Voice
```

## Остаточные ограничения

- Маршрут Discord Voice по-прежнему выбирается по UDP-портам и может
  захватить другой UDP.
- Автоматическая проверка Voice на роутере в поле не проверена: неизвестно,
  отвечают ли реальные голосовые серверы Discord на IP Discovery вне сессии.
- YouTube IP-категории намеренно не выводятся из VLESS.
- WinDivert/winws и NFQUEUE/nfqws2 имеют разные модели; перенос стратегий
  требует адаптации.
- Hardware offload проект не переключает.
- Baseline rollback заменяет управляемые каталоги; rescue snapshot сохраняет
  состояние перед откатом.

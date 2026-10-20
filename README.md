# XKeen + nfqws2 для Discord и YouTube

Проект позволяет независимо выбирать маршрут для четырёх сервисов:

- **Discord TCP** — домены Discord: TCP/TLS и QUIC;
- **Discord Voice** — Voice/STUN UDP-порты Discord;
- **YouTube**;
- **Telegram** — по умолчанию не управляется, включается явно
  ([docs/TELEGRAM.md](docs/TELEGRAM.md)).

Для каждого доступны три режима:

- `Direct`: обычный WAN без nfqws2;
- `Zapret`: обычный WAN с обработкой nfqws2;
- `VPN`: исходный VLESS-маршрут Xray.

```text
клиент → XKeen → Xray/Mihomo
                  ├─ VLESS
                  └─ service-direct → [nfqws2] → WAN
```

Настройки DNS, `proxy_router`, DSCP, IPv6 и policy marks XKeen скрипт читает,
но самовольно не переключает.

## Текущее состояние

Основная конфигурация проверена 15.08.2026; пакет nfqws2 обновлён 20.10.2026:

| Компонент | Состояние |
|---|---|
| Роутер | Keenetic Giga KN-1011, KeeneticOS 5.0.12 |
| XKeen | 2.0, Xray 26.7.28, режим Hybrid |
| nfqws2 | `nfqws2-keenetic 1.3.1`, ядро `v1.0.5.2`, очередь 300, WAN `eth3` |
| Управляющий скрипт | `3.0.0` |
| Активный режим | `both`: Discord TCP/Voice и YouTube через DIRECT + nfqws2 |
| Web-панель | `http://192.168.2.1:8088`, только LAN |
| IPv6 nfqws2 | выключен: рабочего IPv6 WAN-маршрута нет |
| Откат | baseline и последний pre-apply присутствуют |

Путь Discord Desktop Voice до WAN и обратно подтверждён пакетами и счётчиками
NFQUEUE. Для YouTube подтверждены TCP/TLS и загрузка сайта; QUIC/HTTP3 нужно
проверять реальным клиентом.

## Быстрое управление

Команды выполняются на роутере в Entware shell:

```sh
cd /opt/root/keenetic-discord-nfqws2
```

Сначала посмотреть состояние — это ничего не меняет:

```sh
sh apply-discord-nfqws2.sh --status
sh apply-discord-nfqws2.sh --show-snapshots
```

В `--status` маршруты видны по отдельности: `discord_tcp_route=`,
`discord_voice_route=`, `youtube_route=` и `telegram_route=`. Прежний `discord_route=` сохранён:
он равен общему значению или `mixed`, если TCP и Voice различаются.
Настройки Discord UDP видны как `udp_strategy=flowseal|legacy` и
`udp_range=narrow|wide`.

Выбрать один из четырёх preset (Discord в них — сразу TCP и Voice):

```sh
# Discord → zapret, YouTube → VLESS
sh set-zapret-mode.sh discord --core auto --wan-interface eth3 --yes-router

# Discord → VLESS, YouTube → zapret
sh set-zapret-mode.sh youtube --core auto --wan-interface eth3 --yes-router

# оба сервиса → zapret
sh set-zapret-mode.sh both --core auto --wan-interface eth3 --yes-router

# оба сервиса → VLESS
sh set-zapret-mode.sh vless --core auto --wan-interface eth3 --yes-router
```

Эти четыре preset покрывают комбинации `Zapret/VPN`. Для одного сервиса
доступны все три режима; остальные сервисы сохраняют текущее состояние:

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

Telegram — четвёртый сервис, по умолчанию не управляется (`unmanaged`).
Включается так же, без настройки клиентов; подробности и ограничения — в
[docs/TELEGRAM.md](docs/TELEGRAM.md):

```sh
sh set-service-route.sh telegram zapret    --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram unmanaged --core auto --wan-interface eth3 --yes-router
```

`discord` вместо `discord-tcp`/`discord-voice` переключает оба маршрута
Discord сразу:

```sh
sh set-service-route.sh discord zapret --core auto --wan-interface eth3 --yes-router
```

Оба wrapper сохраняют текущие настройки Discord UDP (`--wide-udp`,
`--udp-strategy`), в том числе при переключении только YouTube. Явно
переданные `--wide-udp`, `--narrow-udp` или `--udp-strategy` имеют приоритет:

```sh
sh set-service-route.sh discord-voice zapret --narrow-udp --core auto --wan-interface eth3 --yes-router
```

После обновления скриптов повторный apply не нужен: старая запись
`Discord=X` в `nfqws2.conf` читается как одинаковый X для TCP и Voice.

Каждое применение:

1. создаёт снимок состояния;
2. проверяет Xray/Mihomo и зависимости;
3. применяет изменения транзакционно;
4. автоматически откатывается при ошибке.

## Откат одной командой

Вернуть состояние перед последним применением:

```sh
sh rollback-last-change.sh
```

Вернуть исходное состояние до установки функции:

```sh
sh rollback-to-baseline.sh
```

Перед ручным откатом создаётся rescue snapshot. Не копируйте в инструкции
конкретные имена снимков: актуальные указатели показывает
`--show-snapshots`.

Если первая установка была `--standalone-zapret`, baseline содержит только
пути nfqws2. Тогда первый интегрированный apply дополнительно записывает
**XKeen baseline** (`XKeen baseline:` в `--show-snapshots`), а
`rollback-to-baseline.sh` восстанавливает сначала его, затем nfqws2-baseline.

Откат работает и после `opkg upgrade` отслеживаемых пакетов
(`ca-certificates`, `jq`, `wget-ssl`, `wget-nossl`, `nfqws2-keenetic`): opkg
не умеет ставить старую версию, поэтому расхождение версий выводится как
`WARNING`, а пакет остаётся новым. Если обновлён `nfqws2-keenetic`, из снимка
возвращаются только `nfqws2.conf`, `lists`, `blobs`, `imported-profiles` и
`profile-versions`; Lua-скрипты, `S51nfqws2` и `100-nfqws2.sh` остаются от
установленного пакета: Lua должен совпадать с бинарником
(`NFQWS2_COMPAT_VER`), иначе nfqws2 не запустится. Откат импорта профилей
всегда возвращает только эти данные.

Обновление nfqws2 от 20.10.2026 имеет отдельный rollback-пакет 1.2.4 и копию
профилей в `/opt/etc/nfqws2-update-backups`. Путь последней копии записан в
`latest.path` этого каталога; внутри неё есть `rollback.sh`. Этот откат касается
версии nfqws2, а не версии web-панели.

## Состав Git-репозитория

В Git сохраняются исходники, документация и справочные конфиги. Локальные
`.dat`, резервные копии роутера, отчёты и временные файлы исключены через
`.gitignore`; они остаются на компьютере. Зависимость Python — стандартная
библиотека. Все проверки запускает `sh tests/run-all.sh` (см. «Разработка и тесты»);
тест списков Telegram против `.dat` выполняется, только если локальный
каталог `dat/` есть.

## После перезагрузки

Повторно применять режим не нужно. XKeen и nfqws2 запускаются с Entware, а
firewall-hook восстанавливает NFQUEUE rules.

Через одну-две минуты проверьте:

```sh
xkeen -status
/opt/etc/init.d/S51nfqws2 status
iptables-save -t mangle | grep NFQUEUE
```

Если `/opt` не смонтирован, сначала восстановите Entware/USB. Если `/opt`
доступен, но службы не запустились:

```sh
/opt/etc/init.d/S05xkeen restart on
(cd / && /opt/etc/init.d/S51nfqws2 restart)
```

## Подбор новых стратегий

Есть два интерфейса к одному безопасному переводчику стратегий.

В [`tools/windows`](tools/windows) доступны три BAT-запуска:

```text
tune-youtube.bat
tune-discord-tcp.bat
tune-discord-voice.bat
```

Тюнер скачивает текущие `general*.bat` Flowseal и разбирает их как данные —
BAT-файлы не исполняются. Кандидаты запускаются на роутере только временно,
без записи Xray/XKeen/nfqws2-конфигов; исходная служба восстанавливается
через `EXIT` trap.

Кроме прямого перевода BAT тюнер умеет ограниченно менять `repeats`,
`out-range`, TCP `pos`, `tcp_seq`/`seqovl` и повторы QUIC. `Safe` меняет одну
ось за раз, `Extended` добавляет несколько заранее заданных сочетаний и
смешивание компонентов разных BAT. Полного перебора всех значений нет.

При каждом запуске без заданного seed порядок основного allowlist-пула
случайно меняется; при небольшом лимите меняется и подмножество. Кандидаты с
rank 200+ остаются во второй очереди. Seed сохраняется в отчёте, поэтому
вместе с Flowseal commit удачный путь можно воспроизвести.

Тюнер выводит источник, Git commit/blob SHA и точные аргументы nfqws2. BAT-
запуски автоматически сохраняют последний успешный отчёт в
`tools\windows\reports`.

Та же функция встроена во вкладку **Автоподбор** панели на порту `8088`.
Панель запускает фоновое задание прямо на роутере, показывает кандидаты и
позволяет остановить перебор. YouTube и Discord TCP проверяются HTTP-пробами;
для Discord Voice нужно переподключиться к голосовому каналу и ответить
**Да/Нет**.

Режим **Проверка Voice → По трафику Discord** (по умолчанию) избавляет от
переподключений: зайдите в голосовой канал один раз, роутер оценивает каждого
кандидата по трафику самого Discord и просит подтвердить звук только у
найденного профиля
([подробности](tools/router/README.md#проверка-discord-voice-по-трафику)).

Режим **Пакетом с роутера** доступен, когда сохранён голосовой сервер: один раз
пройдите ручную проверку с ответом **Да**. Затем роутер сам отправляет этому
серверу Discord IP Discovery и отсеивает кандидатов без ответа, а звук нужно
подтвердить только для найденного профиля. Работа этой проверки на реальных
голосовых серверах Discord ещё не подтверждена; подробности —
[`tools/router/README.md`](tools/router/README.md#проверка-discord-voice-пакетом-с-роутера).

Найденный профиль только показывается. Его постоянное применение — отдельная
кнопка с focused snapshot и перезапуском только `nfqws2`.

Ручной автоподбор записывает baseline штатного профиля и требует двух
успешных TCP-проходов с проверкой API/CDN-содержимого. Диагностические метрики
сохраняются в отчёте; для Voice по-прежнему требуется подтверждение звука.

Кнопка **Проверить обновление** скачивает новые стратегии Flowseal для
следующего подбора. Если скачанная версия последняя, показывает **Актуально**.
Запуск подбора и применение найденного профиля остаются отдельными действиями.

Чтобы быстро проверить готовый конфиг Flowseal, выберите в поле
**BAT-файл Flowseal** один файл. Тогда проверяются только его переведённые
профили — без встроенного профиля роутера и смешивания. `Safe`/`Extended`
добавляют лишь вариации параметров этого файла для YouTube и Discord TCP. В
Windows-тюнере то же делает `--source-file "general (ALT3).bat"`.

Подбор требует маршрута `Zapret` именно у подбираемого сервиса: Discord TCP,
Discord Voice или YouTube.

## Локальная web-панель

[`tools/router/xkeen_control_script.sh`](tools/router/xkeen_control_script.sh)
создаёт single-page панель управления XKeen и маршрутами
`Direct / Zapret / VPN` для четырёх сервисов: Discord TCP, Discord Voice,
YouTube и Telegram (у него есть ещё `Выкл`) — у каждого своя карточка. Вкладка **Автоподбор** перебирает
актуальные Flowseal-профили на роутере, а **Импорт профиля** принимает отчёт
Windows-тюнера. Смена маршрута выполняется фоновым заданием: краткий разрыв
LAN-соединения при перезапуске Xray не теряет результат, а после повторного
открытия панель продолжает показывать состояние операции.
Импорт, удаление и откат профиля перезапускают только `nfqws2`; Xkeen при
этих операциях не останавливается и не перезапускается. Пока идёт
переключение, вкладки остаются доступными. Фоновые задания (маршрут, подбор,
проверка роутера) запускаются по одному: второй запуск во время старта
первого отклоняется с HTTP 409.

Для полного apply панель показывает этапы, сохраняет постоянную историю по
дате и позволяет откатиться к snapshot до выбранной операции. История и
проверка после apply показывают все маршруты, включая Telegram. После успеха
она проверяет процессы/конфиги; браузерные HTTP/TLS-пробы запускаются отдельно
во вкладке «Диагностика». QUIC и
Discord Voice остаются ручными проверками. Импортированные профили также
архивируются по UTC-дате и могут быть повторно применены из вкладки импорта.

Установщик панели только записывает `/opt/xkeen-web/app.py`: он не применяет
настройки и не меняет автозапуск.

На проверенном роутере панель уже работает через существующий
`S99xkeen-web`.

Подробности: [`tools/router/README.md`](tools/router/README.md).

Вкладка **Диагностика** добавляет адаптированные Flowseal Run Diagnostics,
Standard tests (HTTPS) и DPI 16–20 КБ из браузера по текущим маршрутам
LAN-устройства. Проверка состояния служб остаётся на роутере. Для Windows можно
скачать helper восстановления кэша Discord с сохранением резервных папок.

## Что именно настраивается

- отдельные правила Xray/Mihomo для Discord TCP, Discord Voice, YouTube и
  Telegram (правила Telegram помечены `ruleTag` `kdn-telegram-domain` и
  `kdn-telegram-ip`);
- разные hostlist и nfqws2-профили сервисов;
- TCP/TLS, QUIC и Discord Voice/STUN;
- узкий UDP-диапазон по умолчанию, явный `--wide-udp` и возврат
  `--narrow-udp`; выбор запоминается в `nfqws2.conf`;
- WAN, core и при необходимости direct mark;
- снимки, автооткат и восстановление служб.

YouTube DIRECT выбирается только по доменным категориям
`ext:zkeen.dat:youtube` и `ext:geosite_v2fly.dat:youtube`.
`ext:zkeenip.dat:youtube` и Google IP-категории остаются через VLESS: это
уменьшает риск отправить напрямую посторонний Google-трафик.

Discord TCP выбирается по доменной категории
`ext:geosite_v2fly.dat:discord`; в nfqws2 ему соответствуют hostlist
`user.list`, `NFQWS_ARGS` и `TCP_PORTS`. Discord Voice — отдельное правило
UDP-портов `3478-3481,5349,19294-19344,50000-50100`; в nfqws2 —
`NFQWS_ARGS_UDP`, `UDP_PORTS` и blob `discord_udp`. Маршруты меняются
независимо. При Voice = VPN правило UDP-портов не создаётся, и голос идёт по
обычной proxy-маршрутизации XKeen.
`ext:zkeenip.dat:discord` намеренно не используется: эта IP-категория включает
общие сети Cloudflare и Google и может ошибочно вывести из VLESS посторонний
трафик. Обычный список доменов нужен nfqws2, который Xray `.dat` не читает.

## Документация

- [`docs/guide.html`](docs/guide.html) — короткая автономная памятка.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — применение, перезагрузка,
  диагностика и восстановление.
- [`docs/MODES-AND-FLAGS.md`](docs/MODES-AND-FLAGS.md) — все режимы и флаги,
  а также handoff для другого агента.
- [`docs/STRATEGY.md`](docs/STRATEGY.md) — действующие TCP/QUIC/UDP-стратегии
  и границы адаптации Flowseal.
- [`docs/XKEEN-INTEGRATION.md`](docs/XKEEN-INTEGRATION.md) — что скрипт читает
  и меняет в XKeen/Xray/Mihomo.
- [`docs/XKEEN-DIRECT-ZAPRET.md`](docs/XKEEN-DIRECT-ZAPRET.md) — путь пакета
  DIRECT → NFQUEUE.
- [`docs/ROUTER-AUDIT-2026-07-23.md`](docs/ROUTER-AUDIT-2026-07-23.md) —
  исторический аудит роутера до первого применения.
- [`tools/windows/README.md`](tools/windows/README.md) — безопасный перебор
  стратегий.
- [`tools/router/README.md`](tools/router/README.md) — локальная панель XKeen
  и переключатели режимов сервисов.
- [`tools/dat-reader/README.md`](tools/dat-reader/README.md) — просмотр
  категорий и доменов внутри бинарных баз Xray/V2Ray `.dat`.
- [`docs/TELEGRAM.md`](docs/TELEGRAM.md) — Telegram: режимы, правила,
  профили nfqws2 и ограничения;
  [`docs/TELEGRAM-RESEARCH.md`](docs/TELEGRAM-RESEARCH.md) — исследование.
- [`docs/CODE-REVIEW.md`](docs/CODE-REVIEW.md) — итоги ревью кода, найденные
  ошибки поведения и совместимость с nfqws2-keenetic 1.3.1 / Xray 26.10.17.

## Разработка и тесты

Все наборы тестов — shell, Python (pytest) и JavaScript — запускаются одной
командой из корня проекта:

```sh
sh tests/run-all.sh
sh tests/run-all.sh --coverage
```

`--coverage` дополнительно печатает branch coverage Python-кода (сейчас около
93%). Shell-тесты выполняются оболочкой из `TEST_SHELL`; ближе всего к Entware
на роутере:

```sh
TEST_SHELL="busybox sh" sh tests/run-all.sh
```

`test-routing-modes.sh` нужны штатные blobs nfqws2. На роутере они берутся из
`/opt`, в остальных случаях — из `NFQWS_TEST_BLOB_SOURCE`, иначе `run-all.sh`
скачивает их через `tests/fetch-nfqws2-blobs.sh`: закреплённый commit
zapret2 и проверка SHA-256. Если задать `KD_TEST_XRAY_BIN` (бинарник
Xray) и `KD_TEST_XRAY_ASSETS` (каталог с `geosite_v2fly.dat`,
`geoip_v2fly.dat`, `zkeen.dat`, `zkeenip.dat`), тест проверяет каждую
сгенерированную конфигурацию настоящим `xray run -test`. Отдельно:

```sh
sh tests/fetch-nfqws2-blobs.sh /tmp/nfqws2-blobs
NFQWS_TEST_BLOB_SOURCE=/tmp/nfqws2-blobs sh tests/test-routing-modes.sh
```

С `TEST_BUSYBOX_APPLETS=1` shell-тесты используют ещё и busybox `awk`,
`sed`, `grep` и другие базовые утилиты, как на роутере (`jq` и `python3`
остаются системными):

```sh
TEST_SHELL="busybox sh" TEST_BUSYBOX_APPLETS=1 sh tests/run-all.sh
```

Отдельные наборы:

- `tests/test-jsonc.sh` — удаление комментариев JSONC в конфигах Xray
  (строчные, встроенные, многострочные, `//` внутри строк);
- `tests/test-voice-diagnostic.sh` — `diagnose-discord-voice.sh` с mock
  `tcpdump`: счётчики и `EVENT|VOICE_ENDPOINT`;
- `tests/test-panel-ui.cjs` — UI панели в Chromium через Playwright против
  `tests/panel_mock_server.py`. Без Playwright набор пропускается, с
  `REQUIRE_PANEL_UI_TESTS=1` — падает.

Нужны `jq`, `sha256sum`, `curl` (для загрузки blobs), `python3` с `pytest`
(и `coverage` для `--coverage`), `node` и для UI-теста — Playwright с
Chromium:

```sh
npm install --no-save playwright@1.56.1
npx playwright install chromium
```

CI [`.github/workflows/tests.yml`](.github/workflows/tests.yml) прогоняет
`run-all.sh --coverage` под `dash` и `busybox sh` (для busybox — с
`TEST_BUSYBOX_APPLETS=1`), устанавливает Playwright и требует UI-тест панели.
Отдельный job запускает `shellcheck -S warning` и `ruff check --select F,B,E9`.

## Ограничения

- Маршрут Discord Voice по-прежнему выбирается по UDP-портам, а не по L7; на
  тех же портах может оказаться другой трафик.
- `--wide-udp` расширяет прямой маршрут до `50000-65535`; без результатов
  диагностики его включать не следует.
- Автоматическая проверка Voice в поле не испытана: неизвестно, отвечают ли
  реальные голосовые серверы Discord на IP Discovery вне сессии. Если сервер
  отвечает и без обхода, подбор переходит на ручную проверку. Windows-тюнер
  проверяет Voice только вручную.
- Стратегии Flowseal работают через WinDivert/winws, а роутер — через
  Netfilter/NFQUEUE и nfqws2. Это контролируемая адаптация, не побайтовая
  копия BAT-профилей.
- Hardware offload может обходить Netfilter. Скрипт его не переключает.
- Baseline-откат заменяет управляемые пути исходными копиями; rescue snapshot
  сохраняет состояние перед самим откатом.

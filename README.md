# XKeen + nfqws2 для Discord и YouTube

Проект позволяет независимо выбирать маршрут для двух сервисов:

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

Проверено на роутере 15.08.2026:

| Компонент | Состояние |
|---|---|
| Роутер | Keenetic Giga KN-1011, KeeneticOS 5.0.12 |
| XKeen | 2.0, Xray 26.7.28, режим Hybrid |
| nfqws2 | `nfqws2-keenetic 1.2.4`, очередь 300, WAN `eth3` |
| Управляющий скрипт | `3.0.0` |
| Активный режим | `both`: Discord и YouTube через DIRECT + nfqws2 |
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

Выбрать один из четырёх режимов:

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
доступны все три режима; второй сервис сохраняет своё текущее состояние:

```sh
sh set-service-route.sh discord direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube vpn    --core auto --wan-interface eth3 --yes-router
```

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

Найденный профиль только показывается. Его постоянное применение — отдельная
кнопка с focused snapshot и перезапуском только `nfqws2`.

Ручной автоподбор записывает baseline штатного профиля и требует двух
успешных TCP-проходов с проверкой API/CDN-содержимого. Диагностические метрики
сохраняются в отчёте; для Voice по-прежнему требуется подтверждение звука.

Кнопка **Проверить обновление** скачивает новые стратегии Flowseal для
следующего подбора. Если скачанная версия последняя, показывает **Актуально**.
Запуск подбора и применение найденного профиля остаются отдельными действиями.

## Локальная web-панель

[`tools/router/xkeen_control_script.sh`](tools/router/xkeen_control_script.sh)
создаёт single-page панель управления XKeen и маршрутами
`Direct / Zapret / VPN` для обоих сервисов. Вкладка **Автоподбор** перебирает
актуальные Flowseal-профили на роутере, а **Импорт профиля** принимает отчёт
Windows-тюнера. Смена маршрута выполняется фоновым заданием: краткий разрыв
LAN-соединения при перезапуске Xray не теряет результат, а после повторного
открытия панель продолжает показывать состояние операции.
Импорт, удаление и откат профиля перезапускают только `nfqws2`; Xkeen при
этих операциях не останавливается и не перезапускается.

Для полного apply панель показывает этапы, сохраняет постоянную историю по
дате и позволяет откатиться к snapshot до выбранной операции. После успеха
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

- отдельные правила Xray/Mihomo для Discord и YouTube;
- разные hostlist и nfqws2-профили двух сервисов;
- TCP/TLS, QUIC и Discord Voice/STUN;
- узкий UDP-диапазон по умолчанию и явный `--wide-udp`;
- WAN, core и при необходимости direct mark;
- снимки, автооткат и восстановление служб.

YouTube DIRECT выбирается только по доменным категориям
`ext:zkeen.dat:youtube` и `ext:geosite_v2fly.dat:youtube`.
`ext:zkeenip.dat:youtube` и Google IP-категории остаются через VLESS: это
уменьшает риск отправить напрямую посторонний Google-трафик.

Discord DIRECT выбирается по доменной категории
`ext:geosite_v2fly.dat:discord` и отдельному правилу voice-портов.
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
  и трёхрежимные переключатели сервисов.
- [`tools/dat-reader/README.md`](tools/dat-reader/README.md) — просмотр
  категорий и доменов внутри бинарных баз Xray/V2Ray `.dat`.

## Ограничения

- Discord Voice до распознавания L7 выбирается по UDP-портам; на тех же портах
  может оказаться другой трафик.
- `--wide-udp` расширяет прямой маршрут до `50000-65535`; без результатов
  диагностики его включать не следует.
- Стратегии Flowseal работают через WinDivert/winws, а роутер — через
  Netfilter/NFQUEUE и nfqws2. Это контролируемая адаптация, не побайтовая
  копия BAT-профилей.
- Hardware offload может обходить Netfilter. Скрипт его не переключает.
- Baseline-откат заменяет управляемые пути исходными копиями; rescue snapshot
  сохраняет состояние перед самим откатом.

# Эксплуатация и восстановление

Это практическая памятка для уже установленного проекта. Все команды ниже
выполняются на роутере:

```sh
cd /opt/root/keenetic-discord-nfqws2
```

## 1. Проверить состояние

Без записи файлов и изменения сети:

```sh
sh apply-discord-nfqws2.sh --status
sh apply-discord-nfqws2.sh --show-snapshots
sh apply-discord-nfqws2.sh --preflight --core auto --wan-interface eth3
sh scripts/diagnose-xkeen-router.sh
```

В выводе диагностики безопасное состояние подписано
`discord_ip_scope=domain-only`. Значение `broad-selector-present` означает,
что общая CDN/IP-категория снова попала в Xray и может затронуть ChatGPT,
OpenAI и другой трафик Cloudflare/Google.

`--status` показывает маршруты по отдельности: `discord_tcp_route=`,
`discord_voice_route=`, `youtube_route=`, `telegram_route=`. `discord_route=` сохранён для
совместимости и равен `mixed`, если маршруты TCP и Voice различаются.
`udp_strategy=flowseal|legacy` и `udp_range=narrow|wide` — записанные
настройки Discord UDP (`unknown`, если `nfqws2.conf` нет).

Проверенное 15.08.2026 состояние:

- активен режим `both`;
- Discord → `discord-direct`, YouTube → `youtube-direct`;
- Xray работает в Hybrid, nfqws2 — на WAN `eth3`;
- Discord выбирается только доменной категорией; широкая
  `ext:zkeenip.dat:discord` на диске отсутствует;
- используются два списка:
  `/opt/etc/nfqws2/lists/user.list` и
  `/opt/etc/nfqws2/lists/youtube.list`;
- IPv6 nfqws2 выключен, поскольку usable IPv6 WAN route отсутствует.

`xkeen -dns`, `xkeen -pr`, `xkeen -ipv6` и `xkeen -dscp` без аргумента здесь
не используются: в установленной версии это переключатели, а не просмотр
состояния.

## 2. Переключить маршрут сервиса

```sh
sh set-zapret-mode.sh discord --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh youtube --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh both    --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh vless   --core auto --wan-interface eth3 --yes-router
```

Значение режимов (Discord — сразу TCP и Voice):

| Режим | Discord | YouTube |
|---|---|---|
| `discord` | zapret | VLESS |
| `youtube` | VLESS | zapret |
| `both` | zapret | zapret |
| `vless` | VLESS | VLESS |

Любой `apply` создаёт `latest-preapply` и автоматически возвращает его при
ошибке.

Для точечного переключения одного сервиса доступны три режима. Discord
разделён на два независимых маршрута: `discord-tcp` (домены Discord, TCP/TLS
и QUIC) и `discord-voice` (Voice/STUN UDP-порты); `discord` переключает оба:

```sh
sh set-service-route.sh discord-tcp direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-tcp zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-tcp vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh discord-voice direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-voice zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh discord-voice vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh discord zapret --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube zapret --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube vpn    --core auto --wan-interface eth3 --yes-router

sh set-service-route.sh telegram zapret    --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh telegram unmanaged --core auto --wan-interface eth3 --yes-router
```

`direct` и `zapret` используют один service-direct маршрут, но в `direct`
nfqws2-профиль сервиса выключен. `vpn` — понятный alias внутреннего режима
`vless`. Wrapper читает и сохраняет режимы остальных сервисов. При Voice =
`vpn` правило UDP-портов Discord не создаётся, и голос идёт по обычной
proxy-маршрутизации XKeen.

После обновления скриптов повторный apply не нужен: старая строка
`# Active routes: Discord=X, YouTube=Y.` в `nfqws2.conf` читается как X для
TCP и Voice, а строка без `Telegram=` — как Telegram `unmanaged`. Новый
apply записывает
`# Active routes: DiscordTCP=X, DiscordVoice=Y, YouTube=Z, Telegram=T.`

Настройки Discord UDP тоже запоминаются в управляемом блоке:

```text
# Discord UDP: strategy=flowseal|legacy, range=narrow|wide.
```

`set-zapret-mode.sh` и `set-service-route.sh` передают их в apply, поэтому
импортированный широкий Voice-профиль или `legacy` не сбрасываются при
переключении, в том числе только YouTube или при Voice = `direct`. Явные
опции вызова побеждают:

```sh
sh set-zapret-mode.sh both --wide-udp   --core auto --wan-interface eth3 --yes-router
sh set-zapret-mode.sh both --narrow-udp --core auto --wan-interface eth3 --yes-router
sh set-service-route.sh youtube zapret --udp-strategy flowseal --core auto --wan-interface eth3 --yes-router
```

Конфиг без этой строки (до обновления) определяется по `UDP_PORTS` и наличию
blob `discord_udp`; это надёжно, пока Voice использует `zapret`.

## 3. Откат

Перед последним `apply`:

```sh
sh rollback-last-change.sh
```

До первого применения проекта:

```sh
sh rollback-to-baseline.sh
```

Посмотреть актуальные точки:

```sh
sh apply-discord-nfqws2.sh --show-snapshots
```

Ручной rollback сначала создаёт rescue snapshot текущего состояния.

Если проект впервые ставился как `--standalone-zapret`, baseline покрывает
только пути nfqws2. Первый интегрированный apply после этого записывает
XKeen baseline (`baseline-xkeen.ptr`); `--show-snapshots` показывает его
строкой `XKeen baseline:`. `rollback-to-baseline.sh` (`--rollback`) тогда
создаёт один rescue snapshot, восстанавливает XKeen baseline и затем
nfqws2-baseline — патчи Xray/Mihomo тоже убираются. Без XKeen baseline откат
работает как раньше. В standalone-режиме (`--standalone-zapret`) такой откат
отказывается восстанавливать интегрированный снимок.

После `opkg upgrade` отслеживаемых пакетов (`ca-certificates`, `jq`,
`wget-ssl`, `wget-nossl`, `nfqws2-keenetic`) откат завершается: opkg не
умеет понижать версию, поэтому выводится предупреждение

```text
WARNING: PKG version is NEW; snapshot has OLD.
         opkg cannot downgrade it; the package stays at NEW.
```

и пакет остаётся новым. Ошибкой остаются только неудачные `opkg install` /
`opkg remove`.

Web-панель дополнительно хранит историю применений по дате. Из неё можно
вернуть состояние до любой завершённой операции, если соответствующий
snapshot не удалён. Эквивалентная низкоуровневая команда принимает только
один проверенный каталог непосредственно внутри управляемого `snapshots`:

```sh
sh apply-discord-nfqws2.sh \
  --rollback-snapshot /opt/etc/keenetic-discord-nfqws2/snapshots/NAME \
  --yes-router
```

Не подставляйте путь вручную без `--show-snapshots`; безопаснее использовать
кнопку в истории панели.

## 4. После перезагрузки роутера

Повторный `apply` не нужен. На постоянном Entware-накопителе остаются
конфиги, списки и снимки.

Порядок запуска:

1. Keenetic монтирует Entware как `/opt`.
2. `S05xkeen` запускает Xray (`start_auto=on`).
3. `S51nfqws2` запускает nfqws2.
4. `100-nfqws2.sh` возвращает NFQUEUE rules после пересборки firewall.

Проверка через одну-две минуты:

```sh
xkeen -status
/opt/etc/init.d/S51nfqws2 status
iptables-save -t mangle | grep NFQUEUE
```

Если `/opt` доступен, но служба не поднялась:

```sh
/opt/etc/init.d/S05xkeen restart on
(cd / && /opt/etc/init.d/S51nfqws2 restart)
```

Если `/opt` отсутствует, исправьте подключение Entware/USB до перезапуска
служб.

## 5. Проверка сервисов

### Discord

Сайт и gateway проверяются обычным клиентом. Для Desktop Voice:

```sh
sh scripts/diagnose-discord-voice.sh CLIENT_IP 30
```

В течение 30 секунд отключитесь и снова войдите в голосовой канал. Скрипт
показывает LAN/WAN endpoints, conntrack и изменение счётчиков NFQUEUE.
Заголовки пакетов не подтверждают качество звука, поэтому результат нужно
проверить в приложении.

По умолчанию обрабатываются UDP:

```text
443, 3478-3481, 5349, 19294-19344, 50000-50100
```

`--wide-udp` расширяет последнюю часть до `50000-65535` сразу в XKeen, core
и nfqws2. Используйте его только если диагностика увидела порт выше `50100`.
`--narrow-udp` возвращает `50000-50100`. Выбранный диапазон запоминается и
сохраняется wrapper-скриптами.

Диагностика также печатает самый активный публичный голосовой сервер, который
ответил клиенту:

```text
EVENT|VOICE_ENDPOINT|IP|PORT|OUT_PACKETS|IN_PACKETS
```

Его запоминает автоподбор для автоматической проверки Voice (раздел 7).

### YouTube

Проверьте отдельно:

- открытие страницы и старт видео;
- перемотку и длительное воспроизведение;
- компьютер и телевизор;
- QUIC/HTTP3, если клиент его использует.

TCP/TLS и HTTP-проверка подтверждены. Наличие QUIC-профиля не доказывает, что
конкретный телевизор выбрал HTTP3.

## 6. Настройка nfqws2

Основной файл:

```text
/opt/etc/nfqws2/nfqws2.conf
```

Важные переменные:

| Переменная | Назначение |
|---|---|
| `NFQWS_ARGS` | базовые TCP/HTTP/TLS-профили |
| `NFQWS_ARGS_QUIC` | базовый QUIC |
| `NFQWS_ARGS_UDP` | Discord Voice/STUN |
| `NFQWS_ARGS_CUSTOM` | отдельные профили, включая YouTube |
| `NFQWS_EXTRA_ARGS` | `MODE_LIST`, `MODE_AUTO` или `MODE_ALL` |
| `TCP_PORTS`, `UDP_PORTS` | порты Netfilter |
| `ISP_INTERFACE` | WAN |
| `IPV6_ENABLED` | обработка IPv6 |

Управляемый блок расположен между:

```text
# BEGIN keenetic-discord-nfqws2
# END keenetic-discord-nfqws2
```

Следующий `apply` генерирует его заново. Постоянный рабочий профиль нужно
переносить в `apply-discord-nfqws2.sh`, а не оставлять ручной правкой.

`MODE_LIST` — безопасный штатный режим. `MODE_AUTO` расширяет список
автоматически, а `MODE_ALL` обрабатывает почти весь подходящий трафик; два
последних режима не включены проектом по умолчанию.

## 7. Подбор стратегий

Проще всего открыть вкладку **Автоподбор** панели:

```text
http://192.168.2.1:8088
```

Подбираемый сервис (Discord TCP, Discord Voice или YouTube) заранее должен
находиться в `Zapret`. YouTube и Discord TCP
проверяются HTTP-пробами автоматически. Для Discord Voice укажите LAN IPv4
компьютера, переподключайтесь к voice-каналу по подсказке и отвечайте
**Да/Нет**.

По умолчанию **Проверка Voice → По трафику Discord**
(`zapret_autotune_job.py --voice-traffic`): зайдите в голосовой канал один раз,
кандидаты оцениваются по трафику самого Discord. Режим **Пакетом с роутера**
(`--voice-auto`) проверяет кандидатов пакетом с роутера. Он становится
доступен после одной ручной проверки Voice с ответом **Да**: сервер из этой
сессии хранится в `/opt/etc/xkeen-web/discord-voice-endpoint.json`.
Кандидаты без ответа сервера отбрасываются автоматически, звук подтверждается
только для найденного профиля. Если сервер отвечает и без nfqws2, все
кандидаты проверяются вручную. Если на финальный вопрос о звуке никто не
ответил за 300 секунд, профиль остаётся найденным, но помечается как
неподтверждённый — проверьте голос перед применением. Подробности и ограничения —
[`tools/router/README.md`](../tools/router/README.md#проверка-discord-voice-пакетом-с-роутера).

Перебор не записывает постоянные конфиги и не вызывает Xkeen. Он временно
заменяет только запущенный процесс `nfqws2`, а отмена и `EXIT` trap
восстанавливают штатную службу. Победитель применяется только отдельной
кнопкой; перед этим создаётся focused snapshot.

Каждый применённый, заменённый или удаляемый профиль архивируется с UTC-датой
в `/opt/etc/nfqws2/profile-versions/<service>`. Вкладка **Импорт профиля**
показывает эти версии и позволяет снова применить выбранную. Текущий профиль,
созданный до появления функции версий, впервые попадёт в архив при следующей
замене или удалении.

Кнопка **Проверить обновление** сравнивает скачанный набор стратегий с GitHub.
Новый commit скачивается автоматически и используется следующим подбором
из панели; если версия последняя, выводится **Актуально**. Рабочий профиль
сохраняется. Затем отдельно запустите подбор и примените найденный результат.

Для обычной проверки выберите `Safe`: он по очереди меняет `repeats`,
`out-range`, TCP `pos`/`seq` и QUIC repeats. `Extended` добавляет
ограниченные сочетания и имеет смысл после неудачи `Safe`. Значение
`Максимум кандидатов` ограничено 64; его увеличение линейно удлиняет тест.
Полного перебора всех параметров нет.

Поле **BAT-файл Flowseal** ограничивает подбор одним файлом из скачанного
набора; список появляется после **Проверить обновление**, файлы без профиля
для выбранного сервиса недоступны. Проверяются только переведённые профили
этого файла, без встроенного профиля роутера и смешивания. `Safe`/`Extended`
добавляют вариации параметров файла только для TCP-сервисов; для Voice — лишь
переведённые профили. С Windows то же самое:

```text
tools\windows\tune-discord-tcp.bat --source-file "general (ALT3).bat"
```

Для запуска с Windows по-прежнему доступны:

Запускайте один файл:

```text
tools\windows\tune-youtube.bat
tools\windows\tune-discord-tcp.bat
tools\windows\tune-discord-voice.bat
```

Тюнер не исполняет скачанные BAT-файлы и не записывает постоянные конфиги.
На время кандидата он заменяет только процесс nfqws2 и восстанавливает
исходную службу при завершении, ошибке, потере SSH или `Ctrl+C`.

YouTube и Discord TCP проверяются автоматически. Discord Voice требует
реального reconnect и ответа пользователя (автоматическая проверка Voice есть
только в панели); QUIC требует HTTP3-клиента.

BAT-файлы сохраняют последние отчёты в `tools\windows\reports`. Их можно
загрузить во вкладку **Импорт профиля** панели на порту `8088`. Соответствующий
сервис должен уже иметь маршрут `Zapret`.

Точечные команды на роутере:

```sh
sh apply-discord-nfqws2.sh --apply-import-profile /opt/tmp/profile.json --yes-router
sh apply-discord-nfqws2.sh --clear-imported-profile youtube --yes-router
sh apply-discord-nfqws2.sh --rollback-import --yes-router
```

Допустимые имена для удаления: `youtube`, `discord-tcp`, `discord-voice`.
Эти три операции создают focused snapshot, меняют только `/opt/etc/nfqws2` и
перезапускают только `nfqws2`. Они не перезапускают Xkeen. Обычное
переключение маршрута остаётся полным apply и может перезапустить обе службы.
В web-панели этот apply запускается как фоновое задание и отслеживается через
`/api/route/status`, поэтому очистка conntrack не обрывает саму операцию.
В интерфейсе видны текущий этап и история. После успеха панель проверяет
процессы и согласованность конфигов. HTTP/TLS-пробы с LAN-устройства доступны
отдельно во вкладке «Диагностика». QUIC и Discord Voice проверяются вручную.

Проверка после apply в панели и **Проверить роутер** во вкладке
«Диагностика» сверяют маршруты Discord TCP и Discord Voice по отдельности.

Пока идёт переключение, вкладки панели остаются доступными. Переключение,
подбор и проверка роутера запускаются по одному: второй запуск, пока первый
ещё стартует, получает HTTP 409 — повторите через несколько секунд.

## 8. WAN, mark и IPv6

- `--wan-interface eth3` фиксирует текущий WAN.
- `--direct-mark` нужен только для осознанной multi-WAN/PBR-схемы.
- При `proxy_router=off` текущим direct-outbound явный mark не нужен.
- Переключатель IPv6 XKeen не меняется. nfqws2 включает IPv6 только при
  рабочем IPv6 default route.

Неверный mark или WAN способен оставить правила без рабочего маршрута.

## Обновление nfqws2 от 20.10.2026

Установлен официальный пакет `nfqws2-keenetic 1.3.1`, ядро `v1.0.5.2`
с `lua_compat_ver 6`. Текущие профили, списки и blobs сохранены побайтно.
В комплекте `tools/router/upgrade-nfqws2-router.sh` закреплены версия и SHA-256
пакета: это сценарий именно данного обновления, а не универсальный updater.

Пакет 1.2.4 собран из установленного состояния для отката. Копия хранится в
`/opt/etc/nfqws2-update-backups/20261020-220034-1.2.4`. Откат:

```sh
sh /opt/etc/nfqws2-update-backups/20261020-220034-1.2.4/rollback.sh
```

Он перезапускает nfqws2; Xray не затрагивает. Перед этим завершите подбор и
другие операции панели. Пакетный postinst запускается при установке, поэтому
ожидается краткий перерыв обработки трафика. При обновлении opkg может
оставить рядом штатный `nfqws2.conf-opkg`; активным остаётся прежний конфиг.

Снимки управляющего скрипта, сделанные до обновления (в том числе baseline),
остаются рабочими: `--rollback-latest`, `--rollback-snapshot` и
`rollback-to-baseline.sh` видят, что версия `nfqws2-keenetic` изменилась, и
возвращают только данные (`nfqws2.conf`, `lists`, `blobs`,
`imported-profiles`, `profile-versions`). Lua-скрипты, `S51nfqws2` и
`100-nfqws2.sh` остаются от 1.3.1: Lua 1.2.4 с ядром 1.3.1 не запускается
(`Incompatible NFQWS2_COMPAT_VER`). Версию пакета возвращает только
`rollback.sh` из `/opt/etc/nfqws2-update-backups`.

## 9. Типовые проблемы

| Симптом | Что проверить |
|---|---|
| После reboot ничего не работает | Смонтирован ли `/opt`, затем статусы двух служб |
| Сайт Discord есть, voice нет | `discord_voice_route`, Hybrid/TProxy, voice-порты, reconnect-диагностику |
| YouTube открывается, видео нет | TLS/QUIC отдельно, hostlist, NFQUEUE counters |
| nfqws2 запущен, эффекта нет | `ISP_INTERFACE`, mangle rules, hardware offload |
| После эксперимента стало хуже | `sh rollback-last-change.sh` |

Предупреждение о неподдерживаемом `seccomp` допустимо, если nfqws2 после него
остаётся в состоянии `running`.

## 10. Тесты проекта

Все наборы тестов (shell, Python, JavaScript) запускаются одной командой:

```sh
sh tests/run-all.sh
sh tests/run-all.sh --coverage
TEST_SHELL="busybox sh" sh tests/run-all.sh
TEST_SHELL="busybox sh" TEST_BUSYBOX_APPLETS=1 sh tests/run-all.sh
```

Последняя команда добавляет busybox `awk`/`sed`/`grep` и другие утилиты, как
на роутере. UI-тест панели (`tests/test-panel-ui.cjs`) пропускается без
Playwright.

Подробности и зависимости — в разделе «Разработка и тесты»
[`README.md`](../README.md#разработка-и-тесты).

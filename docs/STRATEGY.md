# Стратегии Discord и YouTube

Проект использует идеи
[`Flowseal/zapret-discord-youtube`](https://github.com/Flowseal/zapret-discord-youtube),
но не запускает его BAT-файлы на роутере. Flowseal работает через
WinDivert/winws, а Keenetic — через Netfilter/NFQUEUE и
[`nfqws2-keenetic`](https://github.com/nfqws/nfqws2-keenetic).

Поэтому профиль является адаптацией. Для воспроизводимости binary blobs
закреплены SHA-256, а Windows-тюнер в каждом отчёте записывает Git commit и
blob SHA скачанного BAT-файла. Плавающий номер релиза Flowseal в документации
намеренно не фиксируется.

## Discord

### TCP и QUIC

Используются базовые стратегии установленного nfqws2:

- TCP/HTTP/TLS — адаптивный `circular`;
- QUIC — fake `quic_initial`, `repeats=11`;
- область ограничена Discord hostlist;
- IPSet отключён, hostlist mode — `MODE_LIST`.

Порты TCP:

```text
80,443,2053,2083,2087,2096,8443
```

### Voice/STUN

Профиль `flowseal`, включённый по умолчанию:

```text
filter-l7=stun,discord
payload=stun,discord_ip_discovery
fake blob=discord_udp
repeats=6
```

Порты UDP:

```text
443,3478-3481,5349,19294-19344,50000-50100
```

`ACTIVE_DISCORD_UDP.bin` копируется без изменения и проверяется:

```text
SHA-256 2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf
```

`legacy` оставлен для A/B-проверки. `--wide-udp` расширяет последний диапазон
до `50000-65535`, но увеличивает риск отправить напрямую посторонний UDP.

## YouTube

YouTube имеет отдельный hostlist и отдельные профили, поэтому его параметры
можно менять независимо от Discord.

### TCP/TLS — рабочий профиль

```text
--filter-tcp=443
--filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
```

Смысл профиля:

1. отправить модифицированный fake TLS ClientHello;
2. сдвинуть его sequence number;
3. разделить оригинал в начале и около SNI;
4. добавить минимальный overlap и поднять TCP timestamp.

Эта комбинация выбрана живой матрицей на данном подключении. Запрос к
`https://www.youtube.com/` вернул HTTP 200. Из текущих Flowseal BAT она ближе
всего к семейству `general (ALT11).bat`, но не является его точной копией.

Не прошли на этом подключении:

- одиночный Flowseal-подобный `multisplit + seqovl=681`;
- ALT-подобный `hostfakesplit`;
- `tcp_md5 + repeats=11 + multidisorder`.

### QUIC

```text
--filter-udp=443
--filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=11
```

Профиль установлен, но HTTP3/QUIC должен подтверждаться реальным клиентом.
Успешный HTTP/TLS-тест доказывает только TCP-путь.

### Важная граница маршрутизации

В DIRECT переносятся только доменные категории:

```text
ext:zkeen.dat:youtube
ext:geosite_v2fly.dat:youtube
```

IP-категории `zkeenip:youtube` и `zkeenip:google` остаются в VLESS. Это
сознательный компромисс: меньше шанс вывести напрямую весь Google-трафик,
но поток без распознанного домена может остаться в proxy.

Discord разделён на два независимых маршрута: Discord TCP выбирается по
`ext:geosite_v2fly.dat:discord` (TCP/TLS и QUIC, hostlist `user.list`),
Discord Voice — по voice-портам (`NFQWS_ARGS_UDP`). У каждого свой режим
Direct/Zapret/VPN. `zkeenip:discord` удаляется
из Xray: категория включает общие сети Cloudflare/Google и может затронуть
ChatGPT/OpenAI.

## Почему нельзя начинать с `--new`

Перед первым управляемым desync-профилем не должно быть безусловного ведущего
`--new`. Он создаёт пустой профиль №1, который совпадает раньше hostlist и не
даёт последующим профилям вызвать Lua desync.

Генератор добавляет разделитель только когда предыдущий профиль действительно
существует.

## Что перенесено из Flowseal

- сервисные домены и характерные порты;
- раздельные TCP/QUIC и Discord Voice/STUN;
- специальный Discord UDP fake;
- число повторов, fake-модификаторы и идеи split там, где они поддерживаются
  nfqws2;
- возможность перебора актуальных `general*.bat` с фиксацией источника.

Не переносились:

- WinDivert filters и Windows service management;
- буквальный запуск BAT;
- небезопасные или неизвестные параметры без nfqws2-эквивалента;
- автоматическое постоянное применение без просмотра и подтверждения
  пользователя.

Панель умеет сама выполнить временный перебор во вкладке **Автоподбор**.
Победитель только показывается; постоянным он становится после отдельного
подтверждения. Также остаётся импорт отчёта Windows-тюнера.
Перед записью Python backend и router shell независимо проверяют формат,
`candidate_id`, allowlist опций, hostlist и границы портов. Операция создаёт
отдельный снимок и перезапускает только `nfqws2`, не Xkeen.

### Осознанный параметрический перебор

`--mix-level safe` строит варианты от проверенного router-native профиля и
меняет ровно одну ось: TLS `out-range`, fake `repeats`, `tcp_seq`, split
`pos`/`seqovl` либо QUIC `repeats`. Для Voice отдельно меняются повторы и
граница первых UDP-пакетов.

`--mix-level extended` добавляет малую матрицу Voice, три составных рецепта,
одноосевые мутации нескольких разных BAT-семейств и смешивание fake/split.
Генератор не перемножает все значения:

```text
TLS out-range: -d2, -d4, -d10
TLS fake repeats: 2, 6, 11
TCP pos: 1, midsld, 1,midsld, sniext+1
TCP sequence: tcp_seq=-10000/10000, seqovl=1/5/681
QUIC repeats: 3, 6, 11
Voice repeats: 2, 3, 6, 11
Voice out-range: <n2, <n3, <n4
```

Значения `-d10`, `tcp_seq=10000`, `pos=1,midsld`, `seqovl=1` и QUIC
`repeats=11` уже входят в текущий проходной профиль и остаются первым
кандидатом. Остальные варианты используются для восстановления после
изменения DPI, а не автоматически включаются в постоянный конфиг.

## Условия работы

- XKeen перехватывает нужные TCP/UDP-порты;
- Xray sniffing видит TLS/QUIC либо Mihomo применяет эквивалентные rules;
- service-direct rules расположены раньше proxy rules;
- nfqws2 видит WAN `POSTROUTING`;
- hardware offload не обходит нужный Netfilter-путь;
- при IPv6 существует согласованный рабочий WAN route.

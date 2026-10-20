# Read-only аудит роутера — 23.07.2026

> Исторический документ. Он фиксирует состояние **до первого применения**
> проекта. Поэтому ниже nfqws2 ещё не установлен, Discord идёт через VLESS и
> baseline отсутствует. Текущее состояние смотрите в
> [`../README.md`](../README.md) или командой
> `apply-discord-nfqws2.sh --status`.
>
> Позднее `ext:zkeenip.dat:discord` исключили из управляемой маршрутизации:
> категория содержит общие сети Cloudflare/Google. Упоминание ниже сохранено
> только как факт исторического состояния до исправления.

Во время аудита настройки, службы и конфигурационные файлы не изменялись.
Выполнялись только SSH-чтение и диагностика.

## Платформа

- Keenetic Giga KN-1011, KeeneticOS 5.0.12.
- Linux 4.9-ndm-5, MIPS little-endian (`opkg`: `mipsel-3.4_kn`).
- Entware на USB; свободно около 27 ГБ.
- BusyBox 1.37.0; его `stat` не поддерживает GNU-ключ `-c`.
- Около 345 МБ памяти, swap отсутствует.
- Загружены `xt_NFQUEUE`, `nfnetlink_queue`, `xt_TPROXY` и `xt_socket`.

## XKeen

- XKeen 2.0 Stable, init script 2.30.
- Активное ядро: Xray 26.2.6.
- `opkg` показывал пакет `xray_s 26.6.22`, а бинарник — 26.2.6. Проект Xray
  не обновляет и это расхождение автоматически не исправляет.
- Фактический режим: Hybrid (`TCP redirect` + `UDP TProxy`), порт 61219.
- Policy `XKeen`: mark `0xffffaaa`, table 4096, выход через ISP.
- Donor-порты: `80,443,596:599,1400,5222,50000:50030`.
- Исключённых портов нет.
- `proxy_dns=on`, но runtime `file_dns=false`; `02_dns.json` пуст.
- `proxy_router=off`, `ipv6_support=on`.
- `xkeen -dns`, `-pr`, `-ipv6` являются переключателями и не вызывались.
- Ключ `xkeen -pbr` в этой версии отсутствует.

## Xray до применения

- Конфиг проходил `xkeen -xtest`.
- `redirect` и `tproxy` уже имели sniffing
  `http,tls,quic,fakedns`, `routeOnly=true`.
- Outbounds: `vless-reality`, `direct`, `block`; `direct` без `sockopt.mark`.
- Discord направлялся в `vless-reality` через:
  - `ext:geosite_v2fly.dat:discord`;
  - `ext:zkeenip.dat:discord`;
  - UDP `50000-50030`.
- `03_inbounds.json`, `04_outbounds.json`, `05_routing.json` имели режим
  `0777`.

Отсюда требования к реализации:

- `discord-direct` должен стоять раньше доменных, IP и UDP proxy rules;
- `.dat` selectors нужно переносить, а не дублировать;
- обычный список доменов относится только к hostlist nfqws2;
- изменённый Xray JSON следует закрыть до `0600`.

## IPv6 и WAN

- IPv4 default route: `eth3`, WAN-адрес `192.168.1.26`.
- Глобальный IPv6 runtime включён, но usable IPv6 default route отсутствовал.
- Probe возвращал `unreachable ... dev lo`; `lo` нельзя использовать как WAN.

Ожидаемая конфигурация: `ISP_INTERFACE="eth3"` и `IPV6_ENABLED=0`.

## nfqws2 до применения

- `nfqws2-keenetic` не был установлен.
- `ca-certificates` и `wget-ssl` уже присутствовали.
- SSH PATH ставил `/opt/usr/bin` раньше `/opt/bin`, поэтому BusyBox `wget`
  перекрывал HTTPS-capable `wget-ssl`.
- Init script, конфиг, процесс и NFQUEUE rules отсутствовали.

Официальные пути совпали с проектом:

```text
/opt/etc/init.d/S51nfqws2
/opt/etc/nfqws2/nfqws2.conf
/opt/etc/ndm/netfilter.d/100-nfqws2.sh
```

## Исправления по результатам аудита

- GNU `stat -c` заменён переносимым чтением mode bits.
- Удалены ложные вызовы `xkeen -pbr`.
- Настройки читаются из runtime-hook XKeen.
- IPv6 nfqws2 включается только при usable WAN route; `lo` запрещён.
- Xray переносит существующие Discord `.dat` selectors.
- Xray JSON после успешной записи получает `0600`.
- Snapshot включает `/opt/var/opkg-lists`.
- Broad default nfqws2 после установки останавливается до записи узкого
  профиля.
- PATH для opkg HTTPS feed нормализован.

## Ограничения, выявленные аудитом

- Влияние hardware acceleration определяется только реальным тестом и
  счётчиками NFQUEUE; проект ускоритель не переключает.
- UDP DIRECT по портам может захватить другой трафик.
- Flowseal переносится как Linux/nfqws2-адаптация, не как winws-копия.

## Что изменилось после аудита

На момент актуализации документа:

- создан baseline и работает latest-preapply;
- установлен `nfqws2-keenetic 1.2.4`;
- Xray и nfqws2 запущены;
- активен режим `both`;
- добавлены независимые Discord/YouTube routes и hostlists;
- Discord Voice прошёл проверку сетевого пути;
- YouTube TCP/TLS прошёл HTTP-проверку.

Эти пункты не переписывают исторические наблюдения выше.

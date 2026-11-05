# CLI

Команды выполняются из каталога установленного проекта.
Краткая справка: `sh apply-discord-nfqws2.sh --help`.
Требования: [карта документации](../README.md).

## Чтение

```sh
sh apply-discord-nfqws2.sh --status
sh apply-discord-nfqws2.sh --status --json
sh apply-discord-nfqws2.sh --check-config
sh apply-discord-nfqws2.sh --print-nfqws-profiles
sh apply-discord-nfqws2.sh --show-snapshots
sh apply-discord-nfqws2.sh --print-plan
```

`--preflight` проверяет подготовку операции без snapshot/install/restart/config
write. Параметры WAN/core должны соответствовать вашей установке.
Help, offline plan и чтение метаданных `--show-snapshots` не требуют работающего
устройства. Остальные чтения проверяют фактическую поддерживаемую версию XKeen.

## Маршрут

```sh
sh set-service-route.sh youtube zapret --core auto --yes-router
sh set-service-route.sh discord-tcp vless --core auto --yes-router
```

Сервисы: `discord-tcp`, `discord-voice`, `youtube`, `telegram`.
`discord` переключает сразу TCP и Voice.
Режимы первых трёх: direct/zapret/vless.
У Telegram: direct/vless/ws/unmanaged.
Имя `vless` означает общий VPN-маршрут, включая Trojan/Hysteria2.

Пакетные переключатели:

| Аргумент set-zapret-mode.sh | Discord TCP+Voice | YouTube |
|---|---|---|
| discord | Zapret | VPN |
| youtube | VPN | Zapret |
| both | Zapret | Zapret |
| vless | VPN | VPN |

Смена маршрута — полный apply с возможным рестартом XKeen, не диагностика.

## Подготовка чекеров

```sh
sh apply-discord-nfqws2.sh --setup-route-checker --yes-router
```

Это отдельная изменяющая операция: подготовка loopback API/SOCKS, rescue snapshot
и перезапуск Xray с той же VPN-нодой. Нужны Xray 26.10.31+ поколения 26 и curl
с HTTP2; конфликты адресов/портов отклоняются. При уже подготовленном и
подтверждённом процессе повторный запуск не требует рестарта.

Сами проверки маршрута, ресурсов и IP запускаются в панели и не вызывают
эту команду автоматически. После внешнего рестарта, ребута или изменения
конфигов доступ нужно подготовить повторно. Подробности и порядок включения
монитора: [маршрут и VPN/IP](../usage/route-checker.md).

## Параметры apply

| Флаг | Значение |
|---|---|
| --yes-router | Явное подтверждение мутации |
| --core auto / xray | Поддержанный core; mihomo отклоняется |
| --wan-interface | Проверенный WAN или список интерфейсов |
| --direct-mark | Проверенная десятичная policy mark, не произвольное число |
| --discord-tcp-route / --discord-voice-route | Независимые маршруты Discord |
| --discord-route | Оба маршрута Discord |
| --youtube-route / --telegram-route | Маршруты соответствующих сервисов |
| --udp-strategy flowseal / legacy | Профиль Voice; legacy здесь не XKeen2.0 |
| --wide-udp / --narrow-udp | Верхняя граница Voice65535 /50100 |
| --json | Машинный вывод, где поддержан выбранным режимом |

Не копируйте WAN/marks из чужой конфигурации.
Standalone/without-xkeen/no-xkeen не являются поддержанной установкой.

## Снимки и импорт

`--snapshot-baseline` создаёт исходную точку; `--apply` применяет конфигурацию.
`--apply-import-profile FILE` импортирует descriptor,
`--clear-imported-profile SERVICE` убирает импорт сервиса.
`--rollback-snapshot PATH` восстанавливает выбранный полный снимок;
`--rollback-latest`, `--rollback` и `--rollback-import` не взаимозаменяемы.
Мутации требуют `--yes-router` и lock.

Порядок восстановления: [эксплуатация](../usage/operations.md#откат).

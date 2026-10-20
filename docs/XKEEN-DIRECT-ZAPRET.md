# XKeen DIRECT → nfqws2

## Путь пакета

```text
устройство в policy XKeen
  → TCP redirect / UDP TProxy
  → Xray/Mihomo
  → discord-direct или youtube-direct
  → новое исходящее соединение роутера
  → nfqws2 hook в WAN POSTROUTING
  → NFQUEUE
  → провайдер
```

В режиме `direct` пакет проходит service-direct и WAN, но его профиль nfqws2
выключен. В режиме `zapret` маршрут тот же, а профиль включён.

Если сервис выбран в VLESS, WAN видит только proxy-соединение. Локальный
nfqws2 после шифрования уже не может найти или изменить исходный Discord/
YouTube ClientHello.

## Почему nfqws2 не привязан к policy XKeen

Соединение, созданное Xray/Mihomo, обычно не сохраняет исходную Keenetic mark
клиента. Проект поэтому использует несуществующее зарезервированное имя:

```sh
POLICY_NAME="__keenetic_discord_nfqws2_unbound__"
POLICY_EXCLUDE=0
```

Охват ограничивается WAN, портами, hostlist и L7, а не клиентской policy.
Preflight остановится, если policy с таким именем неожиданно существует.

## Как выбирается Discord

Для Xray первыми ставятся правила `discord-direct`:

- `.dat` domain selectors;
- UDP Voice/STUN-порты.

Доменные selectors переносятся из нижних proxy rules. Discord IP selectors
удаляются: `zkeenip:discord` содержит общие сети Cloudflare и Google и может
захватить посторонний трафик, включая ChatGPT.

Обычный `discord-user.list` используется только nfqws2. Он не заменяет Xray
`.dat`.

## Как выбирается YouTube

Первыми ставятся правила `youtube-direct` только для:

```text
ext:zkeen.dat:youtube
ext:geosite_v2fly.dat:youtube
```

`zkeenip:youtube` и Google IP-категории остаются через VLESS. Это сужает
DIRECT, но означает, что поток без распознанного домена может выбрать proxy.

Для доменного выбора Xray нужны sniffing `http,tls` на redirect и `quic` на
tproxy с `routeOnly=true`.

## Порты

При активном ограничении `port_proxying.lst` проект добавляет:

```text
TCP: 80,443,2053,2083,2087,2096,8443
UDP: 443,3478:3481,5349,19294:19344,50000:50100
```

Пока Telegram управляется (не `unmanaged`), добавляется ещё `5222`
(MTProto).

`--wide-udp` меняет последнюю границу на `65535`. Это также расширяет прямой
маршрут в core, поэтому опция не является безопасным универсальным default.

## Проверка

```sh
sh apply-discord-nfqws2.sh --status
sh scripts/diagnose-xkeen-router.sh
iptables-save -t mangle | grep NFQUEUE
```

Для Discord Voice:

```sh
sh scripts/diagnose-discord-voice.sh CLIENT_IP 30
```

## Риски

- другой UDP на тех же voice-портах может попасть в DIRECT;
- неверный WAN или mark оставит nfqws2 без нужного трафика;
- hardware offload способен обойти Netfilter;
- Flowseal/winws и nfqws2 используют разные механизмы desync;
- baseline rollback заменяет управляемые пути, но перед этим создаёт rescue
  snapshot.

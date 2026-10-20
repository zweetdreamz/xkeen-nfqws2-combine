# Telegram как четвёртый сервис: исследование

Цель: добавить Telegram с тем же выбором `Direct / Zapret / VPN`, держа всю
настройку на роутере и ничего не настраивая на клиентах. Это исследование и
план, код ещё не менялся. Источники проверялись в октябре 2026.

## Что дают изученные репозитории

**[bol-van/zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle)**
— готовых материалов для Telegram нет: ни списков, ни ipset, ни стратегий.
Полезное для роутера приходит из самого
[zapret2](https://github.com/bol-van/zapret2): начиная с v0.1.2 nfqws2 умеет
распознавать протокол `mtproto` и payload `mtproto_initial`
(`--filter-l7=mtproto`, `nfq2/protocol.c`, `IsMTProto()`), а также фильтровать
профили по `--ipset=`. Распознаётся только obfuscated2-init с тегом
abridged (`EFEFEFEF`); готовой Telegram-стратегии у bol-van нет.

**[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)** (MIT,
Python 3.8+) — локальный MTProto-прокси: принимает подключение клиента,
расшифровывает obfuscated2-init с помощью секрета, определяет DC и
пересылает поток через WebSocket на `kws{N}.web.telegram.org/apiws`
(фиксированный IP 149.154.167.220 для DC2/DC4). Для остальных DC и при сбоях
используется Cloudflare-прокси со сторонними доменами или прямой TCP.
Ограничения:

- клиент **обязан** быть настроен на прокси (адрес и секрет) — это прямо
  сказано в FAQ проекта (issue #389), прозрачного режима нет;
- только TCP: звонки не проходят;
- зависимости `httpx`, `h2`, `certifi` (чистый Python) и OpenSSL через ctypes.

Порты для роутеров есть: Go-версия
[spatiumstas/tg-ws-proxy-go](https://github.com/spatiumstas/tg-ws-proxy-go)
с пакетами Entware для mipsel/mips/aarch64/armv7 (у репозитория нет файла
лицензии), Rust-форк и менеджер для OpenWrt. Все требуют секрет на клиенте.

Flowseal/zapret-discord-youtube для Telegram советует именно tg-ws-proxy или
публичные MTProto-прокси; в его `.service/hosts` web.telegram.org, `kws*`,
t.me и telesco.pe закреплены на 149.154.167.220.

## Как выбрать трафик Telegram на роутере

MTProto идёт на фиксированные IP дата-центров, поэтому выбор должен быть по
IP, а домены покрывают только web и медиа.

| Категория в `dat/` | Содержимое | Использовать |
|---|---|---|
| `geosite_v2fly.dat:telegram` | 21 домен: t.me, telegram.org, telesco.pe, cdn-telegram.org, telegra.ph… | да, домены |
| `geoip_v2fly.dat:telegram` | 12 сетей: 91.105.192.0/23, 91.108.4.0/22, 91.108.8.0/21, 91.108.16.0/21, 91.108.56.0/22, 95.161.64.0/20, 149.154.160.0/20, 185.76.151.0/24 и 4 IPv6 | да, IP |
| `zkeenip.dat:telegram` | то же плюс 5.28.192.0/18, 109.239.140.0/24, **194.221.0.0/16** | нет: слишком широко, как `zkeenip:discord` |

TCP-порты MTProto: 443, 80, 5222. В аудите роутера донорские порты XKeen уже
включают `80,443,596:599,1400,5222`.

## Предлагаемая схема (всё на роутере)

| Режим | Xray | nfqws2 |
|---|---|---|
| VPN | доменное правило и IP-правило (TCP и UDP) в proxy outbound | нет |
| Direct | те же правила в новый freedom outbound `telegram-direct` | профиль выключен |
| Zapret | как Direct | TLS-профиль для web/CDN по hostlist; MTProto-профиль `--filter-tcp=80,443,5222 --ipset=telegram.ipset --filter-l7=mtproto --payload=mtproto_initial` с fake/split |
| WS-proxy (опционально) | IP-правило TCP в freedom `telegram-wsproxy` с `"redirect":"127.0.0.1:1443"`, UDP — в VPN | — |

**Прозрачный WS-proxy без настройки клиентов возможен только с доработкой.**
Когда клиент подключается к DC напрямую, его obfuscated2-init зашифрован
ключом из самого пакета, без секрета (на этом основан `IsMTProto` в zapret2),
а tg-ws-proxy уже строит такую форму на стороне relay. Нужна правка примерно
в 15 строк: флаг `--transparent`, ключ `prekey` вместо `sha256(prekey+secret)`,
прослушивание только 127.0.0.1. DC берётся из init, поэтому перенаправление
по IP ничего не теряет. Для Mihomo аналога freedom `redirect` нет — режим был
бы только для Xray.

**Звонки (UDP):** в Direct/Zapret, вероятно, не работают (известной
стратегии нет); в VPN работают, если VLESS несёт UDP; WS-proxy на звонки не
влияет, поэтому их UDP в этом режиме уходит в VPN.

## Риски

- Zapret для MTProto не подтверждён: возможна блокировка по IP и поведению,
  которую desync не исправит. Автоподбор по HTTP проверить MTProto не может —
  нужна ручная проверка приложением, как у Voice.
- WS-proxy зависит от доступности `kws*.web.telegram.org` и 149.154.167.220;
  для DC1/3/5 — от сторонних Cloudflare-доменов или собственного Worker;
  форк придётся поддерживать.
- Нагрузка Python-прокси на MIPS-роутер (около 345 МБ RAM) не измерена;
  Go-версия легче.
- IPv6-адреса DC не обрабатываются, пока IPv6 в nfqws2 выключен.

## План реализации

1. Данные: `config/telegram-user.list` и `config/telegram.ipset` из
   `geosite_v2fly`/`geoip_v2fly` с тестом на совпадение с `.dat`.
2. Движок: `--telegram-route direct|zapret|vless` (позже `wsproxy`), запись в
   строку `# Active routes`, `telegram_route=` в `--status`,
   `set-service-route.sh telegram …`, снимки новых файлов.
3. Xray: управляемые правила Telegram (домены, IP TCP 80/443/5222, IP UDP),
   очистка Telegram-селекторов из чужих proxy-правил, outbound
   `04_telegram_nfqws2_outbound.json`.
4. Mihomo: `DOMAIN-SUFFIX` и `IP-CIDR … ,DIRECT`; wsproxy в preflight
   запрещён.
5. nfqws2: TLS- и MTProto-профили в `NFQWS_ARGS_CUSTOM`, ipset и hostlist.
6. Панель: карточка Telegram, диагностика (HTTPS к t.me и web.telegram.org,
   TCP-connect к DC), ручное подтверждение приложением.
7. Опционально WS-proxy: форк tg-ws-proxy с `--transparent`, init-скрипт,
   выбор `--no-cfproxy` или своего Worker.
8. Тесты: матрица маршрутов и откат под busybox.

## Что не проверено

Версии пакетов Entware (bin.entware.net был недоступен), актуальный
`core.telegram.org/resources/cidr.txt` (сверено с копией Loyalsoldier),
лицензия и сборки tg-ws-proxy-go, что все клиенты (Android, iOS) используют
obfuscated2 при прямом подключении, текущая механика блокировок и порты
звонков, нагрузка на роутер.

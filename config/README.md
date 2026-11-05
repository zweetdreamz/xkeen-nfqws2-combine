# Конфигурационные материалы

Этот каталог содержит исходные данные генератора и справочные примеры.

- `discord-user.list` — hostlist Discord для nfqws2.
- `youtube-user.list` — узкий hostlist YouTube. В него намеренно не включён
  весь Google.
- `discord-xray-*.json` — примеры структуры Xray, не готовый полный конфиг.
- `xkeen-port-proxying-discord.lst` — набор требуемых портов.
- `blobs/ACTIVE_DISCORD_UDP.bin` — закреплённый fake для Discord Voice/STUN.

Скрипт проверяет Discord blob перед применением:

```text
SHA-256 2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf
```

YouTube переиспользует blobs установленного nfqws2:

```text
tls_clienthello.bin
quic_initial.bin
```

Их хеши также проверяются генератором. При копировании проекта на роутер
обязательно сохраняйте `config/blobs`: профиль `--udp-strategy flowseal` без
проверенного файла не пройдёт preflight.

Native-движок читает `config/*-user.list` при применении и формирует из них
рабочие hostlists в `/opt/etc/nfqws2/lists/`. Правки только в рабочих списках
могут быть перезаписаны следующим `apply`. Тесты также сверяют исходные списки
с эталонными fixtures.


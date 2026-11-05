# Сторонние компоненты

MIT в [LICENSE](LICENSE) распространяется на собственный код проекта.
Она не заменяет лицензии сторонних программ, данных и импортированных материалов.
XKeen, Xray и nfqws2 устанавливаются отдельно и сохраняют собственные условия.

## Telegram WebSocket relay

Части `tools/router/telegram_ws_relay.py` адаптированы из
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
Уведомление исходного проекта:

```text
MIT License

Copyright (c) 2026 Flowseal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Стратегии, списки и payload

Источники стратегий и данных:
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
и [bol-van/zapret2](https://github.com/bol-van/zapret2).
Это относится в том числе к `config/blobs/ACTIVE_DISCORD_UDP.bin` и
производным тестовым данным в `tests/fixtures/flowseal`.
Лицензия проекта не предоставляет дополнительных прав на эти материалы;
при распространении учитывайте условия их источников.

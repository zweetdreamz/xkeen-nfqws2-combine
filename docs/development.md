# Разработка и поставка

## Локальные проверки

Тесты выполняются на компьютере/в контейнерной копии, не на роутере.
GitHub Actions не требуется. Основной Python3.13, дополнительный3.12.

После изменения `tests/docker/Dockerfile` или `kdn-test-entry.sh` пересоберите
образ: существующий тег `kdn-tests:local` автоматически не обновляется.

```sh
sh tests/docker/run-tests.sh --build --only lint
```

```sh
KDN_ENFORCE_COVERAGE=1 sh tests/docker/run-tests.sh --offline --shell all
sh tests/docker/run-tests.sh --offline --only lint
KDN_ENFORCE_COVERAGE=1 sh tests/docker/run-tests.sh --offline --python 3.12 --only pytest
```

Полный прогон проверяет shell-наборы в dash и BusyBox, Python и браузер —
по одному разу. `--serial` запускает оболочки последовательно; Python и
браузер также не дублируются. Во всех Docker-режимах pytest действует общий
runner: по умолчанию4 worker с изоляцией по файлам, branch coverage и,
при `KDN_ENFORCE_COVERAGE=1`, строгие пороги. Для последовательной диагностики
Python укажите `KDN_PYTEST_WORKERS=0`.

Для отдельного файла передайте его путь после `--`; весь каталог `tests`
при этом не добавляется. Быстрый запуск без общего coverage gate:

```sh
sh tests/docker/run-tests.sh --offline --only pytest --no-coverage -- tests/test_tls_translation_v2.py
```

Offline требует заранее подготовленного Docker-образа и blobs.
После удаления кэшей зависимости потребуется подготовить заново.
Состав/параметры запуска: tests/docker/run-tests.sh --help.

Отчёт тестов не заменяет проверку живой сети.

### Результаты проверок

Длительность зависит от нагрузки Docker, числа worker и подготовки образа.
Результаты не кэшируются. Сохраняйте strict coverage; --no-coverage используйте
для фокусного запуска. Нативные тесты Xray с --network none проверяют локальную
связку, но не доступность провайдера, RCI или качество UDP/QUIC.

## Поставка

Allowlist: tools/dev/deploy-manifest.txt.
Сначала dry-run/проверка целевой версии и подходящая резервная копия.
Фактическое применение и рестарты — отдельное разрешённое действие.
Пошаговая установка/rollback панели: [tools/router](../tools/router/README.md#выкатка-и-откат-версии-панели).

Не переносите .cache, секреты, raw captures или архивы устаревших инструментов.
Корневые shell-лаунчеры, init и runner нужны рабочей поставке.

## Секреты

Не публикуйте .pwd, .env*, ключи, private-router, локальные backups/dat
или pcap/pcapng/har. .gitignore не удаляет уже отслеживаемые секреты
и не очищает историю Git. Фильтры имён не распознают пароль внутри
произвольно названного config/sample.json: просматривайте diff и пакет.

deploy.sh проверяет приватные пути независимо от allowlist до upload/SSH.
Checkpoint исключает известные приватные пути: private-router со всем содержимым,
.cache/.git, backups/dat, Windows reports,
ключи, dotenv, captures и архивы; это копия исходников, не состояния роутера.
Фильтры имён checkpoint не гарантируют отсутствие секретов в произвольных файлах:
проверяйте содержимое перед сохранением и передачей архива.

```sh
sh tools/dev/checkpoint.sh save before-change
```

## Работа с исходниками

Исходники, тесты и документация находятся в корне проекта.
Поставка на роутер выполняется отдельной командой после проверки пакета.

## Скриншоты для README

```sh
node tools/dev/capture-ui-screenshots.cjs
```

Нужны Playwright и Chromium. Для установленного браузера задайте путь
в `KDN_SCREENSHOT_BROWSER`. Результат — `docs/images/*.png`.
Скрипт рендерит публичный HTML-шаблон офлайн с демонстрационными данными:
роутер, пользовательский профиль браузера и конфиги не читает, запросы блокирует.
Перед публикацией просмотрите изображения. Результаты проверок на них вымышлены.

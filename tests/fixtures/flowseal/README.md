# Flowseal corpus — P9.1

Источник: Flowseal/zapret-discord-youtube, immutable commit
176f56dc3f11ce5915c26abcdde903f93d835b64. Дата получения03.11.2026 по Москве.
Файлы проверены по Git blob SHA до декодирования, SHA256 raw bytes записаны отдельно.

phase9-176f56dc3f11.json содержит только извлечённые options/profiles и старые
результаты перевода:22 general*.bat,195 profiles,63 TLS-role profiles,
85 baseline candidates. BAT не запускались и не поставляются на роутер.
Это profile-level translations: YouTube TLS-only, до присоединения QUIC и sweep.
Их IDs не следует считать полным набором итоговых search/import candidate IDs.
Полные raw тексты находятся в ignored .cache/refactor/sdd/phase-9/.

Реальные gap vectors:20 TLS profiles с ip-id=zero,4 с hostfakesplit altorder,
11 с несколькими fake-TLS. Числа относятся к TCP/TLS roles нашего tuner,
а не ко всем произвольным профилям файла.

Это baseline ДО исправления P9.2. Не перегенерировать его ради зелёного теста:
изменившиеся args/family/IDs должны получить явный reviewed change-set.
Исходные source URLs и attribution сохранены в каждой записи.

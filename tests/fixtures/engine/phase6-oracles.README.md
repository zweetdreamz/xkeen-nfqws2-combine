# Shell-эталоны до удаления legacy из поставки

Это тестовые данные, не часть deploy-manifest. В production лаунчеры требуют
Python/kdn. Исторические сценарии доступны только при явном изолированном
KD_TEST_ROOT + KD_ALLOW_TEST_ROOT=1 + KDN_ENGINE=legacy.
Они сохраняют старые проверки full apply/Mihomo/standalone как regression oracle;
это не поддержка этих runtime-режимов в новом native apply.

Зафиксированы перед заменой корневых файлов, checkpoint
20261102T162153Z-phase6-before-shell-split.tar.gz:

- legacy-apply-phase6.sh.txt: db53d7244fd9d4ee9cd14473eabcc61871f5acc906686ca7644deecb40b540e0
- legacy-set-service-phase6.sh.txt: aae5f42a43c3965295373ac67c152d823903eeb4b97cf5f60dfbf20d260570b1
- legacy-set-mode-phase6.sh.txt: de791449d5abbdc7978ffb2140cf7b95f3a3c40543b9a508f46383af28d2f14e

Лаунчеры source этих файлов только в disposable tests: $0, argv и project paths
сохраняются. Python test extractors читают тот же эталон. Safety bridge в старом
коде по-прежнему использует текущие общие policy/strict validation: это не
независимая реализация безопасности. Чистые transforms проверяются отдельно.

"""Refusal texts of the panel's operations: what the coordinator answers when the router is busy.

One preset per kind of operation, with the wording the panel has always used for it. ``project=None`` means the
operation does not ask the project lock: xkeen start/stop never took it (a stale lock must not stop a restart of
XKeen), and the metadata operations and the diagnostics start do not touch the router through the engine.
"""

import dataclasses

from kdn.jobs import coordinator


ROUTE_CHANGE = coordinator.Refusals(
    route="переключение маршрута уже выполняется",
    tuner="маршруты нельзя менять во время подбора",
    diagnostic="маршруты нельзя менять во время диагностики",
)
TUNER_START = coordinator.Refusals(
    route="сначала завершите переключение маршрута",
    tuner="подбор уже выполняется",
    diagnostic="сначала завершите диагностику",
)
DIAGNOSTIC_START = coordinator.Refusals(
    route="сначала завершите переключение маршрута",
    tuner="сначала завершите автоподбор",
    diagnostic="диагностика уже выполняется",
    project=None,
)
TUNER_APPLY = coordinator.Refusals(
    route="сначала завершите переключение маршрута",
    tuner="сначала завершите подбор",
    diagnostic="сначала завершите диагностику",
)
XKEEN_ACTION = coordinator.Refusals(
    route="XKeen нельзя менять во время переключения маршрута",
    tuner="XKeen нельзя менять во время подбора",
    diagnostic="XKeen нельзя менять во время диагностики",
    project=None,
)
PROFILE_APPLY = coordinator.Refusals(
    route="профиль нельзя применять во время переключения маршрута",
    tuner="профиль нельзя применять во время подбора",
    diagnostic="профиль нельзя применять во время диагностики",
)
VERSION_APPLY = coordinator.Refusals(
    route="версию нельзя применять во время переключения маршрута",
    tuner="версию нельзя применять во время подбора",
    diagnostic="версию нельзя применять во время диагностики",
)
PROFILE_CLEAR = coordinator.Refusals(
    route="профиль нельзя удалять во время переключения маршрута",
    tuner="профиль нельзя удалять во время подбора",
    diagnostic="профиль нельзя удалять во время диагностики",
)
IMPORT_ROLLBACK = coordinator.Refusals(
    route="откат нельзя выполнять во время переключения маршрута",
    tuner="откат нельзя выполнять во время подбора",
    diagnostic="откат нельзя выполнять во время диагностики",
)
HISTORY_DELETE = coordinator.Refusals(
    route="нельзя удалять историю во время выполняющегося задания",
    tuner="нельзя удалять историю во время выполняющегося задания",
    diagnostic="нельзя удалять историю во время выполняющегося задания",
    project=None,
)
VERSION_DELETE = coordinator.Refusals(
    route="нельзя удалять версии во время выполняющегося задания",
    tuner="нельзя удалять версии во время выполняющегося задания",
    diagnostic="нельзя удалять версии во время выполняющегося задания",
    project=None,
)
VPN_STORE = dataclasses.replace(ROUTE_CHANGE, project=None)

AUTOMATION_BUSY = "идёт проверка по расписанию; дождитесь завершения или остановите её"
INSPECTION_BUSY = 'идёт проверка маршрута/VPN; дождитесь её завершения'
AUTOMATION_START = coordinator.Refusals(route="", tuner="", diagnostic="")

"""Read-only page/assets/reference endpoints assembled by api.table."""
import html as html_module
import json
from pathlib import Path
import stat

from kdn.common import xkeen
from kdn.web.api import router
from kdn.web.infra import config as cfg
from kdn.web.infra import engine
from kdn.web.infra import readcache
from kdn.web.infra import toolmods
from kdn.web.domain import flowseal
from kdn.web.domain import health
from kdn.web.domain import metrics
from kdn.web.domain import history
from kdn.web.domain import profiles
from kdn.web.domain import tuner_jobs
from kdn.web.domain import vpn


def _load_asset(name):
    try:
        return (Path(__file__).parent.parent / "assets" / name).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"asset missing: {name}") from exc


HTML = _load_asset("index.html")


def initial_service_configs_html():
    """Same standalone service section as the current entry, with escaped data."""
    try:
        services = profiles.current_service_configs()["services"]
        error = ""
    except (OSError, ValueError, RuntimeError) as exc:
        services = {}
        error = f"Не удалось прочитать конфигурацию: {exc}"
    cards = []
    names = {"discord-tcp": "Discord TCP", "discord-voice": "Discord Voice", "youtube": "YouTube", "telegram": "Telegram"}
    for service, name in names.items():
        entry = services.get(service)
        body = []
        if entry:
            body.append('<div class="service-config-label">Маршрут: ' + html_module.escape(entry["route"].upper()) + "</div>")
            if entry["profiles"]:
                for profile in entry["profiles"]:
                    body.append('<div class="service-config-label">' + html_module.escape(profile["label"]) + "</div>")
                    body.append("<pre>" + html_module.escape("\n".join(profile["args"])) + "</pre>")
            else:
                body.append('<div class="hint">' + html_module.escape(entry["note"]) + "</div>")
        else:
            body.append('<div class="hint">' + html_module.escape(error) + "</div>")
        cards.append('<details class="service-config"' + (' open' if service == "discord-tcp" else '') +
                     '><summary>' + html_module.escape(name) + '</summary><div class="service-config-body">' +
                     "".join(body) + '</div></details>')
    section = ('<section class="card" id="service-configs">'
               '<div class="profile-head"><div><h2>Конфигурации сервисов</h2>'
               '<div class="hint">Параметры прочитаны с роутера при открытии страницы. '
               'После смены маршрута обновите страницу.</div></div>'
               '<a class="download" href="/#service-configs">Обновить страницу</a></div>'
               '<div class="service-config-grid">' + "".join(cards) + '</div></section>')
    return HTML.replace("__SERVICE_CONFIG_SECTION__", section, 1)


def download_response(path, filename, content_type):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > cfg.MAX_REPORT_BYTES:
            raise ValueError("небезопасный файл")
        body = path.read_text(encoding="utf-8-sig").encode("utf-8-sig")
    except (OSError, ValueError) as exc:
        return router.error_response(404, str(exc))
    return router.Response(200, body, content_type, {"Content-Disposition": f'attachment; filename="{filename}"'})


def get_page(request):
    return router.text_response(200, initial_service_configs_html(), "text/html; charset=utf-8")


def get_cache_helper(request):
    return download_response(cfg.DISCORD_CACHE_HELPER, "reset-discord-cache.ps1", "text/plain; charset=utf-8")


def get_browser_script(request):
    return router.text_response(200, cfg.BROWSER_DIAGNOSTICS.read_text(encoding="utf-8"), "application/javascript; charset=utf-8")


def get_inspection_script(request):
    return router.text_response(200, _load_asset('inspection.js'), 'application/javascript; charset=utf-8')


def get_vpn_generator_script(request):
    return router.text_response(200, _load_asset('xkeen-ui-generator.js'), 'application/javascript; charset=utf-8')


def get_diagnostic_targets(request):
    module = toolmods.diagnostics_module()
    return router.json_response(200, {"ok": True,
        "standard": [{"name": name, "url": url} for name, url in module.STANDARD_TARGETS if url.startswith("https://")],
        "dpi": [{"name": provider + " · " + identifier, "url": "https://" + host}
                for identifier, provider, host in module.DPI_TARGETS]})


def get_status(request):
    if not cfg.ENGINE.is_file():
        return router.error_response(500, f"project script not found: {cfg.ENGINE}")
    # Refuse unsupported targets before even enumerating configuration metadata.
    # Cache is only an advisory view; the actual version is never cached.
    try:
        with engine.status_read_scope():
            payload = readcache.read('status', [cfg.ENGINE, Path(cfg.XKEEN), cfg.XKEEN_INIT, cfg.XRAY_CONFIG_DIR,
                cfg.NFQWS_CONFIG, cfg.ROUTE_STATE, cfg.TUNER_STATE, cfg.AUTOMATION_STATE],
                engine.read_status_fields)
    except xkeen.UnsupportedXKeen:
        readcache.invalidate()
        raise
    return router.json_response(409 if payload.get('error_code') == 'unsupported_xkeen' else 200 if payload["ok"] else 500, payload)


def get_service_configs(request):
    return router.json_response(200, profiles.current_service_configs())


def get_fast_status(request):
    """Advisory display only: no engine/version commands or apply validation."""
    running = False
    known = True
    try:
        processes = list(Path('/proc').glob('[0-9]*'))
        if not processes:
            known = False
        for process in processes:
            try:
                if (process / 'comm').read_text().strip() == 'xray':
                    running = True
                    break
            except (OSError, UnicodeError):
                continue
    except OSError:
        known = False
    routes = engine.current_routes_fast()
    payload = {'ok': True, 'advisory': True,
               'xkeen_runtime': ('running' if running else 'stopped') if known else 'unknown'}
    payload.update({key: routes.get(service, 'unknown')
                    for service, key in engine.STATUS_ROUTE_KEYS.items()})
    return router.json_response(200, payload)


def get_vpn_nodes(request):
    return router.json_response(200, vpn.nodes_status())


def get_imported(request):
    return router.json_response(200, {"ok": True, "profiles": profiles.imported_profiles(),
                                    "rollback_available": cfg.IMPORT_ROLLBACK_POINTER.is_file()})


def get_tuner_sources(request):
    return router.json_response(200, readcache.read('sources', [cfg.FLOWSEAL_SOURCE_CACHE],
        flowseal.tuner_sources, ttl=10))


def get_voice_endpoint(request):
    return router.json_response(200, {"ok": True, "endpoint": tuner_jobs.learned_voice_endpoint()})


def get_history(request):
    return router.json_response(200, {"ok": True, "items": history.route_history()})


def get_profile_versions(request):
    paths = [cfg.PROFILE_VERSION_DIR, cfg.IMPORTED_PROFILE_DIR,
             *(cfg.PROFILE_VERSION_DIR / service for service in cfg.SERVICES)]
    return router.json_response(200, readcache.read('versions', paths,
        lambda: {"ok": True, "versions": profiles.profile_versions()}))


def get_updates(request):
    return router.json_response(200, flowseal.cached_flowseal_update())


def get_config_checks(request):
    return router.json_response(200, health.config_health())


def get_vpn_ping_activity(request):
    return router.json_response(200, {'ok':True,'active':vpn.VPN_PING_BUSY.is_set()})


def get_metrics(request):
    return router.json_response(200, metrics.snapshot())


READ_ROUTES = tuple(router.Route("GET", path, handler, errors=exceptions, heavy=heavy) for path, handler, exceptions, heavy in (
    ("/api/metrics", get_metrics, (), False),
    ("/", get_page, (), False),
    ("/tools/reset-discord-cache.ps1", get_cache_helper, (), False),
    ("/assets/browser-diagnostics.js", get_browser_script, (), False),
    ("/assets/inspection.js", get_inspection_script, (), False),
    ("/assets/xkeen-ui-generator.js", get_vpn_generator_script, (), False),
    ("/api/diagnostics/targets", get_diagnostic_targets, (), False),
    ("/api/status", get_status, (), True),
    ("/api/status/fast", get_fast_status, (), False),
    ("/api/service-configs", get_service_configs, ((OSError, 500), (ValueError, 500), (RuntimeError, 500)), False),
    ("/api/vpn-nodes", get_vpn_nodes,
     ((OSError, 500), (RuntimeError, 500), (ValueError, 500), (TypeError, 500), (json.JSONDecodeError, 500)), False),
    ('/api/vpn-nodes/activity',get_vpn_ping_activity,(),False),
    ("/api/imported", get_imported, (), False),
    ("/api/tuner/sources", get_tuner_sources, (), False),
    ("/api/tuner/voice-endpoint", get_voice_endpoint, (), False),
    ("/api/history", get_history, ((OSError, 500), (ValueError, 500)), False),
    ("/api/profile-versions", get_profile_versions, ((OSError, 500), (ValueError, 500)), False),
    ("/api/updates", get_updates, (), False),
    ("/api/checks/config", get_config_checks, (), True),
))

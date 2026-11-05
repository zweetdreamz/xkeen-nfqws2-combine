"""Flowseal sources of the tuner: the update check against GitHub and the downloaded BAT files."""

import json
import re
import threading
import urllib.request

from kdn.common import fsutil
from kdn.common import timeutil
from kdn.web.infra import config as cfg
from kdn.web.infra import toolmods
from kdn.web.domain import validation


FLOWSEAL_UPDATE_LOCK = threading.Lock()
FLOWSEAL_REPOSITORY = "Flowseal/zapret-discord-youtube"
FLOWSEAL_REF = "main"


def cached_flowseal_update():
    try:
        sources, commit = toolmods.flowseal_source_module().read_source_cache(cfg.FLOWSEAL_SOURCE_CACHE)
        try:
            payload = fsutil.safe_json_file(cfg.FLOWSEAL_UPDATE_STATE)
        except (OSError, ValueError):
            payload = {}
        payload.update(ok=True, repository=FLOWSEAL_REPOSITORY, downloaded_commit=commit, source_count=len(sources))
        if payload.get("status") not in {"downloaded", "up_to_date", "error"}:
            payload["status"] = "downloaded"
        return payload
    except FileNotFoundError:
        return {"ok": True, "status": "never_downloaded"}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"ok": True, "status": "error", "error": str(exc)}


def check_flowseal_update():
    with FLOWSEAL_UPDATE_LOCK:
        try:
            return download_flowseal_update()
        except (OSError, RuntimeError, ValueError) as exc:
            fsutil.atomic_text(cfg.FLOWSEAL_UPDATE_STATE, json.dumps({
                "ok": True, "status": "error", "error": str(exc)[:1000],
                "checked_utc": timeutil.utc_now(),
            }, ensure_ascii=False) + "\n")
            raise


def download_flowseal_update():
    url = f"https://api.github.com/repos/{FLOWSEAL_REPOSITORY}/commits/{FLOWSEAL_REF}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "keenetic-zapret-panel/6.4",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read(1024 * 1024).decode("utf-8"))
    latest = data.get("sha", "") if isinstance(data, dict) else ""
    if not isinstance(latest, str) or not re.fullmatch(r"[0-9a-f]{40}", latest):
        raise RuntimeError("GitHub не вернул корректный commit")
    commit_info = data.get("commit")
    committer = commit_info.get("committer") if isinstance(commit_info, dict) else None
    authored = committer.get("date", "") if isinstance(committer, dict) else ""
    if not isinstance(authored, str):
        authored = ""
    module = toolmods.flowseal_source_module()
    sources, cached_commit = [], ""
    try:
        sources, cached_commit = module.read_source_cache(cfg.FLOWSEAL_SOURCE_CACHE)
    except (OSError, RuntimeError, ValueError):
        pass
    changed = cached_commit != latest
    if changed:
        sources, fetched_commit = module.fetch_sources(FLOWSEAL_REPOSITORY, latest)
        if fetched_commit != latest:
            raise RuntimeError("скачанный commit не совпал с запрошенным")
        # Validate and atomically replace only after every source is downloaded.
        module.save_source_cache(cfg.FLOWSEAL_SOURCE_CACHE, sources, latest)
    payload = {
        "ok": True, "status": "downloaded" if changed else "up_to_date",
        "repository": FLOWSEAL_REPOSITORY, "latest_commit": latest,
        "downloaded_commit": latest, "source_count": len(sources),
        "latest_date": validation.bounded_text(authored, "latest_date", 80),
        "checked_utc": timeutil.utc_now(),
    }
    fsutil.atomic_text(cfg.FLOWSEAL_UPDATE_STATE, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return payload


def tuner_sources():
    """List the downloaded Flowseal BAT files and the services each one covers."""
    try:
        module = toolmods.flowseal_source_module()
        sources, commit = module.read_source_cache(cfg.FLOWSEAL_SOURCE_CACHE)
    except FileNotFoundError:
        return {"ok": True, "status": "never_downloaded", "commit": "", "sources": []}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"ok": True, "status": "error", "error": str(exc), "commit": "", "sources": []}
    return {
        "ok": True,
        "status": "ready",
        "commit": commit,
        "sources": [
            {"name": source.name, "services": module.source_services(source)}
            for source in sorted(sources, key=lambda item: item.name.casefold())
        ],
    }

"""History of route jobs: one JSON record per job.

A deleted record, of the history or of the profile versions, goes to the record trash and is never destroyed.
"""

import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from kdn.common import fsutil
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.infra import engine
from kdn.web.domain import refusals


def history_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{16}", job_id):
        raise ValueError("некорректный ID операции")
    return cfg.ROUTE_HISTORY_DIR / f"{job_id}.json"


def write_history(entry):
    path = history_path(entry.get("job_id"))
    cfg.ROUTE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(cfg.ROUTE_HISTORY_DIR, 0o700)
    fsutil.atomic_text(path, json.dumps(entry, ensure_ascii=False, indent=2) + "\n")


def update_history(job_id, **changes):
    try:
        entry = fsutil.safe_json_file(history_path(job_id))
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return False
    if entry.get("job_id") != job_id:
        return False
    entry.update(changes)
    write_history(entry)
    return True


def route_history():
    items = []
    def modified(path):
        try:
            return path.lstat().st_mtime
        except OSError:
            return 0.0

    try:
        # Newest files first, so the 200-file read limit drops old entries.
        paths = sorted(fsutil.bounded_files(cfg.ROUTE_HISTORY_DIR), key=modified, reverse=True)
    except OSError:
        paths = []
    for path in paths[:200]:
        if not re.fullmatch(r"[0-9a-f]{16}\.json", path.name):
            continue
        try:
            item = fsutil.safe_json_file(path)
            if item.get("job_id") != path.stem:
                raise ValueError("ID файла не совпадает")
            snapshot_value = item.get("snapshot", "")
            snapshot_path = Path(snapshot_value) if isinstance(snapshot_value, str) else Path("")
            item["rollback_available"] = bool(snapshot_value and engine.safe_snapshot(snapshot_path))
            items.append(history_summary(item))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            items.append(
                {
                    "job_id": path.stem,
                    "status": "error",
                    "error": f"история повреждена: {exc}",
                    "rollback_available": False,
                }
            )
    def created(item):
        value = item.get("created_utc")
        return value if isinstance(value, str) else ""

    items.sort(key=created, reverse=True)
    return items[:cfg.MAX_HISTORY_ITEMS]


def history_summary(item):
    """Public list metadata only; full recovery record remains on disk."""
    limits = {'job_id': 16, 'operation': 64, 'service': 32, 'status': 32,
              'created_utc': 64, 'finished_utc': 64, 'outbound_tag': 128,
              'snapshot': 1024, 'error': 512, 'output_tail': 1024}
    result = {}
    for name, maximum in limits.items():
        if name in item:
            value = item[name] if isinstance(item[name], str) else ''
            result[name] = value[-maximum:] if name == 'output_tail' else value[:maximum]
    for name in ('before_routes', 'after_routes', 'requested_routes'):
        if name not in item:
            continue
        value = item[name] if isinstance(item[name], dict) else {}
        result[name] = {key: route if route in ('direct', 'zapret', 'vpn', 'vless', 'ws', 'unmanaged', 'unknown', 'mixed') else 'unknown'
                        for key, route in value.items() if key in
                        ('discord', 'discord-tcp', 'discord-voice', 'youtube', 'telegram')}
    result['rollback_available'] = item.get('rollback_available') is True
    return result


def archive_record(path, kind, service=""):
    """Hide one record without destroying its recovery copy or route snapshot."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("необычный тип файла записи")
    destination = cfg.RECORD_TRASH_DIR / kind / service if service else cfg.RECORD_TRASH_DIR / kind
    for directory in (cfg.RECORD_TRASH_DIR, cfg.RECORD_TRASH_DIR / kind, destination):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory_info = directory.lstat()
        if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
            raise ValueError("небезопасный каталог корзины")
        os.chmod(directory, 0o700)
    archived = destination / f"{int(time.time())}-{secrets.token_hex(4)}-{path.name}"
    os.replace(path, archived)
    return archived


def delete_history_record(job_id):
    with jobfiles.COORDINATOR.exclusive(refusals.HISTORY_DELETE):
        path = history_path(job_id)
        item = fsutil.safe_json_file(path)
        if item.get("job_id") != job_id:
            raise ValueError("ID записи истории не совпадает")
        archive_record(path, "history")
        return {"ok": True, "snapshot_preserved": True}


def read_history_item(job_id):
    item = fsutil.safe_json_file(history_path(job_id))
    if item.get("job_id") != job_id:
        raise ValueError("ID записи истории не совпадает")
    return item

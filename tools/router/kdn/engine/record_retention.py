"""Post-success metadata rotation under the caller's project lock; no services."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time

from kdn.common import retention
from kdn.engine import config, profile_descriptor, snapshot_store

MAX_RECORDS = 4096
MAX_BYTES = 64 * 1024 * 1024
SNAPSHOT = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9]+(?:-[0-9]+)?')
JOB = re.compile(r'[0-9a-f]{16}\.json')
VERSION = re.compile(r'([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{12})-(?:applied|replaced|cleared)-[0-9]+(?:-[0-9]+)?\.json')
TRASH = re.compile(r'([0-9]{10,12})-[0-9a-f]{8}-(.+)')
SERVICES = ('discord-tcp', 'discord-voice', 'youtube')


def _path(paths, logical):
    return snapshot_store._no_links(config.list_path(logical, paths.test_root))


def _multiple(paths, focused):
    folder = Path(paths.state_root) / 'nfqws-import-snapshots' if focused else Path(paths.snapshot_root)
    folder = snapshot_store._no_links(folder)
    if not folder.exists():
        return False
    checked = 0
    with os.scandir(folder) as entries:
        for count, entry in enumerate(entries, 1):
            if count > 16384:
                raise ValueError('snapshot inventory exceeds retention budget')
            if SNAPSHOT.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                snapshot_store.verify(entry.path, focused=focused)
                checked += 1
                if checked >= 2:
                    return True
    return False


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('ambiguous retention record')
        value[key] = item
    return value


def _records(folders):
    total, count = 0, 0
    for folder in folders:
        if not folder.exists():
            continue
        with os.scandir(folder) as entries:
            for entry in entries:
                count += 1
                if count > MAX_RECORDS:
                    raise ValueError('record retention entry budget exceeded')
                if not entry.name.endswith('.json'):
                    continue
                path = snapshot_store._no_links(entry.path)
                if path.lstat().st_nlink != 1:
                    raise ValueError('linked retention record is not owned exclusively')
                raw = snapshot_store._read(path, 512 * 1024)
                total += len(raw)
                if total > MAX_BYTES:
                    raise ValueError('record retention byte budget exceeded')
                data = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
                if not isinstance(data, dict):
                    raise ValueError('retention record must be an object')
                yield path, data, hashlib.sha256(raw).digest()


def _trash_old(match, now):
    import datetime as dt
    try:
        created = dt.datetime.fromtimestamp(int(match[1]), dt.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return False
    return retention.older_than_limit(created, now=now)


def _commit(actions):
    # Recheck the complete batch before any rename/unlink. No record contents
    # are printed or rewritten; a failed move cannot destroy a snapshot.
    for source, digest, destination in actions:
        if hashlib.sha256(snapshot_store._read(source, 512 * 1024)).digest() != digest:
            raise ValueError('retention record changed during preflight')
        if destination is not None:
            snapshot_store._no_links(destination)
            if destination.exists():
                raise ValueError('retention archive collision')
    for source, _digest, destination in actions:
        snapshot_store._no_links(source)
        if destination is None:
            source.unlink()
        else:
            for folder in (destination.parent.parent, destination.parent):
                snapshot_store._no_links(folder)
                folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(folder, 0o700)
            os.replace(source, destination)
            os.chmod(destination, 0o600)


def expire_history(paths, protected=None):
    """Old completed history goes to trash; trash has its own30-day undo window."""
    if not _multiple(paths, False):
        return 0, 0
    protected = set(protected or ())
    folder = Path(paths.snapshot_root)
    for pointer in (paths.baseline_pointer, paths.xkeen_baseline_pointer, paths.latest_pointer):
        pointer = Path(pointer)
        if pointer.exists() or pointer.is_symlink():
            target = Path(snapshot_store._read(pointer, 4096).decode('utf-8').strip())
            target = snapshot_store._no_links(target)
            if target.parent != folder or not SNAPSHOT.fullmatch(target.name):
                raise ValueError('unsafe history retention pointer')
            protected.add(target.name)
    # The newest point remains protected when cleanup is initiated by a focused
    # operation, which has no current full-snapshot argument of its own.
    names = []
    with os.scandir(folder) as entries:
        for count, entry in enumerate(entries, 1):
            if count > 16384:
                raise ValueError('snapshot inventory exceeds retention budget')
            if SNAPSHOT.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
    protected.add(max(names))
    now = time.time()
    live = _path(paths, '/opt/etc/xkeen-web/history')
    trash = _path(paths, '/opt/etc/xkeen-web/record-trash/history')
    actions = []
    moved = removed = 0
    for path, data, digest in _records((live, trash)):
        archived = TRASH.fullmatch(path.name) if path.parent == trash else None
        name = archived[2] if archived else path.name
        if not JOB.fullmatch(name) or data.get('job_id') != name[:-5]:
            continue
        if data.get('status') not in ('completed', 'failed', 'error', 'cancelled', 'interrupted') or data.get('active'):
            continue
        reference = data.get('snapshot', '')
        if not isinstance(reference, str):
            continue
        if reference:
            target = Path(reference)
            if target.parent != Path(paths.snapshot_root) or not SNAPSHOT.fullmatch(target.name):
                continue
            if target.name in protected:
                continue
            if target.exists() or target.is_symlink():
                snapshot_store.verify(target)
        if archived:
            if _trash_old(archived, now):
                actions.append((path, digest, None))
                removed += 1
        elif retention.older_than_limit(data.get('finished_utc') or data.get('created_utc'), now=now):
            destination = trash / f'{int(now)}-{secrets.token_hex(4)}-{path.name}'
            actions.append((path, digest, destination))
            moved += 1
    _commit(actions)
    return moved, removed


def expire_versions(paths):
    """Inactive profile versions/trash expire; active IDs and newest per service stay."""
    if snapshot_store.focused_pending(paths) or not _multiple(paths, True):
        return 0
    now = time.time()
    base = _path(paths, '/opt/etc/nfqws2')
    trash_root = _path(paths, '/opt/etc/xkeen-web/record-trash/versions')
    active = {}
    for service in SERVICES:
        installed = base / 'imported-profiles' / (service + '.json')
        if installed.exists() or installed.is_symlink():
            data = json.loads(snapshot_store._read(installed, 512 * 1024))
            profile = profile_descriptor.validate_descriptor(data, voice_high=65535)
            if profile['service'] != service:
                raise ValueError('installed profile service mismatch')
            active[service] = profile['candidate_id']
    folders = [base / 'profile-versions' / service for service in SERVICES] + [trash_root / service for service in SERVICES]
    for folder in folders:
        snapshot_store._no_links(folder)
    newest = {service: '' for service in SERVICES}
    candidates = []
    for path, data, digest in _records(folders):
        service = path.parent.name
        archived = TRASH.fullmatch(path.name) if path.parent.parent == trash_root else None
        match = VERSION.fullmatch(archived[2] if archived else path.name)
        if not match:
            continue
        profile = profile_descriptor.validate_descriptor(data, voice_high=65535)
        if profile['service'] != service or profile['candidate_id'] != match[2]:
            raise ValueError('profile version metadata mismatch')
        if not archived:
            newest[service] = max(newest[service], path.name)
        if profile['candidate_id'] == active.get(service):
            continue
        created = match[1]
        created = f'{created[:4]}-{created[4:6]}-{created[6:8]}T{created[9:11]}:{created[11:13]}:{created[13:15]}Z'
        if _trash_old(archived, now) if archived else retention.older_than_limit(created, now=now):
            candidates.append((path, digest, None))
    actions = [item for item in candidates if item[0].name != newest[item[0].parent.name]]
    _commit(actions)
    return len(actions)

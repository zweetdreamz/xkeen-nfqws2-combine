"""Atomic writes and size-checked reads of JSON files."""

import json
import os
from pathlib import Path
import stat
import tempfile

from kdn.common import jsonc


MAX_JSON_BYTES = 512 * 1024


def bounded_files(directory, *, suffix='.json', maximum=4096):
    """Bound metadata enumeration before sorting; never follow a directory link."""
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError('unsafe metadata directory')
    result = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, 1):
            if count > maximum:
                raise ValueError('metadata directory exceeds safe entry budget')
            if entry.name.endswith(suffix):
                result.append(Path(entry.path))
    return result


def atomic_json(path, payload, *, maximum=None, parent_mode=None,
                too_large='JSON state exceeds size limit'):
    """Shared state publication; callers retain their directory/size policy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if parent_mode is not None:
        os.chmod(path.parent, parent_mode)
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if maximum is not None and len(encoded) > maximum:
        raise RuntimeError(too_large)
    atomic_bytes(path, encoded)


def atomic_bytes(path, data, mode=0o600):
    """Binary counterpart of atomic_text; byte-preserving config publication."""
    if not isinstance(data, bytes):
        raise TypeError('atomic_bytes requires bytes')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        try:
            stream = os.fdopen(descriptor, 'wb')
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_text(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        try:
            stream = os.fdopen(descriptor, "w", encoding="utf-8")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def safe_json_file(path, maximum=MAX_JSON_BYTES, comments=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"необычный тип файла: {path}")
    if not 0 < info.st_size <= maximum:
        raise ValueError(f"некорректный размер файла: {path}")
    text = path.read_text(encoding="utf-8")
    data = json.loads(jsonc.strip_json_comments(text) if comments else text)
    if not isinstance(data, dict):
        raise ValueError(f"ожидается JSON-объект: {path}")
    return data


def fsync_path(path):
    """Persist a file's metadata or directory entries; propagate durability errors."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

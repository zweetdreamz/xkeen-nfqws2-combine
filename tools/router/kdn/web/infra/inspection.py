"""One bounded read-only worker, private state and a coordinator hold."""
import json
import sys
import threading
import time

from kdn.common import fsutil
from kdn.inspection import transport
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles


RUN_LOCK = threading.Lock()
STATE_LOCK = threading.RLock()
jobfiles.COORDINATOR.add_hold('inspection', RUN_LOCK.locked, 'идёт проверка маршрута/VPN; дождитесь её завершения')


def read_inspection_state(path, default):
    try:
        return fsutil.safe_json_file(path, maximum=128 * 1024)
    except FileNotFoundError:
        return default


def write_inspection_state(path, value):
    # Check the full parent chain before publishing private state.
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('небезопасный путь состояния проверки')
    fsutil.atomic_json(path, value, maximum=128 * 1024)
    fsutil.fsync_path(path.parent)


def run_inspection_worker(kind, payload):
    try:
        raw = transport.run([sys.executable, '-P', str(cfg.ROUTE_CHECKER), kind],
                            data=json.dumps(payload, allow_nan=False).encode(), timeout=175, limit=65536,
                            termination_grace=2)
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get('kind') != kind or not result.get('ok'):
            raise ValueError('invalid checker result')
        return result
    except (transport.Failure, ValueError):
        return {'ok': True, 'kind': kind, 'status': 'unavailable', 'checked_at': int(time.time()),
                'detail': 'Worker проверки не подтвердил результат; службы не менялись'}

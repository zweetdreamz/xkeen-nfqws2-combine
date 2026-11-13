"""Read-only Linux resource counters; no processes, threads or writes."""
from pathlib import Path
import threading
import time

_lock = threading.Lock()
_previous = None
_cached = None
_sampled_at = 0.0


def snapshot():
    global _previous, _cached, _sampled_at
    with _lock:
        now = time.monotonic()
        if _cached is not None and now - _sampled_at < 1:
            return dict(_cached)
        cpu = None
        memory = None
        try:
            values = [int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
            total, idle = sum(values), values[3] + values[4]
            if _previous is not None:
                delta = total - _previous[0]
                if delta > 0 and 0 <= idle - _previous[1] <= delta:
                    cpu = round(100 * (1 - (idle - _previous[1]) / delta), 1)
            _previous = total, idle
        except (OSError, ValueError, IndexError):
            _previous = None
        try:
            fields = {}
            for line in Path('/proc/meminfo').read_text().splitlines():
                key, value = line.split(':', 1)
                fields[key] = int(value.split()[0])
            total = fields['MemTotal']
            available = fields.get('MemAvailable')
            if available is None:
                available = (fields['MemFree'] + fields.get('Buffers', 0)
                             + fields.get('Cached', 0) + fields.get('SReclaimable', 0)
                             - fields.get('Shmem', 0))
            if total > 0:
                used = total - min(total, max(0, available))
                memory = {'used_mib': round(used / 1024), 'total_mib': round(total / 1024),
                          'percent': round(100 * used / total, 1)}
        except (OSError, ValueError, IndexError, KeyError):
            pass
        _cached = {'ok': True, 'cpu_percent': cpu, 'memory': memory}
        _sampled_at = now
        return dict(_cached)

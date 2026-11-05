"""Conservative age/count policy; no filesystem, deletion or env bypass."""
import math
import time

MIN_KEEP = 1
MAX_AGE_DAYS = 30
MIN_CLOCK_EPOCH = 1577836800  # 2020-01-01: reject typical unsynchronised boot clocks.


def keep_count(value, *, maximum=16384):
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        return MIN_KEEP
    significant = value.lstrip('0')
    return maximum if len(significant) > 6 else min(maximum, max(MIN_KEEP, int(significant or '0')))


def older_than_limit(created_utc, *, now=None):
    """Strictly older than30d; malformed/naive/future/boot-clock dates stay."""
    import datetime as dt
    if not isinstance(created_utc, str) or not 1 <= len(created_utc) <= 64:
        return False
    try:
        stamp = dt.datetime.fromisoformat(created_utc.replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset() != dt.timedelta(0):
            return False
        epoch = stamp.timestamp()
        current = time.time() if now is None else now
        if not math.isfinite(current) or min(epoch, current) < MIN_CLOCK_EPOCH:
            return False
        return current - epoch > MAX_AGE_DAYS * 86400
    except (TypeError, ValueError, OverflowError):
        return False

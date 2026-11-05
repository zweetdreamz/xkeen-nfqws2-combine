"""UTC timestamps in the format of the state files."""

import time


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_now_iso():
    """Precise +00:00 form used by detached diagnostic/tuner job state."""
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).isoformat()

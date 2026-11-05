"""Bounded Linux proc identity of the configured Xray daemon."""
from pathlib import Path

def _identity_fields(path):
    """Read a complete, bounded NUL-delimited proc file; never expose its contents."""
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if not raw or len(raw) > 65536 or not raw.endswith(b'\0'):
        raise ValueError('incomplete process identity')
    return raw[:-1].decode('utf-8', 'strict').split('\0')


def xray_identity(pid, confdir, *, executable='xray', proc_root=None):
    """Match an Xray run daemon, using explicit confdir before bounded proc env.

    Validation/dump/help commands and ambiguous identities never qualify. The
    caller supplies candidate PIDs; no process is signalled or environment logged.
    """
    token = str(pid)
    if (not token.isascii() or not token.isdecimal() or len(token) > 10
            or not 1 < int(token) <= 2147483647 or str(int(token)) != token):
        return False
    root = Path('/proc') if proc_root is None else Path(proc_root)
    folder = root / token
    try:
        args = _identity_fields(folder / 'cmdline')
        if (len(args) < 2 or not all(args) or Path(args[0]).name != Path(executable).name
                or args[1] != 'run'):
            return False
        excluded = {'-test', '--test', '-dump', '--dump', '-version', '--version',
                    '-help', '--help', '-h', '-c', '--c', '-config', '--config'}
        if any(arg.split('=', 1)[0] in excluded for arg in args[2:]):
            return False
        values = []
        for index, arg in enumerate(args[2:], 2):
            flag, equal, value = arg.partition('=')
            if flag in ('-confdir', '--confdir'):
                if not equal:
                    value = args[index + 1] if index + 1 < len(args) else ''
                if not value or value.startswith('-'):
                    return False
                values.append(value)
        if values:
            return len(values) == 1 and values[0] == str(confdir)
        values = [field.partition('=')[2] for field in _identity_fields(folder / 'environ')
                  if field.partition('=')[0] == 'XRAY_LOCATION_CONFDIR']
        return len(values) == 1 and values[0] == str(confdir)
    except (OSError, UnicodeError, ValueError):
        return False

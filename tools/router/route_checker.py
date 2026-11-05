#!/usr/bin/env python3
"""Private bounded stdin/stdout worker. Never launches tuning or node mutation."""
import json
import os
from pathlib import Path
import sys
import signal

# Scripts run with -P on the router: add our own trusted package directory.
sys.path.insert(0, str(Path(__file__).absolute().parent))

from kdn.engine import cli, config, console, options
from kdn.inspection import transport, worker


def _install_signal_handlers():
    # TERM is owned by the launcher. Preserve inherited nohup/background
    # dispositions for HUP/INT, while always allowing bounded TERM cleanup.
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        if signum == signal.SIGTERM or signal.getsignal(signum) != signal.SIG_IGN:
            signal.signal(signum, transport.request_stop)


def main():
    _install_signal_handlers()
    if len(sys.argv) != 2 or sys.argv[1] not in ('route', 'resources', 'vpn'):
        return 2
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            return 2
        payload = json.loads(raw)
        parsed = options.parse_args(['--status'])
        ctx = cli.Context([], os.environ, console.Console(sys.stderr, sys.stderr),
                          paths=config.EnginePaths.from_environ(os.environ), options=parsed,
                          resolved=options.resolve(parsed, ''))
        result = worker.run(ctx, sys.argv[1], payload)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({'ok': False, 'error': 'Некорректный запрос/окружение проверки'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

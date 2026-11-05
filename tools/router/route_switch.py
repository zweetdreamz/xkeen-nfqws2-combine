#!/usr/bin/env python3
"""Process entry for native route wrappers; lifecycle matches kdn.engine."""
import os
import sys

from kdn.engine import cli, config, confvalues, console, lifecycle, options, route_switch


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    output = console.Console.process()
    if not argv or argv[0] not in ('service', 'preset'):
        output.err('Usage: route_switch.py service SERVICE MODE [apply options] | preset PRESET [apply options]')
        return 2
    family, args = argv[0], argv[1:]
    if args and args[0] in ('-h', '--help', 'help'):
        output.out('Routes: discord-tcp, discord-voice, discord, youtube, telegram. Modes: direct/zapret/vpn; Telegram: direct/vpn/ws/unmanaged. XKeen2.1+ with Xray only.')
        return 0
    skip = 2 if family == 'service' else 1
    if len(args) < skip:
        output.err('ERROR: missing service/route or preset')
        return 2
    try:
        parsed = options.parse_args(['--apply', *args[skip:]])
        if parsed.mode != 'apply':
            raise options.ArgError('ERROR: switch accepts apply options only')
        paths = config.EnginePaths.from_environ(os.environ)
        ctx = cli.Context([], os.environ, output, paths=paths, options=parsed,
                          resolved=options.resolve(parsed, confvalues.read_text(paths.nfqws_conf)))
    except (options.ArgError, RuntimeError) as error:
        output.err(str(error))
        return 2
    return route_switch.run(ctx, family, args)


if __name__ == '__main__':
    lifecycle.install_signal_handlers()
    try:
        result = main()
    finally:
        lifecycle.run_cleanups()
    raise SystemExit(result)

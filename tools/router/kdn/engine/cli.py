"""Entry of the engine: the context of a run, the table of Python modes, and the choice between Python and sh."""

import os
import sys

from kdn.common import xkeen
from kdn.engine import checks, config, confvalues, console, legacy, options, plan, preflight, profiles, snapshots, status


# The options of apply-discord-nfqws2.sh that take the next argument as their value.
VALUE_OPTIONS = (
    "--apply-import-profile", "--clear-imported-profile", "--rollback-snapshot", "--udp-strategy", "--discord-route",
    "--discord-tcp-route", "--discord-voice-route", "--youtube-route", "--telegram-route", "--proxy-outbound",
    "--core", "--direct-mark", "--wan-interface", "--focused-operation-context", "--recover-import-source",
)  # fmt: skip
MODES = {
    "status": status,
    "check-config": checks,
    "print-nfqws-profiles": profiles,
    "show-snapshots": snapshots,
    "preflight": preflight,
    "print-plan": plan,
}
MUTATION_MODES = frozenset(('apply', 'snapshot-baseline', 'rollback-baseline', 'rollback-latest',
                           'rollback-snapshot', 'apply-import-profile', 'clear-imported-profile',
                           'rollback-import', 'prune-import-snapshots', 'setup-route-checker'))
OFFLINE_MODES = frozenset(('help', 'print-plan', 'show-snapshots'))


def _run_mutation(ctx):
    """The sole lazy native write boundary; read-only imports stay lightweight."""
    if ctx.options.mode == 'setup-route-checker':
        from kdn.engine import inspection_setup
        return inspection_setup.run(ctx)
    if ctx.options.mode in ('apply', 'preflight'):
        from kdn.engine import apply_ops
        return apply_ops.preflight_run(ctx) if ctx.options.mode == 'preflight' else apply_ops.run(ctx)
    if ctx.options.mode in ('apply-import-profile', 'clear-imported-profile', 'rollback-import', 'prune-import-snapshots'):
        from kdn.engine import import_ops
        return import_ops.run(ctx)
    from kdn.engine import rollback_ops
    return rollback_ops.run(ctx)


class Context:
    """What a mode gets: the arguments and environment of the run, the console, and the seams for tests."""

    __slots__ = ("argv", "environ", "console", "paths", "options", "resolved", "execve")

    def __init__(self, argv, environ, console, paths=None, options=None, resolved=None, execve=os.execve):
        self.argv = argv
        self.environ = environ
        self.console = console
        self.paths = paths
        self.options = options
        self.resolved = resolved
        self.execve = execve


def mode_of(argv):
    """The mode the argument loop of the script ends in, as kdn_scan_mode of its dispatcher computes it.

    A read-only MODES name, a MUTATION_MODES name, "help", or "?" for an unknown/incomplete argument.
    """
    try:
        mode = options.parse_args(argv).mode
    except options.ArgError:
        return "?"
    return mode if mode in MODES or mode in MUTATION_MODES or mode == 'help' else 'other'


class _WarningsConsole:
    """Emit warnings on first native output, not on a flush preceding exec of legacy.

    Legacy repeats validation itself. If exec succeeds, it owns the warnings; a native
    mode emits them before its first output (or when it returns without output).
    """

    __slots__ = ('output', 'warnings')

    def __init__(self, output, warnings):
        self.output = output
        self.warnings = list(warnings)

    def emit(self):
        while self.warnings:
            self.output.err(self.warnings.pop(0))

    def out(self, text='', end='\n'):
        self.emit()
        self.output.out(text, end=end)

    def err(self, text='', end='\n'):
        self.emit()
        self.output.err(text, end=end)

    def flush(self):
        self.output.flush()


def main(argv=None, environ=None, stdout=None, stderr=None, execve=os.execve):
    """Run the mode of the command line and return its exit code; what the Python path lacks goes to the shell."""
    argv = sys.argv[1:] if argv is None else list(argv)
    environ = os.environ if environ is None else environ
    if stdout is None and stderr is None:
        output = console.Console.process()
    else:
        output = console.Console(sys.stdout if stdout is None else stdout, sys.stderr if stderr is None else stderr)
    try:
        paths = config.EnginePaths.from_environ(environ)
    except RuntimeError as error:
        output.err(f"ERROR: {error}")
        output.flush()
        return 2
    try:
        parsed = options.parse_args(argv)
        if parsed.mode not in OFFLINE_MODES:
            try:
                xkeen.require(environ=environ)
            except xkeen.UnsupportedXKeen:
                if parsed.mode == 'status' and parsed.json:
                    import json
                    output.out(json.dumps(xkeen.error_status(), ensure_ascii=False, indent=2))
                else:
                    if parsed.mode in MUTATION_MODES:
                        output.out('STAGE|preflight')
                    output.err('ERROR: ' + xkeen.MESSAGE)
                    if parsed.mode in MUTATION_MODES:
                        output.out('RESULT|failed')
                output.flush()
                return 2
        # The offline plan is about explicit arguments, not effective router
        # defaults. Metadata-only snapshot listing has its own bounded reader.
        config_text = '' if parsed.mode in OFFLINE_MODES else confvalues.read_text(paths.nfqws_conf)
        resolved = options.resolve(parsed, config_text)
    except options.ArgError as error:
        for warning in error.warnings:
            output.err(warning)
        output.err(error.message)
        output.flush()
        return error.code
    delayed = _WarningsConsole(output, resolved.warnings)
    ctx = Context(argv, environ, delayed, paths=paths, options=parsed, resolved=resolved, execve=execve)
    module = MODES.get(parsed.mode)
    if parsed.mode in MUTATION_MODES or (parsed.mode == 'preflight' and not paths.test_root):
        code = _run_mutation(ctx)
    else:
        code = legacy.exec_legacy(ctx) if module is None else module.run(ctx)
    delayed.emit()
    output.flush()
    return code

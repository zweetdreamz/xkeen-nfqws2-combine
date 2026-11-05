"""Command-line options of the engine: the argument loop of apply-discord-nfqws2.sh, variable for variable."""

import re

from kdn.engine import config, confvalues

# Options that set a mode, with no value.
_MODE_FLAGS = {
    "--print-plan": "print-plan",
    "--preflight": "preflight",
    "--status": "status",
    "--check-config": "check-config",
    "--print-nfqws-profiles": "print-nfqws-profiles",
    "--show-snapshots": "show-snapshots",
    "--show-rollback": "show-snapshots",
    "--snapshot-baseline": "snapshot-baseline",
    "--apply": "apply",
    "--rollback-import": "rollback-import",
    "--prune-import-snapshots": "prune-import-snapshots",
    "--setup-route-checker": "setup-route-checker",
    "--rollback": "rollback-baseline",
    "--rollback-baseline": "rollback-baseline",
    "--rollback-latest": "rollback-latest",
    "-h": "help",
    "--help": "help",
}

# Options that set a field to a fixed value: (field, value).
_FLAGS = {
    "--wide-udp": ("wide_udp", True),
    "--narrow-udp": ("wide_udp", False),
    "--standalone-zapret": ("standalone", True),
    "--without-xkeen": ("standalone", True),
    "--no-xkeen": ("standalone", True),
    "--integrated": ("standalone", False),
    "--json": ("json", True),
}

# Options that take the next argument, whatever it looks like:
# (what the error message asks for, mode it sets or None, fields that receive the value).
_VALUE_OPTIONS = {
    "--focused-operation-context": ("an operation context.", None, ("focused_context",)),
    "--recover-import-source": ("a focused source.", None, ("recover_import_source",)),
    "--apply-import-profile": ("a staging JSON file.", "apply-import-profile", ("import_profile",)),
    "--clear-imported-profile": ("a service.", "clear-imported-profile", ("clear_profile",)),
    "--rollback-snapshot": ("a snapshot path.", "rollback-snapshot", ("rollback_snapshot",)),
    "--udp-strategy": ("flowseal or legacy.", None, ("udp_strategy",)),
    "--discord-route": ("direct, zapret or vless.", None, ("discord_tcp_route", "discord_voice_route")),
    "--discord-tcp-route": ("direct, zapret or vless.", None, ("discord_tcp_route",)),
    "--discord-voice-route": ("direct, zapret or vless.", None, ("discord_voice_route",)),
    "--youtube-route": ("direct, zapret or vless.", None, ("youtube_route",)),
    "--telegram-route": ("direct, vless, ws or unmanaged.", None, ("telegram_route",)),
    "--proxy-outbound": ("an Xray outbound tag.", None, ("proxy_outbound_requested",)),
    "--core": ("auto, xray, or mihomo.", None, ("core_requested",)),
    "--direct-mark": ("a decimal Keenetic policy mark.", None, ("direct_mark_requested",)),
    "--wan-interface": ("one interface or a quoted list.", None, ("wan_interface_requested",)),
}

# Route fields that remember whether the user named them: <field>_explicit.
_EXPLICIT_ROUTES = frozenset({"discord_tcp_route", "discord_voice_route", "youtube_route", "telegram_route"})


class ArgError(Exception):
    """An argument the engine rejects: ``message`` goes to stderr, ``code`` is the exit status."""

    def __init__(self, message, code=2, warnings=()):
        super().__init__(message)
        self.message = message
        self.code = code
        self.warnings = warnings


class Options:
    """The values of the shell variables set by the argument loop, with the loop's defaults."""

    __slots__ = (
        "focused_context",
        "recover_import_source",
        "mode",
        "import_profile",
        "clear_profile",
        "rollback_snapshot",
        "confirmed",
        "wide_udp",
        "standalone",
        "udp_strategy",
        "discord_tcp_route",
        "discord_voice_route",
        "youtube_route",
        "telegram_route",
        "discord_tcp_route_explicit",
        "discord_voice_route_explicit",
        "youtube_route_explicit",
        "telegram_route_explicit",
        "proxy_outbound_requested",
        "core_requested",
        "direct_mark_requested",
        "wan_interface_requested",
        "json",
    )

    def __init__(self):
        self.focused_context = ""
        self.recover_import_source = ""
        self.mode = "help"
        self.import_profile = ""
        self.clear_profile = ""
        self.rollback_snapshot = ""
        self.confirmed = False
        self.wide_udp = False
        self.standalone = False
        self.udp_strategy = "flowseal"
        self.discord_tcp_route = "zapret"
        self.discord_voice_route = "zapret"
        self.youtube_route = "vless"
        # Empty: keep the route recorded in nfqws2.conf (resolved after the loop).
        self.telegram_route = ""
        self.discord_tcp_route_explicit = False
        self.discord_voice_route_explicit = False
        self.youtube_route_explicit = False
        self.telegram_route_explicit = False
        self.proxy_outbound_requested = ""
        self.core_requested = "auto"
        self.direct_mark_requested = ""
        self.wan_interface_requested = ""
        self.json = False

    def __eq__(self, other):
        if not isinstance(other, Options):
            return NotImplemented
        return all(getattr(self, name) == getattr(other, name) for name in self.__slots__)

    __hash__ = None

    def __repr__(self):
        return "Options(" + ", ".join(f"{name}={getattr(self, name)!r}" for name in self.__slots__) + ")"


def parse_args(argv):
    """Parse the arguments like the loop of the shell script; the first bad argument raises ArgError."""
    options = Options()
    args = list(argv)
    count = len(args)
    index = 0
    while index < count:
        arg = args[index]
        index += 1
        if arg in _MODE_FLAGS:
            options.mode = _MODE_FLAGS[arg]
        elif arg == "--yes-router":
            options.confirmed = True
            if options.mode == "help":
                options.mode = "apply"
        elif arg in _FLAGS:
            name, value = _FLAGS[arg]
            setattr(options, name, value)
        elif arg in _VALUE_OPTIONS:
            needs, mode, names = _VALUE_OPTIONS[arg]
            if index >= count:
                raise ArgError(f"ERROR: {arg} requires {needs}")
            value = args[index]
            index += 1
            if mode is not None:
                options.mode = mode
            for name in names:
                setattr(options, name, value)
                if name in _EXPLICIT_ROUTES:
                    setattr(options, name + "_explicit", True)
        else:
            raise ArgError(f"ERROR: unknown argument: {arg}")
    if options.focused_context and options.mode not in ("apply-import-profile", "clear-imported-profile", "rollback-import"):
        raise ArgError("ERROR: focused context requires a focused mutation")
    if options.recover_import_source and (options.mode != "rollback-import" or not options.focused_context):
        raise ArgError("ERROR: recovery source requires rollback and operation context")
    return options


class Resolved:
    """A separate result of post-loop validation; parsing options stay unchanged."""

    __slots__ = Options.__slots__ + ('previous_telegram_route', 'telegram_header_route', 'voice_high',
                                   'xkeen_required_ports', 'warnings')

    def __init__(self, options):
        for name in Options.__slots__:
            setattr(self, name, getattr(options, name))
        self.warnings = []
        self.telegram_header_route = ''

    def routes_summary(self):
        return (f'Discord TCP={self.discord_tcp_route}, Discord Voice={self.discord_voice_route}, '
                f'YouTube={self.youtube_route}, Telegram={self.telegram_route}')


def resolve(options, nfqws_text):
    """Validate in the shell's order, including recorded Telegram and standalone defaults."""
    result = Resolved(options)

    def error(message):
        raise ArgError('ERROR: ' + message, warnings=tuple(result.warnings))

    result.previous_telegram_route = confvalues.recorded_telegram_route(nfqws_text)
    result.telegram_route = result.telegram_route or result.previous_telegram_route
    if result.telegram_route == 'zapret':
        if result.telegram_route_explicit:
            error('Telegram has no Zapret route any more; use ws, vless or direct.')
        if result.mode in ('apply', 'preflight'):
            result.warnings.append('WARNING: the recorded Telegram route zapret was removed; Telegram becomes direct.')
        result.telegram_route = 'direct'
    if result.telegram_route not in ('direct', 'vless', 'ws', 'unmanaged'):
        error('unsupported Telegram route: ' + result.telegram_route)
    if result.standalone:
        if result.telegram_route == 'vless' and not result.telegram_route_explicit:
            result.telegram_header_route = 'vless'
            result.telegram_route = 'unmanaged'
        if result.telegram_route == 'ws' and result.telegram_route_explicit:
            error('Telegram WS needs XKeen/Xray and cannot be used with --standalone-zapret.')
        for field in ('discord_tcp_route', 'discord_voice_route', 'youtube_route'):
            if not getattr(result, field + '_explicit'):
                setattr(result, field, 'zapret')
        if result.core_requested != 'auto':
            error('--core cannot be combined with --standalone-zapret.')
        if result.direct_mark_requested or result.proxy_outbound_requested:
            error('--direct-mark/--proxy-outbound require XKeen and cannot be used in standalone mode.')
        routes = (result.discord_tcp_route, result.discord_voice_route, result.youtube_route, result.telegram_route)
        if 'vless' in routes:
            error('vless routing is unavailable with --standalone-zapret; use zapret or direct.')
        if 'zapret' not in routes:
            error('standalone mode needs at least one service with route=zapret.')
    for value, allowed, label in (
        (result.core_requested, ('auto', 'xray', 'mihomo'), 'core'),
        (result.udp_strategy, ('flowseal', 'legacy'), 'UDP strategy'),
        (result.discord_tcp_route, confvalues.ROUTE_VALUES, 'Discord TCP route'),
        (result.discord_voice_route, confvalues.ROUTE_VALUES, 'Discord Voice route'),
        (result.youtube_route, confvalues.ROUTE_VALUES, 'YouTube route'),
    ):
        if value not in allowed:
            error('unsupported ' + label + ': ' + value)
    if result.proxy_outbound_requested and not re.fullmatch(r'[A-Za-z0-9_.:-]+', result.proxy_outbound_requested):
        error('invalid Xray proxy outbound tag: ' + result.proxy_outbound_requested)
    result.voice_high = '65535' if result.wide_udp else '50100'
    result.xkeen_required_ports = (config.XKEEN_REQUIRED_PORTS_NARROW.rsplit(':', 1)[0] + ':' + result.voice_high
                                   + (',5222' if result.telegram_route != 'unmanaged' else ''))
    if result.json and result.mode != 'status':
        error('--json is supported only with --status.')
    return result

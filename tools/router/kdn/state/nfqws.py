"""Managed block of nfqws2.conf: route header, Discord UDP range and Voice ports.

apply-discord-nfqws2.sh writes two header lines, and this module parses them
for the panel:

    # Active routes: DiscordTCP=X, DiscordVoice=X, YouTube=X, Telegram=X.
    # Discord UDP: strategy=flowseal|legacy, range=narrow|wide.

Pure functions over the config text; reading the file stays with the caller.
The router tools still carry copies (merged into this module in phase 8) that
differ in details of the UDP line:
- zapret_autotune_job.recorded_udp_settings accepts only strategy=flowseal|legacy,
  so any other strategy sends it to the UDP_PORTS fallback;
- its fallback matches any UDP_PORTS line, not the last one.
"""

import re


ROUTE_SERVICES = ("discord-tcp", "discord-voice", "youtube", "telegram")
ROUTE_VALUES = frozenset({"direct", "zapret", "vless"})
# Telegram is opt-in: "unmanaged" means the project leaves it to user rules.
# "zapret" is still parsed from old headers but can no longer be selected.
TELEGRAM_ROUTE_VALUES = ROUTE_VALUES | {"ws", "unmanaged"}
# The engine's VOICE_HIGH: the upper Discord Voice UDP port of the narrow and the wide range.
NARROW_VOICE_HIGH = 50100
WIDE_VOICE_HIGH = 65535


def unknown_routes():
    """Fresh route map with every managed service unknown."""
    return {service: "unknown" for service in ROUTE_SERVICES}


def parse_active_routes(text):
    """Read the "# Active routes:" line written by apply-discord-nfqws2.sh.

    Returns {"discord-tcp", "discord-voice", "youtube", "telegram"} -> route,
    or None when the line is missing or malformed. The legacy line
    "Discord=X, YouTube=Y." written before the TCP/Voice split applies X to
    both Discord routes. Lines without Telegram predate it: "unmanaged".
    """
    match = re.search(r"^# Active routes: (.+)\.$", text, re.MULTILINE)
    if not match:
        return None
    values = {}
    for pair in match.group(1).split(", "):
        key, separator, value = pair.partition("=")
        allowed = TELEGRAM_ROUTE_VALUES if key == "Telegram" else ROUTE_VALUES
        if not separator or value not in allowed:
            return None
        values[key] = value
    telegram = values.pop("Telegram", "unmanaged")
    if set(values) == {"DiscordTCP", "DiscordVoice", "YouTube"}:
        return {
            "discord-tcp": values["DiscordTCP"],
            "discord-voice": values["DiscordVoice"],
            "youtube": values["YouTube"],
            "telegram": telegram,
        }
    if set(values) == {"Discord", "YouTube"}:
        return {
            "discord-tcp": values["Discord"],
            "discord-voice": values["Discord"],
            "youtube": values["YouTube"],
            "telegram": telegram,
        }
    return None


def recorded_voice_range(text):
    """Recorded Discord Voice UDP range of nfqws2.conf: "narrow" or "wide".

    The "# Discord UDP: strategy=X, range=Y." line decides. Configs without it
    are inferred from the last UDP_PORTS assignment; no UDP settings at all
    mean the default narrow range.
    """
    match = re.search(r"^# Discord UDP: strategy=[a-z]+, range=(narrow|wide)\.$", text, re.MULTILINE)
    if match:
        return match.group(1)
    ports = re.findall(r"^UDP_PORTS=\"?([0-9:,-]*)", text, re.MULTILINE)
    return "wide" if ports and re.search(r"50000[:-]65535", ports[-1]) else "narrow"


def voice_high(voice_range):
    """Upper Discord Voice UDP port of a recorded range: 65535 for "wide", 50100 otherwise."""
    return WIDE_VOICE_HIGH if voice_range == "wide" else NARROW_VOICE_HIGH


def voice_ports_allowed(value, high=65535):
    """Discord Voice UDP ports the engine accepts; high is the recorded upper port."""
    for item in value.split(","):
        parts = item.split("-", 1)
        if not all(part.isdigit() for part in parts):
            return False
        left = int(parts[0])
        right = int(parts[-1])
        if left > right:
            return False
        allowed = (
            (left == right == 443)
            or (3478 <= left <= right <= 3481)
            or (left == right == 5349)
            or (19294 <= left <= right <= 19344)
            or (50000 <= left <= right <= high)
        )
        if not allowed:
            return False
    return bool(value)


def validate_service_profiles(service, args, *, voice_high=65535):
    """Validate each imported transport profile without I/O or changing argv."""
    def values(name):
        prefix = '--' + name + '='
        return [token[len(prefix):] for token in args if token.startswith(prefix)]

    if service == 'discord-voice':
        udp, lua = values('filter-udp'), values('lua-desync')
        if (isinstance(voice_high, bool) or not isinstance(voice_high, int) or not 50100 <= voice_high <= 65535
                or '--new' in args or len(udp) != 1 or not voice_ports_allowed(udp[0], voice_high)
                or values('filter-tcp') or values('hostlist')
                or set(values('filter-l7')) != {'stun,discord'}
                or set(values('payload')) != {'stun,discord_ip_discovery'}
                or len(lua) != 1 or not re.fullmatch(r'fake:blob=discord_udp:repeats=([1-9]|[1-9][0-9])', lua[0])
                or any(re.search(r'youtube|quic_initial|tls_client', token) for token in args)):
            raise ValueError('unsafe Voice bounds')
        return
    youtube = service == 'youtube'
    profiles = [[]]
    for token in args:
        if token == '--new':
            profiles.append([])
        else:
            profiles[-1].append(token)
    if len(profiles) != (2 if youtube else 1) or any(not profile for profile in profiles):
        raise ValueError('unsafe service profile boundaries')
    transports = []
    for profile in profiles:
        def selectors(name, profile=profile):
            prefix = '--' + name + '='
            return [token[len(prefix):] for token in profile if token.startswith(prefix)]

        tcp, udp = selectors('filter-tcp'), selectors('filter-udp')
        if tcp == ['443'] and not udp:
            transport, l7, payload = 'tcp', 'tls', 'tls_client_hello'
        elif youtube and udp == ['443'] and not tcp:
            transport, l7, payload = 'udp', 'quic', 'quic_initial'
        else:
            raise ValueError('unsafe service transport selectors')
        allowed = {
            'filter-l7': {l7},
            'hostlist': {'/opt/etc/nfqws2/lists/' + ('youtube.list' if youtube else 'user.list')},
            'payload': {payload},
        }
        if (any(set(selectors(name)) != expected for name, expected in allowed.items())
                or not selectors('lua-desync')):
            raise ValueError('unsafe service selectors or empty desync')
        transports.append(transport)
    if sorted(transports) != (['tcp', 'udp'] if youtube else ['tcp']):
        raise ValueError('unsafe service profile transports')
    forbidden = r'user\.list|discord_udp|discord_ip_discovery' if youtube else r'youtube\.list|quic_initial|discord_udp'
    if any(re.search(forbidden, token) for token in args):
        raise ValueError('cross-service token')

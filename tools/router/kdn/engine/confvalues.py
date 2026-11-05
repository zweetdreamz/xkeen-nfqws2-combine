"""Values of the XKeen init script, the netfilter hook and nfqws2.conf: ports of the awk/sed functions of the script.

Every reader works on the bytes of the file as awk and sed see them: decoded as UTF-8 with surrogateescape, split
only on LF (a CR stays in the line), trimmed with an explicit set and never with ``str.strip()`` without an
argument. A missing file gives an empty value or None, as in the script. The functions take the file text (None for
a missing file) or an object with ``xkeen_init``, ``xkeen_hook`` and ``nfqws_conf`` paths. Keys are identifiers: awk
would compare a numeric-looking key as a number (``-v wanted=1`` finds ``01=``), which the port does not model.
"""

import os
import re


# What awk's default FS splits fields on. mawk (the awk of the test stand) splits on blank, tab and newline;
# busybox awk (the awk of the router) on every isspace() character, so there a CR, VT or FF also ends a field.
# The port follows the router; tests/test_engine_confvalues.py checks both models against the real awks.
AWK_FIELD_SEPARATORS = " \t\n\v\f\r"
# [[:space:]] of awk and sed in the C locale.
SPACE = " \t\r\n\v\f"
ROUTE_VALUES = ("direct", "zapret", "vless")
TELEGRAM_VALUES = ("direct", "zapret", "vless", "ws", "unmanaged")
DEPLOYMENT_MODES = ("standalone-zapret", "xkeen-integrated")
UDP_SETTINGS = (
    ("flowseal", "narrow"),
    ("flowseal", "wide"),
    ("legacy", "narrow"),
    ("legacy", "wide"),
)

_DIGITS = re.compile("[0-9]+")
_PORT = re.compile("[0-9]+(?::[0-9]+)?")
_MODE_LINE = re.compile(r"# Deployment mode: ([a-z-]*)\.")
_PROXY_LINE = re.compile(r"# Proxy outbound: ([A-Za-z0-9_.:-]*)\.")
_UDP_LINE = re.compile(r"# Discord UDP: strategy=([a-z]*), range=([a-z]*)\.")
_VOICE_LINE = re.compile(r"# Discord Voice profile: imported ([0-9a-f]*), udp=([0-9,-]*)\.")


def read_text(path):
    """Text of a regular file (``[ -f ]``) as awk reads it, or None."""
    if path is None or not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    return data.decode("utf-8", errors="surrogateescape")


def lines(text):
    """Records of a text: split only on LF, a final LF does not start another record."""
    if not text:
        return []
    records = text.split("\n")
    if records[-1] == "":
        records.pop()
    return records


def _fields(line):
    """Fields of a record with awk's default FS."""
    return [field for field in re.split("[" + re.escape(AWK_FIELD_SEPARATORS) + "]+", line) if field]


fields = _fields


def _split(text, separator):
    """awk ``split(text, parts, separator)`` for a one-character separator."""
    return text.split(separator) if text else []


def _assigned(text, key, last):
    """Value of the first (or last) ``key=value`` line, or None; an awk ``-F=`` program of the script."""
    found = None
    for line in lines(text):
        name, equals, rest = line.partition("=")
        if name != key:
            continue
        # sub(/^[^=]*=/, "") leaves a line without "=" as it is.
        value = (rest if equals else line).strip(SPACE)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not last:
            return value
        found = value
    return found


def assigned_value(text, key, last=False):
    """Value of ``key=value`` in the text: first match, or last one with ``last``; "" when there is none."""
    return _assigned(text, key, last) or ""


def init_value(paths, key):
    """init_value of the script: the first ``key=`` of the XKeen init script."""
    return assigned_value(read_text(paths.xkeen_init), key)


def runtime_value(paths, key):
    """runtime_value of the script: the first ``key=`` of the XKeen netfilter hook."""
    return assigned_value(read_text(paths.xkeen_hook), key)


def xkeen_effective_value(paths, key):
    """The hook value when it is not empty, else the init script value."""
    return runtime_value(paths, key) or init_value(paths, key)


def nfqws_value(paths, key):
    """nfqws_value of the script: the last ``key=`` of nfqws2.conf, empty when that one is empty."""
    return assigned_value(read_text(paths.nfqws_conf), key, last=True)


def active_ports(text):
    """Effective XKeen2.1 ports: inline comments, comma/LF lists and bounded ranges.

    Like upstream read_ports_from_file + validate_and_clean_ports, remove C
    whitespace and normalize reversed ranges. Preserve encounter order and
    distinct ranges: upstream sort -n -u can collapse different ranges sharing
    a start; that presentation quirk must not hide an effective exclusion.
    """
    ports = []
    for line in lines(text):
        for value in line.partition('#')[0].split(','):
            value = value.translate(str.maketrans('', '', SPACE)).replace('-', ':')
            if not _PORT.fullmatch(value):
                continue
            # Strip leading zeroes before int(), bounding work for hostile input.
            parts = [part.lstrip('0') or '0' for part in value.split(':')]
            if any(len(part) > 5 for part in parts):
                continue
            bounds = [int(part) for part in parts]
            if any(not 1 <= port <= 65535 for port in bounds):
                continue
            normalized = ':'.join(str(port) for port in sorted(bounds))
            ports.append(normalized)
    return ",".join(ports)


def _bounds(spec):
    parts = _split(spec.replace("-", ":"), ":")
    if not parts:
        return None
    # Only the first two parts count: "1:2:3" is the range 1:2.
    first, second = parts[0], parts[1] if len(parts) > 1 else parts[0]
    if not (_DIGITS.fullmatch(first) and _DIGITS.fullmatch(second)):
        return None
    # awk compares doubles.
    return float(first), float(second)


def ports_overlap(left, right):
    """True when a port or range of one comma-separated list meets one of the other (``ports_overlap``)."""
    right_bounds = [_bounds(spec) for spec in _split(right, ",")]
    for spec in _split(left, ","):
        first = _bounds(spec)
        if first is None:
            continue
        for second in right_bounds:
            if second is not None and first[0] <= second[1] and second[0] <= first[1]:
                return True
    return False


def _routes_header(text):
    """Pairs ``(key, value)`` of every "# Active routes:" line: a list of lists, one per line."""
    headers = []
    for line in lines(text):
        fields = _fields(line)
        if fields[:3] != ["#", "Active", "routes:"]:
            continue
        pairs = []
        for pair in fields[3:]:
            if pair[-1] in ",.":
                pair = pair[:-1]
            parts = _split(pair, "=")
            pairs.append((parts[0] if parts else "", parts[1] if len(parts) > 1 else ""))
        headers.append(pairs)
    return headers


def recorded_route(text, service):
    """Route of discord-tcp, discord-voice or youtube from the last "# Active routes:" line, or None."""
    keys = {
        "discord-tcp": ("DiscordTCP", "Discord"),
        "discord-voice": ("DiscordVoice", "Discord"),
        "youtube": ("YouTube",),
    }.get(service, ())
    value = None
    for pairs in _routes_header(text):
        value = ""
        for key, pair_value in pairs:
            if key in keys:
                value = pair_value
    return value if value in ROUTE_VALUES else None


def recorded_telegram_route(text):
    """Telegram route of the "# Active routes:" lines (kept from line to line), "unmanaged" when invalid."""
    value = ""
    for pairs in _routes_header(text):
        for key, pair_value in pairs:
            if key == "Telegram":
                value = pair_value
    return value if value in TELEGRAM_VALUES else "unmanaged"


def _first_match(pattern, text):
    for line in lines(text):
        found = pattern.fullmatch(line)
        if found:
            return found
    return None


def recorded_deployment_mode(text):
    """Mode of the first "# Deployment mode:" line when it is a known one, else None."""
    found = _first_match(_MODE_LINE, text)
    return found.group(1) if found and found.group(1) in DEPLOYMENT_MODES else None


def recorded_proxy_outbound(text):
    """Outbound of the first "# Proxy outbound:" line, None when there is none or it is empty."""
    found = _first_match(_PROXY_LINE, text)
    return found.group(1) or None if found else None


def recorded_udp_settings(text, nfqws_ports):
    """(strategy, range) from the "# Discord UDP:" line; else from UDP_PORTS (``nfqws_ports``) and the blobs."""
    found = _first_match(_UDP_LINE, text)
    if found and (found.group(1), found.group(2)) in UDP_SETTINGS:
        return found.group(1), found.group(2)
    nfqws_ports = nfqws_ports or ""
    voice_range = "wide" if "50000:65535" in nfqws_ports or "50000-65535" in nfqws_ports else "narrow"
    text = text or ""
    if "--blob=discord_udp:" in text:
        return "flowseal", voice_range
    if "--filter-l7=stun,discord" in text:
        return "legacy", voice_range
    return "", voice_range


def voice_profile_header(text):
    """(profile id, udp filter) of the first "# Discord Voice profile: imported" line, or None."""
    found = _first_match(_VOICE_LINE, text)
    return (found.group(1), found.group(2)) if found else None

"""Composition invariants and ordered CHECK findings, matching nfqws_config_check."""

import os
import re
import stat

from kdn.engine import compose, config, confvalues


_DIGITS = re.compile(r"[0-9]+")


def port_ranges(spec):
    """(lo/hi pairs, wildcard flag) of NFQWS_PORT_AWK; malformed items set the flag."""
    ranges = []
    wildcard = False
    for item in spec.split(","):
        if item == "":
            continue
        bounds = item.replace(":", "-").split("-")
        if len(bounds) == 1:
            bounds.append(bounds[0])
        if len(bounds) > 2 or not all(_DIGITS.fullmatch(bound) for bound in bounds):
            wildcard = True
            continue
        # awk adds zero, i.e. converts to a double; do not use arbitrary-precision int.
        ranges.append((float(bounds[0]), float(bounds[1])))
    return ranges, wildcard


def _port_text(number):
    return str(int(number))


def port_gaps(a, b, ranges):
    """Uncovered segments of the inclusive port interval [a,b], in increasing order."""
    current = a
    out = []
    while current <= b:
        best = max((high for low, high in ranges if low <= current <= high), default=-1)
        if best >= 0:
            current = best + 1
            continue
        next_low = min((low for low, _high in ranges if current < low < b + 1), default=b + 1)
        stop = next_low - 1
        out.append(_port_text(current) if current == stop else _port_text(current) + "-" + _port_text(stop))
        current = next_low
    return ",".join(out)


def list_entries(path, test_root):
    """Count non-comment lines as awk getline does; a readable .gz counts as one, even empty."""
    real = config.list_path(path, test_root)
    count = 0
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(real, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return -1
            if real.endswith(".gz"):
                stream.read(1)
                return 1
            for raw in stream:
                # BusyBox awk treats NUL as another record separator; mawk
                # retains it inside the line. Follow the router, as R9 does.
                for line in raw.split(b"\0"):
                    if line.endswith(b"\n"):
                        line = line[:-1]
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    line = line.lstrip(b" \t")
                    if line and line[:1] not in (b"#", b";", b"/"):
                        count += 1
    except OSError:
        return count if count else -1
    return count


def header_lines(conf_text):
    voice, voice_range = None, None
    for line in confvalues.lines(conf_text):
        if voice_range is None:
            match = re.fullmatch(r'# Discord UDP: strategy=[a-z]*, range=([a-z]*)\.', line)
            if match:
                voice_range = match.group(1)
        if voice is None:
            match = re.fullmatch(r'# Discord Voice profile: imported ([0-9a-f]*), udp=([0-9,-]*)\.', line)
            if match:
                voice = match.group(1), match.group(2)
    if voice is None:
        return []
    identity, ports = voice
    ranges, _wildcard = port_ranges(ports)
    if voice_range == 'wide' and not any(high >= 65535 for _low, high in ranges):
        return [f'CHECK|warn|voice-range|range=wide is recorded, but the imported Discord Voice profile {identity} filters only UDP {ports}; Xray sends 50000-65535 direct']
    return [f'CHECK|ok|voice-range|imported Discord Voice profile {identity} filters UDP {ports}']


def _profile():
    return {'used': False, 'tcp': '', 'udp': '', 'l7': '', 'lists': [], 'desync': 0, 'host': False, 'legacy': '', 'filter': False}


def _label(number, profile, user_profiles):
    text = '#' + str(number)
    for protocol in ('tcp', 'udp'):
        if profile[protocol]:
            text += ' ' + protocol + '=' + profile[protocol][1:]
    if profile['l7']:
        text += ' l7=' + profile['l7']
    if profile['lists']:
        text += ' list=' + profile['lists'][0].rsplit('/', 1)[-1]
    if number <= user_profiles:
        text += ' (user profile)'
    return text


def _composition_lines(composition, test_root):
    profiles = [_profile()]
    all_lists, managed_lists = {}, set()
    for token in composition.tokens:
        if token == '--new':
            profiles.append(_profile())
            continue
        profile = profiles[-1]
        profile['used'] = True
        option, _equal, value = token.partition('=')
        if option.startswith('--filter-') or option.startswith(('--hostlist', '--ipset')):
            profile['filter'] = True
        if option in ('--filter-tcp', '--filter-udp'):
            profile[option[-3:]] += ',' + value
        elif option == '--filter-l7':
            profile['l7'] = value
        elif option in ('--hostlist', '--ipset'):
            profile['host'] = True
            profile['lists'].append(value)
            all_lists[value] = None  # insertion order is B11's first-reference order
            if len(profiles) > composition.user_profiles:
                managed_lists.add(value)
        elif option in ('--hostlist-domains', '--hostlist-auto', '--ipset-ip'):
            profile['host'] = True
        elif option == '--lua-desync':
            profile['desync'] += 1
            if (value == 'fake' or value.startswith('fake:')) and not re.search(r'(^|:)blob=', value):
                profile['legacy'] += ' ' + value

    queue_tcp = composition.meta.get('TCP_PORTS', '')
    queue_udp = composition.meta.get('UDP_PORTS', '')
    queues = {'tcp': port_ranges(queue_tcp)[0], 'udp': port_ranges(queue_udp)[0]}
    seen_ranges, any_protocol = {'tcp': [], 'udp': []}, {'tcp': False, 'udp': False}
    result = [f'CHECK|ok|compose|{len(profiles)} profiles ({composition.source} _startup_args); TCP_PORTS={queue_tcp}, UDP_PORTS={queue_udp}']
    found = set()
    errors = 0

    def finding(level, name, detail):
        nonlocal errors
        result.append('CHECK|' + level + '|' + name + '|' + detail)
        found.add(name)
        errors += level == 'error'

    def level_for(number):
        return 'warn' if number <= composition.user_profiles else 'error'

    # A profile with only process-global options (or no options) still matches
    # every packet in nfqws. It must not consume traffic before managed desync.
    for number, profile in enumerate(profiles, 1):
        if not profile['filter'] and not profile['desync'] and any(
                later['desync'] for index, later in enumerate(profiles[number:], number + 1)
                if index > composition.user_profiles):
            finding('error', 'shadowed-profile', '#' + str(number)
                    + ' is a catch-all no-op before an active managed desync profile')

    for number, profile in enumerate(profiles, 1):
        if not profile['used']:
            continue
        label = _label(number, profile, composition.user_profiles)
        if not profile['tcp'] and not profile['udp']:
            if profile['desync']:
                finding('warn', 'port-coverage', label + ' has no --filter-tcp/--filter-udp: it sees every queued port')
                any_protocol = {'tcp': True, 'udp': True}
            continue
        for protocol, queue_text in (('tcp', queue_tcp), ('udp', queue_udp)):
            if not profile[protocol]:
                continue
            ranges, wildcard = port_ranges(profile[protocol][1:])
            if wildcard:
                finding('warn', 'port-coverage', label + ' uses a wildcard or negated ' + protocol.upper() + ' filter; not checked')
                any_protocol[protocol] = True
            for low, high in ranges:
                seen_ranges[protocol].append((low, high))
                gaps = port_gaps(low, high, queues[protocol])
                if gaps:
                    finding(level_for(number), 'port-coverage', label + ' filters ' + protocol.upper() + ' ' + gaps + ' outside ' + protocol.upper() + '_PORTS=' + queue_text)
    if 'port-coverage' not in found:
        result.append('CHECK|ok|port-coverage|every profile port is queued')

    for protocol in ('tcp', 'udp'):
        if not any_protocol[protocol]:
            for low, high in queues[protocol]:
                gaps = port_gaps(low, high, seen_ranges[protocol])
                if gaps:
                    finding('warn', 'unhandled-ports', protocol.upper() + ' ' + gaps + ' is queued but no profile filters it')
    if 'unhandled-ports' not in found:
        result.append('CHECK|ok|unhandled-ports|every queued port has a profile')

    for number, profile in enumerate(profiles, 1):
        if profile['used'] and profile['desync'] and not profile['host'] and profile['l7'] != 'stun,discord':
            finding(level_for(number), 'listless-profile', _label(number, profile, composition.user_profiles) + ' has --lua-desync but no --hostlist/--ipset: it desyncs every host')
    if 'listless-profile' not in found:
        result.append('CHECK|ok|listless-profile|every desync profile has a host filter')

    for path in all_lists:
        entries = list_entries(path, test_root)
        level = 'error' if path in managed_lists else 'warn'
        if entries < 0:
            finding(level, 'empty-hostlist', path + ' is missing or unreadable')
        elif entries == 0:
            finding(level, 'empty-hostlist', path + ' has no entries: nfqws2 then treats the profile as having no host filter')
    if 'empty-hostlist' not in found:
        result.append('CHECK|ok|empty-hostlist|every referenced list has entries')

    for number, profile in enumerate(profiles, 1):
        if profile['legacy']:
            finding(level_for(number), 'legacy-blob', _label(number, profile, composition.user_profiles) + ' has --lua-desync=fake without blob=:' + profile['legacy'])
    if 'legacy-blob' not in found:
        result.append('CHECK|ok|legacy-blob|every fake names its blob')
    return result, int(errors > 0)


def check_config(conf_path, paths, environ, quiet=False):
    if not os.path.isfile(conf_path) or not os.access(conf_path, os.R_OK):
        return ['CHECK|error|read|cannot read ' + str(conf_path)], 2
    try:
        composition = compose.compose(conf_path, paths, environ, config.timeout('compose', environ))
    except compose.ComposeError:
        return ['CHECK|error|compose|cannot compose the nfqws2 arguments of ' + str(conf_path)], 2
    result, status = _composition_lines(composition, paths.test_root)
    result.extend(header_lines(confvalues.read_text(conf_path)))
    if any(line.startswith('CHECK|error|') for line in result):
        status = 1
    return ([line for line in result if not line.startswith('CHECK|ok|')] if quiet else result), status


def run(ctx):
    result, status = check_config(ctx.paths.nfqws_conf, ctx.paths, ctx.environ)
    for line in result:
        ctx.console.out(line)
    return status

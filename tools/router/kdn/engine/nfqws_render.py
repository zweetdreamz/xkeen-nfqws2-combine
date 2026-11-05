"""Pure nfqws2 config generation (writer is separate in nfqws_write).

No shell sourcing, domain-list/blob writes, service calls or CLI wiring. Resolved
inputs belong to the caller; generated artifacts still require strict validation.
"""
import re

from kdn.engine import config, confvalues, profile_descriptor


BEGIN = ('# BEGIN ' + config.PROJECT).encode('ascii')
END = ('# END ' + config.PROJECT).encode('ascii')


class BlockLayout:
    """Byte offsets of sed's exact LF-delimited BEGIN/END ranges.

    Nested BEGIN is ordinary content inside a range; the first END closes it.
    Unclosed BEGIN consumes through EOF, as legacy sed does. CRLF markers are
    NOT silently normalised. No trimming/replacement is performed here.
    """
    __slots__ = ('source', 'spans', 'unclosed')

    def __init__(self, source):
        if not isinstance(source, bytes):
            raise TypeError('configuration must be bytes')
        self.source = source
        spans, start, offset = [], None, 0
        records = source.split(b'\n')
        for index, line in enumerate(records):
            end = offset + len(line) + (index < len(records) - 1)
            if start is None:
                if line == BEGIN:
                    start = offset
            elif line == END:
                spans.append((start, end))
                start = None
            offset = end
        self.unclosed = start is not None
        if start is not None:
            spans.append((start, len(source)))
        self.spans = tuple(spans)

    def unmanaged(self):
        parts, offset = [], 0
        for start, end in self.spans:
            parts.append(self.source[offset:start])
            offset = end
        parts.append(self.source[offset:])
        return b''.join(parts)


class RenderInput:
    """Resolved common parameters, not a second argument parser/profile validator.

    routes order: Discord TCP, Discord Voice, YouTube, Telegram. Original config
    remains bytes; imported descriptors use P5.2a schema. No config is sourced.
    """
    __slots__ = ('config', 'routes', 'udp_strategy', 'wide_udp', 'standalone',
                 'wan_interfaces', 'ipv6_enabled', 'proxy_outbound', 'imported_profiles',
                 'telegram_header_route')

    def __init__(self, config_bytes, routes, *, udp_strategy='flowseal', wide_udp=False,
                 standalone=False, wan_interfaces='', ipv6_enabled=False, proxy_outbound='',
                 imported_profiles=None, telegram_header_route=''):
        if not isinstance(config_bytes, bytes) or not isinstance(routes, (tuple, list)):
            raise TypeError('configuration must be bytes and routes a sequence')
        if len(routes) != 4 or any(route not in ('direct', 'zapret', 'vless') for route in routes[:3]):
            raise ValueError('expected three canonical service routes and Telegram route')
        if routes[3] not in ('direct', 'vless', 'ws', 'unmanaged'):
            raise ValueError('unsupported resolved Telegram route')
        if udp_strategy not in ('flowseal', 'legacy'):
            raise ValueError('unsupported UDP strategy')
        if any(type(value) is not bool for value in (wide_udp, standalone, ipv6_enabled)):
            raise TypeError('render flags must be bool')
        if any(not isinstance(value, str) or any(char in value for char in '\r\n\0')
               for value in (wan_interfaces, proxy_outbound)):
            raise ValueError('render text fields must be single-line strings')
        self.config, self.routes = config_bytes, tuple(routes)
        self.udp_strategy, self.wide_udp, self.standalone = udp_strategy, wide_udp, standalone
        self.wan_interfaces, self.ipv6_enabled, self.proxy_outbound = wan_interfaces, ipv6_enabled, proxy_outbound
        if telegram_header_route and telegram_header_route not in ('direct', 'vless', 'ws', 'unmanaged'):
            raise ValueError('unsupported Telegram header route')
        self.telegram_header_route = telegram_header_route
        imported_profiles = {} if imported_profiles is None else imported_profiles
        if not isinstance(imported_profiles, dict) or set(imported_profiles) - set(profile_descriptor.SERVICES):
            raise ValueError('unsupported imported profile mapping')
        self.imported_profiles = {}
        for service, descriptor in imported_profiles.items():
            high = 65535 if wide_udp or service != 'discord-voice' or routes[1] != 'zapret' else 50100
            checked = profile_descriptor.validate_descriptor(descriptor, voice_high=high)
            if checked['service'] != service:
                raise ValueError('imported profile service does not match mapping')
            self.imported_profiles[service] = checked


class RenderOutput:
    """Generated block/full config plus diagnostics and required blob IDs."""
    __slots__ = ('block', 'warnings', 'config', 'required_blobs')

    def __init__(self, block, warnings=(), *, config_bytes=None, required_blobs=()):
        if not isinstance(block, bytes):
            raise TypeError('generated block must be bytes')
        if isinstance(warnings, str):
            raise TypeError('warnings must be a sequence of strings, not a string')
        warnings = tuple(warnings)
        if any(not isinstance(item, str) for item in warnings):
            raise TypeError('warnings must be strings')
        self.block, self.warnings = block, warnings
        self.config = block if config_bytes is None else config_bytes
        self.required_blobs = tuple(required_blobs)


def _custom_ports(source, option):
    inside, value, last = False, b'', b''
    for line in source.split(b'\n'):
        if not inside:
            found = re.match(rb'^[ \t]*NFQWS_ARGS_CUSTOM="', line)
            if found is None:
                continue
            line, inside, value = line[found.end():], True, b''
        before, quote, _ = line.partition(b'"')
        value += b' ' + before
        if quote:
            inside, last = False, value
    selected = []
    for word in re.split(rb'[ \t]+', last):
        if word.startswith(option + b'='):
            for item in word[len(option) + 1:].split(b','):
                if re.fullmatch(rb'[0-9]+(?:[-:][0-9]+)?', item):
                    selected.append(item.replace(b'-', b':').decode('ascii'))
    return ','.join(selected)


def _ranges(value):
    result = []
    for item in value.replace(':', '-').split(','):
        if re.fullmatch(r'[0-9]+(?:-[0-9]+)?', item):
            parts = item.split('-')
            result.append((int(parts[0]), int(parts[-1])))
    return result


def _ports_union(base, extra):
    """Keep original base spelling/order, append only uncovered ranges, as awk."""
    covered, output = _ranges(base), base
    for low, high in _ranges(extra):
        cursor = low
        while cursor <= high:
            stop = max((end for start, end in covered if start <= cursor <= end), default=-1)
            if stop >= 0:
                cursor = stop + 1
                continue
            next_start = min((start for start, _ in covered if start > cursor), default=high + 1)
            end = min(high, next_start - 1)
            output += ',' + (str(cursor) if cursor == end else str(cursor) + ':' + str(end))
            covered.append((cursor, end))
            cursor = end + 1
    return output


def _append_custom(args):
    return ('if [ -n "$NFQWS_ARGS_CUSTOM" ]; then\n'
            '  NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM\n--new"\nfi\n'
            'NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM\n' + args + '"')


def _register(blob, filename):
    return ('NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS\n'
            '                 --blob=' + blob + ':@/opt/etc/nfqws2/blobs/' + filename + '"')


YOUTUBE_ARGS = '''--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
--new
--filter-udp=443 --filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=11'''
TELEGRAM_ARGS = '''--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=telegram_tls:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=telegram_tls:tcp_ts_up'''


def render(request):
    """Return exact legacy managed config text without running/sourcing shell.

    Like legacy awk, blank user lines are collapsed to empty LF lines and trailing
    blanks dropped; opaque bytes in nonblank lines remain untouched. The required
    blobs are installation intent only, not proof they exist/checksum correctly.
    """
    if not isinstance(request, RenderInput):
        raise TypeError('RenderInput required')
    if (not re.fullmatch(r'[A-Za-z0-9_.: -]*', request.wan_interfaces)
            or not re.fullmatch(r'[A-Za-z0-9_.:-]*', request.proxy_outbound)):
        raise ValueError('unsafe resolved interface/outbound text')
    tcp_route, voice_route, youtube_route, telegram_route = request.routes
    imports = {service: value for service, value in request.imported_profiles.items()
               if request.routes[('discord-tcp', 'discord-voice', 'youtube').index(service)] == 'zapret'}
    source = BlockLayout(request.config).unmanaged()
    lines = source.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    while lines and not lines[-1].strip(b' \t\r\v\f'):
        lines.pop()
    source = b''.join((line if line.strip(b' \t\r\v\f') else b'') + b'\n' for line in lines)
    tcp_ports = config.TCP_PORTS_VALUE if tcp_route == 'zapret' and 'discord-tcp' not in imports else '443'
    tcp_filter = config.TCP_PORTS_VALUE if tcp_route == 'zapret' else tcp_ports
    if not re.search(rb'^NFQWS_ARGS="--filter-tcp=', source, re.M):
        raise ValueError('unsupported nfqws2 config: NFQWS_ARGS TCP filter not found')
    source = re.sub(rb'^NFQWS_ARGS="--filter-tcp=[^ \n]*',
                    lambda _: b'NFQWS_ARGS="--filter-tcp=' + tcp_filter.encode('ascii'), source, flags=re.M)
    voice_import = imports.get('discord-voice')
    if voice_import:
        udp_filter = next(token[len('--filter-udp='):] for token in voice_import['args'] if token.startswith('--filter-udp='))
        udp_ports = udp_filter.replace('-', ':')
        if '443' not in udp_ports.split(','):
            udp_ports = '443,' + udp_ports
    elif voice_route == 'zapret':
        udp_filter = config.UDP_FILTER_WIDE if request.wide_udp else config.UDP_FILTER_FLOWSEAL
        udp_ports = config.UDP_PORTS_WIDE if request.wide_udp else config.UDP_PORTS_FLOWSEAL
    else:
        udp_filter = udp_ports = '443'
    tcp_ports = _ports_union(tcp_ports, _custom_ports(source, b'--filter-tcp'))
    udp_ports = _ports_union(udp_ports, _custom_ports(source, b'--filter-udp'))
    warnings, blobs = [], []
    udp_base = udp_desync = ''
    if voice_route == 'zapret':
        if voice_import or request.udp_strategy == 'flowseal':
            udp_base = _register('discord_udp', 'discord_udp.bin')
            blobs.append('discord_udp')
            udp_desync = '                --lua-desync=fake:blob=discord_udp:repeats=6'
        else:
            udp_desync = ('                --lua-desync=circular:fails=2:time=300:retrans=3:nld=2\n'
                          '                --lua-desync=fake:blob=0x00000000:repeats=6:strategy=1')
            if b'--blob=quic_initial:' in source:
                udp_desync += '\n                --lua-desync=fake:blob=quic_initial:repeats=6:strategy=2'
            else:
                warnings.append('nfqws2 config does not register quic_initial; using one legacy UDP strategy.')
    youtube_base = youtube_custom = telegram_base = telegram_custom = ''
    if youtube_route == 'zapret':
        youtube_base = _register('youtube_quic', 'quic_initial.bin')
        youtube_custom = _append_custom('\n'.join(imports['youtube']['args']) if 'youtube' in imports else YOUTUBE_ARGS)
        blobs.append('youtube_quic')
    if telegram_route == 'ws':
        telegram_base, telegram_custom = _register('telegram_tls', 'tls_clienthello.bin'), _append_custom(TELEGRAM_ARGS)
        blobs.append('telegram_tls')
    tcp_assignment = 'NFQWS_ARGS="' + '\n'.join(imports['discord-tcp']['args']) + '"' if 'discord-tcp' in imports else ''
    quic_assignment = '' if tcp_route == 'zapret' else 'NFQWS_ARGS_QUIC=""'
    voice_header = ''
    if voice_import:
        udp_assignment = 'NFQWS_ARGS_UDP="' + '\n'.join(voice_import['args']) + '"'
        voice_header = '# Discord Voice profile: imported ' + voice_import['candidate_id'] + ', udp=' + udp_filter + '.'
    elif voice_route == 'zapret':
        udp_assignment = ('NFQWS_ARGS_UDP="--filter-udp=' + udp_filter + '\n'
                          '                --filter-l7=stun,discord\n'
                          '                --out-range=<n2\n'
                          '                --payload=stun,discord_ip_discovery\n' + udp_desync + '"')
    else:
        udp_assignment = 'NFQWS_ARGS_UDP=""'
    proxy = request.proxy_outbound or confvalues.recorded_proxy_outbound(request.config.decode('utf-8', 'surrogateescape')) or ''
    header = request.telegram_header_route or telegram_route
    body = [BEGIN.decode('ascii'), '# Generated by apply-discord-nfqws2.sh ' + config.SCRIPT_VERSION + '.',
            '# Deployment mode: ' + ('standalone-zapret' if request.standalone else 'xkeen-integrated') + '.',
            '# Active routes: DiscordTCP=' + tcp_route + ', DiscordVoice=' + voice_route + ', YouTube=' + youtube_route + ', Telegram=' + header + '.',
            '# Discord UDP: strategy=' + request.udp_strategy + ', range=' + ('wide' if request.wide_udp else 'narrow') + '.',
            voice_header, '# Proxy outbound: ' + proxy + '.' if proxy else '',
            '# Base TCP/QUIC use user.list; YouTube has isolated custom profiles.',
            udp_base, youtube_base, telegram_base, tcp_assignment, quic_assignment, udp_assignment,
            'NFQWS_EXTRA_ARGS="$MODE_LIST"', 'NFQWS_ARGS_IPSET=""', youtube_custom, telegram_custom,
            'TCP_PORTS=' + tcp_ports, 'UDP_PORTS=' + udp_ports,
            'POLICY_NAME="' + config.UNBOUND_POLICY_NAME + '"', 'POLICY_EXCLUDE=0',
            'IPV6_ENABLED=' + str(int(request.ipv6_enabled)), 'ISP_INTERFACE="' + request.wan_interfaces + '"', END.decode('ascii')]
    block = ('\n'.join(body) + '\n').encode('utf-8', 'surrogateescape')
    return RenderOutput(block, warnings, config_bytes=source + b'\n' + block, required_blobs=blobs)



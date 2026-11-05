"""Pure E4 Xray transformations. No IO, jq, service control or CLI wiring.

Inputs are decoded JSON objects; callers own bounded JSONC loading, validation,
transactional publication and the real Xray configuration test.
"""
from copy import deepcopy


VOICE_PORTS = ('3478-3481,5349,19294-19344,50000-50100',
               '3478-3481,5349,19294-19344,50000-65535')


def direct_outbound(tag, mark=None):
    if not isinstance(tag, str) or not tag or any(ord(c) < 32 for c in tag):
        raise ValueError('invalid outbound tag')
    if mark is not None and (type(mark) is not int or not 0 <= mark <= 2147483647):
        raise ValueError('mark must be a nonnegative int32')
    outbound = {'tag': tag, 'protocol': 'freedom', 'settings': {}}
    if mark is not None:
        outbound['streamSettings'] = {'sockopt': {'mark': mark}}
    return {'outbounds': [outbound]}


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + ' must be an object')
    return value


def inbound_roles(document, *, excluded_tags=()):
    """Ordinary transparent roles; caller supplies special paths to leave untouched."""
    rows = _object(document, 'config').get('inbounds', [])
    if not isinstance(rows, list):
        raise ValueError('inbounds must be an array')
    found = []
    for row in rows:
        _object(row, 'inbound')
        if row.get('tag') in excluded_tags:
            continue
        settings = _object(row.get('settings', {}), 'settings')
        stream = _object(row.get('streamSettings', {}), 'streamSettings')
        sockopt = _object(stream.get('sockopt', {}), 'sockopt')
        role = sockopt.get('tproxy')
        if role not in ('redirect', 'tproxy'):
            role = 'redirect' if settings.get('followRedirect') is True else None
        if role is None:
            continue  # Names alone never grant ownership (e.g. a SOCKS inbound).
        tag = row.get('tag')
        if not isinstance(tag, str) or not tag:
            raise ValueError('transparent inbound needs a tag')
        network = settings.get('allowedNetwork', settings.get('network', 'tcp,udp'))
        networks = network.split(',') if isinstance(network, str) else network
        if (not isinstance(networks, list) or not networks
                or any(n not in ('tcp', 'udp') for n in networks)):
            raise ValueError('invalid transparent inbound network')
        found.append((tag, tuple(networks)))
    return tuple(found)


def patch_inbounds(document, *, excluded_tags=()):
    result = deepcopy(document)
    roles = dict(inbound_roles(result, excluded_tags=excluded_tags))
    if not roles:
        raise ValueError('transparent inbound not found')
    if len(roles) != len(inbound_roles(result, excluded_tags=excluded_tags)):
        raise ValueError('duplicate transparent inbound tag')
    for tag in roles:
        if sum(row.get('tag') == tag for row in result['inbounds']) != 1:
            raise ValueError('duplicate inbound tag')
    for row in result['inbounds']:
        if row.get('tag') not in roles:
            continue
        sniffing = _object(row.get('sniffing', {}), 'sniffing')
        overrides = sniffing.get('destOverride', [])
        if not isinstance(overrides, list) or any(not isinstance(v, str) for v in overrides):
            raise ValueError('destOverride must be an array of strings')
        required = []
        if 'tcp' in roles[row['tag']]:
            required += ['http', 'tls']
        if 'udp' in roles[row['tag']]:
            required += ['quic']
        row['sniffing'] = dict(sniffing, enabled=True, routeOnly=True,
                               destOverride=sorted(set(overrides + required)))
    return result


def _selector(value, service):
    return (isinstance(value, str) and value.startswith('ext:')
            and '@' not in value and service in value.lower())


def patch_routing(document, *, inbound_tags, routes, proxy_outbound, voice_high=50100,
                  block_tags=()):
    """Replace owned service rules, preserving unrelated rules and front ad blocks."""
    if proxy_outbound or 'vless' in routes.values():
        direct_outbound(proxy_outbound)  # common tag validation, no proxy object generated
    if (not isinstance(inbound_tags, (list, tuple)) or not inbound_tags
            or any(not isinstance(t, str) or not t for t in inbound_tags)
            or len(set(inbound_tags)) != len(inbound_tags)):
        raise ValueError('invalid transparent inbound tags')
    for name in ('discord_tcp', 'discord_voice', 'youtube', 'telegram'):
        allowed = ('direct', 'vless', 'ws', 'unmanaged') if name == 'telegram' else ('direct', 'zapret', 'vless')
        if routes.get(name) not in allowed:
            raise ValueError('invalid route: ' + name)
    if type(voice_high) is not int or not 50000 <= voice_high <= 65535:
        raise ValueError('invalid voice port range')
    result = deepcopy(_object(document, 'config'))
    routing = _object(result.get('routing', {}), 'routing')
    original = routing.get('rules', [])
    if not isinstance(original, list) or any(not isinstance(r, dict) for r in original):
        raise ValueError('rules must be an array of objects')
    for row in original:
        for key in ('domain', 'ip'):
            if key in row and not isinstance(row[key], list):
                raise ValueError(key + ' must be an array')
    domains = {'discord': {'ext:geosite_v2fly.dat:discord'},
               'youtube': {'ext:zkeen.dat:youtube', 'ext:geosite_v2fly.dat:youtube'}}
    remaining, front = [], []
    for row in original:
        is_front = (row.get('outboundTag') in block_tags and any(
            isinstance(v, str) and v.startswith('ext:') and '@' in v
            and any(s in v.lower() for s in domains) for v in row.get('domain', [])))
        tag = row.get('ruleTag', '')
        owned_tag = isinstance(tag, str) and (tag.startswith('kdn-telegram')
                                             or tag == 'kdn-discord-voice-vless')
        if isinstance(tag, str) and tag and not owned_tag:
            # Explicit names outside our namespace identify manual rules. Keep
            # their selectors out of service discovery as well as replacement.
            (front if is_front else remaining).append(row)
            continue
        scoped_tags = row.get('inboundTag')
        if isinstance(scoped_tags, str):
            # Go StringList splits scalar values at commas without trimming.
            # Normalize only for scope checks; leave the rule's JSON untouched.
            scoped_tags = scoped_tags.split(',')
        if (isinstance(scoped_tags, list) and scoped_tags
                and any(tag not in (*inbound_tags, 'redirect', 'tproxy') for tag in scoped_tags)):
            # Service selectors on DNS/SOCKS/DSCP paths belong to their owner.
            remaining.append(row)
            continue
        for service in domains:
            domains[service].update(v for v in row.get('domain', [])
                                    if _selector(v, service) and not
                                    (service == 'discord' and 'zkeenip.dat:discord' in v.lower()))
        def only(values, service):
            return bool(values) and all(_selector(v, service) for v in values)
        voice_tags = scoped_tags
        voice_scope = (isinstance(voice_tags, list) and bool(voice_tags)
                       and all(tag in (*inbound_tags, 'redirect', 'tproxy') for tag in voice_tags))
        voice = (row.get('outboundTag') == proxy_outbound and voice_scope
                 and not row.get('ruleTag')
                 and set(row) <= {'type', 'inboundTag', 'outboundTag', 'network', 'port', 'domain', 'ip'}
                 and row.get('network') == 'udp' and row.get('port') in
                 (*VOICE_PORTS, f'3478-3481,5349,19294-19344,50000-{voice_high}')
                 and not row.get('domain') and not row.get('ip'))
        if (owned_tag
                or row.get('outboundTag') in ('discord-direct', 'youtube-direct')
                or only(row.get('domain'), 'discord') or only(row.get('ip'), 'discord')
                or (only(row.get('domain'), 'youtube') and not row.get('ip')) or voice):
            continue
        drop = False
        for key, services in (('domain', ('discord', 'youtube')), ('ip', ('discord',))):
            if row.get(key):
                row[key] = [v for v in row[key] if not any(_selector(v, s) for s in services)]
                if not row[key]:
                    drop = True  # Never widen an emptied selector to a catch-all.
        if drop:
            continue
        (front if is_front else remaining).append(row)
    def rule(outbound, **conditions):
        return dict(type='field', inboundTag=list(inbound_tags), outboundTag=outbound, **conditions)
    def target(name, direct):
        return proxy_outbound if routes[name] == 'vless' else direct
    managed = [rule(target('discord_tcp', 'discord-direct'), domain=sorted(domains['discord'])),
               rule(target('discord_voice', 'discord-direct'), network='udp',
                    port=f'3478-3481,5349,19294-19344,50000-{voice_high}'),
               rule(target('youtube', 'youtube-direct'), domain=sorted(domains['youtube']))]
    if routes['discord_voice'] == 'vless':
        managed[1]['ruleTag'] = 'kdn-discord-voice-vless'
    telegram = routes['telegram']
    if telegram != 'unmanaged':
        tg = target('telegram', 'telegram-direct')
        managed.append(rule(tg, ruleTag='kdn-telegram-domain', domain=['ext:geosite_v2fly.dat:telegram']))
        ip = ['ext:geoip_v2fly.dat:telegram']
        if telegram == 'ws':
            managed += [rule(tg, ruleTag='kdn-telegram-sniffed', ip=ip, protocol=['http', 'tls', 'quic']),
                        rule('telegram-ws', ruleTag='kdn-telegram-ip', ip=ip, network='tcp'),
                        rule(tg, ruleTag='kdn-telegram-udp', ip=ip, network='udp')]
        else:
            managed.append(rule(tg, ruleTag='kdn-telegram-ip', ip=ip))
    routing['rules'] = front + managed + remaining
    result['routing'] = routing
    return result

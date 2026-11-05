"""Native argv builders for service/preset wrappers; no eval or shell parsing."""
from kdn.engine import apply_ops, confvalues, options, status, transaction


PRESETS = {'discord': ('zapret', 'vless'), 'discord-zapret': ('zapret', 'vless'),
           'youtube': ('vless', 'zapret'), 'youtube-zapret': ('vless', 'zapret'),
           'both': ('zapret', 'zapret'), 'all-zapret': ('zapret', 'zapret'),
           'vless': ('vless', 'vless'), 'all-vless': ('vless', 'vless')}


def build(ctx, family, argv):
    """Keep routes/UDP settings under the same project lock as full apply.

    A service switch must never race another writer between reading current
    routes and applying the new selection. Its special mode resolves in apply.
    """
    fields = status.collect(ctx).fields
    udp = []
    if fields.get('udp_strategy') in ('flowseal', 'legacy'):
        udp += ['--udp-strategy', fields['udp_strategy']]
    if fields.get('udp_range') in ('wide', 'narrow'):
        udp.append('--wide-udp' if fields['udp_range'] == 'wide' else '--narrow-udp')
    if family == 'preset':
        if not argv or argv[0] not in PRESETS:
            raise ValueError('unknown routing preset')
        tcp, youtube = PRESETS[argv[0]]
        return ['--apply', '--discord-route', tcp, '--youtube-route', youtube, *udp, *argv[1:]]
    if family != 'service' or len(argv) < 2:
        raise ValueError('expected service and route')
    service, requested, *extra = argv
    if service not in ('discord', 'discord-tcp', 'discord-voice', 'youtube', 'telegram'):
        raise ValueError('unsupported service')
    aliases = {'vpn': 'vless', 'off': 'unmanaged'}
    route = aliases.get(requested, requested)
    allowed = ('direct', 'vless', 'ws', 'unmanaged') if service == 'telegram' else ('direct', 'zapret', 'vless')
    if route not in allowed:
        raise ValueError('unsupported route for service')
    values = {name: fields.get(key) for name, key in (
        ('discord-tcp', 'discord_tcp_route'), ('discord-voice', 'discord_voice_route'),
        ('youtube', 'youtube_route'), ('telegram', 'telegram_route'))}
    for name in ('discord-tcp', 'discord-voice', 'youtube'):
        if values[name] not in ('direct', 'zapret', 'vless'):
            raise ValueError('cannot determine current ' + name + ' route; no changes made')
    if values['telegram'] == 'zapret':
        values['telegram'] = 'direct'  # Historical header only.
    if values['telegram'] not in ('direct', 'vless', 'ws', 'unmanaged'):
        values['telegram'] = 'unmanaged'
    if service == 'discord':
        values['discord-tcp'] = values['discord-voice'] = route
    else:
        values[service] = route
    generated = ['--apply']
    for name, value in values.items():
        generated += ['--' + name + '-route', value]
    return generated + udp + extra


def operation(tx, family, argv):
    # Delayed import through cli keeps the engine's read-only import budget.
    ctx = tx.ctx
    generated = build(ctx, family, argv)
    parsed = options.parse_args(generated)
    if parsed.mode != 'apply' or not parsed.confirmed:
        raise ValueError('route switch requires --yes-router and apply-only options')
    ctx.argv, ctx.options = generated, parsed
    ctx.resolved = options.resolve(parsed, confvalues.read_text(ctx.paths.nfqws_conf))
    return apply_ops.operation(tx)


def run(ctx, family, argv):
    return transaction.execute(ctx, lambda tx: operation(tx, family, argv))

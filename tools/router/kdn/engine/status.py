"""Ordered read-only status fields and the legacy-compatible text report."""

import os
import json

from kdn.common import xkeen
from kdn.engine import config, confvalues, snapshots, statusblocks, system, xrayconf

STATUS_SCHEMA = 1


class StatusError(Exception):
    """A fatal guard error; an unknown core is a diagnostic, not a fatal error."""


class StatusReport:
    # Slots rather than dataclass: the shared CLI must keep its import budget.
    __slots__ = ('fields', 'snapshots', 'xkeen_output', 'warnings', '_standalone')

    def __init__(self, standalone=False):
        self.fields = {}
        self.snapshots = None
        self.xkeen_output = None
        self.warnings = []
        self._standalone = standalone


def _legacy_deployment_fields(paths, standalone):
    """One seam for the legacy standalone/integrated branches, removed in phase 6."""
    names = ('proxy_dns', 'proxy_router', 'ipv6_support', 'mode_proxy', 'policy_mark', 'dscp_exclude',
             'dscp_proxy', 'start_auto', 'table_mark', 'custom_mark', 'xkeen_port_proxying', 'xkeen_port_exclude')
    if standalone:
        return {name: 'route-detected' if name == 'ipv6_support' else 'unmanaged' for name in names}
    result = {}
    for name in names:
        if name == 'xkeen_port_proxying':
            result[name] = confvalues.active_ports(confvalues.read_text(paths.xkeen_port_proxying))
        elif name == 'xkeen_port_exclude':
            result[name] = confvalues.active_ports(confvalues.read_text(paths.xkeen_port_exclude))
        elif name in ('mode_proxy', 'policy_mark', 'dscp_exclude', 'dscp_proxy'):
            result[name] = confvalues.xkeen_effective_value(paths, name)
        else:
            result[name] = confvalues.init_value(paths, name)
    return result


def collect_fields(ctx):
    paths, env = ctx.paths, ctx.environ
    if not system.is_router(paths, paths.test_root):
        raise StatusError('ERROR: this does not look like a Keenetic Entware environment.')
    text = confvalues.read_text(paths.nfqws_conf)
    recorded_mode = confvalues.recorded_deployment_mode(text)
    standalone = ctx.resolved.standalone or recorded_mode == 'standalone-zapret'
    report = StatusReport(standalone)
    if standalone:
        core = 'standalone'
    else:
        core = ctx.resolved.core_requested
        if core == 'auto':
            core = confvalues.init_value(paths, 'name_client')
        if core not in ('xray', 'mihomo'):
            report.warnings.append(f"ERROR: XKeen core is '{core}'; expected xray or mihomo.")

    routes = {service: 'unknown' for service in ('discord-tcp', 'discord-voice', 'youtube')}
    recorded = {service: confvalues.recorded_route(text, service) for service in routes}
    routing_path = xrayconf.routing_file(paths.xray_config_dir) if core == 'xray' else None
    routing = xrayconf.load_strict(routing_path) if routing_path is not None else None
    if core == 'xray':
        if routing_path is not None:
            for service, predicate in (('discord-tcp', xrayconf.discord_tcp_direct),
                                       ('discord-voice', xrayconf.discord_voice_direct), ('youtube', xrayconf.youtube_direct)):
                routes[service] = (recorded[service] if recorded[service] in ('zapret', 'direct') else 'direct') if predicate(routing) else 'vless'
    else:
        for service in routes:
            routes[service] = recorded[service] or 'unknown'

    fields = report.fields
    fields['project'] = config.PROJECT
    fields['script_version'] = config.SCRIPT_VERSION
    fields['deployment_mode'] = recorded_mode or ('standalone' if standalone else 'integrated')
    fields['detected_core'] = core or 'unknown'
    fields['discord_route'] = routes['discord-tcp'] if routes['discord-tcp'] == routes['discord-voice'] else 'mixed'
    fields['discord_tcp_route'] = routes['discord-tcp']
    fields['discord_voice_route'] = routes['discord-voice']
    telegram = confvalues.recorded_telegram_route(text)
    if core == 'xray' and routing_path is not None:
        outbound = xrayconf.telegram_outbound(routing)
        if not outbound:
            telegram = 'unmanaged'
        elif outbound == 'telegram-ws':
            telegram = 'ws'
        elif outbound == 'telegram-direct':
            telegram = telegram if telegram in ('direct', 'zapret') else 'direct'
        else:
            telegram = 'vless'
    fields['telegram_route'] = telegram
    if os.path.isfile(paths.nfqws_conf):
        strategy, udp_range = confvalues.recorded_udp_settings(text, confvalues.nfqws_value(paths, 'UDP_PORTS'))
        fields['udp_strategy'] = strategy or 'unknown'
        fields['udp_range'] = udp_range
        voice = confvalues.voice_profile_header(text)
        if voice is not None:
            fields['discord_voice_profile'] = 'imported:' + voice[0]
            fields['discord_voice_udp'] = voice[1]
        else:
            fields['discord_voice_profile'] = 'builtin'
        fields['proxy_outbound'] = confvalues.recorded_proxy_outbound(text) or ''
    else:
        fields['udp_strategy'] = 'unknown'
        fields['udp_range'] = 'unknown'
    fields['youtube_route'] = routes['youtube']
    fields.update(_legacy_deployment_fields(paths, standalone))
    fields['nfqws_package'] = system.package_version('nfqws2-keenetic', env)
    fields['xkeen_runtime'] = ('unmanaged' if standalone else
                               'running' if system.process_running('xray', env) or system.process_running('mihomo', env) else 'stopped')
    fields['nfqws_runtime'] = 'running' if system.nfqws_running(paths, env, paths.test_root,
                                                            lambda key: confvalues.nfqws_value(paths, key)) else 'stopped'
    return report


def collect_tail(ctx, report):
    report.snapshots = snapshots.describe(ctx.paths)
    if not report._standalone and system.have('xkeen', ctx.environ):
        output = []
        for option in ('-status', '-cp', '-cpe', '-tp'):
            done = system.run(['xkeen', option], ctx.environ, config.timeout('xkeen_status', ctx.environ))
            if done.timed_out:
                report.warnings.append('WARNING: xkeen ' + option + ' timed out.')
            else:
                output.append(done.stdout)
        report.xkeen_output = ''.join(output)


def collect(ctx):
    report = collect_fields(ctx)
    collect_tail(ctx, report)
    return report


def render_text(report):
    text = ''.join(key + '=' + value + '\n' for key, value in report.fields.items())
    if report.snapshots is not None:
        text += ''.join(line + '\n' for line in snapshots.lines(report.snapshots))
    if report.xkeen_output is not None:
        text += '\n' + report.xkeen_output
    return text


def _json_lock(path):
    # Narrow JSON-only architecture exception: lock imports dataclasses/proc;
    # loading it for text modes would violate the router import budget.
    from kdn.common import lock
    state = lock.inspect_lock(path)
    return {'exists': state.exists, 'pid': state.pid, 'alive': state.alive}


def render_json(report, blocks):
    snap = report.snapshots
    document = {'schema': STATUS_SCHEMA, 'text': render_text(report), 'fields': report.fields,
                'snapshots': {name: getattr(snap, name) for name in ('state_dir', 'baseline', 'xkeen_baseline', 'latest_preapply')} if snap else None,
                'xkeen_output': report.xkeen_output, 'warnings': report.warnings, **blocks}
    # Surrogateescape bytes remain representable as JSON escapes; valid Unicode
    # stays literal UTF-8. Never emit an invalid UTF-8 JSON document.
    return (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode('utf-8', 'backslashreplace').decode('utf-8')


def run(ctx):
    try:
        xkeen.require(environ=ctx.environ)
    except xkeen.UnsupportedXKeen:
        if ctx.options is not None and ctx.options.json:
            ctx.console.out(json.dumps(xkeen.error_status(), ensure_ascii=False))
        else:
            ctx.console.err(xkeen.MESSAGE)
        return 2
    try:
        report = collect(ctx)
    except StatusError as error:
        ctx.console.err(str(error))
        return 1
    for warning in report.warnings:
        ctx.console.err(warning)
    if ctx.options is not None and ctx.options.json:
        blocks = {'lock': _json_lock(ctx.paths.lock_dir), 'xkeen': statusblocks.xkeen_block(ctx), 'xray': statusblocks.xray_block(ctx)}
        ctx.console.out(render_json(report, blocks), end='')
    else:
        ctx.console.out(render_text(report), end='')
    return 0

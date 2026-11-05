"""--preflight: hands the run to the shell engine until the mode is ported (task 17)."""

import os

from kdn.engine import config, confvalues, findings, legacy, preflight_wan, preflight_xray, system


REQUIRED_COMMANDS = ('opkg', 'awk', 'sed', 'grep', 'tr', 'sort', 'mktemp', 'cp', 'mv', 'rm', 'find', 'ls', 'dirname', 'ip')


def _error(state, message):
    # Findings carry exact output bytes as text, including the final LF.
    state.findings.append(findings.Finding('err', message + '\n'))
    state.errors += 1


def _legacy_deployment_needs(ctx):
    if ctx.resolved.standalone:
        return False
    core = ctx.resolved.core_requested
    return core == 'mihomo' or (core == 'auto' and confvalues.init_value(ctx.paths, 'name_client') == 'mihomo')


def needs_legacy(ctx):
    return _legacy_deployment_needs(ctx)


def check_requirements(ctx, state):
    paths, env, request = ctx.paths, ctx.environ, ctx.resolved
    if not system.is_router(paths, paths.test_root):
        _error(state, 'ERROR: this does not look like a Keenetic Entware environment.')
    for name in REQUIRED_COMMANDS:
        if not system.have(name, env):
            _error(state, 'ERROR: required command not found: ' + name)
    if not request.standalone and not system.have('xkeen', env):
        _error(state, 'ERROR: xkeen command not found.')
    if not request.standalone and not system.have('jq', env):
        _error(state, 'ERROR: jq is required to patch and validate routing safely.')
    if request.discord_voice_route == 'zapret' and request.udp_strategy == 'flowseal':
        path = paths.source_discord_udp_blob
        if not os.path.isfile(path):
            _error(state, 'ERROR: Flowseal Discord UDP blob is missing: ' + path)
        elif not system.have('sha256sum', env):
            _error(state, 'ERROR: sha256sum is required to verify the Flowseal Discord UDP blob.')
        else:
            import hashlib
            try:
                with open(path, 'rb') as stream:
                    actual = hashlib.sha256(stream.read()).hexdigest()
            except OSError:
                actual = ''
            if actual != config.DISCORD_UDP_BLOB_SHA256:
                _error(state, 'ERROR: Flowseal Discord UDP blob checksum mismatch.\n'
                       '       Expected: ' + config.DISCORD_UDP_BLOB_SHA256 + '\n       Actual:   ' + actual)
    if not paths.test_root and system.package_present('wget-ssl', env):
        done = system.run(['wget', '--version'], env, config.timeout('wget', env), merge_stderr=True) if system.have('wget', env) else None
        if done is None or done.timed_out or '+https' not in done.stdout:
            _error(state, 'ERROR: wget-ssl is installed but an HTTPS-capable wget is not first in PATH.\n'
                   '       Expected /opt/bin/wget before /opt/usr/bin/busybox wget.')
    if not request.standalone and not os.path.isfile(paths.xkeen_init):
        _error(state, 'ERROR: XKeen init file not found: ' + paths.xkeen_init)


def detect_core(ctx, state):
    if state.errors:
        return
    if ctx.resolved.standalone:
        state.detected_core = 'standalone'
        return
    core = ctx.resolved.core_requested
    state.detected_core = confvalues.init_value(ctx.paths, 'name_client') if core == 'auto' else core
    if state.detected_core not in ('xray', 'mihomo'):
        _error(state, "ERROR: XKeen core is '" + state.detected_core + "'; expected xray or mihomo.")


def render_ok(ctx, state):
    request = ctx.resolved
    text = ('Preflight OK. Deployment: standalone nfqws2 (XKeen unmanaged)\n' if request.standalone
            else 'Preflight OK. XKeen core: ' + state.detected_core + '\n')
    text += 'Routes: ' + request.routes_summary() + '\n'
    if state.detected_core == 'xray':
        text += 'Xray discord-direct mark: ' + (state.direct_mark or 'none') + '\n'
        text += 'Xray proxy outbound: ' + (state.proxy_outbound or 'not needed') + '\n'
    text += 'nfqws2 WAN interface(s): ' + state.wan + '\n'
    text += 'nfqws2 IPv6: ' + ('enabled' if state.ipv6 == '1' else 'disabled') + '\n'
    if not request.standalone:
        text += ('XKeen settings: mode=' + confvalues.xkeen_effective_value(ctx.paths, 'mode_proxy')
                 + ', policy_mark=' + confvalues.xkeen_effective_value(ctx.paths, 'policy_mark')
                 + ', proxy_dns=' + confvalues.init_value(ctx.paths, 'proxy_dns')
                 + ', proxy_router=' + confvalues.init_value(ctx.paths, 'proxy_router')
                 + ', ipv6_support=' + confvalues.init_value(ctx.paths, 'ipv6_support')
                 + ', dscp_exclude=' + confvalues.xkeen_effective_value(ctx.paths, 'dscp_exclude')
                 + ', dscp_proxy=' + confvalues.xkeen_effective_value(ctx.paths, 'dscp_proxy') + '\n')
    return text


def run(ctx):
    if needs_legacy(ctx):
        return legacy.exec_legacy(ctx)
    state = findings.State()
    check_requirements(ctx, state)
    detect_core(ctx, state)
    request = ctx.resolved
    if not state.errors and state.detected_core == 'xray':
        xray = preflight_xray.XrayRequest({'tcp': request.discord_tcp_route, 'voice': request.discord_voice_route,
                                          'youtube': request.youtube_route}, request.direct_mark_requested,
                                         request.proxy_outbound_requested, request.telegram_route, ctx.paths.test_root)
        preflight_xray.check(ctx.paths, ctx.environ, xray, state)
    wan = preflight_wan.WanRequest(request.wan_interface_requested, request.standalone, state.direct_mark,
                                   state.detected_core, request.xkeen_required_ports, ctx.paths.test_root)
    preflight_wan.check(ctx.paths, ctx.environ, wan, state)
    for item in state.findings:
        getattr(ctx.console, item.stream)(item.text, end='')
    if state.errors:
        ctx.console.err(f'Preflight failed with {state.errors} error(s).')
        return 1
    ctx.console.out(render_ok(ctx, state), end='')
    return 0

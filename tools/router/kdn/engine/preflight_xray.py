"""Read-only Xray preflight checks; activation belongs to task 20b."""
import os
import re

from kdn.engine import config, confvalues, findings, nfqws_marks, system, xrayconf


class XrayRequest:
    __slots__ = ('routes', 'direct_mark_requested', 'proxy_outbound_requested', 'telegram_route', 'test_root')

    def __init__(self, routes, direct_mark_requested='', proxy_outbound_requested='', telegram_route='unmanaged', test_root=''):
        self.routes = routes
        self.direct_mark_requested = direct_mark_requested
        self.proxy_outbound_requested = proxy_outbound_requested
        self.telegram_route = telegram_route
        self.test_root = test_root


class XrayCheckError(Exception):
    pass


def valid_decimal_mark(text):
    if not re.fullmatch('[0-9]+', text):
        return False
    digits = text.lstrip('0') or '0'
    return len(digits) <= 10 and 1 <= int(digits) <= 4294967295


def resolve_direct_mark(paths, request, environ=None):
    if request.direct_mark_requested:
        if not valid_decimal_mark(request.direct_mark_requested):
            raise XrayCheckError('ERROR: --direct-mark must be a decimal integer from 1 to 4294967295.\n')
        mark = request.direct_mark_requested
    else:
        mark = xrayconf.freedom_mark(paths.xray_config_dir)
        if mark and not valid_decimal_mark(mark):
            raise XrayCheckError('ERROR: existing Xray Freedom mark is not a valid decimal number: ' + mark + '\n')
        if not mark:
            mark = '255' if confvalues.init_value(paths, 'proxy_router') == 'on' else ''
    try:
        # An omitted Freedom mark leaves the socket at kernel mark zero. Check
        # its actual behavior without changing the user's empty setting.
        nfqws_marks.validate(paths, mark or '0', environ)
    except nfqws_marks.MarkError as error:
        raise XrayCheckError('ERROR: ' + str(error) + '.\n') from error
    return mark


def resolve_proxy_outbound(paths, request):
    tag = request.proxy_outbound_requested
    if not tag:
        recorded = confvalues.recorded_proxy_outbound(confvalues.read_text(paths.nfqws_conf))
        if recorded and xrayconf.proxy_outbound_tag_exists(paths.xray_config_dir, recorded):
            tag = recorded
    if not tag:
        tag = xrayconf.discover_proxy_outbound(paths.xray_config_dir)
    if not tag:
        raise XrayCheckError('ERROR: cannot detect the Xray proxy outbound for vless routing.\n'
                             '       Pass it explicitly with --proxy-outbound TAG.\n')
    if not xrayconf.proxy_outbound_tag_exists(paths.xray_config_dir, tag):
        raise XrayCheckError('ERROR: Xray proxy outbound tag not found: ' + tag + '\n')
    return tag


def telegram_dat_present(paths, request):
    if request.telegram_route == 'unmanaged' or not os.path.isdir(paths.xray_dat_dir):
        return
    for name in ('geosite_v2fly.dat', 'geoip_v2fly.dat'):
        path = os.path.join(paths.xray_dat_dir, name)
        try:
            present = os.stat(path).st_size > 0  # shell -s follows symlinks
        except OSError:
            present = False
        if not present:
            raise XrayCheckError('ERROR: Telegram routing needs ' + path + ' (ext:' + name + ':telegram).\n')


def telegram_ws_ready(paths, environ):
    python = paths.telegram_ws_python
    done = system.run([python, '-c', 'import asyncio, ssl'], environ, config.timeout('python_check', environ)) if os.access(python, os.X_OK) else None
    if done is None or done.returncode != 0 or done.timed_out:
        raise XrayCheckError('ERROR: Telegram WS needs ' + python + ' with ssl and asyncio (opkg install python3 python3-openssl).\n')
    if not os.path.isfile(paths.telegram_ws_relay):
        raise XrayCheckError('ERROR: Telegram WS relay is missing: ' + paths.telegram_ws_relay + '\n')


def _tail20(text):
    lines = text.split('\n')
    if lines[-1] == '':
        lines.pop()
        return '\n'.join(lines[-20:]) + ('\n' if lines else '')
    return '\n'.join(lines[-20:])


def xray_test_config(paths, environ):
    binary = system.find_xray(paths, environ)
    if binary is None:
        return 'ERROR: xray binary not found for the configuration test.\n'
    timeout = config.timeout('xray_test', environ)
    done = system.run([str(binary), 'run', '-test', '-confdir', paths.xray_config_dir, '-format', 'json'],
                      dict(environ, XRAY_LOCATION_ASSET=paths.xray_dat_dir), timeout, merge_stderr=True)
    if done.timed_out:
        return f'ERROR: Xray configuration test timed out after {timeout:g}s.\n'
    if done.returncode:
        return 'ERROR: Xray configuration test failed:\n' + _tail20(done.stdout)
    return None


def check(paths, environ, request, state):
    if state.errors:
        return
    try:
        if not os.path.isdir(paths.xray_config_dir):
            raise XrayCheckError('ERROR: Xray config directory not found: ' + paths.xray_config_dir + '\n')
        routes = tuple(request.routes.values()) + (request.telegram_route,)
        if any(route in ('direct', 'zapret', 'ws') for route in routes):
            state.direct_mark = resolve_direct_mark(paths, request, environ)
        if 'vless' in routes:
            state.proxy_outbound = resolve_proxy_outbound(paths, request)
        telegram_dat_present(paths, request)
        if request.telegram_route == 'ws':
            telegram_ws_ready(paths, environ)
        failed = xray_test_config(paths, environ)
        if failed is not None:
            raise XrayCheckError(failed + "ERROR: current Xray configuration fails 'xray -test'.\n")
    except XrayCheckError as error:
        state.findings.append(findings.Finding('err', str(error)))
        state.errors += 1
        return
    if not state.proxy_outbound:
        try:
            state.proxy_outbound = resolve_proxy_outbound(paths, request)
        except XrayCheckError:
            state.proxy_outbound = ''

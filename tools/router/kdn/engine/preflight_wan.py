"""Read-only WAN/policy/port checks; never changes routes or interfaces."""
import re

from kdn.engine import config, confvalues, findings, system


NDMC = '/bin/ndmc'


class WanRequest:
    __slots__ = ('wan_interface_requested', 'standalone', 'direct_mark_effective', 'detected_core', 'required_ports', 'test_root')

    def __init__(self, wan_interface_requested='', standalone=False, direct_mark_effective='', detected_core='xray', required_ports='', test_root=''):
        self.wan_interface_requested = wan_interface_requested
        self.standalone = standalone
        self.direct_mark_effective = direct_mark_effective
        self.detected_core = detected_core
        self.required_ports = required_ports
        self.test_root = test_root


class WanError(Exception):
    pass


def _words(value):
    return [word for word in re.split('[ \t\n]+', value) if word]


def interface_list_contains(interfaces, wanted):
    return wanted in _words(interfaces)


def route_interface(mark, environ, v6=False):
    prefix = ['ip', '-6'] if v6 else ['ip']
    address = '2001:4860:4860::8888' if v6 else '1.1.1.1'
    output = ''
    if mark and mark != '255':
        output = system.run(prefix + ['route', 'get', address, 'mark', mark], environ, config.timeout('ip', environ)).stdout.replace('\0', '').rstrip('\n')
    if not output:
        output = system.run(prefix + ['route', 'get', address], environ, config.timeout('ip', environ)).stdout.replace('\0', '').rstrip('\n')
    if not output:
        output = system.run(prefix + ['route', 'show', 'default'], environ, config.timeout('ip', environ)).stdout.split('\n', 1)[0].replace('\0', '')
    if any(word in ' ' + output + ' ' for word in (' unreachable ', ' blackhole ', ' prohibit ', ' error ', ' dev lo ')):
        return ''
    for line in confvalues.lines(output):
        words = confvalues.fields(line)
        for index, word in enumerate(words[:-1]):
            if word == 'dev':
                return words[index + 1]
    return ''


def route_interface_v6(mark, environ):
    return route_interface(mark, environ, v6=True)


def validate_wan_interfaces(interfaces, environ):
    if not interfaces:
        raise WanError('')
    for name in _words(interfaces):
        if not re.fullmatch('[A-Za-z0-9_.:-]+', name):
            raise WanError('ERROR: invalid WAN interface name: ' + name + '\n')
        if name == 'lo':
            raise WanError('ERROR: loopback cannot be used as an nfqws2 WAN interface.\n')
        if system.run(['ip', 'link', 'show', 'dev', name], environ, config.timeout('ip', environ)).returncode:
            raise WanError('ERROR: WAN interface does not exist: ' + name + '\n')


def resolve_wan_interfaces(paths, environ, request, state):
    mark = request.direct_mark_effective
    state.wan, state.ipv6 = '', '0'
    v6 = ''
    if request.standalone or confvalues.init_value(paths, 'ipv6_support') == 'on':
        v6 = route_interface_v6('' if request.standalone else mark, environ)
        if v6:
            state.ipv6 = '1'
        elif not request.standalone:
            state.findings.append(findings.Finding('err', 'WARNING: XKeen IPv6 support is on, but no usable IPv6 WAN route exists.\n'
                                                         '         nfqws2 IPv6 processing will remain disabled.\n'))
    existing = ''
    if request.wan_interface_requested:
        state.wan = request.wan_interface_requested
    else:
        existing = confvalues.nfqws_value(paths, 'ISP_INTERFACE')
        state.wan = existing
        if not existing:
            state.wan = route_interface(mark, environ)
            if v6 and (' ' + v6 + ' ') not in (' ' + state.wan + ' '):
                state.wan += ' ' + v6
    if not state.wan:
        raise WanError('ERROR: cannot determine WAN interface for nfqws2.\n       Pass it explicitly with --wan-interface IFACE.\n')
    validate_wan_interfaces(state.wan, environ)
    if existing and not request.wan_interface_requested:
        for label, expected in (('IPv4', route_interface(mark, environ)), ('IPv6', v6)):
            if expected and not interface_list_contains(state.wan, expected):
                raise WanError('ERROR: existing nfqws2 ISP_INTERFACE misses routed ' + label + ' WAN: ' + expected + '\n'
                               '       Pass the intended list with --wan-interface "IFACE1 IFACE2".\n')


def check_unbound_policy(paths, environ, request, state):
    if not request.test_root:
        output = system.run([NDMC, '-c', 'show ip policy'], environ, config.timeout('ndmc', environ)).stdout
        if ('description = ' + config.UNBOUND_POLICY_NAME + ':').lower() in output.lower():
            state.findings.append(findings.Finding('err', 'ERROR: reserved unbound policy name already exists: ' + config.UNBOUND_POLICY_NAME + '\n'
                                                   '       Rename that Keenetic policy before applying this profile.\n'))
            state.errors += 1


def check_port_exclusion(paths, request, state):
    if request.standalone:
        return
    proxying = confvalues.active_ports(confvalues.read_text(paths.xkeen_port_proxying))
    excluded = confvalues.active_ports(confvalues.read_text(paths.xkeen_port_exclude))
    if not proxying and excluded and confvalues.ports_overlap(excluded, request.required_ports):
        state.findings.append(findings.Finding('err', 'ERROR: XKeen port_exclude.lst overlaps required Discord ports.\n'
                                               '       Resolve exclusions manually; the script will not silently weaken them.\n'))
        state.errors += 1


def check(paths, environ, request, state):
    if not state.errors:
        try:
            resolve_wan_interfaces(paths, environ, request, state)
        except WanError as error:
            state.findings.append(findings.Finding('err', str(error)))
            state.errors += 1
    check_unbound_policy(paths, environ, request, state)
    check_port_exclusion(paths, request, state)

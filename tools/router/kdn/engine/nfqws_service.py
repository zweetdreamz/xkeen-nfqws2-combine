"""nfqws2-only service operations; no XKeen restart or firewall writes here."""
import os
import shlex
import time

from kdn.engine import checks, compose, config, confvalues, nfqws_marks, nfqws_process, system


class ServiceError(RuntimeError):
    pass


def pid(ctx):
    return system.nfqws_service_pid(ctx.paths, ctx.environ, ctx.paths.test_root,
                                    lambda key: confvalues.nfqws_value(ctx.paths, key))


def action(ctx, verb):
    if verb not in ('start', 'stop', 'restart'):
        raise ValueError('unsupported nfqws action')
    if not os.path.isfile(ctx.paths.nfqws_init) or not os.access(ctx.paths.nfqws_init, os.X_OK):
        if verb == 'stop' and pid(ctx) is None:
            return
        raise ServiceError('nfqws2 init script is missing: ' + ctx.paths.nfqws_init)
    done = nfqws_process.run([ctx.paths.nfqws_init, verb], ctx.environ,
                            timeout=min(120, config.timeout('xray_test', ctx.environ)), cwd='/')
    if verb == 'stop' and not done.timed_out and not done.output_limited:
        if pid(ctx) is None:
            return
        raise ServiceError('nfqws2 is still running after stop')
    if done.returncode or done.timed_out or done.output_limited:
        raise ServiceError('nfqws2 init ' + verb + ' failed (exit ' + str(done.returncode) + ')')


def _ports(text):
    spans, invalid = checks.port_ranges(text)
    if invalid or any(not 1 <= low <= high <= 65535 for low, high in spans):
        raise ServiceError('invalid NFQUEUE port list')
    return frozenset(port for low, high in spans for port in range(int(low), int(high) + 1))


def _rule_options(row):
    """Parse the small iptables-save subset whose coverage we can establish."""
    aliases = {'--protocol': '-p', '--out-interface': '-o', '--in-interface': '-i',
               '--jump': '-j', '--destination-ports': '--dports', '--destination-port': '--dports',
               '--dport': '--dports', '--source-ports': '--sports', '--source-port': '--sports',
               '--sport': '--sports'}
    arities = dict.fromkeys(('-A', '-p', '-o', '-i', '-j', '-m', '--dports', '--sports',
                             '--queue-num', '--connbytes', '--connbytes-dir', '--connbytes-mode',
                             '--mark', '--comment'), 1)
    arities.update({'--tcp-flags': 2, '--queue-bypass': 0, '--syn': 0})
    try:
        words = shlex.split(row)
    except ValueError:
        return None
    options, index = {}, 0
    while index < len(words):
        negated = words[index] == '!'
        if negated:
            index += 1
            if index == len(words):
                return None
        name, equal, value = words[index].partition('=')
        name = aliases.get(name, name)
        arity = arities.get(name)
        if arity is None or (equal and arity != 1):
            return None
        index += 1
        if equal:
            values = [value]
        else:
            values = words[index:index + arity]
            index += arity
        if len(values) != arity or (name != '--comment' and any(
                part == '!' or part.startswith('-') for part in values)):
            return None
        if name == '-m':
            if negated or values[0] not in ('tcp', 'udp', 'multiport', 'connbytes', 'mark', 'comment'):
                return None
            continue
        # A negated transport/interface/port/range only describes a subset.
        # The package deliberately negates its processed-packet mark.
        if (negated and name != '--mark') or name in options:
            return None
        options[name] = (*values, negated) if name == '--mark' else tuple(values)
    return options


def _payload_rule(options, direction):
    if '--syn' in options:
        return False
    if '--tcp-flags' in options and any(value.upper() not in ('NONE', '0', '0x0')
                                       for value in options['--tcp-flags']):
        return False
    connection = {name for name in options if name.startswith('--connbytes')}
    if not connection:
        return True  # An unconditional queue also covers payload packets.
    if (connection != {'--connbytes', '--connbytes-dir', '--connbytes-mode'}
            or options['--connbytes-dir'] != (direction,)
            or options['--connbytes-mode'] != ('packets',)):
        return False
    bounds = options['--connbytes'][0].split(':')
    return (len(bounds) == 2 and all(part.isascii() and part.isdecimal() for part in bounds)
            and all(len(part.lstrip('0') or '0') <= 20 for part in bounds)
            and int(bounds[0].lstrip('0') or '0') <= 1 and int(bounds[1].lstrip('0') or '0') >= 15)


def _mark_coverage(options, processed):
    selector = options.get('--mark')
    if selector is None:
        return True
    text, negated = selector
    try:
        selected = nfqws_marks.processed_mask(text)
    except nfqws_marks.MarkError:
        return False
    if not negated:
        return selected[1] == 0  # Equality with an empty mask matches all marks.
    # The package excludes already processed packets. Every other mark limiter
    # is unproven: it could also exclude allowed Direct/policy traffic.
    return selected == processed and processed[1] != 0


def verify_rules(text, interface, tcp, udp, queue=None, *, processed_mark=nfqws_marks.DEFAULT_PROCESSED):
    """Prove outbound payload and inbound reply coverage for one WAN/family.

    Flag-only rules supplement the connbytes data rules in the package; they
    cannot establish data coverage. Unknown/restricted selectors fail closed.
    """
    try:
        processed = nfqws_marks.processed_mask(processed_mark)
    except nfqws_marks.MarkError as error:
        raise ServiceError('cannot establish effective firewall processed mark') from error
    rules = [options for row in text.splitlines() if (options := _rule_options(row)) is not None]
    for hook, chain in (('POSTROUTING', 'nfqws_post'), ('PREROUTING', 'nfqws_pre')):
        if not any(options.get('-A') == (hook,) and options.get('-j') == (chain,)
                   and not set(options) - {'-A', '-j', '--comment'} for options in rules):
            raise ServiceError('nfqws2 hook is missing: ' + hook + ' -> ' + chain)
    for chain, iface_option, port_option, direction in (
            ('nfqws_post', '-o', '--dports', 'original'), ('nfqws_pre', '-i', '--sports', 'reply')):
        for protocol, expected in (('tcp', tcp), ('udp', udp)):
            ports = []
            for options in rules:
                if (options.get('-A') != (chain,) or options.get('-j') != ('NFQUEUE',)
                        or options.get(iface_option) != (interface,) or options.get('-p') != (protocol,)
                        or set(options).intersection({'-i', '--sports'} if direction == 'original' else {'-o', '--dports'})
                        or not _payload_rule(options, direction)
                        or not _mark_coverage(options, processed)):
                    continue
                if queue is not None and options.get('--queue-num') != (str(queue),):
                    raise ServiceError('nfqws2 NFQUEUE number mismatch for ' + interface)
                if options.get(port_option):
                    ports.append(options[port_option][0])
            if not ports or _ports(','.join(ports)) != _ports(expected):
                raise ServiceError('nfqws2 ' + chain + ' ' + protocol + ' payload NFQUEUE ports mismatch for ' + interface)


def verify(ctx, previous_pid=None, *, attempts=5, delay=1):
    live = None
    for _ in range(attempts):
        live = pid(ctx)
        if live is not None and live != previous_pid:
            break
        live = None
        time.sleep(delay)
    if live is None:
        raise ServiceError('nfqws2 is not running as a new service process')
    composition = compose.compose(ctx.paths.nfqws_conf, ctx.paths, ctx.environ,
                                  config.timeout('compose', ctx.environ))
    values = {key: confvalues.nfqws_value(ctx.paths, key) for key in
              ('TCP_PORTS', 'UDP_PORTS', 'ISP_INTERFACE', 'IPV6_ENABLED', 'IPV6_INTERFACE', 'NFQUEUE_NUM')}
    proc_path = os.path.join(system.PROC_ROOT, str(live), 'cmdline')
    if os.path.isfile(proc_path):
        with open(proc_path, 'rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ServiceError('nfqws2 command line exceeds limit')
        actual = raw.decode('utf-8', 'surrogateescape').split('\0')
        if '--' in actual:
            raise ServiceError('running nfqws2 has an ambiguous option separator')
        queues = [token[len('--qnum='):] for token in actual if token.startswith('--qnum=')]
        queue_aliases = [token for token in actual
                         if token.startswith('--') and token != '--'
                         and '--qnum'.startswith(token.partition('=')[0]) and not token.startswith('--qnum=')]
        if queue_aliases or queues != [values['NFQUEUE_NUM'] or '300']:
            raise ServiceError('running nfqws2 must have exactly one matching NFQUEUE number')
        ignored = ('--user=', '--uid=', '--qnum=', '--pidfile=', '--daemon',
                   '--fastpath-workaround=', '--debug=', '--bind-fix4', '--bind-fix6')
        wanted = [token for token in composition.tokens if not token.startswith(ignored)]
        actual = [token for token in actual if token.startswith('--') and not token.startswith(ignored)]
        if actual != wanted:
            raise ServiceError('running nfqws2 arguments differ from current config')
    else:
        raise ServiceError('cannot read running nfqws2 command line')
    if pid(ctx) != live:
        raise ServiceError('nfqws2 process changed during verification')
    try:
        _skip, processed_mark = nfqws_marks.effective(ctx.paths, ctx.environ)
    except nfqws_marks.MarkError as error:
        raise ServiceError('cannot establish effective nfqws processed mark: ' + str(error)) from error
    families = [('iptables-save', values['ISP_INTERFACE'])]
    if values['IPV6_ENABLED'] not in ('', '0'):
        families.append(('ip6tables-save', values['IPV6_INTERFACE'] or values['ISP_INTERFACE']))
    for tool, interfaces in families:
        done = nfqws_process.run([tool, '-t', 'mangle'], ctx.environ, timeout=10, output_limit=1024 * 1024)
        if done.returncode or done.timed_out or done.output_limited:
            raise ServiceError('cannot read nfqws2 firewall rules: ' + tool)
        if not interfaces.split():
            raise ServiceError('no WAN interface configured for nfqws2')
        for interface in interfaces.split():
            verify_rules(done.output, interface, values['TCP_PORTS'], values['UDP_PORTS'], values['NFQUEUE_NUM'] or '300',
                         processed_mark=processed_mark)
    if pid(ctx) != live:
        raise ServiceError('nfqws2 process disappeared during firewall verification')
    return live


def restart(ctx):
    previous = pid(ctx)
    action(ctx, 'restart')
    return verify(ctx, previous)


def restore_state(ctx, running):
    if running not in ('0', '1'):
        raise ServiceError('invalid saved nfqws2 running state')
    action(ctx, 'stop')
    if running == '1':
        action(ctx, 'start')
        return verify(ctx)
    if pid(ctx) is not None:
        raise ServiceError('nfqws2 is still running after restoring stopped state')
    return None

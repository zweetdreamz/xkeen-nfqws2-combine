"""Upstream-shaped NFQUEUE fixtures shared by service verification tests."""


def firewall_rules(tcp='443', udp='50000:50100', interface='eth3', queue='300'):
    rows = ['-A POSTROUTING -j nfqws_post', '-A PREROUTING -j nfqws_pre']
    for chain, flag, ports_flag, direction in (('nfqws_post', '-o', '--dports', 'original'),
                                                ('nfqws_pre', '-i', '--sports', 'reply')):
        for protocol, ports in (('tcp', tcp), ('udp', udp)):
            prefix = f'-A {chain} {flag} {interface} -m mark ! --mark 0x40000000/0x40000000 -p {protocol} -m multiport {ports_flag} {ports}'
            target = f' -j NFQUEUE --queue-num {queue} --queue-bypass'
            rows.append(prefix + f' -m connbytes --connbytes 1:15 --connbytes-dir {direction} --connbytes-mode packets' + target)
            if protocol == 'tcp':
                for flags in ('FIN FIN', 'RST RST') + (('SYN,ACK SYN,ACK',) if direction == 'reply' else ()):
                    rows.append(prefix + ' -m tcp --tcp-flags ' + flags + target)
    return '\n'.join(rows)


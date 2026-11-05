"""Pure snapshot ownership/version policy. No filesystem or restore operations.

Managed means legacy snapshot coverage, NOT exclusive ownership of every byte.
Shared files still need block-aware merging. Lexical checks do not resolve links;
the future snapshot verifier must check real filesystem targets independently.
Never delete/replace a managed directory wholesale: exclusions apply to children.
"""
from kdn.common import xkeen


COMMON_TREES = ('/opt/etc/nfqws2', '/opt/var/opkg-lists')
COMMON_FILES = (
    '/opt/etc/init.d/S51nfqws2', '/opt/etc/opkg/nfqws2-keenetic.conf',
    '/opt/etc/ndm/netfilter.d/100-nfqws2.sh', '/opt/var/spool/cron/crontabs/root',
)
INTEGRATED_TREES = ('/opt/etc/xkeen', '/opt/etc/xray/configs', '/opt/etc/mihomo')
INTEGRATED_FILES = (
    '/opt/etc/init.d/S05xkeen', '/opt/etc/ndm/netfilter.d/proxy.sh',
    '/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh',
)
EXCLUDED = ('/opt/etc/xray/configs/04_outbounds.json',)


def _within(path, logical_prefix):
    return path == logical_prefix or path.startswith(logical_prefix + '/')


def path_policy(path, scope='integrated'):
    """Classify canonical logical paths; exclusions also protect malformed children.

    An excluded path is never capturable, restorable, or removable. This rule
    applies independently of snapshot age, presence records and restore scope.
    """
    if scope not in ('integrated', 'standalone'):
        raise ValueError('unsupported snapshot scope')
    if (not isinstance(path, str) or not path.startswith('/')
            or any(char in path for char in '\\|\r\n\t\0')
            or any(part in ('', '.', '..') for part in path[1:].split('/'))):
        raise ValueError('noncanonical logical path')
    if any(_within(path, root) for root in EXCLUDED):
        return 'excluded'
    trees, files = COMMON_TREES, COMMON_FILES
    if scope == 'integrated':
        trees += INTEGRATED_TREES
        files += INTEGRATED_FILES
    return 'managed' if path in files or any(_within(path, root) for root in trees) else 'unmanaged'


def versions_compatible(saved, current):
    """Conservative exact release match, not guessed compatibility by major/minor.

    Only the 2.1+ generation is a supported target (optional patch/prerelease).
    Old2.0/unknown snapshots stay inspectable but never authorise any restore,
    including port blocks or focused nfqws data. Major3 needs separate review.
    """
    return (isinstance(saved, str) and isinstance(current, str)
            and xkeen.supported(saved) and xkeen.supported(current) and saved == current)


def version_from_text(text):
    """Compatibility API for the shared pure version policy."""
    return xkeen.parse_version(text)


def xkeen_restore_policy(saved, current):
    """Intent only: even full-compatible restoration must respect exclusions."""
    if not versions_compatible(saved, current):
        raise ValueError('unsupported snapshot XKeen version or version mismatch; restoration refused')
    return 'full-compatible'

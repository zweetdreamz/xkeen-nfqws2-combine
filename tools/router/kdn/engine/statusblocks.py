"""JSON-only metadata blocks; secret values never leave the bounded config reader."""
import json

from kdn.common import jsonc, xkeen
from kdn.engine import confvalues, xrayconf


MAX_XKEEN_JSON = 1024 * 1024
INIT_KEYS = ('dscp_enable', 'dscp_force_proxy', 'dscp_force_proxy_tag', 'name_policy_full', 'nfqws_mark', 'pbr_strict')


def _eligible(ctx):
    if ctx.resolved.standalone or confvalues.recorded_deployment_mode(confvalues.read_text(ctx.paths.nfqws_conf)) == 'standalone-zapret':
        return False
    core = ctx.resolved.core_requested
    return (confvalues.init_value(ctx.paths, 'name_client') if core == 'auto' else core) == 'xray'


def _bounded_config(path):
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(MAX_XKEEN_JSON + 1)
        if len(raw) > MAX_XKEEN_JSON:
            return {}
        value = json.loads(jsonc.strip_json_comments(raw.decode('utf-8-sig')))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _walk(value):
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            yield current
            pending.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            pending.extend(reversed(current))


def xkeen_block(ctx):
    version = xkeen.require(environ=ctx.environ)
    if not _eligible(ctx):
        return None
    text = confvalues.read_text(ctx.paths.xkeen_init)
    # _assigned distinguishes an absent assignment from an explicitly empty one.
    init = {key: confvalues._assigned(text, key, False) for key in INIT_KEYS}
    generation = '.'.join(version.split('.')[:2])
    rows = list(_walk(_bounded_config(ctx.paths.xkeen_json)))
    killswitch = next((row['killswitch'] for row in rows if isinstance(row.get('killswitch'), bool)), None)
    token_set = any(bool(row.get('rci_token')) for row in rows)
    return {'version': version, 'generation': generation, 'init': init,
            'config': {'killswitch': killswitch, 'rci_token_set': token_set}}


def xray_block(ctx):
    xkeen.require(environ=ctx.environ)
    if not _eligible(ctx):
        return None
    path = xrayconf.routing_file(ctx.paths.xray_config_dir)
    return {'inbounds': xrayconf.inbounds(ctx.paths.xray_config_dir),
            'rules': xrayconf.rules_summary(xrayconf.load_strict(path) if path is not None else None)}

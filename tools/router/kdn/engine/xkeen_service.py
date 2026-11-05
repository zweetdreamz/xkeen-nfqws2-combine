"""XKeen2.1 foreground lifecycle and fail-closed E4 preflight, no shell fallback."""
import json
from pathlib import Path
import re
import time

from kdn.common import jsonc, xkeen, xray_process
from kdn.inspection import receipt
from kdn.engine import config, confvalues, nfqws_process, snapshot_store, system


def _document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('ambiguous XKeen JSON field')
            result[key] = value
        return result
    value = json.loads(jsonc.strip_json_comments(raw.decode('utf-8-sig')), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError('XKeen/Xray JSON must be an object')
    return value


def _objects(value):
    pending, count = [value], 0
    while pending:
        row = pending.pop()
        count += 1
        if count > 16384:
            raise ValueError('XKeen JSON structure exceeds budget')
        if isinstance(row, dict):
            yield row
            pending.extend(row.values())
        elif isinstance(row, list):
            pending.extend(row)


def read_policies(ctx, token):
    """Fixed loopback read; token never in argv, output, redirects or error text."""
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://127.0.0.1:79/rci/show/ip/policy',
                                     headers={'X-Ndma-Tkn': token})
    try:
        deadline = time.monotonic() + 10
        with opener.open(request, timeout=5) as response:
            raw = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError('RCI policy read exceeded deadline')
                chunk = response.read1(min(65536, 1024 * 1024 + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > 1024 * 1024:
                    raise ValueError('RCI policy response exceeds budget')
            if response.status != 200 or len(raw) > 1024 * 1024:
                raise ValueError('RCI policy response is invalid or too large')
        value = json.loads(raw)
    except (OSError, ValueError, urllib.error.URLError, RecursionError) as error:
        raise ValueError('RCI policy access failed; check router token/readiness') from error
    if not isinstance(value, (dict, list)):
        raise ValueError('RCI policy response is not structured JSON')
    return value


def policy_marks(policies):
    result = set()
    for row in _objects(policies):
        # Keenetic policy `mark` is a hexadecimal string, optionally prefixed.
        value = row.get('mark')
        if isinstance(value, str) and re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,8}', value):
            number = int(value, 16)
            if 0 < number <= 2147483647 and number != 255:
                result.add(number)
    return result


def preflight(ctx, *, mark=None, plan=None):
    if ctx.resolved.standalone or ctx.resolved.core_requested not in ('auto', 'xray'):
        raise ValueError('native apply supports only integrated Xray on XKeen2.1+')
    nfqws_process.service_capture_ready()
    version = xkeen.require(environ=ctx.environ)
    if confvalues.init_value(ctx.paths, 'name_client') != 'xray':
        raise ValueError('XKeen must be configured for Xray')
    raw = snapshot_store._read(ctx.paths.xkeen_json, 1024 * 1024)
    document = _document(raw)
    tokens = [row['rci_token'] for row in _objects(document) if 'rci_token' in row]
    if (len(tokens) != 1 or not isinstance(tokens[0], str) or not tokens[0].strip()
            or any(ord(char) < 33 or ord(char) > 126 for char in tokens[0])):
        raise ValueError('one nonempty RCI token is required; token values are never logged')
    policies = read_policies(ctx, tokens[0])
    strict = confvalues.init_value(ctx.paths, 'pbr_strict')
    if strict not in ('on', 'off'):
        raise ValueError('XKeen2.1 pbr_strict setting is missing or invalid')
    if strict == 'on':
        allowed = policy_marks(policies)
        if not allowed:
            raise ValueError('pbr_strict needs known Keenetic policy marks')
        if plan is not None:
            corpus = {name: data for name, data, _mode in plan.corpus}
            for item in plan.changes:
                if item.logical.startswith('/opt/etc/xray/configs/'):
                    corpus[Path(item.logical).name] = item.after
            for data in corpus.values():
                if data is None:
                    continue
                for outbound in _document(data).get('outbounds', []):
                    if outbound.get('protocol') in ('blackhole', 'loopback'):
                        continue
                    stream = outbound.get('streamSettings') or {}
                    sockopt = stream.get('sockopt') or {}
                    value = sockopt.get('mark')
                    if type(value) is not int or value not in allowed:
                        raise ValueError('pbr_strict: an outbound lacks an allowed int32 policy mark')
    for row in _objects(policies):
        description = row.get('description')
        if isinstance(description, str) and description.casefold() == config.UNBOUND_POLICY_NAME.casefold():
            raise ValueError('reserved nfqws policy name already exists')
    return version


def pid(ctx):
    """A real Xray daemon using this confdir; isolated node checks never qualify."""
    done = system.run(['pidof', 'xray'], ctx.environ, config.timeout('process', ctx.environ))
    if done.returncode or done.timed_out:
        return None
    found = []
    for token in dict.fromkeys(done.stdout.split()[:64]):
        if xray_process.xray_identity(token, ctx.paths.xray_config_dir, proc_root=system.PROC_ROOT):
            found.append(int(token))
    if len(found) > 1:
        raise RuntimeError('multiple Xray daemons use the effective confdir')
    return found[0] if found else None


def action(ctx, verb, *, attempts=3, delay=1):
    if verb not in ('start', 'stop', 'restart'):
        raise ValueError('unsupported XKeen action')
    argv = [ctx.paths.xkeen_init, verb] + ([] if verb == 'stop' else ['on'])
    previous = pid(ctx) if verb == 'restart' else None
    prepared_digest = None
    if verb == 'restart' and (Path(ctx.paths.xray_config_dir) / receipt.layout.FILE).is_file():
        prepared_digest = receipt.corpus_digest(ctx.paths.xray_config_dir)
    for index in range(attempts):
        done = nfqws_process.run_service(argv, ctx.environ, timeout=120, output_limit=1024 * 1024, cwd='/')
        if getattr(done, 'capture_mode', 'captured') == 'discarded':
            ctx.console.err('WARNING: init output discarded on this kernel; exit status, timeout and owned Xray checks remain enforced.')
        if not done.returncode and not done.timed_out and not done.output_limited:
            break
        # Upstream mutex contention returns1 with an explicit busy diagnostic.
        if (done.returncode != 1 or done.timed_out or done.output_limited
                or not re.search(r'(?i)\bbusy\b|занят', done.output) or index == attempts - 1):
            raise RuntimeError('XKeen ' + verb + ' failed; no asynchronous fallback was attempted')
        time.sleep(delay)
    else:
        raise RuntimeError('XKeen action attempt budget exhausted')
    for _ in range(10):
        live = pid(ctx)
        if (live is None) == (verb == 'stop') and (verb != 'restart' or live != previous):
            if verb == 'restart' and prepared_digest is not None:
                receipt.refresh_if_prepared(Path(config.list_path('/opt/etc/xkeen-web/inspection-runtime.json', ctx.paths.test_root)),
                                            ctx.paths.xray_config_dir, live, expected_digest=prepared_digest)
            return live
        time.sleep(delay)
    raise RuntimeError('XKeen runtime did not reach requested state')

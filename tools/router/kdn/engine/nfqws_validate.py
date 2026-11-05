"""Blob inventory and bounded real nfqws --intercept=0 validation.

Sources: zapret2 v1.0.6 nfq2/nfqws.c (ApplyDefaultBlobs, parse_lua_call),
lua/zapret-lib.lua (blob, apply_arg_prefix), lua/zapret-antidpi.lua (consumers).
Declarations are process-global, even across --new. Dynamic clone outputs are
only possible within their ordered profile; they are not proven to be produced
for every packet. Custom Lua globals/code and conditional execution cannot be
proved statically: strict validation additionally starts the pinned Lua runtime.
Pure inspect_blobs does no I/O; validate_tokens/config deliberately read assets.
"""
import re

from kdn.engine import checks, compose, config, confvalues, nfqws_process


BUILTIN_BLOBS = ('fake_default_tls', 'fake_default_http', 'fake_default_quic')
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*')
_HEX = re.compile(r'0x(?:[A-Fa-f0-9]{2})*')
_OFFSET_FILE = re.compile(r'\+[0-9]+@.+')
_CONSUMERS = {
    'fake': ('blob',), 'syndata': ('blob',),
    'multisplit': ('blob', 'seqovl_pattern'),
    'multidisorder': ('blob', 'seqovl_pattern'),
    'multidisorder_legacy': ('seqovl_pattern',),
    'hostfakesplit': ('blob',),
    'fakedsplit': ('blob', 'pattern', 'seqovl_pattern'),
    'fakeddisorder': ('blob', 'pattern', 'seqovl_pattern'),
    'tcpseg': ('blob', 'seqovl_pattern'), 'udplen': ('pattern',),
    'tls_client_hello_clone': ('fallback',),
}


class BlobDeclaration:
    __slots__ = ('name', 'kind', 'source', 'token_index')

    def __init__(self, name, kind, source, token_index):
        self.name, self.kind, self.source, self.token_index = name, kind, source, token_index


class BlobUse:
    __slots__ = ('profile', 'function', 'argument', 'reference', 'kind', 'optional', 'token_index')

    def __init__(self, profile, function, argument, reference, kind, optional, token_index):
        self.profile, self.function, self.argument = profile, function, argument
        self.reference, self.kind, self.optional, self.token_index = reference, kind, optional, token_index


class BlobIssue:
    __slots__ = ('code', 'profile', 'token_index', 'reference')

    def __init__(self, code, profile, token_index, reference):
        self.code, self.profile, self.token_index, self.reference = code, profile, token_index, reference


class BlobInventory:
    __slots__ = ('declarations', 'uses', 'issues')

    def __init__(self, declarations, uses, issues):
        self.declarations, self.uses, self.issues = tuple(declarations), tuple(uses), tuple(issues)


def _parts(value):
    """Only backslash-colon escapes the delimiter, as parse_lua_call does."""
    parts, current, offset = [], [], 0
    while offset < len(value):
        if value[offset:offset + 2] == '\\:':
            current.append(':')
            offset += 2
            continue
        if value[offset] == ':':
            parts.append(''.join(current))
            current = []
        else:
            current.append(value[offset])
        offset += 1
    parts.append(''.join(current))
    return parts


def _source_kind(source):
    if not source or any(char in source for char in '\r\n\0'):
        return None
    if source.startswith('0x'):
        return 'inline' if _HEX.fullmatch(source) else None
    if source.startswith('+'):
        return 'file' if _OFFSET_FILE.fullmatch(source) else None
    return 'file' if source != '@' else None


def inspect_blobs(tokens, *, builtin_names=BUILTIN_BLOBS):
    """Inspect already composed argv, not shell config text or shlex strings.

    Returns all use locations, unknown references and declaration/argument
    ambiguity. Unknown optional references remain visible with optional=True;
    severity is a caller decision. File existence/hash and custom Lua functions
    are deliberately not certified. token_index is zero-based, profile one-based.
    builtin_names must describe the actual pinned runtime, not guessed defaults.
    """
    if not isinstance(tokens, (tuple, list)) or any(not isinstance(token, str) for token in tokens):
        raise TypeError('blob inventory needs a sequence of argv strings')
    if isinstance(builtin_names, str):
        raise ValueError('invalid builtin blob names')
    builtin_names = tuple(builtin_names)
    if (any(not isinstance(name, str) or not _IDENTIFIER.fullmatch(name) for name in builtin_names)
            or len(set(builtin_names)) != len(builtin_names)):
        raise ValueError('invalid builtin blob names')
    declared, declarations, uses, issues = set(builtin_names), [], [], []
    profile = 1
    # The C collection is global; declarations after a use are still registered
    # before Lua execution. Record all before classifying ordered dynamic uses.
    for index, token in enumerate(tokens):
        if token == '--new' or token.startswith('--new='):
            profile += 1
        if not token.startswith('--blob='):
            continue
        name, colon, source = token[len('--blob='):].partition(':')
        kind = _source_kind(source)
        if not colon or not _IDENTIFIER.fullmatch(name) or kind is None:
            issues.append(BlobIssue('invalid-declaration', profile, index, name))
            continue
        declarations.append(BlobDeclaration(name, kind, source, index))
        if name in declared:
            issues.append(BlobIssue('duplicate-blob', profile, index, name))
        declared.add(name)

    profile, dynamic = 1, set()
    for index, token in enumerate(tokens):
        if token == '--new' or token.startswith('--new='):
            profile += 1
            dynamic = set()
        if not token.startswith('--lua-desync='):
            continue
        function, *arguments = _parts(token[len('--lua-desync='):])
        params = {}
        for argument in arguments:
            key, _equal, value = argument.partition('=')
            if key in params:
                issues.append(BlobIssue('duplicate-argument', profile, index, key))
            params[key] = value
        for key, value in params.items():
            prefixed = value.startswith(('#', '%'))
            if not prefixed and key not in _CONSUMERS.get(function, ()):
                continue
            reference = value[1:] if prefixed else value
            if reference.startswith('0x'):
                kind = 'inline' if _HEX.fullmatch(reference) else 'invalid'
            elif reference in dynamic:
                kind = 'dynamic'
            elif reference in declared:
                kind = 'global'
            else:
                kind = 'unknown'
            uses.append(BlobUse(profile, function, key, reference, kind, 'optional' in params, index))
            if kind in ('unknown', 'invalid'):
                issues.append(BlobIssue('unknown-blob' if kind == 'unknown' else 'invalid-inline',
                                        profile, index, reference))
        if function == 'tls_client_hello_clone' and _IDENTIFIER.fullmatch(params.get('blob', '')):
            dynamic.add(params['blob'])
    return BlobInventory(declarations, uses, issues)


PINNED_LUA_SHA256 = {
    'zapret-lib.lua': '6bf528fef1f0fc3c65e189216fc8a06bb873f6e25d1c29d2bfa4695a09b73440',
    'zapret-antidpi.lua': '6d1fa9168e5de1682fef91fd174f68b58c50f6739ef00f42ca7db2b940b6246d',
    'zapret-auto.lua': '23a9b99a776d868d92f4cc0ee5110f5c1f12fe746620d9c0337022dbc2f52df0',
}
PINNED_X86_SHA256 = '25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1'
# Read-only capture from the installed MIPS package, 2026-11-01.
# Never trust an arbitrary executable merely because it prints a success marker.
PINNED_MIPS_SHA256 = 'cfd8f16c595ae92670d05af0b7af1c12514d793228bb373660567ea73061b497'
PINNED_BINARY_SHA256 = frozenset((PINNED_X86_SHA256, PINNED_MIPS_SHA256))


class ValidationError(Exception):
    """Fail closed before configuration mutation; details contain no asset bytes."""


class ValidationResult:
    __slots__ = ('inventory', 'argv', 'output', 'warnings')

    def __init__(self, inventory, argv, output, warnings):
        self.inventory, self.argv, self.output, self.warnings = inventory, tuple(argv), output, tuple(warnings)


def _read_asset(path, limit, *, decompress=True, gzip_fallback=True):
    import gzip
    import os
    import stat
    import zlib

    chosen = path
    if gzip_fallback and not os.path.exists(chosen) and os.path.isfile(chosen + '.gz'):
        chosen += '.gz'
    try:
        descriptor = os.open(chosen, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValidationError('validation asset is not a bounded regular file')
            if decompress and chosen.endswith('.gz'):
                with gzip.GzipFile(fileobj=handle) as decoded:
                    data = decoded.read(limit + 1)
            else:
                data = handle.read(limit + 1)
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        raise ValidationError('validation asset unreadable') from exc
    if len(data) > limit:
        raise ValidationError('validation asset exceeds budget')
    return data


def _control_options(tokens):
    """Getopt accepts abbreviated long flags: never let them bypass probe guards."""
    protected = ('--qnum', '--user', '--uid', '--pidfile', '--daemon', '--debug',
                 '--intercept', '--dry-run', '--hostlist-auto-debug', '--fastpath-workaround',
                 '--writable', '--help', '--version', '--chdir', '--lua-init', '--lua-desync',
                 '--blob', '--hostlist', '--hostlist-exclude', '--hostlist-auto',
                 '--ipset', '--ipset-exclude', '--new')
    queues = 0
    for token in tokens:
        if not token.startswith('--') or token == '--':
            raise ValidationError('validation requires explicit long options without a separator')
        name, equal, value = token.partition('=')
        if name not in protected and len(name) > 2 and any(item.startswith(name) for item in protected):
            raise ValidationError('abbreviated validation control option is not allowed')
        if name == '--qnum':
            queues += 1
            if not equal or not re.fullmatch('[0-9]{1,5}', value) or int(value) > 65535 or queues > 1:
                raise ValidationError('ambiguous nfqws queue option')


def validate_tokens(tokens, binary, environ, *, timeout=20, file_limit=4194304,
                    output_limit=65536, expected_binary_sha256=None,
                    expected_lua_sha256=None, test_root='', asset_limit=67108864):
    """Check registered blobs/files then actually initialize Lua, never intercept.

    Approved Lua source hashes default to zapret2 v1.0.6; callers must explicitly
    supply a reviewed map for another version. Exact-or-.gz source fallback is
    supported and decompressed bytes hashed, matching nfqws load behavior.
    Binary must match the reviewed x86/MIPS pins unless the caller explicitly
    supplies a reviewed SHA256 for another build. No environment-variable bypass
    or dry-run success shortcut. Docker tests use the pinned x86 build.
    """
    import hashlib
    import os
    import time

    if not 1 <= file_limit <= 16777216:
        raise ValueError('invalid validation file budget')
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120
            or isinstance(asset_limit, bool) or not isinstance(asset_limit, int) or not 1 <= asset_limit <= 1073741824):
        raise ValueError('invalid validation total budget')
    deadline = time.monotonic() + timeout
    seen_assets, asset_bytes = {}, 0

    def asset(path, maximum, *, decompress=True, gzip_fallback=True):
        nonlocal asset_bytes
        if time.monotonic() >= deadline:
            raise ValidationError('validation asset deadline exceeded')
        key = (os.fspath(path), maximum, decompress, gzip_fallback)
        if key not in seen_assets:
            data = _read_asset(os.fspath(path), maximum, decompress=decompress, gzip_fallback=gzip_fallback)
            asset_bytes += len(data)
            if asset_bytes > asset_limit:
                raise ValidationError('aggregate validation asset budget exceeded')
            seen_assets[key] = (hashlib.sha256(data).hexdigest(), len(data))
        if time.monotonic() >= deadline:
            raise ValidationError('validation asset deadline exceeded')
        return seen_assets[key]
    if (not isinstance(tokens, (list, tuple)) or any(not isinstance(token, str) for token in tokens)):
        raise ValidationError('validation arguments must be composed strings')
    if len(tokens) > 8192 or sum(len(token) for token in tokens) > 1048576:
        raise ValidationError('validation argument budget exceeded')
    _control_options(tokens)
    inventory = inspect_blobs(tokens)
    if any(any(char in token for char in '\0\r\n') for token in tokens):
        raise ValidationError('unsafe control character in validation argument')
    if inventory.issues:
        raise ValidationError('invalid blob inventory: ' + ','.join(sorted({issue.code for issue in inventory.issues})))
    for token in tokens:
        if token.startswith('--lua-desync='):
            function, *arguments = _parts(token[len('--lua-desync='):])
            params = dict(argument.partition('=')[::2] for argument in arguments)
            if function in ('fake', 'tls_client_hello_clone') and not params.get('blob'):
                raise ValidationError('required Lua blob argument is missing')
    binary_hash, _binary_size = asset(binary, 16777216, decompress=False, gzip_fallback=False)
    if expected_binary_sha256 is not None and (
            not isinstance(expected_binary_sha256, str) or not re.fullmatch('[a-f0-9]{64}', expected_binary_sha256)):
        raise ValidationError('invalid expected validation binary hash')
    approved_hashes = PINNED_BINARY_SHA256 if expected_binary_sha256 is None else (expected_binary_sha256,)
    if binary_hash not in approved_hashes:
        raise ValidationError('validation binary hash mismatch')
    lua_hashes = PINNED_LUA_SHA256 if expected_lua_sha256 is None else expected_lua_sha256
    args, lua_seen, warnings = [], set(), []
    ignored = ('--qnum', '--user', '--uid', '--pidfile', '--daemon', '--debug', '--intercept', '--dry-run',
               '--hostlist-auto-debug', '--fastpath-workaround')
    forbidden = ('--writable', '--help', '--version', '--chdir', '--')
    read_options = ('--hostlist', '--hostlist-exclude', '--ipset', '--ipset-exclude')
    for token in tokens:
        option, _equal, value = token.partition('=')
        if option in ignored:
            if option == '--fastpath-workaround':
                warnings.append('packet-interception-only fastpath workaround omitted during Lua initialization')
            continue
        if option in forbidden or not token.startswith('--'):
            raise ValidationError('unsafe validation argument')
        if option == '--lua-init':
            if not value.startswith('@'):
                raise ValidationError('inline Lua is not approved for validation')
            path = config.list_path(value[1:], test_root)
            basename = os.path.basename(path).removesuffix('.gz')
            expected = lua_hashes.get(basename)
            if expected is None or asset(path, file_limit)[0] != expected:
                raise ValidationError('unapproved Lua source/hash')
            lua_seen.add(basename)
            token = '--lua-init=@' + path
        elif option == '--blob':
            name, _colon, source = value.partition(':')
            if _source_kind(source) == 'file':
                prefix, path = '', source
                if source.startswith('+'):
                    prefix, _at, path = source.partition('@')
                    prefix += '@'
                elif source.startswith('@'):
                    prefix, path = '@', source[1:]
                path = config.list_path(path, test_root)
                # nfqws blob files are raw bytes (load_file/fopen), unlike Lua
                # and hostlists. Do not invent gzip fallback/decompression here.
                _digest, length = asset(path, file_limit, decompress=False, gzip_fallback=False)
                if prefix.startswith('+') and int(prefix[1:-1]) >= length:
                    raise ValidationError('blob offset exceeds asset size')
                token = '--blob=' + name + ':' + prefix + path
        elif option in read_options or option == '--hostlist-auto':
            path = config.list_path(value, test_root)
            asset(path, file_limit)
            if option == '--hostlist-auto':
                # Auto mode can create/update files; validation needs only load.
                warnings.append('hostlist-auto checked as read-only hostlist')
                option = '--hostlist'
            token = option + '=' + path
        args.append(token)
    if not {'zapret-lib.lua', 'zapret-antidpi.lua'} <= lua_seen:
        raise ValidationError('required pinned Lua libraries are missing')
    # Explicit --uid invokes setgroups even for the same unprivileged uid.
    # Leave non-root identity unchanged; root explicitly retains its identity
    # rather than dropping to the package daemon user before reading assets.
    identity = ['--uid=0:' + str(os.getgid())] if os.getuid() == 0 else []
    argv = [os.fspath(binary), '--intercept=0', *identity, *args]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValidationError('validation asset deadline exceeded')
    done = nfqws_process.run(argv, environ, timeout=remaining, output_limit=output_limit)
    if done.timed_out:
        raise ValidationError('nfqws Lua validation timed out')
    if done.output_limited:
        raise ValidationError('nfqws Lua validation output exceeds budget')
    if done.returncode != 0:
        raise ValidationError('nfqws Lua validation failed (exit ' + str(done.returncode) + ')')
    if 'no intercept quit' not in done.output:
        raise ValidationError('nfqws did not confirm non-intercepting Lua initialization')
    return ValidationResult(inventory, argv, done.output, warnings)


def validate_config(ctx, conf_path):
    """Compose/invariant-check a candidate, then strict-check; no config writes.

    Uses the established shell composition adapter (its bounded scratch files
    only), not a second shell interpreter or divergent CLI path.
    """
    _read_asset(conf_path, 1048576, decompress=False, gzip_fallback=False)
    try:
        composition = compose.compose(conf_path, ctx.paths, ctx.environ, config.timeout('compose', ctx.environ))
    except compose.ComposeError as exc:
        raise ValidationError('nfqws configuration could not be composed') from exc
    findings, status = checks._composition_lines(composition, ctx.paths.test_root)
    findings.extend(checks.header_lines(confvalues.read_text(conf_path)))
    if status or any(line.startswith('CHECK|error|') for line in findings):
        raise ValidationError('nfqws configuration invariants failed')
    tokens, binary = composition.tokens, ctx.paths.nfqws_bin
    if ctx.paths.test_root:
        import os

        binary = ctx.environ.get('KD_TEST_NFQWS2_BIN') or binary
        lua_source = ctx.environ.get('KD_TEST_NFQWS2_LUA_SRC') or ctx.environ.get('KD_TEST_NFQWS2_LUA')
        if lua_source:
            tokens = list(tokens)
            for index, token in enumerate(tokens):
                if token.startswith('--lua-init=@'):
                    basename = os.path.basename(token[len('--lua-init=@'):]).removesuffix('.gz')
                    if basename in PINNED_LUA_SHA256:
                        tokens[index] = '--lua-init=@' + os.path.join(lua_source, basename)
    # Test-root overrides choose assets, never bypass their exact hash checks.
    # A live root cannot be redirected with KD_TEST_* environment variables.
    return validate_tokens(tokens, binary, ctx.environ, test_root=ctx.paths.test_root)

"""Source nfqws2's shell configuration in an isolated child, like the package init."""

import os

from kdn.engine import config, confvalues, lifecycle, system


BUILTIN_STARTUP_ARGS = '''builtin_startup_args() {
  cat <<'EOF'
_startup_args() {
  local fastpath_workaround=
  case "$NFQWS_BASE_ARGS" in
    *--fastpath-workaround=*) ;;
    *) fastpath_workaround="--fastpath-workaround=auto" ;;
  esac

  local args="--user=$USER --qnum=$NFQUEUE_NUM $fastpath_workaround $NFQWS_BASE_ARGS"

  local iface_count=$(echo $ISP_INTERFACE | wc -w)
  if [ "$iface_count" -gt "1" ]; then
    args="$args --bind-fix4"
    if [ -n "$IPV6_ENABLED" ] && [ "$IPV6_ENABLED" -ne "0" ]; then
      args="$args --bind-fix6"
    fi
  fi

  if [ "$LOG_LEVEL" -eq "1" ]; then
    if [ -n "$LOG_DEBUG_PATH" ]; then
      args="--debug=$LOG_DEBUG_PATH $args"
    else
      args="--debug=syslog $args"
    fi
  fi

  if [ -n "$NFQWS_ARGS_CUSTOM" ]; then
    args="$args $NFQWS_ARGS_CUSTOM --new"
  fi

  if [ -n "$NFQWS_ARGS_UDP" ]; then
    args="$args $NFQWS_ARGS_UDP --new"
  fi

  if [ -n "$NFQWS_ARGS_QUIC" ]; then
    if [ -n "$NFQWS_ARGS_IPSET" ]; then
      args="$args $NFQWS_ARGS_QUIC $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new"
    fi
    args="$args $NFQWS_ARGS_QUIC $NFQWS_EXTRA_ARGS --new"
  fi

  if [ -n "$NFQWS_ARGS_IPSET" ]; then
    args="$args $NFQWS_ARGS $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new"
  fi
  args="$args $NFQWS_ARGS $NFQWS_EXTRA_ARGS"

  echo "$args"
}
EOF
}'''

SOURCE_SCRIPT = r'''
    set -f
    LOG_LEVEL=0
    NFQUEUE_NUM=300
    USER=nobody
    user_custom="$(
      NFQWS_ARGS_CUSTOM=""
      . "$3" >/dev/null 2>&1
      printf "%s" "$NFQWS_ARGS_CUSTOM"
    )"
    . "$1" >/dev/null 2>&1
    . "$2"
    user_profiles=0
    for user_token in $user_custom; do
      case "$user_token" in
        --new) user_profiles=$((user_profiles + 1)) ;;
        -*) [ "$user_profiles" -gt 0 ] || user_profiles=1 ;;
      esac
    done
    printf "META TCP_PORTS %s\n" "$TCP_PORTS"
    printf "META UDP_PORTS %s\n" "$UDP_PORTS"
    printf "META NFQUEUE_NUM %s\n" "$NFQUEUE_NUM"
    printf "META USER_PROFILES %s\n" "$user_profiles"
    _startup_args
  '''


class ComposeError(Exception):
    """The config could not produce startup arguments within the time limit."""


class Composition:
    __slots__ = ('tokens', 'meta', 'source', 'user_profiles')

    def __init__(self, tokens, meta, source):
        self.tokens = tokens
        self.meta = meta
        self.source = source
        self.user_profiles = int(meta.get('USER_PROFILES', '0'))


def _function(text):
    selected = []
    inside = False
    for line in confvalues.lines(text):
        if line == '_startup_args() {':
            inside = True
        if inside:
            selected.append(line)
            if line == '}':
                inside = False
    if any('NFQWS_ARGS_QUIC' in line for line in selected) and '}' in selected:
        return '\n'.join(selected) + '\n', 'package init'
    return BUILTIN_STARTUP_ARGS.split("  cat <<'EOF'\n", 1)[1].rsplit('\nEOF\n', 1)[0] + '\n', 'built-in'


def _user_view(text):
    selected = []
    inside = False
    for line in confvalues.lines(text):
        if line == '# BEGIN ' + config.PROJECT:
            inside = True
        if not inside:
            selected.append(line)
        elif line == '# END ' + config.PROJECT:
            inside = False
    return '\n'.join(selected) + ('\n' if selected else '')


def compose(conf_path, paths, environ, timeout, *, processed_mark=None, custom_ports=False):
    """Return startup tokens and first-word META; no host environment except PATH is inherited."""
    import shutil
    import tempfile

    os.makedirs(paths.work_tmp_root, exist_ok=True)
    work = tempfile.mkdtemp(prefix=config.PROJECT + '.', dir=paths.work_tmp_root)

    def cleanup():
        shutil.rmtree(work, ignore_errors=True)

    lifecycle.add_cleanup(cleanup)
    try:
        function, source = _function(confvalues.read_text(paths.nfqws_init))
        function_path = os.path.join(work, 'startup')
        user_path = os.path.join(work, 'user')
        for path, text in ((function_path, function), (user_path, _user_view(confvalues.read_text(conf_path)))):
            with open(path, 'wb') as handle:
                handle.write(text.encode('utf-8', 'surrogateescape'))
        script = SOURCE_SCRIPT
        if custom_ports:
            # Reuse the already sourced user-only view; never source config again.
            script = script.replace('    . "$1" >/dev/null 2>&1', r'''
    custom_tcp= custom_udp=
    for custom_token in $user_custom; do
      case "$custom_token" in
        --filter-tcp=*) custom_tcp="$custom_tcp,${custom_token#*=}" ;;
        --filter-udp=*) custom_udp="$custom_udp,${custom_token#*=}" ;;
      esac
    done
    printf "META CUSTOM_FILTER_TCP %s\n" "${custom_tcp#,}"
    printf "META CUSTOM_FILTER_UDP %s\n" "${custom_udp#,}"
    . "$1" >/dev/null 2>&1''')
        extra = []
        if processed_mark is not None:
            # Opt-in metadata for the mark preflight; keep the established
            # composition/oracle bytes unchanged for ordinary callers.
            script = 'MARK_PROCESSED="$4"\n' + script.replace(
                '    _startup_args\n',
                '    case "$MARK_PROCESSED" in\n'
                '      ""|*[!0-9a-fA-FxX/]*) printf "META MARK_PROCESSED invalid\\n" ;;\n'
                '      *) printf "META MARK_PROCESSED %s\\n" "$MARK_PROCESSED" ;;\n'
                '    esac\n    _startup_args\n')
            extra.append(processed_mark)
        done = system.run(['sh', '-c', script, 'compose', os.fspath(conf_path), function_path, user_path, *extra],
                          {'PATH': environ.get('PATH', os.defpath)}, timeout)
        if done.returncode != 0 or done.timed_out:
            raise ComposeError('could not compose nfqws2 startup arguments')
        tokens, meta = [], {}
        for line in confvalues.lines(done.stdout):
            fields = confvalues.fields(line)
            if fields and fields[0] == 'META':
                key = fields[1] if len(fields) > 1 else ''
                if key == 'MARK_PROCESSED' and processed_mark is not None:
                    # Preserve malformed whitespace/empty masks for explicit
                    # rejection; taking only the first word could guess a mask.
                    meta[key] = line[len('META MARK_PROCESSED '):]
                else:
                    meta[key] = fields[2] if len(fields) > 2 else ''
            else:
                tokens.extend(field for field in fields if field.startswith('-'))
        if not tokens:
            raise ComposeError('no nfqws2 startup arguments')
        return Composition(tokens, meta, source)
    finally:
        cleanup()

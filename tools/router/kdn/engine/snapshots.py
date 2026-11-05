"""Read snapshot pointers without normalising their shell-visible paths."""

import os


class Snapshots:
    __slots__ = ('state_dir', 'baseline', 'xkeen_baseline', 'latest_preapply')

    def __init__(self, state_dir, baseline, xkeen_baseline, latest_preapply):
        self.state_dir = state_dir
        self.baseline = baseline
        self.xkeen_baseline = xkeen_baseline
        self.latest_preapply = latest_preapply


def safe_snapshot_path(paths, candidate):
    prefix = paths.snapshot_root + '/'
    if not candidate.startswith(prefix) or '/../' in candidate or candidate.endswith('/..') or '//' in candidate:
        return False
    leaf = candidate[len(prefix):]
    return bool(leaf) and '/' not in leaf and os.path.isdir(candidate) and not os.path.islink(candidate)


def read_pointer(paths, pointer):
    if not os.path.isfile(pointer):
        return None
    try:
        with open(pointer, 'rb') as handle:
            # sed -n '1p' followed by shell command substitution: only the
            # first LF-delimited record, NUL bytes discarded, CR preserved.
            candidate = handle.readline().split(b'\n', 1)[0].replace(b'\0', b'').decode('utf-8', 'surrogateescape')
    except OSError:
        return None
    return candidate if safe_snapshot_path(paths, candidate) else None


def describe(paths):
    return Snapshots(paths.state_root, read_pointer(paths, paths.baseline_pointer),
                     read_pointer(paths, paths.xkeen_baseline_pointer), read_pointer(paths, paths.latest_pointer))


def lines(snapshots):
    result = ['State directory: ' + snapshots.state_dir, 'Baseline: ' + (snapshots.baseline or 'not created')]
    if snapshots.xkeen_baseline is not None:
        result.append('XKeen baseline: ' + snapshots.xkeen_baseline)
    result.append('Latest pre-apply: ' + (snapshots.latest_preapply or 'not created'))
    return result


def is_router(paths):
    # This mode only needs the filesystem guard; importing system would load
    # subprocess on the lightweight --show-snapshots path (rule 9).
    return bool(paths.test_root) or (os.access('/bin/ndmc', os.X_OK) and os.path.isdir('/opt/etc'))


def run(ctx):
    if not is_router(ctx.paths):
        ctx.console.err('ERROR: this does not look like a Keenetic Entware environment.')
        return 1
    for line in lines(describe(ctx.paths)):
        ctx.console.out(line)
    return 0

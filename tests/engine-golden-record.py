"""Normalise only fixture roots/PIDs in the immutable legacy oracle."""

import re
import sys
import gzip
import difflib
from pathlib import Path


def normalise(data, root):
    data = data.replace(root.encode(), b"@ROOT@")
    return re.sub(rb"keenetic-discord-nfqws2\.[0-9]+", b"keenetic-discord-nfqws2.PID", data)


def stabilise_snapshots(root):
    """Give generated snapshots stable fixture names BEFORE either engine runs."""
    root = Path(root)
    directory = root / 'opt/etc/keenetic-discord-nfqws2/snapshots'
    snapshots = sorted(path for path in directory.glob('*')
                       if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]+', path.name)
                       and path.is_dir() and not path.is_symlink())
    replacements = []
    for index, source in enumerate(snapshots):
        destination = directory / f'fixture-{index:04d}'
        if destination.exists():
            raise RuntimeError(f'fixture snapshot collision: {destination}')
        source.rename(destination)
        replacements.append((str(source).encode(), str(destination).encode()))
    for path in root.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        changed = data
        for before, after in replacements:
            changed = changed.replace(before, after)
        if changed != data:
            path.write_bytes(changed)


def main():
    if sys.argv[1] == 'stabilise':
        stabilise_snapshots(sys.argv[2])
        return 0
    action, root, source, target = sys.argv[1:]
    actual = normalise(Path(source).read_bytes(), root)
    destination = Path(target)
    if action == "record":
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.with_suffix(destination.suffix + '.gz').write_bytes(gzip.compress(actual, mtime=0))
        return 0
    if action != "check":
        raise ValueError(action)
    compressed = destination.with_suffix(destination.suffix + '.gz')
    expected = gzip.decompress(compressed.read_bytes()) if compressed.is_file() else None
    if expected != actual:
        print(f"ENGINE MISMATCH: frozen oracle {target}", file=sys.stderr)
        if expected is not None:
            print(''.join(difflib.unified_diff(
                expected.decode('utf-8', 'backslashreplace').splitlines(keepends=True),
                actual.decode('utf-8', 'backslashreplace').splitlines(keepends=True),
                fromfile='frozen', tofile='actual',
            )), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Compare dispatcher argv vectors without shell evaluation or text argument splitting."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

project, root, binary, log = sys.argv[1:]
count = 0
recording = os.environ.get('KDN_GOLDEN_RECORD') == '1'
recorded = os.environ.get('KDN_GOLDEN_MODE') == 'recorded' and not recording
oracle = Path(os.environ.get('KDN_GOLDEN_DIR', str(Path(project, 'tests/fixtures/engine/golden'))))


def digest():
    result = hashlib.sha256()
    for path in sorted(Path(root).rglob('*')):
        relative = path.relative_to(root).as_posix()
        if relative.startswith('opt/tmp/keenetic-discord-nfqws2.') or path.is_symlink() or not path.is_file():
            continue
        result.update(relative.encode('utf-8', 'surrogateescape') + b'\0' + path.read_bytes() + b'\0')
    return result.digest()


for line in Path(root, 'argv-corpus.jsonl').read_text(encoding='utf-8').split('\n'):
    if not line:
        continue
    args = json.loads(line)
    before = digest()
    results = []
    modes = ('legacy',) if recording else ('python',) if recorded else ('python', 'legacy')
    for mode in modes:
        env = dict(os.environ, KDN_ENGINE=mode, KD_TEST_ROOT=root, KD_ALLOW_TEST_ROOT='1',
                   PATH=binary + os.pathsep + os.environ['PATH'])
        done = subprocess.run(['sh', str(Path(project, 'apply-discord-nfqws2.sh')), *args], env=env,
                              capture_output=True, timeout=90)
        results.append((done.returncode, done.stdout, done.stderr))
    mismatch = len(results) == 2 and results[0] != results[1]
    if recording or recorded:
        with tempfile.TemporaryDirectory(prefix='golden-argv-record.') as temporary:
            for kind, data in zip(('rc', 'out', 'err'),
                                  (str(results[0][0]).encode() + b'\n', results[0][1], results[0][2]), strict=True):
                source = Path(temporary, kind)
                source.write_bytes(data)
                check = subprocess.run([sys.executable, str(Path(project, 'tests/engine-golden-record.py')),
                                        'record' if recording else 'check', root, str(source),
                                        str(oracle / 'argv-corpus' / f'argv-{count}.{kind}')], capture_output=True)
                mismatch = mismatch or check.returncode != 0
    if mismatch or digest() != before:
        with open(log, 'a', encoding='utf-8') as output:
            output.write('ENGINE MISMATCH argv ' + repr(args) + '\n' + repr(results) + '\n')
    count += 1
if not count:
    raise RuntimeError('empty argv corpus')
print('golden-argv-comparisons:', count)

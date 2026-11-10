"""Offline software delivery regressions using only a synthetic router tree."""
import errno
import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='router capability preflight requires Linux')


@pytest.fixture
def delivery(tmp_path):
    helpers = (REPO / 'tests/test-deploy.sh').read_text().split('# ---------------------------------------------------------------- (a) success')[0]
    helpers = helpers.replace('SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"', f'SCRIPT_DIR="{REPO}"')
    helpers = helpers.replace('WORK="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-deploy.XXXXXX")"', f'WORK="{tmp_path}/fixture"\nmkdir -p "$WORK"')
    helpers = helpers.replace("trap 'rm -rf \"$WORK\"' 0 HUP INT TERM", '')
    setup = tmp_path / 'setup.sh'
    setup.write_text(helpers + '''
new_case review
cp "$SCRIPT_DIR/tools/router/xkeen_control_script.sh" "$CASE/project/tools/router/xkeen_control_script.sh"
cp -R "$CASE/router/$PROJECT_REL" "$CASE/router/opt/root/alt-project"
run_deploy --dry-run
expect_rc 0 'fixture package'
''')
    subprocess.run(['sh', str(setup)], check=True, capture_output=True, text=True)
    base = tmp_path / 'fixture/review'
    router = base / 'router'
    env = dict(os.environ, PATH=str(router / 'opt/bin') + os.pathsep + os.environ['PATH'], KDN_DEPLOY_ROOT=str(router), KDN_ALLOW_DEPLOY_ROOT='1', KDN_READY_PAUSE='0', MOCK_DIR=str(base / 'mock'))
    return base, router, env, next((router / 'opt/tmp').glob('kdn-deploy-*/upload.tar.gz'))


def launch(delivery, stage=None, *, rollback=False, tag=''):
    _, _, env, archive = delivery
    command = ['sh', str(REPO / 'tools/router/rollback-xkeen-web.sh')] if rollback else [
        'sh', str(REPO / 'tools/dev/deploy-remote.sh'), '--stage', str(stage or archive.parent), '--project-dir', '/opt/root/alt-project']
    return subprocess.Popen(command, env=dict(env, DEPLOY_TAG=tag), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def result(process, expected=0):
    output = process.communicate(timeout=30)[0]
    assert process.returncode == expected, output
    return output


def tree_bytes(router):
    return {str(p.relative_to(router)): p.read_bytes() for p in router.rglob('*') if p.is_file() and 'opt/tmp/' not in str(p.relative_to(router))}


def run_shim(path):
    spec = importlib.util.spec_from_file_location('delivery_launcher', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def test_custom_target_survives_clean_start_environment_and_rollback(delivery):
    _, router, _, _ = delivery
    original = (router / 'opt/xkeen-web/app.py').read_bytes()
    result(launch(delivery))
    shim = router / 'opt/xkeen-web/app.py'
    with mock.patch.dict(os.environ, {}, clear=True), mock.patch('runpy.run_path') as run:
        run_shim(shim)
    assert run.call_args.args[0] == '/opt/root/alt-project/tools/router/kdn/web/app.py'
    with mock.patch.dict(os.environ, {'XKEEN_PROJECT_DIR': '/opt/root/env-override'}, clear=True), mock.patch('runpy.run_path') as run:
        run_shim(shim)
    assert run.call_args.args[0] == '/opt/root/env-override/tools/router/kdn/web/app.py'
    result(launch(delivery, rollback=True))
    assert shim.read_bytes() == original


def test_failed_rollback_stop_preserves_every_installed_file(delivery):
    base, router, _, _ = delivery
    result(launch(delivery))
    (base / 'mock/stop-fails-once').touch()
    before = tree_bytes(router)
    output = result(launch(delivery, rollback=True), expected=1)
    assert 'Panel software restored' not in output
    assert tree_bytes(router) == before
    assert (base / 'mock/init.log').read_text().splitlines() == ['stop', 'start', 'stop']


def stage_with_tag(delivery, tag):
    _, router, _, archive = delivery
    stage = router / f'opt/tmp/kdn-deploy-review-{tag}'
    stage.mkdir()
    with tarfile.open(archive) as source, tarfile.open(stage / 'upload.tar.gz', 'w:gz', format=tarfile.USTAR_FORMAT) as target:
        for member in source.getmembers():
            data = source.extractfile(member).read()
            if member.name in ('scripts/diagnose.sh', 'scripts/fresh.sh'):
                data = f'#!/bin/sh\necho {tag}\n'.encode()
                member.size = len(data)
            target.addfile(member, io.BytesIO(data))
    return stage


def wait_for_pause(delivery, process):
    base, _, _, _ = delivery
    deadline = time.monotonic() + 20
    while not (base / 'mock/paused').exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(.02)
    assert (base / 'mock/paused').exists(), process.communicate(timeout=5)[0] if process.poll() is not None else 'no pause'


def pause_copy(delivery, pattern):
    _, router, _, _ = delivery
    cp = router / 'opt/bin/cp'
    cp.write_text(f'''#!/bin/sh
source=$1
[ "$source" != -p ] || source=$2
case "${{DEPLOY_TAG:-}}:$source" in {pattern})
  touch "$MOCK_DIR/paused"
  while [ ! -f "$MOCK_DIR/resume" ]; do sleep .02; done
  ;;
esac
exec /bin/cp "$@"
''')
    cp.chmod(0o755)


@pytest.mark.parametrize('contender', ['deploy', 'rollback'])
def test_deploy_lock_covers_install_until_verification(delivery, contender):
    base, router, _, _ = delivery
    result(launch(delivery))  # give rollback a valid pointer
    stage_a, stage_b = stage_with_tag(delivery, 'A'), stage_with_tag(delivery, 'B')
    pause_copy(delivery, 'A:*/tree/scripts/fresh.sh')
    first = launch(delivery, stage_a, tag='A')
    try:
        wait_for_pause(delivery, first)
        result(launch(delivery, stage_b, rollback=contender == 'rollback'), expected=3)
    finally:
        (base / 'mock/resume').touch()
        result(first)
    for file in ('diagnose', 'fresh'):
        assert (router / f'opt/root/alt-project/scripts/{file}.sh').read_text().splitlines()[-1] == 'echo A'


def test_rollback_lock_excludes_deploy_during_restore(delivery):
    base, _, _, _ = delivery
    result(launch(delivery))
    stage = stage_with_tag(delivery, 'B')
    pause_copy(delivery, 'R:*/project/scripts/diagnose.sh')
    first = launch(delivery, rollback=True, tag='R')
    try:
        wait_for_pause(delivery, first)
        result(launch(delivery, stage), expected=3)
    finally:
        (base / 'mock/resume').touch()
        result(first)


@pytest.mark.parametrize('rollback', [False, True])
def test_successful_stop_with_live_panel_refuses_before_software_changes(delivery, rollback):
    _, router, _, _ = delivery
    if rollback:
        result(launch(delivery))
    panel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', str(router / 'opt/xkeen-web/app.py')])
    try:
        before = tree_bytes(router)
        output = result(launch(delivery, rollback=rollback), expected=1)
        assert 'Panel software restored' not in output
        assert tree_bytes(router) == before
    finally:
        panel.terminate()
        panel.wait(timeout=5)


def test_cancelled_deploy_restores_before_releasing_lock(delivery):
    base, router, _, _ = delivery
    stage_a, stage_b = stage_with_tag(delivery, 'A'), stage_with_tag(delivery, 'B')
    pause_copy(delivery, 'A:*/tree/scripts/fresh.sh')
    before = {key: value for key, value in tree_bytes(router).items() if not key.startswith('opt/etc/xkeen-web-backups/')}
    first = launch(delivery, stage_a, tag='A')
    try:
        wait_for_pause(delivery, first)
        first.terminate()
        result(first, expected=1)
        after = {key: value for key, value in tree_bytes(router).items() if not key.startswith('opt/etc/xkeen-web-backups/')}
        assert after == before
        result(launch(delivery, stage_b))
        assert (router / 'opt/root/alt-project/scripts/fresh.sh').read_text().endswith('echo B\n')
    finally:
        (base / 'mock/resume').touch()
        if first.poll() is None:
            first.terminate()
            first.communicate(timeout=30)


def test_persistent_unheld_lock_is_reused_and_symlink_lock_refused(delivery):
    _, router, _, _ = delivery
    lock = router / 'opt/tmp/kdn-software.lock'
    inode = lock.stat().st_ino
    lock.write_text('obsolete owner metadata\n')
    result(launch(delivery))
    assert lock.stat().st_ino == inode
    lock.unlink()
    target = router / 'sentinel'
    target.write_bytes(b'unchanged')
    lock.symlink_to(target)
    result(launch(delivery, rollback=True), expected=2)
    assert target.read_bytes() == b'unchanged'


def test_automatic_rollback_refuses_restore_if_second_stop_fails(delivery):
    base, router, _, _ = delivery
    init = router / 'opt/etc/init.d/S99xkeen-web'
    init.write_text(init.read_text().replace('echo "$1" >> "$MOCK_DIR/init.log"', '''if [ "$1" = stop ] && grep -Fxq start "$MOCK_DIR/init.log" 2>/dev/null; then
  echo 'mock: second stop failed'
  exit 1
fi
echo "$1" >> "$MOCK_DIR/init.log"'''))
    (base / 'mock/panel/api_vpn-nodes').unlink()  # start succeeds but readiness fails
    output = result(launch(delivery), expected=1)
    assert 'panel did not become ready' in output, output
    assert 'mock: second stop failed' in output, output
    assert 'ROLLBACK INCOMPLETE: panel stop unconfirmed' in output, output
    assert 'restored the previous files' not in output, output
    assert (router / 'opt/root/alt-project/scripts/diagnose.sh').read_text().endswith('echo diagnose NEW\n'), output
    assert (router / 'opt/etc/xkeen-web-backups/latest.path').is_file(), output


@pytest.mark.parametrize('script', ['tools/dev/deploy-remote.sh', 'tools/router/rollback-xkeen-web.sh'])
@pytest.mark.parametrize('read_errno', [errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EIO])
@pytest.mark.parametrize('live_panel', [False, True])
def test_stop_confirmation_handles_only_vanished_proc_entries(script, read_errno, live_panel):
    # Execute the shipped helper's Python boundary with deterministic /proc
    # reads: one PID disappears between enumeration and reading its cmdline.
    # A later panel entry must still refuse a stop even after that disappearance.
    source = (REPO / script).read_text().split("<<'PYSTOP'\n", 1)[1].split('\nPYSTOP', 1)[0]
    bootstrap = f"""
import errno
import os
import subprocess
import sys
from pathlib import Path
Path.iterdir = lambda self: [Path('/proc/999999991'), Path('/proc/999999992')]
def read_cmdline(self):
    if self.parent.name == '999999991':
        if {read_errno} == errno.ESRCH:
            # A real kernel race: open cmdline, reap the process, then read.
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            descriptor = os.open('/proc/%s/cmdline' % child.pid, os.O_RDONLY)
            try:
                child.terminate()
                child.wait(timeout=5)
                return os.read(descriptor, 4096)
            finally:
                os.close(descriptor)
                if child.poll() is None:
                    child.kill()
                    child.wait()
        raise OSError({read_errno}, 'synthetic proc read error')
    return b'/opt/xkeen-web/app.py\\0' if {live_panel!r} else b'unrelated\\0'
Path.read_bytes = read_cmdline
"""
    completed = subprocess.run([sys.executable, '-I', '-', '/opt/xkeen-web/app.py', '/opt/etc/init.d/S99xkeen-web'],
                               input=bootstrap + source, text=True, capture_output=True, check=False)
    expected = 0 if read_errno in (errno.ENOENT, errno.ESRCH) and not live_panel else 1
    assert completed.returncode == expected, completed.stdout + completed.stderr
    if live_panel and read_errno in (errno.ENOENT, errno.ESRCH):
        assert 'panel or supervisor is still running' in completed.stderr, completed.stderr

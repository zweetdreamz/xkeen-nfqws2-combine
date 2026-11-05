"""Adapter of the engine: the commands the panel runs on it, and what it reads back from it.

Every command line of the engine (apply-discord-nfqws2.sh) and of the route switch (set-service-route.sh) is built
here, with the absolute paths of the configuration and the panel's timeouts. The rest reads what the engine
leaves: the --status lines, snapshots, the import rollback pointer and the managed block of nfqws2.conf, whose
headers kdn.state.nfqws parses.
"""

from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import time
import uuid

from kdn.common import fsutil, xkeen
from kdn.common import proc
from kdn.state import nfqws
from kdn.web.infra import config as cfg

_status_read = threading.local()


@contextmanager
def status_read_scope():
    """One actual probe for this HTTP read, not a cached version or a write bypass."""
    require_supported_target()
    previous = getattr(_status_read, 'verified', False)
    _status_read.verified = True
    try:
        yield
    finally:
        _status_read.verified = previous


STATUS_ROUTE_KEYS = {
    "discord-tcp": "discord_tcp_route",
    "discord-voice": "discord_voice_route",
    "youtube": "youtube_route",
    "telegram": "telegram_route",
}


def engine_command(*args):
    """Command line of the engine, apply-discord-nfqws2.sh, with these arguments."""
    return ["/bin/sh", str(cfg.ENGINE), *args]


def require_supported_target():
    return xkeen.require(cfg.XKEEN, proc.command_env())


def _status_document(output):
    """Decode the first brace-line document after diagnostics, never a partial JSON prefix."""
    if not isinstance(output, str):
        return None, []
    lines = output.split('\n')
    try:
        start = lines.index('{')
        report = json.loads('\n'.join(lines[start:]))
    except (ValueError, RecursionError):
        return None, []
    if not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1 or not isinstance(report.get('text'), str):
        return None, []
    try:
        report['text'].encode('utf-8', 'surrogateescape')
    except UnicodeError:
        return None, []
    return report, lines[:start]


def _run_status():
    """One JSON attempt, at most one legacy fallback; a timeout is never retried."""
    try:
        if not getattr(_status_read, 'verified', False):
            require_supported_target()
    except xkeen.UnsupportedXKeen:
        report = xkeen.error_status()
        return {'ok': False, 'code': 2, 'error_code': xkeen.ERROR_CODE,
                'supported': False, 'output': report['text'].strip()}, report
    payload = proc.run_command(engine_command('--status', '--json'), timeout=40)
    if payload.get('code') == 124:
        return payload, None
    report, diagnostics = _status_document(payload.get('output', ''))
    if report is not None and report.get('error_code') == xkeen.ERROR_CODE:
        return {**payload, 'ok': False, 'error_code': xkeen.ERROR_CODE,
                'supported': False, 'output': report['text'].strip()}, report
    if report is not None:
        # The native JSON losslessly escapes opaque bytes. The old text path
        # went through run_command's UTF-8 errors=replace decoder; preserve
        # that public HTTP/text contract without altering the parsed report.
        text = report['text'].encode('utf-8', 'surrogateescape').decode('utf-8', 'replace')
        return {**payload, 'output': '\n'.join([*diagnostics, text]).strip()}, report
    return proc.run_command(engine_command('--status'), timeout=40), None


def read_dns_mode():
    result = proc.run_command(["python3", "-P", str(cfg.DNS_TOOL), "--status"], timeout=30)
    if not result['ok']:
        raise RuntimeError('Не удалось прочитать DNS-профиль Home')
    data = json.loads(result['output'])
    if not isinstance(data, dict) or not data.get('ok'):
        raise ValueError('Некорректный статус DNS')
    return data


def set_dns_mode(mode):
    if mode not in ('vless', 'doh'):
        raise ValueError('DNS mode: vless or doh')
    return proc.run_command(["python3", "-P", str(cfg.DNS_TOOL), "--set", mode, "--yes-router"], timeout=120)


def read_status():
    """The legacy-shaped payload, with JSON projected back to the same text output."""
    return _run_status()[0]


def read_status_report():
    """The schema-1 report, or None for an old engine, invalid response or timeout."""
    return _run_status()[1]


def read_status_fields():
    """The --status result with its key=value lines parsed in: the one place the panel reads the engine status."""
    payload = read_status()
    return {**payload, **parse_status(payload.get("output", ""))}


def service_switch_command(service, mode):
    """Route switch of one service through set-service-route.sh; the script detects the core."""
    return ["/bin/sh", str(cfg.SERVICE_SWITCH), service, mode, "--core", "auto", "--yes-router"]


def rollback_snapshot_command(snapshot):
    """Engine restore of one verified snapshot; the engine first takes a rescue snapshot."""
    return engine_command("--rollback-snapshot", str(snapshot), "--yes-router")


def clear_imported_profile(service):
    """Restore the built-in nfqws2 profile of a service in place of the imported one."""
    return proc.run_command(engine_command("--clear-imported-profile", service, "--yes-router"), timeout=300)


def rollback_import(*, source=None, operation_context=None):
    """Manual toggle, or a fixed original source for a pending automation."""
    args = ['--rollback-import', '--yes-router']
    if source is not None:
        args.extend(('--recover-import-source', str(source)))
    if operation_context is not None:
        args.extend(('--focused-operation-context', json.dumps(operation_context, separators=(',', ':'))))
    return proc.run_command(engine_command(*args), timeout=300)


def cleanup_import_history():
    return proc.run_command(engine_command('--prune-import-snapshots', '--yes-router'), timeout=300)


def process_running(name):
    """Whether a process of this name is running, by pidof."""
    return bool(proc.run_command(["pidof", name], timeout=5)["ok"])


def setup_route_checker():
    require_supported_target()
    return proc.run_command(engine_command('--setup-route-checker', '--yes-router'), timeout=300)


def xkeen_command(action):
    """Command line of xkeen for one of the three actions the panel runs."""
    if action not in ("start", "stop", "restart"):
        raise ValueError("неподдерживаемое действие XKeen")
    return [str(cfg.XKEEN_INIT), action, *([] if action == 'stop' else ['on'])]


def run_xkeen_action(command, *, xray_expected):
    require_supported_target()
    # XKeen2.1 init's on argument is foreground; no old CLI detach fallback.
    payload = proc.run_command(command, timeout=150)
    if payload["ok"] and process_running("xray") != xray_expected:
        note = "Xray не запущен после команды XKeen" if xray_expected else "Xray всё ещё запущен после остановки XKeen"
        return {**payload, "ok": False, "output": f"{payload['output']}\n{note}".strip()}
    return payload


def parse_status(text):
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {
            "discord_route",
            "discord_tcp_route",
            "discord_voice_route",
            "youtube_route",
            "telegram_route",
            "xkeen_runtime",
            "nfqws_runtime",
            "detected_core",
            "script_version",
        }:
            result[key] = value
    return result


def recorded_voice_high():
    """Upper Discord Voice UDP port, as the engine's recorded_udp_settings reads it.

    The "# Discord UDP: strategy=X, range=Y." line of nfqws2.conf decides:
    65535 for range=wide, 50100 otherwise. Configs without the line are
    inferred from UDP_PORTS; a missing config means the default narrow range.
    """
    try:
        text = cfg.NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return nfqws.NARROW_VOICE_HIGH, "narrow"
    recorded = nfqws.recorded_voice_range(text)
    return nfqws.voice_high(recorded), recorded


def current_routes_fast():
    try:
        text = cfg.NFQWS_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return nfqws.unknown_routes()
    return nfqws.parse_active_routes(text) or nfqws.unknown_routes()


def safe_snapshot(path):
    try:
        resolved_parent = path.parent.resolve(strict=True)
        expected_parent = cfg.SNAPSHOT_DIR.resolve(strict=True)
        info = path.lstat()
    except OSError:
        return False
    return (
        resolved_parent == expected_parent
        and re.fullmatch(r"[0-9A-Za-z-]+", path.name) is not None
        and stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and (path / "STATE.tsv").is_file()
        and (path / "MANIFEST").is_file()
    )


def parse_snapshot_from_output(output):
    pattern = re.compile(
        r"(?:Snapshot created|Rescue snapshot of current state): "
        + re.escape(str(cfg.SNAPSHOT_DIR))
        + r"[\\/]([0-9A-Za-z-]+)"
    )
    match = pattern.search(output)
    if not match:
        return ""
    candidate = cfg.SNAPSHOT_DIR / match.group(1)
    return str(candidate) if safe_snapshot(candidate) else ""


def nfqws_config_hash():
    return hashlib.sha256(cfg.NFQWS_CONFIG.read_bytes()).hexdigest()


def import_pointer_value():
    try:
        info = cfg.IMPORT_ROLLBACK_POINTER.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 1024:
            raise ValueError("необычный файл указателя отката")
        return cfg.IMPORT_ROLLBACK_POINTER.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def imported_candidate_id(service):
    if service not in {"youtube", "discord-tcp"}:
        raise ValueError("неверный сервис снимка")
    try:
        value = fsutil.safe_json_file(cfg.IMPORTED_PROFILE_DIR / f"{service}.json").get("candidate_id", "")
    except FileNotFoundError:
        return ""
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{12}", value) else ""


def import_process_active():
    """True/False/None: own active, proven absent, or incomplete process scan."""
    from kdn.engine import import_worker
    return import_worker.active(cfg.ENGINE)


class ImportWorkerPending(RuntimeError):
    """A bounded worker wait ended without proving quiescence."""


def wait_import_idle(timeout=360):
    deadline = time.monotonic() + timeout
    while import_process_active() is not False:
        if time.monotonic() >= deadline:
            raise ImportWorkerPending('движок импорта ещё работает или его состояние неизвестно; откат не выполнен')
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def new_import_transaction(profile):
    from kdn.engine import snapshot_store
    return {'schema': 2, 'operation_id': uuid.uuid4().hex, 'project': str(cfg.ENGINE.absolute()),
            'service': profile['service'], 'candidate_id': profile['candidate_id'],
            'before_hash': nfqws_config_hash(), 'before_pointer': import_pointer_value(),
            'before_descriptor': snapshot_store.focused_node(cfg.IMPORTED_PROFILE_DIR / (profile['service'] + '.json')),
            'phase': 'applying'}


def recovery_source(transaction):
    """Validate the operation cue; caller durably pins this result before restore."""
    from kdn.engine import snapshot_store
    operation = snapshot_store.focused_context(transaction)
    if operation['project'] != str(cfg.ENGINE.absolute()):
        raise ValueError('focused recovery belongs to another project')
    pointer = import_pointer_value()
    source = transaction.get('original_source') or pointer
    if (not source or pointer != source or pointer == operation['before_pointer']
            or transaction.get('applied_pointer', pointer) != pointer):
        raise ValueError('focused recovery pointer changed or no operation cue exists')
    _saved, _receipt, _before, digest = snapshot_store.focused_source(
        source, transaction, cfg.IMPORT_ROLLBACK_POINTER.parent / 'nfqws-import-snapshots',
        fingerprint=transaction.get('source_fingerprint'))
    return source, digest


def recovery_confirmed(payload, transaction):
    marker = 'FOCUSED_RECOVERED|' + transaction['operation_id'] + '|' + transaction['source_fingerprint']
    return (payload.get('ok') is True and parse_result(payload.get('output', '')) == 'ok'
            and marker in payload.get('output', '').splitlines())


def route_stage(output, operation):
    # Structured markers win over human text, which remains unchanged below
    # for installed older engines and VPN-manager messages.
    markers = re.findall(r'^STAGE\|([a-z-]+)\r?$', output, flags=re.MULTILINE)
    if markers:
        labels = {'preflight': ('Проверка конфигурации', 10), 'snapshot': ('Создание snapshot', 25)}
        if operation == 'switch':
            labels.update(config=('Запись конфигурации', 45), xray=('Перезапуск XKeen/Xray', 65),
                          nfqws=('Перезапуск nfqws2', 82), verify=('Проверка служб', 94))
        elif operation == 'vpn-node':
            labels.update(snapshot=('Снимок текущей VPN-ноды', 40), xray=('Перезапуск XKeen/Xray', 75),
                          verify=('Проверка выбранной ноды', 94))
        elif operation == 'vpn-recover':
            labels['verify'] = ('Прежняя VPN-нода восстановлена', 94)
        else:
            labels.update(snapshot=('Rescue snapshot', 30), restore=('Восстановление файлов', 58),
                          verify=('Проверка восстановленного состояния', 92))
        if markers[-1] in labels:
            return (markers[-1], *labels[markers[-1]])
    stages = [
        ("preflight", "Проверка конфигурации", 10),
    ]
    if "Snapshot created:" in output:
        stages.append(("snapshot", "Создание snapshot", 25))
    if operation == "switch":
        if "Patching Xray routing:" in output or "Patching Mihomo" in output:
            stages.append(("config", "Запись конфигурации", 45))
        if "Restarting XKeen..." in output:
            stages.append(("xray", "Перезапуск XKeen/Xray", 65))
        if "Restarting nfqws2 only" in output:
            stages.append(("nfqws", "Перезапуск nfqws2", 82))
        if "Started NFQWS2 service" in output:
            stages.append(("verify", "Проверка служб", 94))
    elif operation == "vpn-node":
        if "VPN snapshot created:" in output:
            stages.append(("snapshot", "Снимок текущей VPN-ноды", 40))
        if "Restarting XKeen for selected VPN node" in output:
            stages.append(("xray", "Перезапуск XKeen/Xray", 75))
        if "Global VPN node active" in output:
            stages.append(("verify", "Проверка выбранной ноды", 94))
    elif operation == "vpn-recover":
        if "Previous global VPN node restored" in output:
            stages.append(("verify", "Прежняя VPN-нода восстановлена", 94))
    else:
        if "Rescue snapshot of current state:" in output:
            stages.append(("snapshot", "Rescue snapshot", 30))
        if "Restoring" in output:
            stages.append(("restore", "Восстановление файлов", 58))
        if "Restore complete:" in output:
            stages.append(("verify", "Проверка восстановленного состояния", 92))
    return stages[-1]


def parse_result(output):
    """Only a final complete result marker can settle an operation; never an earlier one."""
    if not isinstance(output, str):
        return None
    final = output.rstrip('\r\n').split('\n')[-1]
    match = re.fullmatch(r'RESULT\|(ok|failed|rolled-back|partial)\r?', final)
    return match.group(1) if match else None


def apply_profile(profile, *, operation_context=None):
    stage_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cfg.IMPORT_STAGING_DIR,
            prefix="xkeen-profile-",
            suffix=".json",
            delete=False,
        ) as stage:
            json.dump(profile, stage, ensure_ascii=False, indent=2)
            stage.write("\n")
            stage_path = stage.name
        os.chmod(stage_path, 0o600)
        args = ['--apply-import-profile', stage_path, '--yes-router']
        if operation_context is not None:
            args.extend(('--focused-operation-context', json.dumps(operation_context, separators=(',', ':'))))
        return proc.run_command(engine_command(*args), timeout=300)
    finally:
        if stage_path:
            try:
                os.unlink(stage_path)
            except FileNotFoundError:
                pass

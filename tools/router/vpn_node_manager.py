#!/usr/bin/env python3
"""Manage one global Xray proxy outbound behind the stable routing tag.

The node registry is private. Route rules always keep using vless-reality;
activating a node replaces only that outbound's configuration. Health checks
run in a short-lived, isolated Xray process and never restart live XKeen.
"""

from __future__ import annotations

import copy
import functools
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit, unquote
import unicodedata

from kdn.common import lock as project_lock, xkeen, xray_process
from kdn import vpn_links, vpn_fields, vpn_diagnostics
from kdn.engine import nfqws_process


ACTIVE_TAG = "vless-reality"
SUPPORTED_PROTOCOLS = frozenset({"vless", "trojan", "hysteria"})
NODE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}\Z")
MAX_NODES = 16
MAX_NODE_BYTES = 32 * 1024
MAX_STORE_BYTES = 768 * 1024
PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace",
)


def store_mutation(method):
    """Same writer/lock protocol for HTTP jobs, CLI and direct module callers."""
    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        self._require_supported_xkeen()
        with project_lock.ProjectLock(self.lock_dir):
            self._mutation_allowed()
            result = method(self, *args, **kwargs)
            return self._after_commit(result)
    return guarded


def cancellable(method):
    """A worker TERM must unwind finally/rollback, not orphan its probe daemon."""
    @functools.wraps(method)
    def guarded(*args, **kwargs):
        previous = {}
        def cancel(_signum, _frame):
            raise SystemExit(130)
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                old = signal.getsignal(signum)
                if old != signal.SIG_IGN:
                    previous[signum] = old
                    signal.signal(signum, cancel)
        try:
            return method(*args, **kwargs)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return guarded


def display_name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 1024 or any(unicodedata.category(char)[0] == 'C' for char in value):
        raise ValueError('некорректное имя VPN-ноды')
    value = unicodedata.normalize('NFC', value.strip())
    if (not value or len(value) > 64 or len(value.encode('utf-8', errors='surrogatepass')) > 256
            or any(not (unicodedata.category(char)[0] in 'LNM' or unicodedata.category(char) in {'So', 'Pd'}
                        or char in ' ._()-+') for char in value)):
        raise ValueError('имя ноды: до64 Unicode букв/цифр, пробелы, emoji и ._()-+')
    return value


def safe_normalize_outbound(source):
    try:
        if isinstance(source, str) and len(source.encode('utf-8')) > MAX_NODE_BYTES:
            raise ValueError('oversized source')
        return normalize_outbound(source)
    except (ValueError, TypeError, AttributeError, RecursionError, UnicodeError):
        raise ValueError('некорректная ссылка или JSON outbound; проверьте формат и параметры') from None


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def public_health(value):
    if not isinstance(value, dict):
        return None
    allowed = {'ok','checked_utc','checked_at','latency_ms','latency_kind','total_ms',
               'startup_ms','http_code','curl_code','target','detail'}
    result = {key:item for key,item in value.items() if key in allowed
              and isinstance(item,(str,int,float,bool)) and (not isinstance(item,str) or len(item)<=500)}
    if isinstance(value.get('log'),str):
        result['log']=value['log'].encode('utf-8')[:8192].decode('utf-8',errors='ignore')
    return result


def stage(name):
    try:
        print('STAGE|' + name, flush=True)
    except OSError:
        pass  # Progress output is not part of the transaction commit.


def strip_json_comments(value: str) -> str:
    result = []
    index = 0
    while index < len(value):
        if value[index] == '"':
            end = index + 1
            while end < len(value) and value[end] != '"':
                end += 2 if value[end] == "\\" else 1
            result.append(value[index:end + 1])
            index = end + 1
        elif value.startswith("//", index):
            end = value.find("\n", index)
            index = len(value) if end < 0 else end
        elif value.startswith("/*", index):
            end = value.find("*/", index + 2)
            result.append(" ")
            index = len(value) if end < 0 else end + 2
        else:
            result.append(value[index])
            index += 1
    return "".join(result)


def private_json(path: Path, limit: int = MAX_STORE_BYTES) -> dict:
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or not 0 < info.st_size <= limit:
        raise ValueError("небезопасный или слишком большой JSON-файл")
    value = json.loads(strip_json_comments(path.read_text(encoding="utf-8")))
    if not isinstance(value, dict):
        raise ValueError("ожидается JSON-объект")
    return value


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def atomic_json(path: Path, value: dict, mode: int = 0o600) -> None:
    payload = _json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, filename = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_restore(source: Path, target: Path, mode=None) -> None:
    data = source.read_bytes()
    descriptor, filename = tempfile.mkstemp(prefix=f".{target.name}.restore.", dir=target.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(source.stat().st_mode) if mode is None else mode)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_outbound(source: str | dict) -> dict:
    if isinstance(source, str):
        source = source.strip()
        if source.lower().startswith(("vless://", "trojan://", "hysteria2://", "hy2://")):
            outbound = vpn_links.parse_link(source, ACTIVE_TAG)
        else:
            try:
                outbound = vpn_links._object(source)
            except json.JSONDecodeError as exc:
                raise ValueError("вставьте VLESS/Trojan/Hysteria2-ссылку или один JSON outbound") from exc
    else:
        outbound = copy.deepcopy(source)
    if not isinstance(outbound, dict) or outbound.get("protocol") not in SUPPORTED_PROTOCOLS:
        raise ValueError("поддерживается один outbound VLESS, Trojan или Hysteria2 (protocol=hysteria)")
    if not isinstance(outbound.get("settings"), dict) or not isinstance(outbound.get("streamSettings"), dict):
        raise ValueError("в outbound обязательны settings и streamSettings")
    hysteria_options = outbound["streamSettings"].get("hysteriaSettings")
    if outbound["protocol"] == "hysteria" and (
            outbound["settings"].get("version") != 2 or
            outbound["streamSettings"].get("network") != "hysteria" or
            not isinstance(hysteria_options, dict) or hysteria_options.get("version") != 2):
        raise ValueError("для Hysteria2 нужны version=2 и transport hysteria")
    pending = [outbound]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 4096:
            raise ValueError('outbound structure exceeds budget')
        if isinstance(item, dict):
            if any(item.get(key) for key in ('proxySettings', 'dialerProxy')):
                raise ValueError("outbound со ссылкой на другой outbound нельзя проверять отдельно")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    outbound["tag"] = ACTIVE_TAG
    if len(json.dumps(outbound, ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_NODE_BYTES:
        raise ValueError("outbound слишком большой")
    return outbound


class VpnNodeManager:
    def __init__(self, *, xray_dir: Path = Path("/opt/etc/xray/configs"),
                 state_file: Path = Path("/opt/etc/xkeen-web/vpn-nodes.json"),
                 backup_dir: Path = Path("/opt/etc/xkeen-web/vpn-switch-backups"),
                 lock_dir: Path = Path("/opt/tmp/keenetic-discord-nfqws2.lock"),
                 xray: str = "/opt/sbin/xray", xkeen: str = "/opt/sbin/xkeen",
                 curl: str = "/opt/bin/curl", dat_dir: Path = Path("/opt/etc/xray/dat"),
                 restart_timeout: float = 90, poll_interval: float = 1.0,
                 nfqws_conf: Path = Path('/opt/etc/nfqws2/nfqws2.conf'),
                 xkeen_init: str = '/opt/etc/init.d/S05xkeen', proc_root: Path = Path('/proc')):
        self.xray_dir = Path(xray_dir)
        self.outbound_file = self.xray_dir / "04_outbounds.json"
        self.state_file = Path(state_file)
        self.transaction_file = self.state_file.parent / "vpn-switch-transaction.json"
        self.backup_dir = Path(backup_dir)
        self.lock_dir = Path(lock_dir)
        self.xray = xray
        self.xkeen = xkeen
        self.curl = curl
        self.dat_dir = Path(dat_dir)
        self.restart_timeout = restart_timeout
        self.poll_interval = poll_interval
        self.nfqws_conf = Path(nfqws_conf)
        self.xkeen_init = xkeen_init
        self.proc_root = Path(proc_root)
        self.compatibility_guard = None

    def _require_supported_xkeen(self):
        if self.compatibility_guard is not None:
            self.compatibility_guard()
            return
        xkeen.require(self.xkeen)
        self._require_supported_xray()

    def _require_supported_xray(self):
        done = nfqws_process.run([self.xray, 'version'], os.environ, timeout=5, output_limit=4096)
        match = re.match(r'Xray (\d+)\.(\d+)\.(\d+)\b', done.output)
        version = tuple(map(int, match.groups())) if match else ()
        if (done.returncode or done.timed_out or done.output_limited or not version
                or version[0] != 26 or version < (26, 10, 31)):
            raise ValueError('для параметров VPN-ноды требуется Xray26.10.31+ поколения26')

    def _owns_xray_pid(self, pid):
        return xray_process.xray_identity(pid, self.xray_dir, executable=self.xray, proc_root=self.proc_root)

    def _xray_pids(self) -> frozenset[str]:
        pidof = subprocess.run(["pidof", "xray"], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, check=False, timeout=5)
        tokens = pidof.stdout.split() if pidof.returncode == 0 else []
        found = frozenset(pid for pid in tokens[:64] if self._owns_xray_pid(pid))
        if len(found) > 1:
            raise RuntimeError('несколько Xray используют рабочий confdir')
        return found

    def _restart_xkeen(self, previous_pids: frozenset[str]) -> None:
        # XKeen2.1 init's final "on" requests synchronous foreground operation.
        # CLI2.0 detaching behaviour is deliberately not a fallback.
        from kdn.inspection import receipt
        prepared_digest = receipt.corpus_digest(self.xray_dir) if (self.xray_dir / receipt.layout.FILE).is_file() else None
        try:
            restarted = subprocess.run([self.xkeen_init, "restart", "on"], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=150, check=False,
                                       env={**os.environ, "XKEEN_FOREGROUND": "1"})
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("xkeen -restart завершился с ошибкой: таймаут 150 с") from exc
        if restarted.returncode != 0:
            raise RuntimeError(f"xkeen -restart завершился с ошибкой: код {restarted.returncode}")
        waited = 0.0
        while not self._xray_pids() - previous_pids:
            if waited >= self.restart_timeout:
                raise RuntimeError(f"Xray не перезапустился за {self.restart_timeout} с")
            time.sleep(self.poll_interval)
            waited += self.poll_interval
        if prepared_digest is not None:
            live = self._xray_pids()
            if len(live) == 1:
                receipt.refresh_if_prepared(self.state_file.parent / 'inspection-runtime.json', self.xray_dir,
                                            int(next(iter(live))), expected_digest=prepared_digest)

    def _xray_config_test(self, directory=None) -> None:
        # "xkeen -xtest" always exits 0 (the XKeen main loop has no exit), so
        # run what XKeen runs itself: xray over the whole config directory.
        command = [self.xray, "run", "-test", "-confdir", str(directory or self.xray_dir), "-format", "json"]
        try:
            test = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  text=True, errors="replace", timeout=60, check=False,
                                  env={**os.environ, "XRAY_LOCATION_ASSET": str(self.dat_dir), 'GOMEMLIMIT': '32MiB'})
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("общий Xray-конфиг не прошёл xray -test: таймаут 60 с") from exc
        if test.returncode != 0:
            raise RuntimeError("общий Xray-конфиг не прошёл xray -test; проверьте параметры ноды (секретный вывод скрыт)")

    def _test_staged(self, document):
        with tempfile.TemporaryDirectory(prefix='xkeen-vpn-stage-') as folder:
            stage = Path(folder)
            total = 0
            for source in self.xray_dir.glob('*.json'):
                data = private_json(source, limit=2 * 1024 * 1024)
                total += source.stat().st_size
                if total > 8 * 1024 * 1024:
                    raise ValueError('Xray configuration exceeds staging budget')
                atomic_json(stage / source.name, document if source == self.outbound_file else data)
            self._xray_config_test(stage)

    def _current_file(self) -> tuple[dict, dict]:
        document = private_json(self.outbound_file)
        outbounds = document.get("outbounds")
        if not isinstance(outbounds, list):
            raise ValueError("в 04_outbounds.json нет списка outbounds")
        matches = [item for item in outbounds if isinstance(item, dict) and item.get("tag") == ACTIVE_TAG]
        if len(matches) != 1 or matches[0].get("protocol") not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"ожидается ровно один VPN outbound с тегом {ACTIVE_TAG}")
        return document, matches[0]

    def _checked_state(self, state):
        nodes = state.get("nodes")
        if (state.get("version") != 1 or not isinstance(nodes, dict) or
                not 1 <= len(nodes) <= MAX_NODES or state.get("active") not in nodes):
            raise ValueError("реестр VPN-нод повреждён")
        for key, node in nodes.items():
            if not isinstance(key, str) or not NODE_NAME.fullmatch(key) or not isinstance(node, dict):
                raise ValueError("некорректная запись VPN-ноды")
            normalize_outbound(node.get("outbound"))
            display_name(node.get('name', key))
        return state

    def load(self) -> dict:
        if self.state_file.exists() or self.state_file.is_symlink():
            state = self._checked_state(private_json(self.state_file))
            _, current = self._current_file()
            current = normalize_outbound(current)
            active = state['nodes'][state['active']]
            # The file is authoritative for the selected outbound on every
            # read. Overlay only in memory: GET never writes the registry.
            if normalize_outbound(active['outbound']) != current:
                active['outbound'] = current
                active['health'] = None
                active['ping'] = None
            return state
        _, current = self._current_file()
        current = normalize_outbound(current)
        return {"version": 1, "active": "current", "nodes": {
            "current": {"name": "Текущее подключение", "outbound": current,
                        "created_utc": utc_now(), "health": None}}}

    def _public_node(self, key: str, node: dict, active: str) -> dict:
        outbound = node["outbound"]
        settings = outbound.get("settings", {})
        endpoint = settings.get("address", "")
        port = settings.get("port", "")
        valid_endpoint = (isinstance(endpoint, str) and len(endpoint) <= 253
                          and re.fullmatch(r'[A-Za-z0-9_.:-]+', endpoint)
                          and type(port) is int and 1 <= port <= 65535)
        stream = outbound.get('streamSettings', {})
        network = stream.get('network', 'tcp')
        security = stream.get('security', 'none')
        network = network if isinstance(network, str) and network in {'tcp', 'raw', 'ws', 'grpc', 'xhttp', 'splithttp', 'httpupgrade', 'hysteria', 'kcp', 'quic'} else 'unknown'
        security = security if isinstance(security, str) and security in {'none', 'tls', 'reality'} else 'unknown'
        tls = stream.get('realitySettings' if security == 'reality' else 'tlsSettings', {}) if security in {'tls', 'reality'} else {}
        tls = tls if isinstance(tls, dict) else {}
        sni = tls.get('serverName')
        sni = sni if isinstance(sni, str) and len(sni) <= 253 and re.fullmatch(r'[A-Za-z0-9_.:-]+', sni) else None
        fingerprint = tls.get('fingerprint')
        fingerprint = fingerprint if isinstance(fingerprint, str) and fingerprint in {
            'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized'
        } else None
        flow = settings.get('flow')
        flow = flow if isinstance(flow, str) and flow in {'xtls-rprx-vision', 'xtls-rprx-vision-udp443'} else None
        health = public_health(node.get('health'))
        # Endpoint is operational context; credentials/Reality keys never leave.
        return {"id": key, "name": node.get("name", key), "active": key == active,
                "protocol": "Hysteria2" if outbound.get("protocol") == "hysteria" else outbound.get("protocol", ""),
                "endpoint": (f"[{endpoint}]:{port}" if ':' in endpoint else f"{endpoint}:{port}") if valid_endpoint else "не указан",
                "network": network, "security": security,
                "flow": flow, "fingerprint": fingerprint, "sni": sni,
                "health": health, "ping": public_health(node.get('ping')), "created_utc": node.get("created_utc", "")}

    def status(self) -> dict:
        try:
            self._require_supported_xkeen()
        except ValueError as error:
            return {'ok': False, 'supported': False, 'error': str(error),
                    'error_code': xkeen.ERROR_CODE if isinstance(error, xkeen.UnsupportedXKeen) else 'unsupported_xray',
                    'active': '', 'nodes': [], 'drift': True, 'canonical_tag': ACTIVE_TAG,
                    'recovery_needed': False, 'warning': str(error)}
        recovery = self.transaction_file.exists() or self.transaction_file.is_symlink()
        try:
            state = self.load()
            _, current = self._current_file()
        except (OSError, ValueError, TypeError, RecursionError):
            if not recovery:
                raise
            # Keep recovery reachable in the UI even after a partial/corrupt
            # registry publication. A GET never repairs those files itself.
            return {'ok': True, 'active': '', 'nodes': [], 'drift': True,
                    'canonical_tag': ACTIVE_TAG, 'recovery_needed': True,
                    'warning': 'Незавершённое переключение VPN: требуется восстановление'}
        active = state.get("active", "")
        stored = state.get("nodes", {}).get(active, {}).get("outbound")
        drift = stored is None or normalize_outbound(stored) != normalize_outbound(current)
        try:
            self._verify_global_targets()
            warning = ""
        except ValueError as exc:
            warning = str(exc)
        return {"ok": True, "active": active, "drift": drift,
                "nodes": [self._public_node(key, node, active) for key, node in state['nodes'].items()],
                "canonical_tag": ACTIVE_TAG, "warning": warning,
                "recovery_needed": recovery}

    def _mutation_allowed(self):
        if self.transaction_file.exists() or self.transaction_file.is_symlink():
            raise ValueError('сначала восстановите незавершённое переключение VPN')
        for target in (self.state_file, self.backup_dir, self.outbound_file):
            if any(path.is_symlink() for path in (target, *target.parents)):
                raise ValueError('небезопасный путь VPN')

    def _prune_private_history(self):
        # Never prune a recovery source, even if a future caller bypasses the
        # mutation admission guard. Only exact manager-owned names are eligible.
        if self.transaction_file.exists() or self.transaction_file.is_symlink():
            return
        groups = ((self.backup_dir, 20, r'\d{8}T\d{6}Z-[0-9a-f]{8}'),
                  (self.state_file.parent / 'vpn-node-trash', 32, r'\d+-[A-Za-z][A-Za-z0-9_.-]{0,31}-[0-9a-f]{8}\.json'),
                  (self.state_file.parent / 'vpn-node-versions', 64, r'\d+-[A-Za-z][A-Za-z0-9_.-]{0,31}-[0-9a-f]{8}\.json'))
        for folder, limit, pattern in groups:
            if not folder.is_dir() or any(p.is_symlink() for p in (folder, *folder.parents)):
                continue
            rows = []
            for path in folder.iterdir():
                if not re.fullmatch(pattern, path.name) or path.is_symlink():
                    continue
                children = list(path.iterdir()) if path.is_dir() else [path]
                if any(p.is_symlink() or not p.is_file() for p in children):
                    continue
                if path.is_dir() and set(p.name for p in children) - {'04_outbounds.json', 'vpn-nodes.json'}:
                    continue
                rows.append((path.name, path, sum(p.stat().st_size for p in children)))
            rows.sort(reverse=True)
            total = 0
            for index, (_, path, size) in enumerate(rows):
                total += size
                if index >= limit or (total > 16 * 1024 * 1024 and index > 0):
                    if path.is_dir():
                        for child in path.iterdir():
                            child.unlink()
                        path.rmdir()
                    else:
                        path.unlink()

    def _after_commit(self, result):
        try:
            self._prune_private_history()
        except OSError:
            # Retention is housekeeping, not a reason to report a committed
            # activation/edit as failed. Preserve the successful transaction.
            result['warning'] = 'Изменение сохранено, но очистка старых VPN-бэкапов не удалась; проверьте место и права'
        return result

    def _check_store_size(self, state):
        if len(_json_bytes(state)) > MAX_STORE_BYTES:
            raise ValueError('реестр VPN превышает допустимый размер')

    def _save_state(self, state):
        self._check_store_size(state)
        atomic_json(self.state_file, state)

    @store_mutation
    def add(self, name: str, source: str, *, auto_name=False) -> dict:
        outbound = safe_normalize_outbound(source)
        state = self.load()
        if auto_name:
            hint = name if isinstance(name, str) else ''
            if not hint:
                try:
                    if source.lower().startswith(('vless://','trojan://','hy2://','hysteria2://')):
                        hint = unquote(urlsplit(source).fragment)
                    else:
                        original = vpn_links._object(strip_json_comments(source))
                        hint = original.get('tag', '')
                except (ValueError, TypeError):
                    pass
            if not isinstance(hint, str) or not hint or hint == 'current':
                address = outbound.get('settings', {}).get('address')
                hint = address if isinstance(address,str) and address else outbound['protocol']
            hint = ''.join(char if (unicodedata.category(char)[0] in 'LNM' or
                           unicodedata.category(char) in {'So', 'Pd'} or char in ' ._()-+') else ' '
                           for char in str(hint))
            base = ' '.join(hint.split())[:48] or 'VPN'
            name = base
            number = 2
            existing = {row.get('name', key).casefold() for key, row in state['nodes'].items()}
            while name.casefold() in existing:
                name = f'{base} {number}'
                number += 1
        name = display_name(name)
        if name == 'current':
            raise ValueError('зарезервированное имя ноды')
        if any(display_name(row.get('name', key)).casefold() == name.casefold() for key, row in state['nodes'].items()) or len(state["nodes"]) >= MAX_NODES:
            raise ValueError("нода уже существует или достигнут предел 16 нод")
        key = name if NODE_NAME.fullmatch(name) and name not in state['nodes'] else 'node_' + secrets.token_hex(8)
        if key in state['nodes']:
            raise ValueError('ID ноды уже существует')
        state["nodes"][key] = {"name": name, "outbound": outbound,
                                "created_utc": utc_now(), "health": None}
        self._save_state(state)
        return {"ok": True, "node": self._public_node(key, state["nodes"][key], state["active"])}

    def update(self, node_id: str, *, name=None, source=None, fields=None) -> dict:
        self._require_supported_xkeen()
        if not isinstance(node_id, str) or not NODE_NAME.fullmatch(node_id):
            raise ValueError('некорректный ID VPN-ноды')
        if name is None and source is None and fields is None:
            raise ValueError('не заданы изменения ноды')
        if source is not None and fields is not None:
            raise ValueError('выберите отдельные поля или полную замену подключения')
        with project_lock.ProjectLock(self.lock_dir):
            if self.transaction_file.exists() or self.transaction_file.is_symlink():
                raise ValueError('сначала восстановите незавершённое переключение VPN')
            for path in (self.state_file, *self.state_file.parents):
                if path.is_symlink():
                    raise ValueError('небезопасный путь реестра VPN')
            state = self.load()
            if node_id not in state['nodes']:
                raise ValueError('VPN-нода не найдена')
            old = state['nodes'][node_id]
            new = copy.deepcopy(old)
            if name is not None:
                new['name'] = display_name(name)
                if any(key != node_id and display_name(row.get('name', key)).casefold() == new['name'].casefold()
                       for key, row in state['nodes'].items()):
                    raise ValueError('имя VPN-ноды уже используется')
            if source is not None:
                if node_id == state['active']:
                    raise ValueError('параметры активной ноды не меняются: сначала выберите резервную')
                new['outbound'] = safe_normalize_outbound(source)
                new['health'] = None
                new['ping'] = None
            if fields is not None:
                new['outbound'] = safe_normalize_outbound(vpn_fields.patch_outbound(new['outbound'], fields))
                if new['outbound'] != old['outbound']:
                    new['health'] = None
                    new['ping'] = None
            if node_id == state['active'] and new['outbound'] != old['outbound']:
                # Editing cannot silently replace a working connection. Keep an
                # explicit reserve variant, then use the existing transactional
                # activation (probe + snapshot + restart + rollback) separately.
                if len(state['nodes']) >= MAX_NODES:
                    raise ValueError('для изменённого варианта освободите место в реестре нод')
                base = new['name'][:48]
                for number in range(1, MAX_NODES + 2):
                    draft_name = base + ' — правка' + (f' {number}' if number > 1 else '')
                    if all(row['name'].casefold() != draft_name.casefold() for row in state['nodes'].values()):
                        break
                draft_id = 'node_' + secrets.token_hex(8)
                if draft_id in state['nodes']:
                    raise ValueError('ID резервного варианта уже существует; повторите сохранение')
                new.update(name=display_name(draft_name), created_utc=utc_now(), health=None)
                new['ping'] = None
                state['nodes'][draft_id] = new
                self._save_state(state)
                return self._after_commit({'ok': True, 'draft': True,
                                          'node': self._public_node(draft_id, new, state['active'])})
            if new == old:
                return {'ok': True, 'node': self._public_node(node_id, old, state['active'])}
            new['updated_utc'] = utc_now()
            state['nodes'][node_id] = new
            self._check_store_size(state)
            versions = self.state_file.parent / 'vpn-node-versions'
            if versions.is_symlink():
                raise ValueError('небезопасный каталог версий нод')
            versions.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(versions, 0o700)
            atomic_json(versions / (str(time.time_ns()) + '-' + node_id + '-' + secrets.token_hex(4) + '.json'), old)
            self._save_state(state)
            return self._after_commit({'ok': True, 'node': self._public_node(node_id, new, state['active'])})

    def rename(self, node_id: str, name: str) -> dict:
        return self.update(node_id, name=name)

    @store_mutation
    def check(self, name: str) -> dict:
        state = self.load()
        if name not in state["nodes"]:
            raise ValueError("нода не найдена")
        if name == state['active']:
            _, current = self._current_file()
            if normalize_outbound(state['nodes'][name]['outbound']) != normalize_outbound(current):
                raise ValueError('Конфиг Xray изменился во время чтения; обновите список и повторите проверку')
        health = self.probe(state["nodes"][name]["outbound"])
        state["nodes"][name]["health"] = health
        self._save_state(state)
        return {"ok": True, "health": health}

    @store_mutation
    def ping_nodes(self, node_ids=None):
        from kdn import vpn_ping
        state = self.load()
        if node_ids is None:
            node_ids = list(state['nodes'])
        if (not isinstance(node_ids,list) or not node_ids or len(node_ids)>MAX_NODES
                or any(not isinstance(key,str) or key not in state['nodes'] for key in node_ids)):
            raise ValueError('нода для пинга не найдена')
        selected = {key:normalize_outbound(state['nodes'][key]['outbound']) for key in node_ids}
        stamp = utc_now()
        measured = vpn_ping.run(selected,self.xray)
        # An external editor is not governed by our lock. Never publish a stale
        # measurement or overwrite its newer node/config with our old snapshot.
        latest = self.load()
        result = []
        for key in node_ids:
            ping = {**measured[key],'checked_utc':stamp,'checked_at':stamp}
            if key not in latest['nodes'] or normalize_outbound(latest['nodes'][key]['outbound']) != selected[key]:
                ping = {'ok':False,'detail':'нода изменилась во время пинга; повторите проверку','checked_utc':stamp}
            else:
                latest['nodes'][key]['ping'] = ping
            result.append({'id':key,'ping':public_health(ping)})
        self._save_state(latest)
        return {'ok':True,'results':result,**({'ping':result[0]['ping']} if len(result)==1 else {})}

    @store_mutation
    def remove(self, name: str) -> dict:
        state = self.load()
        if name not in state["nodes"]:
            raise ValueError("нода не найдена")
        if name == state["active"]:
            raise ValueError("активную VPN-ноду удалять нельзя")
        removed = state['nodes'].pop(name)
        self._check_store_size(state)
        trash = self.state_file.parent / "vpn-node-trash"
        trash.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(trash, 0o700)
        atomic_json(trash / f"{int(time.time())}-{name}-{secrets.token_hex(4)}.json",
                    removed)
        self._save_state(state)
        return {"ok": True}

    def _probe_config(self, outbound: dict, port: int) -> dict:
        selected = normalize_outbound(outbound)
        selected["tag"] = "probe-vpn"
        return {"log": {"loglevel": "warning"},
                "inbounds": [{"tag": "probe-in", "listen": "127.0.0.1", "port": port,
                              "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                "outbounds": [selected],
                "routing": {"rules": [{"inboundTag": ["probe-in"],
                                       "outboundTag": "probe-vpn"}]}}

    @cancellable
    def probe(self, outbound: dict) -> dict:
        started = time.monotonic()
        checked_utc = utc_now()
        base = {"checked_utc": checked_utc, "checked_at": checked_utc}
        events = []
        capture_ready = False

        def note(phase, message):
            if len(events) < 32:
                events.append(f'{time.monotonic() - started:.3f}s [{phase}] {message}')

        def finish(ok, detail='', **fields):
            if capture_ready:
                capture.flush()
                size = os.fstat(capture.fileno()).st_size
                raw = os.pread(capture.fileno(), 8192, max(0, size - 8192)).decode('utf-8', errors='replace')
                issues = vpn_diagnostics.xray_issues(raw)
                for issue in issues:
                    note('xray', issue)
                if not ok and not issues:
                    note('xray', 'Дополнительная причина не определена; сырой вывод скрыт для защиты секретов')
            note('result', 'OK' if ok else 'FAIL')
            result = {**base, 'ok': ok, 'total_ms': round((time.monotonic() - started) * 1000),
                      'log': '\n'.join(events).encode('utf-8')[:8192].decode('utf-8', errors='ignore'), **fields}
            if detail:
                result['detail'] = detail
            return result

        metadata = self._public_node('probe', {'outbound': outbound}, '')
        protocol = metadata['protocol'] if isinstance(metadata['protocol'], str) and metadata['protocol'] in {'vless', 'trojan', 'Hysteria2'} else 'unknown'
        note('path', f"{protocol} / {metadata['network']} / {metadata['security']} → тестовые HTTPS-сайты")
        note('preflight', 'Проверка совместимости XKeen/Xray')
        try:
            self._require_supported_xkeen()
        except ValueError as error:
            return finish(False, str(error))
        # curl must not read .curlrc or honour host proxy/NO_PROXY overrides.
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
        env["GOMEMLIMIT"] = "32MiB"
        env['PYTHONPATH'] = str(Path(__file__).resolve().parent)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="xkeen-vpn-probe-") as directory, tempfile.TemporaryFile(mode='w+b') as capture:
            capture_ready = True
            path = Path(directory) / "probe.json"
            atomic_json(path, self._probe_config(outbound, port))
            try:
                note('config', 'Xray -test: проверка временной конфигурации')
                test = subprocess.run([self.xray, "run", "-c", str(path), "-test"],
                                      stdout=capture, stderr=capture,
                                      timeout=12, check=False, env=env)
            except (OSError, subprocess.TimeoutExpired):
                note('config', 'Таймаут 12 с или ошибка запуска Xray -test')
                return finish(False, 'изолированный Xray не прошёл проверку')
            note('config', f'Xray -test: exit={test.returncode}')
            if test.returncode != 0:
                return finish(False, 'конфигурация ноды не принята Xray')
            capture.seek(0)
            capture.truncate()
            try:
                note('startup', 'Запуск отдельного Xray и ожидание SOCKS на loopback; предел 4 с')
                process = subprocess.Popen([sys.executable, '-m', 'kdn.vpn_probe_child', str(os.getpid()), self.xray, str(path)],
                                           stdin=subprocess.DEVNULL, stdout=capture,
                                           stderr=capture, env=env, start_new_session=True)
            except OSError:
                return finish(False, 'не удалось запустить тестовый Xray')
            stop = threading.Event()
            exceeded = threading.Event()
            log_exceeded = threading.Event()

            def watch_memory():
                while not stop.wait(0.1):
                    try:
                        if os.fstat(capture.fileno()).st_size > 128 * 1024:
                            log_exceeded.set()
                            process.kill()
                            return
                        text = Path("/proc", str(process.pid), "status").read_text()
                        match = re.search(r"^VmRSS:\s+([0-9]+)", text, re.MULTILINE)
                        if match and int(match[1]) > 96 * 1024:
                            exceeded.set()
                            process.kill()
                            return
                    except OSError:
                        return

            watcher = threading.Thread(target=watch_memory, daemon=True)
            watcher.start()
            try:
                deadline = time.monotonic() + 4
                ready = False
                while time.monotonic() < deadline and process.poll() is None and not exceeded.is_set():
                    with socket.socket() as connection:
                        connection.settimeout(0.2)
                        if connection.connect_ex(("127.0.0.1", port)) == 0:
                            ready = True
                            break
                    time.sleep(0.1)
                if not ready:
                    note('startup', f'SOCKS не готов; exit={process.poll()}')
                    if log_exceeded.is_set():
                        return finish(False, 'тестовый Xray превысил лимит журнала 128 KiB')
                    if exceeded.is_set():
                        return finish(False, 'тестовый Xray превысил лимит памяти 96 MiB')
                    return finish(False, 'тестовый SOCKS Xray не открылся')
                note('startup', 'Локальный SOCKS готов; это ещё не подтверждает соединение с VPN-сервером')
                last_code = 0
                first_bytes = []
                for url in PROBE_URLS:
                    if log_exceeded.is_set():
                        return finish(False, 'тестовый Xray превысил лимит журнала 128 KiB')
                    if exceeded.is_set() or process.poll() is not None:
                        return finish(False, 'тестовый Xray остановлен или превысил лимит памяти')
                    target = urlsplit(url).hostname
                    expected = 204 if url.endswith('/generate_204') else 200
                    note('https', f'{target}: ожидается HTTP {expected}; connect-timeout=4 с, max-time=8 с')
                    request_started = time.monotonic()
                    try:
                        result = subprocess.run(
                            [self.curl, "--disable", "--silent", "--show-error", "--noproxy", "",
                             "--socks5-hostname", f"127.0.0.1:{port}",
                             "--proto", "=https", "--connect-timeout", "4", "--max-time", "8",
                             "--output", "/dev/null", "--write-out", "%{http_code}|%{time_starttransfer}", url],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=10, check=False, env=env)
                    except OSError:
                        note('https', 'Не удалось запустить curl')
                        return finish(False, 'не удалось запустить HTTPS-пробу')
                    except subprocess.TimeoutExpired:
                        note('https', f'{target}: процесс curl не завершился за 10 с')
                        return finish(False, 'таймаут HTTPS через эту ноду')
                    note('https', f'{target}: curl={result.returncode} ({vpn_diagnostics.curl_reason(result.returncode)}), запрос={(time.monotonic() - request_started):.3f} с')
                    if process.poll() is not None:
                        note('runtime', f'Тестовый Xray завершился: exit={process.poll()}')
                    for issue in vpn_diagnostics.xray_issues(getattr(result, 'stderr', '')):
                        note('curl', issue)
                    if log_exceeded.is_set():
                        return finish(False, 'тестовый Xray превысил лимит журнала 128 KiB')
                    if exceeded.is_set() or process.poll() is not None:
                        return finish(False, 'тестовый Xray остановлен или превысил лимит памяти')
                    text, separator, elapsed = result.stdout.strip().partition('|')
                    last_code = int(text) if re.fullmatch(r"[0-9]{3}", text) else 0
                    note('https', f'{target}: HTTP {last_code:03d}, ожидается {expected}')
                    if result.returncode != 0 or last_code != expected:
                        return finish(False, f'HTTPS: curl={result.returncode}, HTTP {last_code:03d} вместо {expected}; '+vpn_diagnostics.curl_reason(result.returncode),
                                      http_code=last_code, curl_code=result.returncode, target=target)
                    if not separator or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', elapsed):
                        return finish(False, 'curl не вернул время ответа HTTPS')
                    first_bytes.append(float(elapsed))
                    note('https', f'{target}: первый байт={float(elapsed):.3f} с')
                if exceeded.is_set() or process.poll() is not None:
                    return finish(False, 'тестовый Xray завершился')
                return finish(True, latency_ms=round(min(first_bytes) * 1000), latency_kind='https_ttfb',
                              http_code=last_code, curl_code=0, target=urlsplit(PROBE_URLS[-1]).hostname)
            finally:
                stop.set()
                watcher.join(timeout=2)
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

    def _verify_global_targets(self) -> None:
        if self.nfqws_conf.is_symlink():
            raise ValueError('небезопасный путь nfqws2.conf')
        if self.nfqws_conf.exists():
            with self.nfqws_conf.open('rb') as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('nfqws2.conf превышает лимит')
            tags = re.findall(r'^# Proxy outbound: ([A-Za-z0-9_.:-]*)\.$', raw.decode('utf-8'), re.MULTILINE)
            if tags != [ACTIVE_TAG]:
                raise ValueError('шапка Proxy outbound не совпадает с глобальным VPN tag')
        protocols = {}
        for path in sorted(self.xray_dir.glob("*.json")):
            data = private_json(path, limit=2 * 1024 * 1024)
            for outbound in data.get("outbounds", []):
                if isinstance(outbound, dict):
                    tag = outbound.get("tag")
                    if tag in protocols:
                        raise ValueError(f"повторяющийся outbound tag: {tag}")
                    protocols[tag] = outbound.get("protocol")
        foreign = sorted(tag for tag, protocol in protocols.items()
                         if isinstance(tag, str) and tag != ACTIVE_TAG and
                         protocol not in {"freedom", "blackhole", "dns", "loopback"})
        if foreign:
            raise ValueError("найдены другие proxy outbound; импортируйте их в менеджер: " + ", ".join(foreign))

    @cancellable
    def activate(self, name: str) -> dict:
        self._require_supported_xkeen()
        with project_lock.ProjectLock(self.lock_dir):
            self._mutation_allowed()
            self._require_supported_xkeen()
            return self._activate_locked(name)

    def _activate_locked(self, name: str) -> dict:
        stage('preflight')
        self._mutation_allowed()
        state = self.load()
        if name not in state["nodes"]:
            raise ValueError("нода не найдена")
        status = self.status()
        if status["drift"]:
            raise ValueError("04_outbounds.json изменён вне панели; сначала синхронизируйте текущую ноду")
        self._verify_global_targets()
        if state.get("active") == name:
            return {"ok": True, "unchanged": True}
        if not self._xray_pids():
            raise RuntimeError("Xray сейчас остановлен; сначала запустите XKeen")
        before_outbound = self.outbound_file.read_bytes()
        before_state = self.state_file.read_bytes() if self.state_file.exists() else None
        health = self.probe(state["nodes"][name]["outbound"])
        if not health["ok"]:
            state["nodes"][name]["health"] = health
            self._save_state(state)
            raise ValueError("нода не прошла проверку; действующий VPN не изменён")
        state["active"] = name
        state["nodes"][name]["health"] = health
        self._check_store_size(state)
        document, _ = self._current_file()
        updated = copy.deepcopy(document)
        updated["outbounds"] = [normalize_outbound(state["nodes"][name]["outbound"])
                                if isinstance(item, dict) and item.get("tag") == ACTIVE_TAG else item
                                for item in updated["outbounds"]]
        self._test_staged(updated)
        if (self.outbound_file.read_bytes() != before_outbound or
                (self.state_file.read_bytes() if self.state_file.exists() else None) != before_state):
            raise ValueError('VPN configuration changed during preflight; no changes applied')
        self._verify_global_targets()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snapshot = self.backup_dir / f"{stamp}-{secrets.token_hex(4)}"
        snapshot.mkdir(parents=True, mode=0o700)
        os.chmod(snapshot, 0o700)
        shutil.copy2(self.outbound_file, snapshot / "04_outbounds.json")
        os.chmod(snapshot / "04_outbounds.json", 0o600)
        if self.state_file.is_file():
            private_json(self.state_file)
            shutil.copy2(self.state_file, snapshot / "vpn-nodes.json")
            os.chmod(snapshot / "vpn-nodes.json", 0o600)
        atomic_json(self.transaction_file, {"version": 1, "snapshot": str(snapshot),
                                           "target": name, "created_utc": utc_now(),
                                           'outbound_mode': stat.S_IMODE(self.outbound_file.stat().st_mode),
                                           'checksums': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                                         for p in snapshot.iterdir()}})
        stage('snapshot')
        try:
            atomic_json(self.outbound_file, updated,
                        mode=stat.S_IMODE(self.outbound_file.stat().st_mode))
            stage('xray')
            self._restart_xkeen(self._xray_pids())
            stage('verify')
            self._save_state(state)
            self.transaction_file.unlink()
        except BaseException as exc:
            try:
                self._restore_switch(self._pending_snapshot())
                self.transaction_file.unlink()
            except BaseException as rollback_exc:
                # Keep the marker: no other mutator may continue before recovery.
                raise RuntimeError("переключение не удалось, автоматический откат Xray тоже не удался; требуется recovery: "
                                   + str(rollback_exc)) from None
            raise exc
        return self._after_commit({"ok": True, "active": name, "snapshot": str(snapshot)})

    def _pending_snapshot(self):
        transaction = private_json(self.transaction_file)
        snapshot_value = transaction.get("snapshot")
        snapshot = Path(snapshot_value) if isinstance(snapshot_value, str) else Path("")
        if (transaction.get("version") != 1 or
                snapshot.parent.resolve() != self.backup_dir.resolve() or
                not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{8}", snapshot.name) or
                any(path.is_symlink() for path in (snapshot, *snapshot.parents)) or
                not snapshot.is_dir()):
            raise ValueError("небезопасный или неполный VPN snapshot")
        private_json(snapshot / "04_outbounds.json")
        if (snapshot / "vpn-nodes.json").exists() or (snapshot / "vpn-nodes.json").is_symlink():
            self._checked_state(private_json(snapshot / "vpn-nodes.json"))
        checksums = transaction.get('checksums')
        if checksums is not None:
            present = {'04_outbounds.json'} | ({'vpn-nodes.json'} if (snapshot / 'vpn-nodes.json').exists() else set())
            if not isinstance(checksums, dict) or set(checksums) != present:
                raise ValueError('неполный checksum VPN snapshot')
            for name, checksum in checksums.items():
                if (not isinstance(checksum, str) or not re.fullmatch(r'[a-f0-9]{64}', checksum)
                        or hashlib.sha256((snapshot / name).read_bytes()).hexdigest() != checksum):
                    raise ValueError('checksum VPN snapshot не совпадает')
        mode = transaction.get('outbound_mode', 0o600)
        if type(mode) is not int or not 0 <= mode <= 0o777:
            raise ValueError('некорректные права VPN snapshot')
        return snapshot

    def _restore_switch(self, snapshot):
        # Validate all backup inputs before the first restore, including absent
        # registry semantics. Always restart: disk equality proves no live state.
        document = private_json(snapshot / "04_outbounds.json")
        previous_state = snapshot / "vpn-nodes.json"
        if previous_state.exists() or previous_state.is_symlink():
            self._checked_state(private_json(previous_state))
        self._test_staged(document)
        transaction = private_json(self.transaction_file)
        atomic_restore(snapshot / "04_outbounds.json", self.outbound_file, transaction.get('outbound_mode', 0o600))
        if previous_state.exists():
            atomic_restore(previous_state, self.state_file)
        else:
            if self.state_file.is_symlink():
                raise ValueError("небезопасный реестр VPN")
            self.state_file.unlink(missing_ok=True)
        try:
            self._restart_xkeen(self._xray_pids())
        except RuntimeError as exc:
            raise RuntimeError("старый Xray-конфиг восстановлен на диске, но XKeen не запустился: " + str(exc)) from None

    @cancellable
    def recover_pending(self) -> dict:
        self._require_supported_xkeen()
        with project_lock.ProjectLock(self.lock_dir):
            if not self.transaction_file.exists() and not self.transaction_file.is_symlink():
                return {"ok": True, "needed": False}
            self._require_supported_xkeen()
            stage('preflight')
            # Recovery permits a pending marker, not symlinked destinations.
            for target in (self.state_file, self.outbound_file, self.backup_dir):
                if any(path.is_symlink() for path in (target, *target.parents)):
                    raise ValueError("небезопасный путь восстановления VPN")
            snapshot = self._pending_snapshot()
            self._restore_switch(snapshot)
            self.transaction_file.unlink()
            stage('verify')
            return self._after_commit({"ok": True, "needed": True, "restarted": True})

    @store_mutation
    def sync_current(self) -> dict:
        state = self.load()
        _, current = self._current_file()
        active = state.get("active", "")
        if active not in state["nodes"]:
            raise ValueError("активная нода отсутствует в реестре")
        state["nodes"][active]["outbound"] = normalize_outbound(current)
        state["nodes"][active]["health"] = None
        state['nodes'][active]['ping'] = None
        self._save_state(state)
        return {"ok": True}


def main(argv: list[str]) -> int:
    if not ((len(argv) == 3 and argv[1] == "activate" and NODE_NAME.fullmatch(argv[2])) or
            (len(argv) == 2 and argv[1] == "recover")):
        print("usage: vpn_node_manager.py activate NODE_ID | recover", file=sys.stderr)
        return 2
    try:
        manager = VpnNodeManager()
        if argv[1] == "activate":
            result = manager.activate(argv[2])
        else:
            result = manager.recover_pending()
        if result.get('warning'):
            print(result['warning'], flush=True)
        return 0
    except Exception as exc:
        print(f"VPN node switch failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

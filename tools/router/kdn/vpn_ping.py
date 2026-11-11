"""One isolated Xray for bounded HTTP HEAD pings, including a whole batch.

Same measurement model as XKeen-UI healthchecker: warm up a tunnel, then
measure a second HEAD on its keep-alive connection. This is not ICMP or an
HTTPS/application acceptance test. No live config or daemon is touched.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

from kdn import vpn_diagnostics

HOST = 'cp.cloudflare.com'
PORT = 80
PATH = '/generate_204'
TIMEOUT = 5
STARTUP_TIMEOUT = 4
CONCURRENCY = 4


def configuration(outbounds, token):
    inbounds, selected, rules, sockets = [], [{'tag': 'ping-block', 'protocol': 'blackhole'}], [], {}
    for index, (key, outbound) in enumerate(outbounds.items()):
        name, inbound, tag = f'{token}-{index}', f'ping-in-{index}', f'ping-out-{index}'
        inbounds.append({'tag': inbound, 'protocol': 'tunnel', 'listen': '@'+name,
                         'settings': {'rewriteAddress': HOST, 'rewritePort': PORT}})
        selected.append({**outbound, 'tag': tag})
        rules.append({'inboundTag': [inbound], 'outboundTag': tag})
        sockets[key] = (name, tag)
    return {'log': {'access': 'none', 'loglevel': 'warning'}, 'inbounds': inbounds,
            'outbounds': selected, 'routing': {'rules': rules}}, sockets


def _head(connection, timeout):
    deadline = time.monotonic()+timeout
    request = f'HEAD {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: KDN-Ping\r\nConnection: keep-alive\r\n\r\n'
    connection.settimeout(timeout)
    connection.sendall(request.encode('ascii'))
    data = bytearray()
    while b'\r\n\r\n' not in data:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        block = connection.recv(2048)
        if not block:
            raise ConnectionError
        data.extend(block)
        if len(data) > 32768:
            raise ValueError('HTTP headers exceed budget')
    match = re.match(rb'HTTP/1\.[01] ([1-5][0-9]{2})\b', data)
    if not match:
        raise ValueError('Invalid HTTP response')
    return int(match[1])


def measure(name, *, timeout=TIMEOUT):
    """Only the second request is measured; no fallback to a direct socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect('\0'+name)
        first = _head(connection, timeout)
        if first >= 500:
            return {'ok': False, 'detail': f'Цель пинга ответила HTTP {first}', 'http_code': first}
        started = time.monotonic()
        status = _head(connection, timeout)
        elapsed = max(1, round((time.monotonic()-started)*1000))
        if status >= 500:
            return {'ok': False, 'detail': f'Цель пинга ответила HTTP {status}', 'http_code': status}
        return {'ok': True, 'latency_ms': elapsed, 'latency_kind': 'http_keepalive', 'http_code': status}


def run(outbounds, xray, *, timeout=TIMEOUT):
    if not outbounds or len(outbounds) > 16 or not 0 < timeout <= 10:
        raise ValueError('некорректный набор нод для пинга')
    started = time.monotonic()
    config, sockets = configuration(outbounds, 'kdn-ping-'+secrets.token_hex(8))
    env = {key:value for key,value in os.environ.items() if key.lower() not in {'http_proxy','https_proxy','all_proxy','no_proxy'}}
    env.update(GOMEMLIMIT='32MiB', PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    ready, stop = threading.Event(), threading.Event()
    raw, guard = bytearray(), threading.Lock()
    failure = []
    process = None

    def report(value, tag, elapsed):
        with guard:
            text = raw.decode('utf-8', errors='replace')
        if len(outbounds) > 1:
            text = '\n'.join(line for line in text.splitlines() if tag in line)
        issues = vpn_diagnostics.xray_issues(text)
        log = ['HTTP HEAD через отдельный Xray; повторный запрос по keep-alive.',
               f'Цель: http://{HOST}{PATH}; бюджет каждого запроса: {timeout} с.',
               f'Запуск ядра: {startup_ms} мс; весь замер ноды: {elapsed} мс.',
               'Прогрев и handshake не включены в latency_ms. HTTP-ответ не доказывает работу HTTPS/приложений.']
        if 'http_code' in value:
            log.append(f"HTTP {value['http_code']}")
        log.extend(issues)
        if not value['ok'] and not issues:
            log.append('Дополнительная причина Xray не определена; сырые строки скрыты для защиты секретов.')
        return {**value, 'total_ms': elapsed, 'startup_ms': startup_ms, 'target': HOST,
                'log':'\n'.join(log).encode('utf-8')[:8192].decode('utf-8', errors='ignore')}

    def collect():
        total = 0
        while not stop.is_set():
            try:
                if select.select([process.stdout], [], [], 0.1)[0]:
                    block = os.read(process.stdout.fileno(), 2048)
                    if not block:
                        return
                    total += len(block)
                    with guard:
                        raw.extend(block)
                        del raw[:-8192]
                        if re.search(rb'core: Xray[^\r\n]{0,200} started', raw):
                            ready.set()
                    if total > 128*1024:
                        failure.append('тестовый Xray превысил лимит журнала 128 KiB')
                        process.kill()
                        return
                status = Path('/proc', str(process.pid), 'status').read_text()
                rss = re.search(r'^VmRSS:\s+(\d+)', status, re.MULTILINE)
                if rss and int(rss[1]) > 96*1024:
                    failure.append('тестовый Xray превысил лимит памяти 96 MiB')
                    process.kill()
                    return
            except OSError:
                return

    with tempfile.TemporaryDirectory(prefix='kdn-vpn-ping-') as directory:
        path = Path(directory)/'probe.json'
        descriptor = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(config, output, ensure_ascii=False)
        try:
            process = subprocess.Popen([sys.executable, '-m', 'kdn.vpn_probe_child', str(os.getpid()), xray, str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env, start_new_session=True)
        except OSError:
            return {key:{'ok':False,'detail':'не удалось запустить тестовый Xray'} for key in outbounds}
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            deadline = started+STARTUP_TIMEOUT
            while not ready.wait(0.02):
                if process.poll() is not None or time.monotonic() >= deadline:
                    break
            startup_ms = round((time.monotonic()-started)*1000)
            if not ready.is_set() or process.poll() is not None:
                reason = failure[0] if failure else 'тестовый Xray не запустился; проверьте расширенную диагностику'
                return {key:report({'ok':False,'detail':reason},tag,startup_ms) for key,(_name,tag) in sockets.items()}

            def one(item):
                key, (name, tag) = item
                stamp = time.monotonic()
                try:
                    value = measure(name, timeout=timeout)
                except (TimeoutError, socket.timeout):
                    value = {'ok':False,'detail':f'таймаут HTTP-пинга ({timeout} с на запрос)'}
                except (OSError, ValueError, ConnectionError):
                    value = {'ok':False,'detail':'HTTP-пинг не получил корректного ответа через ноду'}
                if failure:
                    value = {'ok':False,'detail':failure[0]}
                return key, report(value,tag,round((time.monotonic()-stamp)*1000))

            with ThreadPoolExecutor(max_workers=min(CONCURRENCY,len(outbounds))) as pool:
                return dict(pool.map(one,sockets.items()))
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            stop.set()
            reader.join(timeout=1)
            process.stdout.close()

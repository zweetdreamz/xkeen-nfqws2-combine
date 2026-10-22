#!/usr/bin/env python3
"""Transparent Telegram relay on the router: MTProto over WebSocket.

Xray redirects the Telegram clients' MTProto connections (TCP to the DC
networks that Xray could not sniff as TLS/HTTP) to this relay. Clients need no
proxy settings: a direct connection starts with an obfuscated2 header whose
keys are in the header itself, so the relay reads the data-center number from
it and carries the stream unchanged inside a WebSocket to /apiws, as Telegram
Web does. For each connection it tries, in this order:

1. kws{N}.web.telegram.org on 149.154.167.220 (DC2 and DC4 only), once a
   background probe has found it reachable;
2. kws{N}.<domain> through Cloudflare: Cloudflare opens the WebSocket to the
   data center, so this works when the provider blocks Telegram's addresses;
3. a plain TCP connection to the data center.

Speed: a blocked direct WebSocket is re-probed in the background (5 minutes
up to 6 hours apart), never on a client's connection; a few WebSockets per
data center in use are kept open in advance (as tg-ws-proxy's pool), so a new
connection does not wait for TLS and the upgrade; the Cloudflare domain that
answers fastest is used first.

The WebSocket and Cloudflare parts follow Flowseal/tg-ws-proxy (MIT): the same
endpoints, headers, fixed address and default Cloudflare domains (kept encoded
as there). Here no secret is involved and the bytes are not re-encrypted.

Every outgoing connection carries the firewall mark given with --mark (as
Xray's direct outbounds do), so that XKeen's interception of the router's own
traffic does not send it back to Xray and so to this relay. A direct
connection that still comes back (same header) is cut and its route paused.

Usage: telegram_ws_relay.py [--listen 127.0.0.1:18443] [--pidfile PATH]
                            [--log PATH] [--cf-domains-file PATH]
                            [--cf-ips-file PATH] [--no-cf] [--mark N]
       telegram_ws_relay.py --self-test [--mark N]
       telegram_ws_relay.py --print-cf-domains
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import importlib.util
import ipaddress
import os
import random
import re
import signal
import socket
import ssl
import struct
import sys
import time
import urllib.request
from collections import deque
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("telegram_mtproto", _HERE / "telegram_mtproto.py")
mtproto = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("telegram_mtproto", mtproto)
_SPEC.loader.exec_module(mtproto)

# DC2 and DC4 answer WebSocket on this address for every kws{N} name.
WS_FIXED_ADDRESS = {2: "149.154.167.220", 4: "149.154.167.220"}
# Data centers for the plain TCP route; DC203 is a separate one (CDN), as in
# tg-ws-proxy, reached through Cloudflare as kws203.<domain>.
DIRECT_ADDRESSES = {**mtproto.DATA_CENTERS, 203: "91.105.192.100"}
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10
CHUNK = 65536
# A route that failed to connect is skipped for this long.
ROUTE_BACKOFF = 300.0
# A blocked direct WebSocket is probed again after 5 min, 10 min, ... 6 h.
WS_PROBE_BACKOFF = (300.0, 6 * 3600.0)
# Ready WebSockets per route, how long one may wait (Cloudflare closes idle
# WebSockets after 100 s), and how long a route unused is kept warm.
POOL_SIZE = 4
POOL_MAX_AGE = 50.0
POOL_KEEP = 600.0
POOL_TICK = 15.0
# Cloudflare domains tried for one connection; the next one starts this long
# after the previous one if that has not answered yet.
CF_ATTEMPTS = 3
CF_STAGGER = 1.0
# Cloudflare serves every domain on every edge address, so an address that
# does not connect (the provider blocks some Cloudflare ranges) is replaced
# by another: the DNS answer, the user's own addresses and those that
# worked before, fastest first. A dead address is skipped for 30 minutes.
IP_ATTEMPTS = 3
IP_STAGGER = 1.0
IP_BACKOFF = 1800.0
# An address that worked before and then failed is retried sooner, after
# 1, 2, 4 ... minutes: the provider also drops bursts of new connections to
# addresses that work. "Failed" includes no answer to the upgrade: a nearby
# Cloudflare edge may itself be unable to reach Telegram.
IP_RETRY = 60.0
# New TCP connections at once; more only provoke that throttling. Pool
# refills open at most REFILL_LIMIT WebSockets at a time so that clients'
# connections do not queue behind them.
CONNECT_LIMIT = 8
REFILL_LIMIT = 2
# WebSocket sessions shorter than this are logged as drops.
SHORT_SESSION = 10.0
CF_REFRESH_INTERVAL = 6 * 3600
# Linux SO_MARK; Python names it from 3.7 on Linux only.
SO_MARK = getattr(socket, "SO_MARK", 36)

# The default Cloudflare domains of tg-ws-proxy, encoded as in its
# proxy/config.py, and the list it refreshes them from.
CF_DOMAINS_URL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"
_CF_ENCODED = (
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com",
    "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
    "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com",
    "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com", "orgcnunpj.com",
    "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
)
_CF_MIN_DOMAINS = 3
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def decode_cf_domain(value: str) -> str:
    """tg-ws-proxy's encoding: a Caesar shift by the letter count, ".com" -> ".co.uk"."""
    if not value.endswith(".com"):
        return value
    body = value[:-4]
    shift = sum(char.isalpha() for char in body)
    decoded = "".join(
        chr((ord(char) - base - shift) % 26 + base) if char.isalpha() else char
        for char in body
        for base in (97 if char.islower() else 65,)
    )
    return decoded + ".co.uk"


def valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


CF_DEFAULT_DOMAINS = [decode_cf_domain(item) for item in _CF_ENCODED]


class AddressRejected(ConnectionError):
    """A substituted Cloudflare address connected but did not serve the host."""


class DomainError(ConnectionError):
    """The domain itself failed: no DNS answer, or a wrong answer on its own address."""


async def race(factories, stagger: float, discard):
    """Starts factories[i]() i * stagger seconds in, unless one has succeeded.

    Returns the first result; ConnectionErrors of the others are collected,
    and results that arrive after the winner are passed to discard().
    """
    async def run(index, factory):
        await asyncio.sleep(index * stagger)
        return await factory()

    tasks = [asyncio.ensure_future(run(index, factory)) for index, factory in enumerate(factories)]
    errors = []
    winner = None
    won = False
    try:
        for future in asyncio.as_completed(tasks):
            try:
                winner = await future
                won = True
                break
            except ConnectionError as error:
                errors.append(str(error))
    finally:
        for task in tasks:
            task.cancel()
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if not isinstance(result, BaseException) and not (won and result is winner):
                discard(result)
    if not won:
        raise ConnectionError("; ".join(errors) or "nothing to try")
    return winner


def read_ips_file(path: Path | None) -> list[str]:
    """The user's own Cloudflare addresses (IPv4), one per line; '#' comments."""
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    addresses = []
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip()
        try:
            if item and ipaddress.ip_address(item).version == 4 and item not in addresses:
                addresses.append(item)
        except ValueError:
            continue
    return addresses


def read_domains_file(path: Path | None) -> list[str]:
    """The user's own Cloudflare domains: one per line, '#' starts a comment."""
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    domains = []
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip().lower()
        if item and valid_domain(item) and item not in domains:
            domains.append(item)
    return domains


def fetch_cf_domains(url: str = CF_DOMAINS_URL, timeout: float = 20.0) -> list[str]:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed https URL
        text = response.read(65536).decode("utf-8", "replace")
    domains = []
    for line in text.splitlines():
        item = decode_cf_domain(line.strip().lower())
        if valid_domain(item) and item not in domains:
            domains.append(item)
    return domains


LOG_PATH: Path | None = None
LOG_LIMIT = 256 * 1024


def log(message: str) -> None:
    """One line to stderr, or to --log with a single 256 KiB rotation."""
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())} {message}\n"
    if LOG_PATH is None:
        sys.stderr.write(line)
        return
    with contextlib.suppress(OSError):
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_LIMIT:
            LOG_PATH.replace(LOG_PATH.with_name(LOG_PATH.name + ".1"))
        with LOG_PATH.open("a", encoding="utf-8") as stream:
            stream.write(line)


def describe(error: BaseException | None) -> str:
    """Error text for the log; timeouts have none of their own."""
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    text = str(error)
    return text if text else type(error).__name__


def ws_hosts(dc: int, media: bool) -> list[str]:
    names = [f"kws{dc}.web.telegram.org"]
    return [f"kws{dc}-1.web.telegram.org", *names] if media else names


def ws_frame(opcode: int, payload: bytes) -> bytes:
    """A client frame: FIN set, masked as RFC 6455 requires."""
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", length)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", length)
    mask = os.urandom(4)
    repeated = (mask * (length // 4 + 1))[:length]
    masked = (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(length, "big")
    return bytes(header) + mask + masked


def parse_frame(buffer, offset: int):
    """(opcode, payload, next offset) of the frame at offset, or None if incomplete.

    The payload is a slice of buffer (a memoryview over the received data) for
    unmasked frames, as servers send them, so no copy is made here.
    """
    available = len(buffer) - offset
    if available < 2:
        return None
    first, second = buffer[offset], buffer[offset + 1]
    length = second & 0x7F
    start = offset + 2
    if length == 126:
        if available < 4:
            return None
        length = int.from_bytes(buffer[offset + 2:offset + 4], "big")
        start += 2
    elif length == 127:
        if available < 10:
            return None
        length = int.from_bytes(buffer[offset + 2:offset + 10], "big")
        start += 8
    if length > 16 * 1024 * 1024:
        raise ConnectionError("WebSocket frame too large")
    masked = second & 0x80
    end = start + (4 if masked else 0) + length
    if len(buffer) < end:
        return None
    if masked:
        mask = bytes(buffer[start:start + 4])
        payload = bytes(buffer[start + 4:end])
        repeated = (mask * (length // 4 + 1))[:length]
        payload = (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(length, "big")
        return first & 0x0F, payload, end
    return first & 0x0F, buffer[start:end], end


async def read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    first, second = await reader.readexactly(2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
    if length > 16 * 1024 * 1024:
        raise ConnectionError("WebSocket frame too large")
    mask = await reader.readexactly(4) if second & 0x80 else b""
    payload = await reader.readexactly(length)
    if mask:
        repeated = (mask * (length // 4 + 1))[:length]
        payload = (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(length, "big")
    return opcode, payload


class Relay:
    def __init__(self, *, connect_timeout: float = 5.0, ws_port: int = 443,
                 use_tls: bool = True, address_override: str | None = None,
                 fallback_port: int = 443, cf_domains: list[str] | None = None,
                 cf_enabled: bool = True, pool_size: int = POOL_SIZE,
                 cf_ips: list[str] | None = None, mark: int = 0) -> None:
        self.connect_timeout = connect_timeout
        self.ws_port = ws_port
        self.use_tls = use_tls
        self.address_override = address_override  # tests only
        self.fallback_port = fallback_port
        self.ssl_context = ssl.create_default_context() if use_tls else None
        self.cf_enabled = cf_enabled
        self.cf_domains = list(cf_domains if cf_domains is not None else CF_DEFAULT_DOMAINS)
        self.cf_active: dict[int, str] = {}
        self.cf_rtt: dict[str, float] = {}
        self.cf_ips = list(cf_ips or [])
        self.cf_ip_rtt: dict[str, float] = {}
        self.failed_until: dict[tuple, float] = {}
        self.connect_slots = asyncio.Semaphore(CONNECT_LIMIT)
        self.refill_slots = asyncio.Semaphore(REFILL_LIMIT)
        self.ip_failures: dict[str, int] = {}
        # Direct WebSocket per DC: "ok" or "blocked"; unknown until probed.
        self.ws_state: dict[int, str] = {}
        self.ws_failures: dict[int, int] = {}
        self.ws_next_probe: dict[int, float] = {}
        self.pool_size = pool_size
        self.pool: dict[tuple, deque] = {}
        self.pool_used: dict[tuple, float] = {}
        self.tasks: dict[tuple, asyncio.Future] = {}
        self.stats = {"ws": 0, "cf": 0, "direct": 0, "rejected": 0, "pooled": 0}
        # Firewall mark of every outgoing socket; 0 = none. Dropped (once,
        # logged) when the system does not allow it.
        self.so_mark = mark
        self.socket_type = socket.socket  # tests replace it
        # The 64-byte header of each direct TCP connection in progress, and
        # its DC: a connection arriving with one of them is our own, back.
        self.direct_headers: dict[bytes, int] = {}

    # -- route bookkeeping -------------------------------------------------

    def blocked(self, key: tuple) -> bool:
        return time.monotonic() < self.failed_until.get(key, 0.0)

    def mark_failed(self, key: tuple, seconds: float = ROUTE_BACKOFF) -> None:
        self.failed_until[key] = time.monotonic() + seconds

    def ip_candidates(self, resolved: list[str], cloudflare: bool, rotate: int = 0) -> list[str]:
        """Addresses to try: for Cloudflare the user's, DNS and learned ones.

        Learned ones are ordered by the time a whole WebSocket took; rotate
        shifts the order so that parallel attempts use different addresses.
        """
        if not cloudflare:
            return resolved[:1]
        pool = list(dict.fromkeys([*self.cf_ips, *resolved, *self.cf_ip_rtt]))
        usable = [ip for ip in pool if not self.blocked(("ip", ip))]
        if not usable:
            return resolved[:IP_ATTEMPTS]
        known = sorted((ip for ip in usable if ip in self.cf_ip_rtt), key=self.cf_ip_rtt.__getitem__)
        unknown = [ip for ip in usable if ip not in self.cf_ip_rtt]
        ordered = known + unknown
        shift = rotate % len(ordered)
        return (ordered[shift:] + ordered[:shift])[:IP_ATTEMPTS]

    def note_ip_rtt(self, ip: str, seconds: float) -> None:
        """A whole WebSocket (TCP to 101) through this address took seconds."""
        previous = self.cf_ip_rtt.get(ip)
        self.cf_ip_rtt[ip] = seconds if previous is None else 0.7 * previous + 0.3 * seconds
        self.ip_failures.pop(ip, None)

    def ip_failed(self, ip: str) -> None:
        """Skip the address: 30 min if it never worked, else 1, 2, 4 ... min."""
        if ip not in self.cf_ip_rtt:
            self.mark_failed(("ip", ip), IP_BACKOFF)
            return
        failures = self.ip_failures.get(ip, 0) + 1
        self.ip_failures[ip] = failures
        self.mark_failed(("ip", ip), min(IP_RETRY * 2 ** (failures - 1), IP_BACKOFF))

    def cf_order(self, dc: int) -> list[str]:
        """Domains that answered, fastest first, then untried ones shuffled."""
        usable = [domain for domain in self.cf_domains if not self.blocked(("cf", domain))]
        known = sorted((domain for domain in usable if domain in self.cf_rtt), key=self.cf_rtt.__getitem__)
        unknown = [domain for domain in usable if domain not in self.cf_rtt]
        random.shuffle(unknown)
        return (known + unknown)[:CF_ATTEMPTS]

    def note_rtt(self, domain: str, seconds: float) -> None:
        previous = self.cf_rtt.get(domain)
        self.cf_rtt[domain] = seconds if previous is None else 0.7 * previous + 0.3 * seconds

    def ws_failed(self, dc: int) -> None:
        failures = self.ws_failures.get(dc, 0) + 1
        self.ws_failures[dc] = failures
        self.ws_state[dc] = "blocked"
        first, limit = WS_PROBE_BACKOFF
        self.ws_next_probe[dc] = time.monotonic() + min(first * 2 ** (failures - 1), limit)

    def ws_worked(self, dc: int) -> None:
        self.ws_state[dc] = "ok"
        self.ws_failures.pop(dc, None)

    def background(self, key: tuple, coroutine) -> None:
        """One task per key: a probe or a pool refill."""
        if key in self.tasks:
            coroutine.close()
            return
        task = asyncio.ensure_future(coroutine)
        self.tasks[key] = task
        task.add_done_callback(lambda _task, key=key: self.tasks.pop(key, None))

    def schedule_probe(self, dc: int) -> None:
        if time.monotonic() >= self.ws_next_probe.get(dc, 0.0):
            self.background(("probe", dc), self.probe(dc))

    async def probe(self, dc: int) -> None:
        try:
            _, writer, _ = await self.open_websocket(dc, False)
        except ConnectionError as error:
            self.ws_failed(dc)
            log(f"DC{dc}: direct WebSocket unavailable ({error}); next check in "
                f"{(self.ws_next_probe[dc] - time.monotonic()) / 60:.0f} min")
            return
        writer.close()
        if self.ws_state.get(dc) != "ok":
            log(f"DC{dc}: direct WebSocket available")
        self.ws_worked(dc)

    # -- pool of ready WebSockets ------------------------------------------

    async def connect_route(self, key: tuple):
        if key[0] == "cf":
            return await self.open_cloudflare(key[1])
        return await self.open_websocket(key[1], key[2])

    @staticmethod
    def fresh(entry) -> bool:
        reader, writer, _, created = entry
        return (time.monotonic() - created < POOL_MAX_AGE and not writer.is_closing()
                and not reader.at_eof() and reader.exception() is None)

    async def take(self, key: tuple):
        """A ready WebSocket for this route, or one opened now; refills the pool."""
        self.pool_used[key] = time.monotonic()
        bucket = self.pool.get(key)
        while bucket:
            entry = bucket.popleft()
            if self.fresh(entry):
                self.schedule_refill(key)
                self.stats["pooled"] += 1
                return entry[0], entry[1], entry[2], True
            entry[1].close()
        reader, writer, host = await self.connect_route(key)
        self.schedule_refill(key)
        return reader, writer, host, False

    def schedule_refill(self, key: tuple) -> None:
        if self.pool_size > 0:
            self.background(("refill", *key), self.refill(key))

    async def refill(self, key: tuple) -> None:
        bucket = self.pool.setdefault(key, deque())
        missing = self.pool_size - len([entry for entry in bucket if self.fresh(entry)])
        if missing <= 0:
            return

        async def one():
            async with self.refill_slots:
                return await self.connect_route(key)

        results = await asyncio.gather(*(one() for _ in range(missing)), return_exceptions=True)
        for result in results:
            if isinstance(result, tuple):
                bucket.append((*result, time.monotonic()))

    async def maintain(self) -> None:
        """Drops stale pooled WebSockets, keeps used routes warm, re-probes."""
        while True:
            await asyncio.sleep(POOL_TICK)
            now = time.monotonic()
            for key, used in list(self.pool_used.items()):
                bucket = self.pool.get(key, deque())
                keep = now - used < POOL_KEEP
                for entry in list(bucket):
                    if not keep or not self.fresh(entry):
                        bucket.remove(entry)
                        entry[1].close()
                if keep:
                    self.schedule_refill(key)
                else:
                    del self.pool_used[key]
            for dc in WS_FIXED_ADDRESS:
                if self.ws_state.get(dc) == "blocked" and any(
                    key[1] == dc for key in self.pool_used
                ):
                    self.schedule_probe(dc)

    def close(self) -> None:
        for task in list(self.tasks.values()):
            task.cancel()
        for bucket in self.pool.values():
            for entry in bucket:
                entry[1].close()
        self.pool.clear()

    # -- outgoing sockets --------------------------------------------------

    def new_socket(self, family: int) -> socket.socket:
        """A non-blocking TCP socket carrying the mark, if one is set."""
        sock = self.socket_type(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            if self.so_mark:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self.so_mark)
                except OSError as error:
                    log(f"cannot set mark {self.so_mark} on outgoing connections ({describe(error)}); "
                        "continuing without it")
                    self.so_mark = 0
        except BaseException:
            sock.close()
            raise
        return sock

    async def open_tcp(self, address: str, port: int, ssl_context=None, server_hostname=None):
        """asyncio.open_connection() on a socket from new_socket().

        With ssl_context (Python < 3.11 only) TLS follows in the same step.
        """
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        except ValueError:
            family = socket.AF_INET
        sock = self.new_socket(family)
        try:
            await asyncio.get_running_loop().sock_connect(sock, (address, port))
        except BaseException:
            sock.close()
            raise
        # From here the transport owns the socket and closes it on failure.
        if ssl_context is None:
            return await asyncio.open_connection(sock=sock)
        return await asyncio.open_connection(sock=sock, ssl=ssl_context, server_hostname=server_hostname)

    # -- WebSocket ---------------------------------------------------------

    async def upgrade(self, address: str, host: str, cloudflare: bool = False, rotate: int = 0):
        """DNS (IPv4), TCP, TLS (SNI = host), then the WebSocket upgrade to /apiws.

        The steps are timed separately so an error says where it stalled. For
        Cloudflare several addresses race (see IP_ATTEMPTS).
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(address, self.ws_port, family=socket.AF_INET, type=socket.SOCK_STREAM),
                self.connect_timeout,
            )
            resolved = list(dict.fromkeys(info[4][0] for info in infos))
            if not resolved:
                raise OSError("no IPv4 address")
        except (OSError, asyncio.TimeoutError) as error:
            raise DomainError(f"{host}: DNS {describe(error)}") from None
        legacy_tls = self.use_tls and not hasattr(asyncio.StreamWriter, "start_tls")

        def tcp_attempt(ip):
            async def attempt():
                try:
                    async with self.connect_slots:
                        started = time.monotonic()
                        if legacy_tls:  # Python < 3.11: TCP and TLS in one step.
                            connection = self.open_tcp(ip, self.ws_port, self.ssl_context, host)
                        else:
                            connection = self.open_tcp(ip, self.ws_port)
                        reader, writer = await asyncio.wait_for(connection, self.connect_timeout)
                except (OSError, asyncio.TimeoutError, ssl.SSLError) as error:
                    if cloudflare:
                        self.ip_failed(ip)
                    step = "TCP/TLS" if legacy_tls else "TCP"
                    raise ConnectionError(f"{host} via {ip}: {step} {describe(error)}") from None
                return ip, started, reader, writer
            return attempt

        ip, started, reader, writer = await race(
            [tcp_attempt(ip) for ip in self.ip_candidates(resolved, cloudflare, rotate)],
            IP_STAGGER, lambda result: result[3].close(),
        )
        substituted = cloudflare and ip not in resolved

        def rejected(message):
            # A wrong answer: on an address that is not the DNS answer the
            # address is at fault, on the domain's own address the domain.
            if substituted:
                self.mark_failed(("ip", ip), IP_BACKOFF)
                self.cf_ip_rtt.pop(ip, None)
                return AddressRejected(message)
            return DomainError(message)

        if self.use_tls and not legacy_tls:
            try:
                await asyncio.wait_for(writer.start_tls(self.ssl_context, server_hostname=host), self.connect_timeout)
            except ssl.SSLError as error:  # a certificate or protocol error: a wrong answer
                writer.close()
                raise rejected(f"{host} via {ip}: TLS {describe(error)}") from None
            except (OSError, asyncio.TimeoutError) as error:  # a stall: a short pause for the address
                writer.close()
                if cloudflare:
                    self.ip_failed(ip)
                raise ConnectionError(f"{host} via {ip}: TLS {describe(error)}") from None
        key = base64.b64encode(os.urandom(16))
        writer.write(
            b"GET /apiws HTTP/1.1\r\nHost: " + host.encode()
            + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key
            + b"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
        )
        try:
            await writer.drain()
            status = await asyncio.wait_for(reader.readline(), self.connect_timeout)
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), self.connect_timeout)
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ssl.SSLError) as error:
            # No answer to the upgrade: this Cloudflare edge did not reach the
            # data center. Seen on nearby edges (5 ms away) that sit behind
            # the same blocking; the address pauses, the domain is not blamed.
            writer.close()
            if cloudflare:
                self.ip_failed(ip)
            raise ConnectionError(f"{host} via {ip}: upgrade {describe(error)}") from None
        accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
        if status.split(b" ")[1:2] == [b"101"] and headers.get("sec-websocket-accept") == accept:
            if cloudflare:
                self.note_ip_rtt(ip, time.monotonic() - started)
            return reader, writer
        writer.close()
        raise rejected(f"{host} via {ip}: {status.strip().decode('latin-1') or 'no answer'}")

    async def open_websocket(self, dc: int, media: bool):
        """kws{N}.web.telegram.org on the fixed address (DC2/DC4)."""
        address = self.address_override or WS_FIXED_ADDRESS[dc]
        last = "no host"
        for host in ws_hosts(dc, media):
            try:
                reader, writer = await self.upgrade(address, host)
                return reader, writer, host
            except ConnectionError as error:
                last = str(error)
        raise ConnectionError(last)

    async def open_cloudflare(self, dc: int):
        """kws{N}.<domain> through Cloudflare, which connects to the data center.

        Domains are tried staggered: the next starts CF_STAGGER seconds after
        the previous unless that one has answered; the first to answer wins.
        """
        domains = self.cf_order(dc)
        if not domains:
            raise ConnectionError("no Cloudflare domain left")

        def domain_attempt(index, domain):
            async def attempt():
                host = f"kws{dc}.{domain}"
                started = time.monotonic()
                try:
                    reader, writer = await self.upgrade(self.address_override or host, host,
                                                        cloudflare=True, rotate=index)
                except DomainError:
                    self.mark_failed(("cf", domain))
                    raise
                self.note_rtt(domain, time.monotonic() - started)
                return domain, host, reader, writer
            return attempt

        winner = await race([domain_attempt(index, domain) for index, domain in enumerate(domains)], CF_STAGGER,
                            lambda result: result[3].close())
        domain, host, reader, writer = winner
        self.cf_active[dc] = domain
        return reader, writer, host

    # -- connections -------------------------------------------------------

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            header = await asyncio.wait_for(client_reader.readexactly(64), 30)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            client_writer.close()
            return
        looped = self.direct_headers.get(header)
        if looped is not None:
            # Our own direct connection, redirected back here (router traffic
            # intercepted without the mark): cut it, pause the route.
            self.stats["rejected"] += 1
            self.mark_failed(("tcp", looped))
            log(f"DC{looped}: direct connection came back to the relay (redirect loop; "
                "is the Xray direct mark passed with --mark?); direct route paused")
            client_writer.close()
            return
        parsed = mtproto.read_header(header)
        if parsed is None:
            # Not a direct MTProto connection; its destination is unknown here.
            self.stats["rejected"] += 1
            client_writer.close()
            return
        _, raw_dc = parsed
        dc, media = abs(raw_dc), raw_dc < 0
        if dc not in DIRECT_ADDRESSES:
            self.stats["rejected"] += 1
            client_writer.close()
            return
        label = f"DC{dc}{' media' if media else ''}"
        reasons = []

        if dc in WS_FIXED_ADDRESS:
            if self.ws_state.get(dc) == "ok":
                try:
                    ws_reader, ws_writer, host, pooled = await self.take(("ws", dc, media))
                except ConnectionError as error:
                    reasons.append(f"WebSocket {error}")
                    self.ws_failed(dc)
                else:
                    self.stats["ws"] += 1
                    log(f"{label} via WebSocket {host}{' (ready)' if pooled else ''}")
                    await self.pipe_websocket(header, client_reader, client_writer, ws_reader, ws_writer,
                                              label=f"{label} {host}")
                    return
            else:
                # Unknown or blocked: Cloudflare now, the probe in the background.
                self.schedule_probe(dc)

        if self.cf_enabled and self.cf_domains:
            try:
                ws_reader, ws_writer, host, pooled = await self.take(("cf", dc))
            except ConnectionError as error:
                reasons.append(f"Cloudflare {error}")
            else:
                self.stats["cf"] += 1
                peer = (ws_writer.get_extra_info("peername") or ("?",))[0]
                log(f"{label} via Cloudflare {host} {peer}{' (ready)' if pooled else ''}")
                await self.pipe_websocket(header, client_reader, client_writer, ws_reader, ws_writer,
                                          label=f"{label} {host} {peer}")
                return

        await self.relay_direct(dc, header, client_reader, client_writer, "; ".join(reasons) or "not tried")

    async def pipe_websocket(self, header, client_reader, client_writer, ws_reader, ws_writer,
                             label: str = "") -> None:
        started = time.monotonic()
        received = 0

        async def upstream():
            ws_writer.write(ws_frame(OP_BINARY, header))
            while True:
                data = await client_reader.read(CHUNK)
                if not data:
                    break
                ws_writer.write(ws_frame(OP_BINARY, data))
                await ws_writer.drain()
            ws_writer.write(ws_frame(OP_CLOSE, struct.pack(">H", 1000)))

        async def downstream():
            # Frames are parsed from whatever arrived and their payloads go to
            # the client in one write: far fewer steps per byte than awaiting
            # every header and payload, which mattered on the router's CPU.
            buffer = bytearray()
            while True:
                data = await ws_reader.read(CHUNK)
                if not data:
                    break
                buffer += data
                joined, offset, closing = self.take_frames(buffer, ws_writer)
                del buffer[:offset]
                nonlocal received
                received += len(joined)
                if joined:
                    client_writer.write(joined)
                    await client_writer.drain()
                if closing:
                    break

        await self.run_pair(upstream(), downstream(), client_writer, ws_writer)
        lasted = time.monotonic() - started
        if label and lasted < SHORT_SESSION:
            # Telegram keeps its connections for minutes; a short one is a drop.
            log(f"{label}: closed after {lasted:.1f} s, {received} bytes received")

    @staticmethod
    def take_frames(buffer: bytearray, ws_writer) -> tuple[bytes, int, bool]:
        """Payloads of the complete frames in buffer, the bytes they used, and
        whether a close frame came; pings are answered on the way."""
        view = memoryview(buffer)
        payloads = []
        frame = None
        offset = 0
        closing = False
        try:
            while True:
                frame = parse_frame(view, offset)
                if frame is None:
                    break
                opcode, payload, offset = frame
                if opcode in (OP_BINARY, OP_CONT, OP_TEXT):
                    payloads.append(payload)
                elif opcode == OP_PING:
                    ws_writer.write(ws_frame(OP_PONG, bytes(payload)))
                elif opcode == OP_CLOSE:
                    closing = True
                    break
            joined = b"".join(payloads)
        finally:
            # Every slice must be gone before the caller trims the buffer.
            del payloads, frame
            view.release()
        return joined, offset, closing

    async def relay_direct(self, dc, header, client_reader, client_writer, reason: str) -> None:
        address = self.address_override or DIRECT_ADDRESSES[dc]
        if self.blocked(("tcp", dc)):
            log(f"DC{dc}: {reason}; direct to {address} skipped (failed recently)")
            client_writer.close()
            return
        self.direct_headers[header] = dc
        try:
            await self.pipe_direct(dc, address, header, client_reader, client_writer, reason)
        finally:
            self.direct_headers.pop(header, None)

    async def pipe_direct(self, dc, address, header, client_reader, client_writer, reason: str) -> None:
        try:
            dc_reader, dc_writer = await asyncio.wait_for(
                self.open_tcp(address, self.fallback_port), self.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as error:
            self.mark_failed(("tcp", dc))
            log(f"DC{dc}: {reason}; direct to {address} failed too ({describe(error)})")
            client_writer.close()
            return
        self.stats["direct"] += 1
        log(f"DC{dc}: {reason}; direct to {address}")

        async def upstream():
            dc_writer.write(header)
            while True:
                data = await client_reader.read(CHUNK)
                if not data:
                    break
                dc_writer.write(data)
                await dc_writer.drain()

        async def downstream():
            while True:
                data = await dc_reader.read(CHUNK)
                if not data:
                    break
                client_writer.write(data)
                await client_writer.drain()

        await self.run_pair(upstream(), downstream(), client_writer, dc_writer)

    @staticmethod
    async def run_pair(first, second, *writers) -> None:
        tasks = [asyncio.ensure_future(first), asyncio.ensure_future(second)]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(BaseException):
                    await task
            for writer in writers:
                writer.close()


async def refresh_cf_domains(relay: Relay, interval: float = CF_REFRESH_INTERVAL) -> None:
    """Keeps the default Cloudflare domains current, as tg-ws-proxy does."""
    while True:
        try:
            domains = await asyncio.to_thread(fetch_cf_domains)
        except Exception as error:  # noqa: BLE001 - any failure keeps the old list
            log(f"Cloudflare domain list not refreshed: {describe(error)}")
        else:
            if len(domains) >= _CF_MIN_DOMAINS:
                if set(domains) != set(relay.cf_domains):
                    relay.cf_domains = domains
                    log(f"Cloudflare domain list refreshed: {len(domains)} domains")
            else:
                log(f"Cloudflare domain list ignored: only {len(domains)} valid domains")
        await asyncio.sleep(interval)


async def self_test(relay: Relay) -> int:
    """Try every route to every data center; one line per DC."""
    async def one(dc: int) -> tuple[str, bool]:
        started = time.monotonic()
        parts = []
        working = False
        if dc in WS_FIXED_ADDRESS:
            begun = time.monotonic()
            try:
                _, writer, host = await relay.open_websocket(dc, False)
                writer.close()
                parts.append(f"WebSocket ok {host} ({(time.monotonic() - begun) * 1000:.0f} ms)")
                working = True
            except ConnectionError as error:
                parts.append(f"WebSocket failed ({error})")
        if relay.cf_enabled and relay.cf_domains:
            begun = time.monotonic()
            try:
                _, writer, host = await relay.open_cloudflare(dc)
                peer = (writer.get_extra_info("peername") or ("?",))[0]
                writer.close()
                parts.append(f"Cloudflare ok {host} via {peer} ({(time.monotonic() - begun) * 1000:.0f} ms)")
                working = True
            except ConnectionError as error:
                parts.append(f"Cloudflare failed ({error})")
        address = relay.address_override or DIRECT_ADDRESSES[dc]
        try:
            _, writer = await asyncio.wait_for(
                relay.open_tcp(address, relay.fallback_port), relay.connect_timeout
            )
            writer.close()
            parts.append(f"TCP {address}:{relay.fallback_port} ok")
        except (OSError, asyncio.TimeoutError) as error:
            parts.append(f"TCP {address}:{relay.fallback_port} failed ({describe(error)})")
        return f"DC{dc}: {'; '.join(parts)} [{time.monotonic() - started:.1f}s]", working

    results = await asyncio.gather(*(one(dc) for dc in sorted(DIRECT_ADDRESSES)))
    print("\n".join(line for line, _ in results), flush=True)
    return 0 if any(working for _, working in results) else 1


def parse_mark(value: str) -> int:
    try:
        mark = int(value, 0)
    except ValueError:
        mark = -1
    if not 0 <= mark <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("mark must be a number from 0 to 4294967295")
    return mark


def parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if host not in {"127.0.0.1", "0.0.0.0"} or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError("listen must be 127.0.0.1:PORT")
    return host, int(port)


async def serve(listen: tuple[str, int], relay: Relay, ready: asyncio.Event | None = None,
                refresh: bool = False) -> None:
    server = await asyncio.start_server(relay.handle, *listen)
    log(f"listening on {listen[0]}:{listen[1]}; Cloudflare "
        + (f"on ({len(relay.cf_domains)} domains)" if relay.cf_enabled and relay.cf_domains else "off"))
    if ready is not None:
        ready.set()
    refresher = asyncio.create_task(refresh_cf_domains(relay)) if refresh else None
    maintainer = asyncio.create_task(relay.maintain())
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        # No wait_closed(): it waits for every client connection, and Telegram
        # keeps them open. asyncio.run() cancels the handlers on the way out.
        if refresher is not None:
            refresher.cancel()
        maintainer.cancel()
        relay.close()
        server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", type=parse_listen, default=("127.0.0.1", 18443))
    parser.add_argument("--pidfile", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--cf-domains-file", type=Path,
                        help="own Cloudflare domains, one per line (replaces the defaults)")
    parser.add_argument("--cf-ips-file", type=Path,
                        help="own Cloudflare addresses (IPv4), one per line, tried first")
    parser.add_argument("--no-cf", action="store_true", help="do not use Cloudflare")
    parser.add_argument("--mark", type=parse_mark, default=0,
                        help="firewall mark (SO_MARK) of every outgoing connection; 0 = none")
    parser.add_argument("--self-test", action="store_true",
                        help="try WebSocket, Cloudflare and TCP to every data center, then exit")
    parser.add_argument("--print-cf-domains", action="store_true",
                        help="print the Cloudflare domains in use, then exit")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    own_domains = read_domains_file(args.cf_domains_file)
    domains = own_domains or CF_DEFAULT_DOMAINS
    if args.print_cf_domains:
        if not args.no_cf:
            print("\n".join(domains))
        return 0
    relay = Relay(cf_domains=domains, cf_enabled=not args.no_cf, cf_ips=read_ips_file(args.cf_ips_file),
                  mark=args.mark)
    if args.self_test:
        return asyncio.run(self_test(relay))
    global LOG_PATH
    LOG_PATH = args.log
    if args.pidfile:
        args.pidfile.write_text(f"{os.getpid()}\n", encoding="ascii")
    try:
        asyncio.run(serve(args.listen, relay, refresh=not args.no_cf and not own_domains))
    finally:
        if args.pidfile:
            with contextlib.suppress(OSError):
                args.pidfile.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

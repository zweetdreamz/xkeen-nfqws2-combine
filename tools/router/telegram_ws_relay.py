#!/usr/bin/env python3
"""Transparent Telegram relay on the router: MTProto over WebSocket.

Xray redirects the Telegram clients' MTProto connections (TCP to the DC
networks that Xray could not sniff as TLS/HTTP) to this relay. Clients need no
proxy settings: a direct connection starts with an obfuscated2 header whose
keys are in the header itself, so the relay reads the data-center number from
it and carries the stream unchanged inside a WebSocket to /apiws, as Telegram
Web does. For each connection it tries, in this order:

1. kws{N}.web.telegram.org on 149.154.167.220 (DC2 and DC4 only);
2. kws{N}.<domain> through Cloudflare: Cloudflare opens the WebSocket to the
   data center, so this works when the provider blocks Telegram's addresses;
3. a plain TCP connection to the data center.

A route that failed to connect is skipped for a while, so a blocked one does
not delay every new connection.

The WebSocket and Cloudflare parts follow Flowseal/tg-ws-proxy (MIT): the same
endpoints, headers, fixed address and default Cloudflare domains (kept encoded
as there). Here no secret is involved and the bytes are not re-encrypted.

Usage: telegram_ws_relay.py [--listen 127.0.0.1:18443] [--pidfile PATH]
                            [--log PATH] [--cf-domains-file PATH] [--no-cf]
       telegram_ws_relay.py --self-test
       telegram_ws_relay.py --print-cf-domains
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import importlib.util
import os
import random
import re
import signal
import ssl
import struct
import sys
import time
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("telegram_mtproto", _HERE / "telegram_mtproto.py")
mtproto = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("telegram_mtproto", mtproto)
_SPEC.loader.exec_module(mtproto)

# DC2 and DC4 answer WebSocket on this address for every kws{N} name.
WS_FIXED_ADDRESS = {2: "149.154.167.220", 4: "149.154.167.220"}
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10
CHUNK = 65536
# A route that failed to connect is skipped for this long.
ROUTE_BACKOFF = 300.0
# Cloudflare domains tried for one connection.
CF_ATTEMPTS = 3
CF_REFRESH_INTERVAL = 6 * 3600

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
    if dc == 203:  # Telegram's test alias of DC2.
        dc = 2
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
                 cf_enabled: bool = True) -> None:
        self.connect_timeout = connect_timeout
        self.ws_port = ws_port
        self.use_tls = use_tls
        self.address_override = address_override  # tests only
        self.fallback_port = fallback_port
        self.ssl_context = ssl.create_default_context() if use_tls else None
        self.cf_enabled = cf_enabled
        self.cf_domains = list(cf_domains if cf_domains is not None else CF_DEFAULT_DOMAINS)
        self.cf_active: dict[int, str] = {}
        self.failed_until: dict[tuple, float] = {}
        self.stats = {"ws": 0, "cf": 0, "direct": 0, "rejected": 0}

    # -- route bookkeeping -------------------------------------------------

    def blocked(self, key: tuple) -> bool:
        return time.monotonic() < self.failed_until.get(key, 0.0)

    def mark_failed(self, key: tuple) -> None:
        self.failed_until[key] = time.monotonic() + ROUTE_BACKOFF

    def cf_order(self, dc: int) -> list[str]:
        """The domain that worked for this DC first, then the rest shuffled."""
        current = self.cf_active.get(dc)
        others = [domain for domain in self.cf_domains if domain != current and not self.blocked(("cf", domain))]
        random.shuffle(others)
        ordered = ([current] if current in self.cf_domains and not self.blocked(("cf", current)) else []) + others
        return ordered[:CF_ATTEMPTS]

    # -- WebSocket ---------------------------------------------------------

    async def upgrade(self, address: str, host: str):
        """TLS (SNI = host) to address, then the WebSocket upgrade to /apiws."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address, self.ws_port, ssl=self.ssl_context,
                    server_hostname=host if self.use_tls else None,
                ),
                self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as error:
            raise ConnectionError(f"{host} via {address}: {describe(error)}") from None
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
            writer.close()
            raise ConnectionError(f"{host}: upgrade {describe(error)}") from None
        accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
        if status.split(b" ")[1:2] == [b"101"] and headers.get("sec-websocket-accept") == accept:
            return reader, writer
        writer.close()
        raise ConnectionError(f"{host}: {status.strip().decode('latin-1') or 'no answer'}")

    async def open_websocket(self, dc: int, media: bool):
        """kws{N}.web.telegram.org on the fixed address (DC2/DC4)."""
        address = self.address_override or WS_FIXED_ADDRESS[2 if dc == 203 else dc]
        last = "no host"
        for host in ws_hosts(dc, media):
            try:
                reader, writer = await self.upgrade(address, host)
                return reader, writer, host
            except ConnectionError as error:
                last = str(error)
        raise ConnectionError(last)

    async def open_cloudflare(self, dc: int):
        """kws{N}.<domain> through Cloudflare, which connects to the data center."""
        errors = []
        for domain in self.cf_order(dc):
            host = f"kws{dc}.{domain}"
            try:
                reader, writer = await self.upgrade(self.address_override or host, host)
            except ConnectionError as error:
                errors.append(str(error))
                self.mark_failed(("cf", domain))
                continue
            self.cf_active[dc] = domain
            return reader, writer, host
        raise ConnectionError("; ".join(errors) or "no Cloudflare domain left")

    # -- connections -------------------------------------------------------

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            header = await asyncio.wait_for(client_reader.readexactly(64), 30)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
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
        if dc == 0 or (dc not in mtproto.DATA_CENTERS and dc != 203):
            self.stats["rejected"] += 1
            client_writer.close()
            return
        label = f"DC{dc}{' media' if media else ''}"
        reasons = []

        if (2 if dc == 203 else dc) in WS_FIXED_ADDRESS and not self.blocked(("ws", dc)):
            try:
                ws_reader, ws_writer, host = await self.open_websocket(dc, media)
            except ConnectionError as error:
                reasons.append(f"WebSocket {error}")
                if "timeout" in str(error) or " via " in str(error):
                    self.mark_failed(("ws", dc))
            else:
                self.stats["ws"] += 1
                log(f"{label} via WebSocket {host}")
                await self.pipe_websocket(header, client_reader, client_writer, ws_reader, ws_writer)
                return

        if self.cf_enabled and self.cf_domains and dc != 203:
            try:
                ws_reader, ws_writer, host = await self.open_cloudflare(dc)
            except ConnectionError as error:
                reasons.append(f"Cloudflare {error}")
            else:
                self.stats["cf"] += 1
                log(f"{label} via Cloudflare {host}")
                await self.pipe_websocket(header, client_reader, client_writer, ws_reader, ws_writer)
                return

        await self.relay_direct(dc, header, client_reader, client_writer, "; ".join(reasons) or "not tried")

    async def pipe_websocket(self, header, client_reader, client_writer, ws_reader, ws_writer) -> None:
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
            while True:
                opcode, payload = await read_ws_frame(ws_reader)
                if opcode in (OP_BINARY, OP_CONT, OP_TEXT):
                    client_writer.write(payload)
                    await client_writer.drain()
                elif opcode == OP_PING:
                    ws_writer.write(ws_frame(OP_PONG, payload))
                elif opcode == OP_CLOSE:
                    break

        await self.run_pair(upstream(), downstream(), client_writer, ws_writer)

    async def relay_direct(self, dc, header, client_reader, client_writer, reason: str) -> None:
        address = self.address_override or mtproto.DATA_CENTERS.get(dc, mtproto.DATA_CENTERS[2])
        if self.blocked(("tcp", dc)):
            log(f"DC{dc}: {reason}; direct to {address} skipped (failed recently)")
            client_writer.close()
            return
        try:
            dc_reader, dc_writer = await asyncio.wait_for(
                asyncio.open_connection(address, self.fallback_port), self.connect_timeout
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
            try:
                _, writer, host = await relay.open_websocket(dc, False)
                writer.close()
                parts.append(f"WebSocket ok {host}")
                working = True
            except ConnectionError as error:
                parts.append(f"WebSocket failed ({error})")
        if relay.cf_enabled and relay.cf_domains:
            try:
                _, writer, host = await relay.open_cloudflare(dc)
                writer.close()
                parts.append(f"Cloudflare ok {host}")
                working = True
            except ConnectionError as error:
                parts.append(f"Cloudflare failed ({error})")
        address = relay.address_override or mtproto.DATA_CENTERS[dc]
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(address, relay.fallback_port), relay.connect_timeout
            )
            writer.close()
            parts.append(f"TCP {address}:{relay.fallback_port} ok")
        except (OSError, asyncio.TimeoutError) as error:
            parts.append(f"TCP {address}:{relay.fallback_port} failed ({describe(error)})")
        return f"DC{dc}: {'; '.join(parts)} [{time.monotonic() - started:.1f}s]", working

    results = await asyncio.gather(*(one(dc) for dc in sorted(mtproto.DATA_CENTERS)))
    print("\n".join(line for line, _ in results), flush=True)
    return 0 if any(working for _, working in results) else 1


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
        server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", type=parse_listen, default=("127.0.0.1", 18443))
    parser.add_argument("--pidfile", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--cf-domains-file", type=Path,
                        help="own Cloudflare domains, one per line (replaces the defaults)")
    parser.add_argument("--no-cf", action="store_true", help="do not use Cloudflare")
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
    relay = Relay(cf_domains=domains, cf_enabled=not args.no_cf)
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

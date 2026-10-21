#!/usr/bin/env python3
"""Transparent Telegram relay on the router: MTProto over WebSocket.

Xray redirects the Telegram clients' MTProto connections (TCP to the DC
networks that Xray could not sniff as TLS/HTTP) to this relay. Clients need no
proxy settings: a direct connection starts with an obfuscated2 header whose
keys are in the header itself, so the relay reads the data-center number from
it and carries the stream unchanged inside a WebSocket to
kws{N}.web.telegram.org/apiws, as Telegram Web does. When the WebSocket cannot
be opened, the stream goes straight to the data center instead.

The WebSocket part follows Flowseal/tg-ws-proxy (MIT): the same endpoints,
headers and the fixed address 149.154.167.220 for DC2/DC4; here no secret is
involved and the bytes are not re-encrypted.

Usage: telegram_ws_relay.py [--listen 127.0.0.1:18443] [--pidfile PATH]
       telegram_ws_relay.py --self-test
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import importlib.util
import os
import signal
import ssl
import struct
import sys
import time
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
    def __init__(self, *, connect_timeout: float = 8.0, ws_port: int = 443,
                 use_tls: bool = True, address_override: str | None = None,
                 fallback_port: int = 443) -> None:
        self.connect_timeout = connect_timeout
        self.ws_port = ws_port
        self.use_tls = use_tls
        self.address_override = address_override  # tests only
        self.fallback_port = fallback_port
        self.ssl_context = ssl.create_default_context() if use_tls else None
        self.stats = {"ws": 0, "direct": 0, "rejected": 0}

    async def open_websocket(self, dc: int, media: bool):
        last_error: Exception | None = None
        for host in ws_hosts(dc, media):
            address = self.address_override or WS_FIXED_ADDRESS.get(dc, host)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        address, self.ws_port, ssl=self.ssl_context,
                        server_hostname=host if self.use_tls else None,
                    ),
                    self.connect_timeout,
                )
            except (OSError, asyncio.TimeoutError, ssl.SSLError) as error:
                last_error = ConnectionError(f"{host} via {address}: {describe(error)}")
                continue
            key = base64.b64encode(os.urandom(16))
            writer.write(
                b"GET /apiws HTTP/1.1\r\nHost: " + host.encode()
                + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key
                + b"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n"
                b"Origin: https://web.telegram.org\r\n\r\n"
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
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
                writer.close()
                last_error = ConnectionError(f"{host}: upgrade {describe(error)}")
                continue
            accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
            if status.split(b" ")[1:2] == [b"101"] and headers.get("sec-websocket-accept") == accept:
                return reader, writer, host
            writer.close()
            last_error = ConnectionError(f"{host}: {status.strip().decode('latin-1')}")
        raise ConnectionError(describe(last_error))

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
        try:
            ws_reader, ws_writer, host = await self.open_websocket(dc, media)
        except ConnectionError as error:
            await self.relay_direct(dc, header, client_reader, client_writer, str(error))
            return
        self.stats["ws"] += 1
        log(f"DC{dc}{' media' if media else ''} via WebSocket {host}")
        await self.pipe_websocket(header, client_reader, client_writer, ws_reader, ws_writer)

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
        try:
            dc_reader, dc_writer = await asyncio.wait_for(
                asyncio.open_connection(address, self.fallback_port), self.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as error:
            log(f"DC{dc}: WebSocket failed ({reason}); direct to {address} failed too ({describe(error)})")
            client_writer.close()
            return
        self.stats["direct"] += 1
        log(f"DC{dc}: WebSocket failed ({reason}); direct to {address}")

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


async def self_test(relay: Relay) -> int:
    """Open a WebSocket and a direct TCP connection to every data center."""
    async def one(dc: int) -> str:
        started = time.monotonic()
        try:
            _, writer, host = await relay.open_websocket(dc, False)
            writer.close()
            ws = f"ok {host}"
        except ConnectionError as error:
            ws = f"failed ({error})"
        address = relay.address_override or mtproto.DATA_CENTERS[dc]
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(address, relay.fallback_port), relay.connect_timeout
            )
            writer.close()
            direct = "ok"
        except (OSError, asyncio.TimeoutError) as error:
            direct = f"failed ({describe(error)})"
        return f"DC{dc}: WebSocket {ws}; TCP {address}:{relay.fallback_port} {direct} [{time.monotonic() - started:.1f}s]"

    lines = await asyncio.gather(*(one(dc) for dc in sorted(mtproto.DATA_CENTERS)))
    print("\n".join(lines), flush=True)
    return 0 if any(" WebSocket ok " in line for line in lines) else 1


def parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if host not in {"127.0.0.1", "0.0.0.0"} or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError("listen must be 127.0.0.1:PORT")
    return host, int(port)


async def serve(listen: tuple[str, int], relay: Relay, ready: asyncio.Event | None = None) -> None:
    server = await asyncio.start_server(relay.handle, *listen)
    log(f"listening on {listen[0]}:{listen[1]}")
    if ready is not None:
        ready.set()
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
        server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", type=parse_listen, default=("127.0.0.1", 18443))
    parser.add_argument("--pidfile", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--self-test", action="store_true",
                        help="check WebSocket and direct TCP to every data center, then exit")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        return asyncio.run(self_test(Relay()))
    global LOG_PATH
    LOG_PATH = args.log
    if args.pidfile:
        args.pidfile.write_text(f"{os.getpid()}\n", encoding="ascii")
    try:
        asyncio.run(serve(args.listen, Relay()))
    finally:
        if args.pidfile:
            with contextlib.suppress(OSError):
                args.pidfile.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

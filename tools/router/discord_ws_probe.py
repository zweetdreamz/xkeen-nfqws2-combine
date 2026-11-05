#!/usr/bin/env python3
"""Bounded, unauthenticated Discord Gateway WebSocket handshake probe.

Shared by the manual and scheduled nfqws2 candidate runner. This deliberately
does not identify a Discord user or bot, send a token, or keep a session open.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import socket
import ssl
import sys
import time


HOST = "gateway.discord.gg"
PATH = "/?v=10&encoding=json"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def response_ok(header: bytes, key: str) -> bool:
    try:
        text = header.decode("ascii")
        lines = text.split("\r\n")
        if not lines[0].startswith("HTTP/1.1 101 "):
            return False
        fields = {}
        for line in lines[1:]:
            if not line:
                break
            name, separator, value = line.partition(":")
            if separator:
                fields[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        return (fields.get("upgrade", "").lower() == "websocket"
                and "upgrade" in {part.strip().lower() for part in fields.get("connection", "").split(",")}
                and fields.get("sec-websocket-accept") == expected)
    except (UnicodeError, IndexError):
        return False


def probe(timeout: float) -> tuple[str, str]:
    try:
        addresses = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return "unavailable", "dns"
    context = ssl.create_default_context()
    last_reason = "connect"
    for _family, _kind, _proto, _canon, address in addresses[:4]:
        try:
            with socket.create_connection(address, timeout=timeout) as raw:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=HOST) as stream:
                    key = base64.b64encode(os.urandom(16)).decode("ascii")
                    request = (
                        f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                        "User-Agent: keenetic-zapret-check/1\r\n\r\n"
                    )
                    stream.sendall(request.encode("ascii"))
                    response = bytearray()
                    while b"\r\n\r\n" not in response and len(response) < 8192:
                        chunk = stream.recv(2048)
                        if not chunk:
                            break
                        response.extend(chunk)
                    if response_ok(bytes(response), key):
                        return "ok", "upgrade"
                    if bytes(response).startswith((b"HTTP/1.1 403 ", b"HTTP/1.1 429 ")):
                        return "unavailable", "server-policy"
                    last_reason = "bad-upgrade" if response else "empty-reply"
        except ssl.SSLCertVerificationError:
            return "unavailable", "certificate"
        except (OSError, ssl.SSLError):
            last_reason = "connect-or-tls"
    return "fail", last_reason


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=6)
    parser.add_argument("--label", default="")  # diagnostic/test correlation only
    args = parser.parse_args()
    if not 2 <= args.timeout <= 20:
        parser.error("timeout must be 2..20 seconds")
    started = time.monotonic()
    try:
        status, reason = probe(args.timeout)
    except (OSError, ValueError):
        status, reason = "unavailable", "local-error"
    print(f"EVENT|WS|{status}|{time.monotonic() - started:.3f}|{reason}")
    return {"ok": 0, "fail": 1, "unavailable": 2}[status]


if __name__ == "__main__":
    sys.exit(main())

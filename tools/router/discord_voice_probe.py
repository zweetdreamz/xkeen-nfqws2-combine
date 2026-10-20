#!/usr/bin/env python3
"""Ask a Discord voice server whether it answers IP Discovery from the router.

Discord clients start a voice session by sending a 74-byte UDP "IP
Discovery" request to the voice server; the server answers with the
client's public address. The nfqws2 Discord Voice profile selects exactly
this payload (--payload=stun,discord_ip_discovery), so a router-originated
request goes through the candidate strategy under test.

The probe sends a few requests to one known endpoint (learned from a real,
user-confirmed voice session) and prints one result line:

    EVENT|VOICE_PROBE|<label>|<sent>|<received>|<valid>

``valid`` counts IP Discovery responses that echo our SSRC. Only the
standard library is used, so it runs on the router's Entware python3.
"""

from __future__ import annotations

import argparse
import ipaddress
import secrets
import socket
import struct
import sys
import time

REQUEST_TYPE = 0x0001
RESPONSE_TYPE = 0x0002
BODY_LENGTH = 70  # SSRC (4) + address (64) + port (2)
PACKET_LENGTH = 4 + BODY_LENGTH


def discovery_request(ssrc: int) -> bytes:
    """Build an IP Discovery request: type, length, SSRC, empty address/port."""
    return struct.pack(">HHI", REQUEST_TYPE, BODY_LENGTH, ssrc) + bytes(66)


def is_discovery_response(data: bytes, ssrc: int) -> bool:
    if len(data) < 8:
        return False
    packet_type, length, echoed = struct.unpack(">HHI", data[:8])
    return packet_type == RESPONSE_TYPE and length == BODY_LENGTH and echoed == ssrc


def probe(host: str, port: int, *, count: int = 3, interval: float = 0.5,
          timeout: float = 2.0) -> tuple[int, int, int]:
    """Send ``count`` requests; return (sent, received, valid responses)."""
    ssrc = secrets.randbits(32)
    request = discovery_request(ssrc)
    sent = received = valid = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((host, port))
        except OSError:
            # No route (ENETUNREACH and similar): nothing was sent.
            return sent, received, valid
        for number in range(count):
            try:
                sock.send(request)
                sent += 1
            except OSError:
                pass
            if number + 1 < count:
                time.sleep(interval)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data = sock.recv(2048)
            except (socket.timeout, ConnectionRefusedError):
                break
            except OSError:
                break
            received += 1
            if is_discovery_response(data, ssrc):
                valid += 1
    return sent, received, valid


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host", help="IPv4 address of the voice server")
    parser.add_argument("port", type=int)
    parser.add_argument("--label", default="probe")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args(argv)
    try:
        if ipaddress.ip_address(args.host).version != 4:
            parser.error("host must be an IPv4 address")
    except ValueError:
        parser.error("host must be an IPv4 address")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not 1 <= args.count <= 10:
        parser.error("count must be between 1 and 10")
    if not 0 <= args.interval <= 5 or not 0.1 <= args.timeout <= 10:
        parser.error("interval/timeout out of range")
    if not args.label.replace("-", "").replace("_", "").isalnum() or len(args.label) > 32:
        parser.error("label must be short and alphanumeric")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    sent, received, valid = probe(
        args.host, args.port, count=args.count, interval=args.interval, timeout=args.timeout
    )
    print(f"EVENT|VOICE_PROBE|{args.label}|{sent}|{received}|{valid}", flush=True)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

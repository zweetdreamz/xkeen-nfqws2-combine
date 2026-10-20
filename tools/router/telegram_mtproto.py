#!/usr/bin/env python3
"""MTProto transport helpers for the router: obfuscated2 and a handshake probe.

Telegram clients that connect straight to a data center (no proxy secret)
start every TCP connection with a 64-byte obfuscated2 header. Its AES-256-CTR
keys are taken from the header itself, so the router can read it without any
client configuration. This module provides:

- a small pure-Python AES-256-CTR (Entware Python has no crypto library);
- building and reading obfuscated2 headers (the DC number sits in bytes 60-61);
- ``handshake``: a real req_pq_multi -> resPQ exchange with a data center, the
  check the autotuner uses to prove that MTProto passes the DPI.

Usage as a probe:
    python3 telegram_mtproto.py [--label L] [--timeout S] DC:IP:PORT ...
prints EVENT|TG_MTPROTO|label|dc|ip|status|milliseconds per target and exits 0
when at least ``--min-ok`` targets answered.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import os
import secrets
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------
# AES-256 (encryption only; CTR mode never needs the inverse cipher).

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _xor(left: bytes, right: bytes) -> bytes:
    """XOR of two equal-length byte strings (through ints: fast on MIPS)."""
    return (int.from_bytes(left, "big") ^ int.from_bytes(right, "big")).to_bytes(len(left), "big")


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x11B) if value & 0x100 else value


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        word = list(words[i - 1])
        if i % 8 == 0:
            word = word[1:] + word[:1]
            word = [_SBOX[b] for b in word]
            word[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            word = [_SBOX[b] for b in word]
        words.append(list(_xor(bytes(words[i - 8]), bytes(word))))
    # 15 round keys of 16 bytes, column-major like the state.
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(15)]


def _encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    state = list(_xor(block, bytes(round_keys[0])))
    for rnd in range(1, 15):
        state = [_SBOX[b] for b in state]
        # ShiftRows on a column-major state (index = column * 4 + row).
        state = [state[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
        if rnd != 14:
            mixed = []
            for c in range(4):
                a = state[c * 4:c * 4 + 4]
                total = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[r] ^ total ^ _xtime(a[r] ^ a[(r + 1) % 4]) for r in range(4)]
            state = mixed
        state = list(_xor(bytes(state), bytes(round_keys[rnd])))
    return bytes(state)


class AesCtr:
    """AES-256-CTR with a 128-bit big-endian counter (as OpenSSL/Telegram)."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(iv) != 16:
            raise ValueError("CTR needs a 16-byte IV")
        self._keys = _expand_key(bytes(key))
        self._counter = int.from_bytes(iv, "big")
        self._stream = b""

    def process(self, data: bytes) -> bytes:
        while len(self._stream) < len(data):
            block = self._counter.to_bytes(16, "big")
            self._counter = (self._counter + 1) % (1 << 128)
            self._stream += _encrypt_block(self._keys, block)
        out = _xor(bytes(data), self._stream[:len(data)])
        self._stream = self._stream[len(data):]
        return out


# --------------------------------------------------------------------------
# obfuscated2

ABRIDGED_TAG = b"\xef\xef\xef\xef"
_FORBIDDEN_STARTS = (
    b"HEAD", b"POST", b"GET ", b"OPTI", b"PUT ", b"\xdd\xdd\xdd\xdd",
    b"\xee\xee\xee\xee", b"\x16\x03\x01\x02",
)


def make_header(dc: int, tag: bytes = ABRIDGED_TAG) -> tuple[bytes, AesCtr, AesCtr]:
    """Return (header to send, encryptor, decryptor) for a client connection."""
    while True:
        init = bytearray(os.urandom(64))
        if init[0] == 0xEF or bytes(init[:4]) in _FORBIDDEN_STARTS:
            continue
        if init[4:8] == b"\0\0\0\0":
            continue
        break
    init[56:60] = tag
    init[60:62] = struct.pack("<h", dc)
    encryptor = AesCtr(bytes(init[8:40]), bytes(init[40:56]))
    reversed_part = bytes(init[8:56])[::-1]
    decryptor = AesCtr(reversed_part[:32], reversed_part[32:48])
    encrypted = encryptor.process(bytes(init))
    return bytes(init[:56]) + encrypted[56:64], encryptor, decryptor


def read_header(header: bytes) -> tuple[bytes, int] | None:
    """Decrypt a client's obfuscated2 header: (protocol tag, signed DC) or None.

    Works for direct connections only: a proxy secret would change the keys.
    """
    if len(header) < 64:
        return None
    plain = AesCtr(header[8:40], header[40:56]).process(header[:64])
    tag = plain[56:60]
    if tag not in (ABRIDGED_TAG, b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
        return None
    return tag, struct.unpack("<h", plain[60:62])[0]


# --------------------------------------------------------------------------
# Handshake probe: req_pq_multi -> resPQ over abridged transport.

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def handshake(ip: str, port: int, dc: int, timeout: float = 5.0) -> str:
    """Return "ok" when the DC answers req_pq_multi with a matching resPQ."""
    header, encryptor, decryptor = make_header(dc)
    nonce = secrets.token_bytes(16)
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce
    message_id = (int(time.time() * (1 << 32)) // 4) * 4
    message = b"\0" * 8 + struct.pack("<qi", message_id, len(body)) + body
    packet = bytes([len(message) // 4]) + message
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # One write, like real clients: the DPI sees header and payload together.
            sock.sendall(header + encryptor.process(packet))
            first = decryptor.process(_recv_exact(sock, 1))[0]
            if first == 0x7F:
                length = int.from_bytes(decryptor.process(_recv_exact(sock, 3)), "little") * 4
            else:
                length = first * 4
            if length == 4:
                return "server-error"
            if not 40 <= length <= 4096:
                return "bad-length"
            reply = decryptor.process(_recv_exact(sock, length))
    except socket.timeout:
        return "timeout"
    except ConnectionResetError:
        # An RST in the middle of the exchange is a typical DPI reaction.
        return "reset"
    except ConnectionRefusedError:
        return "network-error"
    except ConnectionError:
        return "closed"
    except OSError:
        return "network-error"
    if reply[:8] != b"\0" * 8 or struct.unpack("<I", reply[20:24])[0] != RES_PQ:
        return "bad-reply"
    return "ok" if reply[24:40] == nonce else "bad-nonce"


# Production data centers (IPv4) as built into the official clients.
DATA_CENTERS = {
    1: "149.154.175.53",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "91.108.56.130",
}


def parse_target(value: str) -> tuple[int, str, int]:
    try:
        dc_text, ip, port_text = value.split(":")
        dc, port = int(dc_text), int(port_text)
        if ipaddress.ip_address(ip).version != 4 or not 1 <= dc <= 5 or not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"target must be DC:IPv4:PORT, got {value!r}") from None
    return dc, ip, port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("targets", nargs="*", type=parse_target)
    parser.add_argument("--label", default="probe")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--min-ok", type=int, default=1)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.label.replace("-", "").replace("_", "").isalnum() or len(args.label) > 32:
        parser.error("label must be short and alphanumeric")
    if not 0.5 <= args.timeout <= 30:
        parser.error("timeout out of range")
    targets = args.targets or [(dc, ip, 443) for dc, ip in DATA_CENTERS.items()]

    def run(target: tuple[int, str, int]) -> tuple[int, str, str, int]:
        dc, ip, port = target
        started = time.monotonic()
        status = handshake(ip, port, dc, args.timeout)
        return dc, ip, status, int((time.monotonic() - started) * 1000)

    # In parallel: a blocked DC costs one timeout, not one per DC.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
        results = list(pool.map(run, targets))
    for dc, ip, status, elapsed in results:
        print(f"EVENT|TG_MTPROTO|{args.label}|{dc}|{ip}|{status}|{elapsed}", flush=True)
    passed = sum(status == "ok" for _, _, status, _ in results)
    return 0 if passed >= args.min_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

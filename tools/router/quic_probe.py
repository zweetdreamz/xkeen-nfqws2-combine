#!/usr/bin/env python3
"""Ask a host whether it answers a QUIC v1 Initial sent from the router.

curl on Entware is built without HTTP/3, so this probe builds the first QUIC
packet itself: a real QUIC v1 Initial (RFC 9000/9001) that carries a TLS 1.3
ClientHello with SNI=<host> and ALPN h3, padded to 1200 bytes, protected with
AES-128-GCM and header protection. A server answers it with its own Initial
(or a Version Negotiation / Retry / CONNECTION_CLOSE); a provider that drops
QUIC by name answers with silence. Any non-empty UDP reply counts as "ok".

The nfqws2 QUIC profiles decrypt the Initial and match the SNI against their
hostlist, so a router-originated probe goes through the profile under test.

Output (one line):

    EVENT|QUIC|<label>|<host>|<ip>|<status>|<ms>

status is ok | no-reply | dns-error | socket-error | build-error; <ms> is the
reply time in milliseconds for ok and "-" otherwise. Exit code 0 only for ok.

Only the standard library is used (AES-128, GCM and HKDF are implemented
here), so it runs on the router's Entware python3. Building one packet costs
about 80 AES blocks and 75 table-driven GHASH steps.

The probe idea and the ClientHello layout follow the QUIC check of
nfqws2-ui (https://github.com/zemidala/nfqws2-ui, src/www/api.php,
quicProbe / QUIC_LUA), MIT License, Copyright (c) 2026 zemidala. That code is
Lua run inside nfqws2; this is an independent Python implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import struct
import time
from typing import Any

# ---------------------------------------------------------------- AES-128


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x11B) if value & 0x100 else value


def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        # p *= 3 and q /= 3 in GF(2^8): q is the inverse of p.
        p = p ^ _xtime(p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        rotated = q
        affine = q
        for _ in range(4):
            rotated = ((rotated << 1) | (rotated >> 7)) & 0xFF
            affine ^= rotated
        sbox[p] = affine ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()


def _build_tables() -> tuple[list[int], list[int], list[int], list[int]]:
    te0 = []
    for value in SBOX:
        double = _xtime(value)
        te0.append((double << 24) | (value << 16) | (value << 8) | (double ^ value))
    te1 = [((word >> 8) | (word << 24)) & 0xFFFFFFFF for word in te0]
    te2 = [((word >> 16) | (word << 16)) & 0xFFFFFFFF for word in te0]
    te3 = [((word >> 24) | (word << 8)) & 0xFFFFFFFF for word in te0]
    return te0, te1, te2, te3


TE0, TE1, TE2, TE3 = _build_tables()


class AES128:
    """AES-128 block encryption (FIPS-197), table driven."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("AES-128 needs a 16-byte key")
        words = list(struct.unpack(">4I", key))
        rcon = 1
        for index in range(4, 44):
            temp = words[index - 1]
            if index % 4 == 0:
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                temp = (
                    (SBOX[temp >> 24] << 24)
                    | (SBOX[(temp >> 16) & 0xFF] << 16)
                    | (SBOX[(temp >> 8) & 0xFF] << 8)
                    | SBOX[temp & 0xFF]
                ) ^ (rcon << 24)
                rcon = _xtime(rcon)
            words.append(words[index - 4] ^ temp)
        self.round_keys = words

    def encrypt_block(self, block: bytes) -> bytes:
        rk = self.round_keys
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]
        te0, te1, te2, te3 = TE0, TE1, TE2, TE3
        for offset in range(4, 40, 4):
            t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 255] ^ te2[(s2 >> 8) & 255] ^ te3[s3 & 255] ^ rk[offset]
            t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 255] ^ te2[(s3 >> 8) & 255] ^ te3[s0 & 255] ^ rk[offset + 1]
            t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 255] ^ te2[(s0 >> 8) & 255] ^ te3[s1 & 255] ^ rk[offset + 2]
            t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 255] ^ te2[(s1 >> 8) & 255] ^ te3[s2 & 255] ^ rk[offset + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        sb = SBOX
        out = []
        for column, (a, b, c, d) in enumerate(((s0, s1, s2, s3), (s1, s2, s3, s0), (s2, s3, s0, s1), (s3, s0, s1, s2))):
            word = (
                (sb[a >> 24] << 24)
                | (sb[(b >> 16) & 255] << 16)
                | (sb[(c >> 8) & 255] << 8)
                | sb[d & 255]
            ) ^ rk[40 + column]
            out.append(word)
        return struct.pack(">4I", *out)


# --------------------------------------------------------------- AES-GCM

_GCM_R = 0xE1 << 120


def _gcm_tables(h: int) -> tuple[list[int], list[int]]:
    """Byte tables for multiplying by H (GCM bit order, big-endian ints).

    mul[b] = (b placed in the first byte) * H; red[b] reduces the byte that
    a multiplication by x^8 shifts out of the low end.
    """
    singles = []
    value = h
    for _ in range(8):  # H, H*x, ..., H*x^7 for bits 0x80 .. 0x01
        singles.append(value)
        value = (value >> 1) ^ (_GCM_R if value & 1 else 0)
    mul = [0] * 256
    for byte in range(1, 256):
        acc = 0
        for bit in range(8):
            if byte & (0x80 >> bit):
                acc ^= singles[bit]
        mul[byte] = acc
    red = [0] * 256
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (_GCM_R if value & 1 else 0)
        red[byte] = value
    return mul, red


def _ghash(mul: list[int], red: list[int], data: bytes) -> int:
    """GHASH over ``data`` (already padded to 16 bytes)."""
    y = 0
    for offset in range(0, len(data), 16):
        x = y ^ int.from_bytes(data[offset:offset + 16], "big")
        z = mul[x & 0xFF]
        for shift in range(8, 128, 8):
            z = (z >> 8) ^ red[z & 0xFF] ^ mul[(x >> shift) & 0xFF]
        y = z
    return y


def _pad16(data: bytes) -> bytes:
    return data + bytes(-len(data) % 16)


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-128-GCM with a 12-byte nonce; returns ciphertext || 16-byte tag."""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    cipher = AES128(key)
    mul, red = _gcm_tables(int.from_bytes(cipher.encrypt_block(bytes(16)), "big"))
    counter = int.from_bytes(nonce, "big") << 32
    pieces = []
    for block_index, offset in enumerate(range(0, len(plaintext), 16), 2):
        stream = cipher.encrypt_block((counter | block_index).to_bytes(16, "big"))
        chunk = plaintext[offset:offset + 16]
        pieces.append(
            (int.from_bytes(chunk, "big") ^ int.from_bytes(stream[:len(chunk)], "big")).to_bytes(len(chunk), "big")
        )
    ciphertext = b"".join(pieces)
    lengths = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    digest = _ghash(mul, red, _pad16(aad) + _pad16(ciphertext) + lengths)
    tag = digest ^ int.from_bytes(cipher.encrypt_block((counter | 1).to_bytes(16, "big")), "big")
    return ciphertext + tag.to_bytes(16, "big")


# ----------------------------------------------------- QUIC v1 protection

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, length: int, context: bytes = b"") -> bytes:
    full = b"tls13 " + label.encode("ascii")
    info = struct.pack(">HB", length, len(full)) + full + bytes([len(context)]) + context
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def initial_secrets(dcid: bytes) -> tuple[bytes, bytes]:
    """(client_initial_secret, server_initial_secret) for a destination CID."""
    initial = hkdf_extract(QUIC_V1_SALT, dcid)
    return (
        hkdf_expand_label(initial, "client in", 32),
        hkdf_expand_label(initial, "server in", 32),
    )


def packet_keys(secret: bytes) -> tuple[bytes, bytes, bytes]:
    """(key, iv, hp) for AES-128-GCM packet protection."""
    return (
        hkdf_expand_label(secret, "quic key", 16),
        hkdf_expand_label(secret, "quic iv", 12),
        hkdf_expand_label(secret, "quic hp", 16),
    )


def protect_packet(secret: bytes, header: bytes, payload: bytes, packet_number: int, pn_length: int) -> bytes:
    """Encrypt ``payload`` and apply header protection (RFC 9001 5.3, 5.4).

    ``header`` is the plain header ending with the ``pn_length``-byte packet
    number.
    """
    key, iv, hp = packet_keys(secret)
    nonce = (int.from_bytes(iv, "big") ^ packet_number).to_bytes(12, "big")
    sealed = aes_gcm_encrypt(key, nonce, payload, header)
    pn_offset = len(header) - pn_length
    packet = bytearray(header + sealed)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    if len(sample) != 16:
        raise ValueError("packet too short for a header protection sample")
    mask = AES128(hp).encrypt_block(sample)
    packet[0] ^= mask[0] & (0x0F if packet[0] & 0x80 else 0x1F)
    for index in range(pn_length):
        packet[pn_offset + index] ^= mask[1 + index]
    return bytes(packet)


# ------------------------------------------------------- Initial packet


def varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x4000 | value)
    if value < 0x40000000:
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def _vector16(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _extension(kind: int, data: bytes) -> bytes:
    return struct.pack(">H", kind) + _vector16(data)


HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")


def client_hello(host: str, scid: bytes, random_bytes: bytes, key_share: bytes) -> bytes:
    """A TLS 1.3 ClientHello (handshake message) with SNI, ALPN h3 and QUIC params."""
    name = host.encode("ascii")
    params = (
        varint(0x0F) + varint(len(scid)) + scid  # initial_source_connection_id
        + varint(0x01) + varint(4) + varint(30000)  # max_idle_timeout (ms)
        + varint(0x04) + varint(4) + varint(1048576)  # initial_max_data
        + varint(0x05) + varint(4) + varint(262144)  # initial_max_stream_data_bidi_local
        + varint(0x06) + varint(4) + varint(262144)  # initial_max_stream_data_bidi_remote
        + varint(0x07) + varint(4) + varint(262144)  # initial_max_stream_data_uni
        + varint(0x08) + varint(1) + varint(16)  # initial_max_streams_bidi
        + varint(0x09) + varint(1) + varint(16)  # initial_max_streams_uni
    )
    extensions = b"".join((
        _extension(0x0000, _vector16(b"\x00" + _vector16(name))),  # server_name
        _extension(0x000A, _vector16(struct.pack(">HH", 0x001D, 0x0017))),  # x25519, secp256r1
        _extension(0x000D, _vector16(struct.pack(">8H", 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))),
        _extension(0x0010, _vector16(b"\x02h3")),  # ALPN
        _extension(0x002B, b"\x02\x03\x04"),  # supported_versions: TLS 1.3
        _extension(0x002D, b"\x01\x01"),  # psk_key_exchange_modes: psk_dhe_ke
        _extension(0x0033, _vector16(struct.pack(">H", 0x001D) + _vector16(key_share))),
        _extension(0x0039, params),  # quic_transport_parameters
    ))
    body = (
        b"\x03\x03" + random_bytes
        + b"\x00"  # empty legacy_session_id (required by QUIC)
        + _vector16(struct.pack(">3H", 0x1301, 0x1302, 0x1303))
        + b"\x01\x00"  # null compression
        + _vector16(extensions)
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


DATAGRAM_SIZE = 1200
QUIC_PORT = 443
PN_LENGTH = 4
TAG_LENGTH = 16


def build_initial(host: str, *, dcid: bytes | None = None, scid: bytes | None = None,
                  random_source=os.urandom) -> bytes:
    """A protected QUIC v1 client Initial of exactly 1200 bytes."""
    if not HOST_RE.fullmatch(host):
        raise ValueError(f"invalid host name: {host!r}")
    dcid = dcid if dcid is not None else random_source(8)
    scid = scid if scid is not None else random_source(8)
    hello = client_hello(host, scid, random_source(32), random_source(32))
    crypto = b"\x06" + varint(0) + varint(len(hello)) + hello
    header_without_length = (
        bytes([0xC0 | (PN_LENGTH - 1)]) + b"\x00\x00\x00\x01"
        + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        + varint(0)  # token length
    )
    length_size = 2
    payload_size = DATAGRAM_SIZE - len(header_without_length) - length_size - PN_LENGTH - TAG_LENGTH
    if len(crypto) > payload_size:
        raise ValueError("ClientHello does not fit into one Initial")
    payload = crypto + bytes(payload_size - len(crypto))  # PADDING frames
    header = (
        header_without_length
        + struct.pack(">H", 0x4000 | (PN_LENGTH + payload_size + TAG_LENGTH))
        + bytes(PN_LENGTH)  # packet number 0
    )
    client_secret, _ = initial_secrets(dcid)
    packet = protect_packet(client_secret, header, payload, 0, PN_LENGTH)
    if len(packet) != DATAGRAM_SIZE:
        raise AssertionError("unexpected Initial size")
    return packet


# ------------------------------------------------------------------ probe


def resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, QUIC_PORT, socket.AF_INET, socket.SOCK_DGRAM)
    for info in infos:
        return info[4][0]
    raise OSError("no IPv4 address")


def probe(host: str, ip: str | None = None, timeout: float = 2.0, tries: int = 2) -> dict[str, Any]:
    """Send a QUIC Initial to host:443 and wait for any reply.

    Returns {"status", "ms", "ip", "bytes"}; status is ok, no-reply,
    dns-error, socket-error or build-error.
    """
    result: dict[str, Any] = {"status": "no-reply", "ms": None, "ip": ip or "", "bytes": 0}
    try:
        packet = build_initial(host)
    except (ValueError, OSError):
        result["status"] = "build-error"
        return result
    if not ip:
        try:
            ip = resolve_ipv4(host)
        except (OSError, UnicodeError):
            result["status"] = "dns-error"
            return result
        result["ip"] = ip
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        result["status"] = "socket-error"
        return result
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, QUIC_PORT))
        except OSError:
            result["status"] = "socket-error"
            return result
        started = time.monotonic()
        for _ in range(max(1, tries)):
            try:
                sock.send(packet)
            except OSError:
                result["status"] = "socket-error"
                return result
            try:
                reply = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                # ICMP port/host unreachable: no QUIC answer from this address.
                break
            if reply:
                result.update(status="ok", ms=int(round((time.monotonic() - started) * 1000)), bytes=len(reply))
                return result
        return result
    finally:
        sock.close()


def clean_field(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)[:64] or "-"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("host")
    parser.add_argument("--ip", help="IPv4 to send to instead of resolving HOST")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--tries", type=int, default=2)
    parser.add_argument("--label", default="quic")
    args = parser.parse_args(argv)
    if args.ip:
        try:
            if ipaddress.ip_address(args.ip).version != 4:
                parser.error("--ip must be IPv4")
        except ValueError:
            parser.error("--ip must be IPv4")
    if not 0.2 <= args.timeout <= 10 or not 1 <= args.tries <= 5:
        parser.error("--timeout must be 0.2..10 and --tries 1..5")
    result = probe(args.host, args.ip, args.timeout, args.tries)
    ms = str(result["ms"]) if result["ms"] is not None else "-"
    print(
        f"EVENT|QUIC|{clean_field(args.label)}|{clean_field(args.host)}|"
        f"{clean_field(result['ip'])}|{result['status']}|{ms}",
        flush=True,
    )
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

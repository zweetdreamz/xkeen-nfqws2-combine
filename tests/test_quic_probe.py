"""tools/router/quic_probe.py: crypto against RFC 9001 Appendix A, packet shape, probe."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("quic_probe", ROOT / "tools" / "router" / "quic_probe.py")
QP = importlib.util.module_from_spec(_SPEC)
sys.modules["quic_probe"] = QP
_SPEC.loader.exec_module(QP)

H = bytes.fromhex

# RFC 9001 Appendix A.1 (keys), A.2 (client Initial), A.3 (server Initial).
DCID = H("8394c8f03e515708")
CLIENT_HEADER = H("c300000001088394c8f03e5157080000449e00000002")
CLIENT_PAYLOAD = H(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff"
) + bytes(917)
CLIENT_PACKET = H(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934"
)
SERVER_HEADER = H("c1000000010008f067a5502a4262b50040750001")
SERVER_PAYLOAD = H(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304"
)
SERVER_PACKET = H(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee"
)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    size = 1 << (first >> 6)
    value = first & 0x3F
    for index in range(1, size):
        value = (value << 8) | data[offset + index]
    return value, offset + size


def open_initial(packet: bytes) -> tuple[bytes, bytes, int]:
    """Remove header protection and decrypt a client Initial built by the probe.

    GCM decryption is the same key stream as encryption; the tag is checked by
    sealing the recovered plaintext again.
    """
    dcid_length = packet[5]
    dcid = packet[6:6 + dcid_length]
    offset = 6 + dcid_length
    scid_length = packet[offset]
    offset += 1 + scid_length
    token_length, offset = read_varint(packet, offset)
    offset += token_length
    length, pn_offset = read_varint(packet, offset)
    client, _ = QP.initial_secrets(dcid)
    key, iv, hp = QP.packet_keys(client)
    mask = QP.AES128(hp).encrypt_block(packet[pn_offset + 4:pn_offset + 20])
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_length = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_length], mask[1:1 + pn_length], strict=True))
    header = bytes([first]) + packet[1:pn_offset] + pn_bytes
    packet_number = int.from_bytes(pn_bytes, "big")
    nonce = (int.from_bytes(iv, "big") ^ packet_number).to_bytes(12, "big")
    sealed = packet[pn_offset + pn_length:pn_offset + length]
    plaintext = QP.aes_gcm_encrypt(key, nonce, sealed[:-16], header)[:-16]
    if QP.aes_gcm_encrypt(key, nonce, plaintext, header) != sealed:
        raise AssertionError("authentication tag mismatch")
    return header, plaintext, packet_number


def client_hello_extensions(hello: bytes) -> dict[int, bytes]:
    assert hello[0] == 1
    body = hello[4:4 + int.from_bytes(hello[1:4], "big")]
    offset = 2 + 32
    offset += 1 + body[offset]  # session id
    offset += 2 + int.from_bytes(body[offset:offset + 2], "big")  # cipher suites
    offset += 1 + body[offset]  # compression
    total = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    end = offset + total
    result = {}
    while offset < end:
        kind, size = struct.unpack(">HH", body[offset:offset + 4])
        result[kind] = body[offset + 4:offset + 4 + size]
        offset += 4 + size
    return result


class CryptoVectorTests(unittest.TestCase):
    def test_aes128_fips197_vector(self):
        self.assertEqual(
            QP.AES128(bytes(range(16))).encrypt_block(H("00112233445566778899aabbccddeeff")).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        )

    def test_gcm_nist_vectors(self):
        # NIST GCM spec test cases 2 and 4 (AES-128).
        self.assertEqual(
            QP.aes_gcm_encrypt(bytes(16), bytes(12), bytes(16), b"").hex(),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
        )
        key = H("feffe9928665731c6d6a8f9467308308")
        iv = H("cafebabefacedbaddecaf888")
        plaintext = H(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        self.assertEqual(
            QP.aes_gcm_encrypt(key, iv, plaintext, aad).hex(),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            "5bc94fbc3221a5db94fae95ae7121a47",
        )

    def test_rfc9001_a1_key_derivation(self):
        client, server = QP.initial_secrets(DCID)
        self.assertEqual(client.hex(), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        self.assertEqual(server.hex(), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        self.assertEqual(
            [part.hex() for part in QP.packet_keys(client)],
            ["1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"],
        )
        self.assertEqual(
            [part.hex() for part in QP.packet_keys(server)],
            ["cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"],
        )

    def test_rfc9001_a2_client_initial_protection(self):
        client, _ = QP.initial_secrets(DCID)
        self.assertEqual(QP.protect_packet(client, CLIENT_HEADER, CLIENT_PAYLOAD, 2, 4), CLIENT_PACKET)

    def test_rfc9001_a3_server_initial_protection(self):
        _, server = QP.initial_secrets(DCID)
        self.assertEqual(QP.protect_packet(server, SERVER_HEADER, SERVER_PAYLOAD, 1, 2), SERVER_PACKET)

    def test_header_protection_sample_and_mask(self):
        # A.2: sample d1b1c98dd7689fb8ec11d242b123dc9b gives mask 437b9aec36.
        _, _, hp = QP.packet_keys(QP.initial_secrets(DCID)[0])
        self.assertEqual(QP.AES128(hp).encrypt_block(H("d1b1c98dd7689fb8ec11d242b123dc9b"))[:5].hex(), "437b9aec36")

    def test_varint(self):
        self.assertEqual(QP.varint(37), H("25"))
        self.assertEqual(QP.varint(15293), H("7bbd"))
        self.assertEqual(QP.varint(494878333), H("9d7f3e7d"))
        self.assertEqual(QP.varint(151288809941952652), H("c2197c5eff14e88c"))


class InitialPacketTests(unittest.TestCase):
    def test_initial_is_1200_bytes_long_header_v1(self):
        packet = QP.build_initial("www.youtube.com")
        self.assertEqual(len(packet), 1200)
        self.assertEqual(packet[0] & 0xF0, 0xC0)  # long header, Initial
        self.assertEqual(packet[1:5], b"\x00\x00\x00\x01")

    def test_initial_decrypts_to_client_hello_with_sni_and_h3(self):
        packet = QP.build_initial("rr1---sn-abc.googlevideo.com")
        header, plaintext, packet_number = open_initial(packet)
        self.assertEqual(packet_number, 0)
        self.assertEqual(header[0], 0xC3)
        self.assertEqual(plaintext[0], 0x06)  # CRYPTO frame
        offset, position = read_varint(plaintext, 1)
        self.assertEqual(offset, 0)
        length, position = read_varint(plaintext, position)
        hello = plaintext[position:position + length]
        self.assertTrue(all(byte == 0 for byte in plaintext[position + length:]))  # PADDING
        extensions = client_hello_extensions(hello)
        self.assertIn(b"rr1---sn-abc.googlevideo.com", extensions[0x0000])
        self.assertEqual(extensions[0x0010], b"\x00\x03\x02h3")
        self.assertEqual(extensions[0x002B], b"\x02\x03\x04")
        self.assertEqual(len(extensions[0x0033]), 2 + 2 + 2 + 32)
        self.assertIn(0x0039, extensions)

    def test_each_initial_uses_fresh_connection_ids(self):
        self.assertNotEqual(QP.build_initial("www.youtube.com")[6:14], QP.build_initial("www.youtube.com")[6:14])

    def test_invalid_host_is_rejected(self):
        for host in ("", "bad host", "a" * 300, "x|y", "-a.com"):
            with self.assertRaises(ValueError):
                QP.build_initial(host)


class UdpServer:
    def __init__(self, reply: bytes | None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]
        self.reply = reply
        self.received: list[bytes] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while True:
            try:
                data, address = self.sock.recvfrom(4096)
            except OSError:
                return
            self.received.append(data)
            if self.reply is not None:
                self.sock.sendto(self.reply, address)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.sock.close()


class ProbeTests(unittest.TestCase):
    def test_any_reply_is_ok(self):
        with UdpServer(b"\xc0reply") as server, mock.patch.object(QP, "QUIC_PORT", server.port):
            result = QP.probe("www.youtube.com", "127.0.0.1", timeout=1.0, tries=2)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["bytes"], 6)
        self.assertEqual(result["ip"], "127.0.0.1")
        self.assertIsInstance(result["ms"], int)
        self.assertEqual(len(server.received[0]), 1200)

    def test_silence_is_no_reply_after_all_tries(self):
        with UdpServer(None) as server, mock.patch.object(QP, "QUIC_PORT", server.port):
            result = QP.probe("www.youtube.com", "127.0.0.1", timeout=0.3, tries=2)
            # The server thread may still be reading the second datagram.
            for _ in range(20):
                if len(server.received) >= 2:
                    break
                threading.Event().wait(0.05)
        self.assertEqual(result["status"], "no-reply")
        self.assertIsNone(result["ms"])
        self.assertEqual(len(server.received), 2)

    def test_dns_and_build_errors(self):
        with mock.patch.object(QP, "resolve_ipv4", side_effect=OSError("nxdomain")):
            self.assertEqual(QP.probe("www.youtube.com")["status"], "dns-error")
        self.assertEqual(QP.probe("bad host", "127.0.0.1")["status"], "build-error")

    def test_cli_prints_contract_event(self):
        with UdpServer(b"x") as server, mock.patch.object(QP, "QUIC_PORT", server.port):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = QP.main(["www.youtube.com", "--ip", "127.0.0.1", "--timeout", "1", "--label", "raw"])
        self.assertEqual(code, 0)
        fields = output.getvalue().strip().split("|")
        self.assertEqual(fields[:6], ["EVENT", "QUIC", "raw", "www.youtube.com", "127.0.0.1", "ok"])
        self.assertTrue(fields[6].isdigit())

    def test_cli_no_reply_exit_code_and_dash(self):
        with UdpServer(None) as server, mock.patch.object(QP, "QUIC_PORT", server.port):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = QP.main(["www.youtube.com", "--ip", "127.0.0.1", "--timeout", "0.2", "--tries", "1"])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue().strip(), "EVENT|QUIC|quic|www.youtube.com|127.0.0.1|no-reply|-")

    def test_cli_rejects_ipv6_and_bad_limits(self):
        for argv in (["h.com", "--ip", "::1"], ["h.com", "--timeout", "60"], ["h.com", "--tries", "0"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                QP.main(argv)


if __name__ == "__main__":
    unittest.main()

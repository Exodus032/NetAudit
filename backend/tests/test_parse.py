from __future__ import annotations

import socket
import struct

from netaudit.capture.parse import parse_ipv4_packet


def _ipv4_header(protocol: int, total_length: int, src="10.0.0.5", dst="93.184.216.34") -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, ihl 5 (20 bytes)
        0,  # tos
        total_length,
        0,  # id
        0,  # flags/frag
        64,  # ttl
        protocol,
        0,  # checksum (unused by parser)
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )


def _tcp_header(src_port=51422, dst_port=443, flags=0x12) -> bytes:
    return struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        1000,  # seq
        2000,  # ack
        (5 << 4),  # data offset = 5 words, reserved 0
        flags,
        65535,  # window
        0,  # checksum
        0,  # urgent pointer
    )


def _udp_header(src_port=51500, dst_port=53, length=8) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def _icmp_header(icmp_type=8, code=0) -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + b"\x00" * 4


class TestTcp:
    def test_parses_ports_and_flags(self):
        tcp = _tcp_header(flags=0x12)  # SYN + ACK
        packet = _ipv4_header(protocol=6, total_length=20 + len(tcp)) + tcp
        result = parse_ipv4_packet(packet)
        assert result is not None
        assert result.protocol == "tcp"
        assert result.src_addr == "10.0.0.5"
        assert result.dst_addr == "93.184.216.34"
        assert result.src_port == 51422
        assert result.dst_port == 443
        assert result.flags == "SYN,ACK"
        assert result.length == 20 + len(tcp)

    def test_psh_ack_flags(self):
        tcp = _tcp_header(flags=0x18)  # PSH + ACK
        packet = _ipv4_header(protocol=6, total_length=20 + len(tcp)) + tcp
        result = parse_ipv4_packet(packet)
        assert result.flags == "PSH,ACK"

    def test_truncated_tcp_payload_does_not_raise(self):
        # Only 6 bytes of "TCP" payload -- not enough for ports even.
        packet = _ipv4_header(protocol=6, total_length=26) + b"\x00" * 6
        result = parse_ipv4_packet(packet)
        assert result is not None
        assert result.protocol == "tcp"
        assert result.src_port is None
        assert result.dst_port is None


class TestUdp:
    def test_parses_ports(self):
        udp = _udp_header(src_port=51500, dst_port=53)
        packet = _ipv4_header(protocol=17, total_length=20 + len(udp)) + udp
        result = parse_ipv4_packet(packet)
        assert result is not None
        assert result.protocol == "udp"
        assert result.src_port == 51500
        assert result.dst_port == 53


class TestIcmp:
    def test_parses_type_and_code(self):
        icmp = _icmp_header(icmp_type=8, code=0)
        packet = _ipv4_header(protocol=1, total_length=20 + len(icmp)) + icmp
        result = parse_ipv4_packet(packet)
        assert result is not None
        assert result.protocol == "icmp"
        assert result.icmp_type == 8
        assert result.icmp_code == 0
        assert result.src_port is None


class TestOtherProtocol:
    def test_unknown_protocol_number_reports_other(self):
        packet = _ipv4_header(protocol=47, total_length=24) + b"\x00" * 4  # GRE
        result = parse_ipv4_packet(packet)
        assert result is not None
        assert result.protocol == "other"


class TestMalformed:
    def test_empty_bytes(self):
        assert parse_ipv4_packet(b"") is None

    def test_too_short_for_ip_header(self):
        assert parse_ipv4_packet(b"\x45\x00\x00") is None

    def test_wrong_ip_version(self):
        # version 6 in the top nibble
        packet = bytearray(_ipv4_header(protocol=6, total_length=40))
        packet[0] = 0x65
        assert parse_ipv4_packet(bytes(packet)) is None

    def test_garbage_does_not_raise(self):
        garbage = bytes(range(60))
        # Should either return a best-effort result or None -- must never raise.
        parse_ipv4_packet(garbage)

    def test_ihl_claims_more_than_available_does_not_raise(self):
        # ihl = 15 (60-byte header) but we only supply 20 bytes total.
        packet = bytearray(_ipv4_header(protocol=6, total_length=40))
        packet[0] = 0x4F
        assert parse_ipv4_packet(bytes(packet)) is None

    def test_random_bytes_never_raise(self):
        import random
        rng = random.Random(42)
        for _ in range(200):
            length = rng.randint(0, 80)
            data = bytes(rng.getrandbits(8) for _ in range(length))
            parse_ipv4_packet(data)  # must not raise

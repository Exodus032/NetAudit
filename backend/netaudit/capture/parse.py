"""Pure-python IPv4 header parser used by the raw-socket capture tier.

No dependency on scapy or sockets -- takes raw bytes (as delivered by a
``SIO_RCVALL`` raw socket, i.e. an IPv4 packet with no Ethernet header) and
returns a :class:`ParsedPacket`, or ``None`` if the bytes cannot be
interpreted as IPv4. Must never raise on truncated or malformed input --
that guarantee is what the unit tests in tests/test_parse.py check.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ICMPV6 = 58


@dataclass
class ParsedPacket:
    protocol: str  # "tcp" | "udp" | "icmp" | "other"
    src_addr: str
    dst_addr: str
    src_port: int | None
    dst_port: int | None
    length: int  # total IP packet length (from the IP header, not len(data))
    flags: str  # comma-joined TCP flags, "" otherwise
    icmp_type: int | None = None
    icmp_code: int | None = None


def _format_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _tcp_flags_to_str(flag_byte: int) -> str:
    names = [name for bit, name in TCP_FLAG_BITS if flag_byte & bit]
    return ",".join(names)


def parse_ipv4_packet(data: bytes) -> ParsedPacket | None:
    """Parse a raw IPv4 packet. Returns None instead of raising on bad input."""
    try:
        if not data or len(data) < 20:
            return None

        first_byte = data[0]
        version = first_byte >> 4
        ihl = first_byte & 0x0F
        if version != 4:
            return None
        header_len = ihl * 4
        if header_len < 20 or len(data) < header_len:
            return None

        total_length = struct.unpack("!H", data[2:4])[0]
        proto_num = data[9]
        src_addr = _format_ipv4(data[12:16])
        dst_addr = _format_ipv4(data[16:20])

        payload = data[header_len:]
        # total_length from the header is authoritative for "length"; fall
        # back to what we actually received if the header lies (common on
        # loopback / segmentation-offloaded captures).
        length = total_length if total_length >= header_len else len(data)

        if proto_num == PROTO_TCP:
            return _parse_tcp(payload, src_addr, dst_addr, length)
        if proto_num == PROTO_UDP:
            return _parse_udp(payload, src_addr, dst_addr, length)
        if proto_num in (PROTO_ICMP, PROTO_ICMPV6):
            return _parse_icmp(payload, src_addr, dst_addr, length)

        return ParsedPacket(
            protocol="other",
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=None,
            dst_port=None,
            length=length,
            flags="",
        )
    except (struct.error, IndexError, ValueError):
        return None


def _parse_tcp(payload: bytes, src_addr: str, dst_addr: str, length: int) -> ParsedPacket | None:
    if len(payload) < 14:
        # Not enough for src/dst port + flags byte; report as best-effort TCP
        # with no ports rather than dropping it entirely.
        return ParsedPacket(
            protocol="tcp",
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=None,
            dst_port=None,
            length=length,
            flags="",
        )
    src_port, dst_port = struct.unpack("!HH", payload[0:4])
    flag_byte = payload[13] & 0x3F
    return ParsedPacket(
        protocol="tcp",
        src_addr=src_addr,
        dst_addr=dst_addr,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        flags=_tcp_flags_to_str(flag_byte),
    )


def _parse_udp(payload: bytes, src_addr: str, dst_addr: str, length: int) -> ParsedPacket | None:
    if len(payload) < 4:
        return ParsedPacket(
            protocol="udp",
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=None,
            dst_port=None,
            length=length,
            flags="",
        )
    src_port, dst_port = struct.unpack("!HH", payload[0:4])
    return ParsedPacket(
        protocol="udp",
        src_addr=src_addr,
        dst_addr=dst_addr,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        flags="",
    )


def _parse_icmp(payload: bytes, src_addr: str, dst_addr: str, length: int) -> ParsedPacket | None:
    icmp_type = payload[0] if len(payload) >= 1 else None
    icmp_code = payload[1] if len(payload) >= 2 else None
    return ParsedPacket(
        protocol="icmp",
        src_addr=src_addr,
        dst_addr=dst_addr,
        src_port=None,
        dst_port=None,
        length=length,
        flags="",
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )

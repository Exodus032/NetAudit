"""Frame synthesis for tiers where only header fields were stored (E1/E3).

`netaudit.store.packets` never stores raw frame bytes (see SECURITY.md Part
C item 8: no payload column exists at all, on any tier). To produce a real
`.pcap` file we build a plausible Ethernet/IPv4/TCP|UDP|ICMP header stack
from the fields we *do* have, and we are explicit about what is real and
what is not:

  - Every address, port, protocol and flag byte in the synthesised headers
    comes directly from an observed field.
  - Anything we cannot know (MAC addresses, TCP sequence numbers, IP
    identification, ...) is a fixed, clearly-fake placeholder -- never a
    plausible-looking invented value.
  - Payload is never fabricated. We zero-fill the remainder of the frame up
    to the real observed length so the frame's total size on the wire
    matches what was actually seen, but the bytes themselves carry no
    invented content.
  - `orig_len` is always the real observed length. `incl_len` is exactly
    the number of bytes we actually wrote (header stack, zero-padded to
    `orig_len` when there's room for it; truncated to fit if the observed
    length is implausibly smaller than a minimal header stack).

Sessions built this way must be marked `synthetic: true` with a truthful
`synthetic_reason` -- see `pcap/sessions.py`.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional

FAKE_SRC_MAC = bytes.fromhex("020000000001")  # locally-administered, never a real OUI
FAKE_DST_MAC = bytes.fromhex("020000000002")

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

_TCP_FLAG_BITS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}


def _checksum16(data: bytes) -> int:
    """Standard one's-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _parse_tcp_flags(flags_str: Optional[str]) -> int:
    if not flags_str:
        return 0
    bits = 0
    for token in flags_str.replace("|", ",").split(","):
        token = token.strip().upper()
        if token in _TCP_FLAG_BITS:
            bits |= _TCP_FLAG_BITS[token]
    return bits


def _is_ipv4(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return "." in addr
    except (OSError, ValueError):
        return False


def _ipv4_bytes(addr: str) -> bytes:
    try:
        return socket.inet_aton(addr)
    except OSError:
        return b"\x00\x00\x00\x00"


def _build_ipv4_header(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # version 4, IHL 5 (20 bytes, no options)
        0,              # DSCP/ECN
        total_len & 0xFFFF,
        0,              # identification (unknown -- placeholder)
        0x4000,         # flags/fragment offset: Don't Fragment, no offset
        64,             # TTL (placeholder -- not observed)
        proto,
        0,              # checksum placeholder, filled below
        _ipv4_bytes(src),
        _ipv4_bytes(dst),
    )
    csum = _checksum16(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _build_tcp_header(src_port: int, dst_port: int, flags_str: Optional[str],
                       src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    flags = _parse_tcp_flags(flags_str)
    header_no_csum = struct.pack(
        "!HHIIBBHHH",
        src_port & 0xFFFF, dst_port & 0xFFFF,
        0,              # sequence number (unknown -- placeholder)
        0,              # ack number (unknown -- placeholder)
        5 << 4,         # data offset 5 (20 bytes, no options), reserved bits 0
        flags,
        0,              # window size (unknown -- placeholder)
        0,              # checksum placeholder
        0,              # urgent pointer
    )
    pseudo = _ipv4_bytes(src_ip) + _ipv4_bytes(dst_ip) + struct.pack(
        "!BBH", 0, IPPROTO_TCP, len(header_no_csum) + len(payload)
    )
    csum = _checksum16(pseudo + header_no_csum + payload)
    return header_no_csum[:16] + struct.pack("!H", csum) + header_no_csum[18:]


def _build_udp_header(src_port: int, dst_port: int, src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header_no_csum = struct.pack("!HHHH", src_port & 0xFFFF, dst_port & 0xFFFF, length, 0)
    pseudo = _ipv4_bytes(src_ip) + _ipv4_bytes(dst_ip) + struct.pack("!BBH", 0, IPPROTO_UDP, length)
    csum = _checksum16(pseudo + header_no_csum + payload) or 0xFFFF  # 0 means "no checksum"; avoid ambiguity
    return header_no_csum[:6] + struct.pack("!H", csum)


def _build_icmp_header(payload: bytes) -> bytes:
    # Neither type nor code is observed on any tier; 8/0 (echo request) is
    # the most neutral, clearly-a-placeholder choice.
    header_no_csum = struct.pack("!BBHHH", 8, 0, 0, 0, 0)
    csum = _checksum16(header_no_csum + payload)
    return header_no_csum[:2] + struct.pack("!H", csum) + header_no_csum[4:]


def synthesize_frame(packet: dict) -> tuple[bytes, int]:
    """Build a synthetic Ethernet frame from a stored packet-log row.

    `packet` uses the same field names as `store.packets._row_to_entry`
    (protocol, src_addr, src_port, dst_addr, dst_port, length, flags).

    Returns (frame_bytes, orig_len). `len(frame_bytes)` is the pcap
    `incl_len`; `orig_len` is the real observed length to write into the
    pcap record unchanged.
    """
    protocol = (packet.get("protocol") or "").lower()
    src_addr = packet.get("src_addr") or "0.0.0.0"
    dst_addr = packet.get("dst_addr") or "0.0.0.0"
    src_port = packet.get("src_port") or 0
    dst_port = packet.get("dst_port") or 0
    orig_len = int(packet.get("length") or 0)

    if not _is_ipv4(src_addr) or not _is_ipv4(dst_addr):
        # IPv6 or unparseable address: emit an Ethernet header only, zero-
        # padded, rather than guess at an IPv6 header we have no fields
        # for. Honest and still opens fine in Wireshark as "Ethernet II".
        eth_header = FAKE_DST_MAC + FAKE_SRC_MAC + struct.pack("!H", ETHERTYPE_IPV6)
        return _pad_to(eth_header, orig_len), orig_len

    if protocol == "tcp":
        l4_no_payload_len = 20
        proto_num = IPPROTO_TCP
    elif protocol == "udp":
        l4_no_payload_len = 8
        proto_num = IPPROTO_UDP
    elif protocol == "icmp":
        l4_no_payload_len = 8
        proto_num = IPPROTO_ICMP
    else:
        # Unknown/other protocol: IPv4 header only, no L4 guess.
        eth_header = FAKE_DST_MAC + FAKE_SRC_MAC + struct.pack("!H", ETHERTYPE_IPV4)
        ip_header = _build_ipv4_header(src_addr, dst_addr, 253, 0)  # 253: reserved for experimentation
        stack = eth_header + ip_header
        return _pad_to(stack, orig_len), orig_len

    stack_len_no_payload = 14 + 20 + l4_no_payload_len
    payload_len = max(0, orig_len - stack_len_no_payload)
    payload = b"\x00" * payload_len

    eth_header = FAKE_DST_MAC + FAKE_SRC_MAC + struct.pack("!H", ETHERTYPE_IPV4)
    ip_header = _build_ipv4_header(src_addr, dst_addr, proto_num, l4_no_payload_len + payload_len)

    if protocol == "tcp":
        l4_header = _build_tcp_header(src_port, dst_port, packet.get("flags"), src_addr, dst_addr, payload)
    elif protocol == "udp":
        l4_header = _build_udp_header(src_port, dst_port, src_addr, dst_addr, payload)
    else:
        l4_header = _build_icmp_header(payload)

    frame = eth_header + ip_header + l4_header + payload
    return _pad_to(frame, orig_len), orig_len


def _pad_to(stack: bytes, orig_len: int) -> bytes:
    """Zero-pad `stack` up to orig_len if there's room; otherwise (an
    implausibly small observed length) truncate the header stack itself so
    incl_len never exceeds orig_len. Either way, no fabricated content --
    only zeros or a shorter (but still honest) header prefix."""
    if orig_len <= 0:
        return b""
    if len(stack) < orig_len:
        return stack + b"\x00" * (orig_len - len(stack))
    return stack[:orig_len]

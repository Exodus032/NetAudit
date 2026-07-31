"""Minimal, bounds-checked frame dissector: the inverse of `synth.py`.

Used only on E2 import, to pull (protocol, addrs, ports, flags) out of the
*real* frame bytes a `.pcap`/`.pcapng` file actually contains, so imported
sessions can be queried like the live traffic log. Deliberately narrow --
Ethernet (+ single VLAN tag) carrying IPv4 or IPv6, then TCP/UDP/ICMP(v6).
Anything else degrades to `protocol: "other"` rather than raising; this is
best-effort enrichment of untrusted bytes, not a security boundary, so it
never raises -- a short/malformed frame just yields fewer fields.
"""
from __future__ import annotations

import struct
from typing import Optional

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

_TCP_FLAG_NAMES = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def _tcp_flags_str(bits: int) -> str:
    return ",".join(name for mask, name in _TCP_FLAG_NAMES if bits & mask)


LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


def dissect_frame(linktype: int, data: bytes) -> dict:
    """Dispatches on pcap linktype. Ethernet is dissected normally; RAW
    (no L2 header, straight to IP) is handled directly; anything else
    yields protocol "other" rather than guessing at a layout we don't
    know."""
    if linktype == LINKTYPE_ETHERNET:
        return dissect_ethernet(data)
    if linktype == LINKTYPE_RAW:
        return dissect_raw_ip(data)
    return {
        "protocol": "other", "src_addr": None, "src_port": None,
        "dst_addr": None, "dst_port": None, "flags": None,
    }


def dissect_raw_ip(data: bytes) -> dict:
    result: dict = {
        "protocol": "other", "src_addr": None, "src_port": None,
        "dst_addr": None, "dst_port": None, "flags": None,
    }
    if not data:
        return result
    version = (data[0] >> 4) & 0x0F
    if version == 4:
        _dissect_ipv4(data, result)
    elif version == 6:
        _dissect_ipv6(data, result)
    return result


def dissect_ethernet(data: bytes) -> dict:
    """Best-effort extraction from a captured Ethernet frame. Returns a
    dict with whatever it could determine; always includes at least
    `protocol` (defaulting to "other") and never raises."""
    result: dict = {
        "protocol": "other", "src_addr": None, "src_port": None,
        "dst_addr": None, "dst_port": None, "flags": None,
    }
    if len(data) < 14:
        return result

    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if ethertype == ETHERTYPE_VLAN and len(data) >= offset + 4:
        ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        offset += 4

    if ethertype == ETHERTYPE_IPV4:
        _dissect_ipv4(data[offset:], result)
    elif ethertype == ETHERTYPE_IPV6:
        _dissect_ipv6(data[offset:], result)
    return result


def _dissect_ipv4(buf: bytes, result: dict) -> None:
    if len(buf) < 20:
        return
    ver_ihl = buf[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return
    proto_num = buf[9]
    src = ".".join(str(b) for b in buf[12:16])
    dst = ".".join(str(b) for b in buf[16:20])
    result["src_addr"] = src
    result["dst_addr"] = dst
    _dissect_l4(proto_num, buf[ihl:], result)


def _dissect_ipv6(buf: bytes, result: dict) -> None:
    if len(buf) < 40:
        return
    next_header = buf[6]
    src = _format_ipv6(buf[8:24])
    dst = _format_ipv6(buf[24:40])
    result["src_addr"] = src
    result["dst_addr"] = dst
    _dissect_l4(next_header, buf[40:], result)


def _format_ipv6(raw: bytes) -> str:
    groups = struct.unpack("!8H", raw)
    return ":".join(f"{g:x}" for g in groups)


def _dissect_l4(proto_num: int, buf: bytes, result: dict) -> None:
    if proto_num == 6 and len(buf) >= 20:  # TCP
        result["protocol"] = "tcp"
        src_port, dst_port = struct.unpack("!HH", buf[0:4])
        flags_byte = buf[13]
        result["src_port"] = src_port
        result["dst_port"] = dst_port
        result["flags"] = _tcp_flags_str(flags_byte)
    elif proto_num == 17 and len(buf) >= 8:  # UDP
        result["protocol"] = "udp"
        src_port, dst_port = struct.unpack("!HH", buf[0:4])
        result["src_port"] = src_port
        result["dst_port"] = dst_port
    elif proto_num in (1, 58):  # ICMP / ICMPv6
        result["protocol"] = "icmp"
    else:
        result["protocol"] = "other"

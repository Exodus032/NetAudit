from __future__ import annotations

import struct

from netaudit.pcap import synth


def _checksum_ok(data: bytes) -> bool:
    """The one's-complement checksum of a correctly-checksummed block is 0."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF == 0


def test_tcp_frame_has_correct_lengths_and_zero_payload():
    packet = {
        "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 51000,
        "dst_addr": "93.184.216.34", "dst_port": 443, "length": 1420,
        "flags": "PSH,ACK",
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert orig_len == 1420
    assert len(frame) == 1420  # padded up to the observed length

    eth = frame[0:14]
    assert eth[12:14] == struct.pack("!H", synth.ETHERTYPE_IPV4)

    ip = frame[14:34]
    assert ip[9] == synth.IPPROTO_TCP
    assert _checksum_ok(ip)
    assert ip[12:16] == bytes([10, 0, 0, 5])
    assert ip[16:20] == bytes([93, 184, 216, 34])
    total_len = struct.unpack("!H", ip[2:4])[0]
    assert total_len == 1420 - 14  # IP total length excludes the Ethernet header

    tcp = frame[34:54]
    src_port, dst_port = struct.unpack("!HH", tcp[0:4])
    assert (src_port, dst_port) == (51000, 443)
    flags_byte = tcp[13]
    assert flags_byte & 0x08  # PSH
    assert flags_byte & 0x10  # ACK
    assert not (flags_byte & 0x02)  # not SYN

    payload = frame[54:]
    assert payload == b"\x00" * len(payload)


def test_udp_frame_checksum_and_length():
    packet = {
        "protocol": "udp", "src_addr": "10.0.0.5", "src_port": 51000,
        "dst_addr": "8.8.8.8", "dst_port": 53, "length": 74, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert orig_len == 74
    assert len(frame) == 74
    udp = frame[34:42]
    src_port, dst_port, length = struct.unpack("!HHH", udp[0:6])
    assert (src_port, dst_port) == (51000, 53)
    assert length == 74 - 34  # UDP length = header + payload, excludes eth/ip


def test_icmp_frame_type_is_placeholder_echo():
    packet = {
        "protocol": "icmp", "src_addr": "10.0.0.5", "dst_addr": "1.1.1.1",
        "src_port": None, "dst_port": None, "length": 60, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    icmp = frame[34:42]
    assert icmp[0] == 8  # echo request placeholder
    assert icmp[1] == 0


def test_never_fabricates_payload_content_all_zero():
    packet = {
        "protocol": "tcp", "src_addr": "10.0.0.1", "src_port": 1,
        "dst_addr": "10.0.0.2", "dst_port": 2, "length": 9000, "flags": "SYN",
    }
    frame, orig_len = synth.synthesize_frame(packet)
    header_stack_len = 14 + 20 + 20
    payload = frame[header_stack_len:]
    assert set(payload) <= {0}
    assert orig_len == 9000
    assert len(frame) == 9000


def test_implausibly_small_length_truncates_headers_not_fabricates():
    packet = {
        "protocol": "tcp", "src_addr": "10.0.0.1", "src_port": 1,
        "dst_addr": "10.0.0.2", "dst_port": 2, "length": 5, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert orig_len == 5
    assert len(frame) == 5  # incl_len never exceeds orig_len


def test_zero_length_yields_empty_frame():
    packet = {
        "protocol": "tcp", "src_addr": "10.0.0.1", "src_port": 1,
        "dst_addr": "10.0.0.2", "dst_port": 2, "length": 0, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert frame == b""
    assert orig_len == 0


def test_non_ipv4_address_falls_back_to_ethernet_only():
    packet = {
        "protocol": "tcp", "src_addr": "fe80::1", "dst_addr": "fe80::2",
        "src_port": 1, "dst_port": 2, "length": 100, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert len(frame) == 100
    eth = frame[0:14]
    assert eth[12:14] == struct.pack("!H", synth.ETHERTYPE_IPV6)
    # No fabricated IPv6 header -- everything past the Ethernet header is zero.
    assert set(frame[14:]) <= {0}


def test_unknown_protocol_gets_ip_header_only():
    packet = {
        "protocol": "gre", "src_addr": "10.0.0.1", "dst_addr": "10.0.0.2",
        "src_port": None, "dst_port": None, "length": 100, "flags": None,
    }
    frame, orig_len = synth.synthesize_frame(packet)
    assert len(frame) == 100
    ip = frame[14:34]
    assert _checksum_ok(ip)
    assert set(frame[34:]) <= {0}


def test_tcp_flag_parsing_all_bits():
    packet = {
        "protocol": "tcp", "src_addr": "10.0.0.1", "src_port": 1,
        "dst_addr": "10.0.0.2", "dst_port": 2, "length": 54,
        "flags": "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR",
    }
    frame, _ = synth.synthesize_frame(packet)
    flags_byte = frame[34 + 13]
    assert flags_byte == 0xFF

from __future__ import annotations

import io
import struct

import pytest

from netaudit.pcap import format as pcapfmt


# --- Writer: byte-exact against an independently-derived expected value ----


def test_global_header_bytes_are_exact():
    # snaplen=65535 (0xffff), linktype=1 (EN10MB). Derived by hand from the
    # libpcap spec, not by re-calling the writer under test.
    expected = bytes.fromhex(
        "d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000"
    )
    assert pcapfmt.write_global_header(snaplen=65535, linktype=1) == expected
    assert len(expected) == 24


def test_packet_record_bytes_are_exact():
    data = b"\xaa\xbb\xcc"
    rec = pcapfmt.write_packet_record(ts_sec=1, ts_usec=2, incl_len=3, orig_len=10, data=data)
    expected = bytes.fromhex("01000000" "02000000" "03000000" "0a000000") + data
    assert rec == expected


# --- Round trip: write then read with our own reader -----------------------


def test_round_trip_single_packet():
    buf = io.BytesIO()
    buf.write(pcapfmt.write_global_header(snaplen=65535, linktype=1))
    data = b"hello world!"
    buf.write(pcapfmt.write_packet_record(1721000000, 123456, len(data), len(data), data))
    buf.seek(0)

    header = pcapfmt.read_global_header(buf)
    assert header.snaplen == 65535
    assert header.network == 1
    assert header.byte_order == "<"
    assert header.nanosecond is False

    records = list(pcapfmt.read_pcap_records(buf, header))
    assert len(records) == 1
    r = records[0]
    assert r.ts_sec == 1721000000
    assert r.ts_frac == 123456
    assert r.incl_len == len(data)
    assert r.orig_len == len(data)
    assert r.data == data


def test_round_trip_many_packets_every_field_survives():
    buf = io.BytesIO()
    buf.write(pcapfmt.write_global_header())
    expected = []
    for i in range(50):
        data = bytes([i % 256]) * (i + 1)
        buf.write(pcapfmt.write_packet_record(1000 + i, i * 7, len(data), len(data) + i, data))
        expected.append((1000 + i, i * 7, len(data), len(data) + i, data))
    buf.seek(0)

    header = pcapfmt.read_global_header(buf)
    records = list(pcapfmt.read_pcap_records(buf, header))
    assert len(records) == 50
    for r, (ts_sec, ts_usec, incl_len, orig_len, data) in zip(records, expected):
        assert (r.ts_sec, r.ts_frac, r.incl_len, r.orig_len, r.data) == (ts_sec, ts_usec, incl_len, orig_len, data)


# --- Both endiannesses and the nanosecond magic -----------------------------


def _build_header(magic: int, byte_order: str, snaplen=65535, linktype=1) -> bytes:
    return struct.pack(byte_order + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)


def _build_record(byte_order: str, ts_sec, ts_frac, data: bytes) -> bytes:
    return struct.pack(byte_order + "IIII", ts_sec, ts_frac, len(data), len(data)) + data


@pytest.mark.parametrize(
    "magic,byte_order,nanosecond",
    [
        # The magic is always packed from the canonical *_LE constant; it's
        # `byte_order` that determines the actual raw bytes on the wire.
        # Packing 0xa1b2c3d4 as "<" gives the standard little-endian file
        # (raw bytes d4 c3 b2 a1); packing the *same* logical value as ">"
        # gives what a real big-endian writer emits (raw bytes a1 b2 c3 d4)
        # -- which is exactly the case the MAGIC_*_SWAPPED constants name
        # (a little-endian *reader* misinterpreting those same BE bytes
        # would compute 0xd4c3b2a1).
        (pcapfmt.MAGIC_USEC_LE, "<", False),
        (pcapfmt.MAGIC_USEC_LE, ">", False),
        (pcapfmt.MAGIC_NSEC_LE, "<", True),
        (pcapfmt.MAGIC_NSEC_LE, ">", True),
    ],
)
def test_reads_all_four_magic_variants(magic, byte_order, nanosecond):
    buf = io.BytesIO()
    buf.write(_build_header(magic, byte_order))
    data = b"payload-bytes"
    buf.write(_build_record(byte_order, 5, 999, data))
    buf.seek(0)

    header = pcapfmt.read_global_header(buf)
    assert header.nanosecond is nanosecond
    assert header.byte_order == byte_order

    records = list(pcapfmt.read_pcap_records(buf, header))
    assert len(records) == 1
    assert records[0].data == data
    assert records[0].nanosecond is nanosecond


# --- Malformed input: bounds checks -----------------------------------------


def test_empty_file_raises():
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_global_header(io.BytesIO(b""))


def test_truncated_global_header_raises():
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_global_header(io.BytesIO(b"\xd4\xc3\xb2\xa1\x02\x00"))


def test_bad_magic_raises():
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_global_header(io.BytesIO(b"NOTAPCAP" + b"\x00" * 16))


def test_implausible_snaplen_raises():
    buf = io.BytesIO(_build_header(pcapfmt.MAGIC_USEC_LE, "<", snaplen=0xFFFFFFF0))
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_global_header(buf)


def test_huge_incl_len_is_rejected_not_attempted():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    # Record header claiming a 4 GiB incl_len, no actual data behind it.
    buf.write(struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    with pytest.raises(pcapfmt.PcapError):
        list(pcapfmt.read_pcap_records(buf, header))


def test_incl_len_exceeding_remaining_file_bytes_is_rejected():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    buf.write(struct.pack("<IIII", 1, 0, 1000, 1000))  # claims 1000 bytes
    buf.write(b"only ten!!")  # but only supplies 10
    total_size = buf.tell()
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    with pytest.raises(pcapfmt.PcapError):
        list(pcapfmt.read_pcap_records(buf, header, file_size=total_size))


def test_truncated_record_header_raises():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    buf.write(b"\x01\x02\x03")  # 3 bytes, not a full 16-byte record header
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    with pytest.raises(pcapfmt.PcapError):
        list(pcapfmt.read_pcap_records(buf, header))


def test_truncated_packet_data_raises():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    buf.write(struct.pack("<IIII", 1, 0, 10, 10))
    buf.write(b"short")  # only 5 of the promised 10 bytes
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    with pytest.raises(pcapfmt.PcapError):
        list(pcapfmt.read_pcap_records(buf, header))


def test_zero_length_record_is_accepted():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    buf.write(struct.pack("<IIII", 1, 0, 0, 0))
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    records = list(pcapfmt.read_pcap_records(buf, header))
    assert len(records) == 1
    assert records[0].data == b""


def test_max_packets_cap_stops_reading():
    buf = io.BytesIO()
    buf.write(_build_header(pcapfmt.MAGIC_USEC_LE, "<"))
    for i in range(10):
        buf.write(pcapfmt.write_packet_record(i, 0, 0, 0, b""))
    buf.seek(0)
    header = pcapfmt.read_global_header(buf)
    records = list(pcapfmt.read_pcap_records(buf, header, max_packets=3))
    assert len(records) == 3


# --- pcapng: SHB + IDB + EPB round trip --------------------------------------


def _pcapng_block(btype: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack("<II", btype, total_len) + body + struct.pack("<I", total_len)


def _build_pcapng(packets: list[bytes], linktype=1, snaplen=262144) -> bytes:
    shb_body = struct.pack("<IHHq", pcapfmt.PCAPNG_BOM, 1, 0, -1)
    shb = _pcapng_block(pcapfmt.BT_SECTION_HEADER, shb_body)

    idb_body = struct.pack("<HHI", linktype, 0, snaplen)
    idb = _pcapng_block(pcapfmt.BT_INTERFACE_DESCRIPTION, idb_body)

    out = shb + idb
    for data in packets:
        padded_len = (len(data) + 3) & ~3
        padded_data = data + b"\x00" * (padded_len - len(data))
        epb_body = struct.pack("<IIIII", 0, 0, 1000, len(data), len(data)) + padded_data
        out += _pcapng_block(pcapfmt.BT_ENHANCED_PACKET, epb_body)
    return out


def test_pcapng_round_trip():
    data1 = b"first-packet-bytes"
    data2 = b"second"
    raw = _build_pcapng([data1, data2], linktype=1, snaplen=65535)
    buf = io.BytesIO(raw)

    meta, records = pcapfmt.read_pcapng(buf, file_size=len(raw))
    assert meta.linktype == 1
    assert meta.linktype_name == "EN10MB"
    assert meta.snaplen == 65535

    records = list(records)
    assert len(records) == 2
    assert records[0].data == data1
    assert records[1].data == data2


def test_pcapng_unknown_block_is_skipped_not_fatal():
    data1 = b"kept-packet"
    # Splice an "unknown" block (a fake type, e.g. Interface Statistics 0x5)
    # in between the IDB and the first EPB. Built manually (not sliced out
    # of _build_pcapng's output) so there's no ambiguity about offsets.
    unknown = _pcapng_block(0x00000005, b"\x00" * 8)
    shb_body = struct.pack("<IHHq", pcapfmt.PCAPNG_BOM, 1, 0, -1)
    shb = _pcapng_block(pcapfmt.BT_SECTION_HEADER, shb_body)
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = _pcapng_block(pcapfmt.BT_INTERFACE_DESCRIPTION, idb_body)
    padded = data1 + b"\x00" * ((4 - len(data1) % 4) % 4)
    epb_body = struct.pack("<IIIII", 0, 0, 1000, len(data1), len(data1)) + padded
    epb = _pcapng_block(pcapfmt.BT_ENHANCED_PACKET, epb_body)
    raw2 = shb + idb + unknown + epb

    buf = io.BytesIO(raw2)
    meta, records = pcapfmt.read_pcapng(buf, file_size=len(raw2))
    records = list(records)
    assert len(records) == 1
    assert records[0].data == data1


def test_pcapng_bad_magic_raises():
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_pcapng(io.BytesIO(b"not-a-pcapng-file"))


def test_pcapng_block_length_mismatch_raises():
    shb_body = struct.pack("<IHHq", pcapfmt.PCAPNG_BOM, 1, 0, -1)
    total_len = 12 + len(shb_body)
    bad = struct.pack("<II", pcapfmt.BT_SECTION_HEADER, total_len) + shb_body + struct.pack("<I", total_len + 4)
    with pytest.raises(pcapfmt.PcapError):
        list(pcapfmt.read_pcapng(io.BytesIO(bad), file_size=len(bad))[1])


def test_pcapng_huge_block_length_rejected():
    body = struct.pack("<IHHq", pcapfmt.PCAPNG_BOM, 1, 0, -1)
    bad = struct.pack("<II", pcapfmt.BT_SECTION_HEADER, 0x7FFFFFFF) + body
    with pytest.raises(pcapfmt.PcapError):
        pcapfmt.read_pcapng(io.BytesIO(bad), file_size=len(bad))

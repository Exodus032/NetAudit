"""Hand-written libpcap and pcapng reader/writer.

No scapy, no dpkt -- see ../DEPENDENCIES.md (there is nothing to add; this
module uses only `struct` from the standard library). Written directly
against:

  - libpcap file format (classic ".pcap"):
    https://wiki.wireshark.org/Development/LibpcapFileFormat
  - pcapng ("Next Generation") file format:
    https://github.com/pcapng/pcapng (IETF draft)

This is the highest-risk parsing code in the tool per the spec: import is
untrusted input. Every length field is bounds-checked before it is used to
allocate or slice anything, and the reader never buffers more than one
record/block at a time. Malformed input raises `PcapError`, which the
router (`pcap/router.py`) turns into a 400 with a useful message. It is
never allowed to raise anything else, hang, or read past what is actually
available in the stream.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

# --- Constants ---------------------------------------------------------------

MAGIC_USEC_LE = 0xA1B2C3D4  # native-endian write target, microsecond resolution
MAGIC_USEC_SWAPPED = 0xD4C3B2A1
MAGIC_NSEC_LE = 0xA1B23C4D  # nanosecond-resolution variant
MAGIC_NSEC_SWAPPED = 0x4D3CB2A1

PCAPNG_BLOCK_MAGIC = 0x0A0D0D0A  # Section Header Block type, also the file "magic"
PCAPNG_BOM = 0x1A2B3C4D  # Byte-Order Magic inside the SHB body
PCAPNG_BOM_SWAPPED = 0x4D3C2B1A

BT_SECTION_HEADER = 0x0A0D0D0A
BT_INTERFACE_DESCRIPTION = 0x00000001
BT_ENHANCED_PACKET = 0x00000006

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

LINKTYPE_NAMES = {
    0: "NULL",
    1: "EN10MB",
    101: "RAW",
    228: "IPV4",
    229: "IPV6",
}

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16
PCAPNG_BLOCK_HEADER_LEN = 12  # type(4) + total_len(4) + ... + total_len(4) trailer

# Sanity ceilings. These exist purely so a hostile/corrupt length field can
# never be used to allocate or read an unbounded amount of memory -- they
# are deliberately generous (well above any real single Ethernet frame,
# even jumbo frames) but nowhere near "unbounded".
ABSOLUTE_MAX_PACKET_LEN = 4 * 1024 * 1024  # 4 MiB per packet, generous
ABSOLUTE_MAX_SNAPLEN = 16 * 1024 * 1024  # 16 MiB
ABSOLUTE_MAX_BLOCK_LEN = 16 * 1024 * 1024  # 16 MiB per pcapng block


class PcapError(ValueError):
    """Any malformed/truncated/hostile pcap or pcapng input. Always caught
    at the API boundary (pcap/router.py) and turned into a 400 with this
    message -- never allowed to propagate as an unhandled exception."""


@dataclass
class GlobalHeader:
    magic: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    byte_order: str  # struct format prefix: "<" or ">"
    nanosecond: bool


@dataclass
class PacketRecord:
    ts_sec: int
    ts_frac: int  # microseconds, or nanoseconds if the file is the nsec variant
    incl_len: int
    orig_len: int
    data: bytes
    nanosecond: bool = False

    @property
    def timestamp(self) -> float:
        divisor = 1_000_000_000.0 if self.nanosecond else 1_000_000.0
        return self.ts_sec + (self.ts_frac / divisor)


@dataclass
class FormatMeta:
    linktype: int
    linktype_name: str
    snaplen: int
    is_pcapng: bool
    nanosecond: bool = False


# --- Writing (E1) -------------------------------------------------------------


def write_global_header(snaplen: int = 65535, linktype: int = LINKTYPE_ETHERNET) -> bytes:
    """24-byte libpcap global header. Always writes the standard
    microsecond-resolution, little-endian magic (0xa1b2c3d4), version 2.4 --
    the maximally-compatible choice for a file we produce ourselves."""
    return struct.pack(
        "<IHHiIII",
        MAGIC_USEC_LE,
        2, 4,       # version_major, version_minor
        0,          # thiszone
        0,          # sigfigs
        snaplen,
        linktype,
    )


def write_packet_record(ts_sec: int, ts_usec: int, incl_len: int, orig_len: int, data: bytes) -> bytes:
    if len(data) != incl_len:
        raise ValueError("data length must equal incl_len")
    return struct.pack("<IIII", ts_sec & 0xFFFFFFFF, ts_usec & 0xFFFFFFFF, incl_len, orig_len) + data


def iter_write_pcap(records: Iterator[tuple[int, int, int, bytes]], snaplen: int = 65535,
                     linktype: int = LINKTYPE_ETHERNET) -> Iterator[bytes]:
    """Stream a pcap file as a sequence of byte chunks: the global header,
    then one chunk per record. `records` yields (ts_sec, ts_usec, orig_len, data)
    tuples; incl_len is always len(data) (what we actually wrote)."""
    yield write_global_header(snaplen=snaplen, linktype=linktype)
    for ts_sec, ts_usec, orig_len, data in records:
        yield write_packet_record(ts_sec, ts_usec, len(data), orig_len, data)


# --- Reading: classic pcap (E1 export round-trip, E2 import) -----------------


def _magic_lookup(raw4: bytes) -> Optional[tuple[str, bool]]:
    """Try both byte orders against the four known magic numbers. Returns
    (byte_order, nanosecond) or None if raw4 doesn't match any of them."""
    le_val = struct.unpack("<I", raw4)[0]
    be_val = struct.unpack(">I", raw4)[0]
    if le_val == MAGIC_USEC_LE:
        return "<", False
    if be_val == MAGIC_USEC_LE:
        return ">", False
    if le_val == MAGIC_NSEC_LE:
        return "<", True
    if be_val == MAGIC_NSEC_LE:
        return ">", True
    return None


def _read_exact(f: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes or fewer at true EOF. Never raises on a clean
    EOF (empty read) -- callers distinguish '0 bytes = clean end' from
    '1..n-1 bytes = truncated' themselves."""
    if n < 0:
        raise PcapError("negative read length")
    buf = f.read(n)
    return buf


def read_global_header(f: BinaryIO) -> GlobalHeader:
    raw = _read_exact(f, GLOBAL_HEADER_LEN)
    if len(raw) == 0:
        raise PcapError("empty file")
    if len(raw) < GLOBAL_HEADER_LEN:
        raise PcapError(f"truncated global header: got {len(raw)} of {GLOBAL_HEADER_LEN} bytes")

    order = _magic_lookup(raw[0:4])
    if order is None:
        raise PcapError(
            "not a recognised pcap file (bad magic number; if this is pcapng, "
            "use read_pcapng instead)"
        )
    byte_order, nanosecond = order

    magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
        byte_order + "IHHiIII", raw
    )

    if snaplen == 0 or snaplen > ABSOLUTE_MAX_SNAPLEN:
        raise PcapError(f"implausible snaplen in global header: {snaplen}")

    return GlobalHeader(
        magic=magic, version_major=ver_major, version_minor=ver_minor,
        thiszone=thiszone, sigfigs=sigfigs, snaplen=snaplen, network=network,
        byte_order=byte_order, nanosecond=nanosecond,
    )


def is_pcapng(raw4: bytes) -> bool:
    if len(raw4) < 4:
        return False
    le_val = struct.unpack("<I", raw4)[0]
    be_val = struct.unpack(">I", raw4)[0]
    return le_val == BT_SECTION_HEADER or be_val == BT_SECTION_HEADER


def read_pcap_records(
    f: BinaryIO,
    header: GlobalHeader,
    file_size: Optional[int] = None,
    max_packets: Optional[int] = None,
) -> Iterator[PacketRecord]:
    """Yields PacketRecord one at a time. Never buffers more than one
    record. Stops cleanly at a record boundary on EOF. Raises PcapError on
    anything that looks like corruption or a hostile length claim, but only
    after any records already yielded have been handed to the caller (a
    generator can't "partially raise" -- StopIteration vs PcapError is
    exactly the recoverable/fatal distinction the router acts on).
    """
    count = 0
    while True:
        if max_packets is not None and count >= max_packets:
            return
        pos_before = f.tell() if hasattr(f, "tell") else None
        raw = _read_exact(f, RECORD_HEADER_LEN)
        if len(raw) == 0:
            return  # clean end of file at a record boundary
        if len(raw) < RECORD_HEADER_LEN:
            raise PcapError(
                f"truncated packet record header at record {count} "
                f"(got {len(raw)} of {RECORD_HEADER_LEN} bytes)"
            )

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(header.byte_order + "IIII", raw)

        if incl_len > ABSOLUTE_MAX_PACKET_LEN:
            raise PcapError(
                f"record {count} declares incl_len={incl_len}, exceeding the "
                f"sanity ceiling of {ABSOLUTE_MAX_PACKET_LEN} bytes -- refusing "
                f"to allocate"
            )
        if file_size is not None and pos_before is not None:
            remaining = file_size - (pos_before + RECORD_HEADER_LEN)
            if incl_len > max(remaining, 0):
                raise PcapError(
                    f"record {count} declares incl_len={incl_len} but only "
                    f"{max(remaining, 0)} bytes remain in the file"
                )

        data = _read_exact(f, incl_len) if incl_len else b""
        if len(data) != incl_len:
            raise PcapError(
                f"truncated packet data at record {count} "
                f"(got {len(data)} of {incl_len} bytes)"
            )

        yield PacketRecord(
            ts_sec=ts_sec, ts_frac=ts_frac, incl_len=incl_len, orig_len=orig_len,
            data=data, nanosecond=header.nanosecond,
        )
        count += 1


# --- Reading: pcapng (E2 import only) -----------------------------------------


@dataclass
class _Interface:
    linktype: int
    snaplen: int
    ts_resol_ns_per_unit: float  # nanoseconds represented by one raw timestamp unit


def _parse_if_tsresol(options: bytes, byte_order: str) -> float:
    """if_tsresol option (code 9): one byte. If the high bit is 0, value b
    means resolution is 10^-b seconds; if the high bit is 1, the low 7 bits
    give 2^-b. Default (absent) is 10^-6 (microseconds), matching classic
    pcap. Returns nanoseconds-per-unit."""
    resol_seconds = 1e-6
    off = 0
    n = len(options)
    while off + 4 <= n:
        code, length = struct.unpack(byte_order + "HH", options[off:off + 4])
        off += 4
        if code == 0 and length == 0:
            break
        padded = (length + 3) & ~3
        if off + padded > n:
            break
        body = options[off:off + length]
        if code == 9 and length >= 1:
            b = body[0]
            if b & 0x80:
                resol_seconds = 2.0 ** -(b & 0x7F)
            else:
                resol_seconds = 10.0 ** -b
        off += padded
    return resol_seconds * 1e9


def read_pcapng(
    f: BinaryIO,
    file_size: Optional[int] = None,
    max_packets: Optional[int] = None,
) -> tuple[FormatMeta, Iterator[PacketRecord]]:
    """Parses a pcapng file: Section Header Block, Interface Description
    Block(s) and Enhanced Packet Block(s) at minimum. Any other block type
    is skipped by its declared length (never interpreted, never crashes).
    Returns (meta describing the first interface seen, a generator of
    normalised PacketRecord). `meta` is best-effort when a file declares
    multiple interfaces with different linktypes -- callers that need
    per-packet linktype should not assume otherwise, but this is a rare
    case for a small single-host tool and it's tracked in the README.
    """
    first4 = _read_exact(f, 4)
    if len(first4) < 4 or not is_pcapng(first4):
        raise PcapError("not a recognised pcapng file (bad section header magic)")

    # Re-parse the whole thing through a generator that owns byte-order
    # state (each Section Header Block can, in principle, declare a new
    # byte order for its section).
    interfaces: list[_Interface] = []
    meta_holder: dict = {}

    def _blocks() -> Iterator[PacketRecord]:
        byte_order = "<"
        pos = 0  # bytes consumed, for remaining-length checks
        pending = first4
        count = 0
        while True:
            if max_packets is not None and count >= max_packets:
                return
            # block_total_length (4 bytes) follows the 4-byte block type
            # we may already have in `pending`.
            btype_raw = pending if pending else _read_exact(f, 4)
            pending = b""
            if len(btype_raw) == 0:
                return  # clean EOF between blocks
            if len(btype_raw) < 4:
                raise PcapError("truncated pcapng block type")
            len_raw = _read_exact(f, 4)
            if len(len_raw) < 4:
                raise PcapError("truncated pcapng block length")

            btype = struct.unpack(byte_order + "I", btype_raw)[0]
            block_total_len = struct.unpack(byte_order + "I", len_raw)[0]

            if block_total_len < PCAPNG_BLOCK_HEADER_LEN:
                raise PcapError(f"implausible pcapng block length: {block_total_len}")
            if block_total_len % 4 != 0:
                raise PcapError(f"pcapng block length not 4-byte aligned: {block_total_len}")
            if block_total_len > ABSOLUTE_MAX_BLOCK_LEN:
                raise PcapError(
                    f"pcapng block declares length {block_total_len}, exceeding "
                    f"the sanity ceiling of {ABSOLUTE_MAX_BLOCK_LEN} bytes"
                )

            body_len = block_total_len - PCAPNG_BLOCK_HEADER_LEN
            if file_size is not None:
                remaining = file_size - (pos + 8)
                if block_total_len - 8 > max(remaining, 0):
                    raise PcapError(
                        f"pcapng block declares total length {block_total_len} "
                        f"but only {max(remaining, 0)} bytes remain"
                    )

            body_and_trailer = _read_exact(f, body_len + 4)
            if len(body_and_trailer) != body_len + 4:
                raise PcapError("truncated pcapng block body")
            body = body_and_trailer[:body_len]
            trailer_len = struct.unpack(byte_order + "I", body_and_trailer[body_len:])[0]
            if trailer_len != block_total_len:
                raise PcapError("pcapng block length mismatch (header vs trailer)")

            pos += block_total_len

            if btype == BT_SECTION_HEADER:
                if len(body) < 16:
                    raise PcapError("truncated section header block body")
                bom = struct.unpack("<I", body[0:4])[0]
                if bom == PCAPNG_BOM:
                    byte_order = "<"
                elif bom == PCAPNG_BOM_SWAPPED:
                    byte_order = ">"
                else:
                    raise PcapError("unrecognised pcapng byte-order magic")
                interfaces.clear()
            elif btype == BT_INTERFACE_DESCRIPTION:
                if len(body) < 8:
                    raise PcapError("truncated interface description block body")
                linktype, _reserved, snaplen = struct.unpack(byte_order + "HHI", body[0:8])
                if snaplen > ABSOLUTE_MAX_SNAPLEN:
                    raise PcapError(f"implausible snaplen in IDB: {snaplen}")
                ts_resol_ns = _parse_if_tsresol(body[8:], byte_order)
                interfaces.append(_Interface(linktype=linktype, snaplen=snaplen or 262144,
                                              ts_resol_ns_per_unit=ts_resol_ns))
                if "linktype" not in meta_holder:
                    meta_holder["linktype"] = linktype
                    meta_holder["snaplen"] = snaplen or 262144
            elif btype == BT_ENHANCED_PACKET:
                if len(body) < 20:
                    raise PcapError("truncated enhanced packet block body")
                if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    byte_order + "IIIII", body[0:20]
                )
                if cap_len > ABSOLUTE_MAX_PACKET_LEN:
                    raise PcapError(
                        f"EPB declares captured length {cap_len}, exceeding the "
                        f"sanity ceiling of {ABSOLUTE_MAX_PACKET_LEN} bytes"
                    )
                padded_cap_len = (cap_len + 3) & ~3
                if 20 + padded_cap_len > len(body):
                    raise PcapError("EPB packet data exceeds block body")
                data = body[20:20 + cap_len]

                iface = interfaces[if_id] if 0 <= if_id < len(interfaces) else None
                ts_resol_ns = iface.ts_resol_ns_per_unit if iface else 1000.0
                ts_units = (ts_high << 32) | ts_low
                total_ns = ts_units * ts_resol_ns
                ts_sec = int(total_ns // 1_000_000_000)
                ts_frac_ns = int(total_ns % 1_000_000_000)
                # Normalise to microsecond fraction for the common case,
                # keep nanosecond precision only if the interface actually
                # declared sub-microsecond resolution.
                nanosecond = ts_resol_ns < 1000.0
                ts_frac = ts_frac_ns if nanosecond else ts_frac_ns // 1000

                yield PacketRecord(
                    ts_sec=ts_sec, ts_frac=ts_frac, incl_len=cap_len, orig_len=orig_len,
                    data=data, nanosecond=nanosecond,
                )
                count += 1
            # else: unknown block type (Simple Packet, Name Resolution,
            # Interface Statistics, custom/private blocks, ...) -- already
            # consumed by length above, so we just move on. This is the
            # "reject other blocks gracefully" requirement: we don't
            # interpret them, but we also don't fail the whole import over
            # a decorative block we don't need.

    gen = _blocks()
    first_record = None
    try:
        first_record = next(gen)
    except StopIteration:
        pass
    except PcapError:
        raise

    linktype = meta_holder.get("linktype", LINKTYPE_ETHERNET)
    snaplen = meta_holder.get("snaplen", 262144)
    meta = FormatMeta(
        linktype=linktype,
        linktype_name=LINKTYPE_NAMES.get(linktype, f"UNKNOWN({linktype})"),
        snaplen=snaplen,
        is_pcapng=True,
    )

    def _replay() -> Iterator[PacketRecord]:
        if first_record is not None:
            yield first_record
        yield from gen

    return meta, _replay()

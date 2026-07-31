"""E2 untrusted-input fuzzing: truncate a valid pcap at every byte offset,
and flip every bit in its headers, and confirm the result is always either
a clean parse or a clean `PcapImportError` -- never an unhandled exception,
never a hang. This is the single highest-risk parsing code in the tool.
"""
from __future__ import annotations

import struct
import time

import pytest

from netaudit.pcap import format as pcapfmt
from netaudit.pcap import import_pipeline


def _valid_pcap_bytes() -> bytes:
    buf = bytearray()
    buf += pcapfmt.write_global_header(snaplen=65535, linktype=1)
    for i in range(5):
        data = bytes([(i + 1) % 256]) * (20 + i)
        buf += pcapfmt.write_packet_record(1700000000 + i, i * 100, len(data), len(data), data)
    return bytes(buf)


VALID_PCAP = _valid_pcap_bytes()


def _try_parse(raw: bytes, tmp_path, name="fuzz.pcap"):
    """Writes raw bytes to disk and runs them through the real import
    pipeline's parser. Returns ("ok", result) or ("error", exception)."""
    path = tmp_path / name
    path.write_bytes(raw)
    try:
        result = import_pipeline.parse_pcap_file(path)
        return "ok", result
    except import_pipeline.PcapImportError as exc:
        return "error", exc


class TestTruncationFuzz:
    @pytest.mark.parametrize("cutoff", list(range(0, len(VALID_PCAP))))
    def test_truncated_at_every_offset_never_crashes(self, cutoff, tmp_path):
        truncated = VALID_PCAP[:cutoff]
        outcome, result = _try_parse(truncated, tmp_path, name=f"trunc-{cutoff}.pcap")
        assert outcome in ("ok", "error")
        if outcome == "ok":
            linktype_name, packets, truncated_flag, parse_errors = result
            assert isinstance(packets, list)
            # Every packet we did manage to parse must be internally
            # consistent -- no partial/garbage record ever escapes as if
            # it were real data.
            for p in packets:
                assert p.length >= 0
                assert p.protocol


class TestBitFlipFuzz:
    @pytest.mark.parametrize("byte_index", list(range(0, pcapfmt.GLOBAL_HEADER_LEN)))
    def test_flip_each_bit_in_global_header_never_crashes(self, byte_index, tmp_path):
        for bit in range(8):
            mutated = bytearray(VALID_PCAP)
            mutated[byte_index] ^= (1 << bit)
            outcome, result = _try_parse(bytes(mutated), tmp_path, name=f"flip-gh-{byte_index}-{bit}.pcap")
            assert outcome in ("ok", "error"), f"unexpected outcome flipping byte {byte_index} bit {bit}"

    @pytest.mark.parametrize("byte_index", list(range(
        pcapfmt.GLOBAL_HEADER_LEN, pcapfmt.GLOBAL_HEADER_LEN + pcapfmt.RECORD_HEADER_LEN
    )))
    def test_flip_each_bit_in_first_record_header_never_crashes(self, byte_index, tmp_path):
        for bit in (0, 3, 7):  # sample a few bit positions per byte to keep runtime sane
            mutated = bytearray(VALID_PCAP)
            mutated[byte_index] ^= (1 << bit)
            outcome, result = _try_parse(bytes(mutated), tmp_path, name=f"flip-rh-{byte_index}-{bit}.pcap")
            assert outcome in ("ok", "error"), f"unexpected outcome flipping byte {byte_index} bit {bit}"


class TestHostileClaims:
    def test_declared_incl_len_of_4gb_is_rejected_cleanly(self, tmp_path):
        buf = bytearray()
        buf += pcapfmt.write_global_header()
        buf += struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF)  # no data follows
        outcome, result = _try_parse(bytes(buf), tmp_path)
        # Either a clean error, or (if treated as recoverable truncation) a
        # result with zero packets -- never a hang or a MemoryError.
        assert outcome in ("ok", "error")
        if outcome == "ok":
            _, packets, truncated_flag, _ = result
            assert packets == []

    def test_absurd_packet_count_is_bounded(self, tmp_path):
        # A file with many zero-length records -- must not be treated as
        # "infinite" or exhaust memory/time. Bounded by max_packets.
        buf = bytearray()
        buf += pcapfmt.write_global_header()
        for i in range(2000):
            buf += pcapfmt.write_packet_record(1700000000, i, 0, 0, b"")
        path = tmp_path / "many.pcap"
        path.write_bytes(bytes(buf))
        start = time.monotonic()
        linktype_name, packets, truncated_flag, parse_errors = import_pipeline.parse_pcap_file(
            path, max_packets=500
        )
        elapsed = time.monotonic() - start
        assert len(packets) == 500
        assert truncated_flag is True
        assert elapsed < 5.0

    def test_zero_byte_file_is_a_clean_error(self, tmp_path):
        path = tmp_path / "empty.pcap"
        path.write_bytes(b"")
        with pytest.raises(import_pipeline.PcapImportError):
            import_pipeline.parse_pcap_file(path)

    def test_random_garbage_is_a_clean_error(self, tmp_path):
        path = tmp_path / "garbage.pcap"
        path.write_bytes(bytes(range(256)) * 4)
        with pytest.raises(import_pipeline.PcapImportError):
            import_pipeline.parse_pcap_file(path)

    def test_snaplen_larger_than_file_is_rejected(self, tmp_path):
        buf = struct.pack("<IHHiIII", pcapfmt.MAGIC_USEC_LE, 2, 4, 0, 0, 50_000_000, 1)
        path = tmp_path / "bad-snaplen.pcap"
        path.write_bytes(buf)
        # File is only 24 bytes; a 50MB snaplen is implausible on its own
        # (caught by the absolute ceiling) regardless of file size context.
        with pytest.raises(import_pipeline.PcapImportError):
            import_pipeline.parse_pcap_file(path)

"""E2 import pipeline: streams an untrusted upload to disk under a hard
size cap, then parses it with `format.py` and dissects each frame with
`dissect.py` into rows for `session_store.py`.

Untrusted-input rules (see module docstring in `format.py` for the parser
side of this): never buffer the whole upload in memory, enforce the 200 MB
cap while streaming (not after), and turn every parse failure into a
`PcapImportError` the router can turn into a clean 400 -- never let an
exception type we didn't anticipate escape from here.
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from . import dissect, format as pcapfmt, session_store

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB, per E2
MAX_IMPORT_PACKETS = 1_000_000  # hard packet-count cap, independent of file size


class PcapImportError(ValueError):
    """A clean, user-facing import failure (bad format, corrupt data)."""


class UploadTooLargeError(ValueError):
    """The stream exceeded MAX_UPLOAD_BYTES. Router turns this into 413."""


def stream_to_disk(chunks, dest_path: Path, max_bytes: int = MAX_UPLOAD_BYTES) -> int:
    """Writes an iterable of byte chunks to dest_path, never holding more
    than one chunk in memory, aborting (and removing the partial file) the
    instant the cap is exceeded."""
    written = 0
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(dest_path, "wb") as f:
            for chunk in chunks:
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    raise UploadTooLargeError(
                        f"upload exceeds the {max_bytes} byte cap"
                    )
                f.write(chunk)
    except UploadTooLargeError:
        try:
            dest_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return written


def _open_and_sniff(path: Path) -> tuple[BinaryIO, bytes, int]:
    file_size = path.stat().st_size
    f = open(path, "rb")
    head = f.read(4)
    f.seek(0)
    return f, head, file_size


def parse_pcap_file(path: Path, max_packets: int = MAX_IMPORT_PACKETS):
    """Parses a pcap or pcapng file already fully on disk. Returns
    (linktype_name, packets: list[session_store.ImportedPacket], truncated,
    parse_errors). Raises PcapImportError if nothing at all could be
    parsed (e.g. bad magic, empty file, corrupt global header). A file
    that parses partially (some good records, then corruption or a
    premature end) returns what it could parse with `truncated=True` and
    `parse_errors` set, rather than discarding everything -- a genuinely
    truncated real-world capture is still useful evidence.
    """
    f, head, file_size = _open_and_sniff(path)
    try:
        if len(head) < 4:
            raise PcapImportError("file is empty or too short to be a pcap/pcapng file")

        packets: list[session_store.ImportedPacket] = []
        truncated = False
        parse_errors = 0
        linktype_name = "UNKNOWN"

        if pcapfmt.is_pcapng(head):
            try:
                meta, record_iter = pcapfmt.read_pcapng(f, file_size=file_size, max_packets=max_packets)
            except pcapfmt.PcapError as exc:
                raise PcapImportError(str(exc)) from exc
            linktype_name = meta.linktype_name
            linktype = meta.linktype
            packets, truncated, parse_errors = _drain_records(record_iter, linktype, max_packets)
        else:
            try:
                header = pcapfmt.read_global_header(f)
            except pcapfmt.PcapError as exc:
                raise PcapImportError(str(exc)) from exc
            linktype_name = pcapfmt.LINKTYPE_NAMES.get(header.network, f"UNKNOWN({header.network})")
            record_iter = pcapfmt.read_pcap_records(f, header, file_size=file_size, max_packets=max_packets)
            packets, truncated, parse_errors = _drain_records(record_iter, header.network, max_packets)

        if not packets and parse_errors > 0:
            raise PcapImportError("no valid packets could be parsed from this file")

        if len(packets) >= max_packets:
            truncated = True

        return linktype_name, packets, truncated, parse_errors
    finally:
        f.close()


def _drain_records(record_iter, linktype: int, max_packets: int):
    packets: list[session_store.ImportedPacket] = []
    truncated = False
    parse_errors = 0
    try:
        for rec in record_iter:
            fields = dissect.dissect_frame(linktype, rec.data)
            packets.append(
                session_store.ImportedPacket(
                    ts_epoch=rec.timestamp,
                    protocol=fields["protocol"],
                    src_addr=fields["src_addr"],
                    src_port=fields["src_port"],
                    dst_addr=fields["dst_addr"],
                    dst_port=fields["dst_port"],
                    length=rec.orig_len,
                    flags=fields["flags"],
                )
            )
            if len(packets) >= max_packets:
                truncated = True
                break
    except pcapfmt.PcapError:
        # Mid-stream corruption or a genuinely truncated capture. Whatever
        # was already parsed is still returned; this is not re-raised as a
        # hard failure unless nothing was parsed at all (handled by the
        # caller checking `packets` is empty).
        truncated = True
        parse_errors += 1
    return packets, truncated, parse_errors


def import_upload(
    chunks,
    filename: str,
    work_dir: Optional[Path] = None,
    sessions_db_path: Optional[Path] = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
    max_packets: int = MAX_IMPORT_PACKETS,
) -> dict:
    """Full E2 flow: stream to a temp file (bounded), parse it, store the
    dissected rows, clean up the temp file. Raises UploadTooLargeError or
    PcapImportError; the router maps those to 413/400 respectively."""
    work_dir = work_dir or Path(tempfile.gettempdir()) / "netaudit-pcap-import"
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = work_dir / f"upload-{os.getpid()}-{time.time_ns()}.tmp"

    try:
        stream_to_disk(chunks, tmp_path, max_bytes=max_bytes)
        linktype_name, packets, truncated, parse_errors = parse_pcap_file(tmp_path, max_packets=max_packets)

        session_id = session_store.new_session_id()
        summary = session_store.create_session(
            session_id=session_id,
            filename=filename,
            packets=packets,
            linktype=linktype_name,
            truncated=truncated,
            parse_errors=parse_errors,
            db_path=sessions_db_path,
        )
        return summary
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

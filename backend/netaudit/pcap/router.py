"""E1-E4 routes: PCAP export, PCAP import, sessions, capture filter.

A bare `APIRouter` per the task instructions -- mounted into the real app
by the orchestrator. No import from `netaudit.threat`, `netaudit.posture`,
`netaudit.learn`, `netaudit.compliance` or `netaudit.alerts` anywhere in
this package.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..timeutil import iso_z, now_epoch, parse_iso
from . import bpf, import_pipeline, live_query, session_store, synth

router = APIRouter()

_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "other"}

_SYNTHETIC_REASON = (
    "NetAudit's packet store persists only header/metadata fields (protocol, "
    "addresses, ports, length, flags) and never raw frame bytes, on every "
    "capture tier -- see backend/SECURITY.md Part C item 8. On this machine "
    "capture currently runs on the polling tier, which stores flow-derived "
    "records rather than sniffed frames; even on the npcap/raw-socket tiers, "
    "the store itself holds no payload, so exported frames are always "
    "reconstructed from stored fields, never replayed from a captured buffer."
)


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


# --- E1: PCAP export ---------------------------------------------------------


@router.get("/api/capture/pcap")
def export_pcap(
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    peer: Optional[str] = Query(None),
    port: Optional[int] = Query(None),
    limit: int = Query(100000),
):
    if protocol is not None and protocol.lower() not in _VALID_PROTOCOLS:
        _error(400, "invalid_protocol", f"protocol must be one of {sorted(_VALID_PROTOCOLS)}")
    if port is not None and not (0 <= port <= 65535):
        _error(400, "invalid_port", "port must be 0-65535")
    if limit < 1:
        _error(400, "invalid_limit", "limit must be >= 1")
    limit = min(limit, 1_000_000)  # hard cap per E1

    since_epoch = until_epoch = None
    try:
        if since:
            since_epoch = parse_iso(since)
        if until:
            until_epoch = parse_iso(until)
    except ValueError:
        _error(400, "invalid_timestamp", "since/until must be ISO-8601")

    filters = live_query.PcapExportFilters(
        since=since_epoch, until=until_epoch,
        protocol=protocol.lower() if protocol else None,
        peer=peer, port=port, limit=limit,
    )

    def _generate():
        yield from _iter_pcap_bytes(filters)

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    filename = f"netaudit-{ts}.pcap"
    return StreamingResponse(
        _generate(),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _iter_pcap_bytes(filters: live_query.PcapExportFilters):
    from .format import write_global_header, write_packet_record

    # Materialize the filtered rows *before* starting the slow part (frame
    # synthesis + streaming each chunk out over the network, which can
    # take far longer than the query itself once the client is slow to
    # read). netaudit.store.db arms a wall-clock deadline per connection
    # fetch (SECURITY.md Part C item 6) that aborts the *statement* if too
    # much time passes -- interleaving cursor iteration with slow
    # per-chunk network I/O risks hitting that deadline on a large export.
    # These are header-only rows (no payload), so holding the filtered set
    # in memory is cheap even for a large capture.
    rows = list(live_query.iter_export_packets(filters))

    yield write_global_header(snaplen=65535, linktype=1)  # EN10MB -- every synthesised frame starts with Ethernet
    for row in rows:
        frame, orig_len = synth.synthesize_frame(row)
        ts_epoch = row["ts_epoch"] or 0.0
        ts_sec = int(ts_epoch)
        ts_usec = int(round((ts_epoch - ts_sec) * 1_000_000))
        yield write_packet_record(ts_sec, ts_usec, len(frame), orig_len, frame)


# --- E2: PCAP import ----------------------------------------------------------


class ImportResponse(BaseModel):
    session_id: str
    filename: str
    packets: int
    bytes: int
    first_packet: Optional[str]
    last_packet: Optional[str]
    linktype: str
    truncated: bool
    parse_errors: int


def _import_work_dir() -> Path:
    return Path(tempfile.gettempdir()) / "netaudit-pcap-import"


@router.post("/api/capture/pcap/import")
async def import_pcap(file: UploadFile = File(...)):
    work_dir = _import_work_dir()
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = work_dir / f"upload-{os.getpid()}-{time.time_ns()}.tmp"

    written = 0
    try:
        with open(tmp_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > import_pipeline.MAX_UPLOAD_BYTES:
                    f.close()
                    tmp_path.unlink(missing_ok=True)
                    _error(
                        413, "upload_too_large",
                        f"upload exceeds the {import_pipeline.MAX_UPLOAD_BYTES} byte cap",
                    )
                f.write(chunk)
    finally:
        await file.close()

    try:
        linktype_name, packets, truncated, parse_errors = import_pipeline.parse_pcap_file(tmp_path)
    except import_pipeline.PcapImportError as exc:
        _error(400, "invalid_pcap", str(exc))
    except Exception as exc:  # never let an unanticipated exception escape as a 500 for untrusted input
        _error(400, "invalid_pcap", f"could not parse file: {exc}")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    session_id = session_store.new_session_id()
    filename = file.filename or "upload.pcap"
    summary = session_store.create_session(
        session_id=session_id, filename=filename, packets=packets,
        linktype=linktype_name, truncated=truncated, parse_errors=parse_errors,
    )

    return ImportResponse(
        session_id=summary["session_id"],
        filename=summary["filename"],
        packets=summary["packets"],
        bytes=summary["bytes"],
        first_packet=iso_z(summary["first_packet_epoch"]) if summary["first_packet_epoch"] is not None else None,
        last_packet=iso_z(summary["last_packet_epoch"]) if summary["last_packet_epoch"] is not None else None,
        linktype=summary["linktype"],
        truncated=summary["truncated"],
        parse_errors=summary["parse_errors"],
    )


# --- E3: sessions --------------------------------------------------------------


@router.get("/api/sessions")
def list_sessions():
    live_count = live_query.live_packet_count()
    sessions = [
        {
            "id": "live",
            "kind": "live",
            "label": "Live capture",
            "packets": live_count,
            "synthetic": True,
            "synthetic_reason": _SYNTHETIC_REASON,
        }
    ]
    for row in session_store.list_sessions():
        sessions.append(
            {
                "id": row["id"],
                "kind": "imported",
                "label": row["filename"] or row["id"],
                "packets": row["packets"],
                "synthetic": False,
                "imported_at": iso_z(row["imported_at_epoch"]),
            }
        )
    return {"sessions": sessions}


@router.delete("/api/sessions/{session_id}")
def delete_session(session_id: str):
    if session_id == "live":
        _error(400, "cannot_delete_live", "the live session cannot be deleted")
    existing = session_store.get_session(session_id)
    if existing is None:
        _error(404, "not_found", f"no imported session with id '{session_id}'")
    session_store.delete_session(session_id)
    return {"id": session_id, "deleted": True}


# --- E4: capture filter --------------------------------------------------------


class _FilterState:
    def __init__(self):
        self._lock = threading.Lock()
        self.expression: str = ""
        self.valid: bool = True
        self.error: Optional[str] = None
        self.active: bool = False
        self.compiled_summary: Optional[str] = None

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "expression": self.expression,
                "valid": self.valid,
                "error": self.error,
                # Structural evaluation (bpf.evaluate) can be applied at
                # ingest regardless of tier; none of the tiers this backend
                # supports get a hardware/driver-level BPF program compiled
                # into them by this router (that wiring, if any, belongs to
                # netaudit.capture, owned elsewhere) -- so every tier is
                # reported as "applies via ingest-time evaluation", never
                # "capture-time" for this router's own guarantee.
                "applies_to_tier": ["npcap", "rawsocket", "polling"],
                "active": self.active,
                "compiled_summary": self.compiled_summary,
            }

    def try_set(self, expression: str) -> dict:
        expression = expression or ""
        if not expression.strip():
            with self._lock:
                self.expression = ""
                self.valid = True
                self.error = None
                self.active = False
                self.compiled_summary = None
            return self.snapshot()

        try:
            ast = bpf.parse_bpf(expression)
        except bpf.BpfParseError as exc:
            # Per E4: an invalid PUT must not change the active filter.
            return {
                "expression": expression,
                "valid": False,
                "error": {"message": exc.message, "position": exc.position},
                "applies_to_tier": ["npcap", "rawsocket", "polling"],
                "active": self.active,
                "compiled_summary": None,
            }

        with self._lock:
            self.expression = expression
            self.valid = True
            self.error = None
            self.active = True
            self.compiled_summary = bpf.describe(ast)
        return self.snapshot()


_filter_state = _FilterState()


class FilterUpdateRequest(BaseModel):
    expression: str = ""


@router.get("/api/capture/filter")
def get_filter():
    return _filter_state.snapshot()


@router.put("/api/capture/filter")
def put_filter(body: FilterUpdateRequest):
    result = _filter_state.try_set(body.expression)
    if result.get("valid") is False:
        raise HTTPException(status_code=400, detail={"error": {
            "code": "invalid_filter",
            "message": result["error"]["message"],
            "position": result["error"]["position"],
        }})
    return result

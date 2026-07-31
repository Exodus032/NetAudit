from __future__ import annotations

import csv
import io
import json
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .. import config
from ..security import csv_safe_cell
from ..store.packets import LogFilters, query_log
from ..timeutil import parse_iso

router = APIRouter()

_ENTRY_FIELDS = [
    "id", "ts", "protocol", "src_addr", "src_port", "dst_addr", "dst_port",
    "direction", "length", "flags", "process_name", "pid", "remote_host",
    "is_external", "is_encrypted", "summary", "risk",
]

# Part C item 4: filter fields go through a hardcoded allowlist, never
# interpolated. protocol/direction values were already bound as SQL
# parameters (never string-built), so this isn't closing a SQL-injection
# hole -- it's rejecting nonsense values with 400 instead of silently
# matching zero rows, per spec.
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "other"}
_VALID_DIRECTIONS = {"inbound", "outbound", "local"}


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


def _build_filters(
    limit: int, offset: int, protocol: Optional[str], q: Optional[str],
    since: Optional[str], until: Optional[str], direction: Optional[str],
    min_bytes: Optional[int], sort: str, order: str,
) -> LogFilters:
    if limit < 1:
        _error(400, "invalid_limit", "limit must be >= 1")
    # Part C item 6: hard server-side cap, regardless of what's requested --
    # clamp rather than reject, so a client asking for 999999 just gets the
    # capped result set.
    limit = min(limit, config.MAX_LIMIT)
    if offset < 0:
        _error(400, "invalid_offset", "offset must be >= 0")
    if protocol is not None and protocol not in _VALID_PROTOCOLS:
        _error(400, "invalid_protocol", f"protocol must be one of {sorted(_VALID_PROTOCOLS)}")
    if direction is not None and direction not in _VALID_DIRECTIONS:
        _error(400, "invalid_direction", f"direction must be one of {sorted(_VALID_DIRECTIONS)}")
    if sort not in ("time", "bytes"):
        _error(400, "invalid_sort", "sort must be 'time' or 'bytes'")
    if order not in ("asc", "desc"):
        _error(400, "invalid_order", "order must be 'asc' or 'desc'")

    since_epoch = until_epoch = None
    try:
        if since:
            since_epoch = parse_iso(since)
        if until:
            until_epoch = parse_iso(until)
    except ValueError:
        _error(400, "invalid_timestamp", "since/until must be ISO-8601")

    return LogFilters(
        limit=limit, offset=offset, protocol=protocol, q=q,
        since=since_epoch, until=until_epoch, direction=direction,
        min_bytes=min_bytes, sort=sort, order=order,
    )


@router.get("/api/traffic/log")
def get_traffic_log(
    request: Request,
    limit: int = Query(100), offset: int = Query(0),
    protocol: Optional[str] = Query(None), q: Optional[str] = Query(None),
    since: Optional[str] = Query(None), until: Optional[str] = Query(None),
    direction: Optional[str] = Query(None), min_bytes: Optional[int] = Query(None),
    sort: str = Query("time"), order: str = Query("desc"),
):
    filters = _build_filters(limit, offset, protocol, q, since, until, direction, min_bytes, sort, order)
    entries, total = query_log(filters, request.app.state.db_path)
    return {"total": total, "limit": filters.limit, "offset": filters.offset, "entries": entries}


@router.get("/api/traffic/export")
def export_traffic(
    request: Request,
    format: str = Query("csv"),
    limit: int = Query(1000), offset: int = Query(0),
    protocol: Optional[str] = Query(None), q: Optional[str] = Query(None),
    since: Optional[str] = Query(None), until: Optional[str] = Query(None),
    direction: Optional[str] = Query(None), min_bytes: Optional[int] = Query(None),
    sort: str = Query("time"), order: str = Query("desc"),
):
    if format not in ("csv", "json"):
        _error(400, "invalid_format", "format must be 'csv' or 'json'")

    filters = _build_filters(limit, offset, protocol, q, since, until, direction, min_bytes, sort, order)
    entries, _total = query_log(filters, request.app.state.db_path)
    ts_label = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    filename = f"netaudit-log-{ts_label}.{format}"

    if format == "json":
        body = json.dumps({"entries": entries}, indent=2)
        return StreamingResponse(
            io.BytesIO(body.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_ENTRY_FIELDS)
    writer.writeheader()
    for e in entries:
        # Part C item 5: any cell starting with =, +, -, @, tab, or CR gets
        # a leading `'` so spreadsheet apps never interpret it as a formula
        # (e.g. a hostile process_name like "=cmd|'/C calc'!A1").
        writer.writerow({k: csv_safe_cell(e.get(k)) for k in _ENTRY_FIELDS})
    buf.seek(0)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

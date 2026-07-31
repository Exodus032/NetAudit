from __future__ import annotations

import csv
import io
import json
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..store.packets import LogFilters, query_log
from ..timeutil import parse_iso

router = APIRouter()

_ENTRY_FIELDS = [
    "id", "ts", "protocol", "src_addr", "src_port", "dst_addr", "dst_port",
    "direction", "length", "flags", "process_name", "pid", "remote_host",
    "is_external", "is_encrypted", "summary", "risk",
]


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


def _build_filters(
    limit: int, offset: int, protocol: Optional[str], q: Optional[str],
    since: Optional[str], until: Optional[str], direction: Optional[str],
    min_bytes: Optional[int], sort: str, order: str,
) -> LogFilters:
    if limit < 1 or limit > 1000:
        _error(400, "invalid_limit", "limit must be between 1 and 1000")
    if offset < 0:
        _error(400, "invalid_offset", "offset must be >= 0")
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

    filters = _build_filters(min(limit, 1000), offset, protocol, q, since, until, direction, min_bytes, sort, order)
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
        writer.writerow({k: e.get(k) for k in _ENTRY_FIELDS})
    buf.seek(0)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

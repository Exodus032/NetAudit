"""E5 (reports) and E6 (SIEM export) routes.

A bare `APIRouter` per the task instructions. `get_report_provider` is a
FastAPI dependency the orchestrator overrides (`app.dependency_overrides`)
with a real implementation backed by the posture/threat/rules engines;
this router never imports those packages directly.
"""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, field_validator

from ..timeutil import iso_z, parse_iso
from . import events as events_mod
from . import reports_store
from . import siem
from .provider import ReportDataProvider, get_report_provider
from .report_data import build_report_data
from .report_html import render_html_report
from .report_markdown import render_markdown_report

router = APIRouter()

_VALID_FORMATS = {"html", "markdown", "json"}
_VALID_SECTIONS = {"summary", "posture", "threats", "recommendations", "traffic", "devices"}
_MEDIA_TYPE_FOR_FORMAT = {"html": "text/html; charset=utf-8", "markdown": "text/markdown; charset=utf-8", "json": "application/json"}

_VALID_SIEM_FORMATS = {"jsonl", "cef", "syslog", "ecs"}
_SIEM_MEDIA_TYPE = {
    "jsonl": "application/x-ndjson",
    "ecs": "application/x-ndjson",
    "cef": "text/plain; charset=utf-8",
    "syslog": "text/plain; charset=utf-8",
}


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


# --- E5: reports ---------------------------------------------------------


class ReportRequest(BaseModel):
    format: str = "html"
    sections: list[str] = ["summary", "posture", "threats", "recommendations", "traffic", "devices"]
    window: str = "24h"
    title: str = "NetAudit report"

    @field_validator("sections")
    @classmethod
    def _sections_non_empty(cls, v):
        return v or ["summary"]


def _render(fmt: str, data: dict) -> str:
    if fmt == "html":
        return render_html_report(data)
    if fmt == "markdown":
        return render_markdown_report(data)
    if fmt == "json":
        import json
        return json.dumps(data, default=str, indent=2)
    raise ValueError(f"unknown format {fmt!r}")  # pragma: no cover -- guarded by _VALID_FORMATS above


@router.post("/api/reports")
def create_report(body: ReportRequest, provider: ReportDataProvider = Depends(get_report_provider)):
    if body.format not in _VALID_FORMATS:
        _error(400, "invalid_format", f"format must be one of {sorted(_VALID_FORMATS)}")
    bad_sections = [s for s in body.sections if s not in _VALID_SECTIONS]
    if bad_sections:
        _error(400, "invalid_sections", f"unknown section(s): {bad_sections}")

    data = build_report_data(provider, body.sections, body.window, body.title)
    content = _render(body.format, data)
    meta = reports_store.save_report(content, body.format, body.title, body.window, body.sections)

    return PlainTextResponse(
        content,
        media_type=_MEDIA_TYPE_FOR_FORMAT[body.format],
        headers={
            "X-NetAudit-Report-Id": meta["id"],
            "Content-Disposition": f'attachment; filename="{meta["filename"]}"',
        },
    )


@router.get("/api/reports")
def list_reports():
    metas = reports_store.list_reports()
    return {
        "reports": [
            {
                "id": m["id"], "title": m["title"], "format": m["format"], "window": m["window"],
                "sections": m["sections"], "generated_at": iso_z(m["generated_at_epoch"]),
                "filename": m["filename"], "bytes": m["bytes"],
            }
            for m in metas
        ]
    }


@router.get("/api/reports/{report_id}")
def get_report(report_id: str):
    result = reports_store.get_report(report_id)
    if result is None:
        _error(404, "not_found", f"no report with id '{report_id}'")
    content, meta = result
    return PlainTextResponse(
        content,
        media_type=_MEDIA_TYPE_FOR_FORMAT.get(meta["format"], "text/plain; charset=utf-8"),
        headers={
            "X-NetAudit-Report-Id": meta["id"],
            "Content-Disposition": f'attachment; filename="{meta["filename"]}"',
        },
    )


@router.delete("/api/reports/{report_id}")
def delete_report(report_id: str):
    deleted = reports_store.delete_report(report_id)
    if not deleted:
        _error(404, "not_found", f"no report with id '{report_id}'")
    return {"id": report_id, "deleted": True}


# --- E6: SIEM export -------------------------------------------------------


@router.get("/api/export/events")
def export_events(
    format: str = Query(...),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    kinds: Optional[str] = Query(None),
    provider: ReportDataProvider = Depends(get_report_provider),
):
    if format not in _VALID_SIEM_FORMATS:
        _error(400, "invalid_format", f"format must be one of {sorted(_VALID_SIEM_FORMATS)}")

    kind_set = set(events_mod.VALID_KINDS)
    if kinds:
        requested = {k.strip() for k in kinds.split(",") if k.strip()}
        bad = requested - events_mod.VALID_KINDS
        if bad:
            _error(400, "invalid_kinds", f"unknown kind(s): {sorted(bad)}")
        kind_set = requested

    since_epoch = until_epoch = None
    try:
        if since:
            since_epoch = parse_iso(since)
        if until:
            until_epoch = parse_iso(until)
    except ValueError:
        _error(400, "invalid_timestamp", "since/until must be ISO-8601")

    event_stream = events_mod.iter_events(provider, kind_set, since=since_epoch, until=until_epoch)
    formatter = siem.FORMATTERS[format]

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    ext = {"jsonl": "jsonl", "ecs": "ndjson", "cef": "cef", "syslog": "log"}[format]
    filename = f"netaudit-events-{ts}.{ext}"

    return StreamingResponse(
        formatter(event_stream),
        media_type=_SIEM_MEDIA_TYPE[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

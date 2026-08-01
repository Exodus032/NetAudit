"""Part B endpoints, bare `APIRouter` with no prefix -- paths are written
out in full (`/api/threats`, ...) exactly as API_CONTRACT_V2_SECURITY.md
Part B specifies, matching the convention already used by the v1 routers
this package must not import from.

The engine is resolved through the `get_threat_engine` FastAPI dependency.
The orchestrator wires the real engine in with
`app.dependency_overrides[get_threat_engine] = lambda: real_engine`, or by
setting `request.app.state.threat_engine` (the default implementation
below reads from there so overriding is optional, not required).
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from .engine import ThreatEngine
from .intel import lookup as intel_lookup

router = APIRouter()

MAX_LIMIT = 1000


def get_threat_engine(request: Request) -> ThreatEngine:
    engine = getattr(request.app.state, "threat_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "engine_unavailable", "message": "Threat engine is not configured on this server."}},
        )
    return engine


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


def _parse_iso(value: str) -> datetime:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise _error(400, "bad_request", f"Invalid timestamp '{value}'")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_window_seconds(window: str) -> float:
    w = window.strip().lower()
    try:
        if w.endswith("h"):
            seconds = float(w[:-1]) * 3600
        elif w.endswith("m"):
            seconds = float(w[:-1]) * 60
        elif w.endswith("d"):
            seconds = float(w[:-1]) * 86400
        else:
            seconds = float(w)
    except ValueError:
        raise _error(400, "bad_request", f"Invalid window '{window}'")
    # float() happily parses 'nan'/'inf', which would poison the timeline
    # arithmetic downstream -- reject anything non-finite or non-positive.
    if not math.isfinite(seconds) or seconds <= 0:
        raise _error(400, "bad_request", f"Invalid window '{window}'")
    return seconds


@router.get("/api/threats")
def list_threats(
    limit: int = Query(100),
    offset: int = Query(0),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    include_acknowledged: bool = Query(False),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    engine: ThreatEngine = Depends(get_threat_engine),
):
    limit = max(0, min(int(limit), MAX_LIMIT))
    filters = {}
    if severity:
        filters["severity"] = severity
    if category:
        filters["category"] = category
    if status:
        filters["status"] = status

    since_epoch = _parse_iso(since).timestamp() if since else None
    until_epoch = _parse_iso(until).timestamp() if until else None

    total, threats = engine.list_threats(
        limit=limit, offset=offset, filters=filters, since_epoch=since_epoch,
        until_epoch=until_epoch, q=q, include_acknowledged=include_acknowledged,
        sort=sort, order=order,
    )
    return {"total": total, "limit": limit, "offset": offset, "threats": threats}


@router.get("/api/threats/timeline")
def threats_timeline(
    window: str = Query("24h"),
    bucket: int = Query(3600),
    engine: ThreatEngine = Depends(get_threat_engine),
):
    bucket = max(1, min(int(bucket), 86400))
    window_seconds = _parse_window_seconds(window)
    until = datetime.now(tz=timezone.utc)
    since = until - timedelta(seconds=window_seconds)
    points = engine.timeline(since, until, bucket)
    return {"window": window, "bucket_seconds": bucket, "points": points}


@router.get("/api/threats/detectors")
def list_detectors(engine: ThreatEngine = Depends(get_threat_engine)):
    return {"detectors": engine.list_detectors()}


@router.patch("/api/threats/detectors/{detector_id}")
def patch_detector(detector_id: str, body: dict = Body(...), engine: ThreatEngine = Depends(get_threat_engine)):
    updated, error = engine.patch_detector(detector_id, body)
    if error == "not_found":
        raise _error(404, "not_found", f"No detector '{detector_id}'")
    if error:
        raise _error(400, "validation_error", error)
    return updated


@router.get("/api/threats/{threat_id}")
def get_threat(threat_id: str, engine: ThreatEngine = Depends(get_threat_engine)):
    threat = engine.get_threat(threat_id)
    if threat is None:
        raise _error(404, "not_found", f"No threat '{threat_id}'")
    return threat


@router.post("/api/threats/{threat_id}/acknowledge")
def acknowledge_threat(threat_id: str, body: dict = Body(default={}), engine: ThreatEngine = Depends(get_threat_engine)):
    note = body.get("note") if isinstance(body, dict) else None
    result = engine.acknowledge(threat_id, note)
    if result is None:
        raise _error(404, "not_found", f"No threat '{threat_id}'")
    return {"id": result["id"], "status": result["status"], "note": result.get("acknowledged_note")}


@router.post("/api/threats/{threat_id}/unacknowledge")
def unacknowledge_threat(threat_id: str, body: dict = Body(default={}), engine: ThreatEngine = Depends(get_threat_engine)):
    note = body.get("note") if isinstance(body, dict) else None
    result = engine.unacknowledge(threat_id, note)
    if result is None:
        raise _error(404, "not_found", f"No threat '{threat_id}'")
    return {"id": result["id"], "status": result["status"], "note": result.get("acknowledged_note")}


@router.get("/api/intel/lookup")
def intel_lookup_endpoint(value: str = Query(...), type: str = Query(...)):
    if type not in ("ip", "domain", "url", "port", "process", "mac", "ja3", "hash"):
        raise _error(400, "bad_request", f"Unsupported type '{type}'")
    result = intel_lookup.lookup(value, type)
    return {
        "value": result.value,
        "type": result.type,
        "found": result.found,
        "matches": [
            {"source": m.source, "category": m.category, "confidence": m.confidence,
             "first_added": m.first_added, "note": m.note}
            for m in result.matches
        ],
        "classification": {
            "is_private": result.classification.is_private,
            "is_bogon": result.classification.is_bogon,
            "is_multicast": result.classification.is_multicast,
            "is_tor_exit": result.classification.is_tor_exit,
            "asn": result.classification.asn,
            "org": result.classification.org,
            "country": result.classification.country,
        },
        "reputation": result.reputation,
    }

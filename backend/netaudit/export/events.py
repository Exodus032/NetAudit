"""Normalizes threat / recommendation / posture / traffic records into one
canonical "event" shape for E6's SIEM export, streamed one at a time.

Threat, recommendation and posture data comes from the injected
`ReportDataProvider` (see `provider.py`) -- this module never imports
`netaudit.threat`/`netaudit.posture` directly. Traffic events are read
straight from `netaudit.store.db`, same as `netaudit/pcap/live_query.py`
does for PCAP export; that's this package's own domain to read.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..store import db as dbmod
from .provider import ReportDataProvider

VALID_KINDS = {"threat", "recommendation", "posture", "traffic"}


def _severity_from(value: Optional[str]) -> str:
    return value or "info"


def _normalize_threat(t: dict) -> dict:
    peer = (t.get("evidence") or [{}])
    indicators = t.get("indicators") or []
    dest_ip = next((i["value"] for i in indicators if i.get("type") == "ip"), None)
    return {
        "ts_epoch": _epoch(t.get("last_seen") or t.get("first_seen")),
        "kind": "threat",
        "category": t.get("category") or "anomaly",
        "severity": _severity_from(t.get("severity")),
        "title": t.get("title") or t.get("detector_id") or "threat",
        "message": t.get("summary") or "",
        "source_ip": None,
        "destination_ip": dest_ip,
        "protocol": None,
        "process_name": None,
        "technique_id": (t.get("mitre") or [{}])[0].get("technique") if t.get("mitre") else None,
        "raw": t,
    }


def _normalize_recommendation(r: dict) -> dict:
    return {
        "ts_epoch": _epoch(r.get("last_seen") or r.get("first_seen")),
        "kind": "recommendation",
        "category": r.get("category") or "hygiene",
        "severity": _severity_from(r.get("severity")),
        "title": r.get("title") or r.get("rule_id") or "recommendation",
        "message": r.get("summary") or "",
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "process_name": None,
        "technique_id": None,
        "raw": r,
    }


def _normalize_posture(check: dict) -> dict:
    return {
        "ts_epoch": _epoch(check.get("checked_at")),
        "kind": "posture",
        "category": check.get("category") or "posture",
        "severity": _severity_from(check.get("severity")),
        "title": check.get("title") or check.get("id") or "posture check",
        "message": check.get("observed") or "",
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "process_name": None,
        "technique_id": None,
        "raw": check,
    }


def _normalize_traffic(row: dict) -> dict:
    return {
        "ts_epoch": row["ts_epoch"],
        "kind": "traffic",
        "category": "network_flow",
        "severity": row.get("risk") or "info",
        "title": f"{(row.get('protocol') or '').upper()} {row.get('src_addr')}:{row.get('src_port')} -> "
                 f"{row.get('dst_addr')}:{row.get('dst_port')}",
        "message": row.get("summary") or "",
        "source_ip": row.get("src_addr"),
        "destination_ip": row.get("dst_addr"),
        "protocol": row.get("protocol"),
        "process_name": row.get("process_name"),
        "technique_id": None,
        "raw": row,
    }


def _epoch(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    from ..timeutil import parse_iso
    try:
        return parse_iso(str(value))
    except ValueError:
        return 0.0


def _iter_traffic_rows(since: Optional[float], until: Optional[float], limit: int, db_path: Optional[Path]) -> Iterator[dict]:
    conn = dbmod.get_conn(db_path)
    clauses = []
    params: dict = {}
    if since is not None:
        clauses.append("ts_epoch >= :since")
        params["since"] = since
    if until is not None:
        clauses.append("ts_epoch <= :until")
        params["until"] = until
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    cursor = conn.execute(
        f"""
        SELECT ts_epoch, protocol, src_addr, src_port, dst_addr, dst_port,
               process_name, summary, risk
        FROM packets {where_sql}
        ORDER BY ts_epoch ASC
        LIMIT :limit
        """,
        {**params, "limit": limit},
    )
    for row in cursor:
        yield dict(row)


def iter_events(
    provider: ReportDataProvider,
    kinds: Iterable[str],
    since: Optional[float] = None,
    until: Optional[float] = None,
    traffic_limit: int = 100_000,
    db_path: Optional[Path] = None,
) -> Iterator[dict]:
    """Yields normalized event dicts for every requested kind. Streamed --
    each source is iterated lazily and nothing is materialised beyond one
    event at a time (the provider's lists are already in memory by the
    time they reach this function, but this function itself never builds
    a combined list)."""
    kinds = set(kinds) or VALID_KINDS

    def _in_window(ts_epoch: float) -> bool:
        if since is not None and ts_epoch < since:
            return False
        if until is not None and ts_epoch > until:
            return False
        return True

    if "threat" in kinds:
        for t in provider.threats():
            ev = _normalize_threat(t)
            if _in_window(ev["ts_epoch"]):
                yield ev

    if "recommendation" in kinds:
        for r in provider.recommendations():
            ev = _normalize_recommendation(r)
            if _in_window(ev["ts_epoch"]):
                yield ev

    if "posture" in kinds:
        report = provider.posture_report()
        for check in report.get("checks", []):
            ev = _normalize_posture(check)
            if _in_window(ev["ts_epoch"]):
                yield ev

    if "traffic" in kinds:
        for row in _iter_traffic_rows(since, until, traffic_limit, db_path):
            yield _normalize_traffic(row)

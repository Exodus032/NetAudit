"""Runs all rules, turns their findings into stable/deduped/persisted
Recommendation rows, and serves the /api/recommendations read + dismiss API.
"""
from __future__ import annotations

import hashlib
import json
import time

from ..store import db as dbmod
from ..timeutil import iso_z
from .base import RuleContext
from .builtin import ALL_RULES

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _stable_id(rule_id: str, key: str) -> str:
    digest = hashlib.md5(key.encode("utf-8")).hexdigest()[:4]
    slug = rule_id.replace("_", "-")
    return f"{slug}-{digest}"


def build_context(db_path, window_seconds: float, capture_mode: str, elevated: bool, now: float | None = None) -> RuleContext:
    now = now if now is not None else time.time()
    conn = dbmod.get_conn(db_path)
    start = now - window_seconds
    flows = conn.execute("SELECT * FROM flows WHERE last_seen_epoch >= ?", (start,)).fetchall()
    packets = conn.execute("SELECT * FROM packets WHERE ts_epoch >= ?", (start,)).fetchall()
    devices = conn.execute("SELECT * FROM devices").fetchall()
    return RuleContext(
        now=now, window_seconds=window_seconds, flows=flows, packets=packets,
        devices=devices, capture_mode=capture_mode, elevated=elevated,
    )


def run_once(ctx: RuleContext, db_path=None) -> int:
    """Evaluate every rule and upsert findings. Returns the number of
    findings processed (not the number of DB rows -- dedup happens inside
    the upsert)."""
    conn = dbmod.get_conn(db_path)
    count = 0
    for rule_cls in ALL_RULES:
        rule = rule_cls()
        try:
            findings = list(rule.evaluate(ctx))
        except Exception:
            # A single misbehaving rule must never take down the engine.
            continue
        for finding in findings:
            count += 1
            rec_id = _stable_id(rule.rule_id, finding.key)
            existing = conn.execute("SELECT dismissed, occurrences FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO recommendations (
                        id, rule_id, title, severity, confidence, category, summary, detail,
                        evidence, actions, first_seen_epoch, last_seen_epoch, occurrences,
                        dismissed, related_connection_ids
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
                    """,
                    (
                        rec_id, rule.rule_id, finding.title, finding.severity, finding.confidence,
                        finding.category, finding.summary, finding.detail,
                        json.dumps(finding.evidence), json.dumps(finding.actions),
                        ctx.now, ctx.now, json.dumps(finding.related_connection_ids),
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE recommendations SET
                        title = ?, severity = ?, confidence = ?, category = ?, summary = ?, detail = ?,
                        evidence = ?, actions = ?, last_seen_epoch = ?, occurrences = occurrences + 1,
                        related_connection_ids = ?
                    WHERE id = ?
                    """,
                    (
                        finding.title, finding.severity, finding.confidence, finding.category,
                        finding.summary, finding.detail, json.dumps(finding.evidence),
                        json.dumps(finding.actions), ctx.now, json.dumps(finding.related_connection_ids),
                        rec_id,
                    ),
                )
    return count


def _row_to_recommendation(row) -> dict:
    return {
        "id": row["id"],
        "rule_id": row["rule_id"],
        "title": row["title"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "category": row["category"],
        "summary": row["summary"],
        "detail": row["detail"],
        "evidence": json.loads(row["evidence"] or "[]"),
        "actions": json.loads(row["actions"] or "[]"),
        "first_seen": iso_z(row["first_seen_epoch"]),
        "last_seen": iso_z(row["last_seen_epoch"]),
        "occurrences": row["occurrences"],
        "dismissed": bool(row["dismissed"]),
        "related_connection_ids": json.loads(row["related_connection_ids"] or "[]"),
    }


def list_recommendations(include_dismissed: bool = False, db_path=None) -> list[dict]:
    conn = dbmod.get_conn(db_path)
    if include_dismissed:
        rows = conn.execute("SELECT * FROM recommendations").fetchall()
    else:
        rows = conn.execute("SELECT * FROM recommendations WHERE dismissed = 0").fetchall()
    items = [_row_to_recommendation(r) for r in rows]
    items.sort(key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 99), -r["confidence"]))
    return items


def set_dismissed(rec_id: str, dismissed: bool, db_path=None) -> dict | None:
    conn = dbmod.get_conn(db_path)
    row = conn.execute("SELECT id FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE recommendations SET dismissed = ? WHERE id = ?", (1 if dismissed else 0, rec_id))
    return {"id": rec_id, "dismissed": dismissed}

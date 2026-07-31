"""Persistence for baseline snapshots. Reuses the shared SQLite file via
`netaudit.store.db.get_conn()` (explicitly allowed: "reading the SQLite
store via netaudit.store.db for your own tables is fine") but owns its own
table, created lazily and idempotently here -- `store/db.py` itself is not
touched.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Optional

from ..store import db as dbmod
from ..timeutil import now_iso

_schema_ready_for: set[str] = set()


def _ensure_schema(conn: sqlite3.Connection, db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    if key in _schema_ready_for:
        return
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS baselines (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            checks_json TEXT NOT NULL DEFAULT '[]',
            peers_json TEXT NOT NULL DEFAULT '[]',
            listeners_json TEXT NOT NULL DEFAULT '[]',
            posture_score INTEGER NOT NULL DEFAULT 0,
            threats_score INTEGER,
            overall_score INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    _schema_ready_for.add(key)


def _new_id() -> str:
    return f"bl_{secrets.token_hex(6)}"


@dataclass(frozen=True)
class BaselineRecord:
    id: str
    label: str
    captured_at: str
    checks: list[dict]  # [{"id": str, "status": str}, ...]
    peers: list[str]
    listeners: list[dict]  # [{"port": int, "process": str}, ...]
    posture_score: int
    threats_score: Optional[int]
    overall_score: int


def insert_baseline(
    label: str,
    checks: list[dict],
    peers: list[str],
    listeners: list[dict],
    posture_score: int,
    threats_score: Optional[int],
    overall_score: int,
    db_path=None,
) -> BaselineRecord:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    record = BaselineRecord(
        id=_new_id(),
        label=label,
        captured_at=now_iso(),
        checks=checks,
        peers=peers,
        listeners=listeners,
        posture_score=posture_score,
        threats_score=threats_score,
        overall_score=overall_score,
    )
    conn.execute(
        """
        INSERT INTO baselines (id, label, captured_at, checks_json, peers_json, listeners_json,
                                posture_score, threats_score, overall_score)
        VALUES (:id, :label, :captured_at, :checks_json, :peers_json, :listeners_json,
                :posture_score, :threats_score, :overall_score)
        """,
        {
            "id": record.id,
            "label": record.label,
            "captured_at": record.captured_at,
            "checks_json": json.dumps(record.checks),
            "peers_json": json.dumps(record.peers),
            "listeners_json": json.dumps(record.listeners),
            "posture_score": record.posture_score,
            "threats_score": record.threats_score,
            "overall_score": record.overall_score,
        },
    )
    return record


def _row_to_record(row: sqlite3.Row) -> BaselineRecord:
    return BaselineRecord(
        id=row["id"],
        label=row["label"],
        captured_at=row["captured_at"],
        checks=json.loads(row["checks_json"]),
        peers=json.loads(row["peers_json"]),
        listeners=json.loads(row["listeners_json"]),
        posture_score=row["posture_score"],
        threats_score=row["threats_score"],
        overall_score=row["overall_score"],
    )


def list_baselines(db_path=None) -> list[BaselineRecord]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    rows = conn.execute("SELECT * FROM baselines ORDER BY captured_at DESC").fetchall()
    return [_row_to_record(r) for r in rows]


def get_baseline(baseline_id: str, db_path=None) -> Optional[BaselineRecord]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute("SELECT * FROM baselines WHERE id = ?", (baseline_id,)).fetchone()
    return _row_to_record(row) if row else None


def reset_for_tests(db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    _schema_ready_for.discard(key)

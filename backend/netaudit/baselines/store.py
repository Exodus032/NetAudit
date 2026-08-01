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
import threading
from dataclasses import dataclass
from typing import Optional

from ..store import db as dbmod
from ..timeutil import iso_z, now_iso, parse_iso

_schema_ready_for: set[str] = set()
_schema_lock = threading.Lock()

_ALLOWED_INTERVAL_HOURS = frozenset((6, 12, 24, 48, 168))
_BASELINE_ORIGINS = frozenset(("manual", "scheduled"))


def _canonical_timestamp(value: str) -> str:
    return iso_z(parse_iso(value))


def _ensure_schema(conn: sqlite3.Connection, db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    if key in _schema_ready_for:
        return
    with _schema_lock:
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
                overall_score INTEGER NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT 'manual'
            );
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(baselines)")}
        if "origin" not in columns:
            conn.execute("ALTER TABLE baselines ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS baseline_schedule (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_hours INTEGER NOT NULL DEFAULT 24
                    CHECK (interval_hours IN (6, 12, 24, 48, 168)),
                last_succeeded_at TEXT,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_baselines_origin_captured_at
                ON baselines (origin, captured_at);
            """
        )
        schedule_columns = {row["name"] for row in conn.execute("PRAGMA table_info(baseline_schedule)")}
        if "last_success_at" in schedule_columns and "last_succeeded_at" not in schedule_columns:
            conn.execute("ALTER TABLE baseline_schedule RENAME COLUMN last_success_at TO last_succeeded_at")
        conn.execute(
            """
            INSERT OR IGNORE INTO baseline_schedule (singleton, enabled, interval_hours)
            VALUES (1, 0, 24)
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
    origin: str = "manual"


def insert_baseline(
    label: str,
    checks: list[dict],
    peers: list[str],
    listeners: list[dict],
    posture_score: int,
    threats_score: Optional[int],
    overall_score: int,
    db_path=None,
    origin: str = "manual",
    captured_at: Optional[str] = None,
) -> BaselineRecord:
    if origin not in _BASELINE_ORIGINS:
        raise ValueError("origin must be 'manual' or 'scheduled'")
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    record = BaselineRecord(
        id=_new_id(),
        label=label,
        captured_at=_canonical_timestamp(captured_at) if captured_at is not None else now_iso(),
        checks=checks,
        peers=peers,
        listeners=listeners,
        posture_score=posture_score,
        threats_score=threats_score,
        overall_score=overall_score,
        origin=origin,
    )
    conn.execute(
        """
        INSERT INTO baselines (id, label, captured_at, checks_json, peers_json, listeners_json,
                               posture_score, threats_score, overall_score, origin)
        VALUES (:id, :label, :captured_at, :checks_json, :peers_json, :listeners_json,
                :posture_score, :threats_score, :overall_score, :origin)
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
            "origin": record.origin,
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
        origin=row["origin"],
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


@dataclass(frozen=True)
class BaselineScheduleRecord:
    enabled: bool
    interval_hours: int
    last_succeeded_at: Optional[str]
    last_error: Optional[str]


def _row_to_schedule_record(row: sqlite3.Row) -> BaselineScheduleRecord:
    return BaselineScheduleRecord(
        enabled=bool(row["enabled"]),
        interval_hours=row["interval_hours"],
        last_succeeded_at=row["last_succeeded_at"],
        last_error=row["last_error"],
    )


def get_schedule(db_path=None) -> BaselineScheduleRecord:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute(
        """
        SELECT enabled, interval_hours, last_succeeded_at, last_error
        FROM baseline_schedule
        WHERE singleton = 1
        """
    ).fetchone()
    return _row_to_schedule_record(row)


def save_schedule(enabled: bool, interval_hours: int, db_path=None) -> BaselineScheduleRecord:
    if interval_hours not in _ALLOWED_INTERVAL_HOURS:
        raise ValueError("interval_hours must be one of 6, 12, 24, 48, or 168")
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        """
        UPDATE baseline_schedule
        SET enabled = ?, interval_hours = ?
        WHERE singleton = 1
        """,
        (enabled, interval_hours),
    )
    return get_schedule(db_path)


def mark_schedule_success(captured_at: str, db_path=None) -> BaselineScheduleRecord:
    captured_at = _canonical_timestamp(captured_at)
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        """
        UPDATE baseline_schedule
        SET last_succeeded_at = ?, last_error = NULL
        WHERE singleton = 1
          AND (last_succeeded_at IS NULL OR julianday(last_succeeded_at) <= julianday(?))
        """,
        (captured_at, captured_at),
    )
    return get_schedule(db_path)


def mark_schedule_error(error: str, db_path=None) -> BaselineScheduleRecord:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        "UPDATE baseline_schedule SET last_error = ? WHERE singleton = 1",
        (error,),
    )
    return get_schedule(db_path)


def get_most_recent_scheduled_baseline(db_path=None) -> Optional[BaselineRecord]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute(
        """
        SELECT * FROM baselines
        WHERE origin = 'scheduled'
        ORDER BY julianday(captured_at) DESC
        LIMIT 1
        """
    ).fetchone()
    return _row_to_record(row) if row else None


def delete_scheduled_before(cutoff: str, db_path=None) -> int:
    cutoff = _canonical_timestamp(cutoff)
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    result = conn.execute(
        """
        DELETE FROM baselines
        WHERE origin = 'scheduled' AND julianday(captured_at) < julianday(?)
        """,
        (cutoff,),
    )
    return result.rowcount


def reset_for_tests(db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    _schema_ready_for.discard(key)

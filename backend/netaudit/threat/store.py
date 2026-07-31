"""SQLite persistence for threats, acknowledgements, detector tunables, and
per-occurrence timeline events.

Its own tables, its own file (path from an injected setting -- see
`ThreatStoreSettings`/`get_conn`), never assumes another module's schema.
All SQL is parameterised; the only place a caller-controlled string ever
reaches a query unparameterised is a column *name* pulled through the
hardcoded `SORT_COLUMNS`/`FILTER_COLUMNS` allowlists in this file (Part C
requirement 4).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

# Allowlists: the only column names ever interpolated into SQL text. Never
# accept a column name from a request without going through one of these.
SORT_COLUMNS = {
    "first_seen": "first_seen_epoch",
    "last_seen": "last_seen_epoch",
    "severity": "severity_rank",
    "confidence": "confidence",
    "occurrences": "occurrences",
}
FILTER_COLUMNS = {
    "severity": "severity",
    "category": "category",
    "status": "status",
    "detector_id": "detector_id",
}

SEVERITY_RANK_SQL = (
    "CASE severity "
    "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 1 ELSE 0 END"
)

MAX_LIMIT = 1000

_local = threading.local()
_init_lock = threading.Lock()
_initialized_paths: set[str] = set()


def get_conn(db_path: Path) -> sqlite3.Connection:
    key = str(db_path)
    conn = getattr(_local, "conn", None)
    conn_path = getattr(_local, "path", None)
    if conn is not None and conn_path == key:
        return conn

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _local.conn = conn
    _local.path = key

    with _init_lock:
        if key not in _initialized_paths:
            _init_schema(conn)
            _initialized_paths.add(key)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            detector_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            mitre TEXT NOT NULL DEFAULT '[]',
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '[]',
            indicators TEXT NOT NULL DEFAULT '[]',
            metrics TEXT NOT NULL DEFAULT '{}',
            first_seen_epoch REAL NOT NULL,
            last_seen_epoch REAL NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1,
            related_connection_ids TEXT NOT NULL DEFAULT '[]',
            related_log_ids TEXT NOT NULL DEFAULT '[]',
            false_positive_notes TEXT NOT NULL DEFAULT '',
            recommended_actions TEXT NOT NULL DEFAULT '[]',
            acknowledged_note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen_epoch);
        CREATE INDEX IF NOT EXISTS idx_threats_detector ON threats(detector_id);
        CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
        CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
        CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);

        CREATE TABLE IF NOT EXISTS threat_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT NOT NULL,
            detector_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            ts_epoch REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON threat_events(ts_epoch);

        CREATE TABLE IF NOT EXISTS detector_settings (
            detector_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            tunables TEXT NOT NULL DEFAULT '{}',
            fired_count INTEGER NOT NULL DEFAULT 0,
            last_fired_epoch REAL
        );
        """
    )


def reset_for_tests(db_path: Path) -> None:
    key = str(db_path)
    _initialized_paths.discard(key)
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _local.conn = None
    _local.path = None


class ThreatStore:
    """Thin wrapper around the sqlite schema above. Every method takes/
    returns plain dicts (already JSON-decoded) so callers (engine.py,
    router.py) never touch sqlite3.Row or raw column names directly."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        return get_conn(self.db_path)

    # -- threats ----------------------------------------------------------
    def upsert_threat(self, row: dict) -> None:
        conn = self._conn()
        conn.execute(
            """
            INSERT INTO threats (
                id, detector_id, title, severity, confidence, category, status, mitre,
                summary, detail, evidence, indicators, metrics, first_seen_epoch,
                last_seen_epoch, occurrences, related_connection_ids, related_log_ids,
                false_positive_notes, recommended_actions, acknowledged_note
            ) VALUES (:id, :detector_id, :title, :severity, :confidence, :category, :status,
                      :mitre, :summary, :detail, :evidence, :indicators, :metrics,
                      :first_seen_epoch, :last_seen_epoch, :occurrences,
                      :related_connection_ids, :related_log_ids, :false_positive_notes,
                      :recommended_actions, :acknowledged_note)
            ON CONFLICT(id) DO UPDATE SET
                title=excluded.title, severity=excluded.severity, confidence=excluded.confidence,
                category=excluded.category, status=excluded.status, mitre=excluded.mitre,
                summary=excluded.summary, detail=excluded.detail, evidence=excluded.evidence,
                indicators=excluded.indicators, metrics=excluded.metrics,
                last_seen_epoch=excluded.last_seen_epoch, occurrences=excluded.occurrences,
                related_connection_ids=excluded.related_connection_ids,
                related_log_ids=excluded.related_log_ids,
                false_positive_notes=excluded.false_positive_notes,
                recommended_actions=excluded.recommended_actions
            """,
            row,
        )

    def set_status(self, threat_id: str, status: str) -> None:
        self._conn().execute("UPDATE threats SET status=? WHERE id=?", (status, threat_id))

    def set_acknowledged(self, threat_id: str, acknowledged: bool, note: Optional[str]) -> Optional[dict]:
        conn = self._conn()
        status = "acknowledged" if acknowledged else "active"
        conn.execute(
            "UPDATE threats SET status=?, acknowledged_note=? WHERE id=?",
            (status, note if acknowledged else None, threat_id),
        )
        return self.get_threat(threat_id)

    def get_threat(self, threat_id: str) -> Optional[dict]:
        row = self._conn().execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone()
        return _row_to_dict(row) if row else None

    def list_threats(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[dict[str, str]] = None,
        since_epoch: Optional[float] = None,
        until_epoch: Optional[float] = None,
        q: Optional[str] = None,
        include_acknowledged: bool = False,
        sort: str = "last_seen",
        order: str = "desc",
    ) -> tuple[int, list[dict]]:
        limit = max(0, min(int(limit), MAX_LIMIT))
        offset = max(0, int(offset))
        where: list[str] = []
        params: list[Any] = []

        if filters:
            for key, value in filters.items():
                if value is None:
                    continue
                col = FILTER_COLUMNS.get(key)
                if col is None:
                    continue  # never interpolate an unrecognized column name
                where.append(f"{col} = ?")
                params.append(value)

        if since_epoch is not None:
            where.append("last_seen_epoch >= ?")
            params.append(since_epoch)
        if until_epoch is not None:
            where.append("first_seen_epoch <= ?")
            params.append(until_epoch)
        if not include_acknowledged:
            where.append("status != 'acknowledged'")
        if q:
            where.append("(title LIKE ? OR summary LIKE ? OR detail LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like])

        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        sort_col = SORT_COLUMNS.get(sort, SORT_COLUMNS["last_seen"])
        order_sql = "ASC" if str(order).lower() == "asc" else "DESC"
        if sort == "severity":
            sort_col = SEVERITY_RANK_SQL

        conn = self._conn()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM threats {where_sql}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM threats {where_sql} ORDER BY {sort_col} {order_sql} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        return total, [_row_to_dict(r) for r in rows]

    # -- timeline events ---------------------------------------------------
    def record_event(self, threat_id: str, detector_id: str, severity: str, ts_epoch: float) -> None:
        self._conn().execute(
            "INSERT INTO threat_events (threat_id, detector_id, severity, ts_epoch) VALUES (?, ?, ?, ?)",
            (threat_id, detector_id, severity, ts_epoch),
        )

    def events_between(self, since_epoch: float, until_epoch: float) -> list[dict]:
        rows = self._conn().execute(
            "SELECT severity, ts_epoch FROM threat_events WHERE ts_epoch >= ? AND ts_epoch <= ? ORDER BY ts_epoch",
            (since_epoch, until_epoch),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- detector settings ---------------------------------------------------
    def get_detector_settings(self, detector_id: str) -> dict:
        row = self._conn().execute(
            "SELECT * FROM detector_settings WHERE detector_id=?", (detector_id,)
        ).fetchone()
        if row is None:
            return {"enabled": True, "tunables": {}, "fired_count": 0, "last_fired_epoch": None}
        return {
            "enabled": bool(row["enabled"]),
            "tunables": json.loads(row["tunables"]),
            "fired_count": row["fired_count"],
            "last_fired_epoch": row["last_fired_epoch"],
        }

    def save_detector_settings(self, detector_id: str, enabled: bool, tunables: dict,
                                fired_count: int, last_fired_epoch: Optional[float]) -> None:
        self._conn().execute(
            """
            INSERT INTO detector_settings (detector_id, enabled, tunables, fired_count, last_fired_epoch)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(detector_id) DO UPDATE SET
                enabled=excluded.enabled, tunables=excluded.tunables,
                fired_count=excluded.fired_count, last_fired_epoch=excluded.last_fired_epoch
            """,
            (detector_id, int(enabled), json.dumps(tunables), fired_count, last_fired_epoch),
        )

    def clear_all(self) -> None:
        conn = self._conn()
        conn.execute("DELETE FROM threats")
        conn.execute("DELETE FROM threat_events")
        conn.execute("DELETE FROM detector_settings")


_JSON_COLUMNS = {"mitre", "evidence", "indicators", "metrics", "related_connection_ids", "related_log_ids", "recommended_actions"}


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for col in _JSON_COLUMNS:
        if col in d and isinstance(d[col], str):
            d[col] = json.loads(d[col])
    return d

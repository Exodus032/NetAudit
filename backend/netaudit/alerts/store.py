"""Persistence for alert config/channels/history. Reuses the shared SQLite
file via `netaudit.store.db.get_conn()` for its own tables, same pattern as
`netaudit.baselines.store` -- `store/db.py` itself is never touched.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Optional

from ..store import db as dbmod
from ..timeutil import now_iso

_schema_ready_for: set[str] = set()

_DEFAULT_CHANNELS = [
    {"id": "desktop", "kind": "desktop", "enabled": True, "url": None, "template": None, "last_status": None, "last_attempt": None},
]


def _ensure_schema(conn: sqlite3.Connection, db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    if key in _schema_ready_for:
        return
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            min_severity TEXT NOT NULL DEFAULT 'high',
            rate_limit_per_hour INTEGER NOT NULL DEFAULT 20,
            quiet_start TEXT,
            quiet_end TEXT
        );
        CREATE TABLE IF NOT EXISTS alert_channels (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            url TEXT,
            template TEXT,
            last_status TEXT,
            last_attempt TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts_history (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            source_id TEXT NOT NULL,
            title TEXT NOT NULL,
            channels_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_history_ts ON alerts_history(ts);
        """
    )
    row = conn.execute("SELECT 1 FROM alerts_config WHERE id = 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO alerts_config (id, enabled, min_severity, rate_limit_per_hour, quiet_start, quiet_end) "
            "VALUES (1, 0, 'high', 20, NULL, NULL)"
        )
        for ch in _DEFAULT_CHANNELS:
            conn.execute(
                "INSERT INTO alert_channels (id, kind, enabled, url, template, last_status, last_attempt) "
                "VALUES (:id, :kind, :enabled, :url, :template, :last_status, :last_attempt)",
                {**ch, "enabled": int(ch["enabled"])},
            )
    _schema_ready_for.add(key)


def get_config_row(db_path=None) -> dict:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute("SELECT * FROM alerts_config WHERE id = 1").fetchone()
    return dict(row)


def set_config_row(enabled: bool, min_severity: str, rate_limit_per_hour: int, quiet_start: Optional[str], quiet_end: Optional[str], db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        "UPDATE alerts_config SET enabled = :enabled, min_severity = :min_severity, "
        "rate_limit_per_hour = :rate_limit_per_hour, quiet_start = :quiet_start, quiet_end = :quiet_end WHERE id = 1",
        {
            "enabled": int(enabled),
            "min_severity": min_severity,
            "rate_limit_per_hour": rate_limit_per_hour,
            "quiet_start": quiet_start,
            "quiet_end": quiet_end,
        },
    )


def list_channels(db_path=None) -> list[dict]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    rows = conn.execute("SELECT * FROM alert_channels ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_channel(channel_id: str, db_path=None) -> Optional[dict]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()
    return dict(row) if row else None


def replace_channels(channels: list[dict], db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute("DELETE FROM alert_channels")
    for ch in channels:
        conn.execute(
            "INSERT INTO alert_channels (id, kind, enabled, url, template, last_status, last_attempt) "
            "VALUES (:id, :kind, :enabled, :url, :template, :last_status, :last_attempt)",
            {
                "id": ch["id"],
                "kind": ch["kind"],
                "enabled": int(ch["enabled"]),
                "url": ch.get("url"),
                "template": ch.get("template"),
                "last_status": ch.get("last_status"),
                "last_attempt": ch.get("last_attempt"),
            },
        )


def update_channel_status(channel_id: str, status: str, db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        "UPDATE alert_channels SET last_status = ?, last_attempt = ? WHERE id = ?",
        (status, now_iso(), channel_id),
    )


def insert_history(entry_id: str, ts: str, severity: str, source: str, source_id: str, title: str, channels: list[dict], db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    conn.execute(
        "INSERT INTO alerts_history (id, ts, severity, source, source_id, title, channels_json) "
        "VALUES (:id, :ts, :severity, :source, :source_id, :title, :channels_json)",
        {
            "id": entry_id,
            "ts": ts,
            "severity": severity,
            "source": source,
            "source_id": source_id,
            "title": title,
            "channels_json": json.dumps(channels),
        },
    )


def count_history_since(since_epoch_iso: str, db_path=None) -> int:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    row = conn.execute("SELECT COUNT(*) AS n FROM alerts_history WHERE ts >= ?", (since_epoch_iso,)).fetchone()
    return int(row["n"])


def list_history(limit: int = 200, db_path=None) -> list[dict]:
    conn = dbmod.get_conn(db_path)
    _ensure_schema(conn, db_path)
    rows = conn.execute("SELECT * FROM alerts_history ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["channels"] = json.loads(d.pop("channels_json"))
        result.append(d)
    return result


def reset_for_tests(db_path) -> None:
    key = str(db_path) if db_path is not None else "default"
    _schema_ready_for.discard(key)

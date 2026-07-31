"""Storage for imported pcap/pcapng analysis sessions (E2/E3).

Imported sessions are **never** merged into live capture (`netaudit.store`).
This module owns a small, separate SQLite database file so nothing here
touches the schema in `netaudit/store/db.py`, which belongs to the capture
pipeline. Two tables:

  - `sessions`: one row per imported file (metadata for E3's listing).
  - `session_packets`: the dissected per-packet rows for that session, in
    the same rough shape as `store.packets` entries, so a future consumer
    (e.g. `/api/traffic/log?session=...`, wired up outside this package)
    can query imported traffic the same way it queries live traffic.

Kept out of `netaudit/store/db.py` deliberately: that module is owned by
the capture pipeline and this package may only create files under
`netaudit/pcap/` and `netaudit/export/` (see the task's ownership rules).
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_local = threading.local()
_init_lock = threading.Lock()
_initialized: set[str] = set()


def _default_db_path() -> Path:
    override = os.environ.get("NETAUDIT_PCAP_SESSIONS_DB_PATH")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "NetAudit" / "pcap_sessions.db"


DEFAULT_DB_PATH = _default_db_path()


def get_conn(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    key = str(path)
    conn = getattr(_local, "conn", None)
    conn_path = getattr(_local, "path", None)
    if conn is not None and conn_path == key:
        return conn

    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _local.conn = conn
    _local.path = key

    with _init_lock:
        if key not in _initialized:
            _init_schema(conn)
            _initialized.add(key)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            filename TEXT,
            packets INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            first_packet_epoch REAL,
            last_packet_epoch REAL,
            linktype TEXT,
            truncated INTEGER NOT NULL DEFAULT 0,
            parse_errors INTEGER NOT NULL DEFAULT 0,
            imported_at_epoch REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS session_packets (
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            ts_epoch REAL NOT NULL,
            protocol TEXT NOT NULL,
            src_addr TEXT,
            src_port INTEGER,
            dst_addr TEXT,
            dst_port INTEGER,
            length INTEGER NOT NULL,
            flags TEXT,
            PRIMARY KEY (session_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_session_packets_session ON session_packets(session_id);
        """
    )


def reset_for_tests(db_path: Path) -> None:
    key = str(db_path)
    _initialized.discard(key)
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _local.conn = None
    _local.path = None


def new_session_id() -> str:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    return f"imported-{today}-{secrets.token_hex(2)}"


@dataclass
class ImportedPacket:
    ts_epoch: float
    protocol: str
    src_addr: Optional[str]
    src_port: Optional[int]
    dst_addr: Optional[str]
    dst_port: Optional[int]
    length: int
    flags: Optional[str]


def create_session(
    session_id: str,
    filename: str,
    packets: list[ImportedPacket],
    linktype: str,
    truncated: bool,
    parse_errors: int,
    db_path: Optional[Path] = None,
) -> dict:
    conn = get_conn(db_path)
    total_bytes = sum(p.length for p in packets)
    first_ts = min((p.ts_epoch for p in packets), default=None)
    last_ts = max((p.ts_epoch for p in packets), default=None)
    imported_at = time.time()

    conn.execute("BEGIN")
    try:
        conn.execute(
            """
            INSERT INTO sessions (
                id, filename, packets, bytes, first_packet_epoch, last_packet_epoch,
                linktype, truncated, parse_errors, imported_at_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, filename, len(packets), total_bytes, first_ts, last_ts,
             linktype, int(truncated), parse_errors, imported_at),
        )
        conn.executemany(
            """
            INSERT INTO session_packets (
                session_id, seq, ts_epoch, protocol, src_addr, src_port,
                dst_addr, dst_port, length, flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (session_id, i, p.ts_epoch, p.protocol, p.src_addr, p.src_port,
                 p.dst_addr, p.dst_port, p.length, p.flags)
                for i, p in enumerate(packets)
            ],
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {
        "session_id": session_id,
        "filename": filename,
        "packets": len(packets),
        "bytes": total_bytes,
        "first_packet_epoch": first_ts,
        "last_packet_epoch": last_ts,
        "linktype": linktype,
        "truncated": truncated,
        "parse_errors": parse_errors,
        "imported_at_epoch": imported_at,
    }


def list_sessions(db_path: Optional[Path] = None) -> list[dict]:
    conn = get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM sessions ORDER BY imported_at_epoch DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_session(session_id: str, db_path: Optional[Path] = None) -> Optional[dict]:
    conn = get_conn(db_path)
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    return dict(row) if row else None


def delete_session(session_id: str, db_path: Optional[Path] = None) -> bool:
    conn = get_conn(db_path)
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM session_packets WHERE session_id = ?", (session_id,))
        cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.execute("COMMIT")
        return cur.rowcount > 0
    except Exception:
        conn.execute("ROLLBACK")
        raise


def query_session_packets(
    session_id: str,
    limit: int = 100,
    offset: int = 0,
    protocol: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> tuple[list[dict], int]:
    conn = get_conn(db_path)
    clauses = ["session_id = :sid"]
    params: dict = {"sid": session_id}
    if protocol:
        clauses.append("protocol = :protocol")
        params["protocol"] = protocol
    where_sql = " AND ".join(clauses)

    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM session_packets WHERE {where_sql}", params
    ).fetchone()["c"]

    rows = conn.execute(
        f"""
        SELECT * FROM session_packets WHERE {where_sql}
        ORDER BY seq ASC LIMIT :limit OFFSET :offset
        """,
        {**params, "limit": limit, "offset": offset},
    ).fetchall()

    return [dict(r) for r in rows], total

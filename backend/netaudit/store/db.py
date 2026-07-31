"""SQLite schema + connection handling. WAL mode, one connection per thread
(sqlite3 connections aren't safe to share across threads without care, and
a thread-local avoids serializing every call through a single connection).
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from .. import config

_local = threading.local()
_init_lock = threading.Lock()
_initialized_paths: set[str] = set()

# --- Query timeouts (Part C item 6) -----------------------------------------
#
# SQLite has no native per-statement CPU timeout, so we approximate one with
# a progress handler: it's invoked periodically during query execution and
# can abort the statement by returning non-zero. Each connection is only
# ever used by the thread that created it (see get_conn), so a thread-local
# deadline is enough -- no cross-thread synchronization needed. The deadline
# is (re)armed on every get_conn() call, giving each batch of queries a
# store function makes in one call up to SQL_QUERY_TIMEOUT_SECONDS before
# SQLite aborts with sqlite3.OperationalError. This is a soft, per-call-
# batch bound, not a hard per-statement one -- documented in SECURITY.md.


def _progress_handler() -> int:
    deadline = getattr(_local, "deadline", None)
    if deadline is not None and time.monotonic() > deadline:
        return 1  # non-zero aborts the running statement
    return 0


def _arm_deadline() -> None:
    _local.deadline = time.monotonic() + config.SQL_QUERY_TIMEOUT_SECONDS


def get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DB_PATH
    key = str(path)
    conn = getattr(_local, "conn", None)
    conn_path = getattr(_local, "path", None)
    if conn is not None and conn_path == key:
        _arm_deadline()
        return conn

    path.parent.mkdir(parents=True, exist_ok=True)
    # `timeout` here bounds how long sqlite3 waits on a locked database
    # (busy_timeout), not statement execution time -- see the progress
    # handler above for the latter.
    conn = sqlite3.connect(str(path), timeout=config.SQL_QUERY_TIMEOUT_SECONDS, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.set_progress_handler(_progress_handler, 1000)
    _local.conn = conn
    _local.path = key
    _arm_deadline()

    with _init_lock:
        if key not in _initialized_paths:
            _init_schema(conn)
            _initialized_paths.add(key)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_epoch REAL NOT NULL,
            protocol TEXT NOT NULL,
            src_addr TEXT NOT NULL,
            src_port INTEGER,
            dst_addr TEXT NOT NULL,
            dst_port INTEGER,
            direction TEXT NOT NULL,
            length INTEGER NOT NULL,
            flags TEXT,
            process_name TEXT,
            pid INTEGER,
            remote_addr TEXT,
            remote_host TEXT,
            is_external INTEGER NOT NULL,
            is_encrypted INTEGER NOT NULL,
            summary TEXT,
            risk TEXT NOT NULL DEFAULT 'low'
        );
        CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts_epoch);
        CREATE INDEX IF NOT EXISTS idx_packets_remote ON packets(remote_addr);
        CREATE INDEX IF NOT EXISTS idx_packets_pid ON packets(pid);
        CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);

        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            local_addr TEXT,
            local_port INTEGER,
            remote_addr TEXT,
            remote_port INTEGER,
            remote_host TEXT,
            remote_org TEXT,
            direction TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            process_path TEXT,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            first_seen_epoch REAL NOT NULL,
            last_seen_epoch REAL NOT NULL,
            is_external INTEGER NOT NULL DEFAULT 0,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            risk TEXT NOT NULL DEFAULT 'low',
            risk_reasons TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen_epoch);
        CREATE INDEX IF NOT EXISTS idx_flows_remote ON flows(remote_addr);
        CREATE INDEX IF NOT EXISTS idx_flows_pid ON flows(pid);

        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            first_seen_epoch REAL NOT NULL,
            last_seen_epoch REAL NOT NULL,
            bytes_total INTEGER NOT NULL DEFAULT 0,
            is_gateway INTEGER NOT NULL DEFAULT 0,
            is_self INTEGER NOT NULL DEFAULT 0,
            open_ports TEXT NOT NULL DEFAULT '[]',
            risk TEXT NOT NULL DEFAULT 'low'
        );

        CREATE TABLE IF NOT EXISTS stats_minutely (
            minute_epoch INTEGER PRIMARY KEY,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0,
            packets_in INTEGER NOT NULL DEFAULT 0,
            packets_out INTEGER NOT NULL DEFAULT 0,
            tcp INTEGER NOT NULL DEFAULT 0,
            udp INTEGER NOT NULL DEFAULT 0,
            icmp INTEGER NOT NULL DEFAULT 0,
            other INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS recommendations (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            category TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '[]',
            actions TEXT NOT NULL DEFAULT '[]',
            first_seen_epoch REAL NOT NULL,
            last_seen_epoch REAL NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1,
            dismissed INTEGER NOT NULL DEFAULT 0,
            related_connection_ids TEXT NOT NULL DEFAULT '[]'
        );
        """
    )


def reset_for_tests(db_path: Path) -> None:
    """Drop cached thread-local connection so a fresh :memory:/temp db is
    picked up cleanly between tests."""
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


def clear_all(db_path: Path | None = None) -> None:
    conn = get_conn(db_path)
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM flows")
    conn.execute("DELETE FROM stats_minutely")
    conn.execute("DELETE FROM devices")
    conn.execute("DELETE FROM recommendations")

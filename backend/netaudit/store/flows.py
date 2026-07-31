"""Flow aggregation table feeding /api/connections."""
from __future__ import annotations

import json
import sqlite3
import time

from ..timeutil import iso_z
from . import db as dbmod

# A flow is considered "live" for /api/connections if it's had activity
# within this many seconds.
ACTIVE_WINDOW_SECONDS = 120.0


def upsert_flow(flow: dict, db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    conn.execute(
        """
        INSERT INTO flows (
            id, protocol, state, local_addr, local_port, remote_addr, remote_port,
            remote_host, remote_org, direction, pid, process_name, process_path,
            bytes_in, bytes_out, packets, first_seen_epoch, last_seen_epoch,
            is_external, is_encrypted, risk, risk_reasons
        ) VALUES (
            :id, :protocol, :state, :local_addr, :local_port, :remote_addr, :remote_port,
            :remote_host, :remote_org, :direction, :pid, :process_name, :process_path,
            :bytes_in, :bytes_out, 1, :ts_epoch, :ts_epoch,
            :is_external, :is_encrypted, :risk, :risk_reasons
        )
        ON CONFLICT(id) DO UPDATE SET
            state = excluded.state,
            remote_host = COALESCE(excluded.remote_host, flows.remote_host),
            remote_org = COALESCE(excluded.remote_org, flows.remote_org),
            process_name = COALESCE(excluded.process_name, flows.process_name),
            process_path = COALESCE(excluded.process_path, flows.process_path),
            bytes_in = flows.bytes_in + excluded.bytes_in,
            bytes_out = flows.bytes_out + excluded.bytes_out,
            packets = flows.packets + 1,
            last_seen_epoch = excluded.last_seen_epoch,
            risk = excluded.risk,
            risk_reasons = excluded.risk_reasons
        """,
        flow,
    )


def _row_to_connection(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "protocol": row["protocol"],
        "state": row["state"],
        "local_addr": row["local_addr"],
        "local_port": row["local_port"],
        "remote_addr": row["remote_addr"],
        "remote_port": row["remote_port"],
        "remote_host": row["remote_host"],
        "remote_org": row["remote_org"],
        "direction": row["direction"],
        "pid": row["pid"],
        "process_name": row["process_name"],
        "process_path": row["process_path"],
        "bytes_in": row["bytes_in"],
        "bytes_out": row["bytes_out"],
        "packets": row["packets"],
        "first_seen": iso_z(row["first_seen_epoch"]),
        "last_seen": iso_z(row["last_seen_epoch"]),
        "is_external": bool(row["is_external"]),
        "is_encrypted": bool(row["is_encrypted"]),
        "risk": row["risk"],
        "risk_reasons": json.loads(row["risk_reasons"] or "[]"),
    }


def query_connections(db_path=None, active_window_seconds: float = ACTIVE_WINDOW_SECONDS) -> list[dict]:
    conn = dbmod.get_conn(db_path)
    cutoff = time.time() - active_window_seconds
    rows = conn.execute(
        "SELECT * FROM flows WHERE last_seen_epoch >= ? ORDER BY last_seen_epoch DESC",
        (cutoff,),
    ).fetchall()
    return [_row_to_connection(r) for r in rows]


def query_flows_since(since_epoch: float, db_path=None) -> list[sqlite3.Row]:
    conn = dbmod.get_conn(db_path)
    return conn.execute(
        "SELECT * FROM flows WHERE last_seen_epoch >= ?", (since_epoch,)
    ).fetchall()


def all_flows(db_path=None) -> list[sqlite3.Row]:
    conn = dbmod.get_conn(db_path)
    return conn.execute("SELECT * FROM flows").fetchall()

"""Append + paginated/filtered query for /api/traffic/log."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Optional

from ..timeutil import iso_z
from . import db as dbmod


@dataclass
class LogFilters:
    limit: int = 100
    offset: int = 0
    protocol: Optional[str] = None
    q: Optional[str] = None
    since: Optional[float] = None
    until: Optional[float] = None
    direction: Optional[str] = None
    min_bytes: Optional[int] = None
    sort: str = "time"
    order: str = "desc"


def append_batch(rows: list[dict], db_path=None) -> None:
    if not rows:
        return
    conn = dbmod.get_conn(db_path)
    conn.executemany(
        """
        INSERT INTO packets (
            ts_epoch, protocol, src_addr, src_port, dst_addr, dst_port,
            direction, length, flags, process_name, pid, remote_addr,
            remote_host, is_external, is_encrypted, summary, risk
        ) VALUES (
            :ts_epoch, :protocol, :src_addr, :src_port, :dst_addr, :dst_port,
            :direction, :length, :flags, :process_name, :pid, :remote_addr,
            :remote_host, :is_external, :is_encrypted, :summary, :risk
        )
        """,
        rows,
    )


def _row_to_entry(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "ts": iso_z(row["ts_epoch"]),
        "protocol": row["protocol"],
        "src_addr": row["src_addr"],
        "src_port": row["src_port"],
        "dst_addr": row["dst_addr"],
        "dst_port": row["dst_port"],
        "direction": row["direction"],
        "length": row["length"],
        "flags": row["flags"] or "",
        "process_name": row["process_name"],
        "pid": row["pid"],
        "remote_host": row["remote_host"],
        "is_external": bool(row["is_external"]),
        "is_encrypted": bool(row["is_encrypted"]),
        "summary": row["summary"] or "",
        "risk": row["risk"],
    }


def max_id(db_path=None) -> int:
    conn = dbmod.get_conn(db_path)
    row = conn.execute("SELECT MAX(id) AS m FROM packets").fetchone()
    return row["m"] or 0


def query_since_id(last_id: int, limit: int, db_path=None) -> tuple[list[dict], int]:
    """Rows with id > last_id, oldest first, capped at limit. Returns
    (entries, new_max_id) -- callers that want newest-first (e.g. the /ws/live
    'log' frame) should reverse the list themselves."""
    conn = dbmod.get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM packets WHERE id > ? ORDER BY id ASC LIMIT ?",
        (last_id, limit),
    ).fetchall()
    entries = [_row_to_entry(r) for r in rows]
    new_max = entries[-1]["id"] if entries else last_id
    return entries, new_max


def query_log(filters: LogFilters, db_path=None) -> tuple[list[dict], int]:
    conn = dbmod.get_conn(db_path)

    clauses: list[str] = []
    params: dict = {}

    if filters.protocol:
        clauses.append("protocol = :protocol")
        params["protocol"] = filters.protocol
    if filters.direction:
        clauses.append("direction = :direction")
        params["direction"] = filters.direction
    if filters.since is not None:
        clauses.append("ts_epoch >= :since")
        params["since"] = filters.since
    if filters.until is not None:
        clauses.append("ts_epoch <= :until")
        params["until"] = filters.until
    if filters.min_bytes is not None:
        clauses.append("length >= :min_bytes")
        params["min_bytes"] = filters.min_bytes
    if filters.q:
        clauses.append(
            "(remote_host LIKE :q OR process_name LIKE :q OR src_addr LIKE :q "
            "OR dst_addr LIKE :q OR CAST(src_port AS TEXT) LIKE :q OR CAST(dst_port AS TEXT) LIKE :q)"
        )
        params["q"] = f"%{filters.q}%"

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    total = conn.execute(f"SELECT COUNT(*) AS c FROM packets {where_sql}", params).fetchone()["c"]

    sort_col = "length" if filters.sort == "bytes" else "ts_epoch"
    order_sql = "ASC" if filters.order == "asc" else "DESC"

    rows = conn.execute(
        f"""
        SELECT * FROM packets {where_sql}
        ORDER BY {sort_col} {order_sql}, id {order_sql}
        LIMIT :limit OFFSET :offset
        """,
        {**params, "limit": filters.limit, "offset": filters.offset},
    ).fetchall()

    return [_row_to_entry(r) for r in rows], total

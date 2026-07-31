"""Reads the live packet store directly for PCAP export (E1).

Per the task's decoupling rules, reading `netaudit.store.db` /
`netaudit.store.packets` is fine and expected -- this package only avoids
*writing* to that schema (imported sessions get their own store, see
`session_store.py`). All values below are bound as SQL parameters, never
interpolated, matching the pattern already used in `store/packets.py`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from ..store import db as dbmod


@dataclass
class PcapExportFilters:
    since: Optional[float] = None
    until: Optional[float] = None
    protocol: Optional[str] = None
    peer: Optional[str] = None
    port: Optional[int] = None
    limit: int = 100000


def iter_export_packets(filters: PcapExportFilters, db_path: Optional[Path] = None) -> Iterator[dict]:
    """Yields packet rows (oldest first, for chronological pcap ordering)
    matching the filters, streamed via SQLite's cursor rather than loaded
    into a Python list up front."""
    conn = dbmod.get_conn(db_path)

    clauses: list[str] = []
    params: dict = {}

    if filters.since is not None:
        clauses.append("ts_epoch >= :since")
        params["since"] = filters.since
    if filters.until is not None:
        clauses.append("ts_epoch <= :until")
        params["until"] = filters.until
    if filters.protocol:
        clauses.append("protocol = :protocol")
        params["protocol"] = filters.protocol
    if filters.peer:
        clauses.append("(src_addr = :peer OR dst_addr = :peer OR remote_addr = :peer)")
        params["peer"] = filters.peer
    if filters.port is not None:
        clauses.append("(src_port = :port OR dst_port = :port)")
        params["port"] = filters.port

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    cursor = conn.execute(
        f"""
        SELECT ts_epoch, protocol, src_addr, src_port, dst_addr, dst_port,
               length, flags
        FROM packets {where_sql}
        ORDER BY ts_epoch ASC, id ASC
        LIMIT :limit
        """,
        {**params, "limit": filters.limit},
    )
    for row in cursor:
        yield {
            "ts_epoch": row["ts_epoch"],
            "protocol": row["protocol"],
            "src_addr": row["src_addr"],
            "src_port": row["src_port"],
            "dst_addr": row["dst_addr"],
            "dst_port": row["dst_port"],
            "length": row["length"],
            "flags": row["flags"],
        }


def live_packet_count(db_path: Optional[Path] = None) -> int:
    conn = dbmod.get_conn(db_path)
    row = conn.execute("SELECT COUNT(*) AS c FROM packets").fetchone()
    return row["c"] or 0

"""LAN device table, populated by observed local-subnet traffic and ARP."""
from __future__ import annotations

import json
import sqlite3

from ..timeutil import iso_z
from . import db as dbmod


def upsert_device(device: dict, db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    conn.execute(
        """
        INSERT INTO devices (ip, mac, vendor, hostname, first_seen_epoch, last_seen_epoch,
                              bytes_total, is_gateway, is_self, open_ports, risk)
        VALUES (:ip, :mac, :vendor, :hostname, :ts_epoch, :ts_epoch,
                :bytes_total, :is_gateway, :is_self, :open_ports, :risk)
        ON CONFLICT(ip) DO UPDATE SET
            mac = COALESCE(excluded.mac, devices.mac),
            vendor = COALESCE(excluded.vendor, devices.vendor),
            hostname = COALESCE(excluded.hostname, devices.hostname),
            last_seen_epoch = excluded.last_seen_epoch,
            bytes_total = devices.bytes_total + excluded.bytes_total,
            is_gateway = devices.is_gateway OR excluded.is_gateway,
            is_self = devices.is_self OR excluded.is_self,
            open_ports = excluded.open_ports,
            risk = excluded.risk
        """,
        device,
    )


def _row_to_device(row: sqlite3.Row) -> dict:
    return {
        "ip": row["ip"],
        "mac": row["mac"],
        "vendor": row["vendor"],
        "hostname": row["hostname"],
        "first_seen": iso_z(row["first_seen_epoch"]),
        "last_seen": iso_z(row["last_seen_epoch"]),
        "bytes_total": row["bytes_total"],
        "is_gateway": bool(row["is_gateway"]),
        "is_self": bool(row["is_self"]),
        "open_ports": json.loads(row["open_ports"] or "[]"),
        "risk": row["risk"],
    }


def query_devices(db_path=None) -> list[dict]:
    conn = dbmod.get_conn(db_path)
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen_epoch DESC").fetchall()
    return [_row_to_device(r) for r in rows]


def merge_open_port(ip: str, port: int, db_path=None) -> None:
    conn = dbmod.get_conn(db_path)
    row = conn.execute("SELECT open_ports FROM devices WHERE ip = ?", (ip,)).fetchone()
    if row is None:
        return
    ports = set(json.loads(row["open_ports"] or "[]"))
    ports.add(port)
    conn.execute(
        "UPDATE devices SET open_ports = ? WHERE ip = ?",
        (json.dumps(sorted(ports)), ip),
    )

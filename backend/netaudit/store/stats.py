"""Rolling time-bucket aggregates feeding /api/stats/summary, /timeseries,
and /top. Raw per-packet rows (short retention) are used for fine-grained
queries; the stats_minutely table (never pruned by retention) backs longer
windows / coarser buckets so aggregates survive raw-row pruning."""
from __future__ import annotations

import time
from collections import defaultdict

from ..timeutil import iso_z
from . import db as dbmod

WINDOW_SECONDS = {
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "24h": 86400,
    "all": None,
}

_SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 137: "nbns", 138: "nbns", 139: "smb", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5353: "mdns", 5355: "llmnr", 5432: "postgres", 5985: "winrm",
    5986: "winrm-s", 8080: "http-alt", 8443: "https-alt",
}


def service_name(port: int) -> str:
    return _SERVICE_NAMES.get(port, str(port))


def _window_start(window: str, now: float) -> float | None:
    seconds = WINDOW_SECONDS.get(window, WINDOW_SECONDS["5m"])
    if seconds is None:
        return None
    return now - seconds


def record_batch(events: list[dict], db_path=None) -> None:
    """events: dicts with ts_epoch, length, direction, protocol. Aggregates
    into per-minute buckets and upserts stats_minutely."""
    if not events:
        return
    minute_agg: dict[int, dict] = defaultdict(lambda: {
        "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
        "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    })
    for e in events:
        minute = int(e["ts_epoch"] // 60) * 60
        agg = minute_agg[minute]
        if e["direction"] == "inbound":
            agg["bytes_in"] += e["length"]
            agg["packets_in"] += 1
        else:
            agg["bytes_out"] += e["length"]
            agg["packets_out"] += 1
        proto = e["protocol"]
        if proto in ("tcp", "udp", "icmp"):
            agg[proto] += 1
        else:
            agg["other"] += 1

    conn = dbmod.get_conn(db_path)
    conn.executemany(
        """
        INSERT INTO stats_minutely (minute_epoch, bytes_in, bytes_out, packets_in, packets_out, tcp, udp, icmp, other)
        VALUES (:minute, :bytes_in, :bytes_out, :packets_in, :packets_out, :tcp, :udp, :icmp, :other)
        ON CONFLICT(minute_epoch) DO UPDATE SET
            bytes_in = stats_minutely.bytes_in + excluded.bytes_in,
            bytes_out = stats_minutely.bytes_out + excluded.bytes_out,
            packets_in = stats_minutely.packets_in + excluded.packets_in,
            packets_out = stats_minutely.packets_out + excluded.packets_out,
            tcp = stats_minutely.tcp + excluded.tcp,
            udp = stats_minutely.udp + excluded.udp,
            icmp = stats_minutely.icmp + excluded.icmp,
            other = stats_minutely.other + excluded.other
        """,
        [{"minute": m, **v} for m, v in minute_agg.items()],
    )


def get_timeseries(window: str, bucket_seconds: int, db_path=None, now: float | None = None) -> list[dict]:
    now = now if now is not None else time.time()
    start = _window_start(window, now)
    if start is None:
        start = _earliest_epoch(db_path) or (now - 300)

    first_bucket = int(start // bucket_seconds) * bucket_seconds
    last_bucket = int(now // bucket_seconds) * bucket_seconds
    if last_bucket < first_bucket:
        last_bucket = first_bucket

    buckets: dict[int, dict] = {}
    b = first_bucket
    while b <= last_bucket:
        buckets[b] = {"bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
                       "tcp": 0, "udp": 0, "icmp": 0, "other": 0}
        b += bucket_seconds

    conn = dbmod.get_conn(db_path)

    if bucket_seconds < 60:
        rows = conn.execute(
            "SELECT ts_epoch, protocol, direction, length FROM packets WHERE ts_epoch >= ? AND ts_epoch < ?",
            (first_bucket, last_bucket + bucket_seconds),
        ).fetchall()
        for r in rows:
            key = int(r["ts_epoch"] // bucket_seconds) * bucket_seconds
            if key not in buckets:
                continue
            agg = buckets[key]
            if r["direction"] == "inbound":
                agg["bytes_in"] += r["length"]
                agg["packets_in"] += 1
            else:
                agg["bytes_out"] += r["length"]
                agg["packets_out"] += 1
            proto = r["protocol"] if r["protocol"] in ("tcp", "udp", "icmp") else "other"
            agg[proto] += 1
    else:
        rows = conn.execute(
            "SELECT * FROM stats_minutely WHERE minute_epoch >= ? AND minute_epoch < ?",
            (first_bucket, last_bucket + bucket_seconds),
        ).fetchall()
        for r in rows:
            key = int(r["minute_epoch"] // bucket_seconds) * bucket_seconds
            if key not in buckets:
                continue
            agg = buckets[key]
            agg["bytes_in"] += r["bytes_in"]
            agg["bytes_out"] += r["bytes_out"]
            agg["packets_in"] += r["packets_in"]
            agg["packets_out"] += r["packets_out"]
            agg["tcp"] += r["tcp"]
            agg["udp"] += r["udp"]
            agg["icmp"] += r["icmp"]
            agg["other"] += r["other"]

    return [
        {"t": iso_z(b), **buckets[b]}
        for b in sorted(buckets.keys())
    ]


def _earliest_epoch(db_path=None) -> float | None:
    conn = dbmod.get_conn(db_path)
    row = conn.execute("SELECT MIN(minute_epoch) AS m FROM stats_minutely").fetchone()
    if row and row["m"] is not None:
        return float(row["m"])
    row = conn.execute("SELECT MIN(ts_epoch) AS m FROM packets").fetchone()
    if row and row["m"] is not None:
        return float(row["m"])
    return None


def get_summary(window: str, db_path=None, now: float | None = None) -> dict:
    now = now if now is not None else time.time()
    start = _window_start(window, now)
    query_start = start if start is not None else 0.0
    elapsed = (now - start) if start is not None else max(now - (_earliest_epoch(db_path) or now), 1.0)
    elapsed = max(elapsed, 1.0)

    conn = dbmod.get_conn(db_path)
    row = conn.execute(
        """
        SELECT
          COUNT(*) AS packets_total,
          COALESCE(SUM(length),0) AS bytes_total,
          COALESCE(SUM(CASE WHEN direction='inbound' THEN length ELSE 0 END),0) AS bytes_in,
          COALESCE(SUM(CASE WHEN direction!='inbound' THEN length ELSE 0 END),0) AS bytes_out,
          COALESCE(SUM(CASE WHEN direction='inbound' THEN 1 ELSE 0 END),0) AS packets_in,
          COALESCE(SUM(CASE WHEN direction!='inbound' THEN 1 ELSE 0 END),0) AS packets_out,
          COALESCE(SUM(CASE WHEN protocol='tcp' THEN 1 ELSE 0 END),0) AS tcp_packets,
          COALESCE(SUM(CASE WHEN protocol='udp' THEN 1 ELSE 0 END),0) AS udp_packets,
          COALESCE(SUM(CASE WHEN protocol='icmp' THEN 1 ELSE 0 END),0) AS icmp_packets,
          COALESCE(SUM(CASE WHEN protocol NOT IN ('tcp','udp','icmp') THEN 1 ELSE 0 END),0) AS other_packets,
          COALESCE(SUM(CASE WHEN is_encrypted=1 THEN length ELSE 0 END),0) AS encrypted_bytes,
          COALESCE(SUM(CASE WHEN is_encrypted=0 THEN length ELSE 0 END),0) AS plaintext_bytes,
          COALESCE(SUM(CASE WHEN is_external=1 THEN length ELSE 0 END),0) AS external_bytes,
          COALESCE(SUM(CASE WHEN is_external=0 THEN length ELSE 0 END),0) AS internal_bytes
        FROM packets WHERE ts_epoch >= ?
        """,
        (query_start,),
    ).fetchone()

    flow_row = conn.execute(
        """
        SELECT COUNT(*) AS active_flows,
               COUNT(DISTINCT remote_addr) AS unique_remote_hosts,
               COUNT(DISTINCT CASE WHEN pid IS NOT NULL THEN pid END) AS unique_processes
        FROM flows WHERE last_seen_epoch >= ?
        """,
        (query_start,),
    ).fetchone()

    peak_row = conn.execute(
        """
        SELECT MAX(b) AS peak FROM (
            SELECT SUM(length) AS b FROM packets WHERE ts_epoch >= ? GROUP BY CAST(ts_epoch / 10 AS INTEGER)
        )
        """,
        (query_start,),
    ).fetchone()
    peak_throughput_bps = int((peak_row["peak"] or 0) / 10)

    alerts_rows = conn.execute(
        "SELECT severity, COUNT(*) AS c FROM recommendations WHERE dismissed = 0 GROUP BY severity"
    ).fetchall()
    alerts_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in alerts_rows:
        if r["severity"] in alerts_by_severity:
            alerts_by_severity[r["severity"]] = r["c"]
    open_alerts = sum(alerts_by_severity.values())

    return {
        "window": window,
        "generated_at": iso_z(now),
        "packets_total": row["packets_total"],
        "bytes_total": row["bytes_total"],
        "bytes_in": row["bytes_in"],
        "bytes_out": row["bytes_out"],
        "packets_in": row["packets_in"],
        "packets_out": row["packets_out"],
        "throughput_bps_in": int(row["bytes_in"] * 8 / elapsed),
        "throughput_bps_out": int(row["bytes_out"] * 8 / elapsed),
        "peak_throughput_bps": peak_throughput_bps * 8,
        "active_flows": flow_row["active_flows"],
        "unique_remote_hosts": flow_row["unique_remote_hosts"],
        "unique_processes": flow_row["unique_processes"],
        "tcp_packets": row["tcp_packets"],
        "udp_packets": row["udp_packets"],
        "icmp_packets": row["icmp_packets"],
        "other_packets": row["other_packets"],
        "encrypted_bytes": row["encrypted_bytes"],
        "plaintext_bytes": row["plaintext_bytes"],
        "external_bytes": row["external_bytes"],
        "internal_bytes": row["internal_bytes"],
        "open_alerts": open_alerts,
        "alerts_by_severity": alerts_by_severity,
    }


def get_top(by: str, limit: int, window: str, db_path=None, now: float | None = None) -> list[dict]:
    now = now if now is not None else time.time()
    start = _window_start(window, now)
    query_start = start if start is not None else 0.0

    conn = dbmod.get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM flows WHERE last_seen_epoch >= ?", (query_start,)
    ).fetchall()

    groups: dict[str, dict] = {}

    def bump(key, label, sublabel, is_external, risk, bytes_in, bytes_out, packets):
        g = groups.setdefault(key, {
            "key": key, "label": label, "sublabel": sublabel,
            "bytes_in": 0, "bytes_out": 0, "packets": 0, "flows": 0,
            "is_external": False, "risk": "low",
        })
        if label and not g["label"]:
            g["label"] = label
        if sublabel and not g["sublabel"]:
            g["sublabel"] = sublabel
        g["bytes_in"] += bytes_in
        g["bytes_out"] += bytes_out
        g["packets"] += packets
        g["flows"] += 1
        g["is_external"] = g["is_external"] or is_external
        g["risk"] = _worse_risk(g["risk"], risk)

    for r in rows:
        is_external = bool(r["is_external"])
        if by == "host":
            bump(r["remote_addr"], r["remote_host"], r["remote_org"], is_external, r["risk"],
                 r["bytes_in"], r["bytes_out"], r["packets"])
        elif by == "process":
            pid = r["pid"] if r["pid"] is not None else 0
            name = r["process_name"] or "unknown"
            key = f"{pid}:{name}"
            bump(key, name, r["process_path"], is_external, r["risk"],
                 r["bytes_in"], r["bytes_out"], r["packets"])
        elif by == "port":
            if r["remote_port"] is None:
                continue
            key = f"{r['remote_port']}/{r['protocol']}"
            bump(key, service_name(r["remote_port"]), None, is_external, r["risk"],
                 r["bytes_in"], r["bytes_out"], r["packets"])
        elif by == "protocol":
            key = r["protocol"]
            bump(key, r["protocol"].upper(), None, is_external, r["risk"],
                 r["bytes_in"], r["bytes_out"], r["packets"])
        elif by == "country":
            # No local GeoIP database is bundled (keeps the tool fully
            # offline); fall back to the internal/external split, which is
            # the honest signal we actually have without calling out.
            key = "external" if is_external else "internal"
            label = "External" if is_external else "Internal / LAN"
            bump(key, label, r["remote_org"], is_external, r["risk"],
                 r["bytes_in"], r["bytes_out"], r["packets"])

    for g in groups.values():
        g["bytes_total"] = g["bytes_in"] + g["bytes_out"]

    total_bytes = sum(g["bytes_total"] for g in groups.values()) or 1
    items = sorted(groups.values(), key=lambda g: g["bytes_total"], reverse=True)[:limit]
    for it in items:
        it["share"] = round(it["bytes_total"] / total_bytes, 4)
    return items


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def _worse_risk(a: str, b: str) -> str:
    return a if _RISK_ORDER.get(a, 0) >= _RISK_ORDER.get(b, 0) else b

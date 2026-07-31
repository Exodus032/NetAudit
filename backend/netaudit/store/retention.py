"""Prune old raw packet rows on a timer to cap DB size. Aggregates
(stats_minutely, flows, devices, recommendations) are never pruned here --
only the high-volume `packets` table is."""
from __future__ import annotations

import time

from .. import config
from . import db as dbmod


def prune(db_path=None, retention_hours: float | None = None, max_rows: int | None = None, now: float | None = None) -> dict:
    retention_hours = retention_hours if retention_hours is not None else config.RETENTION_HOURS
    max_rows = max_rows if max_rows is not None else config.RETENTION_MAX_ROWS
    now = now if now is not None else time.time()

    conn = dbmod.get_conn(db_path)
    cutoff = now - retention_hours * 3600
    deleted_by_age = conn.execute("DELETE FROM packets WHERE ts_epoch < ?", (cutoff,)).rowcount or 0

    count_row = conn.execute("SELECT COUNT(*) AS c FROM packets").fetchone()
    total = count_row["c"]
    deleted_by_cap = 0
    if total > max_rows:
        excess = total - max_rows
        conn.execute(
            "DELETE FROM packets WHERE id IN (SELECT id FROM packets ORDER BY id ASC LIMIT ?)",
            (excess,),
        )
        deleted_by_cap = excess

    return {"deleted_by_age": deleted_by_age, "deleted_by_cap": deleted_by_cap}

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from .. import config
from ..store import stats as stats_store

router = APIRouter()

VALID_WINDOWS = {"5m", "15m", "1h", "24h", "all"}
VALID_TOP_BY = {"host", "process", "port", "protocol", "country"}


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


@router.get("/api/stats/summary")
def get_summary(request: Request, window: str = Query("5m")):
    if window not in VALID_WINDOWS:
        _error(400, "invalid_window", f"window must be one of {sorted(VALID_WINDOWS)}")
    db_path = request.app.state.db_path
    return stats_store.get_summary(window, db_path)


@router.get("/api/stats/timeseries")
def get_timeseries(request: Request, window: str = Query("1h"), bucket: int = Query(60)):
    if window not in VALID_WINDOWS:
        _error(400, "invalid_window", f"window must be one of {sorted(VALID_WINDOWS)}")
    if bucket < 1 or bucket > 3600:
        _error(400, "invalid_bucket", "bucket must be between 1 and 3600 seconds")
    db_path = request.app.state.db_path
    points = stats_store.get_timeseries(window, bucket, db_path)
    return {"window": window, "bucket_seconds": bucket, "points": points}


@router.get("/api/stats/top")
def get_top(request: Request, by: str = Query("host"), limit: int = Query(10), window: str = Query("5m")):
    if by not in VALID_TOP_BY:
        _error(400, "invalid_by", f"by must be one of {sorted(VALID_TOP_BY)}")
    if window not in VALID_WINDOWS:
        _error(400, "invalid_window", f"window must be one of {sorted(VALID_WINDOWS)}")
    if limit < 1:
        _error(400, "invalid_limit", "limit must be >= 1")
    # Part C item 6: hard server-side cap regardless of what's requested.
    limit = min(limit, config.MAX_LIMIT)
    db_path = request.app.state.db_path
    items = stats_store.get_top(by, limit, window, db_path)
    return {"by": by, "window": window, "items": items}

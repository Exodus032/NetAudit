from __future__ import annotations

import time

from fastapi import APIRouter, Request

from .. import config

router = APIRouter()


@router.get("/api/health")
def get_health(request: Request):
    pipeline = request.app.state.pipeline
    return {
        "status": "ok",
        "version": config.VERSION,
        "uptime_seconds": round(time.time() - pipeline.start_time, 1),
        "capture": pipeline.capture_status(),
    }

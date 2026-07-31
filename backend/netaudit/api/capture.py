from __future__ import annotations

from fastapi import APIRouter, Request

from ..models import CaptureStartRequest
from ..store import db as dbmod

router = APIRouter()


@router.get("/api/capture/status")
def capture_status(request: Request):
    return request.app.state.pipeline.capture_status()


@router.post("/api/capture/start")
def capture_start(body: CaptureStartRequest, request: Request):
    pipeline = request.app.state.pipeline
    pipeline.restart(body.interface_id)
    return pipeline.capture_status()


@router.post("/api/capture/stop")
def capture_stop(request: Request):
    pipeline = request.app.state.pipeline
    pipeline.stop()
    return pipeline.capture_status()


@router.post("/api/capture/clear")
def capture_clear(request: Request):
    dbmod.clear_all(request.app.state.db_path)
    return {"cleared": True}

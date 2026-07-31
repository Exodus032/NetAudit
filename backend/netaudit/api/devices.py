from __future__ import annotations

from fastapi import APIRouter, Request

from ..store import devices as devices_store

router = APIRouter()


@router.get("/api/devices")
def get_devices(request: Request):
    return {"devices": devices_store.query_devices(request.app.state.db_path)}

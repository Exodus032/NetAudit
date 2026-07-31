from __future__ import annotations

from fastapi import APIRouter, Request

from ..store import flows as flows_store
from ..timeutil import now_iso

router = APIRouter()


@router.get("/api/connections")
def get_connections(request: Request):
    db_path = request.app.state.db_path
    return {
        "generated_at": now_iso(),
        "connections": flows_store.query_connections(db_path),
    }

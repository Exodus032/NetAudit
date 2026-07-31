from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from ..rules import engine as rules_engine
from ..timeutil import now_iso

router = APIRouter()


@router.get("/api/recommendations")
def get_recommendations(request: Request, include_dismissed: bool = Query(False)):
    db_path = request.app.state.db_path
    return {
        "generated_at": now_iso(),
        "recommendations": rules_engine.list_recommendations(include_dismissed, db_path),
    }


@router.post("/api/recommendations/{rec_id}/dismiss")
def dismiss_recommendation(rec_id: str, request: Request):
    result = rules_engine.set_dismissed(rec_id, True, request.app.state.db_path)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": f"No recommendation {rec_id}"}})
    return result


@router.post("/api/recommendations/{rec_id}/restore")
def restore_recommendation(rec_id: str, request: Request):
    result = rules_engine.set_dismissed(rec_id, False, request.app.state.db_path)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": f"No recommendation {rec_id}"}})
    return result

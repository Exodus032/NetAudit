"""FastAPI router for Part A of API_CONTRACT_V2_SECURITY.md.

A bare `APIRouter` with no prefix -- every path below is the full path from
the contract. `PostureService` is resolved through the `get_posture_service`
dependency so the orchestrator can swap in a shared instance (and real
threat/hygiene contributors) via `app.dependency_overrides`.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from .models import PostureCheck, PostureReport, RescanRequest, SecurityScoreResponse
from .service import PostureService, get_posture_service

router = APIRouter()


@router.get("/api/posture", response_model=PostureReport)
def get_posture(
    category: Optional[str] = Query(default=None),
    include_pass: bool = Query(default=True),
    service: PostureService = Depends(get_posture_service),
) -> PostureReport:
    return service.get_report(category=category, include_pass=include_pass)


@router.get("/api/posture/checks/{check_id}", response_model=PostureCheck)
def get_posture_check(check_id: str, service: PostureService = Depends(get_posture_service)) -> PostureCheck:
    check = service.get_check(check_id)
    if check is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"no posture check with id {check_id!r}"}},
        )
    return check


@router.post("/api/posture/rescan", response_model=PostureReport)
def rescan_posture(
    body: Optional[RescanRequest] = None,
    service: PostureService = Depends(get_posture_service),
) -> PostureReport:
    categories = body.categories if body else None
    return service.rescan(categories=categories)


@router.get("/api/security/score", response_model=SecurityScoreResponse)
def get_security_score(service: PostureService = Depends(get_posture_service)) -> SecurityScoreResponse:
    return service.get_security_score()

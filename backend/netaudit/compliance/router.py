from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .models import ComplianceReport, FrameworksResponse
from .providers import PostureProvider, get_posture_provider
from .service import ComplianceService, get_compliance_service

router = APIRouter()


@router.get("/api/compliance/frameworks", response_model=FrameworksResponse)
def get_frameworks(service: ComplianceService = Depends(get_compliance_service)) -> FrameworksResponse:
    return service.frameworks()


@router.get("/api/compliance/{framework_id}", response_model=ComplianceReport)
def get_compliance_report(
    framework_id: str,
    service: ComplianceService = Depends(get_compliance_service),
    provider: PostureProvider = Depends(get_posture_provider),
) -> ComplianceReport:
    report = service.report(framework_id, provider)
    if report is None:
        raise HTTPException(status_code=404, detail=f"unknown compliance framework: {framework_id!r}")
    return report

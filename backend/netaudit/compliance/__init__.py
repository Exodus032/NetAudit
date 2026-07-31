"""Compliance mapping (Part F1/F2 of docs/API_CONTRACT_V3.md).

Maps NetAudit's 43 posture checks to real control identifiers in three
frameworks (`cis_win11`, `nist_800_53`, `essential_eight`). See README.md
for the honesty rules this package follows and which mappings are
confident versus deliberately omitted.
"""
from __future__ import annotations

from .models import (
    ComplianceControl,
    ComplianceReport,
    ComplianceSummary,
    ControlStatus,
    EvidenceCheck,
    FrameworkRef,
    FrameworkSummary,
    FrameworksResponse,
)
from .providers import PostureProvider, StaticPostureProvider, get_posture_provider
from .router import router
from .service import ComplianceService, get_compliance_service

__all__ = [
    "router",
    "ComplianceService",
    "get_compliance_service",
    "PostureProvider",
    "StaticPostureProvider",
    "get_posture_provider",
    "ComplianceReport",
    "ComplianceControl",
    "ComplianceSummary",
    "ControlStatus",
    "EvidenceCheck",
    "FrameworkRef",
    "FrameworkSummary",
    "FrameworksResponse",
]

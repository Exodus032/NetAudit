"""Pydantic response models for Part F1/F2 of docs/API_CONTRACT_V3.md
(compliance mapping). Field-for-field match to the frozen contract.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

ControlStatus = Literal["pass", "fail", "partial", "not_assessed"]


def _model() -> ConfigDict:
    return ConfigDict(populate_by_name=True)


class FrameworkSummary(BaseModel):
    """One element of `GET /api/compliance/frameworks`'s `frameworks` array."""

    model_config = _model()
    id: str
    label: str
    controls_mapped: int
    checks_mapped: int
    coverage_note: str


class FrameworksResponse(BaseModel):
    model_config = _model()
    frameworks: list[FrameworkSummary] = Field(default_factory=list)


class FrameworkRef(BaseModel):
    model_config = _model()
    id: str
    label: str


class EvidenceCheck(BaseModel):
    model_config = _model()
    check_id: str
    status: str  # the raw posture check status ("pass"/"warn"/"fail"/"error"/"skipped"), or "missing"


class ComplianceControl(BaseModel):
    model_config = _model()
    control_id: str
    title: str
    status: ControlStatus
    evidence_checks: list[EvidenceCheck] = Field(default_factory=list)
    rationale: str


class ComplianceSummary(BaseModel):
    model_config = _model()
    pass_: int = Field(alias="pass")
    fail: int
    partial: int
    not_assessed: int
    coverage_percent: int


class ComplianceReport(BaseModel):
    """Body of `GET /api/compliance/{framework_id}`."""

    model_config = _model()
    framework: FrameworkRef
    generated_at: str
    summary: ComplianceSummary
    disclaimer: str
    controls: list[ComplianceControl] = Field(default_factory=list)


class ErrorBody(BaseModel):
    model_config = _model()
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = _model()
    error: ErrorBody

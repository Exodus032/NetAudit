"""Pydantic response models for Part E7 of docs/API_CONTRACT_V3.md
(active LAN scan)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

JobStatus = Literal["running", "completed", "cancelled", "error"]


def _model() -> ConfigDict:
    return ConfigDict(populate_by_name=True)


class ScanRequest(BaseModel):
    model_config = _model()
    subnet: str
    ports: list[int]
    rate_limit_pps: int = 50


class ScanProgress(BaseModel):
    model_config = _model()
    scanned: int
    total: int


class HostResult(BaseModel):
    model_config = _model()
    ip: str
    open_ports: list[int] = Field(default_factory=list)


class ScanJob(BaseModel):
    """Body of `POST /api/devices/scan` and `GET /api/devices/scan/{job_id}`."""

    model_config = _model()
    job_id: str
    status: JobStatus
    subnet: str
    ports: list[int]
    rate_limit_pps: int
    progress: ScanProgress
    results: list[HostResult] = Field(default_factory=list)
    consent_notice: str
    started_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None


class ErrorBody(BaseModel):
    model_config = _model()
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = _model()
    error: ErrorBody

"""Pydantic response models for Part F3/F4 of docs/API_CONTRACT_V3.md
(alerting)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
ChannelKind = Literal["desktop", "webhook", "slack"]
ChannelStatus = Literal["delivered", "failed", "unavailable", "rate_limited", "suppressed"]

SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _model() -> ConfigDict:
    return ConfigDict(populate_by_name=True)


class QuietHours(BaseModel):
    model_config = _model()
    start: str  # "HH:MM", local time
    end: str


class AlertChannel(BaseModel):
    model_config = _model()
    id: str
    kind: ChannelKind
    enabled: bool
    url: Optional[str] = None
    template: Optional[str] = None
    last_status: Optional[str] = None
    last_attempt: Optional[str] = None


class AlertsConfig(BaseModel):
    """Body of `GET`/`PUT /api/alerts/config`."""

    model_config = _model()
    enabled: bool = False
    min_severity: Severity = "high"
    channels: list[AlertChannel] = Field(default_factory=list)
    rate_limit_per_hour: int = 20
    quiet_hours: Optional[QuietHours] = None


class AlertsConfigUpdate(BaseModel):
    """Body accepted by `PUT /api/alerts/config`. Same shape as
    `AlertsConfig` -- a separate model so the endpoint can validate the
    webhook URL rules (scheme, SSRF) before persisting, independent of the
    response model."""

    model_config = _model()
    enabled: bool = False
    min_severity: Severity = "high"
    channels: list[AlertChannel] = Field(default_factory=list)
    rate_limit_per_hour: int = 20
    quiet_hours: Optional[QuietHours] = None


class AlertTestRequest(BaseModel):
    model_config = _model()
    channel_id: str


class AlertTestResult(BaseModel):
    model_config = _model()
    channel_id: str
    status: ChannelStatus
    detail: Optional[str] = None
    attempted_at: str


class AlertHistoryChannelResult(BaseModel):
    model_config = _model()
    id: str
    status: ChannelStatus


class AlertHistoryItem(BaseModel):
    model_config = _model()
    id: str
    ts: str
    severity: Severity
    source: str
    source_id: str
    title: str
    channels: list[AlertHistoryChannelResult] = Field(default_factory=list)


class AlertHistoryResponse(BaseModel):
    model_config = _model()
    alerts: list[AlertHistoryItem] = Field(default_factory=list)


class ErrorBody(BaseModel):
    model_config = _model()
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = _model()
    error: ErrorBody

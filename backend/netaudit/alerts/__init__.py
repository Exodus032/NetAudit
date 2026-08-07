"""Alerting (Part F3/F4 of docs/API_CONTRACT_V3.md): config/channels,
webhook (https-only, SSRF-defended) and desktop delivery, and history.
"""
from __future__ import annotations

from .models import AlertChannel, AlertHistoryResponse, AlertsConfig, AlertsConfigUpdate, AlertTestResult
from .router import router
from .service import AlertConfigError, AlertService, get_alert_service
from .slack import build_slack_payload, send_slack
from .webhook import WebhookRejected, send_webhook

__all__ = [
    "router",
    "AlertService",
    "get_alert_service",
    "AlertConfigError",
    "AlertsConfig",
    "AlertsConfigUpdate",
    "AlertChannel",
    "AlertHistoryResponse",
    "AlertTestResult",
    "send_webhook",
    "send_slack",
    "build_slack_payload",
    "WebhookRejected",
]

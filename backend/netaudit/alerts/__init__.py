"""Alerting (Part F3/F4 of docs/API_CONTRACT_V3.md): config/channels,
webhook (https-only, SSRF-defended) and desktop delivery, history, and
IP reputation enrichment (AbuseIPDB/VirusTotal).
"""
from __future__ import annotations

from .enrichment import EnrichmentService, get_enrichment_service
from .models import (
    AlertChannel,
    AlertHistoryResponse,
    AlertsConfig,
    AlertsConfigUpdate,
    AlertTestResult,
    EnrichmentConfig,
    EnrichmentConfigUpdate,
    EnrichmentTestResult,
)
from .router import router
from .service import AlertConfigError, AlertService, get_alert_service
from .slack import build_slack_payload, send_slack
from .webhook import WebhookRejected, send_request, send_webhook

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
    "EnrichmentService",
    "get_enrichment_service",
    "EnrichmentConfig",
    "EnrichmentConfigUpdate",
    "EnrichmentTestResult",
    "send_webhook",
    "send_request",
    "send_slack",
    "build_slack_payload",
    "WebhookRejected",
]

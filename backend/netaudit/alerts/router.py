from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .desktop import DesktopSender
from .enrichment import EnrichmentConfigError, EnrichmentService, get_enrichment_service
from .models import (
    AlertHistoryResponse,
    AlertsConfig,
    AlertsConfigUpdate,
    AlertTestRequest,
    AlertTestResult,
    EnrichmentConfig,
    EnrichmentConfigUpdate,
    EnrichmentTestRequest,
    EnrichmentTestResult,
)
from .providers import get_desktop_sender, get_webhook_transport
from .service import AlertConfigError, AlertService, get_alert_service
from .webhook import Transport

router = APIRouter()


@router.get("/api/alerts/config", response_model=AlertsConfig)
def get_alerts_config(service: AlertService = Depends(get_alert_service)) -> AlertsConfig:
    return service.get_config()


@router.put("/api/alerts/config", response_model=AlertsConfig)
def put_alerts_config(body: AlertsConfigUpdate, service: AlertService = Depends(get_alert_service)) -> AlertsConfig:
    try:
        return service.update_config(body)
    except AlertConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


@router.post("/api/alerts/test", response_model=AlertTestResult)
def post_alerts_test(
    body: AlertTestRequest,
    service: AlertService = Depends(get_alert_service),
    transport: Transport = Depends(get_webhook_transport),
    desktop_sender: DesktopSender = Depends(get_desktop_sender),
) -> AlertTestResult:
    return service.test_channel(body.channel_id, transport=transport, desktop_sender=desktop_sender)


@router.get("/api/alerts/history", response_model=AlertHistoryResponse)
def get_alerts_history(limit: int = 200, service: AlertService = Depends(get_alert_service)) -> AlertHistoryResponse:
    return service.history(limit=limit)


@router.get("/api/alerts/enrichment", response_model=EnrichmentConfig)
def get_enrichment_config(service: EnrichmentService = Depends(get_enrichment_service)) -> EnrichmentConfig:
    return service.get_config()


@router.put("/api/alerts/enrichment", response_model=EnrichmentConfig)
def put_enrichment_config(body: EnrichmentConfigUpdate, service: EnrichmentService = Depends(get_enrichment_service)) -> EnrichmentConfig:
    try:
        return service.update_config(body)
    except EnrichmentConfigError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


@router.post("/api/alerts/enrichment/test", response_model=EnrichmentTestResult)
def post_enrichment_test(
    body: EnrichmentTestRequest,
    service: EnrichmentService = Depends(get_enrichment_service),
    transport: Transport = Depends(get_webhook_transport),
) -> EnrichmentTestResult:
    return service.test_provider(body.provider_id, transport=transport)

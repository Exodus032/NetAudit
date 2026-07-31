from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .models import ScanJob, ScanRequest
from .providers import InterfaceProvider, PortConnector, get_interface_provider, get_port_connector
from .service import LanScanService, ScanAlreadyRunning, get_lanscan_service
from .validation import ScanValidationError

router = APIRouter()


@router.post("/api/devices/scan", response_model=ScanJob)
def post_devices_scan(
    body: ScanRequest,
    service: LanScanService = Depends(get_lanscan_service),
    interfaces: InterfaceProvider = Depends(get_interface_provider),
    connector: PortConnector = Depends(get_port_connector),
) -> ScanJob:
    try:
        return service.start_scan(body.subnet, body.ports, body.rate_limit_pps, interfaces, connector)
    except ScanValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    except ScanAlreadyRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/devices/scan/{job_id}", response_model=ScanJob)
def get_devices_scan(job_id: str, service: LanScanService = Depends(get_lanscan_service)) -> ScanJob:
    job = service.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown scan job id: {job_id!r}")
    return job


@router.delete("/api/devices/scan/{job_id}", response_model=ScanJob)
def delete_devices_scan(job_id: str, service: LanScanService = Depends(get_lanscan_service)) -> ScanJob:
    job = service.cancel_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown scan job id: {job_id!r}")
    return job

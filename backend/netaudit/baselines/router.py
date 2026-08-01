from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .models import (
    BaselineCreateRequest,
    BaselineDiff,
    BaselineListItem,
    BaselineScheduleResponse,
    BaselineScheduleUpdateRequest,
    BaselinesResponse,
)
from .providers import (
    PostureProvider,
    ScoreProvider,
    TrafficProvider,
    get_posture_provider,
    get_score_provider,
    get_traffic_provider,
)
from .monitor import BaselineMonitor
from .service import BaselineService, get_baseline_service

router = APIRouter()


def get_baseline_monitor(request: Request) -> BaselineMonitor:
    return request.app.state.baseline_monitor


@router.post("/api/baselines", response_model=BaselineListItem)
def create_baseline(
    body: BaselineCreateRequest,
    service: BaselineService = Depends(get_baseline_service),
    posture: PostureProvider = Depends(get_posture_provider),
    traffic: TrafficProvider = Depends(get_traffic_provider),
    score: ScoreProvider = Depends(get_score_provider),
) -> BaselineListItem:
    if not body.label.strip():
        raise HTTPException(status_code=400, detail="label must not be empty")
    return service.create(body.label, posture, traffic, score)


@router.get("/api/baselines", response_model=BaselinesResponse)
def list_baselines_endpoint(service: BaselineService = Depends(get_baseline_service)) -> BaselinesResponse:
    return service.list()


@router.get("/api/baselines/schedule", response_model=BaselineScheduleResponse)
def get_schedule_endpoint(service: BaselineService = Depends(get_baseline_service)) -> BaselineScheduleResponse:
    return service.get_schedule()


@router.put("/api/baselines/schedule", response_model=BaselineScheduleResponse)
def update_schedule_endpoint(
    body: BaselineScheduleUpdateRequest,
    service: BaselineService = Depends(get_baseline_service),
    monitor: BaselineMonitor = Depends(get_baseline_monitor),
) -> BaselineScheduleResponse:
    schedule = service.update_schedule(body.enabled, body.interval_hours)
    monitor.wake()
    return schedule


@router.get("/api/baselines/{a}/diff/{b}", response_model=BaselineDiff)
def diff_baselines_endpoint(a: str, b: str, service: BaselineService = Depends(get_baseline_service)) -> BaselineDiff:
    result = service.diff(a, b)
    if result is None:
        raise HTTPException(status_code=404, detail="one or both baseline ids not found")
    return result

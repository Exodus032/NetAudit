"""Baseline snapshots and diff (Part E8 of docs/API_CONTRACT_V3.md)."""
from __future__ import annotations

from .models import BaselineDiff, BaselineListItem, BaselineRef, BaselinesResponse
from .providers import (
    PostureProvider,
    ScoreProvider,
    TrafficProvider,
    get_posture_provider,
    get_score_provider,
    get_traffic_provider,
)
from .router import router
from .service import BaselineService, get_baseline_service

__all__ = [
    "router",
    "BaselineService",
    "get_baseline_service",
    "PostureProvider",
    "TrafficProvider",
    "ScoreProvider",
    "get_posture_provider",
    "get_traffic_provider",
    "get_score_provider",
    "BaselineDiff",
    "BaselineListItem",
    "BaselineRef",
    "BaselinesResponse",
]

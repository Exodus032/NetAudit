"""NetAudit threat detection engine.

Self-contained: reads its own `TrafficSource` Protocol (never imports from
the rest of `netaudit`), persists to its own SQLite tables via `store.py`,
and exposes a bare `APIRouter` the orchestrator mounts alongside the v1
routers. See `README.md` in this directory for the full detector catalogue,
tunables, false positives, and the bundled indicator set's limitations.
"""
from __future__ import annotations

from .engine import ThreatEngine
from .models import Detector, Severity, Threat, ThreatCategory
from .router import router
from .source import ArpRecord, DnsRecord, FlowRecord, ListTrafficSource, PacketRecord, TrafficSource

__all__ = [
    "ThreatEngine",
    "router",
    "Threat",
    "Detector",
    "Severity",
    "ThreatCategory",
    "TrafficSource",
    "ListTrafficSource",
    "PacketRecord",
    "FlowRecord",
    "DnsRecord",
    "ArpRecord",
]

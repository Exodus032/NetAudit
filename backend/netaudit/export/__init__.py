"""Report generation and SIEM export (API Contract v3 Part E, sections
E5-E6).

Exposes a bare `APIRouter` (`router`). No import from `netaudit.threat`,
`netaudit.posture`, `netaudit.learn`, `netaudit.compliance` or
`netaudit.alerts` anywhere in this package -- see `provider.py` for the
`ReportDataProvider` seam used instead.
"""
from __future__ import annotations

from . import events, provider, report_data, report_html, report_markdown, reports_store, siem
from .router import router

__all__ = [
    "router",
    "events",
    "provider",
    "report_data",
    "report_html",
    "report_markdown",
    "reports_store",
    "siem",
]

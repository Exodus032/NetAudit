"""Decoupling seam for report generation (E5) and SIEM export (E6).

Per the task's ownership rules, this package must not import from
`netaudit.threat`, `netaudit.posture`, `netaudit.learn`,
`netaudit.compliance` or `netaudit.alerts` -- those are owned by other
agents. But E5 needs the security score, posture findings, threats, and
recommendations, and E6 needs threats/recommendations/posture too. Rather
than reach into those packages directly, this module defines a small
`Protocol` describing exactly the data this package needs as plain dicts,
a `StaticReportDataProvider` implementation for tests (and for local
development before the real provider is wired in), and a
`get_report_provider` FastAPI dependency the orchestrator can override with
a real implementation that actually calls into those packages.

Traffic and device data is read directly from `netaudit.store` (see
`netaudit/pcap/live_query.py`'s docstring for why that's fine and expected
-- this package only avoids reaching into the *other agents'* domains).
`traffic_summary()` and `devices()` are still part of the Protocol,
though, so a caller can substitute a filtered/scoped view (e.g. "devices
seen in an imported session") without this package caring how the data
was produced.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ReportDataProvider(Protocol):
    """Everything E5 (reports) and E6 (SIEM export) need, as plain dicts/
    lists of dicts matching the shapes already defined in
    API_CONTRACT.md / API_CONTRACT_V2_SECURITY.md (this package does not
    invent new shapes -- it only depends on the existing documented ones)."""

    def security_score(self) -> dict:
        """Shape of GET /api/security/score (API_CONTRACT_V2_SECURITY.md A5)."""
        ...

    def posture_report(self) -> dict:
        """Shape of GET /api/posture (API_CONTRACT_V2_SECURITY.md A1)."""
        ...

    def threats(self) -> list[dict]:
        """Shape of the `threats` array from GET /api/threats (API_CONTRACT_V2_SECURITY.md B1)."""
        ...

    def recommendations(self) -> list[dict]:
        """Shape of the `recommendations` array from GET /api/recommendations (API_CONTRACT.md #10)."""
        ...

    def traffic_summary(self) -> dict:
        """Shape of GET /api/stats/summary (API_CONTRACT.md #3)."""
        ...

    def devices(self) -> list[dict]:
        """Shape of the `devices` array from GET /api/devices (API_CONTRACT.md #9)."""
        ...


class StaticReportDataProvider:
    """A `ReportDataProvider` backed by fixed data supplied at construction
    time. Used by this package's own tests, and as the harmless default
    dependency result until the orchestrator overrides
    `get_report_provider` with something backed by the real posture/
    threat/rules engines."""

    def __init__(
        self,
        security_score: dict | None = None,
        posture_report: dict | None = None,
        threats: list[dict] | None = None,
        recommendations: list[dict] | None = None,
        traffic_summary: dict | None = None,
        devices: list[dict] | None = None,
    ):
        self._security_score = security_score or _EMPTY_SECURITY_SCORE
        self._posture_report = posture_report or _EMPTY_POSTURE_REPORT
        self._threats = threats or []
        self._recommendations = recommendations or []
        self._traffic_summary = traffic_summary or _EMPTY_TRAFFIC_SUMMARY
        self._devices = devices or []

    def security_score(self) -> dict:
        return self._security_score

    def posture_report(self) -> dict:
        return self._posture_report

    def threats(self) -> list[dict]:
        return self._threats

    def recommendations(self) -> list[dict]:
        return self._recommendations

    def traffic_summary(self) -> dict:
        return self._traffic_summary

    def devices(self) -> list[dict]:
        return self._devices


_EMPTY_SECURITY_SCORE = {
    "generated_at": None, "overall": 0, "grade": "F",
    "components": [], "history": [], "top_wins": [],
}

_EMPTY_POSTURE_REPORT = {
    "generated_at": None, "scan_duration_ms": 0, "score": 0, "grade": "F",
    "counts": {"pass": 0, "warn": 0, "fail": 0, "error": 0, "skipped": 0},
    "categories": [], "checks": [],
}

_EMPTY_TRAFFIC_SUMMARY = {
    "window": "5m", "generated_at": None, "packets_total": 0, "bytes_total": 0,
    "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
    "throughput_bps_in": 0, "throughput_bps_out": 0, "peak_throughput_bps": 0,
    "active_flows": 0, "unique_remote_hosts": 0, "unique_processes": 0,
    "tcp_packets": 0, "udp_packets": 0, "icmp_packets": 0, "other_packets": 0,
    "encrypted_bytes": 0, "plaintext_bytes": 0, "external_bytes": 0, "internal_bytes": 0,
    "open_alerts": 0, "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
}

# Module-level default instance: harmless, empty data. The orchestrator
# overrides `get_report_provider` (a FastAPI dependency) with something
# backed by the real posture/threat/rules engines; nothing in this module
# imports those packages.
_default_provider = StaticReportDataProvider()


def get_report_provider() -> ReportDataProvider:
    return _default_provider

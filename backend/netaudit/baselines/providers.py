"""Decoupling: baselines never imports `netaudit.posture` or anything else
outside this package. It defines the narrow shapes it needs as Protocols,
resolved through FastAPI dependencies the orchestrator overrides with real
implementations.
"""
from __future__ import annotations

from typing import Iterable, Optional, Protocol, runtime_checkable


@runtime_checkable
class PostureProvider(Protocol):
    """Plain-dict posture checks -- same minimal shape as
    `compliance.providers.PostureProvider`, defined separately here on
    purpose (this package must not import `compliance`, or anything else,
    to get it) so the two packages can evolve independently."""

    def checks(self) -> Iterable[dict]: ...


@runtime_checkable
class TrafficProvider(Protocol):
    """Current traffic profile: who we've talked to, and what's listening
    locally. `peers()` returns remote IP/host strings; `listeners()`
    returns dicts with at least `port` (int) and `process` (str)."""

    def peers(self) -> Iterable[str]: ...

    def listeners(self) -> Iterable[dict]: ...


@runtime_checkable
class ScoreProvider(Protocol):
    """Composite security score at snapshot time. Returns a plain dict with
    `posture` (int, always present), `threats` (int or None -- omitted
    when no threat-detection contributor is wired in), and `overall` (int).
    Mirrors the shape of posture's own `SecurityScoreResponse` without
    importing it."""

    def security_score(self) -> dict: ...


class StaticPostureProvider:
    def __init__(self, checks: Optional[list[dict]] = None) -> None:
        self._checks = list(checks or [])

    def checks(self) -> list[dict]:
        return list(self._checks)


class StaticTrafficProvider:
    def __init__(self, peers: Optional[list[str]] = None, listeners: Optional[list[dict]] = None) -> None:
        self._peers = list(peers or [])
        self._listeners = list(listeners or [])

    def peers(self) -> list[str]:
        return list(self._peers)

    def listeners(self) -> list[dict]:
        return list(self._listeners)


class StaticScoreProvider:
    def __init__(self, posture: int = 0, threats: Optional[int] = None, overall: Optional[int] = None) -> None:
        self._posture = posture
        self._threats = threats
        self._overall = overall if overall is not None else posture

    def security_score(self) -> dict:
        return {"posture": self._posture, "threats": self._threats, "overall": self._overall}


_default_posture: Optional[PostureProvider] = None
_default_traffic: Optional[TrafficProvider] = None
_default_score: Optional[ScoreProvider] = None


def get_posture_provider() -> PostureProvider:
    global _default_posture
    if _default_posture is None:
        _default_posture = StaticPostureProvider([])
    return _default_posture


def get_traffic_provider() -> TrafficProvider:
    global _default_traffic
    if _default_traffic is None:
        _default_traffic = StaticTrafficProvider([], [])
    return _default_traffic


def get_score_provider() -> ScoreProvider:
    global _default_score
    if _default_score is None:
        _default_score = StaticScoreProvider(0, None, 0)
    return _default_score

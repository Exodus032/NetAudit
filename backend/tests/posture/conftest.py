"""Shared test fixtures for the posture package's test suite.

Nothing in this suite touches PowerShell, the registry, or any real socket --
`FakeProbes` stands in for `posture.base.ProbeContext` with pre-baked
`ProbeResult` values, so every test is deterministic on any machine
(including CI, elevated or not).
"""
from __future__ import annotations

from typing import Optional

import pytest

from netaudit.posture.probes.runner import ProbeResult


def ok(data=None) -> ProbeResult:
    """A successful probe result carrying `data`."""
    return ProbeResult(ok=True, data=data)


def err(message: str = "simulated probe failure") -> ProbeResult:
    """A failed probe result -- feeding this to a check's `gather()` (via
    `require_ok`, or read directly) is how we exercise the `error` path."""
    return ProbeResult(ok=False, error=message)


class FakeProbes:
    """Drop-in replacement for `posture.base.ProbeContext`. Duck-typed --
    `Check.gather()` only ever calls `.ps()`, `.registry()`, `.net()`, and
    `.is_admin()`, so this doesn't need to subclass anything."""

    def __init__(
        self,
        ps: Optional[dict[str, ProbeResult]] = None,
        registry: Optional[dict[str, ProbeResult]] = None,
        net: Optional[dict[str, ProbeResult]] = None,
        admin: bool = False,
    ) -> None:
        self._ps = ps or {}
        self._registry = registry or {}
        self._net = net or {}
        self._admin = admin

    def ps(self, key: str, timeout: Optional[float] = None) -> ProbeResult:
        if key not in self._ps:
            raise KeyError(f"test did not stub ps probe {key!r}")
        return self._ps[key]

    def registry(self, key: str) -> ProbeResult:
        if key not in self._registry:
            raise KeyError(f"test did not stub registry probe {key!r}")
        return self._registry[key]

    def net(self, key: str) -> ProbeResult:
        if key not in self._net:
            raise KeyError(f"test did not stub net probe {key!r}")
        return self._net[key]

    def is_admin(self) -> bool:
        return self._admin


@pytest.fixture
def fake_probes():
    """Factory fixture: `fake_probes(ps={...}, registry={...}, net={...})`."""

    def _make(**kwargs) -> FakeProbes:
        return FakeProbes(**kwargs)

    return _make

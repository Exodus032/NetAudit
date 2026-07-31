"""The `Check` ABC every posture check implements, plus `ProbeContext`, the
per-scan memoized handle checks use to reach the probe layer.

Design note on testability: `gather()` is the only method allowed to touch
the OS (via `probes`), and it must return a small dict of `ProbeResult`
values. `evaluate()` is pure -- raw dict in, `CheckOutcome` out -- so a unit
test can call `check.evaluate({...fabricated ProbeResult...})` directly for
the pass/fail cases without mocking anything, and call `check.run(fake_ctx)`
(or make `gather` raise) to exercise the error path. See
backend/tests/posture/test_checks_*.py.
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Optional

from .models import CheckStatus, EvidenceItem, PostureCheck, Remediation, Severity
from .probes import netprobe, powershell, registry_probe
from .probes.runner import ProbeResult, is_admin

_CIS_REFERENCES_PATH = Path(__file__).parent / "data" / "cis_references.json"


def _load_cis_references() -> dict[str, list[str]]:
    try:
        with open(_CIS_REFERENCES_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_")}


CIS_REFERENCES: dict[str, list[str]] = _load_cis_references()


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with millisecond precision and a literal `Z`
    suffix, matching every timestamp in API_CONTRACT.md / V2."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


class CheckError(Exception):
    """Raise from `gather()` or `evaluate()` to produce a clean, explained
    `status: "error"` (e.g. "requires administrator privileges"). Any other
    exception is also caught by `Check.run()` and reported as an error, but
    with a generic message -- prefer raising this where the reason is known."""


@dataclass
class CheckOutcome:
    status: CheckStatus
    observed: str
    expected: str = ""
    evidence: list[dict] = field(default_factory=list)  # each: {"label": str, "value": str}


class ProbeContext:
    """Per-scan cache in front of the probe layer. Every distinct probe key
    is executed at most once per scan no matter how many checks need it."""

    def __init__(self) -> None:
        self._cache: dict[str, ProbeResult] = {}
        self._admin: Optional[bool] = None

    def ps(self, key: str, timeout: Optional[float] = None) -> ProbeResult:
        cache_key = f"ps:{key}"
        if cache_key not in self._cache:
            kwargs = {} if timeout is None else {"timeout": timeout}
            self._cache[cache_key] = powershell.run_ps(key, **kwargs)
        return self._cache[cache_key]

    def registry(self, key: str) -> ProbeResult:
        cache_key = f"registry:{key}"
        if cache_key not in self._cache:
            self._cache[cache_key] = registry_probe.read(key)
        return self._cache[cache_key]

    def net(self, key: str) -> ProbeResult:
        cache_key = f"net:{key}"
        if cache_key not in self._cache:
            self._cache[cache_key] = netprobe.run(key)
        return self._cache[cache_key]

    def is_admin(self) -> bool:
        if self._admin is None:
            self._admin = is_admin()
        return self._admin


def as_list(value: object) -> list:
    """`ConvertTo-Json` collapses a single-element PowerShell array down to a
    bare object instead of a one-element JSON array. Every check that reads
    a PS probe expected to return zero-or-more objects should pass its data
    through this to normalize both shapes to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def require_ok(result: ProbeResult, what: str, admin_hint: bool = False) -> object:
    """Common `gather()` helper: unwrap a `ProbeResult`, raising `CheckError`
    with a clear, specific message if the underlying probe failed. Pass
    `admin_hint=True` when this data source is known to need elevation, so
    the message tells the user that rather than leaving them guessing."""
    if not result.ok:
        message = f"could not read {what}: {result.error}"
        if admin_hint:
            message += " -- this check likely requires running NetAudit as Administrator"
        raise CheckError(message)
    return result.data


class Check(ABC):
    """One row in the posture catalogue. Subclasses are stateless -- all the
    per-run data comes in through `gather()`'s `probes` argument."""

    id: ClassVar[str]
    category: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    score_weight: ClassVar[int]
    why_it_matters: ClassVar[str]
    remediation: ClassVar[Remediation]
    references: ClassVar[list[str]] = []

    @abstractmethod
    def gather(self, probes: ProbeContext) -> dict:
        """Call into `probes` and return whatever raw dict `evaluate()`
        expects. May raise `CheckError` (explained) or let a probe-layer
        exception propagate (generic) -- both become status="error"."""

    @abstractmethod
    def evaluate(self, raw: dict) -> CheckOutcome:
        """Pure: raw dict -> CheckOutcome. No I/O."""

    def run(self, probes: ProbeContext) -> PostureCheck:
        start = time.monotonic()
        try:
            raw = self.gather(probes)
            outcome = self.evaluate(raw)
        except CheckError as exc:
            outcome = CheckOutcome(status="error", observed=str(exc))
        except Exception as exc:  # a single broken check must never fail the scan
            outcome = CheckOutcome(status="error", observed=f"check raised an unexpected error: {exc}")
        duration_ms = int((time.monotonic() - start) * 1000)
        references = list(self.references) or list(CIS_REFERENCES.get(self.id, []))
        return PostureCheck(
            id=self.id,
            category=self.category,
            title=self.title,
            status=outcome.status,
            severity=self.severity,
            score_weight=self.score_weight,
            observed=outcome.observed,
            expected=outcome.expected,
            why_it_matters=self.why_it_matters,
            evidence=[EvidenceItem(**e) for e in outcome.evidence],
            remediation=self.remediation,
            references=references,
            checked_at=utc_now_iso(),
            duration_ms=duration_ms,
        )

"""Orchestration: run the catalogue concurrently under a wall-clock budget,
cache the result, compute scores/grades, and serve the composite
`/api/security/score` with optional external contributors.

`get_posture_service` is the FastAPI dependency `router.py` resolves against.
The orchestrator overrides it with
`app.dependency_overrides[get_posture_service] = lambda: my_service` to wire
in a shared instance (and/or real `threats`/`hygiene` contributors) without
this package importing anything from the rest of `netaudit`.
"""
from __future__ import annotations

import concurrent.futures
import time
from collections import deque
from typing import Optional, Protocol, Sequence, runtime_checkable

from .base import CIS_REFERENCES, Check, ProbeContext, utc_now_iso
from .models import (
    CategoryScore,
    Counts,
    PostureCheck,
    PostureReport,
    ScoreComponent,
    ScoreHistoryPoint,
    SecurityScoreResponse,
    TopWin,
)
from .registry import CATEGORY_LABELS, checks_by_category
from .scoring import compute_score, grade_for_score

DEFAULT_SCAN_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_WORKERS = 8
HISTORY_MAX_POINTS = 168  # "up to 168 hourly points" per API_CONTRACT_V2_SECURITY.md A5

# Base weights for /api/security/score per the contract's worked example
# (posture 0.4, threats 0.35, hygiene 0.25). When a component is unavailable
# (no contributor supplied, or the contributor reports it can't score right
# now) it is omitted entirely and the remaining weights are renormalized to
# sum to 1 -- see `_score_components()`.
BASE_WEIGHTS: dict[str, float] = {"posture": 0.4, "threats": 0.35, "hygiene": 0.25}
BASE_LABELS: dict[str, str] = {"posture": "Host configuration", "threats": "Active threats", "hygiene": "Traffic hygiene"}


@runtime_checkable
class ScoreContributor(Protocol):
    """Optional external scorer for the `threats` / `hygiene` components of
    `/api/security/score`. Implemented and supplied by whichever package owns
    threat detection / traffic hygiene -- this package only defines the
    shape it expects, and never imports an implementation."""

    id: str  # "threats" or "hygiene"
    label: str

    def compute_score(self) -> Optional[int]:
        """Return 0-100, or None if this component can't be scored right now
        (e.g. no data collected yet). Returning None omits the component."""
        ...


def _error_check(check: Check, message: str) -> PostureCheck:
    """Build a PostureCheck with status="error" for a check that didn't
    finish in time or whose thread raised outside of `Check.run()`'s own
    try/except (defensive; `run()` already catches everything it can)."""
    references = list(check.references) or list(CIS_REFERENCES.get(check.id, []))
    return PostureCheck(
        id=check.id,
        category=check.category,
        title=check.title,
        status="error",
        severity=check.severity,
        score_weight=check.score_weight,
        observed=message,
        expected="",
        why_it_matters=check.why_it_matters,
        evidence=[],
        remediation=check.remediation,
        references=references,
        checked_at=utc_now_iso(),
        duration_ms=0,
    )


def _build_report(checks: list[PostureCheck], scan_duration_ms: int) -> PostureReport:
    counts = Counts(
        **{
            "pass": sum(1 for c in checks if c.status == "pass"),
            "warn": sum(1 for c in checks if c.status == "warn"),
            "fail": sum(1 for c in checks if c.status == "fail"),
            "error": sum(1 for c in checks if c.status == "error"),
            "skipped": sum(1 for c in checks if c.status == "skipped"),
        }
    )
    overall_score = compute_score(checks)
    grade = grade_for_score(overall_score)

    categories: list[CategoryScore] = []
    for cat_id, label in CATEGORY_LABELS.items():
        cat_checks = [c for c in checks if c.category == cat_id]
        if not cat_checks:
            continue
        categories.append(
            CategoryScore(id=cat_id, label=label, score=compute_score(cat_checks), checks=[c.id for c in cat_checks])
        )

    return PostureReport(
        generated_at=utc_now_iso(),
        scan_duration_ms=scan_duration_ms,
        score=overall_score,
        grade=grade,
        counts=counts,
        categories=categories,
        checks=checks,
    )


def _effort_for(check: PostureCheck) -> str:
    """Heuristic for `top_wins[].effort`: no listed command -> medium
    (manual/unclear); an irreversible fix -> high; a reversible fix with a
    documented risk -> medium; anything else -> low."""
    if not check.remediation.commands:
        return "medium"
    cmd = check.remediation.commands[0]
    if not cmd.reversible:
        return "high"
    if cmd.risk_note:
        return "medium"
    return "low"


def _compute_top_wins(report: PostureReport, limit: int = 5) -> list[TopWin]:
    actionable = [c for c in report.checks if c.status in ("fail", "warn")]
    actionable.sort(key=lambda c: c.score_weight, reverse=True)
    return [
        TopWin(id=c.id, kind="posture", title=c.remediation.summary or c.title, score_gain=c.score_weight, effort=_effort_for(c))
        for c in actionable[:limit]
    ]


class PostureService:
    def __init__(
        self,
        scan_timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
        max_workers: int = DEFAULT_MAX_WORKERS,
        contributors: Optional[Sequence[ScoreContributor]] = None,
    ) -> None:
        self._scan_timeout_seconds = scan_timeout_seconds
        self._max_workers = max_workers
        self._contributors = list(contributors or [])
        self._cached_report: Optional[PostureReport] = None
        self._score_history: "deque[ScoreHistoryPoint]" = deque(maxlen=HISTORY_MAX_POINTS)

    # -- scanning ------------------------------------------------------

    def scan(self, categories: Optional[list[str]] = None) -> PostureReport:
        """Run the catalogue (or just `categories`, if given) concurrently,
        bounded to `scan_timeout_seconds` wall time total. A check that
        hasn't finished by the deadline is reported as `error`, never
        silently dropped, and never blocks the response past the deadline.
        """
        start = time.monotonic()
        grouped = checks_by_category()

        wanted: Optional[set[str]] = set(categories) if categories else None
        if wanted is not None:
            selected = {cat: chks for cat, chks in grouped.items() if cat in wanted}
        else:
            selected = grouped
        to_run: list[Check] = [c for chks in selected.values() for c in chks]

        probes = ProbeContext()
        results: list[PostureCheck] = []
        if to_run:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers)
            try:
                future_map = {executor.submit(check.run, probes): check for check in to_run}
                done, not_done = concurrent.futures.wait(future_map.keys(), timeout=self._scan_timeout_seconds)
                # `wait()` returns `done`/`not_done` as sets -- iterating them
                # directly would order results by whichever thread happened
                # to finish first, making category `checks` lists (and the
                # ordering of `checks` in the report) nondeterministic run to
                # run. Collect into a by-id map instead and rebuild the list
                # in the original, stable `to_run` submission order.
                by_check_id: dict[str, PostureCheck] = {}
                for future in done:
                    check = future_map[future]
                    try:
                        by_check_id[check.id] = future.result()
                    except Exception as exc:  # pragma: no cover - Check.run() already catches its own errors
                        by_check_id[check.id] = _error_check(check, f"check crashed outside its own error handling: {exc}")
                for future in not_done:
                    check = future_map[future]
                    by_check_id[check.id] = _error_check(
                        check, f"did not complete within the {self._scan_timeout_seconds:g}s scan budget"
                    )
                results = [by_check_id[check.id] for check in to_run]
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

        # Partial rescan: keep the cached results for categories we didn't
        # just run, so the response is always a complete report.
        if wanted is not None and self._cached_report is not None:
            kept = [c for c in self._cached_report.checks if c.category not in wanted]
            results = kept + results
        elif wanted is not None and self._cached_report is None:
            # No cache yet -- a scoped rescan can't produce a complete report,
            # so fall back to running everything once.
            return self.scan(categories=None)

        scan_duration_ms = int((time.monotonic() - start) * 1000)
        report = _build_report(results, scan_duration_ms)
        self._cached_report = report
        return report

    def rescan(self, categories: Optional[list[str]] = None) -> PostureReport:
        """`POST /api/posture/rescan`. Always safe to call repeatedly."""
        return self.scan(categories=categories)

    def get_report(self, category: Optional[str] = None, include_pass: bool = True) -> PostureReport:
        """`GET /api/posture`. Serves the cache, scanning once on first call.
        `category` scopes the whole report (score/grade/counts/categories
        included) to that one category. `include_pass` only trims passing
        checks out of the `checks` list -- counts/score/categories still
        reflect the true, full result so the header numbers are never
        silently hidden by the list filter."""
        if self._cached_report is None:
            self.scan()
        report = self._cached_report
        assert report is not None

        if category is not None:
            scoped_checks = [c for c in report.checks if c.category == category]
            report = _build_report(scoped_checks, report.scan_duration_ms)
            report = report.model_copy(update={"generated_at": self._cached_report.generated_at})

        if not include_pass:
            filtered_checks = [c for c in report.checks if c.status != "pass"]
            report = report.model_copy(update={"checks": filtered_checks})

        return report

    def get_check(self, check_id: str) -> Optional[PostureCheck]:
        """`GET /api/posture/checks/{id}`."""
        if self._cached_report is None:
            self.scan()
        assert self._cached_report is not None
        for check in self._cached_report.checks:
            if check.id == check_id:
                return check
        return None

    # -- composite score -------------------------------------------------

    def get_security_score(self) -> SecurityScoreResponse:
        """`GET /api/security/score`. `threats`/`hygiene` come from the
        optional `contributors` supplied at construction time -- when none
        are supplied (or a contributor returns None), that component is
        omitted from `components` and the remaining weights are renormalized
        to sum to 1, per API_CONTRACT_V2_SECURITY.md A5."""
        if self._cached_report is None:
            self.scan()
        report = self._cached_report
        assert report is not None

        present: list[tuple[str, str, int]] = [("posture", BASE_LABELS["posture"], report.score)]
        for contributor in self._contributors:
            score = contributor.compute_score()
            if score is None:
                continue
            present.append((contributor.id, contributor.label, score))

        weight_sum = sum(BASE_WEIGHTS.get(cid, 0.0) for cid, _, _ in present)
        components: list[ScoreComponent] = []
        if weight_sum > 0:
            for cid, label, score in present:
                weight = BASE_WEIGHTS.get(cid, 0.0) / weight_sum
                components.append(ScoreComponent(id=cid, label=label, score=score, weight=round(weight, 4), grade=grade_for_score(score)))

        if components:
            overall = round(sum(c.score * c.weight for c in components))
        else:
            overall = 0
        grade = grade_for_score(overall)

        now_iso = utc_now_iso()
        self._score_history.append(ScoreHistoryPoint(t=now_iso, overall=overall))

        return SecurityScoreResponse(
            generated_at=now_iso,
            overall=overall,
            grade=grade,
            components=components,
            history=list(self._score_history),
            top_wins=_compute_top_wins(report),
        )


# ---------------------------------------------------------------------------
# FastAPI dependency wiring
# ---------------------------------------------------------------------------

_default_service: Optional[PostureService] = None


def get_posture_service() -> PostureService:
    """FastAPI dependency `router.py` depends on. The orchestrator overrides
    this via `app.dependency_overrides[get_posture_service] = lambda: svc`
    to inject a shared instance (and real threats/hygiene contributors)."""
    global _default_service
    if _default_service is None:
        _default_service = PostureService()
    return _default_service


if __name__ == "__main__":
    # Manual smoke test: `python -m netaudit.posture.service` runs a real
    # scan against this machine and prints a summary. Not part of the test
    # suite (which uses fake probes exclusively so it's deterministic and
    # doesn't require Windows or admin).
    import json as _json

    svc = PostureService()
    rep = svc.scan()
    print(f"scan_duration_ms={rep.scan_duration_ms} score={rep.score} grade={rep.grade}")
    print("counts:", rep.counts.model_dump(by_alias=True))
    for chk in rep.checks:
        print(f"[{chk.status:7s}] {chk.id:35s} {chk.observed}")
    score_resp = svc.get_security_score()
    print(_json.dumps(score_resp.model_dump(by_alias=True), indent=2)[:2000])

"""PostureService: scanning, wall-clock bounding, caching, filtering,
partial rescan, and the composite /api/security/score renormalization.

Every test here replaces `netaudit.posture.service.checks_by_category` with
a small set of fake `Check` subclasses -- no real PowerShell/registry/psutil
probing happens, so this is deterministic on any machine.
"""
from __future__ import annotations

import time

import pytest

from netaudit.posture import service as service_module
from netaudit.posture.base import Check, CheckOutcome, ProbeContext
from netaudit.posture.models import Remediation
from netaudit.posture.service import PostureService


def _make_check(check_id: str, check_category: str, check_status: str, weight: int = 5, sleep_seconds: float = 0.0):
    # NOTE: the class body below assigns class attributes named `category`
    # and `score_weight` -- if this function's own parameters were named the
    # same, `category = category` inside the class body would raise
    # NameError (a class body's own assignment target shadows the enclosing
    # function's variable of the same name before the RHS is evaluated).
    # Distinct parameter names sidestep that entirely.
    class _FakeCheck(Check):
        id = check_id
        category = check_category
        title = f"Fake check {check_id}"
        severity = "medium"
        score_weight = weight
        why_it_matters = "This is a fake check used only in the posture test suite."
        remediation = Remediation(summary="No action needed; this is a test fixture.", commands=[])

        def gather(self, probes: ProbeContext) -> dict:
            if sleep_seconds:
                time.sleep(sleep_seconds)
            return {}

        def evaluate(self, raw: dict) -> CheckOutcome:
            return CheckOutcome(status=check_status, observed=f"fake observed value for {check_id}")

    return _FakeCheck()


@pytest.fixture
def patch_catalogue(monkeypatch):
    def _patch(grouped: dict[str, list[Check]]):
        monkeypatch.setattr(service_module, "checks_by_category", lambda: grouped)

    return _patch


def test_scan_aggregates_counts_categories_and_score(patch_catalogue):
    grouped = {
        "firewall": [
            _make_check("f1", "firewall", "pass", weight=10),
            _make_check("f2", "firewall", "fail", weight=10),
        ],
        "smb": [_make_check("s1", "smb", "warn", weight=8)],
    }
    patch_catalogue(grouped)
    svc = PostureService()
    report = svc.scan()

    assert report.counts.pass_ == 1
    assert report.counts.fail == 1
    assert report.counts.warn == 1
    assert report.counts.error == 0
    assert report.counts.skipped == 0
    assert {c.id for c in report.categories} == {"firewall", "smb"}
    firewall_cat = next(c for c in report.categories if c.id == "firewall")
    assert firewall_cat.checks == ["f1", "f2"]
    # firewall: pass(10) fail(10) -> 100*10/20 = 50
    assert firewall_cat.score == 50
    assert report.scan_duration_ms >= 0


def test_scan_bounds_wall_clock_time_and_reports_error_for_stragglers(patch_catalogue):
    grouped = {
        "firewall": [
            _make_check("fast", "firewall", "pass"),
            _make_check("slow", "firewall", "pass", sleep_seconds=2.0),
        ],
    }
    patch_catalogue(grouped)
    svc = PostureService(scan_timeout_seconds=0.2, max_workers=2)
    start = time.monotonic()
    report = svc.scan()
    elapsed = time.monotonic() - start

    assert elapsed < 1.5, "scan must not block past its timeout waiting for a straggler"
    by_id = {c.id: c for c in report.checks}
    assert by_id["fast"].status == "pass"
    assert by_id["slow"].status == "error"
    assert "scan budget" in by_id["slow"].observed


def test_get_report_category_filter_scopes_score_and_checks(patch_catalogue):
    grouped = {
        "firewall": [_make_check("f1", "firewall", "pass", weight=10)],
        "smb": [_make_check("s1", "smb", "fail", weight=10)],
    }
    patch_catalogue(grouped)
    svc = PostureService()
    svc.scan()

    scoped = svc.get_report(category="smb")
    assert [c.id for c in scoped.checks] == ["s1"]
    assert scoped.score == 0  # only the failing smb check is in scope
    assert [c.id for c in scoped.categories] == ["smb"]


def test_get_report_include_pass_false_only_trims_the_checks_list(patch_catalogue):
    grouped = {
        "firewall": [
            _make_check("f1", "firewall", "pass", weight=10),
            _make_check("f2", "firewall", "fail", weight=10),
        ],
    }
    patch_catalogue(grouped)
    svc = PostureService()
    svc.scan()

    filtered = svc.get_report(include_pass=False)
    assert [c.id for c in filtered.checks] == ["f2"]
    # counts/score must still reflect the true, full result
    assert filtered.counts.pass_ == 1
    assert filtered.score == 50


def test_get_check_returns_none_for_unknown_id(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "pass")]})
    svc = PostureService()
    svc.scan()
    assert svc.get_check("does_not_exist") is None
    assert svc.get_check("f1") is not None


def test_rescan_partial_preserves_other_categories(patch_catalogue, monkeypatch):
    grouped = {
        "firewall": [_make_check("f1", "firewall", "pass")],
        "smb": [_make_check("s1", "smb", "fail")],
    }
    patch_catalogue(grouped)
    svc = PostureService()
    first = svc.scan()
    smb_check_before = next(c for c in first.checks if c.id == "s1")

    # Rescan only firewall; smb's cached result must be carried forward untouched.
    updated_grouped = {
        "firewall": [_make_check("f1", "firewall", "fail")],  # flip firewall's result
        "smb": [_make_check("s1", "smb", "pass")],  # would flip smb too, but shouldn't be re-run
    }
    monkeypatch.setattr(service_module, "checks_by_category", lambda: updated_grouped)
    second = svc.rescan(categories=["firewall"])

    by_id = {c.id: c for c in second.checks}
    assert by_id["f1"].status == "fail"  # firewall was rescanned
    assert by_id["s1"].status == smb_check_before.status == "fail"  # smb was preserved from cache


def test_rescan_is_safe_to_call_repeatedly(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "pass")]})
    svc = PostureService()
    for _ in range(3):
        report = svc.rescan()
        assert report.counts.pass_ == 1


def test_security_score_without_contributors_renormalizes_to_posture_only(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "pass", weight=10)]})
    svc = PostureService()
    score = svc.get_security_score()

    assert [c.id for c in score.components] == ["posture"]
    assert score.components[0].weight == 1.0
    assert score.overall == score.components[0].score == 100


def test_security_score_with_one_contributor_renormalizes_weights(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "fail", weight=10)]})  # posture score = 0

    class _ThreatsContributor:
        id = "threats"
        label = "Active threats"

        def compute_score(self):
            return 100

    svc = PostureService(contributors=[_ThreatsContributor()])
    score = svc.get_security_score()

    ids = {c.id: c for c in score.components}
    assert set(ids) == {"posture", "threats"}
    # base weights posture=0.4, threats=0.35 -> renormalized over 0.75
    assert ids["posture"].weight == pytest.approx(0.4 / 0.75, abs=1e-4)
    assert ids["threats"].weight == pytest.approx(0.35 / 0.75, abs=1e-4)
    # overall = 0*postureWeight + 100*threatsWeight = 100 * (0.35/0.75) ~= 46.67 -> 47
    assert score.overall == round(100 * (0.35 / 0.75))


def test_security_score_contributor_returning_none_is_omitted(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "pass", weight=10)]})

    class _UnavailableContributor:
        id = "hygiene"
        label = "Traffic hygiene"

        def compute_score(self):
            return None

    svc = PostureService(contributors=[_UnavailableContributor()])
    score = svc.get_security_score()
    assert [c.id for c in score.components] == ["posture"]


def test_security_score_history_ring_buffer_caps_at_168(patch_catalogue):
    patch_catalogue({"firewall": [_make_check("f1", "firewall", "pass")]})
    svc = PostureService()
    for _ in range(200):
        score = svc.get_security_score()
    assert len(score.history) == 168

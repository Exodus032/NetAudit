"""Combination logic: turns a framework's control definitions plus a
`PostureProvider`'s current checks into a `ComplianceReport`.

Combination rule (deterministic, documented, and unit-tested in
`tests/compliance/test_combination_logic.py`):

    assessed = [status for each mapped check_id that is present in the
                provider AND whose status is one of pass/warn/fail]
                (a check_id that's missing from the provider, or present
                but status error/skipped, contributes no evidence)

    - no check_ids at all, or no assessed evidence -> not_assessed
    - every assessed status is "pass"                -> pass
    - every assessed status is "fail"                -> fail
    - anything else (mixed, or any "warn" present)    -> partial

`not_assessed` never becomes `pass` -- there is no code path from "no
evidence" to a positive result.
"""
from __future__ import annotations

from typing import Optional

from ..timeutil import now_iso
from .loader import ControlDef, FrameworkDef, load_all_frameworks, load_framework
from .models import (
    ComplianceControl,
    ComplianceReport,
    ComplianceSummary,
    EvidenceCheck,
    FrameworkRef,
    FrameworkSummary,
    FrameworksResponse,
)
from .providers import PostureProvider

DISCLAIMER = (
    "Indicative only. NetAudit assesses network-facing configuration on this "
    "host and is not a certified compliance audit. A 'pass' reflects only "
    "the specific technical signal NetAudit can observe, not full "
    "satisfaction of the control in an organizational or audit sense. "
    "NetAudit cannot see anything off this host: no policy documents, no "
    "other machines, no procedural controls, no evidence of what happened "
    "historically. 'not_assessed' means NetAudit has no way to see that "
    "control at all -- it is never inferred as a pass."
)

_ASSESSED_STATUSES = ("pass", "warn", "fail")


def _combine(statuses: list[str]) -> str:
    assessed = [s for s in statuses if s in _ASSESSED_STATUSES]
    if not assessed:
        return "not_assessed"
    if all(s == "pass" for s in assessed):
        return "pass"
    if all(s == "fail" for s in assessed):
        return "fail"
    return "partial"


def _rationale(control: ControlDef, evidence: list[EvidenceCheck], status: str) -> str:
    if not control.check_ids:
        return "No posture check is mapped to this control; NetAudit cannot observe it from a single host's network-facing configuration."
    if status == "not_assessed":
        ids = ", ".join(control.check_ids)
        return f"The mapped check(s) ({ids}) returned no usable evidence on this scan (missing, error, or skipped)."
    parts = ", ".join(f"{e.check_id}={e.status}" for e in evidence)
    if status == "pass":
        return f"All mapped checks passed: {parts}."
    if status == "fail":
        return f"All mapped checks failed: {parts}."
    return f"Mixed results across mapped checks: {parts}."


def _build_control(control: ControlDef, checks_by_id: dict[str, dict]) -> ComplianceControl:
    evidence: list[EvidenceCheck] = []
    statuses: list[str] = []
    for check_id in control.check_ids:
        found = checks_by_id.get(check_id)
        if found is None:
            evidence.append(EvidenceCheck(check_id=check_id, status="missing"))
            continue
        status = str(found.get("status", "missing"))
        evidence.append(EvidenceCheck(check_id=check_id, status=status))
        statuses.append(status)

    control_status = _combine(statuses)
    rationale = _rationale(control, evidence, control_status)
    return ComplianceControl(
        control_id=control.control_id,
        title=control.title,
        status=control_status,  # type: ignore[arg-type]
        evidence_checks=evidence,
        rationale=rationale,
    )


def build_report(framework: FrameworkDef, provider: PostureProvider) -> ComplianceReport:
    checks_by_id = {str(c["id"]): c for c in provider.checks() if "id" in c}
    controls = [_build_control(c, checks_by_id) for c in framework.controls]

    counts = {"pass": 0, "fail": 0, "partial": 0, "not_assessed": 0}
    for c in controls:
        counts[c.status] += 1
    total = len(controls)
    assessed_total = total - counts["not_assessed"]
    coverage_percent = round(100 * assessed_total / total) if total else 0

    return ComplianceReport(
        framework=FrameworkRef(id=framework.id, label=framework.label),
        generated_at=now_iso(),
        summary=ComplianceSummary(
            **{
                "pass": counts["pass"],
                "fail": counts["fail"],
                "partial": counts["partial"],
                "not_assessed": counts["not_assessed"],
                "coverage_percent": coverage_percent,
            }
        ),
        disclaimer=DISCLAIMER,
        controls=controls,
    )


def build_frameworks_response(data_dir=None) -> FrameworksResponse:
    frameworks = load_all_frameworks(data_dir)
    return FrameworksResponse(
        frameworks=[
            FrameworkSummary(
                id=f.id,
                label=f.label,
                controls_mapped=f.controls_mapped,
                checks_mapped=f.checks_mapped,
                coverage_note=f.coverage_note,
            )
            for f in frameworks
        ]
    )


class ComplianceService:
    """Thin orchestration wrapper the router depends on. Kept stateless
    beyond the (lru_cache'd) data-file load -- posture data is always
    fetched fresh from the provider on every call, never cached here,
    since staleness in a compliance report is worse than a bit of
    recomputation."""

    def __init__(self, data_dir=None) -> None:
        self._data_dir = data_dir

    def frameworks(self) -> FrameworksResponse:
        return build_frameworks_response(self._data_dir)

    def report(self, framework_id: str, provider: PostureProvider) -> Optional[ComplianceReport]:
        framework = load_framework(framework_id, self._data_dir)
        if framework is None:
            return None
        return build_report(framework, provider)


_default_service: Optional[ComplianceService] = None


def get_compliance_service() -> ComplianceService:
    global _default_service
    if _default_service is None:
        _default_service = ComplianceService()
    return _default_service

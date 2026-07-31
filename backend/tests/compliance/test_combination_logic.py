from __future__ import annotations

from netaudit.compliance.loader import ControlDef, FrameworkDef
from netaudit.compliance.providers import StaticPostureProvider
from netaudit.compliance.service import build_report


def _fw(control: ControlDef) -> FrameworkDef:
    return FrameworkDef(id="test_fw", label="Test Framework", coverage_note="unit test fixture", controls=(control,))


def test_single_check_pass():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "pass"
    assert report.summary.pass_ == 1


def test_single_check_fail():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "fail"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "fail"


def test_missing_check_is_not_assessed_never_pass():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([])  # "a" never ran / not supplied
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "not_assessed"


def test_error_status_check_is_not_assessed():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "error"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "not_assessed"


def test_skipped_status_check_is_not_assessed():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "skipped"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "not_assessed"


def test_no_check_ids_at_all_is_not_assessed():
    control = ControlDef(control_id="C1", title="T1", check_ids=())
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "not_assessed"


def test_all_pass_across_multiple_checks_is_pass():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a", "b"))
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}, {"id": "b", "status": "pass"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "pass"


def test_all_fail_across_multiple_checks_is_fail():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a", "b"))
    provider = StaticPostureProvider([{"id": "a", "status": "fail"}, {"id": "b", "status": "fail"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "fail"


def test_mixed_pass_and_fail_is_partial():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a", "b"))
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}, {"id": "b", "status": "fail"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "partial"


def test_warn_alone_is_partial_not_pass():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "warn"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "partial"


def test_one_errored_one_passed_ignores_the_errored_one():
    # One of two mapped checks has no evidence (error) -- the control
    # status should be driven entirely by the assessed one, not diluted
    # into "partial" by evidence that doesn't actually exist.
    control = ControlDef(control_id="C1", title="T1", check_ids=("a", "b"))
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}, {"id": "b", "status": "error"}])
    report = build_report(_fw(control), provider)
    assert report.controls[0].status == "pass"
    evidence_by_id = {e.check_id: e.status for e in report.controls[0].evidence_checks}
    assert evidence_by_id == {"a": "pass", "b": "error"}


def test_summary_counts_and_coverage_percent():
    controls = (
        ControlDef(control_id="C1", title="T1", check_ids=("a",)),
        ControlDef(control_id="C2", title="T2", check_ids=("b",)),
        ControlDef(control_id="C3", title="T3", check_ids=("c",)),
        ControlDef(control_id="C4", title="T4", check_ids=()),
    )
    fw = FrameworkDef(id="test_fw", label="Test", coverage_note="unit test fixture", controls=controls)
    provider = StaticPostureProvider(
        [{"id": "a", "status": "pass"}, {"id": "b", "status": "fail"}, {"id": "c", "status": "warn"}]
    )
    report = build_report(fw, provider)
    assert report.summary.pass_ == 1
    assert report.summary.fail == 1
    assert report.summary.partial == 1
    assert report.summary.not_assessed == 1
    # 3 of 4 controls assessed -> 75%
    assert report.summary.coverage_percent == 75


def test_disclaimer_always_present_and_nontrivial():
    control = ControlDef(control_id="C1", title="T1", check_ids=("a",))
    provider = StaticPostureProvider([{"id": "a", "status": "pass"}])
    report = build_report(_fw(control), provider)
    assert "not a certified compliance audit" in report.disclaimer

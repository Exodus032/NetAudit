from __future__ import annotations

from netaudit.baselines.providers import StaticPostureProvider, StaticScoreProvider, StaticTrafficProvider
from netaudit.baselines.service import capture_snapshot, diff_baselines


def _snap(db_path, label, checks, peers=None, listeners=None, posture=0, threats=None, overall=None):
    return capture_snapshot(
        label,
        StaticPostureProvider(checks),
        StaticTrafficProvider(peers or [], listeners or []),
        StaticScoreProvider(posture, threats, overall),
        db_path=db_path,
    )


def test_fixed_check(db_path):
    b1 = _snap(db_path, "before", [{"id": "smb_signing_required", "status": "fail"}])
    b2 = _snap(db_path, "after", [{"id": "smb_signing_required", "status": "pass"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert [t.id for t in diff.checks.fixed] == ["smb_signing_required"]
    assert diff.checks.fixed[0].from_ == "fail"
    assert diff.checks.fixed[0].to == "pass"
    assert diff.checks.regressed == []


def test_regressed_check(db_path):
    b1 = _snap(db_path, "before", [{"id": "firewall_logging_enabled", "status": "pass"}])
    b2 = _snap(db_path, "after", [{"id": "firewall_logging_enabled", "status": "fail"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert [t.id for t in diff.checks.regressed] == ["firewall_logging_enabled"]
    assert diff.checks.fixed == []


def test_unchanged_check(db_path):
    b1 = _snap(db_path, "before", [{"id": "uac_enabled", "status": "pass"}])
    b2 = _snap(db_path, "after", [{"id": "uac_enabled", "status": "pass"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.checks.unchanged_count == 1
    assert diff.checks.fixed == [] and diff.checks.regressed == []


def test_warn_to_pass_is_fixed_and_pass_to_warn_is_regressed(db_path):
    b1 = _snap(db_path, "before", [{"id": "a", "status": "warn"}, {"id": "b", "status": "pass"}])
    b2 = _snap(db_path, "after", [{"id": "a", "status": "pass"}, {"id": "b", "status": "warn"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert [t.id for t in diff.checks.fixed] == ["a"]
    assert [t.id for t in diff.checks.regressed] == ["b"]


def test_check_added_since_older_snapshot_is_not_a_regression(db_path):
    # "b" didn't exist in the older snapshot at all -- even though its
    # current status is "fail", it must never appear in `regressed`.
    b1 = _snap(db_path, "before", [{"id": "a", "status": "pass"}])
    b2 = _snap(db_path, "after", [{"id": "a", "status": "pass"}, {"id": "b", "status": "fail"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.checks.regressed == []
    assert diff.checks.fixed == []
    assert [a.id for a in diff.checks.added] == ["b"]
    assert diff.checks.added[0].status == "fail"


def test_check_removed_since_older_snapshot_is_not_a_fix(db_path):
    # "b" existed and was failing in the older snapshot but doesn't exist
    # in the newer one (e.g. check retired) -- must never appear in `fixed`.
    b1 = _snap(db_path, "before", [{"id": "a", "status": "pass"}, {"id": "b", "status": "fail"}])
    b2 = _snap(db_path, "after", [{"id": "a", "status": "pass"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.checks.fixed == []
    assert diff.checks.regressed == []
    assert [r.id for r in diff.checks.removed] == ["b"]


def test_error_status_transition_is_inconclusive_not_regressed(db_path):
    b1 = _snap(db_path, "before", [{"id": "bitlocker_status", "status": "pass"}])
    b2 = _snap(db_path, "after", [{"id": "bitlocker_status", "status": "error"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.checks.regressed == []
    assert diff.checks.fixed == []
    assert [t.id for t in diff.checks.inconclusive] == ["bitlocker_status"]


def test_new_and_removed_listeners(db_path):
    b1 = _snap(
        db_path, "before", [], listeners=[{"port": 445, "process": "System"}, {"port": 3389, "process": "svchost.exe"}]
    )
    b2 = _snap(db_path, "after", [], listeners=[{"port": 445, "process": "System"}, {"port": 8080, "process": "node.exe"}])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert [l.port for l in diff.new_listeners] == [8080]
    assert diff.new_listeners[0].process == "node.exe"
    assert [l.port for l in diff.removed_listeners] == [3389]


def test_new_peers(db_path):
    b1 = _snap(db_path, "before", [], peers=["10.0.0.1"])
    b2 = _snap(db_path, "after", [], peers=["10.0.0.1", "203.0.113.9"])
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.new_peers == ["203.0.113.9"]


def test_score_delta_basic(db_path):
    b1 = _snap(db_path, "before", [], posture=48, threats=90, overall=60)
    b2 = _snap(db_path, "after", [], posture=70, threats=85, overall=75)
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.score_delta.posture == 22
    assert diff.score_delta.threats == -5
    assert diff.score_delta.overall == 15


def test_score_delta_missing_threats_is_zero_not_a_guess(db_path):
    b1 = _snap(db_path, "before", [], posture=48, threats=None, overall=48)
    b2 = _snap(db_path, "after", [], posture=70, threats=85, overall=75)
    diff = diff_baselines(b1.id, b2.id, db_path)
    assert diff.score_delta.threats == 0
    assert diff.score_delta.posture == 22


def test_diff_unknown_id_returns_none(db_path):
    b1 = _snap(db_path, "before", [])
    assert diff_baselines(b1.id, "does_not_exist", db_path) is None
    assert diff_baselines("does_not_exist", b1.id, db_path) is None

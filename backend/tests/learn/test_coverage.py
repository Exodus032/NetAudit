"""Coverage against the *real* detector/rule/check registries -- imports
`netaudit.threat`, `netaudit.posture` and `netaudit.rules` directly, which
`learn`'s own production code never does (see `learn/__init__.py`). Those
packages are owned and actively worked on elsewhere; if an import fails for
any reason (missing dependency, package mid-refactor, moved module), this
skips cleanly rather than failing the learn test suite for someone else's
work in progress.
"""
from __future__ import annotations

import pytest

from netaudit.learn import content


def test_every_detector_has_an_explanation():
    threat_detectors = pytest.importorskip("netaudit.threat.detectors", reason="netaudit.threat not importable")
    detectors = threat_detectors.all_detectors()
    ids = {d.id for d in detectors}
    assert ids, "no detectors found -- registry import likely broken, not just empty"
    covered = {item_id for (kind, item_id) in content.EXPLANATIONS if kind == "detector"}
    missing = sorted(ids - covered)
    assert not missing, f"explanations.json is missing detector(s): {missing}"


def test_every_rule_has_an_explanation():
    builtin = pytest.importorskip("netaudit.rules.builtin", reason="netaudit.rules not importable")
    ids = {cls.rule_id for cls in builtin.ALL_RULES}
    assert ids, "no rules found -- registry import likely broken, not just empty"
    covered = {item_id for (kind, item_id) in content.EXPLANATIONS if kind == "rule"}
    missing = sorted(ids - covered)
    assert not missing, f"explanations.json is missing rule(s): {missing}"


def test_every_posture_check_has_an_explanation():
    registry = pytest.importorskip("netaudit.posture.registry", reason="netaudit.posture not importable")
    checks = registry.all_checks()
    ids = {c.id for c in checks}
    assert ids, "no posture checks found -- registry import likely broken, not just empty"
    covered = {item_id for (kind, item_id) in content.EXPLANATIONS if kind == "check"}
    missing = sorted(ids - covered)
    assert not missing, f"explanations.json is missing posture check(s): {missing}"


def test_no_stale_detector_explanations():
    """The reverse direction: an explanation for an id that no longer
    exists in the real registry is a sign this content has drifted from
    the code it describes. Not fatal on its own (a detector could be
    renamed mid-refactor by the owning agent), but worth surfacing."""
    threat_detectors = pytest.importorskip("netaudit.threat.detectors", reason="netaudit.threat not importable")
    ids = {d.id for d in threat_detectors.all_detectors()}
    covered = {item_id for (kind, item_id) in content.EXPLANATIONS if kind == "detector"}
    stale = sorted(covered - ids)
    assert not stale, f"explanations.json has detector entries for id(s) no longer in the registry: {stale}"


def test_no_stale_check_explanations():
    registry = pytest.importorskip("netaudit.posture.registry", reason="netaudit.posture not importable")
    ids = {c.id for c in registry.all_checks()}
    covered = {item_id for (kind, item_id) in content.EXPLANATIONS if kind == "check"}
    stale = sorted(covered - ids)
    assert not stale, f"explanations.json has check entries for id(s) no longer in the registry: {stale}"

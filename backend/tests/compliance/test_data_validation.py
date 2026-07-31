"""Every compliance data file must be structurally valid, and every
check_id it references must be a real posture check id. The posture import
is guarded and test-only (this package's production code never imports
posture) -- skip rather than fail if posture isn't importable in this
environment.
"""
from __future__ import annotations

import pytest

from netaudit.compliance.loader import FRAMEWORK_IDS, FrameworkDataError, load_all_frameworks, load_framework

try:
    from netaudit.posture.registry import all_checks

    REAL_CHECK_IDS = {c.id for c in all_checks()}
    POSTURE_AVAILABLE = True
except Exception:
    REAL_CHECK_IDS = set()
    POSTURE_AVAILABLE = False


def test_all_three_frameworks_load():
    frameworks = load_all_frameworks()
    assert {f.id for f in frameworks} == set(FRAMEWORK_IDS)


@pytest.mark.parametrize("framework_id", FRAMEWORK_IDS)
def test_framework_has_nonempty_coverage_note(framework_id):
    fw = load_framework(framework_id)
    assert fw.coverage_note.strip()
    assert len(fw.coverage_note) > 40  # a real explanation, not a placeholder


@pytest.mark.parametrize("framework_id", FRAMEWORK_IDS)
def test_framework_controls_have_unique_ids(framework_id):
    fw = load_framework(framework_id)
    ids = [c.control_id for c in fw.controls]
    assert len(ids) == len(set(ids)), f"duplicate control_id in {framework_id}"


@pytest.mark.parametrize("framework_id", FRAMEWORK_IDS)
def test_framework_controls_have_titles(framework_id):
    fw = load_framework(framework_id)
    for c in fw.controls:
        assert c.title.strip()


@pytest.mark.skipif(not POSTURE_AVAILABLE, reason="netaudit.posture not importable in this environment")
@pytest.mark.parametrize("framework_id", FRAMEWORK_IDS)
def test_every_referenced_check_id_is_real(framework_id):
    fw = load_framework(framework_id)
    dangling = fw.all_check_ids - REAL_CHECK_IDS
    assert not dangling, f"{framework_id} references unknown posture check ids: {sorted(dangling)}"


@pytest.mark.skipif(not POSTURE_AVAILABLE, reason="netaudit.posture not importable in this environment")
def test_posture_catalogue_has_43_checks():
    # Sanity check on the fixture itself, per posture/README.md.
    assert len(REAL_CHECK_IDS) == 43


def test_unknown_framework_id_returns_none():
    assert load_framework("not_a_real_framework") is None


def test_malformed_file_raises_frameworkdataerror(tmp_path):
    bad = tmp_path / "cis_win11.json"
    bad.write_text('{"id": "cis_win11", "label": "x"}', encoding="utf-8")
    with pytest.raises(FrameworkDataError):
        load_framework("cis_win11", tmp_path)


def test_essential_eight_has_at_least_one_unassessable_strategy_with_no_checks():
    # Documents the deliberate "listed but structurally not_assessed" design
    # for Essential Eight strategies this tool cannot see at all.
    fw = load_framework("essential_eight")
    empty = [c for c in fw.controls if not c.check_ids]
    assert len(empty) >= 5


def test_controls_mapped_excludes_empty_check_id_controls():
    fw = load_framework("essential_eight")
    total_controls = len(fw.controls)
    mapped = fw.controls_mapped
    assert mapped < total_controls
    assert mapped == sum(1 for c in fw.controls if c.check_ids)

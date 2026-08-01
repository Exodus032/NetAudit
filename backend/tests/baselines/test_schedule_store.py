from __future__ import annotations

import pytest

from netaudit.baselines.service import BaselineService
from netaudit.baselines.store import insert_baseline


def test_schedule_defaults_to_disabled_with_24_hour_interval(db_path):
    schedule = BaselineService(db_path).get_schedule()

    assert schedule.enabled is False
    assert schedule.interval_hours == 24
    assert schedule.last_success_at is None
    assert schedule.last_error is None
    assert schedule.next_due_at is None


@pytest.mark.parametrize("interval_hours", [6, 12, 24, 48, 168])
def test_schedule_persists_each_allowed_interval(db_path, interval_hours):
    service = BaselineService(db_path)

    updated = service.update_schedule(enabled=True, interval_hours=interval_hours)
    persisted = BaselineService(db_path).get_schedule()

    assert updated.enabled is True
    assert updated.interval_hours == interval_hours
    assert persisted.enabled is True
    assert persisted.interval_hours == interval_hours


def test_schedule_rejects_unsupported_interval(db_path):
    with pytest.raises(ValueError, match="interval_hours"):
        BaselineService(db_path).update_schedule(enabled=True, interval_hours=23)


def test_pruning_scheduled_snapshots_older_than_90_days_preserves_manual_snapshots(db_path):
    manual = insert_baseline(
        label="manual-old",
        checks=[],
        peers=[],
        listeners=[],
        posture_score=0,
        threats_score=None,
        overall_score=0,
        captured_at="2025-12-31T00:00:00.000Z",
        db_path=db_path,
    )
    old_scheduled = insert_baseline(
        label="scheduled-old",
        checks=[],
        peers=[],
        listeners=[],
        posture_score=0,
        threats_score=None,
        overall_score=0,
        origin="scheduled",
        captured_at="2025-12-31T00:00:00.000Z",
        db_path=db_path,
    )
    recent_scheduled = insert_baseline(
        label="scheduled-recent",
        checks=[],
        peers=[],
        listeners=[],
        posture_score=0,
        threats_score=None,
        overall_score=0,
        origin="scheduled",
        captured_at="2026-05-01T00:00:00.000Z",
        db_path=db_path,
    )

    BaselineService(db_path).prune_scheduled("2026-04-01T00:00:00.000Z")

    remaining = {baseline.id: baseline for baseline in BaselineService(db_path).list().baselines}
    assert set(remaining) == {manual.id, recent_scheduled.id}
    assert remaining[manual.id].origin == "manual"
    assert remaining[recent_scheduled.id].origin == "scheduled"
    assert old_scheduled.id not in remaining

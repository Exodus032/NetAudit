from __future__ import annotations

import sqlite3
import threading

import pytest

from netaudit.baselines import store as baseline_store
from netaudit.baselines.providers import StaticPostureProvider, StaticScoreProvider, StaticTrafficProvider
from netaudit.baselines.service import BaselineService
from netaudit.baselines.store import insert_baseline, mark_schedule_error


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


def test_create_scheduled_preserves_captured_at_and_sets_next_due_at(db_path):
    service = BaselineService(db_path)
    service.update_schedule(enabled=True, interval_hours=6)

    created = service.create_scheduled(
        StaticPostureProvider([{"id": "firewall", "status": "pass"}]),
        StaticTrafficProvider([], []),
        StaticScoreProvider(50, None, 50),
        captured_at="2026-04-01T00:00:00.000Z",
    )
    schedule = service.get_schedule()

    assert created.origin == "scheduled"
    assert created.captured_at == "2026-04-01T00:00:00.000Z"
    assert schedule.last_success_at == "2026-04-01T00:00:00.000Z"
    assert schedule.next_due_at == "2026-04-01T06:00:00.000Z"


def test_schedule_error_persists(db_path):
    mark_schedule_error("capture failed", db_path)

    assert BaselineService(db_path).get_schedule().last_error == "capture failed"


def _create_legacy_baselines_table(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE baselines (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            checks_json TEXT NOT NULL DEFAULT '[]',
            peers_json TEXT NOT NULL DEFAULT '[]',
            listeners_json TEXT NOT NULL DEFAULT '[]',
            posture_score INTEGER NOT NULL DEFAULT 0,
            threats_score INTEGER,
            overall_score INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO baselines (
            id, label, captured_at, checks_json, peers_json, listeners_json,
            posture_score, threats_score, overall_score
        ) VALUES ('legacy', 'Existing', '2026-01-01T00:00:00.000Z', '[]', '[]', '[]', 0, NULL, 0);
        """
    )
    conn.close()


def test_concurrent_legacy_migration_keeps_existing_baselines_as_manual(db_path, monkeypatch):
    _create_legacy_baselines_table(db_path)
    baseline_store.reset_for_tests(db_path)
    migration_lock = threading.Lock()
    monkeypatch.setattr(baseline_store, "_schema_lock", migration_lock, raising=False)
    barrier = threading.Barrier(2)
    errors = []

    class BarrierRows:
        def __init__(self, rows):
            self._rows = list(rows)

        def __iter__(self):
            if migration_lock.acquire(blocking=False):
                migration_lock.release()
                barrier.wait(timeout=5)
            return iter(self._rows)

    class ConnectionWrapper:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args):
            rows = self._conn.execute(sql, *args)
            if sql.startswith("PRAGMA table_info(baselines)"):
                return BarrierRows(rows)
            return rows

        def __getattr__(self, name):
            return getattr(self._conn, name)

    def get_conn(_db_path=None):
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return ConnectionWrapper(conn)

    monkeypatch.setattr(baseline_store.dbmod, "get_conn", get_conn)

    def migrate():
        try:
            baseline_store.list_baselines(db_path)
        except Exception as error:
            errors.append(error)

    workers = [threading.Thread(target=migrate), threading.Thread(target=migrate)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not any(worker.is_alive() for worker in workers)
    assert errors == []
    assert baseline_store.list_baselines(db_path)[0].origin == "manual"

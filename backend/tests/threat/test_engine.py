"""Engine: dedupe by stable id, occurrence counting, first/last seen,
cooldown -> resolved, acknowledgement persistence across a simulated
engine restart (a fresh ThreatEngine built on the same store/db_path)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.base import Detector, Finding
from netaudit.threat.engine import ThreatEngine
from netaudit.threat.models import Evidence, MitreRef, TunableSpec
from netaudit.threat.source import ListTrafficSource
from netaudit.threat.store import ThreatStore

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


class _AlwaysFiresDetector(Detector):
    """A trivial detector for engine tests: fires exactly once per tick
    with a fixed key, so we control exactly when/whether it re-fires."""

    id = "test_always_fires"
    label = "Test always fires"
    category = "anomaly"
    description = "test detector"
    default_severity = "medium"
    mitre = [MitreRef(tactic="TA0011", tactic_name="Command and Control")]
    tunables: list[TunableSpec] = []
    cooldown_seconds = 300.0

    def __init__(self, should_fire_fn=None):
        self._should_fire_fn = should_fire_fn or (lambda since, until: True)

    def run(self, source, since, until, tunables):
        if not self._should_fire_fn(since, until):
            return []
        return [Finding(
            key="fixed-key",
            title="Test finding",
            severity="medium",
            confidence=0.7,
            summary="test summary",
            detail="test detail",
            observed_at=until,
            evidence=[Evidence(label="x", value="y")],
        )]


def _engine(db_path, detector=None, window_seconds=3600.0):
    store = ThreatStore(db_path)
    detectors = [detector or _AlwaysFiresDetector()]
    return ThreatEngine(ListTrafficSource(), store, detectors=detectors, window_seconds=window_seconds)


def test_dedupe_by_stable_id_across_ticks(db_path):
    engine = _engine(db_path)
    r1 = engine.run_once(now=NOW)
    r2 = engine.run_once(now=NOW + timedelta(minutes=1))

    assert len(r1) == 1
    assert len(r2) == 1
    assert r1[0]["id"] == r2[0]["id"]


def test_occurrence_counting_increments(db_path):
    engine = _engine(db_path)
    engine.run_once(now=NOW)
    engine.run_once(now=NOW + timedelta(minutes=1))
    result = engine.run_once(now=NOW + timedelta(minutes=2))

    assert result[0]["occurrences"] == 3


def test_first_seen_stable_last_seen_advances(db_path):
    engine = _engine(db_path)
    engine.run_once(now=NOW)
    result = engine.run_once(now=NOW + timedelta(minutes=10))

    assert result[0]["first_seen"] == "2026-07-31T14:00:00.000Z"
    assert result[0]["last_seen"] == "2026-07-31T14:10:00.000Z"


def test_cooldown_transitions_to_resolved(db_path):
    fire_flags = {"fire": True}
    detector = _AlwaysFiresDetector(should_fire_fn=lambda since, until: fire_flags["fire"])
    engine = _engine(db_path, detector=detector)

    engine.run_once(now=NOW)
    threat_id = engine.list_threats()[1][0]["id"]
    assert engine.get_threat(threat_id)["status"] == "active"

    # Stop firing and advance well past the 300s cooldown.
    fire_flags["fire"] = False
    engine.run_once(now=NOW + timedelta(seconds=600))

    assert engine.get_threat(threat_id)["status"] == "resolved"


def test_cooldown_does_not_resolve_before_it_elapses(db_path):
    fire_flags = {"fire": True}
    detector = _AlwaysFiresDetector(should_fire_fn=lambda since, until: fire_flags["fire"])
    engine = _engine(db_path, detector=detector)

    engine.run_once(now=NOW)
    threat_id = engine.list_threats()[1][0]["id"]

    fire_flags["fire"] = False
    engine.run_once(now=NOW + timedelta(seconds=60))  # well under the 300s cooldown

    assert engine.get_threat(threat_id)["status"] == "active"


def test_acknowledgement_persists_across_engine_restart(db_path):
    engine = _engine(db_path)
    engine.run_once(now=NOW)
    threat_id = engine.list_threats()[1][0]["id"]

    result = engine.acknowledge(threat_id, note="known telemetry agent")
    assert result["status"] == "acknowledged"

    # Simulate a restart: brand-new ThreatEngine instance over the same db file.
    restarted = _engine(db_path)
    restarted_threat = restarted.get_threat(threat_id)
    assert restarted_threat["status"] == "acknowledged"
    assert restarted_threat["acknowledged_note"] == "known telemetry agent"


def test_unacknowledge_reverts_to_active(db_path):
    engine = _engine(db_path)
    engine.run_once(now=NOW)
    threat_id = engine.list_threats()[1][0]["id"]
    engine.acknowledge(threat_id, note="known")
    result = engine.unacknowledge(threat_id)

    assert result["status"] == "active"
    assert engine.get_threat(threat_id)["acknowledged_note"] is None


def test_acknowledged_threat_keeps_status_when_refired(db_path):
    engine = _engine(db_path)
    engine.run_once(now=NOW)
    threat_id = engine.list_threats()[1][0]["id"]
    engine.acknowledge(threat_id, note="known")

    engine.run_once(now=NOW + timedelta(minutes=1))

    threat = engine.get_threat(threat_id)
    assert threat["status"] == "acknowledged"
    assert threat["occurrences"] == 2


def test_detector_settings_persist_across_restart(db_path):
    engine = _engine(db_path)
    error = engine.patch_detector("test_always_fires", {"enabled": False})[1]
    assert error is None

    restarted = _engine(db_path)
    detectors = {d["id"]: d for d in restarted.list_detectors()}
    assert detectors["test_always_fires"]["enabled"] is False


def test_patch_detector_rejects_unknown_id(db_path):
    engine = _engine(db_path)
    updated, error = engine.patch_detector("does_not_exist", {"enabled": False})
    assert updated is None
    assert error == "not_found"

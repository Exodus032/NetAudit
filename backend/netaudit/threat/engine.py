"""Runs detectors on a schedule over a window, dedupes findings into stable
threats, tracks first_seen/last_seen/occurrences and status transitions
(active -> resolved via cooldown, active <-> acknowledged via the API),
and persists acknowledgements + tunables to SQLite via `ThreatStore`.

`run_once` is the whole engine tick. A caller (a background scheduler, or
a test) decides when to call it; the engine itself never spawns threads or
reads the wall clock except through the `now` parameter, so it is fully
deterministic and testable.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from .detectors import Detector, Finding, all_detectors
from .models import Action, Detector as DetectorModel, DetectorMitreRef, Evidence, Indicator, TunableSpec
from .source import TrafficSource
from .store import ThreatStore

DEFAULT_WINDOW_SECONDS = 3600.0


def _slug(key: str) -> str:
    out = []
    for ch in key.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in ".-_":
            out.append(ch)
        else:
            out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:60] or "finding"


def _hash4(*parts: str) -> str:
    h = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return h[:4]


def _epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _iso_z(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class _DetectorRuntime:
    detector: Detector
    enabled: bool
    tunables: dict
    fired_count: int
    last_fired_epoch: Optional[float]


class ThreatEngine:
    def __init__(
        self,
        source: TrafficSource,
        store: ThreatStore,
        detectors: Optional[list[Detector]] = None,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.source = source
        self.store = store
        self.window_seconds = window_seconds
        self._runtimes: dict[str, _DetectorRuntime] = {}
        for d in (detectors if detectors is not None else all_detectors()):
            saved = store.get_detector_settings(d.id)
            tunables = dict(d.default_tunable_values())
            tunables.update(saved.get("tunables") or {})
            self._runtimes[d.id] = _DetectorRuntime(
                detector=d,
                enabled=saved.get("enabled", True),
                tunables=tunables,
                fired_count=saved.get("fired_count", 0),
                last_fired_epoch=saved.get("last_fired_epoch"),
            )

    # -- running detectors ---------------------------------------------------
    def run_once(self, now: Optional[datetime] = None) -> list[dict]:
        now = now or datetime.now(tz=timezone.utc)
        since = now - timedelta(seconds=self.window_seconds)
        touched_ids: set[str] = set()

        for runtime in self._runtimes.values():
            if not runtime.enabled:
                continue
            findings = runtime.detector.run(self.source, since, now, runtime.tunables)
            if findings:
                runtime.fired_count += len(findings)
                runtime.last_fired_epoch = _epoch(now)
                self.store.save_detector_settings(
                    runtime.detector.id, runtime.enabled, runtime.tunables,
                    runtime.fired_count, runtime.last_fired_epoch,
                )
            for finding in findings:
                threat_id = self._upsert_finding(runtime.detector, finding)
                touched_ids.add(threat_id)

        self._apply_cooldowns(now, touched_ids)
        _, threats = self.store.list_threats(limit=1000, include_acknowledged=True)
        return [_row_to_threat_dict(r) for r in threats]

    def _upsert_finding(self, detector: Detector, finding: Finding) -> str:
        threat_id = f"{_slug(finding.key)}-{_hash4(detector.id, finding.key)}"
        observed_epoch = _epoch(finding.observed_at)
        existing = self.store.get_threat(threat_id)

        mitre_json = [m.model_dump() for m in detector.mitre]
        evidence_json = [e.model_dump() if isinstance(e, Evidence) else e for e in finding.evidence]
        indicators_json = [i.model_dump() if isinstance(i, Indicator) else i for i in finding.indicators]
        actions_json = [a.model_dump() if isinstance(a, Action) else a for a in finding.recommended_actions]

        if existing is None:
            row = {
                "id": threat_id,
                "detector_id": detector.id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": detector.category,
                "status": "active",
                "mitre": _dump(mitre_json),
                "summary": finding.summary,
                "detail": finding.detail,
                "evidence": _dump(evidence_json),
                "indicators": _dump(indicators_json),
                "metrics": _dump(finding.metrics),
                "first_seen_epoch": observed_epoch,
                "last_seen_epoch": observed_epoch,
                "occurrences": finding.occurrence_count,
                "related_connection_ids": _dump(finding.related_connection_ids),
                "related_log_ids": _dump(finding.related_log_ids),
                "false_positive_notes": finding.false_positive_notes,
                "recommended_actions": _dump(actions_json),
                "acknowledged_note": None,
            }
        else:
            status = existing["status"]
            if status == "resolved":
                status = "active"  # re-fired after cooling off -- treat as active again
            row = {
                "id": threat_id,
                "detector_id": detector.id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": detector.category,
                "status": status,
                "mitre": _dump(mitre_json),
                "summary": finding.summary,
                "detail": finding.detail,
                "evidence": _dump(evidence_json),
                "indicators": _dump(indicators_json),
                "metrics": _dump(finding.metrics),
                "first_seen_epoch": existing["first_seen_epoch"],
                "last_seen_epoch": max(observed_epoch, existing["last_seen_epoch"]),
                "occurrences": existing["occurrences"] + finding.occurrence_count,
                "related_connection_ids": _dump(finding.related_connection_ids),
                "related_log_ids": _dump(finding.related_log_ids),
                "false_positive_notes": finding.false_positive_notes,
                "recommended_actions": _dump(actions_json),
                "acknowledged_note": existing.get("acknowledged_note"),
            }

        self.store.upsert_threat(row)
        self.store.record_event(threat_id, detector.id, finding.severity, observed_epoch)
        return threat_id

    def _apply_cooldowns(self, now: datetime, touched_ids: set[str]) -> None:
        now_epoch = _epoch(now)
        # list_threats excludes acknowledged by default; fetch both statuses explicitly.
        _, active = self.store.list_threats(limit=1000, filters={"status": "active"}, include_acknowledged=True)
        _, acked = self.store.list_threats(limit=1000, filters={"status": "acknowledged"}, include_acknowledged=True)
        for t in [*active, *acked]:
            if t["id"] in touched_ids:
                continue
            detector_id = t["detector_id"]
            runtime = self._runtimes.get(detector_id)
            cooldown = runtime.detector.cooldown_seconds if runtime else Detector.cooldown_seconds
            if now_epoch - t["last_seen_epoch"] > cooldown:
                self.store.set_status(t["id"], "resolved")

    # -- read API ---------------------------------------------------------
    def list_threats(self, **kwargs) -> tuple[int, list[dict]]:
        total, rows = self.store.list_threats(**kwargs)
        return total, [_row_to_threat_dict(r) for r in rows]

    def get_threat(self, threat_id: str) -> Optional[dict]:
        row = self.store.get_threat(threat_id)
        return _row_to_threat_dict(row) if row else None

    def acknowledge(self, threat_id: str, note: Optional[str] = None) -> Optional[dict]:
        if self.store.get_threat(threat_id) is None:
            return None
        row = self.store.set_acknowledged(threat_id, True, note)
        return _row_to_threat_dict(row) if row else None

    def unacknowledge(self, threat_id: str, note: Optional[str] = None) -> Optional[dict]:
        existing = self.store.get_threat(threat_id)
        if existing is None:
            return None
        row = self.store.set_acknowledged(threat_id, False, None)
        return _row_to_threat_dict(row) if row else None

    def timeline(self, since: datetime, until: datetime, bucket_seconds: int) -> list[dict]:
        since_epoch, until_epoch = _epoch(since), _epoch(until)
        events = self.store.events_between(since_epoch, until_epoch)
        n_buckets = max(1, math.ceil((until_epoch - since_epoch) / bucket_seconds))
        buckets = [
            {"t": _iso_z(since_epoch + i * bucket_seconds),
             "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for i in range(n_buckets)
        ]
        for e in events:
            idx = int((e["ts_epoch"] - since_epoch) // bucket_seconds)
            if 0 <= idx < n_buckets and e["severity"] in ("critical", "high", "medium", "low", "info"):
                buckets[idx][e["severity"]] += 1
        return buckets

    # -- detector admin -----------------------------------------------------
    def list_detectors(self) -> list[dict]:
        out = []
        for runtime in self._runtimes.values():
            d = runtime.detector
            out.append(DetectorModel(
                id=d.id, label=d.label, category=d.category, description=d.description,
                enabled=runtime.enabled, default_severity=d.default_severity,
                mitre=[DetectorMitreRef(tactic=m.tactic, technique=m.technique) for m in d.mitre],
                tunables=[TunableSpec(key=t.key, value=runtime.tunables.get(t.key, t.value),
                                       type=t.type, min=t.min, max=t.max, description=t.description)
                          for t in d.tunables],
                fired_count=runtime.fired_count,
                last_fired=_iso_z(runtime.last_fired_epoch) if runtime.last_fired_epoch else None,
            ).model_dump())
        return out

    def patch_detector(self, detector_id: str, body: dict) -> tuple[Optional[dict], Optional[str]]:
        """Returns (updated_detector_dict, error_message). error_message is
        set (and the first item None) on validation failure -- the router
        turns that into the standard 400 error body."""
        runtime = self._runtimes.get(detector_id)
        if runtime is None:
            return None, "not_found"

        if "enabled" in body:
            if not isinstance(body["enabled"], bool):
                return None, "'enabled' must be a boolean"
            runtime.enabled = body["enabled"]

        if "tunables" in body:
            specs = {t.key: t for t in runtime.detector.tunables}
            new_values = body["tunables"]
            if not isinstance(new_values, dict):
                return None, "'tunables' must be an object"
            for key, value in new_values.items():
                spec = specs.get(key)
                if spec is None:
                    return None, f"unknown tunable '{key}' for detector '{detector_id}'"
                err = _validate_tunable(spec, value)
                if err:
                    return None, err
                runtime.tunables[key] = value

        self.store.save_detector_settings(
            detector_id, runtime.enabled, runtime.tunables, runtime.fired_count, runtime.last_fired_epoch,
        )
        return self._detector_dict(runtime), None

    def _detector_dict(self, runtime: _DetectorRuntime) -> dict:
        d = runtime.detector
        return DetectorModel(
            id=d.id, label=d.label, category=d.category, description=d.description,
            enabled=runtime.enabled, default_severity=d.default_severity,
            mitre=[DetectorMitreRef(tactic=m.tactic, technique=m.technique) for m in d.mitre],
            tunables=[TunableSpec(key=t.key, value=runtime.tunables.get(t.key, t.value),
                                   type=t.type, min=t.min, max=t.max, description=t.description)
                      for t in d.tunables],
            fired_count=runtime.fired_count,
            last_fired=_iso_z(runtime.last_fired_epoch) if runtime.last_fired_epoch else None,
        ).model_dump()


def _validate_tunable(spec: TunableSpec, value) -> Optional[str]:
    if spec.type == "bool":
        if not isinstance(value, bool):
            return f"tunable '{spec.key}' must be a bool"
        return None
    if spec.type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"tunable '{spec.key}' must be an int"
    elif spec.type == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"tunable '{spec.key}' must be a number"
    elif spec.type == "str":
        if not isinstance(value, str):
            return f"tunable '{spec.key}' must be a string"
        return None
    if spec.type in ("int", "float"):
        if spec.min is not None and value < spec.min:
            return f"tunable '{spec.key}' must be >= {spec.min}"
        if spec.max is not None and value > spec.max:
            return f"tunable '{spec.key}' must be <= {spec.max}"
    return None


def _dump(value) -> str:
    return json.dumps(value)


def _row_to_threat_dict(row: dict) -> dict:
    return {
        "id": row["id"],
        "detector_id": row["detector_id"],
        "title": row["title"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "category": row["category"],
        "status": row["status"],
        "mitre": row["mitre"],
        "summary": row["summary"],
        "detail": row["detail"],
        "evidence": row["evidence"],
        "indicators": row["indicators"],
        "metrics": row["metrics"],
        "first_seen": _iso_z(row["first_seen_epoch"]),
        "last_seen": _iso_z(row["last_seen_epoch"]),
        "occurrences": row["occurrences"],
        "related_connection_ids": row["related_connection_ids"],
        "related_log_ids": row["related_log_ids"],
        "false_positive_notes": row["false_positive_notes"],
        "recommended_actions": row["recommended_actions"],
        "acknowledged_note": row.get("acknowledged_note"),
        "tags": row.get("tags") or [],
        "enrichment": row.get("enrichment") or {},
    }

"""Snapshot capture and diff logic for Part E8."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from ..timeutil import iso_z, parse_iso

from .models import (
    BaselineDiff,
    BaselineListItem,
    BaselineRef,
    BaselineScheduleResponse,
    BaselinesResponse,
    CheckPresence,
    CheckTransition,
    ChecksDiff,
    ListenerRef,
    ScoreDelta,
)
from .providers import PostureProvider, ScoreProvider, TrafficProvider
from .store import (
    BaselineRecord,
    delete_scheduled_before,
    get_baseline,
    get_most_recent_scheduled_baseline,
    get_schedule,
    insert_baseline,
    list_baselines,
    mark_schedule_error,
    mark_schedule_success,
    save_schedule,
)

_scheduled_capture_lock = threading.Lock()


@dataclass(frozen=True)
class ScheduledCapture:
    baseline: BaselineListItem
    previous_id: Optional[str]

# Ordering of "badness" for a check status, used to classify a status
# transition as fixed/regressed. error/skipped are deliberately excluded --
# they mean "no evidence", not "the setting got better or worse", so a
# transition involving either goes to `inconclusive` rather than being
# forced into fixed or regressed.
_BADNESS = {"pass": 0, "warn": 1, "fail": 2}


def _to_listener_key(listener: dict) -> tuple:
    return (listener.get("port"), listener.get("process"))


def capture_snapshot(
    label: str,
    posture: PostureProvider,
    traffic: TrafficProvider,
    score: ScoreProvider,
    db_path=None,
    origin: str = "manual",
    captured_at: Optional[str] = None,
) -> BaselineRecord:
    checks = [{"id": str(c.get("id")), "status": str(c.get("status"))} for c in posture.checks() if "id" in c]
    peers = sorted({str(p) for p in traffic.peers()})
    listeners = [
        {"port": int(l["port"]), "process": str(l.get("process", ""))} for l in traffic.listeners() if "port" in l
    ]
    scores = score.security_score()
    return insert_baseline(
        label=label,
        checks=checks,
        peers=peers,
        listeners=listeners,
        posture_score=int(scores.get("posture", 0)),
        threats_score=scores.get("threats"),
        overall_score=int(scores.get("overall", scores.get("posture", 0))),
        db_path=db_path,
        origin=origin,
        captured_at=captured_at,
    )


def _record_to_ref(record: BaselineRecord) -> BaselineRef:
    return BaselineRef(id=record.id, label=record.label, captured_at=record.captured_at)


def _record_to_list_item(record: BaselineRecord) -> BaselineListItem:
    return BaselineListItem(
        id=record.id,
        label=record.label,
        captured_at=record.captured_at,
        origin=record.origin,
        checks_count=len(record.checks),
        peers_count=len(record.peers),
        listeners_count=len(record.listeners),
        posture_score=record.posture_score,
        threats_score=record.threats_score,
        overall_score=record.overall_score,
    )


def get_baselines_response(db_path=None) -> BaselinesResponse:
    return BaselinesResponse(baselines=[_record_to_list_item(r) for r in list_baselines(db_path)])


def _schedule_response(db_path=None) -> BaselineScheduleResponse:
    schedule = get_schedule(db_path)
    next_due_at = None
    if schedule.last_success_at is not None:
        next_due_at = iso_z(parse_iso(schedule.last_success_at) + schedule.interval_hours * 3600)
    return BaselineScheduleResponse(
        enabled=schedule.enabled,
        interval_hours=schedule.interval_hours,
        last_success_at=schedule.last_success_at,
        last_error=schedule.last_error,
        next_due_at=next_due_at,
    )


def diff_baselines(from_id: str, to_id: str, db_path=None) -> Optional[BaselineDiff]:
    from_record = get_baseline(from_id, db_path)
    to_record = get_baseline(to_id, db_path)
    if from_record is None or to_record is None:
        return None

    from_checks = {c["id"]: c["status"] for c in from_record.checks}
    to_checks = {c["id"]: c["status"] for c in to_record.checks}

    common_ids = sorted(set(from_checks) & set(to_checks))
    only_from = sorted(set(from_checks) - set(to_checks))
    only_to = sorted(set(to_checks) - set(from_checks))

    fixed: list[CheckTransition] = []
    regressed: list[CheckTransition] = []
    inconclusive: list[CheckTransition] = []
    unchanged_count = 0

    for check_id in common_ids:
        old_status = from_checks[check_id]
        new_status = to_checks[check_id]
        if old_status == new_status:
            unchanged_count += 1
            continue
        old_rank = _BADNESS.get(old_status)
        new_rank = _BADNESS.get(new_status)
        transition = CheckTransition(id=check_id, **{"from": old_status, "to": new_status})
        if old_rank is None or new_rank is None:
            inconclusive.append(transition)
        elif new_rank < old_rank:
            fixed.append(transition)
        else:
            regressed.append(transition)

    added = [CheckPresence(id=cid, status=to_checks[cid]) for cid in only_to]
    removed = [CheckPresence(id=cid, status=from_checks[cid]) for cid in only_from]

    from_peers = set(from_record.peers)
    to_peers = set(to_record.peers)
    new_peers = sorted(to_peers - from_peers)

    from_listeners = {_to_listener_key(l): l for l in from_record.listeners}
    to_listeners = {_to_listener_key(l): l for l in to_record.listeners}
    new_listener_keys = set(to_listeners) - set(from_listeners)
    removed_listener_keys = set(from_listeners) - set(to_listeners)
    new_listeners = [ListenerRef(**to_listeners[k]) for k in sorted(new_listener_keys)]
    removed_listeners = [ListenerRef(**from_listeners[k]) for k in sorted(removed_listener_keys)]

    posture_delta = to_record.posture_score - from_record.posture_score
    if from_record.threats_score is not None and to_record.threats_score is not None:
        threats_delta = to_record.threats_score - from_record.threats_score
    else:
        threats_delta = 0
    overall_delta = to_record.overall_score - from_record.overall_score

    return BaselineDiff(
        **{
            "from": _record_to_ref(from_record),
            "to": _record_to_ref(to_record),
            "score_delta": ScoreDelta(posture=posture_delta, threats=threats_delta, overall=overall_delta),
            "checks": ChecksDiff(
                fixed=fixed,
                regressed=regressed,
                unchanged_count=unchanged_count,
                added=added,
                removed=removed,
                inconclusive=inconclusive,
            ),
            "new_peers": new_peers,
            "new_listeners": new_listeners,
            "removed_listeners": removed_listeners,
        }
    )


class BaselineService:
    def __init__(self, db_path=None) -> None:
        self._db_path = db_path

    def create(self, label: str, posture: PostureProvider, traffic: TrafficProvider, score: ScoreProvider) -> BaselineListItem:
        record = capture_snapshot(label, posture, traffic, score, self._db_path)
        return _record_to_list_item(record)

    def list(self) -> BaselinesResponse:
        return get_baselines_response(self._db_path)

    def diff(self, from_id: str, to_id: str) -> Optional[BaselineDiff]:
        return diff_baselines(from_id, to_id, self._db_path)

    def _create_scheduled(
        self,
        posture: PostureProvider,
        traffic: TrafficProvider,
        score: ScoreProvider,
        captured_at: str,
    ) -> BaselineListItem:
        record = capture_snapshot(
            "Scheduled baseline",
            posture,
            traffic,
            score,
            self._db_path,
            origin="scheduled",
            captured_at=captured_at,
        )
        mark_schedule_success(record.captured_at, self._db_path)
        return _record_to_list_item(record)

    def create_scheduled(
        self,
        posture: PostureProvider,
        traffic: TrafficProvider,
        score: ScoreProvider,
        captured_at: str,
    ) -> BaselineListItem:
        with _scheduled_capture_lock:
            return self._create_scheduled(posture, traffic, score, captured_at)

    def capture_scheduled_if_due(
        self,
        posture: PostureProvider,
        traffic: TrafficProvider,
        score: ScoreProvider,
        captured_at: str,
    ) -> Optional[ScheduledCapture]:
        """Atomically decide due state and capture one scheduled snapshot."""
        current = parse_iso(captured_at)
        with _scheduled_capture_lock:
            schedule = get_schedule(self._db_path)
            if not schedule.enabled:
                return None
            if schedule.last_success_at is not None:
                due_at = parse_iso(schedule.last_success_at) + schedule.interval_hours * 3600
                if current < due_at:
                    return None
            previous = get_most_recent_scheduled_baseline(self._db_path)
            baseline = self._create_scheduled(posture, traffic, score, captured_at)
            return ScheduledCapture(baseline=baseline, previous_id=previous.id if previous is not None else None)

    def prune_scheduled(self, cutoff: str) -> int:
        return delete_scheduled_before(cutoff, self._db_path)


    def record_schedule_error(self, error: str) -> BaselineScheduleResponse:
        mark_schedule_error(error, self._db_path)
        return _schedule_response(self._db_path)

    def get_schedule(self) -> BaselineScheduleResponse:
        return _schedule_response(self._db_path)

    def update_schedule(self, enabled: bool, interval_hours: int) -> BaselineScheduleResponse:
        save_schedule(enabled, interval_hours, self._db_path)
        return _schedule_response(self._db_path)


_default_service: Optional[BaselineService] = None


def get_baseline_service() -> BaselineService:
    global _default_service
    if _default_service is None:
        _default_service = BaselineService()
    return _default_service

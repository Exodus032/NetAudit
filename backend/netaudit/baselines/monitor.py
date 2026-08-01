"""Scheduled baseline capture and change notification."""
from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Protocol

from ..timeutil import iso_z, parse_iso
from .providers import PostureProvider, ScoreProvider, TrafficProvider
from .service import BaselineService

_RETENTION_SECONDS = 90 * 24 * 60 * 60
_MAX_ERROR_LENGTH = 500


class AlertDispatcher(Protocol):
    """The alerting boundary owned by the baseline monitor."""

    def dispatch(self, severity: str, source: str, source_id: str, title: str) -> None: ...


@dataclass(frozen=True)
class MonitorResult:
    captured: bool
    alerted: bool
    error: Optional[str] = None


class BaselineMonitor:
    def __init__(
        self,
        service: BaselineService,
        posture: PostureProvider,
        traffic: TrafficProvider,
        score: ScoreProvider,
        dispatcher: AlertDispatcher,
        clock: Callable[[], str],
    ) -> None:
        self._service = service
        self._posture = posture
        self._traffic = traffic
        self._score = score
        self._dispatcher = dispatcher
        self._clock = clock
        self._wake = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None

    def run_once(self, now: Optional[str] = None) -> MonitorResult:
        """Capture a due snapshot and report material change from its predecessor."""
        current = self._canonical_time(now if now is not None else self._clock())
        current_seconds = parse_iso(current)
        try:
            schedule = self._service.get_schedule()
            if not schedule.enabled:
                return MonitorResult(captured=False, alerted=False)
            if schedule.last_success_at is not None:
                due_at = parse_iso(schedule.last_success_at) + schedule.interval_hours * 3600
                if current_seconds < due_at:
                    return MonitorResult(captured=False, alerted=False)

            previous_id = self._service.latest_scheduled_id()
            created = self._service.create_scheduled(
                self._posture,
                self._traffic,
                self._score,
                captured_at=current,
            )
            self._service.prune_scheduled(iso_z(current_seconds - _RETENTION_SECONDS))
            if previous_id is None:
                return MonitorResult(captured=True, alerted=False)

            diff = self._service.diff(previous_id, created.id)
            if diff is None:
                return MonitorResult(captured=True, alerted=False)

            categories = self._alert_categories(diff)
            if not categories:
                return MonitorResult(captured=True, alerted=False)

            self._dispatcher.dispatch(
                severity="high",
                source="scheduled_baseline",
                source_id=created.id,
                title=f"Scheduled baseline: {', '.join(categories)}",
            )
            return MonitorResult(captured=True, alerted=True)
        except Exception as exc:
            error = self._bounded_error(exc)
            try:
                self._service.record_schedule_error(error)
            except Exception:
                pass
            return MonitorResult(captured=False, alerted=False, error=error)

    def start(self) -> None:
        """Start the asynchronous scheduler once on the current event loop."""
        if self._task is not None:
            return
        self._task = asyncio.get_running_loop().create_task(self._run(), name="netaudit-baseline-monitor")

    def wake(self) -> None:
        """Interrupt the current wait so changed schedule state takes effect."""
        self._wake.set()

    async def shutdown(self) -> None:
        """Cancel and await the scheduler, preventing work after shutdown."""
        task = self._task
        if task is None:
            return
        self._task = None
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    async def _run(self) -> None:
        while True:
            await asyncio.to_thread(self.run_once)
            if self._wake.is_set():
                self._wake.clear()
                continue

            delay = self._seconds_until_next_run()
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    def _seconds_until_next_run(self) -> float:
        try:
            schedule = self._service.get_schedule()
            interval = float(schedule.interval_hours * 3600)
            if not schedule.enabled or schedule.last_success_at is None:
                return interval
            due_at = parse_iso(schedule.last_success_at) + interval
            return max(0.0, min(interval, due_at - parse_iso(self._canonical_time(self._clock()))))
        except Exception:
            return 60.0

    @staticmethod
    def _canonical_time(value: str | datetime) -> str:
        if isinstance(value, datetime):
            return iso_z(value.timestamp())
        return iso_z(parse_iso(value))

    @staticmethod
    def _alert_categories(diff) -> list[str]:
        categories = []
        if diff.checks.regressed:
            categories.append("regressed checks")
        if diff.score_delta.overall < 0:
            categories.append("overall score declined")
        if diff.new_listeners:
            categories.append("new listeners")
        return categories

    @staticmethod
    def _bounded_error(exc: Exception) -> str:
        return (str(exc) or type(exc).__name__)[:_MAX_ERROR_LENGTH]

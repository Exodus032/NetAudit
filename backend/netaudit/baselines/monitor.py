"""Scheduled baseline capture and change notification."""
from __future__ import annotations

import asyncio
import threading
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
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = False
        self._task: Optional[asyncio.Task[None]] = None
        self._retry_not_before: Optional[float] = None
        self._retry_wake = threading.Event()

    def run_once(self, now: Optional[str] = None) -> MonitorResult:
        """Capture a due snapshot and report material change from its predecessor."""
        current = self._canonical_time(now if now is not None else self._clock())
        current_seconds = parse_iso(current)
        if self._retry_not_before is not None and current_seconds < self._retry_not_before:
            if not self._retry_wake.is_set():
                return MonitorResult(captured=False, alerted=False)
        self._retry_wake.clear()
        try:
            capture = self._service.capture_scheduled_if_due(
                self._posture,
                self._traffic,
                self._score,
                captured_at=current,
            )
            if capture is None:
                return MonitorResult(captured=False, alerted=False)

            self._retry_not_before = None
            alerted = False
            try:
                if capture.previous_id is not None:
                    diff = self._service.diff(capture.previous_id, capture.baseline.id)
                    if diff is not None:
                        categories = self._alert_categories(diff)
                        if categories:
                            self._dispatcher.dispatch(
                                severity="high",
                                source="scheduled_baseline",
                                source_id=capture.baseline.id,
                                title=f"Scheduled baseline: {', '.join(categories)}",
                            )
                            alerted = True
            finally:
                self._service.prune_scheduled(iso_z(current_seconds - _RETENTION_SECONDS))
            return MonitorResult(captured=True, alerted=alerted)
        except Exception as exc:
            error = self._bounded_error(exc)
            try:
                schedule = self._service.record_schedule_error(error)
                self._retry_not_before = current_seconds + schedule.interval_hours * 3600
            except Exception:
                pass
            return MonitorResult(captured=False, alerted=False, error=error)

    def start(self) -> None:
        """Start the asynchronous scheduler once on the current event loop."""
        if self._task is not None:
            return
        self._stopping = False
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self._task = self._loop.create_task(self._run(), name="netaudit-baseline-monitor")

    def wake(self) -> None:
        """Interrupt the current wait so changed schedule state takes effect."""
        self._retry_wake.set()
        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self._wake.set)

    async def shutdown(self) -> None:
        """Wait for in-flight capture, then stop the scheduler."""
        task = self._task
        if task is None:
            return
        self._stopping = True
        self.wake()
        cancelled = False
        try:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    cancelled = True
        finally:
            self._task = None
            self._loop = None
        if cancelled:
            raise asyncio.CancelledError

    async def _run(self) -> None:
        while not self._stopping:
            await asyncio.to_thread(self.run_once)
            if self._stopping:
                return

            delay = await asyncio.to_thread(self._seconds_until_next_run)
            if self._stopping:
                return
            if self._wake.is_set():
                self._wake.clear()
                continue
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                continue
            self._wake.clear()

    def _seconds_until_next_run(self) -> float:
        try:
            schedule = self._service.get_schedule()
            interval = float(schedule.interval_hours * 3600)
            if not schedule.enabled:
                return interval
            now = parse_iso(self._canonical_time(self._clock()))
            if self._retry_not_before is not None:
                return max(0.0, min(interval, self._retry_not_before - now))
            if schedule.last_success_at is None:
                return interval
            due_at = parse_iso(schedule.last_success_at) + interval
            return max(0.0, min(interval, due_at - now))
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

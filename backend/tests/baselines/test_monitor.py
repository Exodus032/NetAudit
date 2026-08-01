from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone

import pytest

from netaudit.baselines.monitor import BaselineMonitor
from netaudit.baselines.service import BaselineService


START = datetime(2026, 8, 1, tzinfo=timezone.utc)


def iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class Inputs:
    def __init__(self) -> None:
        self.check_values = [{"id": "firewall", "status": "pass"}]
        self.peer_values: list[str] = []
        self.listener_values: list[dict] = []
        self.overall = 80
        self.fail = False
        self.capture_calls = 0
        self.captured = threading.Event()

    def checks(self) -> list[dict]:
        self.capture_calls += 1
        self.captured.set()
        if self.fail:
            raise RuntimeError("provider unavailable")
        return self.check_values

    def peers(self) -> list[str]:
        return self.peer_values

    def listeners(self) -> list[dict]:
        return self.listener_values

    def security_score(self) -> dict:
        return {"posture": self.overall, "threats": None, "overall": self.overall}


class RecordingDispatcher:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def dispatch(self, severity: str, source: str, source_id: str, title: str) -> None:
        self.calls.append(
            {"severity": severity, "source": source, "source_id": source_id, "title": title}
        )


def make_monitor(db_path, *, enabled: bool = True):
    service = BaselineService(db_path)
    service.update_schedule(enabled=enabled, interval_hours=6)
    inputs = Inputs()
    dispatcher = RecordingDispatcher()
    clock_now = [START]
    monitor = BaselineMonitor(
        service,
        inputs,
        inputs,
        inputs,
        dispatcher,
        clock=lambda: iso(clock_now[0]),
    )
    return monitor, service, inputs, dispatcher, clock_now


def scheduled(service: BaselineService):
    return [baseline for baseline in service.list().baselines if baseline.origin == "scheduled"]


def test_disabled_and_not_due_runs_skip_capture(db_path):
    monitor, service, inputs, dispatcher, _ = make_monitor(db_path, enabled=False)

    assert monitor.run_once(now=iso(START)).captured is False
    assert inputs.capture_calls == 0
    assert dispatcher.calls == []

    service.update_schedule(enabled=True, interval_hours=6)
    assert monitor.run_once(now=iso(START)).captured is True
    assert monitor.run_once(now=iso(START + timedelta(hours=5))).captured is False
    assert len(scheduled(service)) == 1
    assert inputs.capture_calls == 1


def test_first_due_run_captures_a_reference_without_alert(db_path):
    monitor, service, _, dispatcher, _ = make_monitor(db_path)

    result = monitor.run_once(now=iso(START))

    assert result.captured is True
    assert result.alerted is False
    assert result.error is None
    assert len(scheduled(service)) == 1
    assert dispatcher.calls == []


@pytest.mark.parametrize(
    ("change", "title_fragment"),
    [
        (lambda inputs: setattr(inputs, "check_values", [{"id": "firewall", "status": "fail"}]), "regressed checks"),
        (lambda inputs: setattr(inputs, "overall", 70), "overall score declined"),
        (
            lambda inputs: setattr(inputs, "listener_values", [{"port": 8080, "process": "node.exe"}]),
            "new listeners",
        ),
    ],
)
def test_each_material_change_dispatches_one_high_alert(db_path, change, title_fragment):
    monitor, service, inputs, dispatcher, _ = make_monitor(db_path)
    monitor.run_once(now=iso(START))
    change(inputs)

    result = monitor.run_once(now=iso(START + timedelta(hours=6)))

    assert result.captured is True
    assert result.alerted is True
    assert len(dispatcher.calls) == 1
    alert = dispatcher.calls[0]
    assert alert["severity"] == "high"
    assert alert["source"] == "scheduled_baseline"
    assert alert["source_id"] == scheduled(service)[0].id
    assert title_fragment in alert["title"]


@pytest.mark.parametrize(
    "initial, change",
    [
        (lambda inputs: None, lambda inputs: setattr(inputs, "peer_values", ["203.0.113.9"])),
        (lambda inputs: setattr(inputs, "overall", 70), lambda inputs: setattr(inputs, "overall", 90)),
        (
            lambda inputs: setattr(inputs, "listener_values", [{"port": 8080, "process": "node.exe"}]),
            lambda inputs: setattr(inputs, "listener_values", []),
        ),
        (
            lambda inputs: setattr(inputs, "check_values", [{"id": "firewall", "status": "warn"}]),
            lambda inputs: setattr(inputs, "check_values", [{"id": "firewall", "status": "pass"}]),
        ),
    ],
)
def test_peer_only_improvements_and_removals_do_not_alert(db_path, initial, change):
    monitor, _, inputs, dispatcher, _ = make_monitor(db_path)
    initial(inputs)
    monitor.run_once(now=iso(START))
    change(inputs)

    result = monitor.run_once(now=iso(START + timedelta(hours=6)))

    assert result.captured is True
    assert result.alerted is False
    assert dispatcher.calls == []


def test_capture_failure_persists_bounded_error_without_moving_success_or_alerting(db_path):
    monitor, service, inputs, dispatcher, _ = make_monitor(db_path)
    monitor.run_once(now=iso(START))
    previous_success = service.get_schedule().last_success_at
    inputs.fail = True

    result = monitor.run_once(now=iso(START + timedelta(hours=6)))
    schedule = service.get_schedule()

    assert result.captured is False
    assert result.error == "provider unavailable"
    assert schedule.last_success_at == previous_success
    assert schedule.last_error == "provider unavailable"
    assert len(schedule.last_error) <= 500
    assert dispatcher.calls == []


def test_restart_uses_persisted_success_and_captures_when_overdue(db_path):
    first_monitor, service, _, _, _ = make_monitor(db_path)
    first_monitor.run_once(now=iso(START))
    _, _, restarted_inputs, dispatcher, _ = make_monitor(db_path)
    restarted = BaselineMonitor(
        service,
        restarted_inputs,
        restarted_inputs,
        restarted_inputs,
        dispatcher,
        clock=lambda: iso(START),
    )

    assert restarted.run_once(now=iso(START + timedelta(hours=5))).captured is False
    assert restarted.run_once(now=iso(START + timedelta(hours=7))).captured is True
    assert len(scheduled(service)) == 2


def test_success_prunes_scheduled_snapshots_older_than_ninety_days(db_path):
    monitor, service, _, _, _ = make_monitor(db_path)
    service.create_scheduled(
        Inputs(), Inputs(), Inputs(), captured_at=iso(START - timedelta(days=91))
    )

    result = monitor.run_once(now=iso(START))

    assert result.captured is True
    assert len(scheduled(service)) == 1
    assert scheduled(service)[0].captured_at == "2026-08-01T00:00:00.000Z"


def test_async_start_is_idempotent_wake_interrupts_wait_and_shutdown_stops_captures(db_path):
    async def scenario() -> None:
        monitor, service, inputs, _, _ = make_monitor(db_path, enabled=False)
        monitor.start()
        task = monitor._task
        monitor.start()
        assert monitor._task is task

        await asyncio.sleep(0)
        service.update_schedule(enabled=True, interval_hours=6)
        monitor.wake()
        captured = await asyncio.to_thread(inputs.captured.wait, 1)
        assert captured is True
        before_shutdown = inputs.capture_calls

        await monitor.shutdown()
        assert monitor._task is None
        monitor.wake()
        await asyncio.sleep(0.02)
        assert inputs.capture_calls == before_shutdown

    asyncio.run(scenario())

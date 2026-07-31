"""Every load-bearing constraint from Part E7, exercised at the service
layer with fake connectors -- never a real socket, never a real network.
"""
from __future__ import annotations

import time

import pytest

from netaudit.lanscan.providers import StaticInterfaceProvider
from netaudit.lanscan.service import CONSENT_NOTICE, LanScanService, ScanAlreadyRunning
from netaudit.lanscan.validation import ScanValidationError

from .conftest import BlockingConnector, FakeConnector


def _wait_for_completion(service, job_id, timeout=5.0):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        job = service.get_job(job_id)
        if job.status != "running":
            return job
        time.sleep(0.005)
    raise TimeoutError("scan did not reach a terminal status in time")


def test_happy_path_completes_and_reports_open_ports(home_interfaces):
    service = LanScanService(connect_timeout=0.5)
    connector = FakeConnector({("192.168.1.1", 22): True, ("192.168.1.1", 80): False, ("192.168.1.2", 443): True})
    job = service.start_scan("192.168.1.0/30", [22, 80, 443], 100, home_interfaces, connector)
    assert job.status == "running"
    assert job.consent_notice == CONSENT_NOTICE

    final = _wait_for_completion(service, job.job_id)
    assert final.status == "completed"
    assert final.progress.total == 6  # 2 usable hosts * 3 ports
    assert final.progress.scanned == 6
    results = {r.ip: set(r.open_ports) for r in final.results}
    assert results.get("192.168.1.1") == {22}
    assert results.get("192.168.1.2") == {443}


def test_bad_request_never_creates_a_job(home_interfaces):
    service = LanScanService()
    connector = FakeConnector()
    with pytest.raises(ScanValidationError):
        service.start_scan("8.8.8.0/24", [80], 10, home_interfaces, connector)
    # no job exists at all -- confirmed indirectly: a subsequent valid
    # request must succeed (would 409 if the invalid attempt had wrongly
    # left a "running" job behind).
    job = service.start_scan("192.168.1.0/30", [80], 10, home_interfaces, connector)
    assert job.status == "running"
    _wait_for_completion(service, job.job_id)


def test_second_concurrent_scan_rejected(home_interfaces):
    service = LanScanService(connect_timeout=5.0)
    connector = BlockingConnector()
    job = service.start_scan("192.168.1.0/24", [22], 1, home_interfaces, connector)
    assert connector.first_call_started.wait(timeout=2.0)

    with pytest.raises(ScanAlreadyRunning):
        service.start_scan("192.168.1.0/24", [22], 1, home_interfaces, connector)

    connector.release_event.set()
    service.cancel_job(job.job_id)


def test_a_completed_scan_does_not_block_a_new_one(home_interfaces):
    service = LanScanService(connect_timeout=0.5)
    connector = FakeConnector()
    job1 = service.start_scan("192.168.1.0/30", [80], 100, home_interfaces, connector)
    _wait_for_completion(service, job1.job_id)

    job2 = service.start_scan("192.168.1.0/30", [80], 100, home_interfaces, connector)
    assert job2.job_id != job1.job_id
    _wait_for_completion(service, job2.job_id)


def test_cancel_stops_promptly_mid_scan(home_interfaces):
    service = LanScanService(connect_timeout=5.0)
    connector = BlockingConnector()
    # A whole /24 at 1 pps (254 hosts * 1 port) would take ~4 minutes
    # uncancelled -- if cancellation weren't prompt, this test would hang.
    job = service.start_scan("192.168.1.0/24", [22], 1, home_interfaces, connector)
    assert connector.first_call_started.wait(timeout=2.0)

    start = time.perf_counter()
    connector.release_event.set()  # let the in-flight attempt return so the worker can observe the cancel
    cancelled = service.cancel_job(job.job_id)
    elapsed = time.perf_counter() - start

    assert cancelled.status == "cancelled"
    assert elapsed < 1.0, f"cancel took {elapsed:.2f}s -- nowhere near prompt enough"
    assert len(connector.calls) == 1, "a second connect attempt happened after cancellation was requested"


def test_rate_limit_is_actually_enforced_with_measured_pacing(home_interfaces):
    """This is the test that fails if the pacing wait is ever deleted --
    it measures real wall-clock time across a real scan loop (fake
    connector, real threading and real time.sleep-equivalent waits), not
    just that `rate_limit_pps` round-trips through storage."""
    service = LanScanService(connect_timeout=0.5)
    connector = FakeConnector()  # instant responses -- any elapsed time is pacing, not connector latency
    rate_limit_pps = 20
    interval = 1.0 / rate_limit_pps

    start = time.perf_counter()
    job = service.start_scan("192.168.1.0/30", [22, 80], rate_limit_pps, home_interfaces, connector)
    final = _wait_for_completion(service, job.job_id, timeout=5.0)
    elapsed = time.perf_counter() - start

    assert final.status == "completed"
    total_attempts = final.progress.total
    assert total_attempts == 4  # 2 usable hosts * 2 ports

    min_expected = (total_attempts - 1) * interval  # 0.15s
    assert elapsed >= min_expected * 0.7, f"scan finished in {elapsed:.3f}s, expected at least ~{min_expected:.3f}s at {rate_limit_pps}pps -- pacing may be missing"
    assert elapsed < 3.0, f"scan took {elapsed:.3f}s -- unexpectedly slow"


def test_slash31_includes_both_addresses_no_network_broadcast_exclusion():
    service = LanScanService(connect_timeout=0.5)
    connector = FakeConnector({("192.168.1.0", 80): True, ("192.168.1.1", 80): True})
    ifaces = StaticInterfaceProvider([{"address": "192.168.1.0", "prefixlen": 31}])
    job = service.start_scan("192.168.1.0/31", [80], 100, ifaces, connector)
    final = _wait_for_completion(service, job.job_id)
    assert final.progress.total == 2
    assert {r.ip for r in final.results} == {"192.168.1.0", "192.168.1.1"}


def test_unknown_job_id_returns_none(home_interfaces):
    service = LanScanService()
    assert service.get_job("does-not-exist") is None
    assert service.cancel_job("does-not-exist") is None

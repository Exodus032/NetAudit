"""Job model for Part E7. One scan at a time, enforced by `_manager_lock`
plus a status check inside it (not just a naive "is there a job" check --
a completed/cancelled/errored previous job must not block a new one).

Rate limiting is enforced by pacing the scan loop itself: after every
single connect attempt, the worker thread waits `1 / rate_limit_pps`
seconds (via `cancel_event.wait(timeout=...)`, so a cancel wakes it
immediately instead of finishing the sleep first) before the next attempt.
Because the whole scan runs on one thread making one connect attempt at a
time, this directly bounds the attempt rate -- there's no concurrency that
could let the real rate exceed the cap.
"""
from __future__ import annotations

import ipaddress
import secrets
import threading
from dataclasses import dataclass, field
from typing import Optional

from ..timeutil import now_iso
from .models import HostResult, ScanJob, ScanProgress
from .providers import InterfaceProvider, PortConnector
from .validation import ScanValidationError, validate_scan_request

CONSENT_NOTICE = (
    "This scan sends TCP connection attempts to other devices on your local network. "
    "Only run it against a network you own or are explicitly authorised to test."
)

DEFAULT_CONNECT_TIMEOUT_SECONDS = 1.0


class ScanAlreadyRunning(Exception):
    """Raised by `start_scan()` when a scan is already in progress. The
    router maps this to 409."""


@dataclass
class _JobState:
    job_id: str
    subnet: str
    ports: list[int]
    rate_limit_pps: int
    total: int
    started_at: str
    status: str = "running"
    scanned: int = 0
    results: list[dict] = field(default_factory=list)
    completed_at: Optional[str] = None
    error: Optional[str] = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def to_model(self) -> ScanJob:
        with self.lock:
            return ScanJob(
                job_id=self.job_id,
                status=self.status,  # type: ignore[arg-type]
                subnet=self.subnet,
                ports=list(self.ports),
                rate_limit_pps=self.rate_limit_pps,
                progress=ScanProgress(scanned=self.scanned, total=self.total),
                results=[HostResult(**r) for r in self.results],
                consent_notice=CONSENT_NOTICE,
                started_at=self.started_at,
                completed_at=self.completed_at,
                error=self.error,
            )


def _scan_hosts(network: ipaddress.IPv4Network) -> list[str]:
    if network.num_addresses <= 2:
        return [str(ip) for ip in network]  # /31 or /32 -- no network/broadcast address to exclude
    return [str(ip) for ip in network.hosts()]


class LanScanService:
    def __init__(self, connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_SECONDS) -> None:
        self._connect_timeout = connect_timeout
        self._current: Optional[_JobState] = None
        self._manager_lock = threading.Lock()

    def start_scan(
        self,
        subnet: str,
        ports: list[int],
        rate_limit_pps: int,
        interfaces: InterfaceProvider,
        connector: PortConnector,
    ) -> ScanJob:
        with self._manager_lock:
            if self._current is not None and self._current.status == "running":
                raise ScanAlreadyRunning("a scan is already running; only one scan may run at a time")

            # Raises ScanValidationError (the caller/router turns this into
            # 400) -- validated *before* any job object or thread exists.
            network = validate_scan_request(subnet, ports, rate_limit_pps, list(interfaces.interfaces()))
            hosts = _scan_hosts(network)

            job = _JobState(
                job_id=f"scan_{secrets.token_hex(6)}",
                subnet=subnet,
                ports=list(ports),
                rate_limit_pps=rate_limit_pps,
                total=len(hosts) * len(ports),
                started_at=now_iso(),
            )
            self._current = job

        thread = threading.Thread(target=self._run, args=(job, hosts, connector), name=f"lanscan-{job.job_id}", daemon=True)
        job.thread = thread
        thread.start()
        return job.to_model()

    def _run(self, job: _JobState, hosts: list[str], connector: PortConnector) -> None:
        interval = 1.0 / job.rate_limit_pps
        try:
            for host in hosts:
                if job.cancel_event.is_set():
                    break
                open_ports: list[int] = []
                for port in job.ports:
                    if job.cancel_event.is_set():
                        break
                    is_open = connector.try_connect(host, port, self._connect_timeout)
                    with job.lock:
                        job.scanned += 1
                    if is_open:
                        open_ports.append(port)
                    if job.cancel_event.wait(timeout=interval):
                        break
                if open_ports:
                    with job.lock:
                        job.results.append({"ip": host, "open_ports": open_ports})
                if job.cancel_event.is_set():
                    break
        except Exception as exc:  # a connector bug must not leave the job stuck "running" forever
            with job.lock:
                job.status = "error"
                job.error = str(exc)
                job.completed_at = now_iso()
            return

        with job.lock:
            job.status = "cancelled" if job.cancel_event.is_set() else "completed"
            job.completed_at = now_iso()

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        if self._current is not None and self._current.job_id == job_id:
            return self._current.to_model()
        return None

    def cancel_job(self, job_id: str) -> Optional[ScanJob]:
        if self._current is None or self._current.job_id != job_id:
            return None
        job = self._current
        job.cancel_event.set()
        if job.thread is not None:
            job.thread.join(timeout=5.0)
        return job.to_model()


_default_service: Optional[LanScanService] = None


def get_lanscan_service() -> LanScanService:
    global _default_service
    if _default_service is None:
        _default_service = LanScanService()
    return _default_service

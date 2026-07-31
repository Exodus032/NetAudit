"""Zero-privilege capture tier: samples psutil.net_connections() and
psutil.net_io_counters() on an interval and synthesizes flow-level
PacketEvents from the deltas. No per-packet detail is possible this way --
this is documented in the README and reflected in health.degraded_reason
via the stale_capture_tier rule.
"""
from __future__ import annotations

import socket
import threading
import time

import psutil

from .. import config
from .base import CaptureBackend, PacketEvent


class PollingBackend(CaptureBackend):
    tier = "polling"

    def __init__(self, queue_max: int = config.CAPTURE_QUEUE_MAX,
                 interval: float = config.POLL_INTERVAL_SECONDS) -> None:
        super().__init__(queue_max=queue_max)
        self._interval = interval
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, interface_id: str | None = None) -> None:
        if self._running:
            return
        self.interface_id = interface_id
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run, name="netaudit-poll", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        prev_counters = self._snapshot_counters()
        prev_time = time.time()
        while not self._stop_event.is_set():
            self._stop_event.wait(self._interval)
            if self._stop_event.is_set():
                break
            now = time.time()
            dt = max(now - prev_time, 0.001)
            counters = self._snapshot_counters()
            d_sent = 0
            d_recv = 0
            if counters is not None and prev_counters is not None:
                d_sent = max(counters.bytes_sent - prev_counters.bytes_sent, 0)
                d_recv = max(counters.bytes_recv - prev_counters.bytes_recv, 0)
            prev_counters, prev_time = counters, now

            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, PermissionError, OSError):
                conns = []

            active = [c for c in conns if c.raddr and c.laddr]
            n = max(len(active), 1)
            share_in = d_recv / n
            share_out = d_sent / n

            for c in active:
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                name = path = None
                if c.pid is not None:
                    try:
                        p = psutil.Process(c.pid)
                        name = p.name()
                        path = p.exe()
                    except Exception:
                        pass
                event = PacketEvent(
                    ts=now,
                    protocol=proto,
                    src_addr=c.laddr.ip,
                    src_port=c.laddr.port,
                    dst_addr=c.raddr.ip,
                    dst_port=c.raddr.port,
                    length=int(share_in + share_out),
                    bytes_in=int(share_in),
                    bytes_out=int(share_out),
                    pid=c.pid,
                    process_name=name,
                    process_path=path,
                    state=c.status if proto == "tcp" else "ACTIVE",
                    synthetic=True,
                )
                self._emit(event)

    def _snapshot_counters(self):
        try:
            per_nic = psutil.net_io_counters(pernic=True)
        except Exception:
            return None
        if self.interface_id and self.interface_id in per_nic:
            return per_nic[self.interface_id]
        # Fall back to the busiest / any interface if we don't know which
        # one to pick -- polling tier is an approximation regardless.
        if per_nic:
            return next(iter(per_nic.values()))
        return None

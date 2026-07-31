from __future__ import annotations

import threading
import time

import pytest

from netaudit.lanscan.providers import StaticInterfaceProvider


class FakeConnector:
    """Never touches a real socket. `open_map` is a `{(ip, port): bool}`
    table; anything not listed is closed. Records every call for
    assertions (including timing, for the pacing test)."""

    def __init__(self, open_map=None, delay: float = 0.0):
        self.open_map = dict(open_map or {})
        self.calls: list[tuple[str, int, float]] = []  # (ip, port, monotonic_time)
        self._delay = delay

    def try_connect(self, ip: str, port: int, timeout: float) -> bool:
        self.calls.append((ip, port, time.perf_counter()))
        if self._delay:
            time.sleep(self._delay)
        return self.open_map.get((ip, port), False)


class BlockingConnector:
    """First call blocks until the test releases it (via `release_event`),
    letting a test synchronize "cancel arrives mid-attempt" deterministically
    instead of racing real time."""

    def __init__(self):
        self.first_call_started = threading.Event()
        self.release_event = threading.Event()
        self.calls: list[tuple[str, int]] = []

    def try_connect(self, ip: str, port: int, timeout: float) -> bool:
        self.calls.append((ip, port))
        if len(self.calls) == 1:
            self.first_call_started.set()
            self.release_event.wait(timeout=5.0)
        return False


@pytest.fixture
def home_interfaces():
    return StaticInterfaceProvider([{"address": "192.168.1.10", "prefixlen": 24}])

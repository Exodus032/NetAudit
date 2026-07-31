"""Per-peer token-bucket rate limiter for `/api` (Part C item 9).

A local browser page from a malicious site can still issue same-origin-free
GET requests or be pointed at 127.0.0.1 by the user, so the API is
rate-limited per source IP even though it's loopback-only. Kept dependency-
free and bounded in memory (Part C item 6): the bucket table has a hard cap
on distinct peers, since this is a single-user local tool and never needs
to track more than a handful of source addresses.
"""
from __future__ import annotations

import threading
import time


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, capacity: float) -> None:
        self.tokens = capacity
        self.last = time.monotonic()


class RateLimiter:
    def __init__(self, capacity: int = 120, window_seconds: float = 10.0, max_peers: int = 4096) -> None:
        self.capacity = float(capacity)
        self.window_seconds = float(window_seconds)
        self._refill_rate = self.capacity / self.window_seconds  # tokens/sec
        self._max_peers = max_peers
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, peer: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds). retry_after is 0 when allowed."""
        with self._lock:
            bucket = self._buckets.get(peer)
            if bucket is None:
                if len(self._buckets) >= self._max_peers:
                    # A local audit tool should never see thousands of
                    # distinct peers; if it somehow does, drop the table
                    # rather than growing unbounded.
                    self._buckets.clear()
                bucket = _Bucket(self.capacity)
                self._buckets[peer] = bucket

            now = time.monotonic()
            elapsed = max(now - bucket.last, 0.0)
            bucket.last = now
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self._refill_rate)

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0

            deficit = 1.0 - bucket.tokens
            wait = deficit / self._refill_rate
            return False, max(1, int(wait) + 1)

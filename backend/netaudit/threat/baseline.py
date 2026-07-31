"""Rolling per-process/per-peer baselines used by volume + novelty detectors.

A `Baseline` is built once per detector run from historical `FlowRecord`s
(a lookback window a detector queries itself, typically ending just before
the evaluation window under test) and is then read-only. There is no
persistence here -- baselines are cheap to rebuild from whatever history
the `TrafficSource` already holds, and rebuilding avoids ever going stale.

Every "does this fire" question a volume/novelty detector asks first checks
`has_*_baseline(...)`; detectors must not fire until the baseline has
`min_samples` observations, and must say so in their `detail` text when
that's why they stayed quiet.
"""
from __future__ import annotations

from statistics import fmean, pstdev
from typing import Iterable, Optional

from .source import FlowRecord


def _peer_key(process_name: Optional[str], remote_addr: Optional[str]) -> tuple[str, str]:
    return (process_name or "unknown", remote_addr or "unknown")


class Baseline:
    def __init__(self, min_samples: int = 5) -> None:
        self.min_samples = min_samples
        self._peer_bytes: dict[tuple[str, str], list[float]] = {}
        self._process_active_hours: dict[str, set[int]] = {}
        self._known_peers: dict[str, set[str]] = {}
        self._process_samples: dict[str, int] = {}

    @classmethod
    def from_flows(cls, flows: Iterable[FlowRecord], min_samples: int = 5) -> "Baseline":
        b = cls(min_samples=min_samples)
        for f in flows:
            b.observe(f)
        return b

    def observe(self, f: FlowRecord) -> None:
        proc = f.process_name or "unknown"
        total = float(f.bytes_in + f.bytes_out)
        key = _peer_key(proc, f.remote_addr)
        self._peer_bytes.setdefault(key, []).append(total)
        self._process_active_hours.setdefault(proc, set()).add(f.first_seen.hour)
        self._known_peers.setdefault(proc, set()).add(f.remote_addr or "unknown")
        self._process_samples[proc] = self._process_samples.get(proc, 0) + 1

    # -- volume ---------------------------------------------------------
    def peer_sample_count(self, process_name: Optional[str], remote_addr: Optional[str]) -> int:
        return len(self._peer_bytes.get(_peer_key(process_name, remote_addr), []))

    def has_peer_baseline(self, process_name: Optional[str], remote_addr: Optional[str]) -> bool:
        return self.peer_sample_count(process_name, remote_addr) >= self.min_samples

    def peer_volume_stats(self, process_name: Optional[str], remote_addr: Optional[str]) -> tuple[float, float]:
        """(mean, stdev) of historical per-flow byte totals for this
        process/peer pair. (0.0, 0.0) if there is no history at all."""
        vals = self._peer_bytes.get(_peer_key(process_name, remote_addr), [])
        if not vals:
            return 0.0, 0.0
        if len(vals) < 2:
            return fmean(vals), 0.0
        return fmean(vals), pstdev(vals)

    # -- novelty ---------------------------------------------------------
    def has_process_baseline(self, process_name: Optional[str]) -> bool:
        return self._process_samples.get(process_name or "unknown", 0) >= self.min_samples

    def is_known_peer(self, process_name: Optional[str], remote_addr: Optional[str]) -> bool:
        return (remote_addr or "unknown") in self._known_peers.get(process_name or "unknown", set())

    # -- off-hours ---------------------------------------------------------
    def has_hour_baseline(self, process_name: Optional[str]) -> bool:
        return self._process_samples.get(process_name or "unknown", 0) >= self.min_samples

    def is_active_hour(self, process_name: Optional[str], hour: int) -> bool:
        return hour in self._process_active_hours.get(process_name or "unknown", set())

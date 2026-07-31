"""ISO-8601 UTC 'Z' timestamp helpers used everywhere responses touch time."""
from __future__ import annotations

from datetime import datetime, timezone


def iso_z(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    # Match contract examples: milliseconds when non-zero, otherwise bare
    # seconds ("...T13:03:00Z" in the timeseries example). Keep it simple
    # and always emit milliseconds -- still valid ISO-8601 UTC 'Z' and every
    # example in the contract that omits them is also valid with them.
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    return s + "Z"


def now_iso() -> str:
    return iso_z(now_epoch())


def now_epoch() -> float:
    return datetime.now(tz=timezone.utc).timestamp()


def parse_iso(value: str) -> float:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

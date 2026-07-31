"""Shared statistical primitives for detectors.

Pure functions, no I/O, no imports from the rest of netaudit. Every function
is degenerate-input safe: empty input, a single sample, or all-identical
values never raise and never return NaN/inf -- they return None or 0.0 as
documented per function, and callers use that to mean "not enough signal
yet" rather than treating a sentinel as a real measurement.
"""
from __future__ import annotations

import math
from collections import Counter
from statistics import fmean, pstdev
from typing import Iterable, Optional, Sequence

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return fmean(values)


def coefficient_of_variation(values: Sequence[float]) -> Optional[float]:
    """Population stdev / mean. None if fewer than 2 samples or mean is 0
    (a CV is meaningless in both cases -- don't pretend it's 0)."""
    if len(values) < 2:
        return None
    m = fmean(values)
    if m == 0:
        return None
    sd = pstdev(values)
    return sd / m


def inter_arrival_times(timestamps: Sequence[float]) -> list[float]:
    """Non-negative gaps between consecutive timestamps, sorted first."""
    if len(timestamps) < 2:
        return []
    ordered = sorted(timestamps)
    return [b - a for a, b in zip(ordered, ordered[1:])]


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Empty string -> 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def longest_consonant_run(s: str) -> int:
    """Longest run of consecutive consonant letters (case-insensitive).
    Non-alpha characters and vowels break the run."""
    best = run = 0
    for ch in s.lower():
        if ch in CONSONANTS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def unique_char_ratio(s: str) -> float:
    if not s:
        return 0.0
    return len(set(s)) / len(s)


def ewma(values: Sequence[float], alpha: float = 0.3) -> list[float]:
    """Exponentially weighted moving average series, same length as input."""
    if not values:
        return []
    out = [float(values[0])]
    for v in values[1:]:
        out.append(alpha * v + (1 - alpha) * out[-1])
    return out


def ewma_update(prev: Optional[float], new: float, alpha: float = 0.3) -> float:
    """Roll a single new sample into a running EWMA. `prev=None` seeds it."""
    if prev is None:
        return new
    return alpha * new + (1 - alpha) * prev


def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation."""
    if not values:
        return 0.0
    m = median(values)
    return median([abs(v - m) for v in values])


def modified_zscores(values: Sequence[float]) -> list[float]:
    """Iglewicz & Hoaglin modified z-scores using MAD (robust to outliers
    unlike a mean/stdev z-score). All zeros if every value is identical."""
    if not values:
        return []
    m = median(values)
    d = mad(values)
    if d == 0:
        return [0.0 for _ in values]
    return [0.6745 * (v - m) / d for v in values]


def mad_outliers(values: Sequence[float], threshold: float = 3.5) -> list[bool]:
    """True for points whose modified z-score magnitude exceeds threshold.
    3.5 is the commonly cited Iglewicz & Hoaglin default."""
    return [abs(z) > threshold for z in modified_zscores(values)]


def zscore(value: float, population: Sequence[float]) -> Optional[float]:
    """Standard z-score of `value` against a population's mean/stdev. None
    if the population has fewer than 2 samples or zero variance -- there is
    no baseline to compare against yet."""
    if len(population) < 2:
        return None
    m = fmean(population)
    sd = pstdev(population)
    if sd == 0:
        return None
    return (value - m) / sd


def payload_uniformity(values: Sequence[float]) -> Optional[float]:
    """0..1 uniformity score for a set of magnitudes (e.g. payload sizes).
    1.0 = perfectly uniform, approaches 0 as spread grows. None if fewer
    than 2 samples."""
    cv = coefficient_of_variation(values)
    if cv is None:
        return None
    return 1.0 / (1.0 + cv)


def unique_ratio(items: Iterable) -> float:
    items = list(items)
    if not items:
        return 0.0
    return len(set(items)) / len(items)


def safe_ratio(numerator: float, denominator: float) -> float:
    """0.0 instead of ZeroDivisionError/NaN when denominator is 0."""
    if denominator == 0:
        return 0.0
    return numerator / denominator

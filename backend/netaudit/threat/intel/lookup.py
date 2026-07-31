"""`GET /api/intel/lookup` implementation + classification helpers.

Purely local: every answer comes from `bundled.py`'s in-memory index built
from data/indicators.json, plus the standard-library `ipaddress` module for
RFC1918/bogon/multicast classification. No network calls, ever -- see
tests/threat/test_no_network.py, which greps this whole package for
networking calls and fails if it finds one.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Literal, Optional

from . import bundled

Reputation = Literal["clean", "unknown", "suspicious", "malicious"]

# Confidence at/above which a bundled match is treated as "malicious"
# rather than merely "suspicious". Nothing in the shipped starter set
# reaches this today (see threat/README.md) -- it exists for indicator
# files an operator supplies themselves with higher-confidence data.
MALICIOUS_CONFIDENCE_THRESHOLD = 0.85


@dataclass
class Classification:
    is_private: bool = False
    is_bogon: bool = False
    is_multicast: bool = False
    is_tor_exit: bool = False  # always False: see README "known limitations" -- no exit list bundled
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None


@dataclass
class IntelMatch:
    source: str
    category: str
    confidence: float
    first_added: str
    note: str


@dataclass
class LookupResult:
    value: str
    type: str
    found: bool
    matches: list[IntelMatch] = field(default_factory=list)
    classification: Classification = field(default_factory=Classification)
    reputation: Reputation = "unknown"


# True RFC1918 private-use ranges only. Python's `ipaddress.is_private`
# is deliberately broader than this -- it also covers loopback, link-local,
# and the documentation/TEST-NET ranges (RFC 5737), which are "not globally
# routable" but are not "somebody's LAN" and must not read as a clean,
# nothing-to-see-here private address (traffic to a TEST-NET address on the
# wire is itself unusual, not routine).
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def classify_ip(value: str) -> Classification:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return Classification()
    is_priv = any(addr in net for net in _PRIVATE_NETWORKS)
    return Classification(
        is_private=is_priv,
        is_bogon=(not addr.is_global) and not is_priv,
        is_multicast=addr.is_multicast,
        is_tor_exit=False,
    )


def lookup(value: str, type_: str, index: Optional[bundled.IndicatorIndex] = None) -> LookupResult:
    value = value.strip()
    classification = classify_ip(value) if type_ == "ip" else Classification()
    entries = bundled.find_matches(value, type_, index=index)
    matches = [
        IntelMatch(source=e.source, category=e.category, confidence=e.confidence,
                   first_added=e.first_added, note=e.note)
        for e in entries
    ]
    reputation = _reputation_for(classification, matches)
    return LookupResult(
        value=value,
        type=type_,
        found=bool(matches),
        matches=matches,
        classification=classification,
        reputation=reputation,
    )


def _reputation_for(classification: Classification, matches: list[IntelMatch]) -> Reputation:
    # Private/loopback addresses are classified, not judged: a match against
    # our own bundled RFC1918/bogon entries (added purely for the
    # `classification` fields) must not make an ordinary LAN address read
    # as "suspicious".
    if classification.is_private:
        return "clean"
    if matches:
        best = max(m.confidence for m in matches)
        return "malicious" if best >= MALICIOUS_CONFIDENCE_THRESHOLD else "suspicious"
    return "unknown"

"""Loader + in-memory index for the local, offline indicator file.

`data/indicators.json` is the shipped starter set (see its header comment
and threat/README.md for what is and isn't in it, and why). `load(path)`
lets tests point at a fixture file instead of the shipped set so detector
tests never depend on -- or need to be updated when someone edits -- the
real bundled data.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

DATA_PATH = Path(__file__).resolve().parent / "data" / "indicators.json"

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class IndicatorEntry:
    value: str
    type: str  # "cidr" | "ip" | "domain" | "port"
    category: str
    confidence: float
    source: str
    note: str
    first_added: str


class IndicatorIndex:
    def __init__(self, entries: list[IndicatorEntry]) -> None:
        self.entries = entries
        self._networks: list[tuple[IPNetwork, IndicatorEntry]] = []
        self._ips: dict[str, list[IndicatorEntry]] = {}
        self._domains: dict[str, list[IndicatorEntry]] = {}
        self._ports: dict[int, list[IndicatorEntry]] = {}
        for e in entries:
            if e.type == "cidr":
                try:
                    self._networks.append((ipaddress.ip_network(e.value, strict=False), e))
                except ValueError:
                    continue
            elif e.type == "ip":
                self._ips.setdefault(e.value, []).append(e)
            elif e.type == "domain":
                self._domains.setdefault(e.value.lower().lstrip("."), []).append(e)
            elif e.type == "port":
                try:
                    self._ports.setdefault(int(e.value), []).append(e)
                except ValueError:
                    continue

    def match_ip(self, value: str) -> list[IndicatorEntry]:
        out = list(self._ips.get(value, []))
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return out
        for net, e in self._networks:
            if addr in net:
                out.append(e)
        return out

    def match_domain(self, value: str) -> list[IndicatorEntry]:
        v = value.lower().lstrip(".")
        out: list[IndicatorEntry] = []
        for suffix, entries in self._domains.items():
            if v == suffix or v.endswith("." + suffix):
                out.extend(entries)
        return out

    def match_port(self, value: int) -> list[IndicatorEntry]:
        return list(self._ports.get(value, []))


def load(path: Optional[Path] = None) -> IndicatorIndex:
    p = path or DATA_PATH
    with open(p, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    entries = [
        IndicatorEntry(
            value=item["value"],
            type=item["type"],
            category=item["category"],
            confidence=float(item["confidence"]),
            source=item["source"],
            note=item["note"],
            first_added=item.get("first_added", "unknown"),
        )
        for item in raw
    ]
    return IndicatorIndex(entries)


_default_index: Optional[IndicatorIndex] = None


def default_index() -> IndicatorIndex:
    global _default_index
    if _default_index is None:
        _default_index = load()
    return _default_index


def reset_default_index_for_tests() -> None:
    global _default_index
    _default_index = None


def find_matches(value: str, type_: str, index: Optional[IndicatorIndex] = None) -> list[IndicatorEntry]:
    idx = index or default_index()
    if type_ == "ip":
        return idx.match_ip(value)
    if type_ == "domain":
        return idx.match_domain(value)
    if type_ == "port":
        try:
            return idx.match_port(int(value))
        except ValueError:
            return []
    return []

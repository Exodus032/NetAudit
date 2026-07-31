"""Enrichment helpers: PID<->process mapping, reverse DNS, MAC vendor lookup,
and RFC1918 / encrypted-port classification. Kept dependency-light and safe
to call from a hot path -- nothing here blocks for long or raises.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import psutil

from .. import config

# --- Ports conventionally carrying encrypted traffic -----------------------
ENCRYPTED_PORTS = {443, 8443, 993, 995, 22, 465, 636, 990, 3389, 5986}
PLAINTEXT_PORTS = {80, 21, 23, 143, 110, 389}


def is_encrypted_port(port: int | None) -> bool:
    if port is None:
        return False
    return port in ENCRYPTED_PORTS


def is_plaintext_port(port: int | None) -> bool:
    if port is None:
        return False
    return port in PLAINTEXT_PORTS


def classify_external(addr: str) -> bool:
    """True if addr is a routable/external address, False if RFC1918,
    link-local, loopback, or other private space."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return False
    return True


# --- PID <-> local (proto, port) mapping ------------------------------------

class ProcessTable:
    """Refreshable snapshot of psutil.net_connections(), keyed by
    (protocol, local_port), used to attribute raw packets (which have no
    PID) to a process."""

    def __init__(self) -> None:
        self._map: dict[tuple[str, int], tuple[Optional[int], Optional[str], Optional[str]]] = {}
        self._lock = threading.Lock()

    def refresh(self) -> None:
        new_map: dict[tuple[str, int], tuple[Optional[int], Optional[str], Optional[str]]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
            conns = []
        proc_cache: dict[int, tuple[Optional[str], Optional[str]]] = {}
        for c in conns:
            if not c.laddr:
                continue
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            pid = c.pid
            name = path = None
            if pid is not None:
                if pid in proc_cache:
                    name, path = proc_cache[pid]
                else:
                    try:
                        p = psutil.Process(pid)
                        name = p.name()
                        path = p.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                        name = name or None
                        path = None
                    proc_cache[pid] = (name, path)
            new_map[(proto, c.laddr.port)] = (pid, name, path)
        with self._lock:
            self._map = new_map

    def lookup(self, protocol: str, local_port: int | None) -> tuple[Optional[int], Optional[str], Optional[str]]:
        if local_port is None:
            return (None, None, None)
        with self._lock:
            return self._map.get((protocol, local_port), (None, None, None))


# --- Reverse DNS, bounded + cached + async ---------------------------------

class ReverseDnsCache:
    """Bounded concurrency (max_workers threads, Part C item 6) and a
    bounded, LRU-evicted cache (max_entries) so a host that talks to a huge
    number of distinct remote addresses over a long-running capture can't
    grow this dict without limit."""

    def __init__(
        self,
        max_workers: int = config.DNS_MAX_WORKERS,
        max_entries: int = config.DNS_CACHE_MAX_ENTRIES,
    ) -> None:
        self._cache: "OrderedDict[str, Optional[str]]" = OrderedDict()
        self._max_entries = max_entries
        self._inflight: set[str] = set()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="netaudit-dns")

    def lookup(self, addr: str) -> Optional[str]:
        """Non-blocking: returns cached hostname (or None) immediately and
        kicks off a background resolution if we haven't seen this addr."""
        with self._lock:
            if addr in self._cache:
                self._cache.move_to_end(addr)
                return self._cache[addr]
            if addr in self._inflight:
                return None
            self._inflight.add(addr)
        self._executor.submit(self._resolve, addr)
        return None

    def _resolve(self, addr: str) -> None:
        hostname: Optional[str] = None
        try:
            hostname, _, _ = socket.gethostbyaddr(addr)
        except (socket.herror, socket.gaierror, OSError, socket.timeout):
            hostname = None
        with self._lock:
            self._cache[addr] = hostname
            self._cache.move_to_end(addr)
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)  # evict least-recently-used
            self._inflight.discard(addr)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


# --- MAC vendor lookup (tiny built-in OUI table; good enough for a LAN) -----

_OUI_VENDORS = {
    "00:1A:2B": "Cisco",
    "3C:5A:B4": "Google",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:14:22": "Dell",
    "00:1C:C0": "Dell",
    "F4:5C:89": "Apple",
    "AC:DE:48": "Apple",
    "3C:D9:2B": "Hewlett Packard",
    "00:1B:63": "Apple",
    "00:26:B6": "Netgear",
    "20:E5:2A": "Netgear",
    "C4:41:1E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:11:32": "Synology",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
}


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return _OUI_VENDORS.get(prefix, "Unknown")

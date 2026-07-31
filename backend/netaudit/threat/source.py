"""Input contract for the threat engine.

The rest of the `netaudit` package is being written concurrently and will
change under us, so detectors never import from it. They only ever see the
record types and the `TrafficSource` Protocol defined here. The
orchestrator is responsible for writing the real adapter from the live
store onto this Protocol; `ListTrafficSource` below is an in-memory
implementation used by tests and demos.

Field shapes intentionally mirror the v1 API_CONTRACT.md log/connection
entries (see /api/traffic/log, /api/connections) so a real adapter is a
thin, mostly 1:1 mapping.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional, Protocol, Sequence


@dataclass(frozen=True)
class PacketRecord:
    """Mirrors a v1 `/api/traffic/log` entry."""

    id: int
    ts: datetime
    protocol: str  # "tcp" | "udp" | "icmp" | "other"
    src_addr: str
    src_port: Optional[int]
    dst_addr: str
    dst_port: Optional[int]
    direction: str  # "inbound" | "outbound" | "local"
    length: int
    flags: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    remote_host: Optional[str] = None
    is_external: bool = False
    is_encrypted: bool = False
    summary: Optional[str] = None
    # Optional handshake metadata, only ever populated for TLS traffic and
    # only when the capture layer actually parsed a ClientHello/cert.
    # suspicious_tls must skip cleanly (not guess) when these are None.
    tls_version: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_alpn: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_cert_self_signed: Optional[bool] = None
    tls_cert_expired: Optional[bool] = None
    # Truncated (<=64 bytes, per Part C secrets rule), redacted-if-credential
    # payload snippet, only present when the capture layer chose to keep one.
    payload_snippet: Optional[str] = None


@dataclass(frozen=True)
class FlowRecord:
    """Mirrors a v1 `/api/connections` entry (a live or completed flow)."""

    id: str
    protocol: str
    state: str
    local_addr: Optional[str]
    local_port: Optional[int]
    remote_addr: Optional[str]
    remote_port: Optional[int]
    remote_host: Optional[str]
    remote_org: Optional[str]
    direction: str
    pid: Optional[int]
    process_name: Optional[str]
    process_path: Optional[str]
    bytes_in: int
    bytes_out: int
    packets: int
    first_seen: datetime
    last_seen: datetime
    is_external: bool
    is_encrypted: bool


@dataclass(frozen=True)
class DnsRecord:
    """One resolved (or attempted) DNS query."""

    ts: datetime
    query: str
    qtype: str  # "A" | "AAAA" | "TXT" | "NULL" | "CNAME" | "MX" | ...
    response_code: Optional[str] = None  # "NOERROR" | "NXDOMAIN" | ...
    resolved_ips: tuple[str, ...] = ()
    process_name: Optional[str] = None
    pid: Optional[int] = None
    query_bytes: Optional[int] = None
    response_bytes: Optional[int] = None
    server: Optional[str] = None  # resolver that answered


@dataclass(frozen=True)
class ArpRecord:
    """One L2 event: an ARP request/reply/gratuitous-ARP, or (event ==
    "dhcp_offer") a DHCP OFFER seen on the wire.

    DHCP offers are folded into this stream rather than given a fifth
    record/Protocol method because they are broadcast, L2-adjacent, and
    `rogue_dhcp` needs exactly the (ip, mac, ts) shape `arp_spoofing`
    already needs -- adding a whole new source method for one detector's
    one extra field wasn't worth the Protocol surface.
    """

    ts: datetime
    ip: str
    mac: str
    event: str  # "request" | "reply" | "gratuitous" | "dhcp_offer"
    is_gateway: bool = False
    dhcp_server_ip: Optional[str] = None  # set only when event == "dhcp_offer"


class TrafficSource(Protocol):
    def packets(self, since: datetime, until: datetime) -> Iterable[PacketRecord]: ...
    def flows(self, since: datetime, until: datetime) -> Iterable[FlowRecord]: ...
    def dns_events(self, since: datetime, until: datetime) -> Iterable[DnsRecord]: ...
    def arp_events(self, since: datetime, until: datetime) -> Iterable[ArpRecord]: ...


class ListTrafficSource:
    """In-memory `TrafficSource` for tests and demos.

    Packets/DNS/ARP are filtered inclusively on their own `ts`. Flows are
    filtered by interval overlap with [since, until] since a flow spans a
    range rather than a single instant.
    """

    def __init__(
        self,
        packets: Sequence[PacketRecord] = (),
        flows: Sequence[FlowRecord] = (),
        dns_events: Sequence[DnsRecord] = (),
        arp_events: Sequence[ArpRecord] = (),
    ) -> None:
        self._packets = list(packets)
        self._flows = list(flows)
        self._dns = list(dns_events)
        self._arp = list(arp_events)

    def packets(self, since: datetime, until: datetime) -> Iterable[PacketRecord]:
        return [p for p in self._packets if since <= p.ts <= until]

    def flows(self, since: datetime, until: datetime) -> Iterable[FlowRecord]:
        return [f for f in self._flows if f.first_seen <= until and f.last_seen >= since]

    def dns_events(self, since: datetime, until: datetime) -> Iterable[DnsRecord]:
        return [d for d in self._dns if since <= d.ts <= until]

    def arp_events(self, since: datetime, until: datetime) -> Iterable[ArpRecord]:
        return [a for a in self._arp if since <= a.ts <= until]

    def add_packets(self, *records: PacketRecord) -> None:
        self._packets.extend(records)

    def add_flows(self, *records: FlowRecord) -> None:
        self._flows.extend(records)

    def add_dns(self, *records: DnsRecord) -> None:
        self._dns.extend(records)

    def add_arp(self, *records: ArpRecord) -> None:
        self._arp.extend(records)

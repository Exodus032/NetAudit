"""Pydantic response models matching API_CONTRACT.md field-for-field.

These are used for documentation/OpenAPI and for the handful of endpoints
where wiring response_model buys real safety. Most routers build plain
dicts by hand and return them directly (FastAPI serializes dicts fine) --
that keeps the exact shape under our control instead of pydantic silently
dropping/coercing a field we forgot to declare.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel


class CaptureInfo(BaseModel):
    mode: Literal["npcap", "rawsocket", "polling", "off"]
    elevated: bool
    interface: Optional[str]
    running: bool
    degraded_reason: Optional[str]


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    capture: CaptureInfo


class InterfaceInfo(BaseModel):
    id: str
    name: str
    description: Optional[str]
    ipv4: Optional[str]
    ipv6: Optional[str]
    mac: Optional[str]
    netmask: Optional[str]
    is_up: bool
    is_loopback: bool
    speed_mbps: Optional[int]


class InterfacesResponse(BaseModel):
    interfaces: list[InterfaceInfo]
    default_interface_id: Optional[str]


class AlertsBySeverity(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class StatsSummary(BaseModel):
    window: str
    generated_at: str
    packets_total: int
    bytes_total: int
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    throughput_bps_in: int
    throughput_bps_out: int
    peak_throughput_bps: int
    active_flows: int
    unique_remote_hosts: int
    unique_processes: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    encrypted_bytes: int
    plaintext_bytes: int
    external_bytes: int
    internal_bytes: int
    open_alerts: int
    alerts_by_severity: AlertsBySeverity


class TimeseriesPoint(BaseModel):
    t: str
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    tcp: int
    udp: int
    icmp: int
    other: int


class TimeseriesResponse(BaseModel):
    window: str
    bucket_seconds: int
    points: list[TimeseriesPoint]


class TopItem(BaseModel):
    key: str
    label: Optional[str]
    sublabel: Optional[str]
    bytes_in: int
    bytes_out: int
    bytes_total: int
    packets: int
    flows: int
    share: float
    is_external: bool
    risk: Literal["low", "medium", "high"]


class TopResponse(BaseModel):
    by: str
    window: str
    items: list[TopItem]


class ConnectionItem(BaseModel):
    id: str
    protocol: str
    state: str
    local_addr: Optional[str]
    local_port: Optional[int]
    remote_addr: Optional[str]
    remote_port: Optional[int]
    remote_host: Optional[str]
    remote_org: Optional[str]
    direction: Literal["inbound", "outbound", "local"]
    pid: Optional[int]
    process_name: Optional[str]
    process_path: Optional[str]
    bytes_in: int
    bytes_out: int
    packets: int
    first_seen: str
    last_seen: str
    is_external: bool
    is_encrypted: bool
    risk: Literal["low", "medium", "high"]
    risk_reasons: list[str]


class ConnectionsResponse(BaseModel):
    generated_at: str
    connections: list[ConnectionItem]


class TrafficLogEntry(BaseModel):
    id: int
    ts: str
    protocol: str
    src_addr: str
    src_port: Optional[int]
    dst_addr: str
    dst_port: Optional[int]
    direction: str
    length: int
    flags: str
    process_name: Optional[str]
    pid: Optional[int]
    remote_host: Optional[str]
    is_external: bool
    is_encrypted: bool
    summary: str
    risk: str


class TrafficLogResponse(BaseModel):
    total: int
    limit: int
    offset: int
    entries: list[TrafficLogEntry]


class DeviceItem(BaseModel):
    ip: str
    mac: Optional[str]
    vendor: Optional[str]
    hostname: Optional[str]
    first_seen: str
    last_seen: str
    bytes_total: int
    is_gateway: bool
    is_self: bool
    open_ports: list[int]
    risk: str


class DevicesResponse(BaseModel):
    devices: list[DeviceItem]


class EvidenceItem(BaseModel):
    label: str
    value: str


class ActionItem(BaseModel):
    label: str
    kind: Literal["manual", "command", "link"]
    detail: Optional[str] = None
    command: Optional[str] = None
    requires_admin: Optional[bool] = None
    url: Optional[str] = None


class Recommendation(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    category: Literal["encryption", "exposure", "suspicious_peer", "configuration", "volume", "discovery", "hygiene"]
    summary: str
    detail: str
    evidence: list[EvidenceItem]
    actions: list[ActionItem]
    first_seen: str
    last_seen: str
    occurrences: int
    dismissed: bool
    related_connection_ids: list[str]


class RecommendationsResponse(BaseModel):
    generated_at: str
    recommendations: list[Recommendation]


class DismissResponse(BaseModel):
    id: str
    dismissed: bool


class CaptureStartRequest(BaseModel):
    interface_id: Optional[str] = None


class ClearResponse(BaseModel):
    cleared: bool


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody

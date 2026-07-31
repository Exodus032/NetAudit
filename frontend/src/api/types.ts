// Hand-written types mirroring docs/API_CONTRACT.md exactly. Do not diverge from
// field names, enum values, or shapes documented there.

export type CaptureMode = "npcap" | "rawsocket" | "polling" | "off";

export interface CaptureStatus {
  mode: CaptureMode;
  elevated: boolean;
  interface: string;
  running: boolean;
  degraded_reason: string | null;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime_seconds: number;
  capture: CaptureStatus;
}

export interface NetInterface {
  id: string;
  name: string;
  description: string;
  ipv4: string;
  ipv6: string;
  mac: string;
  netmask: string;
  is_up: boolean;
  is_loopback: boolean;
  speed_mbps: number;
}

export interface InterfacesResponse {
  interfaces: NetInterface[];
  default_interface_id: string;
}

export type StatsWindow = "5m" | "15m" | "1h" | "24h" | "all";

export interface AlertsBySeverity {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface StatsSummary {
  window: StatsWindow;
  generated_at: string;
  packets_total: number;
  bytes_total: number;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  throughput_bps_in: number;
  throughput_bps_out: number;
  peak_throughput_bps: number;
  active_flows: number;
  unique_remote_hosts: number;
  unique_processes: number;
  tcp_packets: number;
  udp_packets: number;
  icmp_packets: number;
  other_packets: number;
  encrypted_bytes: number;
  plaintext_bytes: number;
  external_bytes: number;
  internal_bytes: number;
  open_alerts: number;
  alerts_by_severity: AlertsBySeverity;
}

export interface TimeseriesPoint {
  t: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  tcp: number;
  udp: number;
  icmp: number;
  other: number;
}

export interface TimeseriesResponse {
  window: StatsWindow;
  bucket_seconds: number;
  points: TimeseriesPoint[];
}

export type TopBy = "host" | "process" | "port" | "protocol" | "country";
export type RiskLevel = "low" | "medium" | "high";

export interface TopItem {
  key: string;
  label: string;
  sublabel: string;
  bytes_in: number;
  bytes_out: number;
  bytes_total: number;
  packets: number;
  flows: number;
  share: number;
  is_external: boolean;
  risk: RiskLevel;
}

export interface TopResponse {
  by: TopBy;
  window: StatsWindow;
  items: TopItem[];
}

export type ConnectionDirection = "inbound" | "outbound" | "local";

export interface Connection {
  id: string;
  protocol: string;
  state: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  remote_host: string;
  remote_org: string;
  direction: ConnectionDirection;
  pid: number;
  process_name: string;
  process_path: string;
  bytes_in: number;
  bytes_out: number;
  packets: number;
  first_seen: string;
  last_seen: string;
  is_external: boolean;
  is_encrypted: boolean;
  risk: RiskLevel;
  risk_reasons: string[];
}

export interface ConnectionsResponse {
  generated_at: string;
  connections: Connection[];
}

export interface TrafficLogEntry {
  id: number;
  ts: string;
  protocol: string;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  direction: ConnectionDirection;
  length: number;
  flags: string;
  process_name: string;
  pid: number;
  remote_host: string;
  is_external: boolean;
  is_encrypted: boolean;
  summary: string;
  risk: RiskLevel;
}

export interface TrafficLogResponse {
  total: number;
  limit: number;
  offset: number;
  entries: TrafficLogEntry[];
}

export interface TrafficLogQuery {
  limit?: number;
  offset?: number;
  protocol?: string;
  q?: string;
  since?: string;
  until?: string;
  direction?: ConnectionDirection;
  min_bytes?: number;
  sort?: "time" | "bytes";
  order?: "asc" | "desc";
}

export interface Device {
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  first_seen: string;
  last_seen: string;
  bytes_total: number;
  is_gateway: boolean;
  is_self: boolean;
  open_ports: number[];
  risk: RiskLevel;
}

export interface DevicesResponse {
  devices: Device[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RecommendationCategory =
  | "encryption"
  | "exposure"
  | "suspicious_peer"
  | "configuration"
  | "volume"
  | "discovery"
  | "hygiene";
export type ActionKind = "manual" | "command" | "link";

export interface EvidenceItem {
  label: string;
  value: string;
}

export interface RecommendationAction {
  label: string;
  kind: ActionKind;
  detail: string;
  command?: string;
  requires_admin?: boolean;
  url?: string;
}

export interface Recommendation {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  category: RecommendationCategory;
  summary: string;
  detail: string;
  evidence: EvidenceItem[];
  actions: RecommendationAction[];
  first_seen: string;
  last_seen: string;
  occurrences: number;
  dismissed: boolean;
  related_connection_ids: string[];
}

export interface RecommendationsResponse {
  generated_at: string;
  recommendations: Recommendation[];
}

export interface DismissResponse {
  id: string;
  dismissed: boolean;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}

// --- WebSocket frames -------------------------------------------------

export interface WsStatsFrame {
  type: "stats";
  data: StatsSummary;
}
export interface WsLogFrame {
  type: "log";
  data: TrafficLogEntry[];
}
export interface WsAlertFrame {
  type: "alert";
  data: Recommendation;
}
export interface WsConnectionsFrame {
  type: "connections";
  data: Connection[];
}
export interface WsCaptureFrame {
  type: "capture";
  data: CaptureStatus;
}

export type WsFrame =
  | WsStatsFrame
  | WsLogFrame
  | WsAlertFrame
  | WsConnectionsFrame
  | WsCaptureFrame
  | { type: string; data: unknown };

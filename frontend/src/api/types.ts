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

// =======================================================================
// v2 security extensions â€” docs/API_CONTRACT_V2_SECURITY.md (FROZEN)
// =======================================================================

// --- Part A: host security posture ------------------------------------

export type CheckStatus = "pass" | "warn" | "fail" | "error" | "skipped";
export type Grade = "A" | "B" | "C" | "D" | "F";

export interface RemediationCommand {
  shell: string;
  command: string;
  requires_admin: boolean;
  reversible: boolean;
  risk_note?: string;
}

export interface Remediation {
  summary: string;
  commands: RemediationCommand[];
  docs_url?: string;
}

export interface PostureCheck {
  id: string;
  category: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  score_weight: number;
  observed: string;
  expected: string;
  why_it_matters: string;
  evidence: EvidenceItem[];
  remediation: Remediation;
  references: string[];
  checked_at: string;
  duration_ms: number;
}

export interface PostureCategorySummary {
  id: string;
  label: string;
  score: number;
  checks: string[];
}

export interface PostureCounts {
  pass: number;
  warn: number;
  fail: number;
  error: number;
  skipped: number;
}

export interface PostureResponse {
  generated_at: string;
  scan_duration_ms: number;
  score: number;
  grade: Grade;
  counts: PostureCounts;
  categories: PostureCategorySummary[];
  checks: PostureCheck[];
}

export interface PostureQuery {
  category?: string;
  include_pass?: boolean;
}

export interface PostureRescanBody {
  categories?: string[];
}

// --- Composite security score -----------------------------------------

export type ScoreComponentKind = "posture" | "threat" | "recommendation";
export type Effort = "low" | "medium" | "high";

export interface ScoreComponent {
  id: string;
  label: string;
  score: number;
  weight: number;
  grade: Grade;
}

export interface ScoreHistoryPoint {
  t: string;
  overall: number;
}

export interface TopWin {
  id: string;
  kind: ScoreComponentKind;
  title: string;
  score_gain: number;
  effort: Effort;
}

export interface SecurityScoreResponse {
  generated_at: string;
  overall: number;
  grade: Grade;
  components: ScoreComponent[];
  history: ScoreHistoryPoint[];
  top_wins: TopWin[];
}

// --- Part B: threat detection -------------------------------------------

export type ThreatStatus = "active" | "resolved" | "acknowledged";
export type ThreatCategory =
  | "command_and_control"
  | "exfiltration"
  | "reconnaissance"
  | "lateral_movement"
  | "credential_exposure"
  | "dns_abuse"
  | "spoofing"
  | "malicious_peer"
  | "policy_violation"
  | "anomaly";
export type IndicatorType = "ip" | "domain" | "url" | "port" | "process" | "mac" | "ja3" | "hash";
export type ThreatActionKind = "manual" | "command" | "link";

export interface MitreRef {
  tactic: string;
  tactic_name?: string;
  technique: string;
  technique_name?: string;
}

export interface ThreatIndicator {
  type: IndicatorType;
  value: string;
  context?: string;
}

export interface ThreatMetrics {
  [key: string]: number | string | undefined;
}

export interface ThreatAction {
  label: string;
  kind: ThreatActionKind;
  shell?: string;
  command?: string;
  requires_admin?: boolean;
  reversible?: boolean;
  detail: string;
  url?: string;
}

export interface Threat {
  id: string;
  detector_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  category: ThreatCategory;
  status: ThreatStatus;
  mitre: MitreRef[];
  summary: string;
  detail: string;
  evidence: EvidenceItem[];
  indicators: ThreatIndicator[];
  metrics: ThreatMetrics;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  related_connection_ids: string[];
  related_log_ids: number[];
  false_positive_notes: string;
  recommended_actions: ThreatAction[];
  acknowledged_note?: string;
}

export interface ThreatsQuery {
  limit?: number;
  offset?: number;
  severity?: Severity;
  category?: ThreatCategory;
  status?: ThreatStatus;
  since?: string;
  until?: string;
  q?: string;
  include_acknowledged?: boolean;
}

export interface ThreatsResponse {
  total: number;
  limit: number;
  offset: number;
  threats: Threat[];
}

export interface ThreatAckResponse {
  id: string;
  status: ThreatStatus;
  note?: string;
}

export interface ThreatTimelinePoint {
  t: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ThreatTimelineResponse {
  window: StatsWindow;
  bucket_seconds: number;
  points: ThreatTimelinePoint[];
}

export interface DetectorTunable {
  key: string;
  value: number | string | boolean;
  type: "int" | "float" | "bool" | "string";
  min?: number;
  max?: number;
  description: string;
}

export interface Detector {
  id: string;
  label: string;
  category: ThreatCategory;
  description: string;
  enabled: boolean;
  default_severity: Severity;
  mitre: Partial<MitreRef>[];
  tunables: DetectorTunable[];
  fired_count: number;
  last_fired: string | null;
}

export interface DetectorsResponse {
  detectors: Detector[];
}

// --- Bootstrap (Part C item 2) -----------------------------------------

export interface BootstrapResponse {
  token: string;
  version: string;
  capture_mode: CaptureMode;
}

// =======================================================================
// v3 learning mode â€” docs/API_CONTRACT_V3.md Part D (FROZEN)
// =======================================================================

export type GlossaryCategory = "protocol" | "security" | "networking" | "tool";
export type Difficulty = "beginner" | "intermediate" | "advanced";

export interface GlossaryTerm {
  id: string;
  term: string;
  expansion?: string | null;
  short: string;
  detail: string;
  why_it_matters: string;
  see_also: string[];
  category: GlossaryCategory;
  difficulty: Difficulty;
}

export interface GlossaryResponse {
  terms: GlossaryTerm[];
}

export type ExplainKind = "detector" | "rule" | "check" | "metric" | "field";

export interface WorkedExample {
  scenario: string;
  walkthrough: string[];
}

export interface Explanation {
  kind: ExplainKind;
  id: string;
  title: string;
  plain: string;
  how_it_decides: string;
  what_would_make_it_wrong: string;
  worked_example?: WorkedExample | null;
  glossary_terms: string[];
  learn_more?: string | null;
}

/** Matches the six views the frontend actually renders â€” same ids the D4
 * tour and D5 lessons content use for `view`/`check.value`. */
export type LearnViewId = "overview" | "traffic-log" | "connections" | "recommendations" | "posture" | "threats";

export interface TourStep {
  id: string;
  order: number;
  view: LearnViewId;
  target: string;
  title: string;
  body: string;
  glossary_terms: string[];
  action_hint: string | null;
}

export interface TourResponse {
  steps: TourStep[];
}

export type LessonCheckKind = "view_visited" | "filter_applied" | "element_clicked" | "manual";

export interface LessonCheck {
  kind: LessonCheckKind;
  value: string;
}

export interface LessonStep {
  order: number;
  instruction: string;
  explanation: string;
  check: LessonCheck;
  glossary_terms: string[];
}

export interface Lesson {
  id: string;
  title: string;
  summary: string;
  difficulty: Difficulty;
  estimated_minutes: number;
  prerequisites: string[];
  objectives: string[];
  steps: LessonStep[];
  uses_live_data: boolean;
}

export interface LessonsResponse {
  lessons: Lesson[];
}

export interface DeepLink {
  view: string;
  id: string;
}

export type FindingSource = "posture" | "recommendation" | "threat";

export interface PrioritisedFinding {
  id: string;
  source: FindingSource;
  title: string;
  severity: Severity;
  impact_score: number;
  effort: Effort;
  observed?: string | null;
  priority_rank: number;
  why_first: string;
  one_line_fix: string;
  deep_link: DeepLink;
}

export interface PrioritisedFindingsResponse {
  generated_at: string;
  items: PrioritisedFinding[];
}

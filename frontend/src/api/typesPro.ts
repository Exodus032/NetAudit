// Hand-written types mirroring docs/API_CONTRACT_V3.md Part E (professional
// workflows) and Part F (compliance/alerting) exactly. Do not diverge from
// field names, enum values, or shapes documented there — cross-checked
// against the real backend Pydantic models under backend/netaudit/{pcap,
// export,lanscan,baselines,compliance,alerts}/models.py.

import type { Severity } from "./types";

// =======================================================================
// E1-E3: PCAP export / import / sessions
// =======================================================================

export type PcapProtocol = "tcp" | "udp" | "icmp" | "other";

export interface PcapExportQuery {
  since?: string;
  until?: string;
  protocol?: PcapProtocol;
  peer?: string;
  port?: number;
  limit?: number;
}

export interface PcapImportResponse {
  session_id: string;
  filename: string;
  packets: number;
  bytes: number;
  first_packet: string | null;
  last_packet: string | null;
  linktype: string;
  truncated: boolean;
  parse_errors: number;
}

export type SessionKind = "live" | "imported";

export interface CaptureSession {
  id: string;
  kind: SessionKind;
  label: string;
  packets: number;
  synthetic: boolean;
  synthetic_reason?: string | null;
  imported_at?: string | null;
}

export interface SessionsResponse {
  sessions: CaptureSession[];
}

export interface DeleteSessionResponse {
  id: string;
  deleted: boolean;
}

// =======================================================================
// E4: capture filter
// =======================================================================

export interface CaptureFilterState {
  expression: string;
  valid: boolean;
  error: string | null;
  applies_to_tier: string[];
  active: boolean;
  compiled_summary: string | null;
}

/** Thrown by updateCaptureFilter() on a 400 — carries the parser's exact
 * character position alongside the message, per E4 ("returns 400 with the
 * parse error and position"). ApiError alone can't carry `position`. */
export class BpfFilterError extends Error {
  position: number;
  constructor(message: string, position: number) {
    super(message);
    this.name = "BpfFilterError";
    this.position = position;
  }
}

// =======================================================================
// E5: report generation
// =======================================================================

export type ReportFormat = "html" | "markdown" | "json";

export const REPORT_SECTIONS = ["summary", "posture", "threats", "recommendations", "traffic", "devices"] as const;
export type ReportSection = (typeof REPORT_SECTIONS)[number];

export interface ReportRequest {
  format: ReportFormat;
  sections: ReportSection[];
  window: string;
  title: string;
}

/** The report body streamed back by POST/GET — the backend returns raw
 * text (PlainTextResponse), not a JSON envelope, so the client reconstructs
 * this shape from the response body + headers. */
export interface ReportContent {
  id: string;
  content: string;
  format: ReportFormat;
  filename: string;
}

export interface ReportListItem {
  id: string;
  title: string;
  format: ReportFormat;
  window: string;
  sections: string[];
  generated_at: string;
  filename: string;
  bytes: number;
}

export interface ReportsListResponse {
  reports: ReportListItem[];
}

export interface DeleteReportResponse {
  id: string;
  deleted: boolean;
}

// =======================================================================
// E6: SIEM / log-pipeline export
// =======================================================================

export type SiemFormat = "jsonl" | "cef" | "syslog" | "ecs";
export type SiemEventKind = "threat" | "recommendation" | "posture" | "traffic";

export const SIEM_EVENT_KINDS: SiemEventKind[] = ["threat", "recommendation", "posture", "traffic"];

export interface SiemExportQuery {
  format: SiemFormat;
  since?: string;
  until?: string;
  kinds?: SiemEventKind[];
}

export interface SiemExportResult {
  text: string;
  contentType: string;
  filename: string;
}

// =======================================================================
// E7: active LAN scan
// =======================================================================

export type ScanJobStatus = "running" | "completed" | "cancelled" | "error";

export interface ScanRequest {
  subnet: string;
  ports: number[];
  rate_limit_pps: number;
}

export interface ScanProgress {
  scanned: number;
  total: number;
}

export interface HostResult {
  ip: string;
  open_ports: number[];
}

export interface ScanJob {
  job_id: string;
  status: ScanJobStatus;
  subnet: string;
  ports: number[];
  rate_limit_pps: number;
  progress: ScanProgress;
  results: HostResult[];
  consent_notice: string;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

// Server-side guarantees the UI shows as permanent facts, not errors to hit.
export const LAN_SCAN_LIMITS = {
  maxPrefixLen: 24,
  maxPorts: 20,
  maxRatePps: 100,
  scanKind: "TCP connect only",
} as const;

// =======================================================================
// E8: baseline snapshots
// =======================================================================

export interface BaselineRef {
  id: string;
  label: string;
  captured_at: string;
}

export type BaselineOrigin = "manual" | "scheduled";

export type BaselineScheduleInterval = 6 | 12 | 24 | 48 | 168;

export interface BaselineSchedule {
  enabled: boolean;
  interval_hours: BaselineScheduleInterval;
  last_succeeded_at: string | null;
  next_due_at: string | null;
  last_error: string | null;
}


export interface BaselineListItem extends BaselineRef {
  origin: BaselineOrigin;
  checks_count: number;
  peers_count: number;
  listeners_count: number;
  posture_score: number;
  threats_score: number | null;
  overall_score: number;
}

export interface BaselinesResponse {
  baselines: BaselineListItem[];
}

export interface ScoreDelta {
  posture: number;
  threats: number;
  overall: number;
}

export interface CheckTransition {
  id: string;
  from: string;
  to: string;
}

export interface CheckPresence {
  id: string;
  status: string;
}

export interface ChecksDiff {
  fixed: CheckTransition[];
  regressed: CheckTransition[];
  unchanged_count: number;
  added: CheckPresence[];
  removed: CheckPresence[];
  inconclusive: CheckTransition[];
}

export interface ListenerRef {
  port: number;
  process: string;
}

export interface BaselineDiff {
  from: BaselineRef;
  to: BaselineRef;
  score_delta: ScoreDelta;
  checks: ChecksDiff;
  new_peers: string[];
  new_listeners: ListenerRef[];
  removed_listeners: ListenerRef[];
}

// =======================================================================
// F1-F2: compliance
// =======================================================================

export interface ComplianceFrameworkSummary {
  id: string;
  label: string;
  controls_mapped: number;
  checks_mapped: number;
  coverage_note: string;
}

export interface FrameworksResponse {
  frameworks: ComplianceFrameworkSummary[];
}

export type ControlStatus = "pass" | "fail" | "partial" | "not_assessed";

export interface EvidenceCheck {
  check_id: string;
  status: string;
}

export interface ComplianceControl {
  control_id: string;
  title: string;
  status: ControlStatus;
  evidence_checks: EvidenceCheck[];
  rationale: string;
}

export interface ComplianceSummary {
  pass: number;
  fail: number;
  partial: number;
  not_assessed: number;
  coverage_percent: number;
}

export interface ComplianceReport {
  framework: { id: string; label: string };
  generated_at: string;
  summary: ComplianceSummary;
  disclaimer: string;
  controls: ComplianceControl[];
}

// =======================================================================
// F3-F4: alerting
// =======================================================================

export type AlertChannelKind = "desktop" | "webhook" | "slack";
export type AlertChannelStatus = "delivered" | "failed" | "unavailable" | "rate_limited" | "suppressed";

export interface QuietHours {
  start: string;
  end: string;
}

export interface AlertChannel {
  id: string;
  kind: AlertChannelKind;
  enabled: boolean;
  url?: string | null;
  template?: string | null;
  last_status?: string | null;
  last_attempt?: string | null;
}

export interface AlertsConfig {
  enabled: boolean;
  min_severity: Severity;
  channels: AlertChannel[];
  rate_limit_per_hour: number;
  quiet_hours: QuietHours | null;
}

export interface AlertTestResult {
  channel_id: string;
  status: AlertChannelStatus;
  detail?: string | null;
  attempted_at: string;
}

export interface AlertHistoryChannelResult {
  id: string;
  status: AlertChannelStatus;
}

export interface AlertHistoryItem {
  id: string;
  ts: string;
  severity: Severity;
  source: string;
  source_id: string;
  title: string;
  channels: AlertHistoryChannelResult[];
}

export interface AlertHistoryResponse {
  alerts: AlertHistoryItem[];
}

export type EnrichmentProviderId = "abuseipdb" | "virustotal";

/** One reputation provider as the API reports it: the key is never echoed
 * back, `has_key` is the only key fact the client gets. */
export interface EnrichmentProvider {
  id: EnrichmentProviderId;
  enabled: boolean;
  has_key: boolean;
  last_status?: string | null;
  last_attempt?: string | null;
}

/** Accepted by PUT. `api_key` replaces the stored key when provided;
 * `clear_key` drops it explicitly; neither set means the stored key is
 * kept. */
export interface EnrichmentProviderUpdate {
  id: EnrichmentProviderId;
  enabled: boolean;
  api_key?: string | null;
  clear_key?: boolean;
}

export interface EnrichmentConfig {
  enabled: boolean;
  min_severity: Severity;
  cache_ttl_hours: number;
  providers: EnrichmentProvider[];
}

export interface EnrichmentConfigUpdate {
  enabled: boolean;
  min_severity: Severity;
  cache_ttl_hours: number;
  providers: EnrichmentProviderUpdate[];
}

export interface EnrichmentTestResult {
  provider_id: EnrichmentProviderId;
  status: AlertChannelStatus;
  detail?: string | null;
  attempted_at: string;
}

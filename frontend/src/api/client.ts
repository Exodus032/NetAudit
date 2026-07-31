// Typed fetch wrapper — one function per REST endpoint in docs/API_CONTRACT.md.
// Set VITE_USE_MOCKS=1 to force the in-memory mock backend. Otherwise this
// talks to the real backend at /api (proxied to 127.0.0.1:8787 by Vite) and
// falls back to mocks automatically if the backend is unreachable.

import { setBackendMode } from "./backendMode";
import { BootstrapError, ensureToken, invalidateToken } from "./auth";
import {
  mockCaptureClear,
  mockCaptureStart,
  mockCaptureStatus,
  mockCaptureStop,
  mockConnections,
  mockDevices,
  mockDismiss,
  mockExportRows,
  mockHealth,
  mockInterfaces,
  mockPosture,
  mockPostureCheck,
  mockPostureRescan,
  mockRecommendations,
  mockSecurityScore,
  mockStatsSummary,
  mockThreat,
  mockThreatAck,
  mockThreats,
  mockThreatsTimeline,
  mockTimeseries,
  mockTop,
  mockTrafficLog,
} from "../mocks/server";
import { startMockTicker } from "../mocks/store";
import type {
  ApiErrorBody,
  CaptureStatus,
  ConnectionsResponse,
  DevicesResponse,
  DismissResponse,
  HealthResponse,
  InterfacesResponse,
  PostureCheck,
  PostureQuery,
  PostureResponse,
  RecommendationsResponse,
  SecurityScoreResponse,
  StatsSummary,
  StatsWindow,
  Threat,
  ThreatAckResponse,
  ThreatsQuery,
  ThreatsResponse,
  ThreatTimelineResponse,
  TimeseriesResponse,
  TopBy,
  TopResponse,
  TrafficLogEntry,
  TrafficLogQuery,
  TrafficLogResponse,
} from "./types";

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = "ApiError";
  }
}

const FORCE_MOCKS = import.meta.env.VITE_USE_MOCKS === "1";

if (FORCE_MOCKS) {
  setBackendMode("forced-mock");
  startMockTicker();
}

function isNetworkError(err: unknown): boolean {
  // A BootstrapError means we couldn't get a token at all — from the
  // frontend's point of view that's equivalent to "backend unreachable", so
  // it takes the same fallback-to-mock path as a raw network failure.
  return err instanceof TypeError || err instanceof BootstrapError;
}

async function fetchWithToken(path: string, init?: RequestInit): Promise<Response> {
  const token = await ensureToken();
  const headers = new Headers(init?.headers);
  if (token) headers.set("X-NetAudit-Token", token);
  return fetch(path, { ...init, headers });
}

async function realFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res = await fetchWithToken(path, init);
  if (res.status === 401) {
    // Token may have expired or the backend restarted with a new one — drop
    // it and retry exactly once with a freshly bootstrapped token.
    invalidateToken();
    res = await fetchWithToken(path, init);
  }
  if (!res.ok) {
    let body: ApiErrorBody | null = null;
    try {
      body = await res.json();
    } catch {
      // ignore parse failure, fall through to generic message
    }
    throw new ApiError(res.status, body?.error?.code ?? "unknown_error", body?.error?.message ?? res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

/** Try the real backend; on network failure, flip to mock mode and retry via the mock fn. */
async function withFallback<T>(path: string, init: RequestInit | undefined, mockFn: () => Promise<T>): Promise<T> {
  if (FORCE_MOCKS) return mockFn();
  try {
    const result = await realFetch<T>(path, init);
    setBackendMode("real");
    return result;
  } catch (err) {
    if (isNetworkError(err)) {
      setBackendMode("fallback-mock");
      startMockTicker();
      return mockFn();
    }
    throw err;
  }
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : "";
}

export function getHealth(): Promise<HealthResponse> {
  return withFallback("/api/health", undefined, mockHealth);
}

export function getInterfaces(): Promise<InterfacesResponse> {
  return withFallback("/api/interfaces", undefined, mockInterfaces);
}

export function getStatsSummary(window: StatsWindow = "5m"): Promise<StatsSummary> {
  return withFallback(`/api/stats/summary${qs({ window })}`, undefined, () => mockStatsSummary(window));
}

export function getStatsTimeseries(window: StatsWindow = "1h", bucket = 60): Promise<TimeseriesResponse> {
  return withFallback(`/api/stats/timeseries${qs({ window, bucket })}`, undefined, () => mockTimeseries(window, bucket));
}

export function getStatsTop(by: TopBy = "host", limit = 10, window: StatsWindow = "5m"): Promise<TopResponse> {
  return withFallback(`/api/stats/top${qs({ by, limit, window })}`, undefined, () => mockTop(by, limit, window));
}

export function getConnections(): Promise<ConnectionsResponse> {
  return withFallback("/api/connections", undefined, mockConnections);
}

export function getDevices(): Promise<DevicesResponse> {
  return withFallback("/api/devices", undefined, mockDevices);
}

function logQueryToParams(q: TrafficLogQuery): Record<string, string | number | undefined> {
  return {
    limit: q.limit,
    offset: q.offset,
    protocol: q.protocol,
    q: q.q,
    since: q.since,
    until: q.until,
    direction: q.direction,
    min_bytes: q.min_bytes,
    sort: q.sort,
    order: q.order,
  };
}

export function getTrafficLog(query: TrafficLogQuery = {}): Promise<TrafficLogResponse> {
  return withFallback(`/api/traffic/log${qs(logQueryToParams(query))}`, undefined, () => mockTrafficLog(query));
}

function toCsv(entries: TrafficLogEntry[]): string {
  const cols: (keyof TrafficLogEntry)[] = [
    "id", "ts", "protocol", "src_addr", "src_port", "dst_addr", "dst_port", "direction",
    "length", "flags", "process_name", "pid", "remote_host", "is_external", "is_encrypted", "summary", "risk",
  ];
  const header = cols.join(",");
  const escape = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = entries.map((e) => cols.map((c) => escape(e[c])).join(","));
  return [header, ...rows].join("\n");
}

/** Triggers a file download for the current log filters, format csv|json. */
export async function exportTrafficLog(query: TrafficLogQuery, format: "csv" | "json" = "csv"): Promise<void> {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `netaudit-log-${ts}.${format}`;
  if (!FORCE_MOCKS) {
    try {
      // Real backend streams the file directly; a same-origin navigation lets
      // the browser handle the Content-Disposition download.
      const probe = await fetch(`/api/traffic/export${qs({ ...logQueryToParams(query), format })}`, { method: "HEAD" }).catch(() => null);
      if (probe && probe.ok) {
        const a = document.createElement("a");
        a.href = `/api/traffic/export${qs({ ...logQueryToParams(query), format })}`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        return;
      }
    } catch {
      // fall through to mock export below
    }
  }
  const rows = await mockExportRows(query);
  const content = format === "json" ? JSON.stringify(rows, null, 2) : toCsv(rows);
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function getRecommendations(includeDismissed = false): Promise<RecommendationsResponse> {
  return withFallback(`/api/recommendations${qs({ include_dismissed: includeDismissed || undefined })}`, undefined, () =>
    mockRecommendations(includeDismissed),
  );
}

export function dismissRecommendation(id: string): Promise<DismissResponse> {
  return withFallback(`/api/recommendations/${encodeURIComponent(id)}/dismiss`, { method: "POST" }, () => mockDismiss(id, true));
}

export function restoreRecommendation(id: string): Promise<DismissResponse> {
  return withFallback(`/api/recommendations/${encodeURIComponent(id)}/restore`, { method: "POST" }, () => mockDismiss(id, false));
}

export function getCaptureStatus(): Promise<CaptureStatus> {
  return withFallback("/api/capture/status", undefined, mockCaptureStatus);
}

export function startCapture(interfaceId: string): Promise<CaptureStatus> {
  return withFallback(
    "/api/capture/start",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interface_id: interfaceId }) },
    () => mockCaptureStart(interfaceId),
  );
}

export function stopCapture(): Promise<CaptureStatus> {
  return withFallback("/api/capture/stop", { method: "POST" }, mockCaptureStop);
}

export function clearCapture(): Promise<{ cleared: boolean }> {
  return withFallback("/api/capture/clear", { method: "POST" }, mockCaptureClear);
}

// --- v2 security extensions (docs/API_CONTRACT_V2_SECURITY.md) -----------

export function getPosture(query: PostureQuery = {}): Promise<PostureResponse> {
  return withFallback(
    `/api/posture${qs({ category: query.category, include_pass: query.include_pass })}`,
    undefined,
    () => mockPosture(query),
  );
}

export function getPostureCheck(id: string): Promise<PostureCheck | null> {
  return withFallback(`/api/posture/checks/${encodeURIComponent(id)}`, undefined, () => mockPostureCheck(id));
}

export function rescanPosture(categories?: string[]): Promise<PostureResponse> {
  return withFallback(
    "/api/posture/rescan",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(categories ? { categories } : {}) },
    () => mockPostureRescan(categories),
  );
}

export function getSecurityScore(): Promise<SecurityScoreResponse> {
  return withFallback("/api/security/score", undefined, mockSecurityScore);
}

function threatsQueryToParams(q: ThreatsQuery): Record<string, string | number | boolean | undefined> {
  return {
    limit: q.limit,
    offset: q.offset,
    severity: q.severity,
    category: q.category,
    status: q.status,
    since: q.since,
    until: q.until,
    q: q.q,
    include_acknowledged: q.include_acknowledged,
  };
}

export function getThreats(query: ThreatsQuery = {}): Promise<ThreatsResponse> {
  return withFallback(`/api/threats${qs(threatsQueryToParams(query))}`, undefined, () => mockThreats(query));
}

export function getThreat(id: string): Promise<Threat | null> {
  return withFallback(`/api/threats/${encodeURIComponent(id)}`, undefined, () => mockThreat(id));
}

export function acknowledgeThreat(id: string, note?: string): Promise<ThreatAckResponse> {
  return withFallback(
    `/api/threats/${encodeURIComponent(id)}/acknowledge`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(note ? { note } : {}) },
    () => mockThreatAck(id, "acknowledged", note),
  );
}

export function unacknowledgeThreat(id: string, note?: string): Promise<ThreatAckResponse> {
  return withFallback(
    `/api/threats/${encodeURIComponent(id)}/unacknowledge`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(note ? { note } : {}) },
    () => mockThreatAck(id, "active", note),
  );
}

export function getThreatsTimeline(window: StatsWindow = "24h", bucket = 3600): Promise<ThreatTimelineResponse> {
  return withFallback(`/api/threats/timeline${qs({ window, bucket })}`, undefined, () => mockThreatsTimeline(window, bucket));
}

export const isMockForced = FORCE_MOCKS;

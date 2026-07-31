// Mock REST handlers — mirror docs/API_CONTRACT.md response shapes exactly,
// reading/writing the shared in-memory store in ./store.ts.

import {
  state,
  computeStatsSummary,
  setStatsWindow,
  computePostureCategories,
  computePostureCounts,
  computePostureScore,
  computeSecurityScore,
  gradeFor,
} from "./store";
import { buildPostureChecks } from "./postureCatalog";
import { mulberry32, randInt } from "./rng";
import type {
  ConnectionsResponse,
  DevicesResponse,
  DismissResponse,
  HealthResponse,
  InterfacesResponse,
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
} from "../api/types";

const latency = () => randInt(mulberry32(Date.now() % 997), 40, 160);

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), latency()));
}

export function mockHealth(): Promise<HealthResponse> {
  return delay({
    status: "ok",
    version: "1.0.0",
    uptime_seconds: (Date.now() - state.startedAt) / 1000,
    capture: state.capture,
  });
}

export function mockInterfaces(): Promise<InterfacesResponse> {
  return delay({ interfaces: state.interfaces, default_interface_id: state.interfaces[0]?.id ?? "" });
}

export function mockStatsSummary(window: StatsWindow = "5m"): Promise<StatsSummary> {
  setStatsWindow(window);
  return delay(computeStatsSummary());
}

const WINDOW_MS: Record<StatsWindow, number> = {
  "5m": 5 * 60_000,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  all: 7 * 24 * 60 * 60_000,
};

// packets_in/out and the protocol breakdown come from state.logs (the sparse
// per-packet log — fine for a per-bucket count). bytes_in/bytes_out come from
// state.throughputHistory, a continuous 1-sample-per-second series that the
// live ticker extends one step at a time (see mocks/store.ts) — historical
// seeding and live ticking are the SAME generation process, so there is no
// seam between "seeded history" and "live tail" for the chart to show a step
// at. (An earlier version summed packet lengths straight from state.logs for
// bytes too; since that log is deliberately sparse — ~650 rows over 2.5h, to
// keep the Traffic Log table readable — versus dense once the live ticker
// starts, that produced a >30x bucket-density jump exactly at the boundary,
// visible as a near-vertical step in the Overview throughput chart.)
// Buckets are contiguous, end at "now", and zero-fill naturally for periods
// with no samples — including bucket ranges older than either series' seed
// span, which is correct zero-fill behavior per the contract, not a bug.
export function mockTimeseries(window: StatsWindow = "1h", bucket = 60): Promise<TimeseriesResponse> {
  const windowMs = WINDOW_MS[window] ?? WINDOW_MS["1h"];
  const bucketMs = Math.max(1000, bucket * 1000);
  const bucketCount = Math.min(720, Math.max(1, Math.round(windowMs / bucketMs)));
  const now = Date.now();
  const points: TimeseriesResponse["points"] = [];

  // throughputHistory is oldest-first and buckets below are processed oldest
  // to newest too, so a single forward-only pointer is enough to sum each
  // bucket's samples in O(samples + buckets) rather than O(buckets*samples).
  const samples = state.throughputHistory;
  let sampleFloor = 0;

  for (let i = bucketCount - 1; i >= 0; i--) {
    const bucketEnd = now - i * bucketMs;
    const bucketStart = bucketEnd - bucketMs;
    let packets_in = 0;
    let packets_out = 0;
    let tcp = 0;
    let udp = 0;
    let icmp = 0;
    let other = 0;
    // state.logs is newest-first; a full scan per bucket is O(buckets*logs)
    // which stays well under a millisecond at this data size (<=4000 logs,
    // <=720 buckets) — simplicity over a two-pointer merge here.
    for (const e of state.logs) {
      const t = new Date(e.ts).getTime();
      if (t >= bucketEnd) continue;
      if (t < bucketStart) break; // everything after is older still
      if (e.direction === "inbound") packets_in += 1;
      else packets_out += 1;
      if (e.protocol === "tcp") tcp += 1;
      else if (e.protocol === "udp") udp += 1;
      else if (e.protocol === "icmp") icmp += 1;
      else other += 1;
    }

    while (sampleFloor < samples.length && samples[sampleFloor].t < bucketStart) sampleFloor++;
    let bytes_in = 0;
    let bytes_out = 0;
    for (let s = sampleFloor; s < samples.length && samples[s].t < bucketEnd; s++) {
      bytes_in += samples[s].bytesIn;
      bytes_out += samples[s].bytesOut;
    }

    points.push({
      t: new Date(bucketStart).toISOString(),
      bytes_in,
      bytes_out,
      packets_in,
      packets_out,
      tcp,
      udp,
      icmp,
      other,
    });
  }
  return delay({ window, bucket_seconds: bucket, points });
}

export function mockTop(by: TopBy = "host", limit = 10, _window: StatsWindow = "5m"): Promise<TopResponse> {
  const recentLogs = state.logs.slice(0, 500);
  const groups = new Map<string, { label: string; sublabel: string; bytes_in: number; bytes_out: number; packets: number; flows: Set<string>; is_external: boolean; risk: "low" | "medium" | "high" }>();

  for (const e of recentLogs) {
    let key: string;
    let label: string;
    let sublabel = "";
    if (by === "host") {
      key = e.remote_host || "unknown";
      label = e.remote_host || "unknown";
    } else if (by === "process") {
      key = `${e.pid}:${e.process_name}`;
      label = e.process_name;
      sublabel = `pid ${e.pid}`;
    } else if (by === "port") {
      const port = e.direction === "outbound" ? e.dst_port : e.src_port;
      key = `${port}/${e.protocol}`;
      label = serviceName(port);
      sublabel = `${port}/${e.protocol}`;
    } else if (by === "protocol") {
      key = e.protocol;
      label = e.protocol.toUpperCase();
    } else {
      key = e.is_external ? "External" : "Internal";
      label = key;
    }
    const g = groups.get(key) ?? { label, sublabel, bytes_in: 0, bytes_out: 0, packets: 0, flows: new Set<string>(), is_external: e.is_external, risk: e.risk };
    if (e.direction === "inbound") g.bytes_in += e.length;
    else g.bytes_out += e.length;
    g.packets += 1;
    g.flows.add(`${e.src_addr}:${e.src_port}-${e.dst_addr}:${e.dst_port}`);
    if (riskRank(e.risk) > riskRank(g.risk)) g.risk = e.risk;
    groups.set(key, g);
  }

  const totalBytes = Array.from(groups.values()).reduce((s, g) => s + g.bytes_in + g.bytes_out, 0) || 1;
  const items = Array.from(groups.entries())
    .map(([key, g]) => ({
      key,
      label: g.label,
      sublabel: g.sublabel,
      bytes_in: g.bytes_in,
      bytes_out: g.bytes_out,
      bytes_total: g.bytes_in + g.bytes_out,
      packets: g.packets,
      flows: g.flows.size,
      share: (g.bytes_in + g.bytes_out) / totalBytes,
      is_external: g.is_external,
      risk: g.risk,
    }))
    .sort((a, b) => b.bytes_total - a.bytes_total)
    .slice(0, limit);

  return delay({ by, window: _window, items });
}

function riskRank(r: "low" | "medium" | "high"): number {
  return r === "high" ? 2 : r === "medium" ? 1 : 0;
}

function serviceName(port: number): string {
  const names: Record<number, string> = { 443: "https", 80: "http", 53: "dns", 22: "ssh", 21: "ftp", 8443: "https-alt", 993: "imaps", 995: "pop3s", 3333: "unknown" };
  return names[port] ?? `port ${port}`;
}

export function mockConnections(): Promise<ConnectionsResponse> {
  return delay({ generated_at: new Date().toISOString(), connections: state.connections });
}

export function mockDevices(): Promise<DevicesResponse> {
  return delay({ devices: state.devices });
}

export function mockTrafficLog(query: TrafficLogQuery = {}): Promise<TrafficLogResponse> {
  let entries = state.logs;
  if (query.protocol) entries = entries.filter((e) => e.protocol === query.protocol);
  if (query.direction) entries = entries.filter((e) => e.direction === query.direction);
  if (typeof query.min_bytes === "number") entries = entries.filter((e) => e.length >= query.min_bytes!);
  if (query.since) entries = entries.filter((e) => e.ts >= query.since!);
  if (query.until) entries = entries.filter((e) => e.ts <= query.until!);
  if (query.q) {
    const q = query.q.toLowerCase();
    entries = entries.filter(
      (e) =>
        e.remote_host.toLowerCase().includes(q) ||
        e.process_name.toLowerCase().includes(q) ||
        String(e.dst_port).includes(q) ||
        String(e.src_port).includes(q) ||
        e.src_addr.includes(q) ||
        e.dst_addr.includes(q),
    );
  }
  const sortKey = query.sort ?? "time";
  const order = query.order ?? "desc";
  entries = [...entries].sort((a, b) => {
    const av = sortKey === "bytes" ? a.length : a.ts;
    const bv = sortKey === "bytes" ? b.length : b.ts;
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return order === "asc" ? cmp : -cmp;
  });

  const total = entries.length;
  const limit = Math.min(1000, query.limit ?? 100);
  const offset = query.offset ?? 0;
  const page = entries.slice(offset, offset + limit);
  return delay({ total, limit, offset, entries: page });
}

export function mockExportRows(query: TrafficLogQuery = {}): Promise<TrafficLogEntry[]> {
  return mockTrafficLog({ ...query, limit: 1000, offset: 0 }).then((r) => r.entries);
}

export function mockRecommendations(includeDismissed: boolean): Promise<RecommendationsResponse> {
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const recs = state.recommendations
    .filter((r) => includeDismissed || !r.dismissed)
    .slice()
    .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || b.confidence - a.confidence);
  return delay({ generated_at: new Date().toISOString(), recommendations: recs });
}

export function mockDismiss(id: string, dismissed: boolean): Promise<DismissResponse> {
  const rec = state.recommendations.find((r) => r.id === id);
  if (rec) rec.dismissed = dismissed;
  return delay({ id, dismissed });
}

export function mockCaptureStatus() {
  return delay(state.capture);
}
export function mockCaptureStart(interfaceId: string) {
  state.capture = { ...state.capture, interface: interfaceId, running: true };
  return delay(state.capture);
}
export function mockCaptureStop() {
  state.capture = { ...state.capture, running: false };
  return delay(state.capture);
}
export function mockCaptureClear() {
  state.logs = [];
  return delay({ cleared: true });
}

// --- Part A: security posture -------------------------------------------

export function mockPosture(query: PostureQuery = {}): Promise<PostureResponse> {
  let checks = state.postureChecks;
  if (query.category) checks = checks.filter((c) => c.category === query.category);
  if (query.include_pass === false) checks = checks.filter((c) => c.status !== "pass");
  // categories/counts/score reflect the FULL catalogue regardless of the
  // category/include_pass filters, which only narrow the returned `checks`.
  return delay({
    generated_at: state.postureGeneratedAt,
    scan_duration_ms: state.postureScanDurationMs,
    score: computePostureScore(state.postureChecks),
    grade: gradeFor(computePostureScore(state.postureChecks)),
    counts: computePostureCounts(state.postureChecks),
    categories: computePostureCategories(state.postureChecks),
    checks,
  });
}

export function mockPostureCheck(id: string) {
  const check = state.postureChecks.find((c) => c.id === id);
  return delay(check ?? null);
}

export function mockPostureRescan(_categories?: string[]): Promise<PostureResponse> {
  // Mock rescan: refresh timestamps only, keep the same catalogue content so
  // results stay stable and don't flicker between clicks — a real scan would
  // re-run the actual checks.
  const now = new Date().toISOString();
  state.postureChecks = buildPostureChecks(now);
  state.postureGeneratedAt = now;
  state.postureScanDurationMs = randInt(mulberry32(Date.now() % 5003), 1400, 3200);
  return mockPosture({});
}

export function mockSecurityScore(): Promise<SecurityScoreResponse> {
  return delay(computeSecurityScore());
}

// --- Part B: threat detection --------------------------------------------

function sortThreats(list: Threat[]): Threat[] {
  const order = ["critical", "high", "medium", "low", "info"];
  return [...list].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || b.confidence - a.confidence);
}

export function mockThreats(query: ThreatsQuery = {}): Promise<ThreatsResponse> {
  let threats = state.threats;
  const includeAck = query.include_acknowledged ?? false;
  if (!includeAck) threats = threats.filter((t) => t.status !== "acknowledged");
  if (query.severity) threats = threats.filter((t) => t.severity === query.severity);
  if (query.category) threats = threats.filter((t) => t.category === query.category);
  if (query.status) threats = threats.filter((t) => t.status === query.status);
  if (query.since) threats = threats.filter((t) => t.last_seen >= query.since!);
  if (query.until) threats = threats.filter((t) => t.last_seen <= query.until!);
  if (query.q) {
    const q = query.q.toLowerCase();
    threats = threats.filter((t) => t.title.toLowerCase().includes(q) || t.summary.toLowerCase().includes(q));
  }
  threats = sortThreats(threats);
  const total = threats.length;
  const limit = Math.min(1000, query.limit ?? 100);
  const offset = query.offset ?? 0;
  return delay({ total, limit, offset, threats: threats.slice(offset, offset + limit) });
}

export function mockThreat(id: string) {
  return delay(state.threats.find((t) => t.id === id) ?? null);
}

export function mockThreatAck(id: string, status: "acknowledged" | "active", note?: string): Promise<ThreatAckResponse> {
  const threat = state.threats.find((t) => t.id === id);
  if (threat) {
    threat.status = status;
    threat.acknowledged_note = status === "acknowledged" ? note : undefined;
  }
  return delay({ id, status, note });
}

const THREAT_WINDOW_MS: Record<StatsWindow, number> = {
  "5m": 5 * 60_000,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  all: 7 * 24 * 60 * 60_000,
};

export function mockThreatsTimeline(window: StatsWindow = "24h", bucket = 3600): Promise<ThreatTimelineResponse> {
  const windowMs = THREAT_WINDOW_MS[window] ?? THREAT_WINDOW_MS["24h"];
  const bucketMs = Math.max(1000, bucket * 1000);
  const bucketCount = Math.min(720, Math.max(1, Math.round(windowMs / bucketMs)));
  const now = Date.now();
  const points: ThreatTimelineResponse["points"] = [];
  for (let i = bucketCount - 1; i >= 0; i--) {
    const bucketEnd = now - i * bucketMs;
    const bucketStart = bucketEnd - bucketMs;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const t of state.threats) {
      const seen = new Date(t.first_seen).getTime();
      if (seen >= bucketStart && seen < bucketEnd) counts[t.severity] += 1;
    }
    points.push({ t: new Date(bucketStart).toISOString(), ...counts });
  }
  return delay({ window, bucket_seconds: bucket, points });
}

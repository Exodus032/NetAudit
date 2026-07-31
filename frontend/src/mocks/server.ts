// Mock REST handlers — mirror docs/API_CONTRACT.md response shapes exactly,
// reading/writing the shared in-memory store in ./store.ts.

import { state, computeStatsSummary, setStatsWindow, randFloat } from "./store";
import { mulberry32, randInt } from "./rng";
import type {
  ConnectionsResponse,
  DevicesResponse,
  DismissResponse,
  HealthResponse,
  InterfacesResponse,
  RecommendationsResponse,
  StatsSummary,
  StatsWindow,
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

// Anchored to bits/sec at roughly the same order of magnitude as the mock
// ticker's actual generation rate (~1-8 log entries/sec at ~64-1500 bytes each,
// averaging ~28 Kbps combined) rather than an arbitrary MB-scale figure, so
// buckets of any width scale consistently AND match the live tail (useTimeseries
// appends points derived from the real throughput_bps_in/out the stats summary
// reports, which is itself now a short trailing-slice rate — see
// computeStatsSummary's THROUGHPUT_SLICE_MS in mocks/store.ts). Without this
// alignment, a fabricated high-bandwidth historical curve and a modest
// live-computed tail created a visible cliff where the two joined.
export function mockTimeseries(window: StatsWindow = "1h", bucket = 60): Promise<TimeseriesResponse> {
  const windowMs = WINDOW_MS[window] ?? WINDOW_MS["1h"];
  const bucketMs = Math.max(1000, bucket * 1000);
  const bucketCount = Math.min(720, Math.max(1, Math.round(windowMs / bucketMs)));
  const now = Date.now();
  const rand = mulberry32(bucketCount * 7919 + bucket);
  const points: TimeseriesResponse["points"] = [];
  let phase = rand() * Math.PI * 2;
  for (let i = bucketCount - 1; i >= 0; i--) {
    const t = new Date(now - i * bucketMs - (now % bucketMs));
    phase += 0.35;
    const baseBps = 24_000 + Math.sin(phase) * 10_000; // ~14-34 Kbps
    const noiseBps = randFloat(rand, -6_000, 9_000);
    const bytesPerSecond = Math.max(0, baseBps + noiseBps) / 8;
    const bytes_in = Math.round(bytesPerSecond * bucket);
    const bytes_out = Math.max(0, Math.round(bytes_in * randFloat(rand, 0.12, 0.35)));
    const tcp = Math.round((bytes_in + bytes_out) / 900);
    const udp = Math.round(tcp * randFloat(rand, 0.1, 0.25));
    points.push({
      t: t.toISOString(),
      bytes_in,
      bytes_out,
      packets_in: Math.round(bytes_in / 700),
      packets_out: Math.round(bytes_out / 700),
      tcp,
      udp,
      icmp: randInt(rand, 0, 4),
      other: randInt(rand, 0, 8),
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

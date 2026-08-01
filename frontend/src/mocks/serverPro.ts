// Mock handlers for Part E (professional workflows) and Part F (compliance/
// alerting) of docs/API_CONTRACT_V3.md — mirrors mocks/server.ts's style
// (delay() wrapper, reading the shared ../mocks/store state where that gives
// more realistic/consistent data, otherwise a small local in-memory store
// scoped to this file).

import { state, computeSecurityScore } from "./store";
import { buildPostureChecks } from "./postureCatalog";
import { mulberry32, randInt } from "./rng";
import type { PostureCheck } from "../api/types";
import type {
  AlertChannel,
  AlertChannelKind,
  AlertHistoryItem,
  AlertHistoryResponse,
  AlertsConfig,
  AlertTestResult,
  BaselineDiff,
  BaselineListItem,
  BaselinesResponse,
  CaptureFilterState,
  CaptureSession,
  ChecksDiff,
  ComplianceControl,
  ComplianceFrameworkSummary,
  ComplianceReport,
  ControlStatus,
  DeleteReportResponse,
  DeleteSessionResponse,
  EvidenceCheck,
  FrameworksResponse,
  HostResult,
  ListenerRef,
  PcapExportQuery,
  PcapImportResponse,
  ReportContent,
  ReportListItem,
  ReportRequest,
  ReportsListResponse,
  ScanJob,
  ScanRequest,
  SessionsResponse,
  SiemEventKind,
  SiemExportQuery,
  SiemExportResult,
  SiemFormat,
} from "../api/typesPro";

const rand = mulberry32(20260801);

const latency = () => randInt(mulberry32(Date.now() % 991), 60, 220);
function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), latency()));
}
function fail(message: string): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(message)), latency()));
}

function isoNow(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

// =======================================================================
// Local mock-only state (imported sessions, reports, scan job, baselines,
// alert config/history, capture filter) — separate from ../mocks/store.ts,
// which this package must not edit.
// =======================================================================

interface ImportedSession extends CaptureSession {
  bytes: number;
  parse_errors: number;
  truncated: boolean;
  linktype: string;
}

interface StoredReport {
  meta: ReportListItem;
  content: string;
}

interface StoredBaseline extends BaselineListItem {
  checkStatuses: Record<string, string>;
  peers: string[];
  listeners: ListenerRef[];
}

const proState = {
  captureFilter: {
    expression: "",
    valid: true,
    error: null,
    applies_to_tier: ["npcap", "rawsocket", "polling"],
    active: false,
    compiled_summary: null,
  } as CaptureFilterState,
  importedSessions: [] as ImportedSession[],
  reports: [] as StoredReport[],
  reportSeq: 1,
  scanJob: null as ScanJob | null,
  scanTimer: null as ReturnType<typeof setInterval> | null,
  baselines: [] as StoredBaseline[],
  baselineSeq: 1,
  alertsConfig: {
    enabled: false,
    min_severity: "high",
    channels: [
      { id: "desktop", kind: "desktop", enabled: true, url: null, template: null, last_status: null, last_attempt: null },
    ],
    rate_limit_per_hour: 20,
    quiet_hours: { start: "23:00", end: "07:00" },
  } as AlertsConfig,
  alertsHistory: [] as AlertHistoryItem[],
};

// =======================================================================
// E1: PCAP export (client streams the actual file itself for mocks; this
// only backs the "N packets will be exported" live estimate)
// =======================================================================

export function mockPcapExportEstimate(query: PcapExportQuery): Promise<number> {
  let logs = state.logs;
  if (query.protocol) logs = logs.filter((l) => l.protocol === query.protocol);
  if (query.since) logs = logs.filter((l) => l.ts >= query.since!);
  if (query.until) logs = logs.filter((l) => l.ts <= query.until!);
  if (query.peer) {
    const needle = query.peer.toLowerCase();
    logs = logs.filter((l) => l.remote_host.toLowerCase().includes(needle) || l.src_addr.includes(needle) || l.dst_addr.includes(needle));
  }
  if (query.port) logs = logs.filter((l) => l.src_port === query.port || l.dst_port === query.port);
  const limit = query.limit ?? 100000;
  return delay(Math.min(logs.length, limit));
}

/** Builds a minimal-but-real libpcap byte stream in the browser for mock
 * mode, mirroring the backend's global-header + zero-payload-record shape
 * (E1) closely enough to open and inspect, never claiming to have real
 * frame bytes. */
export function mockBuildPcapBlob(query: PcapExportQuery): Promise<Blob> {
  let logs = state.logs;
  if (query.protocol) logs = logs.filter((l) => l.protocol === query.protocol);
  if (query.since) logs = logs.filter((l) => l.ts >= query.since!);
  if (query.until) logs = logs.filter((l) => l.ts <= query.until!);
  if (query.port) logs = logs.filter((l) => l.src_port === query.port || l.dst_port === query.port);
  const limit = Math.min(query.limit ?? 100000, 1_000_000);
  const rows = logs.slice(0, limit);

  const GLOBAL_HEADER_LEN = 24;
  const RECORD_HEADER_LEN = 16;
  const ETH_IP_L4_LEN = 54; // 14 (eth) + 20 (ipv4) + 20 (tcp, worst-case-ish)
  const buf = new ArrayBuffer(GLOBAL_HEADER_LEN + rows.length * (RECORD_HEADER_LEN + ETH_IP_L4_LEN));
  const view = new DataView(buf);
  let off = 0;
  view.setUint32(off, 0xa1b2c3d4, true); off += 4; // magic
  view.setUint16(off, 2, true); off += 2; // version major
  view.setUint16(off, 4, true); off += 2; // version minor
  view.setInt32(off, 0, true); off += 4; // thiszone
  view.setUint32(off, 0, true); off += 4; // sigfigs
  view.setUint32(off, 65535, true); off += 4; // snaplen
  view.setUint32(off, 1, true); off += 4; // linktype EN10MB

  for (const row of rows) {
    const tsSec = Math.floor(new Date(row.ts).getTime() / 1000);
    view.setUint32(off, tsSec >>> 0, true); off += 4;
    view.setUint32(off, 0, true); off += 4; // usec — not tracked at mock granularity
    view.setUint32(off, ETH_IP_L4_LEN, true); off += 4; // incl_len
    view.setUint32(off, Math.max(row.length, ETH_IP_L4_LEN), true); off += 4; // orig_len
    off += ETH_IP_L4_LEN; // zero-filled synthetic frame body (never fabricated payload)
  }
  return delay(new Blob([buf], { type: "application/vnd.tcpdump.pcap" }));
}

// =======================================================================
// E2: PCAP import
// =======================================================================

let importedSessionSeq = 1;

export function mockImportPcap(file: File, onProgress?: (pct: number) => void): Promise<PcapImportResponse> {
  const MAX = 200 * 1024 * 1024;
  if (file.size > MAX) {
    return fail(`upload exceeds the ${MAX} byte cap`);
  }
  return new Promise((resolve, reject) => {
    let pct = 0;
    const tick = () => {
      pct = Math.min(100, pct + randInt(rand, 15, 35));
      onProgress?.(pct);
      if (pct < 100) {
        setTimeout(tick, 120);
        return;
      }
      // A file with "corrupt" or "bad" in its name simulates a malformed
      // upload — untrusted input handling (E2) should surface this clearly,
      // never silently.
      if (/corrupt|invalid|bad/i.test(file.name)) {
        reject(new Error(`could not parse '${file.name}': not a recognised pcap/pcapng file`));
        return;
      }
      const seq = importedSessionSeq++;
      const packets = randInt(rand, 200, 60000);
      const bytes = packets * randInt(rand, 80, 900);
      const firstOffset = -randInt(rand, 3600, 3600 * 12) * 1000;
      const now = Date.now();
      const session: ImportedSession = {
        id: `imported-${new Date().toISOString().slice(0, 10)}-${seq.toString(16).padStart(4, "0")}`,
        kind: "imported",
        label: file.name,
        packets,
        synthetic: false,
        imported_at: isoNow(),
        bytes,
        parse_errors: /warn/i.test(file.name) ? randInt(rand, 1, 5) : 0,
        truncated: false,
        linktype: "EN10MB",
      };
      proState.importedSessions.unshift(session);
      resolve({
        session_id: session.id,
        filename: session.label,
        packets: session.packets,
        bytes: session.bytes,
        first_packet: new Date(now + firstOffset).toISOString(),
        last_packet: new Date(now + firstOffset + randInt(rand, 60000, 3600000)).toISOString(),
        linktype: session.linktype,
        truncated: session.truncated,
        parse_errors: session.parse_errors,
      });
    };
    tick();
  });
}

// =======================================================================
// E3: sessions
// =======================================================================

const LIVE_SYNTHETIC_REASON =
  "NetAudit's packet store persists only header/metadata fields (protocol, addresses, ports, length, flags), never raw frame bytes, on any capture tier. Exported/displayed frames are always reconstructed from stored fields.";

export function mockListSessions(): Promise<SessionsResponse> {
  const live: CaptureSession = {
    id: "live",
    kind: "live",
    label: "Live capture",
    packets: state.logs.length,
    synthetic: true,
    synthetic_reason: LIVE_SYNTHETIC_REASON,
  };
  return delay({ sessions: [live, ...proState.importedSessions] });
}

export function mockDeleteSession(id: string): Promise<DeleteSessionResponse> {
  if (id === "live") return fail("the live session cannot be deleted");
  const idx = proState.importedSessions.findIndex((s) => s.id === id);
  if (idx === -1) return fail(`no imported session with id '${id}'`);
  proState.importedSessions.splice(idx, 1);
  return delay({ id, deleted: true });
}

// =======================================================================
// E4: capture filter — reuses a JS port of the backend's own BPF-subset
// grammar so mock validation behaves identically to the real parser.
// =======================================================================

interface BpfError {
  message: string;
  position: number;
}

function tokenizeBpf(expr: string): { text: string; pos: number }[] {
  const tokens: { text: string; pos: number }[] = [];
  const re = /\(|\)|\/|[^\s()/]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(expr))) tokens.push({ text: m[0], pos: m.index });
  return tokens;
}

function validateBpf(expr: string): { ok: true; summary: string } | { ok: false; error: BpfError } {
  const trimmed = expr.trim();
  if (!trimmed) return { ok: false, error: { message: "expression is empty", position: 0 } };
  const tokens = tokenizeBpf(expr);
  let i = 0;
  const endPos = tokens.length ? tokens[tokens.length - 1].pos + tokens[tokens.length - 1].text.length : expr.length;
  const peek = () => tokens[i];
  const KQ = new Set(["tcp", "udp", "icmp", "port", "host", "net", "src", "dst", "not"]);

  function primary(): string {
    const tok = peek();
    if (!tok) throw { message: "unexpected end of expression", position: endPos } as BpfError;
    if (tok.text === "(") {
      i++;
      const inner = orExpr();
      const close = peek();
      if (!close || close.text !== ")") throw { message: "expected ')'", position: close ? close.pos : endPos } as BpfError;
      i++;
      return `(${inner})`;
    }
    const lower = tok.text.toLowerCase();
    if (lower === "tcp" || lower === "udp" || lower === "icmp") {
      i++;
      return lower.toUpperCase();
    }
    let qualifier: string | null = null;
    let word = lower;
    let wordTok = tok;
    if (lower === "src" || lower === "dst") {
      i++;
      qualifier = lower;
      wordTok = peek()!;
      if (!wordTok) throw { message: "expected 'port', 'host' or 'net' after qualifier", position: endPos } as BpfError;
      word = wordTok.text.toLowerCase();
    }
    if (word === "port") {
      i++;
      const numTok = peek();
      if (!numTok || !/^\d+$/.test(numTok.text)) throw { message: "expected a port number after 'port'", position: numTok ? numTok.pos : endPos } as BpfError;
      const port = Number(numTok.text);
      if (port < 0 || port > 65535) throw { message: `port ${port} out of range (0-65535)`, position: numTok.pos } as BpfError;
      i++;
      return qualifier ? `${qualifier} port ${port}` : `dst/src port ${port}`;
    }
    if (word === "host") {
      i++;
      const hostTok = peek();
      if (!hostTok) throw { message: "expected an address after 'host'", position: endPos } as BpfError;
      if (!/^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/.test(hostTok.text)) {
        throw { message: `'${hostTok.text}' is not a valid IP address`, position: hostTok.pos } as BpfError;
      }
      i++;
      return `${qualifier ?? "src/dst"} host ${hostTok.text}`;
    }
    if (word === "net") {
      i++;
      const addrTok = peek();
      if (!addrTok) throw { message: "expected an address after 'net'", position: endPos } as BpfError;
      i++;
      const slashTok = peek();
      if (!slashTok || slashTok.text !== "/") throw { message: "expected '/' after net address (e.g. 'net 10.0.0.0/8')", position: slashTok ? slashTok.pos : endPos } as BpfError;
      i++;
      const prefixTok = peek();
      if (!prefixTok || !/^\d+$/.test(prefixTok.text)) throw { message: "expected a prefix length after '/'", position: prefixTok ? prefixTok.pos : endPos } as BpfError;
      i++;
      return `${qualifier ?? "src/dst"} net ${addrTok.text}/${prefixTok.text}`;
    }
    throw { message: `unexpected keyword '${wordTok.text}' (expected tcp/udp/icmp/port/host/net/and/or/not/'(')`, position: wordTok.pos } as BpfError;
  }

  function unary(): string {
    const tok = peek();
    if (tok && tok.text.toLowerCase() === "not") {
      i++;
      return `NOT ${unary()}`;
    }
    return primary();
  }

  function startsPrimary(tok?: { text: string; pos: number }): boolean {
    if (!tok) return false;
    if (tok.text === "(") return true;
    return KQ.has(tok.text.toLowerCase());
  }

  function andExpr(): string {
    let node = unary();
    for (;;) {
      const tok = peek();
      if (tok && tok.text.toLowerCase() === "and") {
        i++;
        node = `(${node} AND ${unary()})`;
      } else if (startsPrimary(tok)) {
        node = `(${node} AND ${unary()})`;
      } else break;
    }
    return node;
  }

  function orExpr(): string {
    let node = andExpr();
    for (;;) {
      const tok = peek();
      if (tok && tok.text.toLowerCase() === "or") {
        i++;
        node = `(${node} OR ${andExpr()})`;
      } else break;
    }
    return node;
  }

  try {
    const summary = orExpr();
    const trailing = peek();
    if (trailing) throw { message: `unexpected trailing token '${trailing.text}'`, position: trailing.pos } as BpfError;
    return { ok: true, summary };
  } catch (e) {
    return { ok: false, error: e as BpfError };
  }
}

export function mockGetCaptureFilter(): Promise<CaptureFilterState> {
  return delay({ ...proState.captureFilter });
}

export function mockPutCaptureFilter(expression: string): Promise<CaptureFilterState> {
  if (!expression.trim()) {
    proState.captureFilter = {
      expression: "",
      valid: true,
      error: null,
      applies_to_tier: ["npcap", "rawsocket", "polling"],
      active: false,
      compiled_summary: null,
    };
    return delay({ ...proState.captureFilter });
  }
  const result = validateBpf(expression);
  if (!result.ok) {
    return new Promise((_, reject) =>
      setTimeout(() => reject(Object.assign(new Error(result.error.message), { position: result.error.position, isBpf: true })), latency()),
    );
  }
  proState.captureFilter = {
    expression,
    valid: true,
    error: null,
    applies_to_tier: ["npcap", "rawsocket", "polling"],
    active: true,
    compiled_summary: result.summary,
  };
  return delay({ ...proState.captureFilter });
}

// =======================================================================
// E5: reports
// =======================================================================

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function buildReportContent(req: ReportRequest): string {
  const score = computeSecurityScore();
  const generatedAt = isoNow();
  const sectionBlocks: Record<string, string> = {
    summary: `Overall security score: ${score.overall}/100 (${score.grade}). Window: ${req.window}.`,
    posture: `${state.postureChecks.filter((c) => c.status === "fail").length} failing posture checks out of ${state.postureChecks.length}.`,
    threats: `${state.threats.filter((t) => t.status === "active").length} active threats.`,
    recommendations: `${state.recommendations.filter((r) => !r.dismissed).length} open recommendations.`,
    traffic: `${state.logs.length} traffic log rows retained in this session.`,
    devices: `${state.devices.length} devices seen on the network.`,
  };

  if (req.format === "json") {
    return JSON.stringify(
      {
        title: req.title,
        window: req.window,
        generated_at: generatedAt,
        sections: Object.fromEntries(req.sections.map((s) => [s, sectionBlocks[s]])),
        security_score: score.overall,
        grade: score.grade,
      },
      null,
      2,
    );
  }

  if (req.format === "markdown") {
    const lines = [`# ${req.title}`, "", `Generated ${generatedAt} · window ${req.window}`, ""];
    for (const s of req.sections) lines.push(`## ${s[0].toUpperCase()}${s.slice(1)}`, "", sectionBlocks[s], "");
    return lines.join("\n");
  }

  // html
  const body = req.sections
    .map((s) => `<section><h2>${escapeHtml(s[0].toUpperCase() + s.slice(1))}</h2><p>${escapeHtml(sectionBlocks[s])}</p></section>`)
    .join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(req.title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:840px;margin:2rem auto;padding:0 1rem;color:#111}
h1{border-bottom:2px solid #222;padding-bottom:.4rem} section{margin-bottom:1.4rem}</style>
</head><body><h1>${escapeHtml(req.title)}</h1><p>Generated ${generatedAt} · window ${req.window} · score ${score.overall}/100 (${score.grade})</p>
${body}</body></html>`;
}

export function mockCreateReport(req: ReportRequest): Promise<ReportContent> {
  const id = `report-${proState.reportSeq++}-${Date.now().toString(36)}`;
  const content = buildReportContent(req);
  const ext = req.format === "html" ? "html" : req.format === "markdown" ? "md" : "json";
  const filename = `netaudit-report-${id}.${ext}`;
  const meta: ReportListItem = {
    id,
    title: req.title,
    format: req.format,
    window: req.window,
    sections: req.sections,
    generated_at: isoNow(),
    filename,
    bytes: new Blob([content]).size,
  };
  proState.reports.unshift({ meta, content });
  // 50-report cap, oldest pruned, mirroring the real backend's store.
  if (proState.reports.length > 50) proState.reports.length = 50;
  return delay({ id, content, format: req.format, filename });
}

export function mockListReports(): Promise<ReportsListResponse> {
  return delay({ reports: proState.reports.map((r) => r.meta) });
}

export function mockGetReport(id: string): Promise<ReportContent> {
  const found = proState.reports.find((r) => r.meta.id === id);
  if (!found) return fail(`no report with id '${id}'`);
  return delay({ id, content: found.content, format: found.meta.format, filename: found.meta.filename });
}

export function mockDeleteReport(id: string): Promise<DeleteReportResponse> {
  const idx = proState.reports.findIndex((r) => r.meta.id === id);
  if (idx === -1) return fail(`no report with id '${id}'`);
  proState.reports.splice(idx, 1);
  return delay({ id, deleted: true });
}

// =======================================================================
// E6: SIEM export
// =======================================================================

function cefEscapeHeader(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}
function cefEscapeExt(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\n/g, " ").replace(/\r/g, "");
}

interface NormalizedEvent {
  ts: string;
  kind: SiemEventKind;
  severity: string;
  title: string;
  source_ip?: string;
  dest_ip?: string;
  protocol?: string;
  process?: string;
  technique?: string;
}

function collectMockEvents(kinds: Set<SiemEventKind>, since?: string, until?: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  if (kinds.has("threat")) {
    for (const t of state.threats) {
      if (since && t.last_seen < since) continue;
      if (until && t.last_seen > until) continue;
      events.push({ ts: t.last_seen, kind: "threat", severity: t.severity, title: t.title, technique: t.mitre[0]?.technique });
    }
  }
  if (kinds.has("recommendation")) {
    for (const r of state.recommendations) {
      if (r.dismissed) continue;
      if (since && r.last_seen < since) continue;
      if (until && r.last_seen > until) continue;
      events.push({ ts: r.last_seen, kind: "recommendation", severity: r.severity, title: r.title });
    }
  }
  if (kinds.has("posture")) {
    for (const c of state.postureChecks) {
      if (c.status !== "fail" && c.status !== "warn") continue;
      events.push({ ts: c.checked_at, kind: "posture", severity: c.severity, title: c.title });
    }
  }
  if (kinds.has("traffic")) {
    for (const l of state.logs.slice(0, 300)) {
      if (since && l.ts < since) continue;
      if (until && l.ts > until) continue;
      events.push({
        ts: l.ts,
        kind: "traffic",
        severity: l.risk === "high" ? "high" : l.risk === "medium" ? "medium" : "info",
        title: l.summary,
        source_ip: l.src_addr,
        dest_ip: l.dst_addr,
        protocol: l.protocol,
        process: l.process_name,
      });
    }
  }
  events.sort((a, b) => (a.ts < b.ts ? 1 : -1));
  return events;
}

function formatSiem(format: SiemFormat, events: NormalizedEvent[]): string {
  if (format === "jsonl") {
    return events.map((e) => JSON.stringify(e)).join("\n");
  }
  if (format === "ecs") {
    return events
      .map((e) =>
        JSON.stringify({
          "@timestamp": e.ts,
          "event.kind": e.kind,
          "event.category": e.kind,
          "source.ip": e.source_ip,
          "destination.ip": e.dest_ip,
          "network.protocol": e.protocol,
          "process.name": e.process,
          "threat.technique.id": e.technique,
          message: e.title,
        }),
      )
      .join("\n");
  }
  if (format === "cef") {
    return events
      .map((e) => {
        const header = ["CEF:0", "NetAudit", "netaudit", "1.0", e.kind, cefEscapeHeader(e.title), severityToCef(e.severity)].join("|");
        const ext = [
          `rt=${new Date(e.ts).getTime()}`,
          e.source_ip ? `src=${cefEscapeExt(e.source_ip)}` : null,
          e.dest_ip ? `dst=${cefEscapeExt(e.dest_ip)}` : null,
          e.protocol ? `proto=${cefEscapeExt(e.protocol)}` : null,
        ]
          .filter(Boolean)
          .join(" ");
        return `${header}|${ext}`;
      })
      .join("\n");
  }
  // syslog RFC 5424
  return events
    .map((e) => {
      const sd = `[netaudit@0 kind="${e.kind}" severity="${e.severity}"]`;
      return `<134>1 ${e.ts} netaudit netaudit - - ${sd} ${e.title.replace(/\n/g, " ")}`;
    })
    .join("\n");
}

function severityToCef(sev: string): number {
  switch (sev) {
    case "critical": return 10;
    case "high": return 8;
    case "medium": return 5;
    case "low": return 3;
    default: return 1;
  }
}

export function mockSiemExport(query: SiemExportQuery): Promise<SiemExportResult> {
  const kinds = new Set(query.kinds && query.kinds.length ? query.kinds : (["threat", "recommendation", "posture", "traffic"] as SiemEventKind[]));
  const events = collectMockEvents(kinds, query.since, query.until);
  const text = formatSiem(query.format, events);
  const ext: Record<SiemFormat, string> = { jsonl: "jsonl", ecs: "ndjson", cef: "cef", syslog: "log" };
  const contentType: Record<SiemFormat, string> = {
    jsonl: "application/x-ndjson",
    ecs: "application/x-ndjson",
    cef: "text/plain",
    syslog: "text/plain",
  };
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  return delay({ text, contentType: contentType[query.format], filename: `netaudit-events-${ts}.${ext[query.format]}` });
}

// =======================================================================
// E7: LAN scan
// =======================================================================

const CONSENT_NOTICE =
  "This sends real TCP connection attempts to other devices on your local network. Only run it on a network you are authorised to test.";

function isRfc1918(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function parseSubnet(subnet: string): { ip: string; prefix: number } | null {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(subnet.trim());
  if (!m) return null;
  return { ip: m[1], prefix: Number(m[2]) };
}

export function mockStartLanScan(req: ScanRequest): Promise<ScanJob> {
  if (proState.scanJob && proState.scanJob.status === "running") {
    return fail("a scan is already running — cancel it before starting another");
  }
  const parsed = parseSubnet(req.subnet);
  if (!parsed) return fail(`'${req.subnet}' is not a valid CIDR subnet`);
  if (!isRfc1918(parsed.ip)) return fail("the target must be a private (RFC1918) subnet");
  if (parsed.prefix < 24) return fail("the target must be a /24 or smaller (more specific) subnet");
  if (req.ports.length === 0) return fail("at least one port is required");
  if (req.ports.length > 20) return fail("maximum 20 ports per scan");
  if (req.rate_limit_pps > 100) return fail("rate limit is capped at 100 pps");

  const hostCount = Math.min(254, 2 ** (32 - parsed.prefix) - 2 || 1);
  const base = parsed.ip.split(".").slice(0, 3).join(".");
  const job: ScanJob = {
    job_id: `scan-${Date.now().toString(36)}`,
    status: "running",
    subnet: req.subnet,
    ports: req.ports,
    rate_limit_pps: req.rate_limit_pps,
    progress: { scanned: 0, total: hostCount },
    results: [],
    consent_notice: CONSENT_NOTICE,
    started_at: isoNow(),
    completed_at: null,
    error: null,
  };
  proState.scanJob = job;

  let host = 1;
  proState.scanTimer = setInterval(() => {
    if (!proState.scanJob || proState.scanJob.status !== "running") {
      if (proState.scanTimer) clearInterval(proState.scanTimer);
      return;
    }
    if (host > hostCount) {
      proState.scanJob.status = "completed";
      proState.scanJob.completed_at = isoNow();
      if (proState.scanTimer) clearInterval(proState.scanTimer);
      return;
    }
    const ip = `${base}.${host}`;
    if (rand() < 0.35) {
      const openPorts = req.ports.filter(() => rand() < 0.3);
      const result: HostResult = { ip, open_ports: openPorts };
      proState.scanJob.results.push(result);
    }
    proState.scanJob.progress = { scanned: host, total: hostCount };
    host += 1;
  }, Math.max(40, Math.round(1000 / Math.max(1, req.rate_limit_pps / 4))));

  return delay({ ...job });
}

export function mockGetLanScan(jobId: string): Promise<ScanJob> {
  if (!proState.scanJob || proState.scanJob.job_id !== jobId) return fail(`unknown scan job id: '${jobId}'`);
  return delay({ ...proState.scanJob, results: [...proState.scanJob.results] });
}

export function mockCancelLanScan(jobId: string): Promise<ScanJob> {
  if (!proState.scanJob || proState.scanJob.job_id !== jobId) return fail(`unknown scan job id: '${jobId}'`);
  if (proState.scanJob.status === "running") {
    proState.scanJob.status = "cancelled";
    proState.scanJob.completed_at = isoNow();
  }
  if (proState.scanTimer) clearInterval(proState.scanTimer);
  return delay({ ...proState.scanJob });
}

// =======================================================================
// E8: baselines
// =======================================================================

function badnessRank(status: string): number {
  return status === "pass" ? 0 : status === "warn" ? 1 : status === "fail" ? 2 : -1;
}

function snapshotChecks(): Record<string, string> {
  const fresh = buildPostureChecks(isoNow());
  const out: Record<string, string> = {};
  for (const c of fresh) out[c.id] = c.status;
  return out;
}

function snapshotPeers(): string[] {
  const set = new Set<string>();
  for (const c of state.connections) if (c.is_external) set.add(c.remote_addr);
  return Array.from(set).slice(0, 40);
}

function snapshotListeners(): ListenerRef[] {
  const seen = new Map<number, string>();
  for (const c of state.connections) {
    if (c.direction === "local" || c.direction === "inbound") seen.set(c.local_port, c.process_name);
  }
  return Array.from(seen.entries()).map(([port, process]) => ({ port, process }));
}

export function mockCreateBaseline(label: string): Promise<BaselineListItem> {
  const id = `baseline-${proState.baselineSeq++}-${Date.now().toString(36)}`;
  const checkStatuses = snapshotChecks();
  const peers = snapshotPeers();
  const listeners = snapshotListeners();
  const score = computeSecurityScore();
  const postureComponent = score.components.find((c) => c.id === "posture");
  const threatComponent = score.components.find((c) => c.id === "threat");
  const item: StoredBaseline = {
    id,
    label,
    captured_at: isoNow(),
    checks_count: Object.keys(checkStatuses).length,
    peers_count: peers.length,
    listeners_count: listeners.length,
    posture_score: postureComponent?.score ?? score.overall,
    threats_score: threatComponent?.score ?? null,
    overall_score: score.overall,
    checkStatuses,
    peers,
    listeners,
  };
  proState.baselines.unshift(item);
  const { checkStatuses: _cs, peers: _p, listeners: _l, ...listItem } = item;
  void _cs; void _p; void _l;
  return delay(listItem);
}

export function mockListBaselines(): Promise<BaselinesResponse> {
  return delay({
    baselines: proState.baselines.map(({ checkStatuses, peers, listeners, ...rest }) => {
      void checkStatuses; void peers; void listeners;
      return rest;
    }),
  });
}

export function mockDiffBaselines(a: string, b: string): Promise<BaselineDiff> {
  const from = proState.baselines.find((x) => x.id === a);
  const to = proState.baselines.find((x) => x.id === b);
  if (!from || !to) return fail("one or both baseline ids not found");

  const checks: ChecksDiff = { fixed: [], regressed: [], unchanged_count: 0, added: [], removed: [], inconclusive: [] };
  const allIds = new Set([...Object.keys(from.checkStatuses), ...Object.keys(to.checkStatuses)]);
  for (const id of allIds) {
    const fromStatus = from.checkStatuses[id];
    const toStatus = to.checkStatuses[id];
    if (fromStatus === undefined) { checks.added.push({ id, status: toStatus }); continue; }
    if (toStatus === undefined) { checks.removed.push({ id, status: fromStatus }); continue; }
    if (fromStatus === toStatus) { checks.unchanged_count += 1; continue; }
    const fr = badnessRank(fromStatus);
    const tr = badnessRank(toStatus);
    if (fr === -1 || tr === -1) { checks.inconclusive.push({ id, from: fromStatus, to: toStatus }); continue; }
    if (tr < fr) checks.fixed.push({ id, from: fromStatus, to: toStatus });
    else checks.regressed.push({ id, from: fromStatus, to: toStatus });
  }

  const fromPeers = new Set(from.peers);
  const newPeers = to.peers.filter((p) => !fromPeers.has(p));
  const fromListeners = new Map(from.listeners.map((l) => [l.port, l.process]));
  const toListeners = new Map(to.listeners.map((l) => [l.port, l.process]));
  const newListeners = to.listeners.filter((l) => !fromListeners.has(l.port));
  const removedListeners = from.listeners.filter((l) => !toListeners.has(l.port));

  return delay({
    from: { id: from.id, label: from.label, captured_at: from.captured_at },
    to: { id: to.id, label: to.label, captured_at: to.captured_at },
    score_delta: {
      posture: to.posture_score - from.posture_score,
      threats: from.threats_score != null && to.threats_score != null ? to.threats_score - from.threats_score : 0,
      overall: to.overall_score - from.overall_score,
    },
    checks,
    new_peers: newPeers,
    new_listeners: newListeners,
    removed_listeners: removedListeners,
  });
}

// =======================================================================
// F1-F2: compliance — real control->check_id mappings, condensed from
// backend/netaudit/compliance/data/*.json, combined against the same mock
// posture catalogue the Posture view renders (see postureCatalog.ts).
// =======================================================================

interface FrameworkData {
  id: string;
  label: string;
  coverage_note: string;
  controls: { control_id: string; title: string; check_ids: string[] }[];
}

const FRAMEWORKS: FrameworkData[] = [
  {
    id: "cis_win11",
    label: "CIS Microsoft Windows 11 Benchmark v3.0.0",
    coverage_note:
      "Covers only the network-facing subset of the benchmark: 11 controls cross-checked as stable across published revisions (SMB signing, UAC admin approval mode, firewall state/inbound-block/logging across all three profiles, LLMNR, IPv6). The other 36 posture checks are deliberately left unmapped rather than assigned a guessed sub-section id. Indicative technical mapping, not a CIS-certified crosswalk.",
    controls: [
      { control_id: "2.3.9.2", title: "Microsoft network server: Digitally sign communications (always)", check_ids: ["smb_signing_required"] },
      { control_id: "2.3.17.6", title: "User Account Control: Run all administrators in Admin Approval Mode", check_ids: ["uac_enabled"] },
      { control_id: "9.1.1", title: "Windows Firewall: Domain: Firewall state", check_ids: ["firewall_profiles_enabled"] },
      { control_id: "9.2.1", title: "Windows Firewall: Private: Firewall state", check_ids: ["firewall_profiles_enabled"] },
      { control_id: "9.3.1", title: "Windows Firewall: Public: Firewall state", check_ids: ["firewall_profiles_enabled"] },
      { control_id: "9.1.2", title: "Windows Firewall: Domain: Inbound connections (Block)", check_ids: ["firewall_inbound_default_block"] },
      { control_id: "9.2.2", title: "Windows Firewall: Private: Inbound connections (Block)", check_ids: ["firewall_inbound_default_block"] },
      { control_id: "9.3.2", title: "Windows Firewall: Public: Inbound connections (Block)", check_ids: ["firewall_inbound_default_block"] },
      { control_id: "9.1.9", title: "Windows Firewall: Domain: Logging: Log dropped packets", check_ids: ["firewall_logging_enabled"] },
      { control_id: "18.6.4.4", title: "Turn off multicast name resolution (LLMNR)", check_ids: ["llmnr_disabled"] },
      { control_id: "18.6.19.2.1", title: "Disable IPv6 (DisabledComponents = 0xff)", check_ids: ["ipv6_state"] },
    ],
  },
  {
    id: "nist_800_53",
    label: "NIST SP 800-53 Rev. 5",
    coverage_note:
      "Indicative mapping only, not a NIST-endorsed crosswalk. All 43 posture checks are grouped under 18 SP 800-53 Rev. 5 controls across the AC, AU, CM, IA, SC and SI families. A single host-level, network-facing check is rarely sufficient on its own to fully satisfy a control that in a real ATO also needs organizational and procedural evidence NetAudit cannot see. Treat 'pass' as 'the narrow technical signal was favorable', not 'the control is fully satisfied'.",
    controls: [
      { control_id: "AC-2", title: "Account Management", check_ids: ["guest_account_disabled"] },
      { control_id: "AC-3", title: "Access Enforcement", check_ids: ["smb_shares_exposed"] },
      { control_id: "AC-6", title: "Least Privilege", check_ids: ["uac_enabled", "local_admin_count"] },
      { control_id: "AC-17", title: "Remote Access", check_ids: ["rdp_disabled_or_nla", "winrm_exposure", "remote_registry_disabled", "psremoting_scope"] },
      { control_id: "AC-18", title: "Wireless Access", check_ids: ["wifi_encryption_strength", "wifi_open_networks_saved", "wifi_autoconnect_open"] },
      { control_id: "AU-12", title: "Audit Record Generation", check_ids: ["firewall_logging_enabled"] },
      {
        control_id: "CM-7", title: "Least Functionality",
        check_ids: ["smb1_disabled", "llmnr_disabled", "netbios_disabled", "mdns_exposure", "wpad_disabled", "ipv6_state", "ip_forwarding_disabled", "promiscuous_adapters", "unused_adapters_enabled", "listening_on_all_interfaces", "high_risk_ports_open", "unexpected_listeners", "upnp_disabled"],
      },
      { control_id: "IA-2", title: "Identification and Authentication (Organizational Users)", check_ids: ["smb_guest_auth_disabled"] },
      { control_id: "IA-5", title: "Authenticator Management", check_ids: ["blank_passwords", "autologon_disabled"] },
      { control_id: "SC-7", title: "Boundary Protection", check_ids: ["firewall_profiles_enabled", "firewall_inbound_default_block", "firewall_allow_rules_broad", "network_profile_public"] },
      { control_id: "SC-8", title: "Transmission Confidentiality and Integrity", check_ids: ["smb_signing_required", "tls10_11_disabled", "ssl3_disabled"] },
      { control_id: "SC-13", title: "Cryptographic Protection", check_ids: ["weak_ciphers_disabled"] },
      { control_id: "SC-17", title: "Public Key Infrastructure Certificates", check_ids: ["certificate_store_anomalies"] },
      { control_id: "SC-20", title: "Secure Name/Address Resolution Service (Authoritative Source)", check_ids: ["dns_over_https"] },
      { control_id: "SC-21", title: "Secure Name/Address Resolution Service (Recursive or Caching Resolver)", check_ids: ["dns_servers_trusted"] },
      { control_id: "SC-28", title: "Protection of Information at Rest", check_ids: ["bitlocker_status"] },
      { control_id: "SI-2", title: "Flaw Remediation", check_ids: ["windows_update_current"] },
      { control_id: "SI-3", title: "Malicious Code Protection", check_ids: ["defender_realtime_enabled", "defender_signatures_current"] },
    ],
  },
  {
    id: "essential_eight",
    label: "ACSC Essential Eight",
    coverage_note:
      "ACSC publishes eight named mitigation strategies, not numbered controls, so control_id is a stable slug rather than an invented identifier. Only 'Patch Operating Systems' and 'Restrict Administrative Privileges' have any host-level, network-facing signal this tool can observe, and only partially. The other six strategies are completely outside what a single host's network-facing configuration audit can see and are always not_assessed here — that is a statement about vantage point, not a finding that they are failing.",
    controls: [
      { control_id: "patch_operating_systems", title: "Patch Operating Systems", check_ids: ["windows_update_current"] },
      { control_id: "patch_applications", title: "Patch Applications", check_ids: [] },
      { control_id: "multi_factor_authentication", title: "Multi-factor Authentication", check_ids: [] },
      { control_id: "restrict_administrative_privileges", title: "Restrict Administrative Privileges", check_ids: ["guest_account_disabled", "local_admin_count", "blank_passwords", "autologon_disabled", "uac_enabled"] },
      { control_id: "application_control", title: "Application Control", check_ids: [] },
      { control_id: "restrict_office_macros", title: "Restrict Microsoft Office Macro Settings", check_ids: [] },
      { control_id: "user_application_hardening", title: "User Application Hardening", check_ids: [] },
      { control_id: "regular_backups", title: "Regular Backups", check_ids: [] },
    ],
  },
];

function combineControlStatus(checkIds: string[], byId: Map<string, PostureCheck>): { status: ControlStatus; evidence: EvidenceCheck[] } {
  const evidence: EvidenceCheck[] = checkIds.map((id) => {
    const check = byId.get(id);
    return { check_id: id, status: check ? check.status : "missing" };
  });
  const assessed = evidence.filter((e) => e.status === "pass" || e.status === "warn" || e.status === "fail");
  if (assessed.length === 0) return { status: "not_assessed", evidence };
  if (assessed.every((e) => e.status === "pass")) return { status: "pass", evidence };
  if (assessed.every((e) => e.status === "fail")) return { status: "fail", evidence };
  return { status: "partial", evidence };
}

export function mockComplianceFrameworks(): Promise<FrameworksResponse> {
  const frameworks: ComplianceFrameworkSummary[] = FRAMEWORKS.map((f) => ({
    id: f.id,
    label: f.label,
    controls_mapped: f.controls.length,
    checks_mapped: new Set(f.controls.flatMap((c) => c.check_ids)).size,
    coverage_note: f.coverage_note,
  }));
  return delay({ frameworks });
}

export function mockComplianceReport(frameworkId: string): Promise<ComplianceReport> {
  const fw = FRAMEWORKS.find((f) => f.id === frameworkId);
  if (!fw) return fail(`unknown compliance framework: '${frameworkId}'`);
  const checks = buildPostureChecks(isoNow());
  const byId = new Map(checks.map((c) => [c.id, c]));

  const controls: ComplianceControl[] = fw.controls.map((c) => {
    const { status, evidence } = combineControlStatus(c.check_ids, byId);
    const rationale =
      evidence.length === 0
        ? "This strategy has no network-facing, host-level signal NetAudit can observe."
        : status === "not_assessed"
          ? "The mapped check(s) returned no usable evidence (missing, errored, or skipped)."
          : status === "pass"
            ? "Every mapped check currently passes."
            : status === "fail"
              ? "Every mapped check currently fails."
              : "Mapped checks disagree, or at least one only partially satisfies this control.";
    return { control_id: c.control_id, title: c.title, status, evidence_checks: evidence, rationale };
  });

  const summary = controls.reduce(
    (acc, c) => {
      acc[c.status] += 1;
      return acc;
    },
    { pass: 0, fail: 0, partial: 0, not_assessed: 0 } as Record<ControlStatus, number>,
  );
  const assessedCount = summary.pass + summary.fail + summary.partial;
  const coveragePercent = controls.length ? Math.round((assessedCount / controls.length) * 100) : 0;

  return delay({
    framework: { id: fw.id, label: fw.label },
    generated_at: isoNow(),
    summary: { ...summary, coverage_percent: coveragePercent },
    disclaimer:
      "Indicative only. NetAudit assesses network-facing configuration on this host and is not a certified compliance audit.",
    controls,
  });
}

// =======================================================================
// F3-F4: alerting
// =======================================================================

export function mockGetAlertsConfig(): Promise<AlertsConfig> {
  return delay({ ...proState.alertsConfig, channels: proState.alertsConfig.channels.map((c) => ({ ...c })) });
}

function isPrivateHostname(url: URL): boolean {
  const h = url.hostname.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") return true;
  if (/^10\.|^192\.168\.|^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

export function mockUpdateAlertsConfig(config: AlertsConfig): Promise<AlertsConfig> {
  for (const ch of config.channels) {
    if (ch.kind !== "webhook" || !ch.enabled) continue;
    if (!ch.url) return fail("an enabled webhook channel must have a URL");
    let parsed: URL;
    try {
      parsed = new URL(ch.url);
    } catch {
      return fail(`'${ch.url}' is not a valid URL`);
    }
    if (parsed.protocol !== "https:") return fail("webhook URLs must use https");
    if (isPrivateHostname(parsed)) return fail("webhook URL resolves to a private/loopback address and was rejected");
  }
  proState.alertsConfig = { ...config, channels: config.channels.map((c) => ({ ...c })) };
  return delay({ ...proState.alertsConfig });
}

export function mockTestAlertChannel(channelId: string): Promise<AlertTestResult> {
  const channel = proState.alertsConfig.channels.find((c) => c.id === channelId);
  if (!channel) return fail(`unknown channel id: '${channelId}'`);
  const now = isoNow();
  let status: AlertTestResult["status"] = "delivered";
  let detail: string | null = null;

  if (channel.kind === "desktop") {
    status = "delivered";
    detail = "Toast notification sent.";
  } else {
    if (!channel.url) {
      status = "failed";
      detail = "no URL configured";
    } else {
      try {
        const parsed = new URL(channel.url);
        if (parsed.protocol !== "https:") {
          status = "failed";
          detail = "rejected: only https URLs are allowed";
        } else if (isPrivateHostname(parsed)) {
          status = "failed";
          detail = "rejected: URL resolves to a private/loopback address";
        } else {
          status = rand() < 0.85 ? "delivered" : "failed";
          detail = status === "delivered" ? "webhook responded 2xx" : "webhook did not respond with 2xx";
        }
      } catch {
        status = "failed";
        detail = "invalid URL";
      }
    }
  }

  channel.last_status = status;
  channel.last_attempt = now;

  proState.alertsHistory.unshift({
    id: `hist-${Date.now().toString(36)}`,
    ts: now,
    severity: "info",
    source: "test",
    source_id: "manual-test",
    title: `Test alert to ${channel.kind}`,
    channels: [{ id: channel.id, status }],
  });

  return delay({ channel_id: channelId, status, detail, attempted_at: now });
}

export function mockAlertsHistory(limit = 200): Promise<AlertHistoryResponse> {
  return delay({ alerts: proState.alertsHistory.slice(0, limit) });
}

export type { AlertChannel, AlertChannelKind };

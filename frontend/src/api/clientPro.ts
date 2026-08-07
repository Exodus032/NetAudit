// Typed fetch wrapper for Part E/F of docs/API_CONTRACT_V3.md. Reuses
// client.ts's withFallback/realFetch/fetchWithToken/qs/ApiError rather than
// growing a second copy of the token/retry/fallback machinery. A few
// endpoints here return raw bytes or text instead of a JSON envelope (pcap
// export, report content, SIEM export) and need direct access to the
// Response — those use a small `rawFetch` helper built on fetchWithToken,
// the same primitive the JSON helpers use underneath withFallback.

import { ApiError, fetchWithToken, isMockForced, qs, withFallback, getTrafficLog } from "./client";
import { ensureToken, invalidateToken } from "./auth";
import {
  mockAlertsHistory,
  mockGetEnrichmentConfig,
  mockUpdateEnrichmentConfig,
  mockTestEnrichmentProvider,
  mockCancelLanScan,
  mockComplianceFrameworks,
  mockComplianceReport,
  mockCreateBaseline,
  mockCreateReport,
  mockDeleteReport,
  mockDeleteSession,
  mockDiffBaselines,
  mockGetBaselineSchedule,
  mockGetAlertsConfig,
  mockGetCaptureFilter,
  mockGetLanScan,
  mockGetReport,
  mockImportPcap,
  mockListBaselines,
  mockListReports,
  mockListSessions,
  mockPcapExportEstimate,
  mockPutCaptureFilter,
  mockSiemExport,
  mockUpdateBaselineSchedule,
  mockStartLanScan,
  mockTestAlertChannel,
  mockUpdateAlertsConfig,
  mockBuildPcapBlob,
} from "../mocks/serverPro";
import type {
  AlertHistoryResponse,
  AlertsConfig,
  AlertTestResult,
  EnrichmentConfig,
  EnrichmentConfigUpdate,
  EnrichmentTestResult,
  BaselineDiff,
  BaselineSchedule,
  BaselineListItem,
  BaselinesResponse,
  CaptureFilterState,
  ComplianceReport,
  DeleteReportResponse,
  DeleteSessionResponse,
  FrameworksResponse,
  PcapExportQuery,
  PcapImportResponse,
  ReportContent,
  ReportRequest,
  ReportsListResponse,
  ScanJob,
  ScanRequest,
  SessionsResponse,
  SiemExportQuery,
  SiemExportResult,
} from "./typesPro";
import { BpfFilterError } from "./typesPro";

/** Same shape as fetchWithToken's 401-retry in realFetch, exposed here
 * because several endpoints below need the raw Response (headers, blob,
 * text) rather than realFetch's parsed-JSON return. */
async function rawFetch(path: string, init?: RequestInit): Promise<Response> {
  let res = await fetchWithToken(path, init);
  if (res.status === 401) {
    invalidateToken();
    res = await fetchWithToken(path, init);
  }
  return res;
}

async function apiErrorFromResponse(res: Response): Promise<ApiError> {
  let body: { error?: { code?: string; message?: string } } | null = null;
  try {
    body = await res.json();
  } catch {
    // ignore — fall through to generic message
  }
  return new ApiError(res.status, body?.error?.code ?? "unknown_error", body?.error?.message ?? res.statusText);
}

function isNetworkError(err: unknown): boolean {
  return err instanceof TypeError;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function filenameFromContentDisposition(cd: string | null, fallback: string): string {
  const match = cd ? /filename="?([^";]+)"?/.exec(cd) : null;
  return match ? match[1] : fallback;
}

// =======================================================================
// E1: PCAP export
// =======================================================================

function pcapExportParams(query: PcapExportQuery) {
  return { since: query.since, until: query.until, protocol: query.protocol, peer: query.peer, port: query.port, limit: query.limit };
}

/** Approximate "N packets will be exported" count for the given filters.
 * There is no dedicated count endpoint in the contract, so this reuses the
 * traffic log's `total` (via the already-shared api/client.ts) as the best
 * available live estimate — it does not weight by the `port` filter on the
 * real backend path since traffic/log has no matching parameter, so treat
 * this as an estimate, not an exact preview. */
export async function estimatePcapExport(query: PcapExportQuery): Promise<number> {
  if (isMockForced) return mockPcapExportEstimate(query);
  const q = [query.peer, query.port != null ? String(query.port) : undefined].filter(Boolean).join(" ");
  const res = await getTrafficLog({
    protocol: query.protocol,
    since: query.since,
    until: query.until,
    q: q || undefined,
    limit: 1,
  });
  return res.total;
}

export async function exportPcap(query: PcapExportQuery): Promise<void> {
  const fallbackName = `netaudit-${new Date().toISOString().replace(/[:.]/g, "-")}.pcap`;
  if (!isMockForced) {
    try {
      const res = await rawFetch(`/api/capture/pcap${qs(pcapExportParams(query))}`);
      if (!res.ok) throw await apiErrorFromResponse(res);
      const blob = await res.blob();
      downloadBlob(blob, filenameFromContentDisposition(res.headers.get("Content-Disposition"), fallbackName));
      return;
    } catch (err) {
      if (!isNetworkError(err)) throw err;
      // network unreachable — fall through to the mock export below
    }
  }
  const blob = await mockBuildPcapBlob(query);
  downloadBlob(blob, fallbackName);
}

// =======================================================================
// E2: PCAP import
// =======================================================================

const MAX_PCAP_UPLOAD_BYTES = 200 * 1024 * 1024;

export function importPcap(file: File, onProgress?: (percent: number) => void): Promise<PcapImportResponse> {
  if (file.size > MAX_PCAP_UPLOAD_BYTES) {
    return Promise.reject(new ApiError(413, "upload_too_large", `upload exceeds the ${MAX_PCAP_UPLOAD_BYTES} byte (200 MB) cap`));
  }
  if (isMockForced) return mockImportPcap(file, onProgress);

  const attempt = (retried: boolean): Promise<PcapImportResponse> =>
    ensureToken().then(
      (token) =>
        new Promise<PcapImportResponse>((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open("POST", "/api/capture/pcap/import");
          if (token) xhr.setRequestHeader("X-NetAudit-Token", token);
          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) onProgress?.(Math.round((e.loaded / e.total) * 100));
          };
          xhr.onload = () => {
            if (xhr.status === 401 && !retried) {
              invalidateToken();
              attempt(true).then(resolve, reject);
              return;
            }
            if (xhr.status >= 200 && xhr.status < 300) {
              try {
                resolve(JSON.parse(xhr.responseText));
              } catch {
                reject(new ApiError(xhr.status, "invalid_response", "could not parse import response"));
              }
              return;
            }
            try {
              const body = JSON.parse(xhr.responseText);
              reject(new ApiError(xhr.status, body?.error?.code ?? "unknown_error", body?.error?.message ?? xhr.statusText));
            } catch {
              reject(new ApiError(xhr.status, "unknown_error", xhr.statusText || "import failed"));
            }
          };
          xhr.onerror = () => reject(new TypeError("network error"));
          const form = new FormData();
          form.append("file", file);
          xhr.send(form);
        }),
    );

  return attempt(false).catch((err) => {
    if (isNetworkError(err)) return mockImportPcap(file, onProgress);
    throw err;
  });
}

// =======================================================================
// E3: sessions
// =======================================================================

export function listSessions(): Promise<SessionsResponse> {
  return withFallback("/api/sessions", undefined, mockListSessions);
}

export function deleteSession(id: string): Promise<DeleteSessionResponse> {
  return withFallback(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }, () => mockDeleteSession(id));
}

// =======================================================================
// E4: capture filter
// =======================================================================

export function getCaptureFilter(): Promise<CaptureFilterState> {
  return withFallback("/api/capture/filter", undefined, mockGetCaptureFilter);
}

export async function updateCaptureFilter(expression: string): Promise<CaptureFilterState> {
  if (isMockForced) return mockPutCaptureFilter(expression).catch(rethrowAsBpf);

  try {
    const res = await rawFetch("/api/capture/filter", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expression }),
    });
    if (res.status === 400) {
      const body: { error?: { message?: string; position?: number } } = await res.json().catch(() => ({}));
      throw new BpfFilterError(body.error?.message ?? "invalid filter expression", body.error?.position ?? 0);
    }
    if (!res.ok) throw await apiErrorFromResponse(res);
    return await res.json();
  } catch (err) {
    if (err instanceof BpfFilterError || err instanceof ApiError) throw err;
    if (!isNetworkError(err)) throw err;
    return mockPutCaptureFilter(expression).catch(rethrowAsBpf);
  }
}

function rethrowAsBpf(err: unknown): never {
  if (err && typeof err === "object" && "isBpf" in err) {
    const e = err as unknown as { message: string; position: number };
    throw new BpfFilterError(e.message, e.position);
  }
  throw err;
}

// =======================================================================
// E5: reports
// =======================================================================

export async function createReport(req: ReportRequest): Promise<ReportContent> {
  if (isMockForced) return mockCreateReport(req);
  try {
    const res = await rawFetch("/api/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw await apiErrorFromResponse(res);
    const content = await res.text();
    const id = res.headers.get("X-NetAudit-Report-Id") ?? "";
    const filename = filenameFromContentDisposition(res.headers.get("Content-Disposition"), `netaudit-report.${req.format}`);
    return { id, content, format: req.format, filename };
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (!isNetworkError(err)) throw err;
    return mockCreateReport(req);
  }
}

export function listReports(): Promise<ReportsListResponse> {
  return withFallback("/api/reports", undefined, mockListReports);
}

export async function getReport(id: string): Promise<ReportContent> {
  if (isMockForced) return mockGetReport(id);
  try {
    const res = await rawFetch(`/api/reports/${encodeURIComponent(id)}`);
    if (!res.ok) throw await apiErrorFromResponse(res);
    const content = await res.text();
    const ct = res.headers.get("Content-Type") ?? "";
    const format = ct.includes("html") ? "html" : ct.includes("markdown") ? "markdown" : "json";
    const filename = filenameFromContentDisposition(res.headers.get("Content-Disposition"), `netaudit-report-${id}`);
    return { id, content, format, filename };
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (!isNetworkError(err)) throw err;
    return mockGetReport(id);
  }
}

export function deleteReport(id: string): Promise<DeleteReportResponse> {
  return withFallback(`/api/reports/${encodeURIComponent(id)}`, { method: "DELETE" }, () => mockDeleteReport(id));
}

// =======================================================================
// E6: SIEM export
// =======================================================================

export async function fetchSiemExport(query: SiemExportQuery): Promise<SiemExportResult> {
  if (isMockForced) return mockSiemExport(query);
  try {
    const res = await rawFetch(
      `/api/export/events${qs({ format: query.format, since: query.since, until: query.until, kinds: query.kinds?.join(",") })}`,
    );
    if (!res.ok) throw await apiErrorFromResponse(res);
    const text = await res.text();
    const contentType = res.headers.get("Content-Type") ?? "text/plain";
    const filename = filenameFromContentDisposition(res.headers.get("Content-Disposition"), `netaudit-events.${query.format}`);
    return { text, contentType, filename };
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (!isNetworkError(err)) throw err;
    return mockSiemExport(query);
  }
}

export function downloadSiemExport(result: SiemExportResult): void {
  const blob = new Blob([result.text], { type: result.contentType });
  downloadBlob(blob, result.filename);
}

// =======================================================================
// E7: LAN scan
// =======================================================================

export function startLanScan(req: ScanRequest): Promise<ScanJob> {
  return withFallback(
    "/api/devices/scan",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) },
    () => mockStartLanScan(req),
  );
}

export function getLanScan(jobId: string): Promise<ScanJob> {
  return withFallback(`/api/devices/scan/${encodeURIComponent(jobId)}`, undefined, () => mockGetLanScan(jobId));
}

export function cancelLanScan(jobId: string): Promise<ScanJob> {
  return withFallback(`/api/devices/scan/${encodeURIComponent(jobId)}`, { method: "DELETE" }, () => mockCancelLanScan(jobId));
}

// =======================================================================
// E8: baselines
// =======================================================================

export function createBaseline(label: string): Promise<BaselineListItem> {
  return withFallback(
    "/api/baselines",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label }) },
    () => mockCreateBaseline(label),
  );
}

export function listBaselines(): Promise<BaselinesResponse> {
  return withFallback("/api/baselines", undefined, mockListBaselines);
}

export function getBaselineSchedule(): Promise<BaselineSchedule> {
  return withFallback("/api/baselines/schedule", undefined, mockGetBaselineSchedule);
}

export function updateBaselineSchedule(schedule: Pick<BaselineSchedule, "enabled" | "interval_hours">): Promise<BaselineSchedule> {
  return withFallback(
    "/api/baselines/schedule",
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: schedule.enabled, interval_hours: schedule.interval_hours }),
    },
    () => mockUpdateBaselineSchedule(schedule),
  );
}

export function diffBaselines(a: string, b: string): Promise<BaselineDiff> {
  return withFallback(`/api/baselines/${encodeURIComponent(a)}/diff/${encodeURIComponent(b)}`, undefined, () => mockDiffBaselines(a, b));
}

// =======================================================================
// F1-F2: compliance
// =======================================================================

export function getComplianceFrameworks(): Promise<FrameworksResponse> {
  return withFallback("/api/compliance/frameworks", undefined, mockComplianceFrameworks);
}

export function getComplianceReport(frameworkId: string): Promise<ComplianceReport> {
  return withFallback(`/api/compliance/${encodeURIComponent(frameworkId)}`, undefined, () => mockComplianceReport(frameworkId));
}

// =======================================================================
// F3-F4: alerting
// =======================================================================

export function getAlertsConfig(): Promise<AlertsConfig> {
  return withFallback("/api/alerts/config", undefined, mockGetAlertsConfig);
}

export function updateAlertsConfig(config: AlertsConfig): Promise<AlertsConfig> {
  return withFallback(
    "/api/alerts/config",
    { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) },
    () => mockUpdateAlertsConfig(config),
  );
}

export function testAlertChannel(channelId: string): Promise<AlertTestResult> {
  return withFallback(
    "/api/alerts/test",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ channel_id: channelId }) },
    () => mockTestAlertChannel(channelId),
  );
}

export function getAlertsHistory(limit = 200): Promise<AlertHistoryResponse> {
  return withFallback(`/api/alerts/history${qs({ limit })}`, undefined, () => mockAlertsHistory(limit));
}

// =======================================================================
// F5: IP reputation enrichment (AbuseIPDB / VirusTotal)
// =======================================================================

export function getEnrichmentConfig(): Promise<EnrichmentConfig> {
  return withFallback("/api/alerts/enrichment", undefined, mockGetEnrichmentConfig);
}

export function updateEnrichmentConfig(config: EnrichmentConfigUpdate): Promise<EnrichmentConfig> {
  return withFallback(
    "/api/alerts/enrichment",
    { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) },
    () => mockUpdateEnrichmentConfig(config),
  );
}

export function testEnrichmentProvider(providerId: string): Promise<EnrichmentTestResult> {
  return withFallback(
    "/api/alerts/enrichment/test",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider_id: providerId }) },
    () => mockTestEnrichmentProvider(providerId),
  );
}

export { ApiError, BpfFilterError };

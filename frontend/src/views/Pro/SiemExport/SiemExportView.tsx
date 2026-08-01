import { useState } from "react";
import { useSiemExport } from "../../../hooks/useSiemExport";
import { SIEM_EVENT_KINDS } from "../../../api/typesPro";
import type { SiemEventKind, SiemFormat } from "../../../api/typesPro";
import "../../../components/pro/pro-common.css";
import "./SiemExportView.css";

const FORMAT_LABELS: Record<SiemFormat, string> = {
  jsonl: "JSONL",
  ecs: "ECS (Elastic Common Schema)",
  cef: "CEF (ArcSight)",
  syslog: "Syslog (RFC 5424)",
};

const KIND_LABELS: Record<SiemEventKind, string> = {
  threat: "Threats",
  recommendation: "Recommendations",
  posture: "Posture",
  traffic: "Traffic",
};

const WINDOWS: { id: string; label: string; ms: number | null }[] = [
  { id: "1h", label: "Last 1h", ms: 60 * 60_000 },
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60_000 },
  { id: "7d", label: "Last 7d", ms: 7 * 24 * 60 * 60_000 },
  { id: "all", label: "All available", ms: null },
];

export function SiemExportView() {
  const { result, previewLines, totalLines, loading, error, run, download } = useSiemExport();
  const [format, setFormat] = useState<SiemFormat>("jsonl");
  const [range, setRange] = useState("24h");
  const [kinds, setKinds] = useState<SiemEventKind[]>([...SIEM_EVENT_KINDS]);

  const toggleKind = (k: SiemEventKind) => {
    setKinds((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));
  };

  const handlePreview = () => {
    const rangeMs = WINDOWS.find((w) => w.id === range)?.ms ?? null;
    void run({
      format,
      since: rangeMs ? new Date(Date.now() - rangeMs).toISOString() : undefined,
      kinds: kinds.length ? kinds : undefined,
    });
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">SIEM / log-pipeline export</span>
        </div>
        <div className="panel siem-form">
          <div className="pro-form-grid">
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="siem-format">Format</label>
              <select id="siem-format" className="pro-select" value={format} onChange={(e) => setFormat(e.target.value as SiemFormat)}>
                {(Object.keys(FORMAT_LABELS) as SiemFormat[]).map((f) => (
                  <option key={f} value={f}>{FORMAT_LABELS[f]}</option>
                ))}
              </select>
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="siem-window">Time range</label>
              <select id="siem-window" className="pro-select" value={range} onChange={(e) => setRange(e.target.value)}>
                {WINDOWS.map((w) => (
                  <option key={w.id} value={w.id}>{w.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="pro-field">
            <span className="pro-field-label">Event kinds</span>
            <div className="pro-checkbox-row">
              {SIEM_EVENT_KINDS.map((k) => (
                <label key={k} className="pro-checkbox">
                  <input type="checkbox" checked={kinds.includes(k)} onChange={() => toggleKind(k)} />
                  {KIND_LABELS[k]}
                </label>
              ))}
            </div>
          </div>

          {error && <div className="pro-inline-error">{error}</div>}

          <div className="pro-section-actions">
            <button className="pro-btn pro-btn-primary" onClick={handlePreview} disabled={loading || kinds.length === 0}>
              {loading ? "Fetching…" : "Fetch & preview"}
            </button>
            <button className="pro-btn" onClick={download} disabled={!result}>
              Download {result ? `(${result.filename})` : ""}
            </button>
          </div>
          <p className="pro-muted">
            Streamed by the backend, one record at a time — nothing is held fully in memory server-side. Values that
            could contain <code className="mono">=</code>, <code className="mono">|</code>, or newlines are escaped
            per-format rather than emitted raw.
          </p>
        </div>
      </section>

      {result && (
        <section className="view-section">
          <div className="view-section-header">
            <span className="view-section-title">
              Preview — first {previewLines.length} of {totalLines} record{totalLines === 1 ? "" : "s"}
            </span>
          </div>
          <div className="panel">
            {previewLines.length === 0 ? (
              <p className="pro-muted">No matching events for this window/format.</p>
            ) : (
              <pre className="pro-pre siem-preview">{previewLines.join("\n")}</pre>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

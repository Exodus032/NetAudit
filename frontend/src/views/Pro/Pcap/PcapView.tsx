import { useCallback, useMemo, useState } from "react";
import { usePcapExportEstimate, usePcapImport, usePcapSessions, exportPcap } from "../../../hooks/usePcap";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import { ProgressBar } from "../../../components/pro/ProgressBar";
import { formatDateTime, formatNumber, formatBytes } from "../../../lib/format";
import type { PcapExportQuery, PcapProtocol } from "../../../api/typesPro";
import "../../../components/pro/pro-common.css";
import "./PcapView.css";

const TIME_RANGES: { id: string; label: string; ms: number | null }[] = [
  { id: "15m", label: "Last 15m", ms: 15 * 60_000 },
  { id: "1h", label: "Last 1h", ms: 60 * 60_000 },
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60_000 },
  { id: "all", label: "All captured", ms: null },
];

export function PcapView() {
  const { sessions, loading, error, reload, remove } = usePcapSessions();

  const [protocol, setProtocol] = useState<PcapProtocol | "">("");
  const [peer, setPeer] = useState("");
  const [port, setPort] = useState("");
  const [range, setRange] = useState("1h");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const query: PcapExportQuery = useMemo(() => {
    const rangeMs = TIME_RANGES.find((r) => r.id === range)?.ms ?? null;
    return {
      protocol: protocol || undefined,
      peer: peer || undefined,
      port: port ? Number(port) : undefined,
      since: rangeMs ? new Date(Date.now() - rangeMs).toISOString() : undefined,
      limit: 100000,
    };
  }, [protocol, peer, port, range]);

  const { count, loading: estimating } = usePcapExportEstimate(query);

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      await exportPcap(query);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : String(err));
    } finally {
      setExporting(false);
    }
  };

  const onImported = useCallback(() => {
    void reload();
  }, [reload]);
  const { phase, progress, error: importError, result, upload, reset } = usePcapImport(onImported);
  const [dragActive, setDragActive] = useState(false);

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void upload(file);
  };

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void upload(file);
    e.target.value = "";
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Export to .pcap</span>
        </div>
        <div className="panel pcap-export-panel">
          <div className="pro-form-grid">
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="pcap-protocol">Protocol</label>
              <select id="pcap-protocol" className="pro-select" value={protocol} onChange={(e) => setProtocol(e.target.value as PcapProtocol | "")}>
                <option value="">All protocols</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="pcap-peer">Host / peer</label>
              <input id="pcap-peer" className="pro-input" value={peer} onChange={(e) => setPeer(e.target.value)} placeholder="e.g. 10.0.0.5" />
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="pcap-port">Port</label>
              <input id="pcap-port" className="pro-input" type="number" min={0} max={65535} value={port} onChange={(e) => setPort(e.target.value)} placeholder="any" />
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="pcap-range">Time window</label>
              <select id="pcap-range" className="pro-select" value={range} onChange={(e) => setRange(e.target.value)}>
                {TIME_RANGES.map((r) => (
                  <option key={r.id} value={r.id}>{r.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="pcap-export-footer">
            <span className="pcap-count">
              {estimating ? "Counting…" : count === null ? "Count unavailable" : `${formatNumber(count)} packets will be exported`}
            </span>
            <button className="pro-btn pro-btn-primary" onClick={handleExport} disabled={exporting || count === 0}>
              {exporting ? "Exporting…" : "Export .pcap"}
            </button>
          </div>
          {exportError && <div className="pro-inline-error">{exportError}</div>}
          <p className="pro-muted">
            Every capture tier stores header fields only, never raw frame bytes — exported frames are reconstructed
            from what was actually observed, with payload zero-filled rather than fabricated. Sessions marked
            "synthetic" below say so explicitly.
          </p>
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Import a capture</span>
        </div>
        <div className="panel">
          <div
            className={`pro-dropzone${dragActive ? " pro-dropzone-active" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={onDrop}
            onClick={() => document.getElementById("pcap-file-input")?.click()}
            role="button"
            tabIndex={0}
          >
            Drop a .pcap or .pcapng file here, or click to browse
            <div className="pro-dropzone-hint">200 MB maximum · parsed as untrusted input, never merged into live capture</div>
            <input id="pcap-file-input" type="file" accept=".pcap,.pcapng" hidden onChange={onFileInput} />
          </div>

          {phase === "uploading" && (
            <div className="pcap-import-progress">
              <ProgressBar percent={progress} label="Uploading and parsing…" />
            </div>
          )}

          {phase === "error" && importError && (
            <ErrorState title="Import failed" detail={importError} action={<button className="pro-btn" onClick={reset}>Try another file</button>} />
          )}

          {phase === "done" && result && (
            <div className="pcap-import-result">
              <div className="pro-notice pro-notice-good">
                <span className="pro-notice-icon" aria-hidden="true">✓</span>
                <div>
                  <strong>{result.filename}</strong> imported as session <code className="mono">{result.session_id}</code>.{" "}
                  {formatNumber(result.packets)} packets, {formatBytes(result.bytes)}.
                  {result.parse_errors > 0 && (
                    <div className="pro-inline-error">
                      {result.parse_errors} packet{result.parse_errors === 1 ? "" : "s"} could not be parsed and were skipped.
                    </div>
                  )}
                  {result.truncated && <div className="pro-inline-error">The file appears truncated — some packets may be missing.</div>}
                </div>
              </div>
              <button className="pro-btn" onClick={reset}>Import another</button>
            </div>
          )}
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Sessions</span>
        </div>

        {error && <ErrorState title="Couldn't load sessions" detail={error} />}
        {!error && loading && <SkeletonRows rows={3} height={44} />}
        {!error && !loading && sessions.length === 0 && <EmptyState title="No sessions" />}

        <div className="pro-list">
          {sessions.map((s) => (
            <div key={s.id} className="pro-card">
              <div className="pro-card-main">
                <div className="pro-card-title">
                  {s.label}
                  {s.synthetic && (
                    <span className="pcap-synthetic-badge" title={s.synthetic_reason ?? undefined}>
                      synthetic
                    </span>
                  )}
                </div>
                <div className="pro-card-meta">
                  <span>{s.kind === "live" ? "Live capture" : "Imported"}</span>
                  <span>{formatNumber(s.packets)} packets</span>
                  {s.imported_at && <span>Imported {formatDateTime(s.imported_at)}</span>}
                </div>
              </div>
              <div className="pro-card-actions">
                <button className="pro-btn pro-btn-danger" onClick={() => void remove(s.id)} disabled={s.kind === "live"}>
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

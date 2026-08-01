import { useState } from "react";
import { useReports } from "../../../hooks/useReports";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import { formatBytes, formatDateTime } from "../../../lib/format";
import { REPORT_SECTIONS } from "../../../api/typesPro";
import type { ReportFormat, ReportSection } from "../../../api/typesPro";
import "../../../components/pro/pro-common.css";
import "./ReportsView.css";

const SECTION_LABELS: Record<ReportSection, string> = {
  summary: "Executive summary",
  posture: "Security posture",
  threats: "Threats",
  recommendations: "Recommendations",
  traffic: "Traffic",
  devices: "Devices",
};

const WINDOWS = ["1h", "24h", "7d", "30d"];

export function ReportsView() {
  const { reports, loading, error, generating, genError, active, activeLoading, generate, view, remove, setActive } = useReports();

  const [format, setFormat] = useState<ReportFormat>("html");
  const [sections, setSections] = useState<ReportSection[]>([...REPORT_SECTIONS]);
  const [window, setWindowValue] = useState("24h");
  const [title, setTitle] = useState("NetAudit report");

  const toggleSection = (s: ReportSection) => {
    setSections((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  };

  const handleGenerate = async () => {
    if (sections.length === 0) return;
    await generate({ format, sections, window, title });
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Generate a report</span>
        </div>
        <div className="panel reports-form">
          <div className="pro-form-grid">
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="report-title">Title</label>
              <input id="report-title" className="pro-input" value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="report-format">Format</label>
              <select id="report-format" className="pro-select" value={format} onChange={(e) => setFormat(e.target.value as ReportFormat)}>
                <option value="html">HTML</option>
                <option value="markdown">Markdown</option>
                <option value="json">JSON</option>
              </select>
            </div>
            <div className="pro-field">
              <label className="pro-field-label" htmlFor="report-window">Time window</label>
              <select id="report-window" className="pro-select" value={window} onChange={(e) => setWindowValue(e.target.value)}>
                {WINDOWS.map((w) => (
                  <option key={w} value={w}>{w}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="pro-field">
            <span className="pro-field-label">Sections</span>
            <div className="pro-checkbox-row">
              {REPORT_SECTIONS.map((s) => (
                <label key={s} className="pro-checkbox">
                  <input type="checkbox" checked={sections.includes(s)} onChange={() => toggleSection(s)} />
                  {SECTION_LABELS[s]}
                </label>
              ))}
            </div>
          </div>

          {sections.length === 0 && <div className="pro-inline-error">Pick at least one section.</div>}
          {genError && <div className="pro-inline-error">{genError}</div>}

          <div className="pro-section-actions">
            <button className="pro-btn pro-btn-primary" onClick={handleGenerate} disabled={generating || sections.length === 0}>
              {generating ? "Generating…" : "Generate report"}
            </button>
          </div>
        </div>
      </section>

      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Past reports</span>
        </div>

        {error && <ErrorState title="Couldn't load reports" detail={error} />}
        {!error && loading && <SkeletonRows rows={3} height={44} />}
        {!error && !loading && reports.length === 0 && <EmptyState title="No reports yet" detail="Generate one above." />}

        <div className="pro-list">
          {reports.map((r) => (
            <div key={r.id} className="pro-card">
              <div className="pro-card-main">
                <div className="pro-card-title">{r.title}</div>
                <div className="pro-card-meta">
                  <span className="reports-format-tag">{r.format}</span>
                  <span>window {r.window}</span>
                  <span>{formatBytes(r.bytes)}</span>
                  <span>{formatDateTime(r.generated_at)}</span>
                </div>
              </div>
              <div className="pro-card-actions">
                <button className="pro-btn" onClick={() => void view(r.id)}>View</button>
                <button className="pro-btn pro-btn-danger" onClick={() => void remove(r.id)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {(activeLoading || active) && (
        <section className="view-section">
          <div className="view-section-header">
            <span className="view-section-title">Report preview</span>
            {active && (
              <button className="pro-btn" onClick={() => setActive(null)}>Close</button>
            )}
          </div>
          <div className="panel">
            {activeLoading && <SkeletonRows rows={4} height={20} />}
            {!activeLoading && active && <ReportPreview format={active.format} content={active.content} />}
          </div>
        </section>
      )}
    </div>
  );
}

function ReportPreview({ format, content }: { format: ReportFormat; content: string }) {
  if (format === "html") {
    return <iframe title="Report preview" sandbox="" srcDoc={content} className="reports-iframe" />;
  }
  return <pre className="pro-pre reports-pre">{content}</pre>;
}

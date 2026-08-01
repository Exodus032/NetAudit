import { useEffect, useState } from "react";
import { useComplianceFrameworks, useComplianceReport } from "../../../hooks/useCompliance";
import { ErrorState, EmptyState, SkeletonRows } from "../../../components/common/States";
import type { ControlStatus } from "../../../api/typesPro";
import "../../../components/pro/pro-common.css";
import "./ComplianceView.css";

const STATUS_META: Record<ControlStatus, { label: string; cls: string }> = {
  pass: { label: "Pass", cls: "compliance-status-pass" },
  fail: { label: "Fail", cls: "compliance-status-fail" },
  partial: { label: "Partial", cls: "compliance-status-partial" },
  not_assessed: { label: "Not assessed", cls: "compliance-status-not-assessed" },
};

function StatusBadge({ status }: { status: ControlStatus }) {
  const meta = STATUS_META[status];
  return <span className={`compliance-status-pill ${meta.cls}`}>{meta.label}</span>;
}

export function ComplianceView() {
  const { frameworks, loading: fwLoading, error: fwError } = useComplianceFrameworks();
  const [frameworkId, setFrameworkId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!frameworkId && frameworks.length > 0) setFrameworkId(frameworks[0].id);
  }, [frameworks, frameworkId]);

  const { report, loading, error } = useComplianceReport(frameworkId);

  const toggle = (id: string) => {
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Compliance framework</span>
        </div>

        {fwError && <ErrorState title="Couldn't load frameworks" detail={fwError} />}
        {fwLoading && <SkeletonRows rows={2} height={40} />}

        {!fwLoading && frameworks.length > 0 && (
          <div className="compliance-framework-picker">
            {frameworks.map((f) => (
              <button
                key={f.id}
                className={`compliance-framework-btn${frameworkId === f.id ? " active" : ""}`}
                onClick={() => setFrameworkId(f.id)}
              >
                <div className="compliance-framework-label">{f.label}</div>
                <div className="pro-muted">{f.controls_mapped} controls · {f.checks_mapped} checks mapped</div>
              </button>
            ))}
          </div>
        )}
      </section>

      {error && <ErrorState title="Couldn't load the compliance report" detail={error} />}
      {loading && <SkeletonRows rows={4} height={30} />}

      {!loading && report && (
        <>
          <section className="view-section">
            <div className="pro-notice">
              <span className="pro-notice-icon" aria-hidden="true">ℹ</span>
              <div>{report.disclaimer}</div>
            </div>

            <div className="pro-guarantees compliance-summary">
              <div className="pro-guarantee">
                <div className="pro-guarantee-value">{report.summary.pass}</div>
                <div className="pro-guarantee-label">Pass</div>
              </div>
              <div className="pro-guarantee">
                <div className="pro-guarantee-value">{report.summary.fail}</div>
                <div className="pro-guarantee-label">Fail</div>
              </div>
              <div className="pro-guarantee">
                <div className="pro-guarantee-value">{report.summary.partial}</div>
                <div className="pro-guarantee-label">Partial</div>
              </div>
              <div className="pro-guarantee">
                <div className="pro-guarantee-value">{report.summary.not_assessed}</div>
                <div className="pro-guarantee-label">Not assessed</div>
              </div>
              <div className="pro-guarantee">
                <div className="pro-guarantee-value">{report.summary.coverage_percent}%</div>
                <div className="pro-guarantee-label">Controls with any evidence</div>
              </div>
            </div>
          </section>

          <section className="view-section">
            <div className="view-section-header">
              <span className="view-section-title">Controls</span>
            </div>

            {report.controls.length === 0 && <EmptyState title="No controls mapped for this framework" />}

            <div className="pro-list">
              {report.controls.map((c) => (
                <div key={c.control_id} className="pro-card compliance-control-card">
                  <button className="compliance-control-toggle" onClick={() => toggle(c.control_id)} aria-expanded={expanded.has(c.control_id)}>
                    <span className="compliance-control-caret" aria-hidden="true">{expanded.has(c.control_id) ? "▾" : "▸"}</span>
                    <span className="mono compliance-control-id">{c.control_id}</span>
                    <span className="compliance-control-title">{c.title}</span>
                    <StatusBadge status={c.status} />
                  </button>
                  {expanded.has(c.control_id) && (
                    <div className="compliance-control-detail">
                      <p>{c.rationale}</p>
                      {c.evidence_checks.length > 0 ? (
                        <table className="compliance-evidence-table">
                          <tbody>
                            {c.evidence_checks.map((e) => (
                              <tr key={e.check_id}>
                                <td className="mono">{e.check_id}</td>
                                <td>{e.status}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <p className="pro-muted">No posture checks are mapped to this control — NetAudit has no vantage point here.</p>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}

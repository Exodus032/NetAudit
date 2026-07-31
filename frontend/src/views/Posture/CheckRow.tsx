import { useState } from "react";
import type { PostureCheck } from "../../api/types";
import { CheckStatusBadge, SeverityBadge } from "../../components/common/Badge";
import { CommandBlock } from "../../components/common/CommandBlock";
import "./CheckRow.css";

export function CheckRow({ check }: { check: PostureCheck }) {
  const [open, setOpen] = useState(false);
  const isNeutral = check.status === "error" || check.status === "skipped";

  return (
    <div className={`check-row${open ? " open" : ""}${isNeutral ? " neutral" : ""}`}>
      <button className="check-row-summary" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="check-row-caret" aria-hidden="true">{open ? "▾" : "▸"}</span>
        <CheckStatusBadge status={check.status} />
        <SeverityBadge severity={check.severity} />
        <span className="check-row-title">{check.title}</span>
      </button>
      {open && (
        <div className="check-row-detail">
          <dl className="check-row-grid">
            <dt>Observed</dt>
            <dd>{check.observed}</dd>
            <dt>Expected</dt>
            <dd>{check.expected}</dd>
          </dl>
          <p className="check-row-why">
            <strong>Why it matters. </strong>
            {check.why_it_matters}
          </p>

          {check.evidence.length > 0 && (
            <table className="check-evidence">
              <tbody>
                {check.evidence.map((ev, i) => (
                  <tr key={i}>
                    <td className="check-evidence-label">{ev.label}</td>
                    <td className="check-evidence-value mono">{ev.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div className="check-remediation">
            <div className="check-remediation-summary">{check.remediation.summary}</div>
            {check.remediation.commands.map((cmd, i) => (
              <CommandBlock key={i} command={cmd.command} requiresAdmin={cmd.requires_admin} riskNote={cmd.risk_note} />
            ))}
            {check.remediation.docs_url && (
              <a className="check-docs-link" href={check.remediation.docs_url} target="_blank" rel="noreferrer noopener">
                Read more ↗
              </a>
            )}
            {check.references.length > 0 && (
              <div className="check-references">{check.references.join(" · ")}</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

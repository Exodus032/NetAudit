import { useState } from "react";
import type { Threat } from "../../api/types";
import { SeverityBadge, CategoryChip, ThreatStatusBadge } from "../../components/common/Badge";
import { CommandBlock } from "../../components/common/CommandBlock";
import { ConfidenceMeter } from "./ConfidenceMeter";
import { ExplainChip } from "../../components/learn/ExplainChip";
import { formatDateTime, formatNumber } from "../../lib/format";
import "./ThreatRow.css";

/** One-line rendering of a provider's parsed reputation result: the
 * AbuseIPDB confidence score, or VirusTotal's malicious/suspicious
 * counts. An `{error}` entry renders as the error code itself. */
function formatEnrichment(providerId: string, parsed: Record<string, unknown>): string {
  if (typeof parsed.error === "string") return parsed.error;
  if (providerId === "abuseipdb") {
    const score = parsed.abuse_confidence_score;
    if (typeof score === "number") return `score ${score}${parsed.is_tor ? " · tor exit" : ""}`;
    return "no data";
  }
  const stats = (parsed.last_analysis_stats ?? {}) as Record<string, unknown>;
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  if (malicious || suspicious) return `${malicious} malicious / ${suspicious} suspicious`;
  return "no detections";
}

export function ThreatRow({
  threat,
  onAcknowledge,
  onUnacknowledge,
  isFirst,
}: {
  threat: Threat;
  onAcknowledge: (id: string, note?: string) => Promise<void>;
  onUnacknowledge: (id: string, note?: string) => Promise<void>;
  isFirst?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const isAck = threat.status === "acknowledged";
  const isResolved = threat.status === "resolved";

  const handleToggleAck = async () => {
    setBusy(true);
    setActionError(null);
    try {
      if (isAck) await onUnacknowledge(threat.id);
      else await onAcknowledge(threat.id);
    } catch (err) {
      // The hook already rolled the optimistic update back; just say why.
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className={`threat-row${isResolved ? " threat-row-resolved" : ""}${isAck ? " threat-row-ack" : ""}`}>
      <div className="threat-row-header">
        <SeverityBadge severity={threat.severity} />
        <ThreatStatusBadge status={threat.status} />
        <CategoryChip category={threat.category} />
        <ConfidenceMeter confidence={threat.confidence} />
        <ExplainChip kind="metric" id="confidence" label="Confidence" />
        <div className="threat-row-spacer" />
        {!isResolved && (
          <button className="threat-ack-btn" onClick={handleToggleAck} disabled={busy}>
            {isAck ? "Unacknowledge" : "Acknowledge"}
          </button>
        )}
      </div>

      {actionError && (
        <div className="threat-action-error" role="alert">
          Couldn't update: {actionError}
        </div>
      )}

      {threat.mitre.length > 0 && (
        <div className="mitre-badges">
          {threat.mitre.map((m, i) => (
            <span
              key={i}
              className="mitre-badge mono"
              title={[m.tactic_name, m.technique_name].filter(Boolean).join(" · ") || undefined}
            >
              {m.tactic}
              {m.technique ? ` · ${m.technique}` : ""}
            </span>
          ))}
        </div>
      )}

      <div className="threat-row-title-row">
        {/* ExplainChip is its own <button> — kept outside threat-row-title-btn
            so it isn't nested inside another interactive control. */}
        <button className="threat-row-title-btn" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          <span className="threat-row-caret" aria-hidden="true">{open ? "▾" : "▸"}</span>
          <span className="threat-row-title">{threat.title}</span>
        </button>
        <ExplainChip kind="detector" id={threat.detector_id} label={threat.title} />
      </div>
      <p className="threat-row-summary">{threat.summary}</p>

      {threat.false_positive_notes && (
        <div className="threat-fp-note">
          <span className="threat-fp-icon" aria-hidden="true">◐</span>
          <div>
            <strong>Could be benign — read before acting. </strong>
            {threat.false_positive_notes}
          </div>
        </div>
      )}

      {isAck && threat.acknowledged_note && <div className="threat-ack-note">Acknowledged: {threat.acknowledged_note}</div>}

      <div className="threat-row-meta">
        <span>{formatNumber(threat.occurrences)} occurrences</span>
        <span>First seen {formatDateTime(threat.first_seen)}</span>
        <span>Last seen {formatDateTime(threat.last_seen)}</span>
      </div>

      {open && (
        <div className="threat-row-detail" {...(isFirst ? { "data-tour": "threat-detail-drawer" } : {})}>
          <p className="threat-row-detail-text">{threat.detail}</p>

          {threat.evidence.length > 0 && (
            <table className="threat-evidence">
              <tbody>
                {threat.evidence.map((ev, i) => (
                  <tr key={i}>
                    <td className="threat-evidence-label">{ev.label}</td>
                    <td className="threat-evidence-value mono">{ev.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {Object.keys(threat.metrics).length > 0 && (
            <div className="threat-metrics">
              {Object.entries(threat.metrics).map(([k, v]) => (
                <span key={k} className="threat-metric-chip">
                  <span className="threat-metric-key">{k.replace(/_/g, " ")}</span>
                  <span className="threat-metric-value mono">{String(v)}</span>
                </span>
              ))}
            </div>
          )}

          {threat.indicators.length > 0 && (
            <div className="threat-indicators">
              {threat.indicators.map((ind, i) => (
                <span key={i} className="threat-indicator-chip mono" title={ind.context}>
                  {ind.type}: {ind.value}
                </span>
              ))}
            </div>
          )}

          {(threat.tags?.length ?? 0) > 0 && (
            <div className="threat-tags">
              <span className="threat-tags-label">Auto-tags</span>
              {threat.tags?.map((t, i) => (
                <span key={i} className="threat-tag-chip mono">{t}</span>
              ))}
            </div>
          )}

          {threat.enrichment && Object.keys(threat.enrichment).length > 0 && (
            <div className="threat-enrichment">
              <span className="threat-tags-label">IP enrichment</span>
              {Object.entries(threat.enrichment).map(([ip, providers]) => (
                <div key={ip} className="threat-enrichment-ip">
                  <span className="threat-enrichment-addr mono">{ip}</span>
                  {Object.entries(providers as Record<string, Record<string, unknown>>).map(([providerId, parsed]) => (
                    <span key={providerId} className="threat-enrichment-provider mono">
                      {providerId}: {formatEnrichment(providerId, parsed)}
                    </span>
                  ))}
                </div>
              ))}
            </div>
          )}

          {threat.recommended_actions.length > 0 && (
            <ul className="threat-actions">
              {threat.recommended_actions.map((a, i) => (
                <li className="threat-action-item" key={i}>
                  <div className="threat-action-head">
                    <span className="threat-action-label">{a.label}</span>
                  </div>
                  {a.detail && <p className="threat-action-detail">{a.detail}</p>}
                  {a.kind === "link" && a.url && (
                    <a className="threat-action-link" href={a.url} target="_blank" rel="noreferrer noopener">
                      Open link ↗
                    </a>
                  )}
                  {a.kind === "command" && a.command && (
                    <CommandBlock command={a.command} requiresAdmin={a.requires_admin} />
                  )}
                </li>
              ))}
            </ul>
          )}
          {threat.recommended_actions.length === 0 && (
            <p className="threat-no-actions">No specific action recommended — informational only.</p>
          )}
        </div>
      )}
    </article>
  );
}

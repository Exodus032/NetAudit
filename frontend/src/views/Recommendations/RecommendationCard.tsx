import { useState } from "react";
import type { Recommendation } from "../../api/types";
import { SeverityBadge, CategoryChip } from "../../components/common/Badge";
import { ActionItem } from "./ActionItem";
import { formatDateTime, formatNumber, formatPercent } from "../../lib/format";
import "./RecommendationCard.css";

export function RecommendationCard({
  rec,
  onDismiss,
  onRestore,
  highlight,
}: {
  rec: Recommendation;
  onDismiss: (id: string) => void;
  onRestore: (id: string) => void;
  highlight: boolean;
}) {
  const [busy, setBusy] = useState(false);

  const handleToggle = async () => {
    setBusy(true);
    try {
      if (rec.dismissed) await onRestore(rec.id);
      else await onDismiss(rec.id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className={`rec-card${highlight ? " rec-card-highlight" : ""}${rec.dismissed ? " rec-card-dismissed" : ""}`}>
      <div className="rec-card-header">
        <SeverityBadge severity={rec.severity} />
        <CategoryChip category={rec.category} />
        <span className="rec-confidence">confidence {formatPercent(rec.confidence)}</span>
        <div className="rec-card-spacer" />
        <button className="rec-dismiss-btn" onClick={handleToggle} disabled={busy}>
          {rec.dismissed ? "Restore" : "Dismiss"}
        </button>
      </div>

      <h3 className="rec-title">{rec.title}</h3>
      <p className="rec-summary">{rec.summary}</p>
      <p className="rec-detail">{rec.detail}</p>

      {rec.evidence.length > 0 && (
        <table className="rec-evidence">
          <tbody>
            {rec.evidence.map((ev) => (
              <tr key={ev.label}>
                <td className="rec-evidence-label">{ev.label}</td>
                <td className="rec-evidence-value mono">{ev.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {rec.actions.length > 0 && (
        <ul className="rec-actions">
          {rec.actions.map((a, i) => (
            <ActionItem key={i} action={a} />
          ))}
        </ul>
      )}

      <div className="rec-meta">
        <span>{formatNumber(rec.occurrences)} occurrences</span>
        <span>First seen {formatDateTime(rec.first_seen)}</span>
        <span>Last seen {formatDateTime(rec.last_seen)}</span>
      </div>
    </article>
  );
}

import { useSecurityScore } from "../../hooks/useSecurityScore";
import "./SecurityScoreTile.css";

function scoreColor(score: number): string {
  if (score >= 80) return "var(--status-good)";
  if (score >= 60) return "var(--status-warning)";
  if (score >= 40) return "var(--status-serious)";
  return "var(--status-critical)";
}

/** Composite /api/security/score summary, linking through to the Posture
 * view — the only place this number is broken down into what's driving it. */
export function SecurityScoreTile({ onOpenPosture }: { onOpenPosture: () => void }) {
  const { data, loading, error } = useSecurityScore();

  if (error) return null; // non-critical widget on this view; don't block Overview on it

  return (
    <button className="security-score-tile" onClick={onOpenPosture}>
      <div className="security-score-tile-figure" style={{ color: data ? scoreColor(data.overall) : undefined }}>
        {loading && !data ? "—" : data?.overall}
        {data && <span className="security-score-tile-grade">{data.grade}</span>}
      </div>
      <div className="security-score-tile-body">
        <div className="security-score-tile-label">Overall security score</div>
        <div className="security-score-tile-components">
          {data?.components.map((c) => (
            <span key={c.id} className="security-score-tile-component">
              {c.label} <strong className="tabular">{c.score}</strong>
            </span>
          ))}
        </div>
      </div>
      <span className="security-score-tile-cta">Posture &amp; threats →</span>
    </button>
  );
}

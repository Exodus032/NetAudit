import { usePrioritisedFindings } from "../../hooks/usePrioritisedFindings";
import { ErrorState, EmptyState, SkeletonRows } from "../../components/common/States";
import { severityVisual } from "../../lib/severity";
import { formatRelativeTime } from "../../lib/format";
import type { PrioritisedFinding } from "../../api/typesLearn";
import "./FixFirstView.css";

const SOURCE_LABELS: Record<string, string> = {
  posture: "Security posture",
  recommendation: "Recommended action",
  threat: "Threat",
};

const EFFORT_LABELS: Record<string, string> = { low: "Low effort", medium: "Medium effort", high: "High effort" };

interface FixFirstViewProps {
  onNavigate?: (view: string) => void;
}

/** GET /api/findings/prioritised, rendered as an ordered, student-readable
 * "what should I fix first" list. Impact and effort are shown as-is from the
 * ranking, not softened — a high-effort item stays labeled high-effort even
 * when it outranks a low-effort one on severity. */
export function FixFirstView({ onNavigate }: FixFirstViewProps) {
  const { items, generatedAt, loading, error, reload } = usePrioritisedFindings();

  if (error) return <ErrorState title="Couldn't load prioritised findings" detail={error} action={<button onClick={reload}>Retry</button>} />;
  if (loading && items.length === 0) return <SkeletonRows rows={6} height={64} />;

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Fix this first</span>
          {generatedAt && <span className="fixfirst-generated">Ranked {formatRelativeTime(generatedAt)}</span>}
        </div>
        <p className="fixfirst-intro">
          One ranked list across security posture, recommended actions and threats, combining how bad each problem is with
          how cheap it is to fix. Highest impact for the least effort comes first.
        </p>
      </section>

      <section className="view-section">
        {items.length === 0 && (
          <EmptyState title="Nothing to fix right now" detail="No failing checks, active threats, or open recommendations." icon="✓" />
        )}
        <ol className="fixfirst-list">
          {items.map((item) => (
            <FindingCard key={item.id} item={item} onNavigate={onNavigate} />
          ))}
        </ol>
      </section>
    </div>
  );
}

function FindingCard({ item, onNavigate }: { item: PrioritisedFinding; onNavigate?: (view: string) => void }) {
  const sev = severityVisual(item.severity);

  return (
    <li className="fixfirst-card">
      <div className="fixfirst-rank">#{item.priority_rank}</div>
      <div className="fixfirst-main">
        <div className="fixfirst-head">
          <span className="badge" style={{ color: `var(${sev.colorVar})`, borderColor: `var(${sev.colorVar})` }}>
            <span aria-hidden="true">{sev.icon}</span> {sev.label}
          </span>
          <span className="chip">{SOURCE_LABELS[item.source] ?? item.source}</span>
          <span className="chip fixfirst-effort">{EFFORT_LABELS[item.effort] ?? item.effort}</span>
          <span className="fixfirst-impact" title={`Impact score: ${item.impact_score} of 100`}>
            Impact {item.impact_score}
          </span>
        </div>
        <div className="fixfirst-title">{item.title}</div>
        {/* A posture title states the goal ("Require SMB signing"), which on
            its own reads like good news in a list of things to fix.
            `observed` is what is actually true. */}
        {item.observed && (
          <p className="fixfirst-observed">
            <span className="fixfirst-observed-label">Right now:</span> {item.observed}
          </p>
        )}
        <p className="fixfirst-why">{item.why_first}</p>
        <div className="fixfirst-fix">
          <span className="fixfirst-fix-label">Fix:</span> {item.one_line_fix}
        </div>
      </div>
      {onNavigate && (
        <button className="fixfirst-goto" onClick={() => onNavigate(item.deep_link.view)}>
          View details ↗
        </button>
      )}
    </li>
  );
}

import { useState } from "react";
import { useRecommendations } from "../../hooks/useRecommendations";
import { RecommendationCard } from "./RecommendationCard";
import { ErrorState, EmptyState } from "../../components/common/States";
import "./RecommendationsView.css";

export function RecommendationsView() {
  const [includeDismissed, setIncludeDismissed] = useState(false);
  const { recommendations, loading, error, dismiss, restore, newlyArrivedIds } = useRecommendations(includeDismissed);

  return (
    <div>
      <div className="rec-toolbar">
        <label className="rec-toggle">
          <input
            type="checkbox"
            checked={includeDismissed}
            onChange={(e) => setIncludeDismissed(e.target.checked)}
          />
          Include dismissed
        </label>
      </div>

      {error && <ErrorState title="Couldn't load recommendations" detail={error} />}

      {!error && loading && recommendations.length === 0 && (
        <div className="rec-skel-list">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="rec-skel-card" aria-hidden="true" />
          ))}
        </div>
      )}

      {!error && !loading && recommendations.length === 0 && (
        <EmptyState title="No open recommendations" detail="NetAudit hasn't flagged anything that needs your attention right now." icon="✓" />
      )}

      {recommendations.length > 0 && (
        <div data-tour="recommendations-list">
          {recommendations.map((rec, i) => (
            <RecommendationCard
              key={rec.id}
              rec={rec}
              onDismiss={dismiss}
              onRestore={restore}
              highlight={newlyArrivedIds.has(rec.id)}
              isFirst={i === 0}
            />
          ))}
        </div>
      )}
    </div>
  );
}

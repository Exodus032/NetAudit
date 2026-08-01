import { useMemo, useState } from "react";
import { useThreats } from "../../hooks/useThreats";
import { useThreatsTimeline } from "../../hooks/useThreatsTimeline";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { ThreatFilters, type ThreatFilterState } from "./ThreatFilters";
import { ThreatTimelineChart } from "./ThreatTimelineChart";
import { ThreatRow } from "./ThreatRow";
import { ErrorState, EmptyState } from "../../components/common/States";
import { WindowSelector } from "../../components/common/WindowSelector";
import type { StatsWindow, ThreatsQuery } from "../../api/types";
import { formatNumber } from "../../lib/format";
import "./ThreatsView.css";

const DEFAULT_FILTERS: ThreatFilterState = { q: "", severity: "", category: "", status: "", includeAcknowledged: false };

export function ThreatsView() {
  const [filters, setFilters] = useState<ThreatFilterState>(DEFAULT_FILTERS);
  const [timelineWindow, setTimelineWindow] = useState<StatsWindow>("24h");
  const debouncedQ = useDebouncedValue(filters.q, 300);

  // Filtering by status=acknowledged only makes sense if acknowledged threats
  // aren't already excluded upstream — this keeps that combination usable
  // without changing the contract's default (include_acknowledged: false).
  const effectiveIncludeAck = filters.includeAcknowledged || filters.status === "acknowledged";

  const query: ThreatsQuery = useMemo(
    () => ({
      q: debouncedQ || undefined,
      severity: filters.severity || undefined,
      category: filters.category || undefined,
      status: filters.status || undefined,
      include_acknowledged: effectiveIncludeAck || undefined,
    }),
    [debouncedQ, filters.severity, filters.category, filters.status, effectiveIncludeAck],
  );

  const { threats, total, loading, error, acknowledge, unacknowledge } = useThreats(query);
  const { points: timelinePoints, loading: timelineLoading } = useThreatsTimeline(timelineWindow);

  return (
    <div>
      <section className="view-section">
        <div className="view-section-header">
          <span className="view-section-title">Threat activity</span>
          <WindowSelector value={timelineWindow} onChange={setTimelineWindow} />
        </div>
        <div className="panel">
          <ThreatTimelineChart points={timelinePoints} loading={timelineLoading} />
        </div>
      </section>

      <section className="view-section">
        <ThreatFilters
          filters={filters}
          onChange={setFilters}
          totalLabel={`${formatNumber(threats.length)} shown${total > threats.length ? ` of ${formatNumber(total)}` : ""}`}
        />

        {error && <ErrorState title="Couldn't load threats" detail={error} />}

        {!error && loading && threats.length === 0 && (
          <div className="threats-skel-list">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="threats-skel-card" aria-hidden="true" />
            ))}
          </div>
        )}

        {!error && !loading && threats.length === 0 && (
          <EmptyState
            title="No threats match these filters"
            detail="Nothing active right now — widen the filters or include acknowledged/resolved threats."
            icon="✓"
          />
        )}

        {threats.length > 0 && (
          <div data-tour="threats-list">
            {threats.map((t, i) => (
              <ThreatRow key={t.id} threat={t} onAcknowledge={acknowledge} onUnacknowledge={unacknowledge} isFirst={i === 0} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

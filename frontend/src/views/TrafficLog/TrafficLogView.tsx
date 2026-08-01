import { useMemo, useState } from "react";
import { FilterBar, type LogFilters } from "./FilterBar";
import { LogTable } from "./LogTable";
import { LogDetailDrawer } from "./LogDetailDrawer";
import { useTrafficLog } from "../../hooks/useTrafficLog";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { exportTrafficLog } from "../../api/client";
import { ErrorState, SkeletonRows, EmptyState } from "../../components/common/States";
import type { TrafficLogEntry, TrafficLogQuery } from "../../api/types";
import { formatNumber } from "../../lib/format";
import "./TrafficLogView.css";

const RANGE_MS: Record<LogFilters["timeRange"], number | null> = {
  "5m": 5 * 60_000,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  all: null,
};

const DEFAULT_FILTERS: LogFilters = { q: "", protocol: "", direction: "", minBytes: "", timeRange: "all" };

export function TrafficLogView() {
  const [filters, setFilters] = useState<LogFilters>(DEFAULT_FILTERS);
  const debouncedQ = useDebouncedValue(filters.q, 300);
  const [sort, setSort] = useState<"time" | "bytes">("time");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [liveTailOn, setLiveTailOn] = useState(true);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<TrafficLogEntry | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const query: TrafficLogQuery = useMemo(() => {
    const rangeMs = RANGE_MS[filters.timeRange];
    return {
      q: debouncedQ || undefined,
      protocol: filters.protocol || undefined,
      direction: (filters.direction || undefined) as TrafficLogQuery["direction"],
      min_bytes: filters.minBytes ? Number(filters.minBytes) : undefined,
      since: rangeMs ? new Date(Date.now() - rangeMs).toISOString() : undefined,
      sort,
      order,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ, filters.protocol, filters.direction, filters.minBytes, filters.timeRange, sort, order]);

  const { entries, total, loading, error, pendingCount, flushPending } = useTrafficLog(query, liveTailOn, paused);

  const handleSortChange = (newSort: "time" | "bytes", newOrder: "asc" | "desc") => {
    setSort(newSort);
    setOrder(newOrder);
  };

  const handleScrollStateChange = (scrolledAway: boolean) => {
    setPaused(scrolledAway);
  };

  const handleExport = (format: "csv" | "json") => {
    setExportError(null);
    // exportTrafficLog no longer falls back to mock rows on an auth/server
    // error — it throws instead, so surface that here.
    exportTrafficLog(query, format).catch((err) => {
      setExportError(err instanceof Error ? err.message : String(err));
    });
  };

  return (
    <div className="traffic-log-view">
      <FilterBar
        filters={filters}
        onChange={setFilters}
        liveTailOn={liveTailOn}
        onToggleLiveTail={() => setLiveTailOn((v) => !v)}
        onExport={handleExport}
        totalLabel={`${formatNumber(entries.length)} shown${total > entries.length ? ` of ${formatNumber(total)}` : ""}`}
      />

      {pendingCount > 0 && (
        <button className="pending-banner" onClick={flushPending}>
          {pendingCount} new {pendingCount === 1 ? "row" : "rows"} — click to show
        </button>
      )}

      {exportError && <ErrorState title="Export failed" detail={exportError} />}

      {error && <ErrorState title="Couldn't load the traffic log" detail={error} />}
      {!error && loading && entries.length === 0 && <SkeletonRows rows={10} height={24} />}
      {!error && !loading && entries.length === 0 && (
        <EmptyState title="No matching traffic" detail="Try widening the time range or clearing filters." />
      )}
      {entries.length > 0 && (
        <LogTable
          entries={entries}
          sort={sort}
          order={order}
          onSortChange={handleSortChange}
          onRowClick={setSelected}
          onScrollStateChange={handleScrollStateChange}
          selectedId={selected?.id ?? null}
        />
      )}

      <LogDetailDrawer entry={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

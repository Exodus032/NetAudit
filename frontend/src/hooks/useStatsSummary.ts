import { useEffect, useRef, useState } from "react";
import { getStatsSummary } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { StatsSummary, StatsWindow } from "../api/types";

interface UseStatsSummaryResult {
  data: StatsSummary | null;
  loading: boolean;
  error: string | null;
  history: number[]; // recent throughput totals, for sparklines
}

/** Fetches the stats summary for `window`, then keeps it fresh from live
 * `stats` websocket frames until the window changes. */
export function useStatsSummary(window: StatsWindow): UseStatsSummaryResult {
  const [data, setData] = useState<StatsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const historyRef = useRef<number[]>([]);
  const [, forceTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    historyRef.current = [];
    getStatsSummary(window)
      .then((res) => {
        if (cancelled) return;
        setData(res);
        historyRef.current = [res.throughput_bps_in + res.throughput_bps_out];
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [window]);

  useLiveFrames((frame) => {
    if (frame.type !== "stats") return;
    const summary = frame.data as StatsSummary;
    // Live pushes are always 5-minute summaries (the backend's operating
    // window). Merging one wholesale into a 1h/24h view would clobber those
    // totals with 5-minute numbers under the wider label, so the full frame
    // is adopted only when 5m is selected; for wider windows only the
    // instantaneous fields (current throughput, active flows) are taken,
    // since those don't depend on the aggregation window.
    if (window === "5m") {
      setData({ ...summary, window });
    } else {
      setData(
        (cur) =>
          cur && {
            ...cur,
            generated_at: summary.generated_at,
            throughput_bps_in: summary.throughput_bps_in,
            throughput_bps_out: summary.throughput_bps_out,
            active_flows: summary.active_flows,
          },
      );
    }
    historyRef.current = [...historyRef.current, summary.throughput_bps_in + summary.throughput_bps_out].slice(-20);
    forceTick((t) => t + 1);
  });

  return { data, loading, error, history: historyRef.current };
}

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
    // The backend's live push may reflect its own operating window; keep the
    // frontend's selected window label stable while taking the fresh numbers.
    setData({ ...summary, window });
    historyRef.current = [...historyRef.current, summary.throughput_bps_in + summary.throughput_bps_out].slice(-20);
    forceTick((t) => t + 1);
  });

  return { data, loading, error, history: historyRef.current };
}

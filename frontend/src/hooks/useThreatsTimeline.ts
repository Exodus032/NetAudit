import { useEffect, useState } from "react";
import { getThreatsTimeline } from "../api/client";
import type { StatsWindow, ThreatTimelinePoint } from "../api/types";

const WINDOW_BUCKET: Record<StatsWindow, number> = {
  "5m": 5,
  "15m": 15,
  "1h": 60,
  "24h": 3600,
  all: 3600,
};

export function useThreatsTimeline(window: StatsWindow) {
  const [points, setPoints] = useState<ThreatTimelinePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getThreatsTimeline(window, WINDOW_BUCKET[window])
      .then((res) => {
        if (!cancelled) setPoints(res.points);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [window]);

  return { points, loading, error };
}

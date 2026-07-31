import { useEffect, useState } from "react";
import { getStatsTimeseries } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { StatsSummary, StatsWindow, TimeseriesPoint } from "../api/types";

export const WINDOW_BUCKET: Record<StatsWindow, number> = {
  "5m": 5,
  "15m": 15,
  "1h": 60,
  "24h": 900,
  all: 3600,
};

interface UseTimeseriesResult {
  points: TimeseriesPoint[];
  loading: boolean;
  error: string | null;
}

/** Historical timeseries for the window, with a rolling live tail built from
 * `stats` websocket frames so the chart keeps moving between REST refetches. */
export function useTimeseries(window: StatsWindow): UseTimeseriesResult {
  const [points, setPoints] = useState<TimeseriesPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const bucket = WINDOW_BUCKET[window];

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getStatsTimeseries(window, bucket)
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
  }, [window, bucket]);

  useLiveFrames((frame) => {
    if (frame.type !== "stats") return;
    const s = frame.data as StatsSummary;
    setPoints((prev) => {
      if (prev.length === 0) return prev;
      const tickSeconds = 2; // stats frames arrive ~every 2s per contract
      const point: TimeseriesPoint = {
        t: s.generated_at,
        bytes_in: Math.round((s.throughput_bps_in / 8) * tickSeconds),
        bytes_out: Math.round((s.throughput_bps_out / 8) * tickSeconds),
        packets_in: 0,
        packets_out: 0,
        tcp: 0,
        udp: 0,
        icmp: 0,
        other: 0,
      };
      const next = [...prev.slice(1), point];
      return next;
    });
  });

  return { points, loading, error };
}

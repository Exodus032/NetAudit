import { useEffect, useState } from "react";
import { getStatsTop } from "../api/client";
import type { StatsWindow, TopBy, TopItem } from "../api/types";

export function useTopStats(by: TopBy, window: StatsWindow, limit = 8) {
  const [items, setItems] = useState<TopItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    const load = () =>
      getStatsTop(by, limit, window)
        .then((res) => {
          if (!cancelled) setItems(res.items);
        })
        .catch((err) => {
          if (!cancelled) setError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    load();
    const id = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [by, window, limit]);

  return { items, loading, error };
}

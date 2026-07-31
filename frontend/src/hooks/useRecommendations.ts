import { useCallback, useEffect, useRef, useState } from "react";
import { dismissRecommendation, getRecommendations, restoreRecommendation } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { Recommendation } from "../api/types";

const SEVERITY_ORDER: Recommendation["severity"][] = ["critical", "high", "medium", "low", "info"];

function sortRecs(list: Recommendation[]): Recommendation[] {
  return [...list].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence,
  );
}

export function useRecommendations(includeDismissed: boolean) {
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newlyArrivedIds, setNewlyArrivedIds] = useState<Set<string>>(new Set());
  const knownIds = useRef<Set<string>>(new Set());

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getRecommendations(includeDismissed)
      .then((res) => {
        setRecommendations(sortRecs(res.recommendations));
        knownIds.current = new Set(res.recommendations.map((r) => r.id));
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, [includeDismissed]);

  useEffect(() => {
    load();
  }, [load]);

  useLiveFrames((frame) => {
    if (frame.type !== "alert") return;
    const rec = frame.data as Recommendation;
    setRecommendations((prev) => {
      const exists = prev.some((r) => r.id === rec.id);
      const next = exists ? prev.map((r) => (r.id === rec.id ? rec : r)) : [...prev, rec];
      return sortRecs(next.filter((r) => includeDismissed || !r.dismissed));
    });
    if (!knownIds.current.has(rec.id)) {
      knownIds.current.add(rec.id);
      setNewlyArrivedIds((prev) => new Set(prev).add(rec.id));
      setTimeout(() => {
        setNewlyArrivedIds((prev) => {
          const next = new Set(prev);
          next.delete(rec.id);
          return next;
        });
      }, 6000);
    }
  });

  const dismiss = useCallback(
    async (id: string) => {
      const prev = recommendations;
      setRecommendations((cur) => (includeDismissed ? cur.map((r) => (r.id === id ? { ...r, dismissed: true } : r)) : cur.filter((r) => r.id !== id)));
      try {
        await dismissRecommendation(id);
      } catch (err) {
        setRecommendations(prev); // roll back
        throw err;
      }
    },
    [recommendations, includeDismissed],
  );

  const restore = useCallback(
    async (id: string) => {
      const prev = recommendations;
      setRecommendations((cur) => cur.map((r) => (r.id === id ? { ...r, dismissed: false } : r)));
      try {
        await restoreRecommendation(id);
      } catch (err) {
        setRecommendations(prev); // roll back
        throw err;
      }
    },
    [recommendations],
  );

  return { recommendations, loading, error, dismiss, restore, newlyArrivedIds, reload: load };
}

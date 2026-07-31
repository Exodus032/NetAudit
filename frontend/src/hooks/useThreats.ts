import { useCallback, useEffect, useState } from "react";
import { acknowledgeThreat, getThreats, unacknowledgeThreat } from "../api/client";
import type { Threat, ThreatsQuery } from "../api/types";

const SEVERITY_ORDER: Threat["severity"][] = ["critical", "high", "medium", "low", "info"];

function sortThreats(list: Threat[]): Threat[] {
  return [...list].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence,
  );
}

export function useThreats(query: ThreatsQuery) {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getThreats(query)
      .then((res) => {
        setThreats(sortThreats(res.threats));
        setTotal(res.total);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.severity, query.category, query.status, query.include_acknowledged, query.q]);

  useEffect(() => {
    load();
  }, [load]);

  const acknowledge = useCallback(
    async (id: string, note?: string) => {
      const prev = threats;
      setThreats((cur) =>
        query.include_acknowledged
          ? cur.map((t) => (t.id === id ? { ...t, status: "acknowledged", acknowledged_note: note } : t))
          : cur.filter((t) => t.id !== id),
      );
      try {
        await acknowledgeThreat(id, note);
      } catch (err) {
        setThreats(prev);
        throw err;
      }
    },
    [threats, query.include_acknowledged],
  );

  const unacknowledge = useCallback(
    async (id: string, note?: string) => {
      const prev = threats;
      setThreats((cur) => cur.map((t) => (t.id === id ? { ...t, status: "active", acknowledged_note: undefined } : t)));
      try {
        await unacknowledgeThreat(id, note);
      } catch (err) {
        setThreats(prev);
        throw err;
      }
    },
    [threats],
  );

  return { threats, total, loading, error, acknowledge, unacknowledge, reload: load };
}

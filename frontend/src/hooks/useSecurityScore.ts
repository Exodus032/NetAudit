import { useEffect, useState } from "react";
import { getSecurityScore } from "../api/client";
import type { SecurityScoreResponse } from "../api/types";

/** No websocket frame carries this — it's a computed composite, so we poll
 * gently rather than push. Every 30s is plenty for a score that only moves
 * when posture/threats/hygiene change. */
export function useSecurityScore() {
  const [data, setData] = useState<SecurityScoreResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      getSecurityScore()
        .then((res) => {
          if (cancelled) return;
          setData(res);
          // A later poll succeeding must clear a transient earlier failure,
          // or the tile stays hidden until reload.
          setError(null);
        })
        .catch((err) => {
          if (!cancelled) setError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    load();
    const id = setInterval(load, 30_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return { data, loading, error };
}

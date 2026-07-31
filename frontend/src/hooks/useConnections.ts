import { useEffect, useState } from "react";
import { getConnections } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { Connection } from "../api/types";

export function useConnections() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getConnections()
      .then((res) => {
        if (!cancelled) setConnections(res.connections);
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
  }, []);

  useLiveFrames((frame) => {
    if (frame.type !== "connections") return;
    setConnections(frame.data as Connection[]);
  });

  return { connections, loading, error };
}

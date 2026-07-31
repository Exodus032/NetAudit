import { useCallback, useEffect, useState } from "react";
import { getPosture, rescanPosture } from "../api/client";
import type { PostureQuery, PostureResponse } from "../api/types";

export function usePosture(query: PostureQuery) {
  const [data, setData] = useState<PostureResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getPosture(query)
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.category, query.include_pass]);

  useEffect(() => {
    load();
  }, [load]);

  const rescan = useCallback(async () => {
    setRescanning(true);
    try {
      const res = await rescanPosture();
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRescanning(false);
    }
  }, []);

  return { data, loading, error, rescanning, rescan, reload: load };
}

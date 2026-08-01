// Lazy, cached fetch of a single explanation for <ExplainChip>/<ExplainPopover>.
// Cached at module scope (keyed by "kind:id") because the same detector/rule/
// check/metric/field can be referenced by chips on several different views —
// no reason to refetch it every time a popover opens.
import { useCallback, useEffect, useRef, useState } from "react";
import { getExplanation } from "../api/clientLearn";
import type { ExplainKind, Explanation } from "../api/typesLearn";

const cache = new Map<string, Promise<Explanation | null>>();

function fetchCached(kind: ExplainKind, id: string): Promise<Explanation | null> {
  const key = `${kind}:${id}`;
  let p = cache.get(key);
  if (!p) {
    p = getExplanation(kind, id);
    cache.set(key, p);
    // Don't cache a failed fetch — let the next open retry.
    p.catch(() => cache.delete(key));
  }
  return p;
}

export function useExplain(kind: ExplainKind, id: string) {
  const [data, setData] = useState<Explanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fetchedKey = useRef<string | null>(null);

  const load = useCallback(() => {
    const key = `${kind}:${id}`;
    if (fetchedKey.current === key) return;
    fetchedKey.current = key;
    setLoading(true);
    setError(null);
    fetchCached(kind, id)
      .then(setData)
      .catch((err) => {
        fetchedKey.current = null;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => setLoading(false));
  }, [kind, id]);

  useEffect(() => {
    fetchedKey.current = null;
    setData(null);
    setError(null);
  }, [kind, id]);

  return { data, loading, error, load };
}

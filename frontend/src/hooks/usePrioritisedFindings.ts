import { useCallback, useEffect, useState } from "react";
import { getPrioritisedFindings } from "../api/clientLearn";
import type { PrioritisedFinding } from "../api/typesLearn";

export function usePrioritisedFindings() {
  const [items, setItems] = useState<PrioritisedFinding[]>([]);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getPrioritisedFindings()
      .then((res) => {
        setItems(res.items);
        setGeneratedAt(res.generated_at);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return { items, generatedAt, loading, error, reload: load };
}

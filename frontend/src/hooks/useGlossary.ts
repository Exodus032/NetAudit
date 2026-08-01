import { useCallback, useEffect, useState } from "react";
import { getGlossary } from "../api/clientLearn";
import type { GlossaryTerm } from "../api/typesLearn";

export function useGlossary() {
  const [terms, setTerms] = useState<GlossaryTerm[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getGlossary()
      .then((res) => setTerms(res.terms))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return { terms, loading, error, reload: load };
}

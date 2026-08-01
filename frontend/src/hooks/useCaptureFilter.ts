// E4: BPF-subset capture filter — get/validate/apply, with the parser's
// exact error position surfaced for the editor to highlight.

import { useCallback, useEffect, useState } from "react";
import { getCaptureFilter, updateCaptureFilter } from "../api/clientPro";
import { BpfFilterError } from "../api/typesPro";
import type { CaptureFilterState } from "../api/typesPro";

export function useCaptureFilter() {
  const [state, setState] = useState<CaptureFilterState | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<{ message: string; position: number } | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setLoadError(null);
    return getCaptureFilter()
      .then((res) => {
        setState(res);
        setDraft(res.expression);
      })
      .catch((err) => setLoadError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const apply = useCallback(async (expression: string) => {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await updateCaptureFilter(expression);
      setState(res);
      setDraft(res.expression);
      return res;
    } catch (err) {
      if (err instanceof BpfFilterError) {
        setSaveError({ message: err.message, position: err.position });
      } else {
        setSaveError({ message: err instanceof Error ? err.message : String(err), position: 0 });
      }
      throw err;
    } finally {
      setSaving(false);
    }
  }, []);

  const clear = useCallback(() => apply(""), [apply]);

  return { state, loading, loadError, draft, setDraft, saving, saveError, apply, clear, reload };
}

// E8: baseline snapshots — capture, list, and diff any two.

import { useCallback, useEffect, useState } from "react";
import { createBaseline, diffBaselines, getBaselineSchedule, listBaselines, updateBaselineSchedule } from "../api/clientPro";
import type { BaselineDiff, BaselineListItem, BaselineSchedule } from "../api/typesPro";

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useBaselines() {
  const [baselines, setBaselines] = useState<BaselineListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [captureError, setCaptureError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return listBaselines()
      .then((res) => setBaselines(res.baselines))
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const capture = useCallback(
    async (label: string) => {
      setCapturing(true);
      setCaptureError(null);
      try {
        const item = await createBaseline(label);
        setBaselines((cur) => [item, ...cur]);
        return item;
      } catch (err) {
        setCaptureError(errMessage(err));
        throw err;
      } finally {
        setCapturing(false);
      }
    },
    [],
  );

  return { baselines, loading, error, capturing, captureError, capture, reload };
}

export function useBaselineSchedule() {
  const [schedule, setSchedule] = useState<BaselineSchedule | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return getBaselineSchedule()
      .then(setSchedule)
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const save = useCallback(async (next: BaselineSchedule) => {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await updateBaselineSchedule(next);
      setSchedule(res);
      return res;
    } catch (err) {
      setSaveError(errMessage(err));
      throw err;
    } finally {
      setSaving(false);
    }
  }, []);

  return { schedule, loading, error, saving, saveError, save, reload };
}

export function useBaselineDiff() {
  const [diff, setDiff] = useState<BaselineDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async (a: string, b: string) => {
    setLoading(true);
    setError(null);
    setDiff(null);
    try {
      const res = await diffBaselines(a, b);
      setDiff(res);
      return res;
    } catch (err) {
      setError(errMessage(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { diff, loading, error, run };
}

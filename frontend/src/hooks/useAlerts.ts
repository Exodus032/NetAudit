// F3-F4: alert channel config, enable/disable, test-send, and delivery
// history.

import { useCallback, useEffect, useState } from "react";
import { getAlertsConfig, getAlertsHistory, testAlertChannel, updateAlertsConfig } from "../api/clientPro";
import { ApiError } from "../api/client";
import type { AlertHistoryItem, AlertsConfig, AlertTestResult } from "../api/typesPro";

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return err instanceof Error ? err.message : String(err);
}

export function useAlertsConfig() {
  const [config, setConfig] = useState<AlertsConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return getAlertsConfig()
      .then(setConfig)
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const save = useCallback(async (next: AlertsConfig) => {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await updateAlertsConfig(next);
      setConfig(res);
      return res;
    } catch (err) {
      setSaveError(errMessage(err));
      throw err;
    } finally {
      setSaving(false);
    }
  }, []);

  return { config, loading, error, saving, saveError, save, reload, setConfig };
}

export function useAlertTest() {
  const [pending, setPending] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AlertTestResult>>({});

  const test = useCallback(async (channelId: string) => {
    setPending(channelId);
    try {
      const res = await testAlertChannel(channelId);
      setResults((cur) => ({ ...cur, [channelId]: res }));
      return res;
    } finally {
      setPending((cur) => (cur === channelId ? null : cur));
    }
  }, []);

  return { pending, results, test };
}

export function useAlertsHistory() {
  const [history, setHistory] = useState<AlertHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return getAlertsHistory()
      .then((res) => setHistory(res.alerts))
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return { history, loading, error, reload };
}

// E6: SIEM/log-pipeline export — fetches the full formatted stream once,
// uses it for both the "first few records" preview and the download.

import { useCallback, useState } from "react";
import { downloadSiemExport, fetchSiemExport } from "../api/clientPro";
import type { SiemExportQuery, SiemExportResult } from "../api/typesPro";

const PREVIEW_LINES = 8;

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useSiemExport() {
  const [result, setResult] = useState<SiemExportResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async (query: SiemExportQuery) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchSiemExport(query);
      setResult(res);
      return res;
    } catch (err) {
      setError(errMessage(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const download = useCallback(() => {
    if (result) downloadSiemExport(result);
  }, [result]);

  const previewLines = result ? result.text.split("\n").filter(Boolean).slice(0, PREVIEW_LINES) : [];
  const totalLines = result ? result.text.split("\n").filter(Boolean).length : 0;

  return { result, previewLines, totalLines, loading, error, run, download };
}

// E1-E3: PCAP export (with a live count estimate), drag-and-drop import
// with progress, and the imported-sessions list.

import { useCallback, useEffect, useState } from "react";
import { deleteSession, estimatePcapExport, exportPcap, importPcap, listSessions } from "../api/clientPro";
import { ApiError } from "../api/client";
import type { CaptureSession, PcapExportQuery, PcapImportResponse } from "../api/typesPro";

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return err instanceof Error ? err.message : String(err);
}

export function usePcapSessions() {
  const [sessions, setSessions] = useState<CaptureSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return listSessions()
      .then((res) => setSessions(res.sessions))
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const remove = useCallback(
    async (id: string) => {
      await deleteSession(id);
      setSessions((cur) => cur.filter((s) => s.id !== id));
    },
    [],
  );

  return { sessions, loading, error, reload, remove };
}

export function usePcapExportEstimate(query: PcapExportQuery) {
  const [count, setCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    estimatePcapExport(query)
      .then((n) => {
        if (!cancelled) setCount(n);
      })
      .catch(() => {
        if (!cancelled) setCount(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.protocol, query.since, query.until, query.peer, query.port, query.limit]);

  return { count, loading };
}

export type ImportPhase = "idle" | "uploading" | "done" | "error";

export function usePcapImport(onImported?: (result: PcapImportResponse) => void) {
  const [phase, setPhase] = useState<ImportPhase>("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PcapImportResponse | null>(null);

  const upload = useCallback(
    async (file: File) => {
      setPhase("uploading");
      setProgress(0);
      setError(null);
      setResult(null);
      try {
        const res = await importPcap(file, setProgress);
        setResult(res);
        setPhase("done");
        onImported?.(res);
      } catch (err) {
        setError(errMessage(err));
        setPhase("error");
      }
    },
    [onImported],
  );

  const reset = useCallback(() => {
    setPhase("idle");
    setProgress(0);
    setError(null);
    setResult(null);
  }, []);

  return { phase, progress, error, result, upload, reset };
}

export { exportPcap };

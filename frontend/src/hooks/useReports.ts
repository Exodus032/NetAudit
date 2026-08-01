// E5: report generation, listing, viewing, and deletion.

import { useCallback, useEffect, useState } from "react";
import { createReport, deleteReport, getReport, listReports } from "../api/clientPro";
import type { ReportContent, ReportListItem, ReportRequest } from "../api/typesPro";

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useReports() {
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [active, setActive] = useState<ReportContent | null>(null);
  const [activeLoading, setActiveLoading] = useState(false);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return listReports()
      .then((res) => setReports(res.reports))
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const generate = useCallback(
    async (req: ReportRequest) => {
      setGenerating(true);
      setGenError(null);
      try {
        const content = await createReport(req);
        setActive(content);
        await reload();
        return content;
      } catch (err) {
        setGenError(errMessage(err));
        throw err;
      } finally {
        setGenerating(false);
      }
    },
    [reload],
  );

  const view = useCallback(async (id: string) => {
    setActiveLoading(true);
    try {
      const content = await getReport(id);
      setActive(content);
      return content;
    } finally {
      setActiveLoading(false);
    }
  }, []);

  const remove = useCallback(
    async (id: string) => {
      await deleteReport(id);
      setReports((cur) => cur.filter((r) => r.id !== id));
      setActive((cur) => (cur?.id === id ? null : cur));
    },
    [],
  );

  return { reports, loading, error, generating, genError, active, activeLoading, generate, view, remove, reload, setActive };
}

// F1-F2: compliance framework picker and per-control report.

import { useCallback, useEffect, useState } from "react";
import { getComplianceFrameworks, getComplianceReport } from "../api/clientPro";
import type { ComplianceFrameworkSummary, ComplianceReport } from "../api/typesPro";

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useComplianceFrameworks() {
  const [frameworks, setFrameworks] = useState<ComplianceFrameworkSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    getComplianceFrameworks()
      .then((res) => setFrameworks(res.frameworks))
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  return { frameworks, loading, error };
}

export function useComplianceReport(frameworkId: string | null) {
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    if (!frameworkId) {
      setReport(null);
      return;
    }
    setLoading(true);
    setError(null);
    getComplianceReport(frameworkId)
      .then(setReport)
      .catch((err) => setError(errMessage(err)))
      .finally(() => setLoading(false));
  }, [frameworkId]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { report, loading, error, reload };
}

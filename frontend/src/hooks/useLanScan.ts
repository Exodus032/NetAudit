// E7: active LAN scan — start, poll while running, cancel. One job at a
// time, matching the backend's own constraint.

import { useCallback, useEffect, useRef, useState } from "react";
import { cancelLanScan, getLanScan, startLanScan } from "../api/clientPro";
import { ApiError } from "../api/client";
import type { ScanJob, ScanRequest } from "../api/typesPro";

const POLL_MS = 900;

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return err instanceof Error ? err.message : String(err);
}

export function useLanScan() {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  const poll = useCallback(
    (jobId: string) => {
      stopPolling();
      pollRef.current = setInterval(() => {
        getLanScan(jobId)
          .then((res) => {
            setJob(res);
            if (res.status !== "running") stopPolling();
          })
          .catch(() => stopPolling());
      }, POLL_MS);
    },
    [stopPolling],
  );

  const start = useCallback(
    async (req: ScanRequest) => {
      setStarting(true);
      setError(null);
      try {
        const res = await startLanScan(req);
        setJob(res);
        if (res.status === "running") poll(res.job_id);
        return res;
      } catch (err) {
        setError(errMessage(err));
        throw err;
      } finally {
        setStarting(false);
      }
    },
    [poll],
  );

  const cancel = useCallback(async () => {
    if (!job) return;
    const res = await cancelLanScan(job.job_id);
    setJob(res);
    stopPolling();
  }, [job, stopPolling]);

  return { job, starting, error, start, cancel };
}

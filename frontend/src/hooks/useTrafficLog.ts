import { useCallback, useEffect, useRef, useState } from "react";
import { getTrafficLog } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { TrafficLogEntry, TrafficLogQuery } from "../api/types";

const PAGE_SIZE = 300;
const MAX_ROWS = 3000;

function matchesQuery(e: TrafficLogEntry, q: TrafficLogQuery): boolean {
  if (q.protocol && e.protocol !== q.protocol) return false;
  if (q.direction && e.direction !== q.direction) return false;
  if (typeof q.min_bytes === "number" && e.length < q.min_bytes) return false;
  if (q.since && e.ts < q.since) return false;
  if (q.until && e.ts > q.until) return false;
  if (q.q) {
    const needle = q.q.toLowerCase();
    const haystack = `${e.remote_host} ${e.process_name} ${e.dst_port} ${e.src_port} ${e.src_addr} ${e.dst_addr}`.toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  return true;
}

export function useTrafficLog(query: TrafficLogQuery, liveTailOn: boolean, paused: boolean) {
  const [entries, setEntries] = useState<TrafficLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const pendingRowsRef = useRef<TrafficLogEntry[]>([]);
  const queryRef = useRef(query);
  queryRef.current = query;

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    return getTrafficLog({ ...queryRef.current, limit: PAGE_SIZE, offset: 0, sort: query.sort ?? "time", order: query.order ?? "desc" })
      .then((res) => {
        setEntries(res.entries);
        setTotal(res.total);
        setPendingCount(0);
        pendingRowsRef.current = [];
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.protocol, query.direction, query.min_bytes, query.since, query.until, query.q, query.sort, query.order]);

  useEffect(() => {
    reload();
  }, [reload]);

  const flushPending = useCallback(() => {
    if (pendingRowsRef.current.length === 0) return;
    setEntries((prev) => [...pendingRowsRef.current, ...prev].slice(0, MAX_ROWS));
    setTotal((t) => t + pendingRowsRef.current.length);
    pendingRowsRef.current = [];
    setPendingCount(0);
  }, []);

  useLiveFrames((frame) => {
    if (frame.type !== "log" || !liveTailOn) return;
    const rows = (frame.data as TrafficLogEntry[]).filter((e) => matchesQuery(e, queryRef.current));
    if (rows.length === 0) return;
    if (paused) {
      pendingRowsRef.current = [...rows, ...pendingRowsRef.current];
      setPendingCount((c) => c + rows.length);
    } else {
      setEntries((prev) => [...rows, ...prev].slice(0, MAX_ROWS));
      setTotal((t) => t + rows.length);
    }
  });

  return { entries, total, loading, error, reload, pendingCount, flushPending };
}

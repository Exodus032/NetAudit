import { useEffect, useState } from "react";
import { getDevices } from "../api/client";
import type { Device } from "../api/types";

export function useDevices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getDevices()
      .then((res) => {
        if (!cancelled) setDevices(res.devices);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  useEffect(() => {
    const id = setInterval(() => setRefreshKey((k) => k + 1), 20_000);
    return () => clearInterval(id);
  }, []);

  return { devices, loading, error, refresh: () => setRefreshKey((k) => k + 1) };
}

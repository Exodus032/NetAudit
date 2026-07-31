import { useEffect, useState } from "react";
import { getHealth } from "../api/client";
import { useLiveFrames } from "../api/useLiveSocket";
import type { CaptureStatus } from "../api/types";

export function useCaptureStatus() {
  const [capture, setCapture] = useState<CaptureStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((res) => {
        if (!cancelled) setCapture(res.capture);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useLiveFrames((frame) => {
    if (frame.type !== "capture") return;
    setCapture(frame.data as CaptureStatus);
  });

  return { capture, loading };
}

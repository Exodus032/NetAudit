// Guided-tour state: fetches the 15 steps, tracks current step, remembers
// completion in localStorage, and auto-opens once on first run. <GuidedTour>
// is mounted once at app level with no props, so a restart request from
// elsewhere (the Learn view's "Take the tour again" button) has to travel
// through a window event rather than a prop/context — requestTourRestart()
// below is the public trigger for that.
import { useCallback, useEffect, useRef, useState } from "react";
import { getTour } from "../api/clientLearn";
import type { TourStep } from "../api/typesLearn";

const STORAGE_KEY = "netaudit.learn.tourCompleted";
const RESTART_EVENT = "netaudit:tour-restart";

export function isTourCompleted(): boolean {
  if (typeof window === "undefined") return true;
  return window.localStorage.getItem(STORAGE_KEY) === "1";
}

function markCompleted() {
  window.localStorage.setItem(STORAGE_KEY, "1");
}

/** Call from anywhere (e.g. the Learn view) to reopen the tour from step 1,
 * regardless of prior completion. */
export function requestTourRestart() {
  window.dispatchEvent(new Event(RESTART_EVENT));
}

export function useTour() {
  const [steps, setSteps] = useState<TourStep[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
  const autoStarted = useRef(false);

  useEffect(() => {
    getTour()
      .then((res) => setSteps(res.steps))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  // Auto-open exactly once, the first time steps are available, if the
  // student has never finished (or skipped) the tour before.
  useEffect(() => {
    if (loading || steps.length === 0 || autoStarted.current) return;
    autoStarted.current = true;
    if (!isTourCompleted()) {
      setIndex(0);
      setOpen(true);
    }
  }, [loading, steps.length]);

  useEffect(() => {
    const onRestart = () => {
      setIndex(0);
      setOpen(true);
    };
    window.addEventListener(RESTART_EVENT, onRestart);
    return () => window.removeEventListener(RESTART_EVENT, onRestart);
  }, []);

  const close = useCallback(() => setOpen(false), []);

  const finish = useCallback(() => {
    markCompleted();
    setOpen(false);
  }, []);

  const next = useCallback(() => {
    setIndex((i) => {
      if (i + 1 >= steps.length) {
        markCompleted();
        setOpen(false);
        return i;
      }
      return i + 1;
    });
  }, [steps.length]);

  const back = useCallback(() => setIndex((i) => Math.max(0, i - 1)), []);

  const skip = useCallback(() => {
    markCompleted();
    setOpen(false);
  }, []);

  return {
    steps,
    loading,
    error,
    open,
    index,
    step: steps[index] ?? null,
    total: steps.length,
    next,
    back,
    skip,
    close,
    finish,
  };
}

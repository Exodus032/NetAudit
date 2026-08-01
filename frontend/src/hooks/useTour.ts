// Guided-tour state: each monitor view has its own short tour. A segment
// opens the first time its view is visited, rather than moving the visitor
// through every screen in one long, auto-navigating sequence.
import { useCallback, useEffect, useState } from "react";
import { getTour } from "../api/clientLearn";
import type { TourStep } from "../api/typesLearn";

const STORAGE_KEY = "netaudit.learn.tourCompleted";
const COMPLETED_VIEWS_KEY = "netaudit.learn.tourCompletedViews";
const RESTART_EVENT = "netaudit:tour-restart";
const TOUR_VIEWS = ["overview", "traffic-log", "connections", "recommendations", "posture", "threats"] as const;

type TourView = (typeof TOUR_VIEWS)[number];

function completedViews(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const stored = JSON.parse(window.localStorage.getItem(COMPLETED_VIEWS_KEY) ?? "[]");
    return new Set(Array.isArray(stored) ? stored.filter((view): view is string => typeof view === "string") : []);
  } catch {
    return new Set();
  }
}

function isTourView(view: string | undefined): view is TourView {
  return !!view && TOUR_VIEWS.includes(view as TourView);
}

export function isTourCompleted(): boolean {
  if (typeof window === "undefined") return true;
  return window.localStorage.getItem(STORAGE_KEY) === "1" || TOUR_VIEWS.every((view) => completedViews().has(view));
}

function markAllCompleted() {
  window.localStorage.setItem(STORAGE_KEY, "1");
}

function markViewCompleted(view: TourView) {
  const completed = completedViews();
  completed.add(view);
  window.localStorage.setItem(COMPLETED_VIEWS_KEY, JSON.stringify([...completed]));
  if (TOUR_VIEWS.every((tourView) => completed.has(tourView))) markAllCompleted();
}

function resetProgress() {
  window.localStorage.removeItem(STORAGE_KEY);
  window.localStorage.removeItem(COMPLETED_VIEWS_KEY);
}

/** Call from anywhere (e.g. the Learn view) to reopen the tour from step 1,
 * regardless of prior completion. */
export function requestTourRestart() {
  window.dispatchEvent(new Event(RESTART_EVENT));
}

export function useTour(currentView?: string) {
  const [steps, setSteps] = useState<TourStep[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
  const [restartVersion, setRestartVersion] = useState(0);
  const pageSteps = isTourView(currentView) ? steps.filter((step) => step.view === currentView) : [];

  useEffect(() => {
    getTour()
      .then((res) => setSteps(res.steps))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  // A page's segment opens when the visitor reaches that page for the first
  // time. Moving between segments is deliberately left to sidebar navigation.
  useEffect(() => {
    if (loading || pageSteps.length === 0 || !isTourView(currentView)) {
      setOpen(false);
      return;
    }
    if (!isTourCompleted() && !completedViews().has(currentView)) {
      setIndex(0);
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, [loading, currentView, pageSteps.length, restartVersion]);

  useEffect(() => {
    const onRestart = () => {
      resetProgress();
      setIndex(0);
      setRestartVersion((version) => version + 1);
    };
    window.addEventListener(RESTART_EVENT, onRestart);
    return () => window.removeEventListener(RESTART_EVENT, onRestart);
  }, []);

  const close = useCallback(() => setOpen(false), []);

  const finish = useCallback(() => {
    if (isTourView(currentView)) markViewCompleted(currentView);
    setOpen(false);
  }, [currentView]);

  const next = useCallback(() => {
    setIndex((i) => {
      if (i + 1 >= pageSteps.length) {
        if (isTourView(currentView)) markViewCompleted(currentView);
        setOpen(false);
        return i;
      }
      return i + 1;
    });
  }, [currentView, pageSteps.length]);

  const back = useCallback(() => setIndex((i) => Math.max(0, i - 1)), []);

  const skip = useCallback(() => {
    markAllCompleted();
    setOpen(false);
  }, []);

  return {
    steps,
    loading,
    error,
    open,
    index,
    step: pageSteps[index] ?? null,
    total: pageSteps.length,
    next,
    back,
    skip,
    close,
    finish,
  };
}

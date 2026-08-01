// Lessons list plus per-lesson progress, persisted in localStorage — the
// backend explicitly keeps no server-side progress state (docs/API_CONTRACT_V3.md
// D5: "The frontend tracks completion locally"). Step completion is a
// self-reported checkbox rather than automatic instrumentation of
// view_visited/filter_applied/element_clicked: reliably detecting those
// across views this package doesn't own (Overview, TrafficLog, ...) would
// need hooks wired in App.tsx/those views, which are out of scope here (see
// file-ownership note in the final report). A student ticking "done" after
// following the instruction is an honest, simple stand-in.
import { useCallback, useEffect, useState } from "react";
import { getLessons } from "../api/clientLearn";
import type { Lesson } from "../api/typesLearn";

export interface LessonProgress {
  completedSteps: number[];
  completedAt?: string;
}

type ProgressMap = Record<string, LessonProgress>;

const STORAGE_KEY = "netaudit.learn.lessonProgress";
const CHANGE_EVENT = "netaudit:lesson-progress-change";

function readAll(): ProgressMap {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as ProgressMap) : {};
  } catch {
    return {};
  }
}

function writeAll(map: ProgressMap) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

export function useLessons() {
  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressMap>(readAll);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    return getLessons()
      .then((res) => setLessons(res.lessons))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const onChange = () => setProgress(readAll());
    window.addEventListener(CHANGE_EVENT, onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener(CHANGE_EVENT, onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  const toggleStep = useCallback((lessonId: string, stepOrder: number, totalSteps: number) => {
    const all = readAll();
    const cur = all[lessonId] ?? { completedSteps: [] };
    const has = cur.completedSteps.includes(stepOrder);
    const completedSteps = has ? cur.completedSteps.filter((o) => o !== stepOrder) : [...cur.completedSteps, stepOrder].sort((a, b) => a - b);
    const completedAt = completedSteps.length >= totalSteps ? new Date().toISOString() : undefined;
    all[lessonId] = { completedSteps, completedAt };
    writeAll(all);
    setProgress(all);
  }, []);

  const resetLesson = useCallback((lessonId: string) => {
    const all = readAll();
    delete all[lessonId];
    writeAll(all);
    setProgress(all);
  }, []);

  const progressFor = useCallback((lessonId: string): LessonProgress => progress[lessonId] ?? { completedSteps: [] }, [progress]);

  return { lessons, loading, error, progressFor, toggleStep, resetLesson, reload: load };
}

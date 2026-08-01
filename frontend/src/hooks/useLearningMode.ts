// Learning-mode toggle, backed by localStorage, default ON. Any component
// calling this hook stays in sync with any other (same tab, via a window
// event; other tabs, via the native "storage" event) without needing a
// React context — the toggle lives in the Learn view, but ExplainChip
// instances are sprinkled across every other view in the app.
import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "netaudit.learn.learningMode";
const CHANGE_EVENT = "netaudit:learning-mode-change";

function readStored(): boolean {
  if (typeof window === "undefined") return true;
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (raw === null) return true; // default ON
  return raw === "1";
}

function writeStored(enabled: boolean) {
  window.localStorage.setItem(STORAGE_KEY, enabled ? "1" : "0");
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

/** Read-only check outside a component (e.g. before deciding to fetch). */
export function isLearningModeEnabled(): boolean {
  return readStored();
}

export function useLearningMode(): { enabled: boolean; setEnabled: (v: boolean) => void; toggle: () => void } {
  const [enabled, setEnabledState] = useState<boolean>(readStored);

  useEffect(() => {
    const onChange = () => setEnabledState(readStored());
    window.addEventListener(CHANGE_EVENT, onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener(CHANGE_EVENT, onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  const setEnabled = useCallback((v: boolean) => {
    writeStored(v);
    setEnabledState(v);
  }, []);

  const toggle = useCallback(() => setEnabled(!readStored()), [setEnabled]);

  return { enabled, setEnabled, toggle };
}

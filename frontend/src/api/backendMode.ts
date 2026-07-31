// Tiny external store tracking whether we're talking to the real backend or
// mock data, and why. Consumed via useSyncExternalStore in components that
// need to show a "backend unreachable" banner.

export type BackendMode = "real" | "forced-mock" | "fallback-mock" | "unknown";

let mode: BackendMode = "unknown";
const listeners = new Set<() => void>();

export function getBackendMode(): BackendMode {
  return mode;
}

export function setBackendMode(next: BackendMode): void {
  if (mode === next) return;
  mode = next;
  for (const l of listeners) l();
}

export function subscribeBackendMode(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

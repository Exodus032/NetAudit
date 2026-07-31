// Local auth token flow per docs/API_CONTRACT_V2_SECURITY.md Part C item 2.
// The backend requires a per-run token (X-NetAudit-Token header, or ?token=
// on the websocket) obtained from GET /api/bootstrap. The token lives in
// memory only — never localStorage/sessionStorage — and is re-fetched once
// on a 401. Skipped entirely in forced mock mode, since mocks never make a
// real network call and there is no backend to authenticate against.

const FORCE_MOCKS = import.meta.env.VITE_USE_MOCKS === "1";

interface BootstrapResponse {
  token: string;
  version: string;
  capture_mode: string;
}

/** Thrown for both network failures and non-OK responses from /api/bootstrap
 * so callers can treat "couldn't get a token" the same as "backend unreachable"
 * and fall back to mocks either way. */
export class BootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BootstrapError";
  }
}

let cachedToken: string | null = null;
let inFlight: Promise<string> | null = null;

async function fetchBootstrap(): Promise<string> {
  let res: Response;
  try {
    res = await fetch("/api/bootstrap");
  } catch (err) {
    throw new BootstrapError(err instanceof Error ? err.message : "bootstrap request failed");
  }
  if (!res.ok) {
    throw new BootstrapError(`bootstrap failed with HTTP ${res.status}`);
  }
  let data: BootstrapResponse;
  try {
    data = await res.json();
  } catch {
    throw new BootstrapError("bootstrap response was not valid JSON");
  }
  if (!data.token) {
    throw new BootstrapError("bootstrap response had no token");
  }
  cachedToken = data.token;
  return cachedToken;
}

/** Resolves the current token, bootstrapping (once, deduped across
 * concurrent callers) if we don't have one yet. No-op in forced mock mode. */
export async function ensureToken(): Promise<string> {
  if (FORCE_MOCKS) return "";
  if (cachedToken) return cachedToken;
  if (!inFlight) {
    inFlight = fetchBootstrap().finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}

/** Drops the cached token so the next ensureToken() call re-bootstraps.
 * Called after a 401 (REST) or an unexpected close (websocket). */
export function invalidateToken(): void {
  cachedToken = null;
}

export function getCachedToken(): string | null {
  return cachedToken;
}

export function isMockForced(): boolean {
  return FORCE_MOCKS;
}

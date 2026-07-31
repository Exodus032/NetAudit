# NetAudit — frontend

React + TypeScript + Vite dashboard for the NetAudit local network auditor. Talks
to the backend described in `../docs/API_CONTRACT.md` (frozen v1) and
`../docs/API_CONTRACT_V2_SECURITY.md` (frozen v2 security extensions), or runs
entirely standalone against a built-in mock backend.

## Setup

```powershell
npm install
npm run dev          # http://localhost:5173, proxies /api and /ws to 127.0.0.1:8787
```

```powershell
npx tsc --noEmit      # type-check (project references: use -p tsconfig.app.json
                       # if you want to check src/ directly rather than via `tsc -b`)
npm run build          # production build to dist/
npm run preview        # serve the production build locally
```

The backend serves `dist/` directly if present, so all asset paths are relative
(`base: "./"` in `vite.config.ts`) and there's nothing else to configure for a
combined deploy.

## Mock mode

Set `VITE_USE_MOCKS=1` to force the entire app onto an in-memory mock backend —
no real backend required:

```powershell
$env:VITE_USE_MOCKS=1; npm run dev
```

Even without that flag, the app **automatically falls back to mocks** if the
real backend is unreachable (connection refused, or the auth bootstrap call
fails — see below), and a "Mock data" pill appears in the header whenever mocks
are active, whether forced or auto-detected. This is the primary way to demo
and develop the UI without a running backend.

The mock layer lives under `src/mocks/`:

- `fixtures.ts` — pools of realistic IPs, process names, remote hosts, ports.
- `rng.ts` — a small seeded PRNG (mulberry32) so generated data is reproducible.
- `store.ts` — an in-memory, self-ticking store: traffic log, connections,
  devices, and recommendations, updated on a 1-2s cadence to feel live.
- `server.ts` — REST-shaped handlers over the store, matching the contract's
  response bodies exactly (pagination, filters, sort, top-N aggregation, CSV
  export rows, etc).

Mock data includes hundreds of traffic-log rows, ~30 live connections, a LAN
device list, and ten recommendations spanning every severity from `critical`
to `info`.

## How it talks to the backend

- **REST** — `src/api/client.ts` exports one typed function per endpoint in
  the contract, using a shared `fetch` wrapper. All types in `src/api/types.ts`
  are hand-written directly from `API_CONTRACT.md` — field names and enum
  values must match exactly, since the contract is frozen.
- **WebSocket** — `src/api/liveSocket.ts` is a singleton connection manager for
  `/ws/live` with exponential backoff reconnect (capped at 30s, jittered), a
  connection-state indicator in the header (`connecting` / `open` /
  `reconnecting` / `closed`), and tolerance for unknown frame types, missing
  frame types, or any arrival order. `src/api/useLiveSocket.ts` wraps it for
  React (`useConnectionState()`, `useLiveFrames(handler)`). After a few failed
  real-socket attempts it swaps to the mock ticker automatically, same as the
  REST fallback.
- **Auth token (v2 security contract)** — per `API_CONTRACT_V2_SECURITY.md`
  Part C item 2, every real `/api` and `/ws` call must carry a local bootstrap
  token. `src/api/auth.ts` fetches it once from `GET /api/bootstrap`, holds it
  **in memory only** (never localStorage — it's per-run and shouldn't survive
  a reload), attaches it as `X-NetAudit-Token` on REST calls and `?token=` on
  the websocket URL, and retries a request exactly once through a fresh
  bootstrap on a 401. This whole flow is **skipped entirely in forced mock
  mode** (`VITE_USE_MOCKS=1`), since mocks never make a real network call.
- Both paths independently detect an unreachable backend and fall back to
  mocks, each surfacing that state as `fallback-mock` vs `forced-mock` vs
  `real` via `src/api/backendMode.ts`.

## View structure

Single-page app, left nav + header, four views (`src/views/`):

1. **Overview** — stat tiles (traffic, throughput, flows, hosts, alerts) with
   sparklines; a live in/out throughput area chart with a 5m/15m/1h/24h window
   selector, fed by REST on window change and by `stats` websocket frames in
   between; protocol and encrypted-vs-plaintext breakdowns as segmented bars;
   top-talkers panel (host/process/port/protocol toggle); a capture-degraded
   banner when `capture.mode !== "npcap"` or `elevated` is false.
2. **Traffic log** — the workhorse view. A virtualized table
   (`@tanstack/react-virtual`) over `/api/traffic/log`, sortable by time/bytes,
   with a debounced filter bar (free text, protocol, direction, min bytes,
   time range), a live-tail toggle that prepends `log` websocket frames and
   auto-pauses on scroll-up (with a "N new rows" banner to resume), a detail
   drawer per row, and CSV/JSON export of the current filtered view.
3. **Connections & devices** — live connections grouped by process (state,
   peer, bytes in/out, risk with reasons on hover), and a LAN device table
   (IP/MAC/vendor/hostname/open ports/last seen/gateway & self badges).
4. **Recommended actions** — severity-sorted cards with category chip,
   confidence, evidence table, and per-`kind` actions: `manual` instructions,
   `link` (opens externally), `command` (copy-only code block with a visible
   "requires administrator" warning when applicable — **the UI never offers
   to run a command**). Dismiss/restore with optimistic UI and rollback on
   error, an "include dismissed" toggle, and a brief highlight on recommendations
   that arrive via the `alert` websocket frame.

## Design system

Dark-first (light theme toggle persists to `localStorage`), design tokens in
`src/index.css`, categorical/status colors from the project's dataviz palette
(fixed 8-hue categorical order, reserved status scale for severity/risk —
never reused for plain series identity). Recharts for the throughput area
chart; everything else (segmented bars, share bars, sparklines) is small
hand-built SVG/CSS to stay both consistent with the palette and lightweight.
Addresses, ports, and byte/time columns are monospaced; tables scroll inside
their own container rather than the page.

## Verified

- `npm install`, `npx tsc -p tsconfig.app.json --noEmit`, and `npm run build`
  all pass cleanly.
- All four views were exercised in a real browser (mock mode) via Playwright:
  charts render and update live, the traffic log virtualizes and live-tails,
  row click opens the detail drawer, dismiss/restore works with optimistic
  removal, and the console stayed error-free throughout. Screenshots are in
  `docs/screenshots/`.

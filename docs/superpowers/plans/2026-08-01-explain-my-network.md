# Explain My Network Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a restartable, beginner-focused Explain my network page that orients users to NetAudit and links them to the existing dashboard views.

**Architecture:** Keep the feature in the existing Learn view package. A lazily loaded `ExplainNetworkView` renders static, accurate explanatory chapters and navigates through the existing `onNavigate` callback. The app registry exposes the view, while a header button provides the only entry point. No backend request, storage, capture, or detector change is needed.

**Tech Stack:** React 18, TypeScript, Vite, CSS, Vitest, React Testing Library.

---

## File structure

| File | Responsibility |
| --- | --- |
| `frontend/src/views/Learn/ExplainNetworkView.tsx` | Semantic beginner explanation and direct actions into existing views. |
| `frontend/src/views/Learn/ExplainNetworkView.css` | Four-card layout, action styles, and narrow viewport collapse. |
| `frontend/src/views/Learn/index.tsx` | Lazy-load and register the new internal Learn view. |
| `frontend/src/App.tsx` | Route the header action to the new view. |
| `frontend/src/components/layout/Header.tsx` | Render the labeled header entry action. |
| `frontend/src/components/layout/Header.css` | Style the header entry action and preserve usable narrow-header wrapping. |
| `frontend/src/components/layout/Sidebar.tsx` | Supply the view title for the hidden header-only view. |
| `frontend/src/test/setup.ts` | Register DOM matchers and cleanup after every test. |
| `frontend/src/views/Learn/ExplainNetworkView.test.tsx` | Verify scope language and navigation actions. |
| `frontend/src/components/layout/Header.test.tsx` | Verify the header action invokes its callback. |
| `frontend/vite.config.ts` | Configure the jsdom test environment and setup file. |
| `frontend/package.json` and `frontend/package-lock.json` | Add the test script and test-only dependencies. |

### Task 1: Add frontend component test support

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`
- Modify: `frontend/vite.config.ts`
- Create: `frontend/src/test/setup.ts`

- [ ] **Step 1: Add the smallest test runtime configuration**

Run:

```bash
cd frontend
npm install --save-dev vitest jsdom @testing-library/react @testing-library/jest-dom
```

Update `package.json` scripts to include:

```json
"test": "vitest run"
```

Extend `vite.config.ts` with test configuration while retaining the existing plugin, base, dev-server proxy, and build configuration:

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8787", changeOrigin: true },
      "/ws": { target: "http://127.0.0.1:8787", ws: true, changeOrigin: true },
    },
  },
  build: { outDir: "dist" },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: true,
  },
});
```

Create `frontend/src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(cleanup);
```

- [ ] **Step 2: Verify the test runner is configured**

Run: `cd frontend && npm test`

Expected: Vitest starts successfully, then exits with its "No test files found" error because the feature tests have not been created yet.

- [ ] **Step 3: Commit the test infrastructure**

```bash
git add frontend/package.json frontend/package-lock.json frontend/vite.config.ts frontend/src/test/setup.ts
git commit -m "test: add frontend component test support"
```

### Task 2: Create the Explain my network view

**Files:**
- Create: `frontend/src/views/Learn/ExplainNetworkView.tsx`
- Create: `frontend/src/views/Learn/ExplainNetworkView.css`
- Modify: `frontend/src/views/Learn/index.tsx`
- Create: `frontend/src/views/Learn/ExplainNetworkView.test.tsx`

- [ ] **Step 1: Write the failing navigation and scope tests**

Create `frontend/src/views/Learn/ExplainNetworkView.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ExplainNetworkView } from "./ExplainNetworkView";

describe("ExplainNetworkView", () => {
  it("explains capture limits without claiming a safe network", () => {
    render(<ExplainNetworkView onNavigate={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "What is my network doing?" })).toBeInTheDocument();
    expect(screen.getByText(/cannot prove that nothing is wrong/i)).toBeInTheDocument();
    expect(screen.getByText(/never changes your system/i)).toBeInTheDocument();
  });

  it("navigates every chapter action to its existing dashboard view", () => {
    const onNavigate = vi.fn();
    render(<ExplainNetworkView onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole("button", { name: "Open overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Open traffic log" }));
    fireEvent.click(screen.getByRole("button", { name: "Open connections and devices" }));
    fireEvent.click(screen.getByRole("button", { name: "Open recommended actions" }));
    fireEvent.click(screen.getByRole("button", { name: "Open security posture" }));
    fireEvent.click(screen.getByRole("button", { name: "Open threats" }));
    fireEvent.click(screen.getByRole("button", { name: "Review a suggested fix" }));

    expect(onNavigate.mock.calls).toEqual([
      ["overview"],
      ["traffic"],
      ["connections"],
      ["recommendations"],
      ["posture"],
      ["threats"],
      ["recommendations"],
    ]);
  });
});
```

- [ ] **Step 2: Run the view test and verify it fails**

Run: `cd frontend && npm test -- ExplainNetworkView`

Expected: FAIL with a module-resolution error because `ExplainNetworkView.tsx` does not exist.

- [ ] **Step 3: Implement the minimal static explanation view**

Create `frontend/src/views/Learn/ExplainNetworkView.tsx`:

```tsx
import "./ExplainNetworkView.css";

type ExplainNetworkViewProps = {
  onNavigate?: (view: string) => void;
};

type Chapter = {
  number: string;
  title: string;
  detail: string;
  actions: { label: string; view: string }[];
};

const CHAPTERS: Chapter[] = [
  {
    number: "1. Right now",
    title: "See the big picture",
    detail: "Start with the overview. It brings together traffic, active connections, your capture tier, and a security score. The score is a starting point, not a verdict.",
    actions: [{ label: "Open overview", view: "overview" }],
  },
  {
    number: "2. Who is talking",
    title: "Understand activity",
    detail: "Connections and traffic tell you which devices, applications, and remote hosts this computer is communicating with. A connection is one conversation between two endpoints.",
    actions: [
      { label: "Open traffic log", view: "traffic" },
      { label: "Open connections and devices", view: "connections" },
    ],
  },
  {
    number: "3. What needs attention",
    title: "Review security findings",
    detail: "Recommendations, posture checks, and threats all explain their evidence. Treat a finding as a reason to look closer, not proof that something is malicious or misconfigured.",
    actions: [
      { label: "Open recommended actions", view: "recommendations" },
      { label: "Open security posture", view: "posture" },
      { label: "Open threats", view: "threats" },
    ],
  },
  {
    number: "4. What next",
    title: "Choose a safe action",
    detail: "NetAudit never changes your system. It shows the evidence and suggested commands, then you decide whether to review and run a fix yourself.",
    actions: [{ label: "Review a suggested fix", view: "recommendations" }],
  },
];

export function ExplainNetworkView({ onNavigate }: ExplainNetworkViewProps) {
  return (
    <div className="explain-network">
      <section className="explain-network-intro" aria-labelledby="explain-network-heading">
        <p className="explain-network-eyebrow">Start here</p>
        <h2 id="explain-network-heading">What is my network doing?</h2>
        <p>
          NetAudit observes connections this computer makes and checks its security setup. It shows facts first, then helps you decide what needs attention.
        </p>
        <p className="explain-network-limit">
          What NetAudit can observe depends on the active capture tier. A missing finding cannot prove that nothing is wrong, so check the overview's capture-tier banner before drawing conclusions.
        </p>
      </section>

      <section className="explain-network-chapters" aria-label="How to understand your network">
        {CHAPTERS.map((chapter) => (
          <article className="explain-network-card" key={chapter.title}>
            <p className="explain-network-card-number">{chapter.number}</p>
            <h3>{chapter.title}</h3>
            <p>{chapter.detail}</p>
            <div className="explain-network-card-actions">
              {chapter.actions.map((action) => (
                <button key={action.label} type="button" onClick={() => onNavigate?.(action.view)}>
                  {action.label}
                </button>
              ))}
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
```

Create `frontend/src/views/Learn/ExplainNetworkView.css`:

```css
.explain-network { max-width: 960px; margin: 0 auto; }
.explain-network-intro { max-width: 720px; margin-bottom: 28px; }
.explain-network-eyebrow, .explain-network-card-number { color: var(--text-muted); font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.explain-network-intro h2 { margin: 4px 0 10px; font-size: 28px; }
.explain-network-intro > p { color: var(--text-secondary); max-width: 66ch; }
.explain-network-limit { margin-top: 14px; padding-left: 12px; border-left: 3px solid var(--series-4); }
.explain-network-chapters { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.explain-network-card { display: flex; flex-direction: column; min-height: 220px; padding: 20px; border: 1px solid var(--border); border-radius: var(--radius-lg); background: var(--surface-1); }
.explain-network-card h3 { margin: 6px 0 8px; font-size: 18px; }
.explain-network-card > p:not(.explain-network-card-number) { color: var(--text-secondary); }
.explain-network-card-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: auto; padding-top: 18px; }
.explain-network-card-actions button { border: 1px solid var(--border); border-radius: var(--radius-md); padding: 7px 10px; background: var(--surface-2); color: var(--text-primary); cursor: pointer; }
.explain-network-card-actions button:hover { border-color: var(--series-1); background: color-mix(in srgb, var(--series-1) 15%, var(--surface-2)); }
@media (max-width: 680px) { .explain-network-chapters { grid-template-columns: 1fr; } .explain-network-intro h2 { font-size: 24px; } }
```

- [ ] **Step 4: Register the lazy view without adding a sidebar item**

In `frontend/src/views/Learn/index.tsx`, add the lazy import beside the other Learn view imports:

```ts
const ExplainNetworkView = lazy(() => import("./ExplainNetworkView").then((m) => ({ default: m.ExplainNetworkView })));
```

Add this registry entry:

```ts
"learn-explain-network": withSuspense(ExplainNetworkView),
```

Do not add it to `LEARN_NAV_ITEMS`. The header action is the feature's intentional entry point.

- [ ] **Step 5: Run the view test and verify it passes**

Run: `cd frontend && npm test -- ExplainNetworkView`

Expected: PASS. The test proves the capture-limit language and every destination passed to `onNavigate`.

- [ ] **Step 6: Commit the view**

```bash
git add frontend/src/views/Learn/ExplainNetworkView.tsx frontend/src/views/Learn/ExplainNetworkView.css frontend/src/views/Learn/ExplainNetworkView.test.tsx frontend/src/views/Learn/index.tsx
git commit -m "feat: add explain my network view"
```

### Task 3: Add the header entry point and application route

**Files:**
- Modify: `frontend/src/components/layout/Header.tsx`
- Modify: `frontend/src/components/layout/Header.css`
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`
- Create: `frontend/src/components/layout/Header.test.tsx`

- [ ] **Step 1: Write the failing header-action test**

Create `frontend/src/components/layout/Header.test.tsx`:

```tsx
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Header } from "./Header";

describe("Header", () => {
  it("opens Explain my network through its callback", () => {
    const onExplainNetwork = vi.fn();
    render(
      <Header
        viewId="overview"
        connectionState="open"
        theme="dark"
        onToggleTheme={vi.fn()}
        learningMode={false}
        onToggleLearningMode={vi.fn()}
        onExplainNetwork={onExplainNetwork}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Explain my network" }));
    expect(onExplainNetwork).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 2: Run the header test and verify it fails**

Run: `cd frontend && npm test -- Header`

Expected: FAIL because `Header` has no `onExplainNetwork` prop and no matching button.

- [ ] **Step 3: Implement the route and header action**

Add `onExplainNetwork: () => void` to `Header`'s destructured arguments and prop type. Render this button before the existing Learn toggle:

```tsx
<button
  type="button"
  className="explain-network-toggle"
  onClick={onExplainNetwork}
  title="Understand what NetAudit can see and where to start"
>
  Explain my network
</button>
```

Add styles to `frontend/src/components/layout/Header.css`:

```css
.explain-network-toggle {
  height: 30px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface-1);
  color: var(--text-primary);
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
}
.explain-network-toggle:hover { background: var(--surface-2); }
@media (max-width: 720px) {
  .app-header { align-items: flex-start; gap: 10px; }
  .app-header-actions { justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
  .conn-indicator { display: none; }
}
```

In `frontend/src/App.tsx`, pass the route callback:

```tsx
onExplainNetwork={() => setView("learn-explain-network")}
```

In `frontend/src/components/layout/Sidebar.tsx`, include the header-only view title after creating the navigation-derived map:

```ts
export const VIEW_TITLES: Record<string, string> = {
  ...Object.fromEntries(ALL_NAV_ITEMS.map((item) => [item.id, item.label])),
  "learn-explain-network": "Explain my network",
};
```

- [ ] **Step 4: Run the focused tests and frontend build**

Run:

```bash
cd frontend
npm test -- ExplainNetworkView Header
npm run build
```

Expected: all tests PASS and TypeScript plus Vite build complete successfully.

- [ ] **Step 5: Commit the entry point**

```bash
git add frontend/src/App.tsx frontend/src/components/layout/Header.tsx frontend/src/components/layout/Header.css frontend/src/components/layout/Header.test.tsx frontend/src/components/layout/Sidebar.tsx
git commit -m "feat: add explain my network entry point"
```

### Task 4: Verify the full user flow and responsive layout

**Files:**
- Modify only if verification identifies a defect in the files from Tasks 2 or 3.

- [ ] **Step 1: Start the application with the existing launcher**

Run from the repository root:

```powershell
.\start.ps1
```

Expected: backend dashboard is available on `http://127.0.0.1:8787`.

- [ ] **Step 2: Smoke-test the desktop user flow in a browser**

At a desktop viewport, select `Explain my network` in the header. Verify the page title, scope paragraph, capture-tier warning, four chapters, and all seven destination buttons. Select each destination and confirm it opens the correct existing view. Select the header action again and confirm the page begins at its top.

- [ ] **Step 3: Inspect the narrow responsive layout in a browser**

At a 390px-wide viewport, verify the header actions wrap without horizontal scrolling, connection status is hidden, cards are one column, all action labels are visible, and keyboard focus remains visible.

- [ ] **Step 4: Run the final automated checks**

Run:

```bash
cd frontend
npm test
npm run build
npm run lint
```

Expected: all commands exit successfully.

- [ ] **Step 5: Commit any verification-driven correction**

If a visual or interaction defect required a correction, commit only that correction:

```bash
git add frontend/src
git commit -m "fix: refine explain my network layout"
```

If no correction was required, do not create an empty commit.

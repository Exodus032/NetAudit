# Mobile Sidebar Labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove clipped sidebar labels from compact viewport navigation while preserving each destination's accessible name.

**Architecture:** Add a label element to each existing sidebar button. The compact media rule hides the label visually through a reusable screen-reader-only declaration rather than removing it, so icons remain visible and accessible names retain the destination text. The change remains local to the Sidebar component and styles.

**Tech Stack:** React 18, TypeScript, CSS, Vite, Chromium.

---

### Task 1: Reproduce and encode the narrow navigation contract

**Files:**
- Read: `frontend/src/components/layout/Sidebar.tsx:40-72`
- Read: `frontend/src/components/layout/Sidebar.css:42-95`
- Browser: fresh production app at 390px width

- [ ] **Step 1: Capture the failing narrow behavior**

Open the app at a 390px viewport, navigate to Baselines, and capture the sidebar. Expected before the fix: icon rail width is 64px but visible labels overflow or clip.

- [ ] **Step 2: Define the regression contract**

Use a Chromium accessibility snapshot after the fix. Every primary navigation button must retain a non-empty text-derived accessible name, including `Baselines`, while no `.sidebar-label` box is visually rendered in the compact rail.

### Task 2: Implement the smallest accessible compact-sidebar repair

**Files:**
- Modify: `frontend/src/components/layout/Sidebar.tsx:54-61`
- Modify: `frontend/src/components/layout/Sidebar.css:84-95`

- [ ] **Step 1: Write the failing source shape**

Change the sidebar button content to introduce the label wrapper but do not hide it yet:

```tsx
<span className="sidebar-icon" aria-hidden="true">{item.icon}</span>
<span className="sidebar-label">{item.label}</span>
```

At 390px, Chromium must still show the label as visible. This confirms the screenshot regression is represented by the wrapper rather than a changed destination name.

- [ ] **Step 2: Add compact visual hiding**

In the existing `@media (max-width: 860px)` block, replace the descendant rule with:

```css
.sidebar-brand span:last-child,
.sidebar-label,
.sidebar-footer {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
```

This removes the label from visual layout but keeps it in the accessibility tree.

- [ ] **Step 3: Confirm the narrow contract**

Open the rebuilt app at 390px. Confirm the sidebar shows icon-only buttons, no clipped label text, and the accessibility snapshot names the button `Baselines`.

### Task 3: Verify the release path

**Files:**
- Verify: `frontend/package.json`
- Verify: `frontend/src/components/layout/Sidebar.tsx`
- Verify: `frontend/src/components/layout/Sidebar.css`

- [ ] **Step 1: Build the production bundle**

Run: `npm run build` from `frontend/`.

Expected: `tsc -b && vite build` exits with status 0.

- [ ] **Step 2: Inspect responsive production output**

Build and launch the production backend. Inspect Baselines at 1365px and 390px. Confirm desktop displays the text labels, compact mode hides label glyphs, navigation still changes the active view, and the schedule controls remain visible and usable.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/layout/Sidebar.tsx frontend/src/components/layout/Sidebar.css
git commit -m "fix: hide compact sidebar labels visually"
```

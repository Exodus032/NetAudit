# Mobile sidebar label visibility

## Goal
Keep the existing compact 64px sidebar at widths of 860px or less without rendering clipped navigation text.

## Scope
`frontend/src/components/layout/Sidebar.tsx` will wrap each navigation label in a dedicated `span`. `frontend/src/components/layout/Sidebar.css` will visually hide that span in compact-sidebar mode while retaining it in the button's accessible name. The current desktop sidebar, icon rail width, button click behavior, and section grouping remain unchanged.

## Behavior
- Above 860px, buttons display their icon and visible text label.
- At or below 860px, buttons display their icon only. The label span is visually hidden, not removed from the accessibility tree.
- Each button retains its text-derived accessible name, allowing screen readers and the existing browser accessibility snapshot to identify the destination.
- The narrow Baselines screen must show no clipped sidebar labels. The content area remains usable at a 390px viewport.

## Verification
- First reproduce the old 390px behavior in Chromium, where sidebar labels remain visible and clipped.
- Add a focused regression check for the label wrapper and compact styling in the existing frontend testing pattern, or use a deterministic browser smoke script if no frontend test runner exists.
- Run `npm run build`.
- Launch the app and inspect the Baselines view at desktop width and 390px width. Confirm icon-only compact navigation at 390px and visible labels at desktop width.

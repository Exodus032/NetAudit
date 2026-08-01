# Explain my network

## Goal

Give people with little networking knowledge a plain-language orientation to NetAudit before they inspect live traffic or security findings. The feature must explain what the application observes, how to read its main areas, and why its findings require review rather than blind trust.

## Scope

- Add an `Explain my network` action to the application header.
- Add a dedicated, restartable explanation page. Opening it always begins at the top and stores no progress.
- Organize the page into four short chapters:
  1. **See the big picture**: overview data, traffic, active connections, capture tier, and security score.
  2. **Understand activity**: devices, applications, remote hosts, and observed conversations.
  3. **Review security findings**: recommendations, host posture checks, and behavioural threats, with their evidence.
  4. **Choose a safe action**: NetAudit presents reviewable commands and never changes the system itself.
- Give each chapter a clear action that navigates to the existing corresponding dashboard view.
- Explain capture-tier limitations where relevant. Missing observations must never be presented as proof that nothing is wrong.
- Use everyday language and define terms before relying on them.

## Non-goals

- No new packet capture, aggregation, detector, or posture-check data.
- No new backend endpoint or persistence.
- No automatic tour at first launch.
- No automatic remediation, telemetry, or configuration changes.
- No replacement for the existing per-screen guided tour, glossary, lessons, or learning-mode explanation chips.

## Architecture

The explanation page is a frontend view registered through the existing application view registry and selected through the normal navigation flow. The header action changes the active view to that page.

The page is static explanatory UI with navigation callbacks. It must not duplicate live values, fetch a second data source, or invent a dashboard summary. Its calls to action navigate into the existing views, which continue to load and present live data through their current APIs.

The feature is intentionally separate from the existing API-driven guided tour. The tour remains focused on highlighting individual controls on monitor pages. Explain my network establishes the mental model and directs a beginner to the right place first.

## User flow

1. A user selects `Explain my network` from the header.
2. The page explains NetAudit's scope and limits in plain language.
3. The user reads one of the four short chapters.
4. The chapter action opens the relevant existing view.
5. Selecting `Explain my network` again returns to the top of the page.

## Failure and degraded-data behaviour

The explanation page remains available when the backend is disconnected or the application is using mock data because it does not depend on a new request. It must describe the active capture tier as a limit on what can be observed and direct users to the existing overview capture-tier information. It must not state or imply that a lack of displayed findings means the network is safe.

## Accessibility and responsive behaviour

The header action is a labeled button and the page uses semantic headings, descriptive link or button text, and the existing navigation callback. The chapter actions remain keyboard reachable. Chapters collapse to a single column on narrow screens without obscuring their actions or requiring horizontal scrolling.

## Verification

- Add focused frontend tests for opening the new view and each chapter navigation action.
- Verify the explanation page renders without a backend-specific dependency and includes the capture-limit language.
- Run the frontend build and exercise the header action and all chapter links in the browser.
- Visually inspect the screen at desktop and narrow viewport sizes.
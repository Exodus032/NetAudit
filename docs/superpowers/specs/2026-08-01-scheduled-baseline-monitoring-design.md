# Scheduled baseline monitoring

## Goal

Give NetAudit an opt-in, local scheduler that captures baseline snapshots while the backend is running, compares successive automated snapshots, and routes material security regressions through the existing alert service.

## Scope

- Add a backend-owned schedule component to the baselines package.
- Let the user enable or disable automatic snapshots and choose one preset interval: 6 hours, 12 hours, 24 hours, 48 hours, or 7 days. The default is 24 hours.
- Persist schedule state in SQLite: enabled state, interval, last successful automatic snapshot, and last capture error.
- Distinguish scheduled baselines from manual ones. Keep manual snapshots unchanged. Keep only the most recent 90 days of scheduled snapshots.
- Add a Scheduled monitoring card to the Baselines view. It provides the enable switch, interval selector, last successful snapshot, next due time, and latest scheduler error. Scheduled rows are visibly identified in the existing snapshot list.
- Reuse the existing AlertService. It continues to enforce configured delivery channels, severity filtering, quiet hours, rate limits, and webhook safety rules.

## Scheduling model

The scheduler lives in the backend process. It starts after the security packages are wired and runs only while NetAudit is running. It does not create a Windows scheduled task or a separate service.

The scheduler bases each next run on the persisted last successful automated snapshot. On backend startup, it takes one snapshot if the schedule is enabled and overdue. It never attempts to replay missed intervals, so a long shutdown produces at most one overdue snapshot. The first automatic snapshot establishes a reference and creates no alert.

Each later automatic snapshot compares with the preceding automatic snapshot. A single high-severity alert event is dispatched only if the comparison contains one or more of these material regressions:

- a posture check regressed
- the overall security score fell
- a new listening service appeared

New peers, removed listeners, unchanged checks, and improved scores are retained in the baseline diff but do not cause scheduled-monitoring alerts.

## Data and API design

The baselines package owns the additional schema. Automatic snapshots carry an origin distinct from manual snapshots. A singleton schedule record stores the selected preset interval and status fields. Retention deletes automated snapshots older than 90 days only after a successful capture. Manual snapshots are never deleted by the scheduler.

Add additive `GET /api/baselines/schedule` and `PUT /api/baselines/schedule` endpoints. The update endpoint accepts only the five preset intervals. The frontend client, TypeScript types, hooks, and mock server follow the existing baseline API patterns.

## Failure handling

A failed snapshot records a concise error and does not advance the last-success time. The scheduler retries once after the next selected interval. It does not create an alert for scheduler failures. Schedule update validation happens in the backend, not only in the UI.

The scheduler task is cancelled and awaited during FastAPI lifespan shutdown. Cancellation prevents a late snapshot from being written after the backend stops. A restart restores persisted state instead of resetting the interval or creating duplicate snapshots.

## Alternatives considered

- Windows Task Scheduler: continues while NetAudit is closed, but adds platform-specific task ownership, installation, permissions, and cleanup. Out of scope.
- Frontend timer: needs no backend scheduler, but monitoring stops when the browser tab closes. It cannot provide ongoing monitoring.

## Verification

- Unit tests cover preset validation, first-snapshot behavior, overdue-on-start behavior, persisted timing after restart, cancellation, and failure recording.
- Baseline comparison tests cover alerts for posture regressions, score drops, and new listeners, plus no alert for unchanged, improved, or peer-only differences.
- Retention tests prove that scheduled snapshots older than 90 days are removed while manual snapshots remain.
- API tests cover persisted schedule reads and updates.
- Frontend tests cover the schedule state and interval update path. A browser check confirms the Baselines view on desktop and narrow viewports.

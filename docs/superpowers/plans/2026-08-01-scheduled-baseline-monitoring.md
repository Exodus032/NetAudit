# Scheduled Baseline Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in, local scheduled baseline snapshots with configurable preset intervals, 90-day automatic retention, and alerts only for material security regressions.

**Architecture:** The `baselines` package owns schedule persistence and a `BaselineMonitor` coordinator. The monitor is started and stopped by the FastAPI lifespan, obtains live dependencies through the existing app wiring, and sends a single high-severity event to the injected existing alert dispatcher when a new scheduled snapshot regresses. The existing Baselines React view gets a schedule card backed by additive schedule endpoints.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, SQLite, asyncio, pytest, React 18, TypeScript, Vite.

---

## File map

| File | Responsibility |
| --- | --- |
| `backend/netaudit/baselines/models.py` | Public schedule request and response shapes plus baseline origin. |
| `backend/netaudit/baselines/store.py` | Idempotent schema migration, scheduled-baseline metadata, schedule state, and 90-day retention. |
| `backend/netaudit/baselines/service.py` | Manual and scheduled capture methods, schedule persistence façade, and regression classification helpers. |
| `backend/netaudit/baselines/monitor.py` | One independently testable background coordinator. It owns due-time calculation, capture, alert dispatch, error recording, wake-up, and cancellation. |
| `backend/netaudit/baselines/router.py` | Additive schedule API endpoints. |
| `backend/netaudit/integration.py` | Construct the monitor with the already-wired baseline providers and alert service. |
| `backend/netaudit/server.py` | Start the monitor during lifespan startup and await shutdown cancellation. |
| `frontend/src/api/typesPro.ts` | Matching TypeScript schedule and origin types. |
| `frontend/src/api/clientPro.ts` and `frontend/src/mocks/serverPro.ts` | Real and mock schedule API operations. |
| `frontend/src/hooks/useBaselines.ts` | Schedule loading, saving, pending state, and user-visible save errors. |
| `frontend/src/views/Pro/Baselines/*` | Schedule controls and responsive layout. |
| `backend/tests/baselines/test_schedule_store.py` | Storage migration, schedule validation, and retention contracts. |
| `backend/tests/baselines/test_monitor.py` | Scheduler behavior, alert selection, error handling, restart timing, and cancellation. |
| `backend/tests/baselines/test_router.py` | Schedule endpoint behavior and validation. |
| `docs/API_CONTRACT_V3.md` | Additive schedule endpoint contract. |

### Task 1: Persist schedule state and baseline origin

**Files:**
- Modify: `backend/netaudit/baselines/models.py`
- Modify: `backend/netaudit/baselines/store.py`
- Modify: `backend/netaudit/baselines/service.py`
- Create: `backend/tests/baselines/test_schedule_store.py`

- [ ] **Step 1: Write failing storage and service tests**

```python
import pytest

from netaudit.baselines.service import BaselineService
from netaudit.baselines.store import get_schedule, insert_baseline, list_baselines


def test_schedule_defaults_disabled_with_a_24_hour_interval(db_path):
    schedule = get_schedule(db_path)
    assert schedule.enabled is False
    assert schedule.interval_hours == 24
    assert schedule.last_succeeded_at is None
    assert schedule.last_error is None


def test_only_scheduled_snapshots_older_than_90_days_are_removed(db_path):
    service = BaselineService(db_path)
    manual = insert_baseline("Before hardening", [], [], [], 50, None, 50, origin="manual", captured_at="2026-05-01T00:00:00Z", db_path=db_path)
    old_scheduled = insert_baseline("Scheduled baseline", [], [], [], 50, None, 50, origin="scheduled", captured_at="2026-05-01T00:00:00Z", db_path=db_path)
    recent_scheduled = insert_baseline("Scheduled baseline", [], [], [], 50, None, 50, origin="scheduled", captured_at="2026-07-15T00:00:00Z", db_path=db_path)

    service.prune_scheduled("2026-07-30T00:00:00Z")

    assert {record.id for record in list_baselines(db_path)} == {manual.id, recent_scheduled.id}
    assert old_scheduled.id not in {record.id for record in list_baselines(db_path)}


def test_schedule_rejects_an_interval_outside_the_supported_presets(db_path):
    service = BaselineService(db_path)
    with pytest.raises(ValueError, match="interval_hours"):
        service.update_schedule(enabled=True, interval_hours=4)
```

- [ ] **Step 2: Run the new storage tests and verify they fail**

Run: `python -m uv run --project backend pytest backend/tests/baselines/test_schedule_store.py -v`

Expected: FAIL during collection because `get_schedule`, origin-aware `insert_baseline`, `prune_scheduled`, and `update_schedule` do not exist.

- [ ] **Step 3: Add explicit schedule and origin models**

In `models.py`, introduce these shared shapes. Keep `BaselineListItem.origin` additive so existing manual snapshot callers remain valid.

```python
from typing import Literal, Optional

BaselineOrigin = Literal["manual", "scheduled"]
ScheduleIntervalHours = Literal[6, 12, 24, 48, 168]


class BaselineScheduleUpdate(BaseModel):
    enabled: bool
    interval_hours: ScheduleIntervalHours


class BaselineSchedule(BaseModel):
    enabled: bool = False
    interval_hours: ScheduleIntervalHours = 24
    last_succeeded_at: Optional[str] = None
    next_due_at: Optional[str] = None
    last_error: Optional[str] = None
```

Add `origin: BaselineOrigin = "manual"` to `BaselineListItem` and `BaselineRecord`. Do not change the existing manual `POST /api/baselines` request body or response fields other than this additive origin field.

- [ ] **Step 4: Implement safe SQLite migration and persistence helpers**

Extend `_ensure_schema` to support databases created before this feature. Inspect `PRAGMA table_info(baselines)` before issuing `ALTER TABLE baselines ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'`; never assume the column exists. Create the singleton table and index exactly once per connection key:

```sql
CREATE TABLE IF NOT EXISTS baseline_schedule (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    last_succeeded_at TEXT,
    last_error TEXT
);
INSERT OR IGNORE INTO baseline_schedule (id) VALUES (1);
CREATE INDEX IF NOT EXISTS idx_baselines_origin_captured_at
    ON baselines (origin, captured_at);
```

Add these focused store functions: `get_schedule(db_path=None)`, `save_schedule(enabled, interval_hours, db_path=None)`, `mark_schedule_success(captured_at, db_path=None)`, `mark_schedule_error(message, db_path=None)`, `delete_scheduled_before(cutoff, db_path=None)`, and `latest_scheduled_baseline(db_path=None)`. They must return the Pydantic schedule or a `BaselineRecord` where applicable.

Update `insert_baseline` to accept keyword-only `origin: BaselineOrigin = "manual"` and `captured_at: Optional[str] = None`; use `now_iso()` only when the caller has not supplied a capture time. Include `origin` in the insert, row mapper, and list-item conversion. `delete_scheduled_before` must filter `WHERE origin = 'scheduled' AND captured_at < ?` so manual snapshots can never be pruned.

Add `BaselineService.create_scheduled(posture, traffic, score, captured_at)` to call `capture_snapshot` with the `Scheduled baseline` label and `origin="scheduled"`. Add `BaselineService.prune_scheduled(cutoff)` as the only service façade over `delete_scheduled_before`.

`BaselineService.update_schedule` must accept only `{6, 12, 24, 48, 168}` and raise `ValueError("interval_hours must be one of 6, 12, 24, 48, 168")` for every other value. `BaselineService.get_schedule` must compute `next_due_at` from the persisted successful timestamp plus the saved interval, returning `None` before the first successful scheduled snapshot.

- [ ] **Step 5: Run the storage tests and existing baseline tests**

Run: `python -m uv run --project backend pytest backend/tests/baselines/test_schedule_store.py backend/tests/baselines/test_diff.py -v`

Expected: PASS. The new tests prove manual data survives pruning and invalid intervals cannot enter the database.

- [ ] **Step 6: Commit the persistence layer**

```bash
git add backend/netaudit/baselines/models.py backend/netaudit/baselines/store.py backend/netaudit/baselines/service.py backend/tests/baselines/test_schedule_store.py
git commit -m "feat: persist baseline monitoring schedule"
```

### Task 2: Add the independently testable scheduler

**Files:**
- Create: `backend/netaudit/baselines/monitor.py`
- Modify: `backend/netaudit/baselines/service.py`
- Create: `backend/tests/baselines/test_monitor.py`

- [ ] **Step 1: Write failing monitor tests using fakes**

```python
from netaudit.baselines.monitor import BaselineMonitor
from netaudit.baselines.service import BaselineService


class Inputs:
    def __init__(self):
        self.check_values = [{"id": "firewall", "status": "pass"}]
        self.peer_values = []
        self.listener_values = []
        self.overall = 80
        self.fail = False

    def checks(self):
        if self.fail:
            raise RuntimeError("provider unavailable")
        return self.check_values

    def peers(self):
        return self.peer_values

    def listeners(self):
        return self.listener_values

    def security_score(self):
        return {"posture": self.overall, "threats": None, "overall": self.overall}


class RecordingDispatcher:
    def __init__(self):
        self.calls = []

    def dispatch(self, severity, source, source_id, title):
        self.calls.append({"severity": severity, "source": source, "source_id": source_id, "title": title})


def make_monitor(db_path):
    service = BaselineService(db_path)
    service.update_schedule(enabled=True, interval_hours=24)
    inputs = Inputs()
    dispatcher = RecordingDispatcher()
    return BaselineMonitor(service, inputs, inputs, inputs, dispatcher), service, inputs, dispatcher


def test_first_due_run_captures_a_reference_without_alert(db_path):
    monitor, _, _, dispatcher = make_monitor(db_path)

    result = monitor.run_once(now="2026-08-01T00:00:00Z")

    assert result.captured is True
    assert result.alerted is False
    assert dispatcher.calls == []


def test_regression_conditions_dispatch_one_high_alert(db_path):
    monitor, _, inputs, dispatcher = make_monitor(db_path)
    monitor.run_once(now="2026-08-01T00:00:00Z")
    inputs.check_values = [{"id": "firewall", "status": "fail"}]
    inputs.listener_values = [{"port": 8080, "process": "node.exe"}]
    inputs.overall = 70

    monitor.run_once(now="2026-08-02T00:00:00Z")

    assert dispatcher.calls[0]["severity"] == "high"
    assert dispatcher.calls[0]["source"] == "scheduled_baseline"
    assert len(dispatcher.calls) == 1


def test_peer_only_and_improved_changes_do_not_alert(db_path):
    monitor, _, inputs, dispatcher = make_monitor(db_path)
    monitor.run_once(now="2026-08-01T00:00:00Z")
    inputs.peer_values = ["203.0.113.9"]
    monitor.run_once(now="2026-08-02T00:00:00Z")
    inputs.overall = 90
    monitor.run_once(now="2026-08-03T00:00:00Z")

    assert dispatcher.calls == []


def test_capture_failure_is_recorded_and_does_not_advance_last_success(db_path):
    monitor, service, inputs, dispatcher = make_monitor(db_path)
    monitor.run_once(now="2026-08-01T00:00:00Z")
    previous_success = service.get_schedule().last_succeeded_at
    inputs.fail = True

    result = monitor.run_once(now="2026-08-02T00:00:00Z")

    assert result.error == "provider unavailable"
    assert service.get_schedule().last_succeeded_at == previous_success
    assert service.get_schedule().last_error == "provider unavailable"
    assert dispatcher.calls == []
```

Add async tests using `asyncio.run()` for `start()`, `wake()`, and `shutdown()`: changing schedule state wakes a waiting monitor, and shutdown leaves no pending task or subsequent snapshot.

- [ ] **Step 2: Run the monitor tests and verify they fail**

Run: `python -m uv run --project backend pytest backend/tests/baselines/test_monitor.py -v`

Expected: FAIL because `netaudit.baselines.monitor` does not exist.

- [ ] **Step 3: Implement a narrow monitor boundary**

Create `monitor.py`. Do not import `netaudit.alerts`; define an `AlertDispatcher` `Protocol` whose `dispatch(severity, source, source_id, title)` method matches the existing `AlertService.dispatch` call shape. Define a frozen `MonitorResult` dataclass with `captured: bool`, `alerted: bool`, and `error: Optional[str]`. `BaselineMonitor` accepts `BaselineService`, the three existing baseline provider protocols, the dispatcher protocol, and an injectable `clock` returning an ISO timestamp. Its public operations are `run_once(now=None)`, `wake()`, `start()`, and asynchronous `shutdown()`.

`run_once` must:

1. Return without capture if schedule is disabled or `now` precedes the computed due timestamp.
2. Capture one `origin="scheduled"` snapshot with the label `Scheduled baseline` when due.
3. Mark its success, then delete automatic snapshots older than `now - 90 days`.
4. Treat the first scheduled snapshot as a reference. For later snapshots, diff it against the prior scheduled record.
5. Dispatch exactly one `severity="high"`, `source="scheduled_baseline"` alert when `diff.checks.regressed`, `diff.score_delta.overall < 0`, or `diff.new_listeners` is nonempty. Use the newly captured baseline id as `source_id`; make the title enumerate only triggered categories.
6. Ignore new peers, removed listeners, fixed checks, and score improvements for alert eligibility.
7. On capture/provider failure, save a bounded error string, leave `last_succeeded_at` untouched, and return an error result without dispatching.

The loop may wait with an `asyncio.Event`, but run blocking snapshot work via `await asyncio.to_thread(self.run_once)` so FastAPI's event loop stays responsive. Recompute delay after every run and wake, cap a wait at the configured interval, and cancel/await the background task in `shutdown()`.

- [ ] **Step 4: Run the monitor tests and full baseline suite**

Run: `python -m uv run --project backend pytest backend/tests/baselines -v`

Expected: PASS. Verify the test names demonstrate reference-only first capture, each material regression condition, alert exclusion conditions, persisted overdue timing, retention, failure retry, and cancellation.

- [ ] **Step 5: Commit scheduler behavior**

```bash
git add backend/netaudit/baselines/monitor.py backend/netaudit/baselines/service.py backend/tests/baselines/test_monitor.py
git commit -m "feat: schedule baseline monitoring"
```

### Task 3: Expose schedule state and wire the lifecycle

**Files:**
- Modify: `backend/netaudit/baselines/router.py`
- Modify: `backend/netaudit/baselines/__init__.py`
- Modify: `backend/netaudit/integration.py`
- Modify: `backend/netaudit/server.py`
- Modify: `backend/tests/baselines/test_router.py`
- Create: `backend/tests/baselines/test_lifecycle.py`

- [ ] **Step 1: Write failing endpoint and lifespan tests**

Extend the current `make_client` fixture with a schedule service dependency. Add this contract:

```python
def test_schedule_defaults_and_updates_persist(tmp_path):
    client = make_client(tmp_path / "t.db")
    assert client.get("/api/baselines/schedule").json() == {
        "enabled": False,
        "interval_hours": 24,
        "last_succeeded_at": None,
        "next_due_at": None,
        "last_error": None,
    }

    updated = client.put("/api/baselines/schedule", json={"enabled": True, "interval_hours": 48})
    assert updated.status_code == 200
    assert updated.json()["enabled"] is True
    assert updated.json()["interval_hours"] == 48


def test_schedule_rejects_non_preset_interval(tmp_path):
    response = make_client(tmp_path / "t.db").put("/api/baselines/schedule", json={"enabled": True, "interval_hours": 4})
    assert response.status_code == 422
```

In `test_lifecycle.py`, use `create_app(db_path=db_path, token_path=tmp_path / "token", autostart_capture=False)` and a replaceable monitor fake to prove lifespan calls `start()` after wiring and awaits `shutdown()` when the app context exits.

- [ ] **Step 2: Run endpoint and lifecycle tests to verify they fail**

Run: `python -m uv run --project backend pytest backend/tests/baselines/test_router.py backend/tests/baselines/test_lifecycle.py -v`

Expected: FAIL with `404` for the schedule route and missing lifecycle monitor wiring.

- [ ] **Step 3: Implement additive API and application wiring**

Add these router operations before the parameterized diff route so `/schedule` is never interpreted as a baseline id:

```python
@router.get("/api/baselines/schedule", response_model=BaselineSchedule)
def get_schedule(service: BaselineService = Depends(get_baseline_service)) -> BaselineSchedule:
    return service.get_schedule()

@router.put("/api/baselines/schedule", response_model=BaselineSchedule)
def put_schedule(
    body: BaselineScheduleUpdate,
    service: BaselineService = Depends(get_baseline_service),
    monitor: BaselineMonitor = Depends(get_baseline_monitor),
) -> BaselineSchedule:
    schedule = service.update_schedule(body.enabled, body.interval_hours)
    monitor.wake()
    return schedule
```

Expose `get_baseline_monitor()` as a dependency provider, parallel to `get_baseline_service()`. In `wire_pro`, create one `BaselineMonitor` from the existing `baseline_service`, `posture_adapter`, `traffic_provider`, `score_provider`, and `alert_service`; store it in `app.state.baseline_monitor`, and override the provider. In `server.py` lifespan, call `app.state.baseline_monitor.start()` after capture background tasks start and `await app.state.baseline_monitor.shutdown()` before pipeline shutdown. Preserve the existing threat and ARP shutdown order.

- [ ] **Step 4: Run API and integration verification**

Run: `python -m uv run --project backend pytest backend/tests/baselines/test_router.py backend/tests/baselines/test_lifecycle.py backend/tests/alerts -q`

Expected: PASS. The alert suite must remain unchanged because the monitor only calls its established `AlertService.dispatch` interface.

- [ ] **Step 5: Commit the API and lifecycle wiring**

```bash
git add backend/netaudit/baselines/router.py backend/netaudit/baselines/__init__.py backend/netaudit/integration.py backend/netaudit/server.py backend/tests/baselines/test_router.py backend/tests/baselines/test_lifecycle.py
git commit -m "feat: expose baseline monitoring controls"
```

### Task 4: Add schedule controls to the Baselines view

**Files:**
- Modify: `frontend/src/api/typesPro.ts`
- Modify: `frontend/src/api/clientPro.ts`
- Modify: `frontend/src/mocks/serverPro.ts`
- Modify: `frontend/src/hooks/useBaselines.ts`
- Modify: `frontend/src/views/Pro/Baselines/BaselinesView.tsx`
- Modify: `frontend/src/views/Pro/Baselines/BaselinesView.css`

- [ ] **Step 1: Add TypeScript contract and API functions**

Add matching types:

```ts
export type BaselineOrigin = "manual" | "scheduled";
export type BaselineIntervalHours = 6 | 12 | 24 | 48 | 168;

export interface BaselineSchedule {
  enabled: boolean;
  interval_hours: BaselineIntervalHours;
  last_succeeded_at: string | null;
  next_due_at: string | null;
  last_error: string | null;
}
```

Add `origin: BaselineOrigin` to `BaselineListItem`. Add client functions and mock equivalents:

```ts
export function getBaselineSchedule(): Promise<BaselineSchedule> {
  return withFallback("/api/baselines/schedule", undefined, mockGetBaselineSchedule);
}

export function updateBaselineSchedule(update: Pick<BaselineSchedule, "enabled" | "interval_hours">): Promise<BaselineSchedule> {
  return withFallback("/api/baselines/schedule", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(update) }, () => mockUpdateBaselineSchedule(update));
}
```

The mock state begins disabled at 24 hours and calculates `next_due_at` only after a successful automatic snapshot, matching the backend response semantics.

- [ ] **Step 2: Add a dedicated schedule hook**

Keep manual snapshot state isolated. Add `useBaselineSchedule()` beside `useBaselines()` with `schedule`, `loading`, `saving`, `error`, and `save(update)` state. It loads once with `getBaselineSchedule`, clears errors before saving, replaces schedule state only with the response returned by `updateBaselineSchedule`, and preserves the prior state on failure.

- [ ] **Step 3: Render controls with semantic, responsive markup**

Add a Scheduled monitoring section before Capture a baseline. Use a checkbox or existing switch pattern for the opt-in state, a labeled `<select>` with exact options `6 hours`, `12 hours`, `24 hours`, `48 hours`, and `7 days`, and a save button disabled only while a save is pending. Render these explicit states:

```tsx
<p className="pro-muted">{schedule.enabled ? "NetAudit captures a snapshot while the backend is running." : "Scheduled monitoring is off."}</p>
<p>Last snapshot: {schedule.last_succeeded_at ? formatDateTime(schedule.last_succeeded_at) : "Not captured yet"}</p>
<p>Next due: {schedule.next_due_at ? formatDateTime(schedule.next_due_at) : "After the first scheduled snapshot"}</p>
{schedule.last_error && <div className="pro-inline-error">{schedule.last_error}</div>}
```

Add an `Origin` column to the existing snapshots table. Render `Scheduled` for `origin === "scheduled"` and `Manual` otherwise. Use CSS grid or flex wrapping so controls stack cleanly at narrow widths. Do not change the manual capture or diff behavior.

- [ ] **Step 4: Build the frontend**

Run: `cd frontend && npm run build`

Expected: TypeScript compilation and Vite build succeed. Fix every type mismatch between the API, mock, hook, and view before continuing.

- [ ] **Step 5: Visually verify desktop and narrow viewports**

Run the application, navigate to the Baselines view, and verify:

1. Desktop: schedule card, toggle, select, save state, error state, and origin column are readable without overlap.
2. Narrow viewport: schedule controls stack, labels remain associated with inputs, and the snapshot table can scroll horizontally instead of clipping columns.
3. Toggle and interval changes persist through a reload using the real local API.

Record the exact visual verification in the implementation handoff and correct any layout issue before proceeding.

- [ ] **Step 6: Commit the dashboard controls**

```bash
git add frontend/src/api/typesPro.ts frontend/src/api/clientPro.ts frontend/src/mocks/serverPro.ts frontend/src/hooks/useBaselines.ts frontend/src/views/Pro/Baselines/BaselinesView.tsx frontend/src/views/Pro/Baselines/BaselinesView.css
git commit -m "feat: configure scheduled baseline monitoring"
```

### Task 5: Document the additive API and perform final verification

**Files:**
- Modify: `docs/API_CONTRACT_V3.md`

- [ ] **Step 1: Document the exact schedule endpoints**

Add an additive subsection immediately after E8. Include the full response shape and valid request values:

```json
{
  "enabled": true,
  "interval_hours": 24,
  "last_succeeded_at": "2026-08-01T00:00:00Z",
  "next_due_at": "2026-08-02T00:00:00Z",
  "last_error": null
}
```

Document `PUT /api/baselines/schedule` accepting only `6`, `12`, `24`, `48`, or `168` in `interval_hours`. State that it runs only while NetAudit is open, the first automatic snapshot is a non-alerting reference, only scheduled snapshots are pruned after 90 days, and automatic alerts cover regressions, overall score decreases, and new listeners only.

- [ ] **Step 2: Run all changed backend contracts**

Run: `python -m uv run --project backend pytest backend/tests/baselines backend/tests/alerts -q`

Expected: PASS. This covers the scheduler, API, baseline diffs, and alert dispatch behavior.

- [ ] **Step 3: Run the complete backend suite and lock validation**

Run: `python -m uv lock --project backend --check && python -m uv run --project backend pytest backend/tests -q`

Expected: lock check succeeds and the complete suite passes. Investigate and fix any failure before claiming completion.

- [ ] **Step 4: Scan all changed source files**

Run the configured Aikido full scan for these modified or added files:

```text
backend/netaudit/baselines/models.py
backend/netaudit/baselines/store.py
backend/netaudit/baselines/service.py
backend/netaudit/baselines/monitor.py
backend/netaudit/baselines/router.py
backend/netaudit/baselines/__init__.py
backend/netaudit/integration.py
backend/netaudit/server.py
frontend/src/api/typesPro.ts
frontend/src/api/clientPro.ts
frontend/src/mocks/serverPro.ts
frontend/src/hooks/useBaselines.ts
frontend/src/views/Pro/Baselines/BaselinesView.tsx
frontend/src/views/Pro/Baselines/BaselinesView.css
```

Expected: no new secrets or SAST findings. If the scanner itself fails, report the exact incomplete component and do not describe the scan as clean.

- [ ] **Step 5: Commit documentation and final verification**

```bash
git add docs/API_CONTRACT_V3.md
git commit -m "docs: describe scheduled baseline monitoring"
```

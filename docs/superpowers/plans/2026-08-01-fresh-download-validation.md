# Fresh Download Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify that a first-time downloader can clone, install, launch, and use NetAudit without relying on repository-local build artifacts.

**Architecture:** Create a disposable clone outside the repository, use a new backend virtual environment and newly installed frontend dependencies, then launch the production single-origin application. Validate authenticated health, SPA delivery, core API bootstrap, and desktop and narrow browser rendering. Any failure is reproduced in the clean clone and traced before changing source.

**Tech Stack:** Git, uv, Python 3.14, npm, Vite, FastAPI, Chromium.

---

### Task 1: Create and install a disposable clone

**Files:**
- Read: `README.md:73-148`
- Read: `start.ps1:55-166`

- [ ] Clone `origin/master` into a new temporary directory outside this repository.
- [ ] Run `uv sync --project backend` in the clone and record the command output and created environment.
- [ ] Run `npm install` then `npm run build` in the clone's `frontend/` directory.
- [ ] Treat lockfile, dependency-resolution, install, and frontend compilation failures as defects to investigate from their reported command and files.

### Task 2: Exercise the downloaded production program

**Files:**
- Read: `backend/netaudit/server.py`
- Read: `frontend/vite.config.ts`

- [ ] Start `uv run --directory backend -m netaudit.server` with isolated database and token paths.
- [ ] Read the isolated token and call `GET /api/health` with `X-NetAudit-Token`; expect HTTP 200 and JSON health data.
- [ ] Request `/` and verify the backend returns the built frontend document.
- [ ] Open the application in Chromium at a desktop viewport and narrow viewport. Confirm the primary dashboard renders and navigate the core Baselines flow.
- [ ] Stop the isolated process and delete only the temporary clone and its generated state.

### Task 3: Regressions and defect handling

**Files:**
- Test: `backend/tests/`
- Test: `frontend/package.json`

- [ ] If a validation failure occurs, reproduce it once in the clean clone, read its full error, identify the responsible boundary, and write a failing regression test before modifying production code.
- [ ] After every repair, recreate the disposable clone and repeat Tasks 1 and 2.
- [ ] Run `uv lock --project backend --check`, the full backend test suite, and `npm run build` from the final downloaded clone.

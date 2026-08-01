# UV Project Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cloned NetAudit repositories install and run the backend through uv's locked project workflow.

**Architecture:** `backend/pyproject.toml` replaces the pip requirements manifest as the canonical dependency declaration. `backend/uv.lock` records its fully resolved graph. The README and Windows launcher both invoke uv against `backend/`, so direct setup and `start.ps1` select the same environment.

**Tech Stack:** Python 3.11+, uv, PowerShell, pytest.

---

### Task 1: Specify and test the uv project contract

**Files:**
- Create: `backend/tests/test_project_setup.py`
- Create: `backend/pyproject.toml`
- Delete: `backend/requirements.txt`

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def test_backend_is_a_locked_uv_project():
    project = tomllib.loads((BACKEND / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "netaudit"
    assert project["project"]["version"] == "1.0.0"
    assert project["project"]["requires-python"] == ">=3.11"
    assert project["project"]["dependencies"] == [
        "fastapi==0.141.1",
        "uvicorn[standard]==0.52.0",
        "pydantic==2.13.4",
        "psutil==7.2.2",
        'scapy==2.7.0; platform_system == "Windows"',
        "python-multipart==0.0.32",
    ]
    assert project["dependency-groups"]["dev"] == [
        "pytest==9.1.1",
        "httpx==0.28.1",
    ]
    assert not (BACKEND / "requirements.txt").exists()
    assert (BACKEND / "uv.lock").is_file()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && .venv\\Scripts\\python.exe -m pytest tests/test_project_setup.py -v`

Expected: FAIL because `backend/pyproject.toml` does not exist.

- [ ] **Step 3: Add the canonical dependency manifest**

Create `backend/pyproject.toml` with:

```toml
[project]
name = "netaudit"
version = "1.0.0"
description = "Local network auditing and security tool"
requires-python = ">=3.11"
dependencies = [
    "fastapi==0.141.1",
    "uvicorn[standard]==0.52.0",
    "pydantic==2.13.4",
    "psutil==7.2.2",
    'scapy==2.7.0; platform_system == "Windows"',
    "python-multipart==0.0.32",
]

[dependency-groups]
dev = [
    "pytest==9.1.1",
    "httpx==0.28.1",
]
```

Delete `backend/requirements.txt`. The test-only dependencies remain in the `dev` group instead of the production dependency list.

- [ ] **Step 4: Generate the lockfile and make the test pass**

Run: `uv lock --project backend && uv run --project backend pytest backend/tests/test_project_setup.py -v`

Expected: uv writes `uv.lock`, then pytest reports `1 passed`.

- [ ] **Step 5: Commit**

```bash
git add backend/pyproject.toml backend/tests/test_project_setup.py backend/uv.lock backend/requirements.txt
git commit -m "Adopt uv project dependencies"
```

### Task 2: Migrate the launcher to uv

**Files:**
- Modify: `start.ps1:61-72`
- Modify: `start.ps1:100-116`
- Test: `backend/tests/test_project_setup.py`

- [ ] **Step 1: Write the failing launcher contract test**

Append to `backend/tests/test_project_setup.py`:

```python
def test_windows_launcher_syncs_and_runs_the_backend_with_uv():
    launcher = (ROOT / "start.ps1").read_text(encoding="utf-8")

    assert "Get-Command uv -ErrorAction Stop" in launcher
    assert "& $uv sync --project $backend" in launcher
    assert "'run', '--directory', $backend, '--no-sync', '-m', 'netaudit.server'" in launcher
    assert "pip install" not in launcher
    assert "python -m venv" not in launcher
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --project backend pytest backend/tests/test_project_setup.py::test_windows_launcher_syncs_and_runs_the_backend_with_uv -v`

Expected: FAIL because `start.ps1` still creates a virtual environment and invokes pip.

- [ ] **Step 3: Replace the launcher backend setup and process command**

Replace the current `.venv` and pip setup block with:

```powershell
$uv = (Get-Command uv -ErrorAction Stop).Source

if (-not $SkipInstall) {
    Write-Host '    syncing python dependencies with uv...'
    & $uv sync --project $backend
}
```

Replace the backend process configuration and launch with:

```powershell
$backendArgs = @('run', '--directory', $backend, '--no-sync', '-m', 'netaudit.server')
if ($Lan) {
    $backendArgs += '--unsafe-bind'
    $backendArgs += '0.0.0.0'
    $backendArgs += '--allow-lan-bootstrap'
}

$backendProc = Start-Process -FilePath $uv -ArgumentList $backendArgs `
    -WorkingDirectory $backend -PassThru
```

Retain the existing LAN arguments and all frontend behavior. `--no-sync` ensures `-SkipInstall` continues to prevent dependency installation and that a normal launch reuses the preceding `uv sync` result.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `uv run --project backend pytest backend/tests/test_project_setup.py -v`

Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add start.ps1 backend/tests/test_project_setup.py
git commit -m "Run Windows launcher through uv"
```

### Task 3: Publish uv setup commands in the README

**Files:**
- Modify: `README.md:82-103`
- Modify: `README.md:137-144`
- Test: `backend/tests/test_project_setup.py`

- [ ] **Step 1: Write the failing README contract test**

Append to `backend/tests/test_project_setup.py`:

```python
def test_readme_documents_the_uv_project_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Requires uv and Node.js 20+" in readme
    assert "uv sync --project backend" in readme
    assert "uv run --directory backend -m netaudit.server" in readme
    assert "python3 -m venv backend/.venv" not in readme
    assert "pip install -r backend/requirements.txt" not in readme
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run --project backend pytest backend/tests/test_project_setup.py::test_readme_documents_the_uv_project_workflow -v`

Expected: FAIL because the README still describes venv and pip setup.

- [ ] **Step 3: Replace the Linux, macOS, and manual setup commands**

Change the Linux and macOS prerequisite sentence to `Requires uv and Node.js 20+ with npm.` Change the cloned-repository block to:

```bash
git clone https://github.com/Exodus032/NetAudit.git
cd NetAudit
uv sync --project backend
(cd frontend && npm install && npm run build)
uv run --directory backend -m netaudit.server
```

Replace the manual Windows backend setup line with:

```powershell
uv sync --project backend; uv run --directory backend -m netaudit.server   # 127.0.0.1:8787
```

Do not alter the frontend command.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `uv run --project backend pytest backend/tests/test_project_setup.py::test_readme_documents_the_uv_project_workflow -v`

Expected: `1 passed`.

- [ ] **Step 5: Commit**

```bash
git add README.md backend/tests/test_project_setup.py
git commit -m "Document uv setup workflow"
```

### Task 4: Verify the complete uv workflow

**Files:**
- Verify: `backend/pyproject.toml`
- Verify: `backend/uv.lock`
- Verify: `README.md`
- Verify: `start.ps1`
- Verify: `backend/tests/test_project_setup.py`

- [ ] **Step 1: Confirm the committed lockfile matches project metadata**

Run: `uv lock --project backend --check`

Expected: exit code 0 with no lockfile update.

- [ ] **Step 2: Run the full backend test suite**

Run: `uv run --project backend pytest backend/tests -q`

Expected: all tests pass.

- [ ] **Step 3: Smoke-test the documented launch command**

Run: `uv run --directory backend -m netaudit.server`

Expected: the process reports its loopback HTTP endpoint and responds to `GET /api/health` only with the generated local token. Stop the process cleanly after observing startup.

- [ ] **Step 4: Scan modified code for security findings**

Run the Aikido full scan for `backend/pyproject.toml`, `backend/tests/test_project_setup.py`, and `start.ps1`.

Expected: no new secrets or SAST findings.

- [ ] **Step 5: Commit final verified changes**

```bash
git add README.md start.ps1 backend/pyproject.toml backend/tests/test_project_setup.py backend/uv.lock backend/requirements.txt
git commit -m "Complete uv project workflow"
```

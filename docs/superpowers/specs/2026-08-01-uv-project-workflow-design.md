# UV project workflow

## Goal

Replace the cloned-repository Python setup instructions with uv's project workflow. Users must be able to install the backend dependencies reproducibly and start NetAudit without manually creating or activating a virtual environment.

## Scope

- Add uv-compatible project metadata for `backend/`.
- Lock Python dependencies with `backend/uv.lock`.
- Update README setup commands to use `uv sync --project backend` and `uv run --project backend -m netaudit.server`.
- Update `start.ps1` only if it creates the backend virtual environment or installs dependencies itself.
- Keep frontend installation and build commands unchanged.

## Command contract

After cloning the repository, Linux and macOS users run:

```bash
uv sync --project backend
(cd frontend && npm install && npm run build)
uv run --project backend -m netaudit.server
```

The backend project metadata declares the current runtime dependencies and its supported Python version. `backend/uv.lock` captures the resolved dependency graph. The existing package remains executable as `python -m netaudit.server` within uv's managed environment.

## Alternatives considered

- `uv venv` plus `uv pip install -r requirements.txt`: smaller documentation change, but retains an unpinned pip-style workflow.
- `uvx netaudit`: requires packaging, a CLI entry point, publication to a package index, and release ownership. It is out of scope.

## Error handling

uv reports unsupported Python versions and dependency-resolution failures. README instructions retain the stated Python and Node.js prerequisites.

## Verification

- A focused automated test validates the project metadata and the README command contract.
- `uv lock --project backend --check` validates that the committed lockfile matches project metadata.
- Starting `uv run --project backend -m netaudit.server` provides the smoke test.

# Dependencies

None beyond what the backend already installs (`fastapi`, `pydantic`,
standard library `sqlite3`/`json`/`secrets`/`dataclasses`). Persistence
reuses the shared SQLite file via `netaudit.store.db.get_conn()` -- no new
storage engine, no new package.

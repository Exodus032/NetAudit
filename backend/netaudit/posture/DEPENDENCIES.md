# Dependencies

This package introduces **no new third-party dependency**. Everything it
needs beyond the standard library is already declared in
`backend/requirements.txt` for the wider NetAudit project:

| Package | Used for | Already in requirements.txt? |
|---|---|---|
| `fastapi` | `router.py`'s `APIRouter`, request/response typing | Yes (`fastapi>=0.115,<1.0`) |
| `pydantic` | `models.py` response/request models | Yes (`pydantic>=2.7,<3.0`) |
| `psutil` | `probes/netprobe.py` -- cross-platform enumeration of listening sockets and their owning process, used by the `listening_services` category | Yes (`psutil>=6.0`) |

Everything else -- process execution (`subprocess`), registry access
(`winreg`), JSON parsing, threading/timeouts, dataclasses -- is standard
library.

No dependency added here makes an outbound network call, phones home, or
requires anything beyond what the parent project already installs.

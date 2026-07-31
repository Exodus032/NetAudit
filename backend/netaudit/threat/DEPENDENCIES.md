# Threat engine dependencies

No new third-party packages. Everything in `threat/` runs on the standard
library plus the two packages already present in `requirements.txt` for the
rest of the backend:

| Package | Already in requirements.txt? | Used for |
|---|---|---|
| `fastapi` | yes | `router.py`'s `APIRouter`, `Depends`, request/response handling |
| `pydantic` | yes (fastapi dependency) | `models.py` response shapes (`Threat`, `Detector`, `Action`, ...) |

Standard library used throughout: `sqlite3` (`store.py`), `ipaddress`
(`intel/lookup.py`, `detectors/recon.py`), `statistics`/`math` (`stats.py`,
`baseline.py`), `dataclasses`, `collections` (`Counter`, `defaultdict`),
`hashlib` (stable id generation in `engine.py`), `json`, `datetime`, `re`
(test file only), `abc`, `typing`.

No `numpy`, `pandas`, or `scikit-learn` — every statistic in `stats.py`
(coefficient of variation, Shannon entropy, EWMA, MAD-based outliers,
inter-arrival analysis) is implemented directly against `statistics`/`math`,
which is more than sufficient at the data volumes one machine's traffic log
produces.

No networking package (`requests`, `httpx`, `aiohttp`, `urllib.request`) is
imported anywhere in this package — see Part C's no-outbound-network-calls
constraint and `tests/threat/test_security_constraints.py::TestNoOutboundNetworkCalls`,
which greps the whole package for exactly that and fails the build if
anyone (including a future edit to this package) adds one.

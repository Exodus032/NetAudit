# Baseline snapshots and diff

Implements Part E8 of `docs/API_CONTRACT_V3.md`. A snapshot is a named,
timestamped capture of posture check results, the current traffic profile
(peers talked to, local listeners), and the composite security score, all
supplied by three small Protocols (`providers.py`) so this package never
imports `netaudit.posture`, `netaudit.threat`, or anything else outside
itself. Persisted to a `baselines` table in the shared SQLite file via
`netaudit.store.db.get_conn()` (allowed per the task's decoupling rules --
this package owns its own table, created lazily in `store.py`, and never
touches `store/db.py` itself).

## Diff semantics

`GET /api/baselines/{a}/diff/{b}` returns exactly the frozen contract shape
(`from`, `to`, `score_delta`, `checks.fixed`/`regressed`/`unchanged_count`,
`new_peers`, `new_listeners`, `removed_listeners`), plus three additive
fields under `checks` the contract doesn't show but that are necessary to
avoid a real correctness bug:

- `checks.added` -- a check id present in `to` but not `from`. **Never**
  counted as a regression, even though its current status might be `fail`
  -- it simply didn't exist to compare against in the older snapshot.
- `checks.removed` -- a check id present in `from` but not `to`. **Never**
  counted as a fix.
- `checks.inconclusive` -- a check id present in both, with a changed
  status, where either side is `error`/`skipped`. These carry no
  before/after security signal (an errored probe isn't "worse" than a
  passing one, it's just unknown), so they're excluded from
  `fixed`/`regressed`/`unchanged_count` rather than forced into one.

`fixed` vs. `regressed` is decided by a fixed badness order
`pass(0) < warn(1) < fail(2)`: moving to a lower rank is `fixed`, higher is
`regressed`, same rank is `unchanged`. This correctly handles `warn`
transitions (`pass -> warn` is a regression, `warn -> pass` is a fix), not
just the `pass`/`fail` case the contract's own example shows.

`score_delta.threats` is `0` (not a diff) when either snapshot didn't have
a threats score at capture time -- there is nothing genuine to subtract in
that case, and pretending otherwise would misrepresent the data. This is a
real, stated limitation, not silently glossed over.

## Decoupling

Three Protocols in `providers.py`:

- `PostureProvider.checks() -> Iterable[dict]` -- `{id, status}` per check.
- `TrafficProvider.peers() -> Iterable[str]` /
  `.listeners() -> Iterable[dict]` (`{port, process}` per listener).
- `ScoreProvider.security_score() -> dict` -- `{posture, threats, overall}`,
  `threats` optionally `None`.

Each has a `get_*_provider()` FastAPI dependency the orchestrator overrides
with real implementations, and a `Static*Provider` fake used by this
package's own tests.

## Testing

```
.\.venv\Scripts\python.exe -m pytest tests/baselines -q
```

Covers: fixed/regressed/unchanged classification (including `warn`
transitions), added/removed checks never miscounted as regressed/fixed,
inconclusive handling of `error`/`skipped` statuses, new/removed listener
and new-peer detection, score delta arithmetic (including the missing-
threats-score case), and the router contract shape via `TestClient` against
faked providers, including a 404 for an unknown baseline id in a diff.

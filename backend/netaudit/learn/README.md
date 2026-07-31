# NetAudit learning mode

Part D of `docs/API_CONTRACT_V3.md` (FROZEN -- do not edit that file).
Glossary, plain-language explanations of every detector/rule/check/metric,
a guided tour, structured lessons, and the D6 prioritised-findings
endpoint that answers "what should I fix first?".

The content is the product here. Everything else in this package exists to
serve, validate, and rank that content correctly.

## Layout

```
learn/
  __init__.py     exports router, LearnService, and the five Part D models
  models.py       Part D response shapes (pydantic), field-for-field
  content.py      loads + validates data/*.json at import time
  service.py      lookup/search over content, + FindingsProvider Protocol for D6
  prioritise.py   the D6 ranking algorithm -- pure, no I/O, table-driven
  router.py       the seven Part D endpoints, bare APIRouter, no prefix
  data/
    glossary.json       48 terms (D1's required list has 48 ids)
    explanations.json   83 entries: 22 detectors + 10 rules + 43 checks + 6 metrics
    tour.json           15 steps across all 6 views
    lessons.json        7 lessons, beginner -> advanced
```

## Decoupling from `threat`/`posture`/`rules`

No file under `learn/` imports `netaudit.threat`, `netaudit.posture`, or
`netaudit.rules` at module import time. Those packages are owned and
actively changed elsewhere; this router must keep working even if their
internals move.

- D1-D5 (glossary, explain, tour, lessons) are pure content -- they need
  nothing from those packages at all.
- D6 needs live data (current posture status, active recommendations,
  active threats). That's resolved through the `FindingsProvider` Protocol
  in `service.py`, which declares three methods --
  `posture_checks()`/`recommendations()`/`threats()`, each returning plain
  `list[dict]` -- and the `get_findings_provider` FastAPI dependency in
  `router.py`, which the orchestrator overrides with the real
  implementation (`app.dependency_overrides[get_findings_provider] =
  lambda: real_provider`, or by setting `app.state.learn_findings_provider`).
  `StaticFindingsProvider` is the fixed, in-memory implementation used by
  every test in this package and by local development.
- The only place this package imports the real registries at all is
  `backend/tests/learn/test_coverage.py`, and only through
  `pytest.importorskip` -- if `netaudit.threat`/`.posture`/`.rules` can't be
  imported for any reason (mid-refactor, a missing dependency), those tests
  skip cleanly instead of failing this package's suite for someone else's
  work in progress.

## The content model

Every data file is a JSON object with one top-level array (`terms`,
`explanations`, `steps`, or `lessons`). `content.py` loads all four,
validates every entry against its pydantic model in `models.py`, and
cross-checks references between them -- all at **import time**, not on
first request. If a data file is malformed, references something that
doesn't exist, or contains obvious placeholder text (`TODO`, `TBD`,
`FIXME`, `lorem ipsum`), importing `netaudit.learn` raises immediately.
That's deliberate: broken content should fail loudly in CI/at startup, not
serve garbage to a student.

### Adding a glossary term

1. Add an entry to `data/glossary.json`'s `terms` array with all required
   fields (`id`, `term`, `short`, `detail`, `why_it_matters`, `see_also`,
   `category`, `difficulty`; `expansion` is optional -- omit or `null` it
   for a term that isn't an acronym).
2. Every id in `see_also` must already exist in the file (or be added in
   the same change) -- a dangling reference fails validation at import.
3. `category` is one of `protocol | security | networking | tool`;
   `difficulty` is one of `beginner | intermediate | advanced`.
4. Run `pytest tests/learn/test_data_glossary.py` -- it re-validates the
   whole file and fails listing exactly what's wrong (duplicate id,
   dangling `see_also`, placeholder text, missing required D1 coverage).

### Adding an explanation (detector, rule, check, or metric)

1. **Read the actual implementation first.** Every explanation in
   `explanations.json` was written from the real `evaluate()`/detector
   source, not from the category README summary alone -- a mechanism
   description that doesn't match the code is worse than no explanation.
2. Add an entry to `data/explanations.json`'s `explanations` array:
   `kind` (`detector|rule|check|metric|field`), `id` (matching the real
   registry id exactly), `title`, `plain`, `how_it_decides`,
   `what_would_make_it_wrong` (a *real*, specific reason the finding might
   not mean what it looks like -- not a generic hedge), optionally
   `worked_example` (`scenario` + a `walkthrough` list of strings -- for a
   detector or rule this should be genuine, checkable arithmetic against
   the real thresholds; for a check it's fine to be a single crisp
   "this observed value -> this verdict" line rather than padded to more
   steps that add no information), `glossary_terms` (every id must already
   exist in `glossary.json`), and optionally `learn_more` (a MITRE
   ATT&CK tactic/technique id, or a CIS control reference, where one
   genuinely applies -- omit it rather than inventing one).
3. If it's a detector/rule/check id, run
   `pytest tests/learn/test_coverage.py` -- it imports the real
   `netaudit.threat.detectors` / `netaudit.rules.builtin` /
   `netaudit.posture.registry` registries and fails listing any id with no
   explanation, and any explanation for an id no longer in the registry
   (stale content).
4. Run `pytest tests/learn/test_data_explanations.py` for the rest
   (placeholder text, dangling glossary references, per-kind counts).

### Adding a tour step

Add an entry to `data/tour.json`'s `steps` array: `id`, `order` (must sort
to a contiguous 1..N sequence across the whole file), `view` (one of
`overview | traffic-log | connections | recommendations | posture |
threats`), `target` (a non-empty CSS selector the frontend attaches via a
`data-tour` attribute), `title`, `body`, `glossary_terms`, and
`action_hint` (`null`, or a short first-person instruction like "try
filtering by protocol"). The full tour must cover all six views at least
once and have at least 12 steps -- `test_data_tour.py` enforces both.

### Adding a lesson

Add an entry to `data/lessons.json`'s `lessons` array: `id`, `title`,
`summary`, `difficulty`, `estimated_minutes`, `prerequisites` (a list of
other lesson ids -- every one must exist, and the whole prerequisite graph
must stay acyclic), `objectives`, `steps` (each with `order`,
`instruction`, `explanation`, a `check` of `{"kind": "view_visited" |
"filter_applied" | "element_clicked" | "manual", "value": "..."}`, and
`glossary_terms`), and `uses_live_data` (whether the lesson's steps are
meant to be worked through against the user's own captured traffic, or are
conceptual/reference-only). `test_data_lessons.py` enforces the DAG
property, sequential step ordering, and glossary reference validity;
`content.py` itself also detects a cycle and raises at import time, so a
genuinely broken prerequisite graph fails before any test even runs.

## D6: how prioritisation actually works

`prioritise.py` is a pure function, `rank(items) -> list[RankedItem]`, with
no I/O and no dependency on the real posture/threat/rules packages --
everything it needs arrives as plain dicts (see the `FindingsProvider`
docstring in `service.py` for the expected shape). The formula is
documented in full in `prioritise.py`'s module docstring; in short:

```
impact_score = clamp(
    round(SEVERITY_BASE[severity] * multiplier)
    + EFFORT_BONUS[effort]
    + ATTACK_PATH_BONUS.get(id, 0),
    0, 100,
)
```

- `multiplier` is the posture `status` (`fail` = 1.0, `warn` = 0.6) for
  posture items, or `confidence` (0-1) for recommendations/threats.
- `EFFORT_BONUS` is a small, deliberately modest nudge (+-10) so a cheap
  fix outranks an equally severe expensive one without letting effort
  override a real severity gap.
- `ATTACK_PATH_BONUS` is a small, explicit, commented table for findings
  that are themselves well-known, credential-free attack paths (SMB
  signing, LLMNR/NTLM capture, blank passwords, and similar) -- not a
  hidden fudge factor, and most ids correctly get 0.

Ties are broken, in order, by severity rank, then source priority
(`threat > posture > recommendation`), then `id` ascending -- so the same
input always produces the same ranking regardless of input order.

`LearnService.prioritised_findings()` is the layer above `rank()` that
actually calls the injected `FindingsProvider`, filters posture checks
down to `fail`/`warn` only (a `pass`/`error`/`skipped` check is not a
finding), and tags each item with its `source` before handing the combined
list to `rank()`.

## Testing

```
.venv\Scripts\python.exe -m pytest tests/learn -q
```

- `test_data_*.py` -- each data file loads, validates, has no placeholder
  text, and its internal references (see_also, glossary_terms,
  prerequisites) all resolve.
- `test_content_validation.py` -- exercises `content.py`'s own validation
  logic against deliberately broken fixture data (placeholder text,
  dangling references, a prerequisite cycle), independent of whatever the
  real shipped data currently looks like.
- `test_coverage.py` -- guarded-import tests against the real
  `netaudit.threat`/`netaudit.posture`/`netaudit.rules` registries; skips
  cleanly if those packages can't be imported.
- `test_prioritise.py` -- hand-computed `impact_score` values checked
  against the documented formula, the full worked ranking for a realistic
  mixed posture/recommendation scenario, deterministic tie-breaking, and
  empty/single-item inputs.
- `test_service.py` -- `LearnService` lookups and the D6
  filter-then-rank pipeline via `StaticFindingsProvider`, including the
  all-clear (nothing failing/warning) case.
- `test_router.py` -- `TestClient` over the real router, asserting every
  Part D response shape field-for-field, 404 on an unknown glossary/explain
  /lesson id, and 400 on an unrecognised `explain` kind.

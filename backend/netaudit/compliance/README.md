# Compliance mapping

Implements Part F1/F2 of `docs/API_CONTRACT_V3.md`: maps NetAudit's 43
posture checks (`netaudit/posture/README.md`) to real control identifiers in
three frameworks, and combines multiple check results into one control
status.

## Honesty over completeness

This is the governing rule for every file under `data/`: a wrong control
number in a compliance report is worse than an absent one. Concretely:

- Every `control_id` is either given directly by the frozen API contract
  (`2.3.9.2` for SMB signing), or was cross-checked against multiple
  independently published excerpts of the relevant benchmark before being
  included.
- Where a check exists but no control identifier could be verified with
  confidence, the check is simply **not mapped** in that framework, rather
  than assigned a guessed identifier. `coverage_note` in each data file says
  so explicitly and lists what's missing and why.
- `not_assessed` is the status whenever the mapped check(s) return no
  evidence (missing from the provider, or status `error`/`skipped`) --
  never inferred as a `pass`. See `service._combine()`.

## Why CIS Windows 11 is the smallest of the three

CIS Windows benchmark sub-section numbering (`2.3.x.y`, `9.x.y`, `18.x.y...`)
is **not stable across benchmark revisions** -- verified during this build
by comparing published excerpts of the same setting across benchmark
versions v1.x through v5.x. Examples of drift actually observed while
researching this file:

- "Remote Registry" service disable: numbered `5.21` in one Windows 11
  Enterprise v4.0.0 excerpt, `5.24` in a v5.0.0 Stand-alone excerpt, `5.25`
  in a Level-2/BitLocker variant, and `81.21` in the Intune settings-catalog
  numbering (a different product entirely). Excluded from `cis_win11.json`
  -- not confident enough in any single number.
- RDP Network Level Authentication: `18.9.65.3.9.4` (Windows 11 Intune v1),
  `18.10.57.3.9.4` (Server 2016), `18.9.59.3.9.4` (Windows 10 v1.8.1) --
  three different numbers for the same setting across products/versions.
  Excluded.
- WinRM "Allow unencrypted traffic": `18.10.89.1.2`/`18.10.89.2.3` in one
  Windows 11 excerpt vs. `18.9.102.2.2` in a Server 2022/Azure excerpt.
  Excluded.
- Guest account status: `2.3.1.1` vs `2.3.1.3` across sources, with the
  `2.3.1.1` hit coming from an Intune-profile numbering that isn't directly
  comparable to the mainline Enterprise benchmark numbering the contract's
  `v3.0.0` label implies. Excluded.

Against that backdrop, the 11 controls actually included in
`data/cis_win11.json` were kept because the same number showed up
consistently across several independent, differently-formatted sources
(Windows 10, Windows 11, and Server excerpts alike), which is the strongest
signal available without a primary-source PDF of the exact `v3.0.0`
release in hand:

| control_id | setting | confidence |
|---|---|---|
| `2.3.9.2` | SMB signing (server) | given directly by the frozen API contract's own F2 example |
| `2.3.17.6` | UAC: run all administrators in Admin Approval Mode | consistent across several Windows 8/8.1/2012 R2/11 excerpts |
| `9.1.1` / `9.2.1` / `9.3.1` | Firewall state, Domain/Private/Public | this exact section-9 layout has been stable for many years across Windows 10/11/Server 2016/2019/2022 benchmarks |
| `9.1.2` / `9.2.2` / `9.3.2` | Inbound connections (Block), Domain/Private/Public | `9.1.2` directly confirmed; `.2`/`.3` profiles follow the same, independently-confirmed pattern |
| `9.1.9` | Domain logging: log dropped packets | confirmed as a pair (`9.1.9`/`9.1.10`) from one coherent source; private/public logging digits were **not** independently confirmed to the same offset, so only the Domain profile control is included |
| `18.6.4.4` | Turn off multicast name resolution (LLMNR) | one Windows-11-labeled source, but the setting itself and its `18.6.x` neighborhood is well documented |
| `18.6.19.2.1` | Disable IPv6 (`DisabledComponents`) | confirmed consistently across four separate Windows 11 excerpts (Level 2) |

Everything else in the 43-check catalogue is left out of `cis_win11.json`
entirely for this reason. **If you have the actual CIS Microsoft Windows 11
Benchmark v3.0.0 PDF, verifying (and correcting, if needed) every ID above
against it, and extending coverage to more checks, would be the single
highest-value follow-up to this package.**

## NIST SP 800-53 Rev. 5

Far less version-sensitive: control IDs (`AC-17`, `SC-7`, `SI-3`, ...) and
titles are the stable, canonical Rev. 5 catalogue and don't drift the way
CIS sub-sections do. All 43 checks are mapped, grouped under 18 controls
across the AC/AU/CM/IA/SC/SI families. This is still an *indicative*
crosswalk -- a real ATO needs organizational/procedural evidence this tool
can never see -- not a certified one, and `coverage_note` says so.

## ACSC Essential Eight

The 8 top-level strategies have no ACSC-published numeric identifiers, so
`control_id` is a stable slug of the strategy name (`patch_operating_systems`,
not an invented number). All 8 strategies are represented as controls, so a
caller sees the full standard's shape -- but only **2** of them
(`patch_operating_systems`, `restrict_administrative_privileges`) have any
mapped check_ids; the other 6 always resolve to `not_assessed` by
construction, because network-facing host configuration genuinely cannot
see application control, application patching, MFA, Office macro settings,
user application hardening, or backups. That's transparency about a real
tool limitation, not a bug.

## Combination logic

See `service._combine()`. A control's status is computed from the set of
its mapped checks' statuses, restricted to `pass`/`warn`/`fail` (a check
that's missing from the provider, or has status `error`/`skipped`,
contributes no evidence):

- no evidence at all -> `not_assessed`
- every assessed check is `pass` -> `pass`
- every assessed check is `fail` -> `fail`
- anything else (mixed, or any `warn` present) -> `partial`

## Decoupling

`providers.py` defines `PostureProvider` (a `Protocol` with one method,
`checks() -> Iterable[dict]`, each dict needing only `id` and `status`).
This package never imports `netaudit.posture`. `get_posture_provider()` is
the FastAPI dependency the orchestrator overrides with the real posture
service; `StaticPostureProvider` is the fake used by this package's own
tests and by the done-criteria verification run.

## Testing

```
.\.venv\Scripts\python.exe -m pytest tests/compliance -q
```

- `test_data_validation.py`: every data file's JSON shape is valid; every
  `check_id` referenced is a real posture check id (guarded import of
  `netaudit.posture`, `pytest.skip`s if unavailable rather than failing);
  no dangling/duplicate references; every framework has a non-empty
  `coverage_note`.
- `test_combination_logic.py`: `pass`/`fail`/`partial`/`not_assessed`
  combination rules, including `not_assessed` propagation from missing or
  errored evidence -- and confirms `not_assessed` never becomes `pass`.
- `test_router.py`: `GET /api/compliance/frameworks` and
  `GET /api/compliance/{id}` via `TestClient` against a faked
  `PostureProvider`, asserting the contract shape field-for-field,
  including the disclaimer and a 404 for an unknown framework id.

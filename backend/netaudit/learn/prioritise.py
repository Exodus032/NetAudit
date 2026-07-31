"""D6 prioritisation: one deterministic, explainable ranking over posture
checks, hygiene recommendations and threats.

This module is pure -- `rank(items)` takes plain dicts in, returns plain
dicts out, no I/O, no imports from `netaudit.posture`/`netaudit.threat`/
`netaudit.rules`. `service.py` is the only caller that knows about a
`FindingsProvider`; everything here is unit-testable with hand-built input.

## Expected input shape

Each item passed to `rank()` is a plain dict with:

- `id` (str) -- stable id, unprefixed (e.g. `"smb_signing_required"`).
- `source` (`"posture" | "recommendation" | "threat"`)
- `title` (str)
- `severity` (`"critical"|"high"|"medium"|"low"|"info"`) -- for posture this
  is the check's static severity (the risk *if* it fails), not derived from
  status.
- `status` (str, posture only) -- `"fail"` or `"warn"`. Only failing/warning
  posture checks should be passed in at all; a `pass`/`error`/`skipped`
  check is not a finding and the caller should filter it out before calling
  `rank()` (`service.py` does this).
- `confidence` (float 0-1, optional, recommendation/threat) -- how sure the
  detector/rule is. Defaults to 1.0 when absent (posture checks are direct
  measurements, not probabilistic, so they don't carry this field at all).
- `effort` (`"low"|"medium"|"high"`, optional) -- cost of applying the fix.
  Defaults to `"medium"` when the caller doesn't know. `service.py`'s
  real-world callers are expected to supply this from the actual
  remediation shape (one command vs. several, admin-only vs. not,
  hardware/physical-access requirements).
- `one_line_fix` (str, optional) -- short human fix description.
- `deep_link_view` (str, optional) -- defaults from `source`.

## The formula

`impact_score = clamp(round(SEVERITY_BASE[severity] * multiplier)
                       + EFFORT_BONUS[effort]
                       + ATTACK_PATH_BONUS.get(id, 0), 0, 100)`

- `SEVERITY_BASE` sets the floor: how bad is this class of problem at all.
- `multiplier` softens the score for signals that are not a hard, confirmed
  fact: a posture `warn` (0.6 -- a real but softer finding, by design; see
  `posture/README.md`'s "fail vs warn" section) or a detector/rule's
  `confidence` (0-1, used as-is for `recommendation`/`threat`).
- `EFFORT_BONUS` is what makes this "favour... low effort", not just
  severity: a cheap fix is nudged up, an expensive one nudged down, without
  letting effort override a real severity gap (the swing is +-10, well
  under one severity band).
- `ATTACK_PATH_BONUS` is a small, explicit, documented table (not a hidden
  fudge factor) for findings that are themselves a well-known, credential-
  free attack path -- SMB relay via missing signing, LLMNR/NTLM hash
  capture via Responder-style poisoning, a service reachable from any
  network. Items not listed get 0; this is additive evidence, not a
  replacement for severity.

Worked check: `smb_signing_required` -- posture, severity high (base 72),
status fail (x1.0), effort low (+10), and it's in `ATTACK_PATH_BONUS` for
the reason above (+5) -- scores 87. The contract's D6 example shows this
same check at 82 (the 72+10 arithmetic without a bonus table); that example
is illustrative shape, not a binding number, and this module's own
worked-out arithmetic is documented here and in `test_prioritise.py` rather
than reverse-fitted to match it.

## Ranking and ties

Sorted by `impact_score` descending. Ties are broken, in order, by:
1. severity rank (critical > high > medium > low > info)
2. source priority (`threat` > `posture` > `recommendation` -- an actively
   observed behaviour outranks a static gap, which outranks generic hygiene
   advice, at equal score)
3. `id` ascending (final, arbitrary-but-stable tiebreak so output order
   never depends on input order or dict hashing)
"""
from __future__ import annotations

from typing import Optional, TypedDict

SEVERITY_BASE: dict[str, int] = {
    "critical": 92,
    "high": 72,
    "medium": 50,
    "low": 28,
    "info": 10,
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

STATUS_MULTIPLIER: dict[str, float] = {
    "fail": 1.0,
    "warn": 0.6,
}

EFFORT_BONUS: dict[str, int] = {
    "low": 10,
    "medium": 0,
    "high": -10,
}

SOURCE_TIEBREAK_RANK: dict[str, int] = {
    "threat": 2,
    "posture": 1,
    "recommendation": 0,
}

DEFAULT_VIEW_FOR_SOURCE: dict[str, str] = {
    "posture": "posture",
    "recommendation": "recommendations",
    "threat": "threats",
}

# Explicit, small, documented table of findings that are themselves a
# well-known attack path exploitable with no special access (no valid
# credentials, no prior foothold, no physical access) -- not a general
# severity multiplier, an additive nudge for the specific, named reason in
# each comment. Anything not listed here gets 0, which is the correct
# default, not a gap: most findings are real risks without being a single
# famous named technique.
ATTACK_PATH_BONUS: dict[str, int] = {
    # SMB relay/tamper against an unsigned session needs only network
    # position, no credentials -- the textbook use of Responder/ntlmrelayx.
    "smb_signing_required": 5,
    "smb1_disabled": 6,  # EternalBlue-class remote code execution, no auth.
    # LLMNR/NetBIOS poisoning (Responder) captures NTLM hashes from any
    # broadcast name lookup -- one of the single most common initial-access
    # techniques on a flat network, and needs no credentials to start.
    "llmnr_disabled": 5,
    "netbios_disabled": 3,
    # An unauthenticated blank-password or auto-logon account is a login,
    # not an exploit -- as close to "walk in the front door" as this
    # catalogue gets.
    "blank_passwords": 6,
    "autologon_disabled": 5,
    "guest_account_disabled": 3,
    # A directly reachable high-risk legacy port (SMB/RDP/Telnet/FTP/...) is
    # a standing, internet-scanned-for target the moment it's reachable.
    "high_risk_ports_open": 5,
    "rdp_disabled_or_nla": 4,
    # WPAD lets whoever answers first on the segment hand this machine a
    # malicious proxy -- needs network position but no credentials.
    "wpad_disabled": 3,
    # An open/WEP Wi-Fi network is decryptable/joinable by anyone in range.
    "wifi_encryption_strength": 4,
    "wifi_autoconnect_open": 4,
    # A listener reachable from any interface, not just localhost -- the
    # hygiene-rule equivalent of high_risk_ports_open.
    "listening_exposed": 4,
    # SSL 3.0 (POODLE) is a fully broken protocol with public tooling.
    "ssl3_disabled": 4,
}


class RankedItem(TypedDict):
    id: str
    source: str
    title: str
    severity: str
    impact_score: int
    effort: str
    priority_rank: int
    why_first: str
    one_line_fix: str
    deep_link: dict


def _multiplier(item: dict) -> float:
    if item["source"] == "posture":
        status = item.get("status", "fail")
        return STATUS_MULTIPLIER.get(status, 1.0)
    confidence = item.get("confidence")
    if confidence is None:
        return 1.0
    return max(0.0, min(1.0, float(confidence)))


def impact_score(item: dict) -> int:
    """The pure per-item scoring function -- exposed on its own so a test
    can assert on a single hand-computed number without going through the
    whole list/ranking machinery."""
    severity = item["severity"]
    base = SEVERITY_BASE[severity]
    multiplier = _multiplier(item)
    effort = item.get("effort", "medium")
    bonus = ATTACK_PATH_BONUS.get(item["id"], 0)
    score = round(base * multiplier) + EFFORT_BONUS[effort] + bonus
    return max(0, min(100, score))


def _why_first(item: dict, score: int) -> str:
    severity = item["severity"]
    effort = item.get("effort", "medium")
    bonus = ATTACK_PATH_BONUS.get(item["id"], 0)
    status = item.get("status")

    severity_phrase = {
        "critical": "Critical severity",
        "high": "High severity",
        "medium": "Medium severity",
        "low": "Low severity",
        "info": "Informational",
    }[severity]
    effort_phrase = {
        "low": "a low-effort fix",
        "medium": "a moderate-effort fix",
        "high": "a high-effort fix",
    }[effort]
    parts = [f"{severity_phrase} and {effort_phrase}."]
    if status == "warn":
        parts.append("Currently a soft warning, not a confirmed failure, which is why it ranks below equivalent hard fails.")
    if bonus >= 5:
        parts.append("It closes a well-known attack path that needs no special access (no credentials, no foothold) to exploit.")
    elif bonus > 0:
        parts.append("It reduces exposure to a known, commonly-abused attack technique on this network.")
    return " ".join(parts)


def _view_for(item: dict) -> str:
    return item.get("deep_link_view") or DEFAULT_VIEW_FOR_SOURCE[item["source"]]


def _sort_key(item: dict, score: int) -> tuple:
    return (
        -score,
        -SEVERITY_RANK[item["severity"]],
        -SOURCE_TIEBREAK_RANK.get(item["source"], 0),
        item["id"],
    )


def rank(items: list[dict]) -> list[RankedItem]:
    """Rank findings from posture/recommendation/threat sources. Pure,
    deterministic: the same input list (in any order) always produces the
    same output list with the same `priority_rank` values."""
    scored = [(item, impact_score(item)) for item in items]
    scored.sort(key=lambda pair: _sort_key(pair[0], pair[1]))

    ranked: list[RankedItem] = []
    for i, (item, score) in enumerate(scored, start=1):
        ranked.append(
            RankedItem(
                id=f"{item['source']}:{item['id']}",
                source=item["source"],
                title=item["title"],
                severity=item["severity"],
                impact_score=score,
                effort=item.get("effort", "medium"),
                priority_rank=i,
                why_first=_why_first(item, score),
                one_line_fix=item.get("one_line_fix") or "See the deep link for the exact remediation steps.",
                deep_link={"view": _view_for(item), "id": item["id"]},
            )
        )
    return ranked

"""explanations.json: loads, validates against Explanation, no placeholder
text, every glossary_terms reference resolves, and the expected counts per
kind (22 detectors, 10 rules, 43 checks, 6 metrics) are present -- the
*real* registry coverage check (does every live detector/rule/check id have
an entry) lives in test_coverage.py with a guarded import, not here."""
from __future__ import annotations

from netaudit.learn import content
from netaudit.learn.models import Explanation

BANNED = ("TODO", "TBD", "FIXME", "lorem ipsum")


def test_explanations_load_and_validate():
    assert len(content.EXPLANATIONS) >= 80
    for exp in content.EXPLANATIONS.values():
        assert isinstance(exp, Explanation)


def test_kind_counts_match_the_catalogue_sizes():
    by_kind: dict[str, int] = {}
    for (kind, _id) in content.EXPLANATIONS:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    assert by_kind.get("detector") == 22
    assert by_kind.get("rule") == 10
    assert by_kind.get("check") == 43
    assert by_kind.get("metric") == 6


def test_required_metric_ids_present():
    # D3: "Metrics that need explaining (throughput_bps, coefficient of
    # variation, entropy, confidence, severity, risk) go under kind=metric."
    required = {"throughput_bps", "coefficient_of_variation", "entropy", "confidence", "severity", "risk"}
    present = {mid for (kind, mid) in content.EXPLANATIONS if kind == "metric"}
    assert required <= present


def test_no_placeholder_or_empty_text():
    for (kind, item_id), exp in content.EXPLANATIONS.items():
        for field_name in ("title", "plain", "how_it_decides", "what_would_make_it_wrong"):
            value = getattr(exp, field_name)
            assert value and value.strip(), f"{kind}/{item_id}.{field_name} is empty"
            for marker in BANNED:
                assert marker.lower() not in value.lower(), f"{kind}/{item_id}.{field_name} has placeholder text"


def test_every_glossary_term_reference_resolves():
    for (kind, item_id), exp in content.EXPLANATIONS.items():
        for term in exp.glossary_terms:
            assert term in content.GLOSSARY, f"{kind}/{item_id} references missing glossary term {term!r}"


def test_worked_examples_have_a_scenario_and_nonempty_steps():
    # Detectors and rules measure something numeric (a CV, a byte count, a
    # ratio against a threshold) and so should show real, multi-line
    # arithmetic per the D3 quality bar. A posture check's worked example
    # is often honestly a single crisp "this value -> this verdict" read --
    # padding those to a second line would be filler, not more information,
    # so only detectors/rules are held to the >=2-step bar.
    for (kind, item_id), exp in content.EXPLANATIONS.items():
        if exp.worked_example is None:
            continue
        assert exp.worked_example.scenario.strip()
        min_steps = 2 if kind in ("detector", "rule") else 1
        assert len(exp.worked_example.walkthrough) >= min_steps, f"{kind}/{item_id} worked_example has too few steps"
        for line in exp.worked_example.walkthrough:
            assert line.strip()


def test_detectors_have_worked_examples_or_document_why_not():
    # rogue_dhcp, known_bad_peer, tor_or_proxy, suspicious_tls, new_external_peer
    # legitimately have no meaningful numeric worked example (lookup-only or
    # "cannot fire" detectors) -- everything else measures something and
    # should show its arithmetic.
    no_example_expected = {
        "rogue_dhcp", "known_bad_peer", "tor_or_proxy", "suspicious_tls", "new_external_peer",
    }
    for (kind, item_id), exp in content.EXPLANATIONS.items():
        if kind != "detector":
            continue
        if item_id in no_example_expected:
            continue
        assert exp.worked_example is not None, f"detector {item_id} should have a worked_example"


def test_no_duplicate_kind_id_pairs():
    keys = list(content.EXPLANATIONS.keys())
    assert len(keys) == len(set(keys))

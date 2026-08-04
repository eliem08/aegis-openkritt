"""Bounty economics: min bounty, likely gain, agreement-weighted expected value."""

from __future__ import annotations

from aegis.ai.economics import agreement_confidence, enrich_row, estimate


def test_estimate_uses_program_table():
    e = estimate(vuln_type="CWE-287", severity="high", handle="matomo")
    assert e.min_bounty == 777 and e.top_bounty == 1777
    assert e.vuln_type == "CWE-287" and e.severity == "high"


def test_unknown_program_falls_back_to_default():
    e = estimate(vuln_type="CWE-89", severity="critical", handle="nobody")
    assert e.min_bounty == 2000 and e.top_bounty == 10000


def test_agreement_confidence_scales():
    assert agreement_confidence(5, 5) == 1.0
    assert agreement_confidence(1, 5) < agreement_confidence(4, 5)
    assert agreement_confidence(1, 5) >= 0.2                # a lone flag isn't zeroed
    assert agreement_confidence(1, 1) == 0.6                # single agent = neutral


def test_expected_gain_rises_with_agreement():
    lo = estimate(vuln_type="x", severity="high", handle="matomo", agreement=1, samples=5)
    hi = estimate(vuln_type="x", severity="high", handle="matomo", agreement=5, samples=5)
    assert hi.expected_gain > lo.expected_gain
    # sanity: expected gain is a discounted fraction of the likely bounty
    assert 0 < hi.expected_gain < hi.likely_bounty


def test_estimate_dict_shape_has_the_money_fields():
    d = estimate(vuln_type="CWE-639", severity="high", handle="matomo",
                 agreement=4, samples=5).as_dict()
    assert set(d) >= {"vuln_type", "severity", "min_bounty", "likely_bounty",
                      "top_bounty", "agreement", "confidence", "expected_gain"}
    assert d["agreement"] == "4/5 agents"


def test_enrich_row_attaches_economics():
    row = {"json_answer": {"vulnerability_type": "CWE-352", "severity": "medium"},
           "agreement": 3, "samples": 5, "severity": "medium"}
    out = enrich_row(row, handle="matomo")
    assert out["economics"]["min_bounty"] == 333
    assert out["economics"]["agreement"] == "3/5 agents"

import pytest

from aegis.knowledge import enrich_candidate, normalized_prior, reprioritize_finding
from aegis.model import Candidate, Finding, SSVCDecision


def test_normalized_prior_top_is_one(insights):
    # CWE-639 is the most common url weakness -> normalized prior 1.0
    assert normalized_prior(insights, "CWE-639", asset_type="url") == 1.0
    assert normalized_prior(insights, "CWE-000", asset_type="url") == 0.0


def test_enrich_raises_common_weakness(insights):
    cand = Candidate(asset="api.acme.test", cwe="CWE-639", p_exploit=0.5)
    enriched = enrich_candidate(cand, insights, weight=0.4, asset_type="url")
    # blended toward normalized prior 1.0: 0.6*0.5 + 0.4*1.0 = 0.7
    assert enriched.p_exploit == pytest.approx(0.7)


def test_enrich_noop_for_unseen_weakness(insights):
    cand = Candidate(asset="x", cwe="CWE-000", p_exploit=0.5)
    assert enrich_candidate(cand, insights, asset_type="url").p_exploit == 0.5


def test_enrich_noop_without_cwe(insights):
    cand = Candidate(asset="x", cwe="", p_exploit=0.5)
    assert enrich_candidate(cand, insights).p_exploit == 0.5


def test_reprioritize_finding_recomputes(insights):
    f = Finding(
        asset="api.acme.test", cwe="CWE-639",
        p_exploit=0.5, business_impact=0.9, asset_criticality=0.9, confidence=0.9,
    )
    before = f.p_exploit
    out = reprioritize_finding(f, insights, weight=0.4, asset_type="url")
    assert out.p_exploit > before
    # priority recomputed from the new p_exploit
    assert out.priority == pytest.approx(out.p_exploit * 0.9 * 0.9 * 1.0 * 0.9)
    assert out.ssvc in (SSVCDecision.ACT, SSVCDecision.ATTEND, SSVCDecision.TRACK)


def test_weight_must_be_valid(insights):
    cand = Candidate(asset="x", cwe="CWE-639")
    with pytest.raises(ValueError):
        enrich_candidate(cand, insights, weight=1.5, asset_type="url")

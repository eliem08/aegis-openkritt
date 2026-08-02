from aegis.model import FindingStatus
from aegis.orchestrator import triage


def test_reproducible_candidate_becomes_verified_finding(make_candidate, make_evidence):
    ev = make_evidence(reproducible=True, confidence=0.8)
    cand = make_candidate(evidence_id=ev.evidence_id, confidence=0.8)
    result = triage([cand], {ev.evidence_id: ev})
    assert len(result.findings) == 1
    assert result.hypotheses == []
    f = result.findings[0]
    assert f.status == FindingStatus.VERIFIED
    assert f.exploit_proof_ref == ev.evidence_id
    assert f.request_sequence  # pulled from evidence steps


def test_candidate_without_evidence_is_hypothesis(make_candidate):
    cand = make_candidate(evidence_id=None)
    result = triage([cand], {})
    assert result.findings == []
    assert len(result.hypotheses) == 1


def test_candidate_with_non_reproducible_evidence_is_hypothesis(make_candidate, make_evidence):
    ev = make_evidence(reproducible=False)  # no canary
    cand = make_candidate(evidence_id=ev.evidence_id)
    result = triage([cand], {ev.evidence_id: ev})
    assert result.findings == []
    assert len(result.hypotheses) == 1


def test_low_confidence_reproducible_is_finding_but_not_verified(make_candidate, make_evidence):
    ev = make_evidence(reproducible=True, confidence=0.3)
    cand = make_candidate(evidence_id=ev.evidence_id, confidence=0.3)
    result = triage([cand], {ev.evidence_id: ev})
    assert len(result.findings) == 1
    assert result.findings[0].status == FindingStatus.CANDIDATE


def test_duplicate_candidates_collapse(make_candidate, make_evidence):
    ev1 = make_evidence()
    ev2 = make_evidence()
    c1 = make_candidate(evidence_id=ev1.evidence_id, confidence=0.6)
    c2 = make_candidate(evidence_id=ev2.evidence_id, confidence=0.9)  # same fingerprint
    result = triage([c1, c2], {ev1.evidence_id: ev1, ev2.evidence_id: ev2})
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.duplicate_count == 2
    assert f.confidence == 0.9  # highest-confidence representative kept


def test_findings_sorted_by_priority(make_candidate, make_evidence):
    ev_lo = make_evidence()
    ev_hi = make_evidence()
    lo = make_candidate(evidence_id=ev_lo.evidence_id, cwe="CWE-200", route="/lo", confidence=0.3, business_impact=0.2)
    hi = make_candidate(evidence_id=ev_hi.evidence_id, cwe="CWE-639", route="/hi", confidence=0.9, business_impact=0.9)
    result = triage([lo, hi], {ev_lo.evidence_id: ev_lo, ev_hi.evidence_id: ev_hi})
    assert [f.route for f in result.findings] == ["/hi", "/lo"]

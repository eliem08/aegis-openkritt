from datetime import datetime, timezone
from decimal import Decimal

from aegis.graph.model import AssetKind, new_observation
from aegis.model.finding import Candidate
from aegis.nextgen import EventType
from aegis.nextgen_bridge import IntelligenceRuntime, opportunity_from_candidate


def test_existing_observations_and_candidates_flow_into_runtime():
    runtime = IntelligenceRuntime(scope_id="scope", engagement_id="eng")
    observation = new_observation(
        engagement_id="eng", scan_id="s", task_id="t", asset_key="domain:example.com",
        kind=AssetKind.DOMAIN, source="subfinder", data={"hostname": "example.com"},
        observed_at=datetime.now(timezone.utc),
    )
    emitted = runtime.ingest_observation(observation)
    assert emitted[0].type == EventType.DOMAIN
    assert "domain:example.com" in runtime.graph.nodes

    candidate = Candidate(asset="repo", code_location="app.py:9", cwe="CWE-78",
                          worker="semgrep", confidence=.8, p_exploit=.7,
                          evidence_id="evidence-1")
    event = runtime.ingest_candidate(candidate)
    assert event.payload["validation_status"] == "unverified"
    assert candidate.candidate_id in runtime.lifecycles

    score = opportunity_from_candidate(
        candidate, expected_bounty=Decimal("2000"), duplicate_risk=.2,
        model_cost=Decimal("5"), review_cost=Decimal("10"))
    assert score.profitable and score.net_ev > 0

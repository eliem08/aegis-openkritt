from __future__ import annotations

from aegis.ai.jarvis.hunt_generator import generate_hunt_candidates, infer_surfaces
from aegis.ai.jarvis.hunt_lanes import lane_for_family
from aegis.ai.jarvis.severity_portfolio import SeverityPortfolioPolicy, select_diverse_candidates
from aegis.ai.jarvis.universal_mission import compile_candidate_mission
from aegis.ai.jarvis.weakness_catalog import HuntCandidate, SeverityTier, UNIVERSAL_FAMILIES


def _family(family_id: str):
    return next(family for family in UNIVERSAL_FAMILIES if family.family_id == family_id)


def _candidate(family_id: str, severity: SeverityTier, payout: float) -> HuntCandidate:
    return HuntCandidate(
        family=_family(family_id),
        surface=_family(family_id).surfaces[0],
        severity=severity,
        expected_payout_usd=payout,
        p_valid=0.9,
        p_accepted=0.9,
        p_unique=0.9,
        p_reproducible=0.9,
        validation_cost_usd=1.0,
        novelty_score=0.8,
        chainability=0.7,
        coverage_gap=0.8,
    )


def test_severity_portfolio_reserves_low_and_medium_capacity() -> None:
    highs = [_candidate("injection", SeverityTier.HIGH, 5000.0 + index) for index in range(12)]
    lows = [_candidate("privacy", SeverityTier.LOW, 500.0 + index) for index in range(3)]
    mediums = [_candidate("workflow", SeverityTier.MEDIUM, 1500.0 + index) for index in range(4)]
    selected = select_diverse_candidates(
        [*highs, *lows, *mediums],
        SeverityPortfolioPolicy(max_items=10),
    )
    severities = [candidate.severity for candidate in selected]
    assert severities.count(SeverityTier.LOW) >= 3
    assert severities.count(SeverityTier.MEDIUM) >= 4


def test_universal_catalog_has_info_low_medium_high_coverage() -> None:
    severities = {family.baseline_severity for family in UNIVERSAL_FAMILIES}
    assert SeverityTier.INFO in severities
    assert SeverityTier.LOW in severities
    assert SeverityTier.MEDIUM in severities
    assert SeverityTier.HIGH in severities
    assert len(UNIVERSAL_FAMILIES) >= 25


def test_hunt_lane_routes_authz_to_local_multi_identity() -> None:
    lane = lane_for_family(_family("authz"))
    assert lane.lane_id == "local-multi-identity"
    assert lane.local_validation
    assert "negative_control" not in lane.analysis_steps or lane.evidence_required


def test_mission_compiler_marks_state_change_lane_for_approval() -> None:
    candidate = _candidate("workflow", SeverityTier.MEDIUM, 1800.0)
    mission = compile_candidate_mission(candidate=candidate, scope_digest="scope-1")
    assert mission.scope_digest == "scope-1"
    assert mission.tasks
    assert any(task.payload and task.payload.get("requires_human_approval") for task in mission.tasks)
    assert mission.tasks[-1].action == "assemble_evidence_bundle"


def test_surface_generation_creates_multiple_profit_candidates() -> None:
    signals = infer_surfaces(
        [
            "src/graphql/schema.py",
            "src/auth/oauth.py",
            "src/web/upload.py",
            ".github/workflows/release.yml",
            "infra/main.tf",
        ],
        ["nginx cloudflare websocket webhook xml"],
    )
    candidates = generate_hunt_candidates(program_id="program", signals=signals)
    families = {candidate.family.family_id for candidate in candidates}
    assert {"authz", "oauth", "file", "cicd", "cloud", "proxy", "xml"} <= families

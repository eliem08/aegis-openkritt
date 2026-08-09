"""Jarvis bridge: real hunt rows -> canonical agentic_os proposals, and the fail-closed
ProposalPolicy Judge enforcing the master-brief invariants on the live path. Deterministic."""

from __future__ import annotations

from aegis.ai.agentic_os import AgentProposal, RiskClass
from aegis.ai.jarvis_bridge import (
    judge_findings,
    lifecycle_for,
    proposal_from_row,
    source_review_authorization,
)


def _row(origin_src, cwe="CWE-89", path="src/app/db.py", line=10, summary="sqli", conf=0.8):
    return {"json_answer": {"vulnerability_type": cwe, "file_path": path, "line": line,
                            "summary": summary}, "severity": "high",
            "source": origin_src, "confidence": conf, "scanner_metadata": {"cwe": cwe}}


def test_proposal_from_row_is_read_only_with_source_evidence():
    p = proposal_from_row(_row("aegis:tool:semgrep"))
    assert isinstance(p, AgentProposal)
    assert p.risk is RiskClass.READ_ONLY          # surfacing a source finding changes nothing
    assert p.requires_network is False
    assert p.requires_external_model is False      # scanner origin
    assert p.evidence and p.evidence[0].summary.startswith("src/app/db.py")
    assert p.metadata["cwe"] == "CWE-89"


def test_llm_origin_requires_external_model():
    p = proposal_from_row(_row("aegis:llm:deepseek"))
    assert p.requires_external_model is True


def test_lifecycle_starts_candidate_and_advances_to_source_supported():
    lc = lifecycle_for(_row("aegis:tool:semgrep"))
    assert lc.stage.value == "source_supported"
    assert lc.evidence                              # carries the source citation


def test_judge_approves_source_review_findings():
    authz = source_review_authorization("scope123", budget_usd=5.0)
    rows = [_row("aegis:tool:semgrep"), _row("aegis:llm:deepseek", cwe="CWE-502")]
    out = judge_findings(rows, authz)
    assert len(out.approved) == 2 and out.vetoed == []
    assert all("jarvis" in r for r in out.approved)
    assert out.approved[0]["jarvis"]["stage"] == "source_supported"


def test_judge_vetoes_network_action_without_authorization():
    # a proposal that requires network (e.g. a live-attack step) must be vetoed under the
    # source-review envelope (network_allowed=False) — the safety invariant on the live path.
    authz = source_review_authorization("scope123")
    from aegis.ai.agentic_os import AgentRole, ProposalPolicy
    net = AgentProposal(role=AgentRole.API, action="send-live-request", rationale="probe",
                        risk=RiskClass.READ_ONLY, expected_information_gain=1.0,
                        requires_network=True)
    d = ProposalPolicy().evaluate(net, authz)
    assert d.approved is False and "network" in d.reason


def test_state_change_needs_grant_then_human_approval():
    from aegis.ai.agentic_os import (
        AgentRole,
        AuthorizationEnvelope,
        Budget,
        ProposalPolicy,
        mint_execution_grant,
    )
    from aegis.policy.signing import HmacSignatureVerifier
    v = HmacSignatureVerifier({"grant": "k"})
    policy = ProposalPolicy(v)
    sc = AgentProposal(role=AgentRole.API, action="local-repro", rationale="x",
                       risk=RiskClass.CONTROLLED_STATE_CHANGE, expected_information_gain=1.0)
    budget = Budget(max_cost_usd=5, max_requests=10, max_human_minutes=60)
    # self-set booleans are ignored — no grant -> vetoed (needs a policy-derived grant)
    naked = AuthorizationEnvelope(scope_digest="s", state_change_allowed=True, human_approval=True,
                                  budget=budget)
    assert "execution grant" in policy.evaluate(sc, naked).reason
    # grant granting state-change but NOT human approval -> vetoed for human approval
    g1 = mint_execution_grant(type("D", (), {"allowed": True})(), scope_digest="s", budget=budget,
                              verifier=v, state_change=True, human_approval=False)
    d1 = policy.evaluate(sc, AuthorizationEnvelope(scope_digest="s", budget=budget, grant=g1))
    assert d1.approved is False and "human approval" in d1.reason
    # grant with state-change + human approval -> allowed
    g2 = mint_execution_grant(type("D", (), {"allowed": True})(), scope_digest="s", budget=budget,
                              verifier=v, state_change=True, human_approval=True)
    assert policy.evaluate(sc, AuthorizationEnvelope(scope_digest="s", budget=budget,
                                                     grant=g2)).approved is True


def test_judge_vetoes_over_budget():
    authz = source_review_authorization("s", budget_usd=1.0)
    from aegis.ai.agentic_os import AgentRole, ProposalPolicy
    pricey = AgentProposal(role=AgentRole.HYPOTHESIS, action="x", rationale="y",
                           risk=RiskClass.READ_ONLY, expected_information_gain=1.0,
                           expected_cost_usd=100.0)
    d = ProposalPolicy().evaluate(pricey, authz)
    assert d.approved is False and "budget" in d.reason

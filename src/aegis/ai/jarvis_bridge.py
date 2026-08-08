"""Bridge the real hunt pipeline into Jarvis's canonical agentic contract (:mod:`agentic_os`).

Rather than run Jarvis as a second, parallel framework, this adapts the hunt's actual output
(scanner + skill + LLM candidate rows) into the canonical :class:`AgentProposal` /
:class:`FindingLifecycle` model and runs the fail-closed :class:`ProposalPolicy` as a
deterministic Judge. That makes the master-brief invariants real on the live path:

  * every candidate is a canonical proposal with an evidence stage (starts at ``candidate``);
  * the Judge **vetoes** any proposal that would require network access, a state change, or is a
    forbidden risk class, or that exceeds the run's budget — unless the authorization envelope
    explicitly allows it AND (for state changes) a human has approved. Source-review findings are
    READ_ONLY with no network, so they pass; anything trying to autonomously act on a live target
    is blocked here. Nothing is submitted.

Deterministic and LLM-free: cheap, reproducible, unit-testable. This is the seam through which the
richer Jarvis specialists (Skeptic/Reproduction/Evidence council, economics) can later plug in
without forking the hunt.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .agentic_os import (
    AgentProposal,
    AgentRole,
    AuthorizationEnvelope,
    Budget,
    Decision,
    EvidenceRef,
    EvidenceStage,
    FindingLifecycle,
    ProposalPolicy,
    RiskClass,
)

# origin (from the row's `source` tag) -> canonical agent role
_ROLE_BY_ORIGIN = {
    "scanner": AgentRole.STATIC_ANALYSIS,
    "skill": AgentRole.ATTACK_SURFACE,
    "llm": AgentRole.HYPOTHESIS,
}


def _origin(row: dict) -> str:
    src = str(row.get("source") or "")
    if ":tool:" in src:
        return "scanner"
    if ":skill:" in src:
        return "skill"
    return "llm"


def source_review_authorization(scope_digest: str, *, budget_usd: float = 5.0,
                                max_requests: int = 0, max_human_minutes: float = 240.0,
                                human_approval: bool = False) -> AuthorizationEnvelope:
    """The authorization posture for local source review: NO network, NO state change, external
    model egress allowed (the hunt calls an LLM). Anything needing more is vetoed by the Judge."""
    return AuthorizationEnvelope(
        scope_digest=scope_digest or "unknown",
        network_allowed=False, state_change_allowed=False,
        external_model_egress_allowed=True, human_approval=human_approval,
        budget=Budget(max_cost_usd=budget_usd, max_requests=max_requests,
                      max_human_minutes=max_human_minutes))


def proposal_from_row(row: dict, *, information_gain: float = 0.0) -> AgentProposal:
    """Map one hunt candidate row (canonical `_row` shape) to a canonical AgentProposal — the
    act of SURFACING a source finding for human review (read-only, no network/state change)."""
    ja = row.get("json_answer") or {}
    md = row.get("scanner_metadata") or {}
    origin = _origin(row)
    path = str(ja.get("file_path") or "")
    line = ja.get("line") or 0
    cwe = str(md.get("cwe") or ja.get("vulnerability_type") or "")
    digest = sha256(f"{path}:{line}:{cwe}".encode()).hexdigest()[:16]
    ev = EvidenceRef(evidence_id=digest, kind="source-citation", digest=digest,
                     summary=f"{path}:{line}"[:200])
    return AgentProposal(
        role=_ROLE_BY_ORIGIN.get(origin, AgentRole.DATAFLOW),
        action="surface-source-finding-for-human-review",
        rationale=str(ja.get("summary") or cwe or "candidate")[:300],
        risk=RiskClass.READ_ONLY,                 # surfacing a source finding changes nothing
        expected_information_gain=float(information_gain or row.get("confidence") or 0.0),
        expected_cost_usd=0.0, expected_requests=0, expected_human_minutes=5.0,
        requires_network=False, requires_external_model=(origin == "llm"),
        evidence=(ev,),
        metadata={"cwe": cwe, "path": path, "line": line, "origin": origin,
                  "severity": str(row.get("severity") or "")})


def lifecycle_for(row: dict) -> FindingLifecycle:
    """Canonical evidence lifecycle for a row: CANDIDATE, advanced to SOURCE_SUPPORTED when the
    row carries a concrete source citation (file+line)."""
    ja = row.get("json_answer") or {}
    fid = sha256(f"{ja.get('file_path')}:{ja.get('line')}".encode()).hexdigest()[:16]
    lc = FindingLifecycle(finding_id=fid, stage=EvidenceStage.CANDIDATE)
    if ja.get("file_path"):
        digest = sha256(f"{ja.get('file_path')}:{ja.get('line')}".encode()).hexdigest()[:16]
        lc.advance(EvidenceStage.SOURCE_SUPPORTED,
                   [EvidenceRef(digest, "source-citation", digest,
                                f"{ja.get('file_path')}:{ja.get('line')}")])
    return lc


@dataclass
class JudgeOutcome:
    approved: list[dict]                  # rows the Judge cleared (annotated with row["jarvis"])
    vetoed: list[tuple[dict, str]]        # (row, veto reason)
    decisions: list[tuple[str, bool, str]]   # (proposal_id, approved, reason) for audit

    def summary(self) -> dict:
        return {"approved": len(self.approved), "vetoed": len(self.vetoed),
                "veto_reasons": sorted({r for _, r in self.vetoed})}


def judge_findings(rows: list[dict], authorization: AuthorizationEnvelope,
                   *, policy: ProposalPolicy | None = None) -> JudgeOutcome:
    """Run the fail-closed ProposalPolicy Judge over hunt candidate rows. Approved rows are
    annotated with their canonical proposal/lifecycle; vetoed rows (forbidden/network/state-
    change/over-budget) are separated out with a reason. Deterministic."""
    policy = policy or ProposalPolicy()
    approved: list[dict] = []
    vetoed: list[tuple[dict, str]] = []
    decisions: list[tuple[str, bool, str]] = []
    for row in rows:
        gain = float(row.get("confidence") or 0.0)
        proposal = proposal_from_row(row, information_gain=gain)
        decision: Decision = policy.evaluate(proposal, authorization)
        decisions.append((proposal.proposal_id, decision.approved, decision.reason))
        if decision.approved:
            lc = lifecycle_for(row)
            row = {**row, "jarvis": {"proposal_id": proposal.proposal_id,
                                     "role": proposal.role.value, "stage": lc.stage.value,
                                     "risk": proposal.risk.value,
                                     "information_gain": proposal.expected_information_gain}}
            approved.append(row)
        else:
            vetoed.append((row, decision.reason))
    return JudgeOutcome(approved=approved, vetoed=vetoed, decisions=decisions)

"""Knowledge-aware planning (Master Prompt §3 PLAN, §8).

Wraps any base planner and reorders its proposed actions so that the ones whose
weakness classes are *historically common* on the target asset type run first —
history steering effort, never overriding policy. Recon actions stay at the
front (surface must be mapped before probing). Every reordered action gets a
rationale note with its history score, so the choice is auditable.

Duck-typed on the base planner (anything with ``.plan(inputs, surface)``), so
this module does not import the orchestrator.
"""

from __future__ import annotations

from typing import Protocol

from aegis.model import AttackSurface, EngagementInputs, TestPlan

from .insights import CorpusInsights

# Which CWE classes each action class tends to surface (for scoring only).
ACTION_WEAKNESS_MAP: dict[str, set[str]] = {
    "authenticated_testing": {"CWE-639", "CWE-284", "CWE-285", "CWE-863", "CWE-862"},
    "synthetic_data_access": {"CWE-200"},
    "safe_state_change": {"CWE-352"},
    "cross_tenant_proof": {"CWE-639", "CWE-284"},
    "server_side_request_forgery": {"CWE-918"},
    "privilege_escalation": {"CWE-269", "CWE-863"},
    "benign_request_mutation": {"CWE-89", "CWE-79"},
}

RECON_ACTIONS = {"passive_discovery", "tech_fingerprint", "spec_ingestion"}


class _BasePlanner(Protocol):
    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        ...


class KnowledgeAwarePlanner:
    def __init__(
        self,
        base: _BasePlanner,
        insights: CorpusInsights,
        *,
        asset_type: str | None = None,
    ) -> None:
        self.base = base
        self.insights = insights
        self.asset_type = asset_type

    def _score(self, action_name: str) -> float:
        cwes = ACTION_WEAKNESS_MAP.get(action_name)
        if not cwes:
            return 0.0
        priors = self.insights.priors_for(asset_type=self.asset_type)
        return sum(priors.get(cwe, 0.0) for cwe in cwes)

    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        base_plan = self.base.plan(inputs, surface)
        recon = [a for a in base_plan.actions if a.action in RECON_ACTIONS]
        probes = [a for a in base_plan.actions if a.action not in RECON_ACTIONS]

        scored = sorted(probes, key=lambda a: self._score(a.action), reverse=True)
        reordered = []
        for action in scored:
            score = self._score(action.action)
            note = f"history score={score:.3f}"
            rationale = f"{action.rationale} | {note}" if action.rationale else note
            reordered.append(action.model_copy(update={"rationale": rationale}))

        return TestPlan(actions=recon + reordered)

"""Bridge dormant ``aegis.active`` detector plans into the canonical Jarvis policy model.

This module deliberately does **not** execute live probes.  It converts the existing
Phase-3 detector planner into :class:`~aegis.ai.agentic_os.AgentProposal` objects so
network/state-changing work is visible to — and vetoable by — the same deterministic
``ProposalPolicy`` used by the source-review hunt.

The default source-review authorization envelope has no network/state-change/human
approval, therefore every live active probe is structurally blocked.  A future explicit
active engagement may reuse the same proposals with a stronger authorization envelope;
no detector gets a second/private bypass around policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aegis.active import DetectorPlan, DetectorTask, plan_detectors, routes_from_assets

from .agentic_os import AgentProposal, AgentRole, RiskClass


@dataclass(frozen=True)
class ActiveProposalSpec:
    detector: str
    role: AgentRole
    rationale: str


_SPECS: dict[str, ActiveProposalSpec] = {
    "bola": ActiveProposalSpec(
        "bola", AgentRole.AUTHORIZATION,
        "Compare owned identities against discovered object routes to test object ownership.",
    ),
    "bfla": ActiveProposalSpec(
        "bfla", AgentRole.AUTHORIZATION,
        "Test a declared low-privilege identity against a discovered privileged endpoint.",
    ),
    "cross_tenant": ActiveProposalSpec(
        "cross_tenant", AgentRole.AUTHORIZATION,
        "Run an owned-account tenant differential on an explicitly discovered route.",
    ),
    "missing_auth": ActiveProposalSpec(
        "missing_auth", AgentRole.AUTHENTICATION,
        "Compare authenticated and unauthenticated behavior on a discovered route.",
    ),
    "exposed_files": ActiveProposalSpec(
        "exposed_files", AgentRole.ATTACK_SURFACE,
        "Request only explicitly discovered file-like routes; never enumerate default paths.",
    ),
    "error_disclosure": ActiveProposalSpec(
        "error_disclosure", AgentRole.API,
        "Apply a bounded benign request mutation to inspect error disclosure.",
    ),
    "cors": ActiveProposalSpec(
        "cors", AgentRole.API,
        "Perform a bounded CORS differential on an explicitly discovered route.",
    ),
    "open_redirect": ActiveProposalSpec(
        "open_redirect", AgentRole.API,
        "Perform a bounded redirect-parameter differential on an explicitly discovered route.",
    ),
    "ssrf": ActiveProposalSpec(
        "ssrf", AgentRole.HYPOTHESIS,
        "Use the private OAST lane only for discovered URL-accepting parameters.",
    ),
    "graphql": ActiveProposalSpec(
        "graphql", AgentRole.API,
        "Inspect an explicitly discovered GraphQL endpoint with bounded requests.",
    ),
    "path_bypass": ActiveProposalSpec(
        "path_bypass", AgentRole.AUTHORIZATION,
        "Compare bounded path-normalization variants on an explicitly discovered route.",
    ),
    "contract_review": ActiveProposalSpec(
        "contract_review", AgentRole.STATIC_ANALYSIS,
        "Analyze operator-provided contract source offline.",
    ),
}


def _proposal_for_task(task: DetectorTask) -> AgentProposal:
    spec = _SPECS.get(
        task.detector,
        ActiveProposalSpec(
            task.detector,
            AgentRole.HYPOTHESIS,
            f"Run the bounded {task.detector} detector against discovered evidence only.",
        ),
    )
    offline = task.est_requests <= 0 and task.action == "passive_discovery" and task.detector == "contract_review"
    # Conservatively model every live request as CONTROLLED_STATE_CHANGE.  Some probes are
    # semantically read-only, but this forces BOTH state-change authorization and human approval
    # in ProposalPolicy and prevents a new detector from accidentally becoming an autonomous
    # internet action just because its HTTP method happens to be GET.
    risk = RiskClass.OFFLINE if offline else RiskClass.CONTROLLED_STATE_CHANGE
    return AgentProposal(
        role=spec.role,
        action=f"active:{task.detector}",
        rationale=spec.rationale,
        risk=risk,
        expected_information_gain=0.85 if task.detector in {"bola", "bfla", "ssrf"} else 0.65,
        expected_cost_usd=0.0,
        expected_requests=max(0, int(task.est_requests)),
        requires_network=not offline,
        evidence=(),
        metadata={
            "active_detector": task.detector,
            "declared_action": task.action,
            "targets": list(task.targets),
            "config": dict(task.config),
            "execution": "proposal_only",
        },
    )


def proposals_from_plan(plan: DetectorPlan) -> tuple[AgentProposal, ...]:
    """Convert an ``aegis.active`` plan to canonical policy proposals."""
    return tuple(_proposal_for_task(task) for task in plan.tasks)


def plan_active_proposals(
    assets: Iterable,
    *,
    host: str = "",
    seeds=(),
    identities=(),
    privileged_endpoints=(),
    enabled=None,
    identifier_samples=None,
    contracts=(),
    per_target_requests: int = 2,
    max_targets_per_detector: int = 200,
) -> tuple[DetectorPlan, tuple[AgentProposal, ...]]:
    """Plan active work from discovered assets without executing any live request.

    This is the canonical integration seam for ``active/``.  The detector package remains
    responsible for deciding *what is applicable* from evidence; ``agentic_os`` remains
    responsible for deciding *whether it may execute*.
    """
    routes = routes_from_assets(list(assets))
    plan = plan_detectors(
        routes,
        host=host,
        seeds=seeds,
        identities=identities,
        privileged_endpoints=privileged_endpoints,
        enabled=enabled,
        per_target_requests=per_target_requests,
        max_targets_per_detector=max_targets_per_detector,
        identifier_samples=identifier_samples,
        contracts=contracts,
    )
    return plan, proposals_from_plan(plan)

"""Bridge ``aegis.active`` detector plans into the canonical Jarvis policy model.

This module does not execute live probes. It converts detector plans into canonical
``AgentProposal`` objects so network/state-changing work is visible to — and vetoable by —
the same deterministic ``ProposalPolicy`` used by the source-review hunt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aegis.active import (
    DetectorPlan,
    DetectorTask,
    analyze_desync_observations,
    observations_from_assets,
    plan_detectors,
    routes_from_assets,
)

from .agentic_os import AgentProposal, AgentRole, RiskClass


@dataclass(frozen=True)
class ActiveProposalSpec:
    detector: str
    role: AgentRole
    rationale: str


_SPECS: dict[str, ActiveProposalSpec] = {
    "bola": ActiveProposalSpec(
        "bola",
        AgentRole.AUTHORIZATION,
        "Compare owned identities against discovered object routes to test object ownership.",
    ),
    "bfla": ActiveProposalSpec(
        "bfla",
        AgentRole.AUTHORIZATION,
        "Test a declared low-privilege identity against a discovered privileged endpoint.",
    ),
    "cross_tenant": ActiveProposalSpec(
        "cross_tenant",
        AgentRole.AUTHORIZATION,
        "Run an owned-account tenant differential on an explicitly discovered route.",
    ),
    "missing_auth": ActiveProposalSpec(
        "missing_auth",
        AgentRole.AUTHENTICATION,
        "Compare authenticated and unauthenticated behavior on a discovered route.",
    ),
    "exposed_files": ActiveProposalSpec(
        "exposed_files",
        AgentRole.ATTACK_SURFACE,
        "Request only explicitly discovered file-like routes; never enumerate default paths.",
    ),
    "error_disclosure": ActiveProposalSpec(
        "error_disclosure",
        AgentRole.API,
        "Apply a bounded benign request mutation to inspect error disclosure.",
    ),
    "cors": ActiveProposalSpec(
        "cors",
        AgentRole.API,
        "Perform a bounded CORS differential on an explicitly discovered route.",
    ),
    "open_redirect": ActiveProposalSpec(
        "open_redirect",
        AgentRole.API,
        "Perform a bounded redirect-parameter differential on an explicitly discovered route.",
    ),
    "ssrf": ActiveProposalSpec(
        "ssrf",
        AgentRole.HYPOTHESIS,
        "Use the private OAST lane only for discovered URL-accepting parameters.",
    ),
    "graphql": ActiveProposalSpec(
        "graphql",
        AgentRole.API,
        "Inspect an explicitly discovered GraphQL endpoint with bounded requests.",
    ),
    "path_bypass": ActiveProposalSpec(
        "path_bypass",
        AgentRole.AUTHORIZATION,
        "Compare bounded path-normalization variants on an explicitly discovered route.",
    ),
    "http_desync": ActiveProposalSpec(
        "http_desync",
        AgentRole.API,
        "Validate evidence-backed HTTP parser disagreement on discovered routes with bounded differentials.",
    ),
    "contract_review": ActiveProposalSpec(
        "contract_review",
        AgentRole.STATIC_ANALYSIS,
        "Analyze operator-provided contract source offline.",
    ),
}

_FOLLOWUP_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssrf", ("ssrf", "server-side request", "webhook", "url fetch", "callback url")),
    ("graphql", ("graphql", "resolver", "introspection")),
    ("path_bypass", ("path bypass", "path normalization", "traversal", "route bypass")),
    (
        "http_desync",
        (
            "request smuggling",
            "http request smuggling",
            "http desync",
            "desynchronization",
            "cl.te",
            "te.cl",
            "te.te",
            "h2 downgrade",
        ),
    ),
    ("bola", ("idor", "bola", "object authorization", "ownership check", "tenant")),
    ("bfla", ("bfla", "function authorization", "privilege escalation", "admin endpoint")),
    ("missing_auth", ("missing auth", "unauthenticated", "authentication bypass")),
    ("cors", ("cors", "access-control-allow-origin")),
    ("open_redirect", ("open redirect", "redirect_uri", "redirect uri")),
    ("error_disclosure", ("error disclosure", "stack trace", "debug error")),
)


def _proposal_for_task(task: DetectorTask) -> AgentProposal:
    spec = _SPECS.get(
        task.detector,
        ActiveProposalSpec(
            task.detector,
            AgentRole.HYPOTHESIS,
            f"Run the bounded {task.detector} detector against discovered evidence only.",
        ),
    )
    offline = (
        task.est_requests <= 0
        and task.action == "passive_discovery"
        and task.detector == "contract_review"
    )
    risk = RiskClass.OFFLINE if offline else RiskClass.CONTROLLED_STATE_CHANGE
    high_value = {"bola", "bfla", "ssrf", "http_desync"}
    return AgentProposal(
        role=spec.role,
        action=f"active:{task.detector}",
        rationale=spec.rationale,
        risk=risk,
        expected_information_gain=0.90 if task.detector in high_value else 0.65,
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
    return tuple(_proposal_for_task(task) for task in plan.tasks)


def followup_intents_for_finding(row: dict) -> tuple[AgentProposal, ...]:
    answer = row.get("json_answer") or {}
    blob = " ".join(
        str(value or "")
        for value in (
            answer.get("vulnerability_type"),
            answer.get("summary"),
            answer.get("explanation"),
            row.get("cwe"),
        )
    ).lower()
    detectors = []
    for detector, needles in _FOLLOWUP_HINTS:
        if any(needle in blob for needle in needles):
            detectors.append(detector)
    proposals = []
    for detector in sorted(set(detectors)):
        spec = _SPECS[detector]
        proposals.append(
            AgentProposal(
                role=spec.role,
                action=f"active-plan:{detector}",
                rationale=spec.rationale,
                risk=RiskClass.CONTROLLED_STATE_CHANGE,
                expected_information_gain=0.90 if detector == "http_desync" else 0.85,
                expected_cost_usd=0.0,
                expected_requests=1,
                requires_network=True,
                metadata={
                    "active_detector": detector,
                    "execution": "requires_discovered_route_plan",
                    "source_location": f"{answer.get('file_path', '')}:{answer.get('line', '')}",
                },
            )
        )
    return tuple(proposals)


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
    desync_candidates=None,
    per_target_requests: int = 2,
    max_targets_per_detector: int = 200,
) -> tuple[DetectorPlan, tuple[AgentProposal, ...]]:
    """Plan active work from discovered assets without executing a live request.

    HTTP desync is fully connected to the asset graph: unless a caller intentionally supplies a
    candidate set, Jarvis extracts protocol/intermediary evidence from the same discovered ROUTE
    assets used by every other detector and analyzes it automatically.
    """
    asset_list = list(assets)
    routes = routes_from_assets(asset_list)
    if desync_candidates is None:
        desync_candidates = analyze_desync_observations(observations_from_assets(asset_list))
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
        desync_candidates=desync_candidates,
    )
    return plan, proposals_from_plan(plan)

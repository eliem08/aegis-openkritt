"""Repository adapter for the canonical opportunity/mission/authority runtime."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Mapping

from aegis.ai.agentic_os import (
    AgentProposal,
    AgentRole,
    AuthorizationEnvelope,
    ProposalPolicy,
    RiskClass,
)
from aegis.ai.jarvis.universal_mission import compile_opportunity_mission
from aegis.integrations.repo_pipeline import (
    PipelineResult,
    ScanLaunch,
    run_repo_pipeline,
    scan_one_repo,
)
from aegis.scheduler.profit import HuntOpportunity

from .reward import accept_probability


def repository_opportunities(
    programs,
    *,
    expected_bounties: Mapping[str, Decimal] | None = None,
    authorizations: Mapping[str, AuthorizationEnvelope] | None = None,
    p_find: float = 0.5,
    p_valid: float = 0.5,
    p_accepted: float = 0.5,
    model_cost: Decimal = Decimal("0.02"),
    scanner_cost: Decimal = Decimal("0.05"),
    verification_cost: Decimal = Decimal("0.50"),
    reward_policies: Mapping | None = None,
) -> tuple[HuntOpportunity, ...]:
    """Adapt authorized repository scope into canonical opportunities."""
    payouts = {str(key): Decimal(str(value)) for key, value in (expected_bounties or {}).items()}
    envelopes = authorizations or {}
    policies = reward_policies or {}
    opportunities: list[HuntOpportunity] = []
    for program in programs:
        envelope = envelopes.get(program.handle)
        grant = envelope.grant if envelope else None
        for repo in program.repos:
            opportunities.append(HuntOpportunity(
                opportunity_id=f"repo:{program.handle}:{repo.repo_full}",
                program_id=f"program:{program.handle}",
                program_handle=program.handle,
                asset_id=f"repository:{repo.repo_full}",
                asset_kind="source_code",
                asset_locator=repo.repo_full,
                scope_digest=envelope.scope_digest if envelope else "",
                authorization_id=grant.decision_fingerprint if grant else "",
                attack_surface="source",
                weakness_family="target_allocation",
                prerequisite_state="ready" if grant else "waiting_for_authorization",
                estimated_payout_usd=payouts.get(program.handle),
                p_find=p_find,
                p_valid=p_valid,
                p_unique=1.0,
                p_accepted=accept_probability(p_accepted, policies.get(program.handle)),
                p_reproducible=1.0,
                model_cost_usd=model_cost,
                scanner_cost_usd=scanner_cost,
                validation_cost_usd=verification_cost,
                uncertainty=1.0 if program.handle not in payouts else 0.25,
                information_gain=0.75,
                provenance=(
                    f"hackerone:{program.handle}",
                    f"scope:{repo.identifier}",
                    "aegis.hunt.repository_runtime",
                ),
                metadata={"max_severity": repo.max_severity,
                          "eligible_for_bounty": repo.eligible_for_bounty},
            ))
    return tuple(opportunities)


@dataclass(frozen=True)
class RepositoryAuthorizationResult:
    opportunity: HuntOpportunity
    mission_id: str
    approved: bool
    reason: str


class RepositoryRuntimeAdapter:
    """Authorize and launch repository missions through the existing scanner adapter."""

    def __init__(self, h1_client, ok_client, *, verifier) -> None:
        self.h1_client = h1_client
        self.ok_client = ok_client
        self.policy = ProposalPolicy(verifier)

    def authorize(
        self,
        opportunity: HuntOpportunity,
        envelope: AuthorizationEnvelope | None,
    ) -> RepositoryAuthorizationResult:
        mission = compile_opportunity_mission(opportunity, mission_prefix="repo")
        if envelope is None:
            return RepositoryAuthorizationResult(
                opportunity, mission.mission_id, False, "signed authorization envelope is missing"
            )
        proposal = AgentProposal(
            role=AgentRole.REPOSITORY_INTELLIGENCE,
            action="launch_authorized_repository_scan",
            rationale="execute the selected repository mission through the configured scanner",
            risk=RiskClass.READ_ONLY,
            expected_information_gain=opportunity.information_gain,
            expected_cost_usd=float(opportunity.features.model_cost
                                    + opportunity.features.scanner_cost),
            expected_requests=0,
            requires_network=True,
            requires_external_model=True,
            metadata={
                "opportunity_id": opportunity.opportunity_id,
                "mission_id": mission.mission_id,
                "asset_id": opportunity.asset_id,
                "scope_digest": opportunity.scope_digest,
            },
        )
        decision = self.policy.evaluate(proposal, envelope)
        return RepositoryAuthorizationResult(
            opportunity, mission.mission_id, decision.approved, decision.reason
        )

    def launch_program(
        self,
        program: PipelineResult,
        opportunities: tuple[HuntOpportunity, ...],
        envelope: AuthorizationEnvelope | None,
        *,
        model: str,
        fallbacks=None,
        bounty_only: bool = False,
        workflow_id=None,
        post_script_id=None,
        use_deepseek_fallback: bool = False,
    ) -> tuple[PipelineResult, tuple[RepositoryAuthorizationResult, ...]]:
        decisions = tuple(self.authorize(item, envelope) for item in opportunities)
        allowlist = {
            item.opportunity.asset_locator for item in decisions if item.approved
        }
        if not allowlist:
            return PipelineResult(
                handle=program.handle,
                program_name=program.program_name,
                repos=program.repos,
                gated=program.gated,
                reason=program.reason,
            ), decisions
        launched = run_repo_pipeline(
            self.h1_client,
            self.ok_client,
            program.handle,
            model=model,
            fallbacks=fallbacks,
            bounty_only=bounty_only,
            workflow_id=workflow_id,
            post_script_id=post_script_id,
            use_deepseek_fallback=use_deepseek_fallback,
            launch=True,
            repo_allowlist=allowlist,
        )
        return launched, decisions

    def launch_verification(
        self,
        opportunity: HuntOpportunity,
        envelope: AuthorizationEnvelope | None,
        *,
        model: str,
        repo_scope: str,
        thinking_effort: str = "",
        fallbacks=None,
        workflow_id=None,
    ) -> tuple[ScanLaunch | None, RepositoryAuthorizationResult]:
        decision = self.authorize(opportunity, envelope)
        if not decision.approved:
            return None, decision
        launch = scan_one_repo(
            self.ok_client,
            opportunity.asset_locator,
            model=model,
            workflow_id=workflow_id,
            handle=opportunity.program_handle,
            repo_scope=repo_scope,
            thinking_effort=thinking_effort,
            fallbacks=fallbacks,
        )
        return launch, decision


__all__ = [
    "RepositoryAuthorizationResult",
    "RepositoryRuntimeAdapter",
    "repository_opportunities",
]

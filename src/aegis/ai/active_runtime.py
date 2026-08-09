"""Canonical execution seam for Jarvis active detector plans.

This closes the gap between ``active_bridge`` planning/policy and detector execution.  A task
is never executed merely because it was planned: its paired canonical ``AgentProposal`` must
be approved by ``ProposalPolicy`` under the supplied authorization envelope, cumulative
request/cost budgets are enforced across the whole plan, and an approved task with no
registered executor fails closed instead of disappearing as a scaffold.

Executors remain detector-specific bounded implementations.  They return immutable evidence
references rather than mutating finding lifecycle state directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Protocol

from aegis.active import DetectorPlan, DetectorTask

from .active_bridge import plan_active_proposals
from .agentic_os import (
    AuthorizationEnvelope,
    Budget,
    Decision,
    EvidenceRef,
    ProposalPolicy,
    process_grant_verifier,
)


@dataclass(frozen=True)
class ActiveExecutionContext:
    authorization: AuthorizationEnvelope
    assets: tuple[Any, ...]


@dataclass(frozen=True)
class ActiveExecutionResult:
    status: str
    evidence: tuple[EvidenceRef, ...] = ()
    requests_used: int = 0
    cost_usd: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)


class ActiveDetectorExecutor(Protocol):
    def execute(
        self,
        task: DetectorTask,
        context: ActiveExecutionContext,
    ) -> ActiveExecutionResult: ...


@dataclass(frozen=True)
class ActiveTaskRun:
    task: DetectorTask
    decision: Decision
    result: ActiveExecutionResult | None = None
    runtime_reason: str = ""

    @property
    def executed(self) -> bool:
        return self.result is not None


@dataclass(frozen=True)
class ActiveRuntimeReport:
    plan: DetectorPlan
    runs: tuple[ActiveTaskRun, ...]

    @property
    def evidence(self) -> tuple[EvidenceRef, ...]:
        return tuple(
            item
            for run in self.runs
            if run.result is not None
            for item in run.result.evidence
        )

    def summary(self) -> dict[str, Any]:
        return {
            "planned": len(self.plan.tasks),
            "approved": sum(run.decision.approved for run in self.runs),
            "executed": sum(run.executed for run in self.runs),
            "policy_blocked": sum(not run.decision.approved for run in self.runs),
            "executor_missing": sum(run.runtime_reason == "executor_missing" for run in self.runs),
            "evidence": len(self.evidence),
            "requests_used": sum(
                max(0, int(run.result.requests_used))
                for run in self.runs
                if run.result is not None
            ),
            "cost_usd": round(
                sum(
                    max(0.0, float(run.result.cost_usd))
                    for run in self.runs
                    if run.result is not None
                ),
                4,
            ),
        }


def _remaining_envelope(
    authorization: AuthorizationEnvelope,
    *,
    requests_used: int,
    cost_used: float,
) -> AuthorizationEnvelope:
    budget = authorization.budget
    return replace(
        authorization,
        budget=Budget(
            max_cost_usd=max(0.0, float(budget.max_cost_usd) - max(0.0, cost_used)),
            max_requests=max(0, int(budget.max_requests) - max(0, requests_used)),
            max_human_minutes=max(0.0, float(budget.max_human_minutes)),
        ),
    )


def run_active_plan(
    assets,
    authorization: AuthorizationEnvelope,
    *,
    executors: Mapping[str, ActiveDetectorExecutor],
    enabled=None,
    policy: ProposalPolicy | None = None,
    **planner_kwargs,
) -> ActiveRuntimeReport:
    """Plan, authorize, dispatch, and collect evidence for one bounded active round.

    ``executors`` is explicit and fail-closed: a detector cannot become executable merely by
    being added to the planner.  This invariant prevents future feature registration from
    silently creating a live network capability.
    """

    asset_tuple = tuple(assets)
    plan, proposals = plan_active_proposals(
        asset_tuple,
        enabled=enabled,
        **planner_kwargs,
    )
    if len(plan.tasks) != len(proposals):
        raise RuntimeError("active planner/proposal cardinality mismatch")

    proposal_policy = policy or ProposalPolicy(process_grant_verifier())
    runs: list[ActiveTaskRun] = []
    requests_used = 0
    cost_used = 0.0

    for task, proposal in zip(plan.tasks, proposals, strict=True):
        current_authorization = _remaining_envelope(
            authorization,
            requests_used=requests_used,
            cost_used=cost_used,
        )
        decision = proposal_policy.evaluate(proposal, current_authorization)
        if not decision.approved:
            runs.append(ActiveTaskRun(task=task, decision=decision))
            continue

        executor = executors.get(task.detector)
        if executor is None:
            # Approved policy is necessary but never sufficient for execution. Missing concrete
            # implementation is a runtime block, not a successful/verified detector outcome.
            runs.append(
                ActiveTaskRun(
                    task=task,
                    decision=decision,
                    runtime_reason="executor_missing",
                )
            )
            continue

        result = executor.execute(
            task,
            ActiveExecutionContext(
                authorization=current_authorization,
                assets=asset_tuple,
            ),
        )
        used_requests = max(0, int(result.requests_used))
        used_cost = max(0.0, float(result.cost_usd))
        if used_requests > task.est_requests:
            raise RuntimeError(
                f"{task.detector} executor exceeded declared request estimate: "
                f"{used_requests} > {task.est_requests}"
            )
        if requests_used + used_requests > authorization.budget.max_requests:
            raise RuntimeError("active executor exceeded engagement request budget")
        if cost_used + used_cost > authorization.budget.max_cost_usd:
            raise RuntimeError("active executor exceeded engagement cost budget")

        requests_used += used_requests
        cost_used += used_cost
        runs.append(ActiveTaskRun(task=task, decision=decision, result=result))

    return ActiveRuntimeReport(plan=plan, runs=tuple(runs))

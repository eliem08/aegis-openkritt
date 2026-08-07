"""Learning and persistence agents for the advanced Jarvis council."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .coverage import CoverageCell, prioritize_blind_spots
from .mission_scheduler import MissionPlan, MissionScheduler
from .rule_factory import RuleDraft, draft_detection_rule
from .state_store import JarvisStateStore, LearnedPrior, VulnerabilityFamily


@dataclass(frozen=True)
class BountyOutcome:
    program_id: str
    weakness: str
    accepted: bool
    duplicate: bool
    payout_usd: float = 0.0
    cost_usd: float = 0.0


@dataclass(frozen=True)
class ConfirmedFinding:
    program_id: str
    finding_id: str
    mechanism: str
    invariant: str
    cwe: str = ""
    tags: tuple[str, ...] = ()
    confidence: float = 1.0


class OutcomeLearningAgent:
    """Turn real bounty outcomes into calibrated program/weakness priors."""

    role = AgentRole.PROFITABILITY

    def learn(
        self,
        store: JarvisStateStore,
        outcomes: Iterable[BountyOutcome],
    ) -> tuple[LearnedPrior, ...]:
        latest: dict[tuple[str, str], LearnedPrior] = {}
        for outcome in outcomes:
            prior = store.record_outcome(
                program_id=outcome.program_id,
                weakness=outcome.weakness,
                accepted=outcome.accepted,
                duplicate=outcome.duplicate,
                payout_usd=outcome.payout_usd,
                cost_usd=outcome.cost_usd,
            )
            latest[(prior.program_id, prior.weakness)] = prior
        return tuple(latest[key] for key in sorted(latest))

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("learning:outcomes")
        if item is None or not item.value:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="learn_from_bounty_outcomes",
                rationale=(
                    "Update acceptance, uniqueness, payout, and cost priors from resolved "
                    "bounty outcomes before allocating more research budget."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.95,
                metadata={"memory_key": "learning:outcomes"},
            ),
        )


class VulnerabilityFamilyAgent:
    """Abstract confirmed findings into cross-program mechanism families."""

    role = AgentRole.VARIANT

    @staticmethod
    def family_id(finding: ConfirmedFinding) -> str:
        material = "\x1f".join(
            (
                finding.mechanism.strip().lower(),
                finding.invariant.strip().lower(),
                finding.cwe.strip().upper(),
            )
        )
        return f"vf1:{sha256(material.encode()).hexdigest()}"

    def learn(
        self,
        store: JarvisStateStore,
        findings: Iterable[ConfirmedFinding],
    ) -> tuple[VulnerabilityFamily, ...]:
        grouped: dict[str, list[ConfirmedFinding]] = {}
        for finding in findings:
            if finding.confidence < 0.8:
                continue
            grouped.setdefault(self.family_id(finding), []).append(finding)

        families: list[VulnerabilityFamily] = []
        for family_id, members in sorted(grouped.items()):
            representative = members[0]
            family = VulnerabilityFamily(
                family_id=family_id,
                mechanism=representative.mechanism.strip(),
                invariant=representative.invariant.strip(),
                cwe=representative.cwe.strip().upper(),
                exemplars=tuple(
                    sorted({f"{member.program_id}:{member.finding_id}" for member in members})
                ),
                tags=tuple(sorted({tag for member in members for tag in member.tags})),
                confidence=min(1.0, sum(member.confidence for member in members) / len(members)),
            )
            store.upsert_family(family)
            families.append(family)
        return tuple(families)

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("families:confirmed_findings")
        if item is None or not item.value:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="abstract_vulnerability_families",
                rationale=(
                    "Generalize evidence-complete findings into mechanism-level families so "
                    "future variant hunts reuse the violated invariant rather than raw payloads."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.9,
                metadata={"memory_key": "families:confirmed_findings"},
            ),
        )


class RuleSynthesisAgent:
    """Create reviewable Semgrep/CodeQL drafts only from high-confidence families."""

    role = AgentRole.STATIC_ANALYSIS

    def draft(
        self,
        families: Iterable[VulnerabilityFamily],
        *,
        engines: tuple[str, ...] = ("semgrep", "codeql"),
    ) -> tuple[RuleDraft, ...]:
        drafts = []
        for family in families:
            if family.confidence < 0.7:
                continue
            for engine in engines:
                drafts.append(draft_detection_rule(family, engine=engine))
        return tuple(sorted(drafts, key=lambda draft: (draft.family_id, draft.engine)))

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("rules:families")
        if item is None or not item.value:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="synthesize_fixture_gated_detection_rules",
                rationale=(
                    "Convert confirmed vulnerability mechanisms into private detector drafts, "
                    "then require positive/negative fixture validation before promotion."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.82,
                metadata={"memory_key": "rules:families"},
            ),
        )


class CoverageOptimizerAgent:
    """Prioritize valuable, changed, and under-tested surface/weakness intersections."""

    role = AgentRole.ATTACK_SURFACE

    @staticmethod
    def rank(cells: Iterable[CoverageCell]) -> tuple[CoverageCell, ...]:
        return prioritize_blind_spots(list(cells))

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("coverage:cells")
        if item is None or not isinstance(item.value, list):
            return ()
        cells = [cell for cell in item.value if isinstance(cell, CoverageCell)]
        ranked = self.rank(cells)
        if not ranked:
            return ()
        top = ranked[0]
        return (
            AgentProposal(
                role=self.role,
                action="investigate_blind_spot",
                rationale=(
                    f"Prioritize under-tested surface {top.surface}/{top.weakness}; "
                    f"attempts={top.attempts}, changed={top.changed_since_last_attempt}, "
                    f"expected_value=${top.expected_value_usd:.2f}."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=min(1.0, 1.0 / (top.attempts + 1.0) + 0.4),
                metadata={"surface": top.surface, "weakness": top.weakness},
            ),
        )


class MissionSchedulerAgent:
    """Resume checkpointed missions and surface only dependency-ready tasks."""

    role = AgentRole.COMMANDER

    @staticmethod
    def next_ready(
        scheduler: MissionScheduler,
        mission_id: str,
    ) -> tuple[MissionPlan, tuple[str, ...]] | None:
        plan = scheduler.resume(mission_id)
        if plan is None:
            return None
        ready = scheduler.ready_tasks(plan)
        return plan, tuple(task.task_id for task in ready)

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("missions:resumable")
        if item is None or not item.value:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="resume_checkpointed_missions",
                rationale=(
                    "Resume incomplete missions from durable checkpoints and schedule only "
                    "dependency-ready work under the current authorization envelope."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.75,
                metadata={"memory_key": "missions:resumable"},
            ),
        )

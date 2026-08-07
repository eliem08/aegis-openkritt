"""Agentic security-research control plane for Aegis.

The module intentionally separates autonomous reasoning from action authority.
Agents produce evidence-linked proposals; the orchestrator decides whether a
proposal may execute under the active authorization, cost, network, and human
approval constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping, Protocol


class AgentRole(str, Enum):
    COMMANDER = "commander"
    PROGRAM_POLICY = "program_policy"
    ASSET_DISCOVERY = "asset_discovery"
    REPOSITORY_INTELLIGENCE = "repository_intelligence"
    ATTACK_SURFACE = "attack_surface"
    STATIC_ANALYSIS = "static_analysis"
    HYPOTHESIS = "hypothesis"
    INVARIANT = "invariant"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    API = "api"
    BUSINESS_LOGIC = "business_logic"
    DATAFLOW = "dataflow"
    DEPENDENCY = "dependency"
    CLOUD = "cloud"
    HISTORY = "history"
    VARIANT = "variant"
    REPRODUCTION = "reproduction"
    EVIDENCE = "evidence"
    JUDGE = "judge"
    PROFITABILITY = "profitability"
    REPORT = "report"


class RiskClass(str, Enum):
    OFFLINE = "offline"
    READ_ONLY = "read_only"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"
    FORBIDDEN = "forbidden"


class EvidenceStage(str, Enum):
    CANDIDATE = "candidate"
    SOURCE_SUPPORTED = "source_supported"
    RUNTIME_OBSERVED = "runtime_observed"
    ORACLE_PASSED = "oracle_passed"
    LOCALLY_REPRODUCED = "locally_reproduced"
    INDEPENDENTLY_VERIFIED = "independently_verified"
    HUMAN_APPROVED = "human_approved"
    SUBMISSION_READY = "submission_ready"


_STAGE_ORDER = {stage: index for index, stage in enumerate(EvidenceStage)}


@dataclass(frozen=True)
class Budget:
    max_cost_usd: float = 0.0
    max_requests: int = 0
    max_human_minutes: float = 0.0


@dataclass(frozen=True)
class AuthorizationEnvelope:
    scope_digest: str
    network_allowed: bool = False
    state_change_allowed: bool = False
    external_model_egress_allowed: bool = False
    human_approval: bool = False
    budget: Budget = field(default_factory=Budget)


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    kind: str
    digest: str
    summary: str = ""


@dataclass(frozen=True)
class AgentProposal:
    role: AgentRole
    action: str
    rationale: str
    risk: RiskClass
    expected_information_gain: float
    expected_cost_usd: float = 0.0
    expected_requests: int = 0
    expected_human_minutes: float = 0.0
    requires_network: bool = False
    requires_external_model: bool = False
    evidence: tuple[EvidenceRef, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def proposal_id(self) -> str:
        material = {
            "role": self.role.value,
            "action": self.action,
            "rationale": self.rationale,
            "risk": self.risk.value,
            "evidence": [e.digest for e in self.evidence],
            "metadata": dict(self.metadata),
        }
        digest = sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()
        return f"ap1:{digest}"


@dataclass(frozen=True)
class Decision:
    proposal_id: str
    approved: bool
    reason: str


class ProposalPolicy:
    """Fail-closed policy for autonomous agent proposals."""

    def evaluate(self, proposal: AgentProposal, authorization: AuthorizationEnvelope) -> Decision:
        if proposal.risk is RiskClass.FORBIDDEN:
            return Decision(proposal.proposal_id, False, "forbidden risk class")
        if proposal.requires_network and not authorization.network_allowed:
            return Decision(proposal.proposal_id, False, "network access is not authorized")
        if proposal.requires_external_model and not authorization.external_model_egress_allowed:
            return Decision(proposal.proposal_id, False, "external-model egress is not authorized")
        if proposal.risk is RiskClass.CONTROLLED_STATE_CHANGE:
            if not authorization.state_change_allowed:
                return Decision(proposal.proposal_id, False, "state changes are not authorized")
            if not authorization.human_approval:
                return Decision(proposal.proposal_id, False, "human approval is required")
        if proposal.expected_cost_usd > authorization.budget.max_cost_usd:
            return Decision(proposal.proposal_id, False, "proposal exceeds cost budget")
        if proposal.expected_requests > authorization.budget.max_requests:
            return Decision(proposal.proposal_id, False, "proposal exceeds request budget")
        if proposal.expected_human_minutes > authorization.budget.max_human_minutes:
            return Decision(proposal.proposal_id, False, "proposal exceeds human-review budget")
        return Decision(proposal.proposal_id, True, "authorized")


@dataclass
class FindingLifecycle:
    finding_id: str
    stage: EvidenceStage = EvidenceStage.CANDIDATE
    evidence: list[EvidenceRef] = field(default_factory=list)

    def advance(self, target: EvidenceStage, evidence: Iterable[EvidenceRef] = ()) -> None:
        current = _STAGE_ORDER[self.stage]
        requested = _STAGE_ORDER[target]
        if requested != current + 1:
            raise ValueError(f"invalid lifecycle transition: {self.stage.value} -> {target.value}")
        new_evidence = list(evidence)
        if target is not EvidenceStage.HUMAN_APPROVED and not new_evidence:
            raise ValueError("evidence is required for autonomous lifecycle advancement")
        self.evidence.extend(new_evidence)
        self.stage = target


@dataclass
class MemoryItem:
    key: str
    value: Any
    provenance: tuple[str, ...] = ()
    confidence: float = 1.0


class SharedMemory:
    """Small deterministic shared memory used by agents and resumable workspaces."""

    def __init__(self) -> None:
        self._items: dict[str, MemoryItem] = {}

    def put(self, item: MemoryItem) -> None:
        if not 0.0 <= item.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        self._items[item.key] = item

    def get(self, key: str) -> MemoryItem | None:
        return self._items.get(key)

    def snapshot(self) -> dict[str, Any]:
        return {
            key: {
                "value": item.value,
                "provenance": list(item.provenance),
                "confidence": item.confidence,
            }
            for key, item in sorted(self._items.items())
        }


@dataclass(frozen=True)
class GraphEdge:
    source: str
    relation: str
    target: str
    provenance: str
    confidence: float = 1.0


class SecurityKnowledgeGraph:
    """Minimal in-memory graph contract for security reasoning and persistence adapters."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[GraphEdge] = []

    def upsert_node(self, node_id: str, kind: str, **attributes: Any) -> None:
        current = self.nodes.setdefault(node_id, {"kind": kind})
        current.update(attributes)

    def connect(self, edge: GraphEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError("graph edges require existing source and target nodes")
        if not 0.0 <= edge.confidence <= 1.0:
            raise ValueError("edge confidence must be in [0, 1]")
        if edge not in self.edges:
            self.edges.append(edge)

    def neighbors(self, node_id: str, relation: str | None = None) -> tuple[str, ...]:
        result = {
            edge.target
            for edge in self.edges
            if edge.source == node_id and (relation is None or edge.relation == relation)
        }
        return tuple(sorted(result))


@dataclass
class AgentContext:
    authorization: AuthorizationEnvelope
    memory: SharedMemory
    graph: SecurityKnowledgeGraph
    lifecycles: dict[str, FindingLifecycle] = field(default_factory=dict)


class SecurityAgent(Protocol):
    role: AgentRole

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]: ...


class AgenticOrchestrator:
    """Coordinates specialists while retaining centralized action authority."""

    def __init__(self, agents: Iterable[SecurityAgent], policy: ProposalPolicy | None = None) -> None:
        self.agents = tuple(agents)
        self.policy = policy or ProposalPolicy()

    def planning_round(self, context: AgentContext) -> list[tuple[AgentProposal, Decision]]:
        evaluated: list[tuple[AgentProposal, Decision]] = []
        for agent in self.agents:
            for proposal in agent.propose(context):
                decision = self.policy.evaluate(proposal, context.authorization)
                evaluated.append((proposal, decision))
        evaluated.sort(
            key=lambda item: (
                not item[1].approved,
                -item[0].expected_information_gain,
                item[0].expected_cost_usd,
                item[0].proposal_id,
            )
        )
        return evaluated

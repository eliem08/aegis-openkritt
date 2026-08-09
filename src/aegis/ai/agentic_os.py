"""Agentic security-research control plane for Aegis.

The module intentionally separates autonomous reasoning from action authority.
Agents produce evidence-linked proposals; the orchestrator decides whether a
proposal may execute under the active authorization, cost, network, and human
approval constraints.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Iterable, Mapping, Protocol


class AgentRole(str, Enum):
    """Canonical agent roles.

    Legacy names are aliases rather than a second enum so old council code and the newer
    control plane cannot drift on role identity.
    """

    COMMANDER = "commander"
    PROGRAM_POLICY = "program_policy"
    POLICY = "program_policy"  # legacy alias
    ASSET_DISCOVERY = "asset_discovery"
    RECON = "asset_discovery"  # legacy alias
    REPOSITORY_INTELLIGENCE = "repository_intelligence"
    ATTACK_SURFACE = "attack_surface"
    STATIC_ANALYSIS = "static_analysis"
    HYPOTHESIS = "hypothesis"
    INVARIANT = "invariant"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    API = "api"
    BUSINESS_LOGIC = "business_logic"
    CLIENT = "client"
    DATAFLOW = "dataflow"
    DEPENDENCY = "dependency"
    SUPPLY_CHAIN = "dependency"  # legacy alias
    CLOUD = "cloud"
    HISTORY = "history"
    VARIANT = "variant"
    PATCH_VARIANT = "variant"  # legacy alias
    COVERAGE = "coverage"
    REPRODUCTION = "reproduction"
    EVIDENCE = "evidence"
    JUDGE = "judge"
    SKEPTIC = "judge"  # legacy alias
    PROFITABILITY = "profitability"
    REPORT = "report"
    REPORTING = "report"  # legacy alias


class RiskClass(str, Enum):
    OFFLINE = "offline"
    READ_ONLY = "read_only"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"
    FORBIDDEN = "forbidden"
    HIGH_RISK = "forbidden"  # legacy alias; fail closed rather than preserving ambiguity


class EvidenceStage(str, Enum):
    CANDIDATE = "candidate"
    SOURCE_SUPPORTED = "source_supported"
    RUNTIME_OBSERVED = "runtime_observed"
    ORACLE_PASSED = "oracle_passed"
    LOCALLY_REPRODUCED = "locally_reproduced"
    REPRODUCED = "locally_reproduced"  # legacy alias
    INDEPENDENTLY_VERIFIED = "independently_verified"
    HUMAN_APPROVED = "human_approved"
    SUBMISSION_READY = "submission_ready"


_STAGE_ORDER = {stage: index for index, stage in enumerate(EvidenceStage)}


@dataclass(frozen=True)
class Budget:
    max_cost_usd: float = 0.0
    max_requests: int = 0
    max_human_minutes: float = 0.0


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _decision_fingerprint(decision: Any) -> str:
    """Stable digest of a signed PolicyEngine decision, so a grant is bound to exactly one
    authorization verdict and cannot be replayed for a different action."""
    material = {
        "allowed": bool(getattr(decision, "allowed", False)),
        "verdict": str(getattr(getattr(decision, "verdict", None), "value", "")),
        "tier": str(getattr(getattr(decision, "tier", None), "value", "")),
        "approvals": sorted(getattr(decision, "required_approvals", []) or []),
        "fingerprint": str(getattr(decision, "fingerprint", "")
                           or getattr(decision, "request_id", "")),
    }
    return sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()[:24]


@dataclass(frozen=True)
class ExecutionGrant:
    """An immutable, signed capability grant. This is the ONLY object that may confer network or
    state-change authority on the agentic layer. It is minted exclusively by
    :func:`mint_execution_grant` from a *signed PolicyEngine decision* — Jarvis/agent code can
    never construct one with elevated capabilities on its own, and :class:`ProposalPolicy` refuses
    any network/state-change proposal whose envelope lacks a verifiable grant that permits it."""
    scope_digest: str
    network_allowed: bool
    state_change_allowed: bool
    external_model_egress_allowed: bool
    human_approval: bool
    budget: Budget
    decision_fingerprint: str
    issued_at: str
    nonce: str
    signature: str = ""

    def _payload(self) -> dict:
        return {"scope_digest": self.scope_digest, "network_allowed": self.network_allowed,
                "state_change_allowed": self.state_change_allowed,
                "external_model_egress_allowed": self.external_model_egress_allowed,
                "human_approval": self.human_approval,
                "budget": {"max_cost_usd": self.budget.max_cost_usd,
                           "max_requests": self.budget.max_requests,
                           "max_human_minutes": self.budget.max_human_minutes},
                "decision_fingerprint": self.decision_fingerprint,
                "issued_at": self.issued_at, "nonce": self.nonce}

    def verify(self, verifier, *, key_id: str = "grant") -> bool:
        if verifier is None or not self.signature:
            return False
        try:
            return bool(verifier.verify(self._payload(), self.signature, key_id))
        except Exception:
            return False


def mint_execution_grant(decision, *, scope_digest: str, budget: Budget, verifier,
                         key_id: str = "grant", network: bool = False,
                         state_change: bool = False, external_model_egress: bool = False,
                         human_approval: bool = False, now: datetime | None = None
                         ) -> ExecutionGrant:
    """Derive a signed :class:`ExecutionGrant` from a PolicyEngine ``decision``. Capabilities are
    clamped to what the engine ALLOWED — a denied decision yields an all-False (inert) grant, so
    the agentic layer can never obtain more authority than the signed policy authorized. Requires
    a signer (``verifier.sign``); callers without the signing key cannot forge a grant."""
    allowed = bool(getattr(decision, "allowed", False))
    grant = ExecutionGrant(
        scope_digest=str(scope_digest or "unknown"),
        network_allowed=bool(network and allowed),
        state_change_allowed=bool(state_change and allowed),
        external_model_egress_allowed=bool(external_model_egress),
        human_approval=bool(human_approval and allowed),
        budget=budget, decision_fingerprint=_decision_fingerprint(decision),
        issued_at=(now or _now()).isoformat(), nonce=secrets.token_hex(8))
    signature = verifier.sign(grant._payload(), key_id)
    return replace(grant, signature=signature)


@dataclass(frozen=True)
class HumanApprovalReceipt:
    """Cryptographic proof that a *named human* approved a *specific finding*. Required to reach
    HUMAN_APPROVED / SUBMISSION_READY — a privileged process can no longer flip the lifecycle to
    "approved" without a verifiable receipt bound to the finding."""
    finding_digest: str
    reviewer_id: str
    decision: str            # "approved" | "rejected" | "submit"
    issued_at: str
    nonce: str
    signature: str = ""

    def _payload(self) -> dict:
        return {"finding_digest": self.finding_digest, "reviewer_id": self.reviewer_id,
                "decision": self.decision, "issued_at": self.issued_at, "nonce": self.nonce}

    def verify(self, verifier, finding_id: str, *, key_id: str = "approval",
               accept: tuple[str, ...] = ("approved", "submit")) -> bool:
        if verifier is None or not self.signature:
            return False
        if self.decision not in accept or self.finding_digest != finding_id or not self.reviewer_id:
            return False
        try:
            return bool(verifier.verify(self._payload(), self.signature, key_id))
        except Exception:
            return False


def sign_human_approval(finding_id: str, reviewer_id: str, decision: str, *, verifier,
                        key_id: str = "approval", now: datetime | None = None
                        ) -> HumanApprovalReceipt:
    """Mint a signed human-approval receipt (approval service / operator tool holds the key)."""
    receipt = HumanApprovalReceipt(finding_digest=finding_id, reviewer_id=reviewer_id,
                                   decision=decision, issued_at=(now or _now()).isoformat(),
                                   nonce=secrets.token_hex(8))
    return replace(receipt, signature=verifier.sign(receipt._payload(), key_id))


_PROCESS_GRANT_VERIFIER: Any = None


def process_grant_verifier():
    """The verifier used to mint/verify execution grants + approval receipts on the agentic layer.

    Production: set ``AEGIS_GRANT_KEY`` (operator-held signing secret) — the operator controls the
    authority. Otherwise a per-process ephemeral key is used, so grants/receipts are unforgeable
    across processes and are never persisted to disk.
    """
    import os

    from ..policy.signing import HmacSignatureVerifier
    key = os.environ.get("AEGIS_GRANT_KEY", "").strip()
    if key:
        return HmacSignatureVerifier({"grant": key, "approval": key})
    global _PROCESS_GRANT_VERIFIER
    if _PROCESS_GRANT_VERIFIER is None:
        secret = secrets.token_hex(32)
        _PROCESS_GRANT_VERIFIER = HmacSignatureVerifier({"grant": secret, "approval": secret})
    return _PROCESS_GRANT_VERIFIER


@dataclass(frozen=True)
class AuthorizationEnvelope:
    scope_digest: str
    network_allowed: bool = False
    state_change_allowed: bool = False
    external_model_egress_allowed: bool = False
    human_approval: bool = False
    budget: Budget = field(default_factory=Budget)
    grant: ExecutionGrant | None = None   # signed capability grant; REQUIRED for network/state-change


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
    """Fail-closed policy for autonomous agent proposals.

    Network and controlled-state-change authority may come ONLY from a signed
    :class:`ExecutionGrant` (minted from a PolicyEngine decision), never from a boolean the
    agentic layer set on the envelope itself. Construct with the same ``verifier`` the
    PolicyEngine uses; without a verifier, any network/state-change proposal fails closed.
    """

    def __init__(self, verifier=None, *, grant_key_id: str = "grant") -> None:
        self._verifier = verifier
        self._grant_key_id = grant_key_id

    def _valid_grant(self, authorization: AuthorizationEnvelope) -> ExecutionGrant | None:
        grant = authorization.grant
        if grant is None:
            return None
        if not grant.verify(self._verifier, key_id=self._grant_key_id):
            return None
        return grant

    def evaluate(self, proposal: AgentProposal, authorization: AuthorizationEnvelope) -> Decision:
        if proposal.risk is RiskClass.FORBIDDEN:
            return Decision(proposal.proposal_id, False, "forbidden risk class")

        grant = self._valid_grant(authorization)

        # network authority: ONLY a verified ExecutionGrant may confer it (a self-set
        # authorization.network_allowed boolean is ignored — single-authority chain).
        if proposal.requires_network and not (grant and grant.network_allowed):
            return Decision(proposal.proposal_id, False,
                            "network access requires a verified policy-derived execution grant")
        # external-model egress (LLM calls, not target network) may come from the envelope or grant
        if proposal.requires_external_model and not (
                authorization.external_model_egress_allowed
                or (grant and grant.external_model_egress_allowed)):
            return Decision(proposal.proposal_id, False, "external-model egress is not authorized")
        if proposal.risk is RiskClass.CONTROLLED_STATE_CHANGE:
            if not (grant and grant.state_change_allowed):
                return Decision(proposal.proposal_id, False,
                                "state change requires a verified policy-derived execution grant")
            if not grant.human_approval:
                return Decision(proposal.proposal_id, False, "human approval is required")

        budget = grant.budget if grant else authorization.budget
        if proposal.expected_cost_usd > budget.max_cost_usd:
            return Decision(proposal.proposal_id, False, "proposal exceeds cost budget")
        if proposal.expected_requests > budget.max_requests:
            return Decision(proposal.proposal_id, False, "proposal exceeds request budget")
        if proposal.expected_human_minutes > budget.max_human_minutes:
            return Decision(proposal.proposal_id, False, "proposal exceeds human-review budget")
        return Decision(proposal.proposal_id, True, "authorized")


@dataclass
class FindingLifecycle:
    finding_id: str
    stage: EvidenceStage = EvidenceStage.CANDIDATE
    evidence: list[EvidenceRef] = field(default_factory=list)
    approvals: list[HumanApprovalReceipt] = field(default_factory=list)

    def advance(self, target: EvidenceStage, evidence: Iterable[EvidenceRef] = (), *,
                approval: HumanApprovalReceipt | None = None, verifier=None,
                approval_key_id: str = "approval") -> None:
        current = _STAGE_ORDER[self.stage]
        requested = _STAGE_ORDER[target]
        if requested != current + 1:
            raise ValueError(f"invalid lifecycle transition: {self.stage.value} -> {target.value}")
        new_evidence = list(evidence)
        # HUMAN_APPROVED and SUBMISSION_READY are human-gated: they require a cryptographically
        # verifiable HumanApprovalReceipt bound to THIS finding — not just a state flip. A
        # privileged process can no longer advance to "approved"/"submission ready" on its own.
        if target in (EvidenceStage.HUMAN_APPROVED, EvidenceStage.SUBMISSION_READY):
            if approval is None or not approval.verify(verifier, self.finding_id,
                                                       key_id=approval_key_id):
                raise ValueError(
                    f"{target.value} requires a valid signed HumanApprovalReceipt for this finding")
            self.approvals.append(approval)
        elif not new_evidence:
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
        # default to a verifier-backed policy so signed execution grants are actually checked
        self.policy = policy or ProposalPolicy(process_grant_verifier())

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

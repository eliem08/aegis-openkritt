"""Aegis next-generation intelligence and evidence foundations.

This module is execution-agnostic. It routes scope-bound facts, maintains an attack-
surface relationship graph, prioritizes work by net value and information gain, and
requires deterministic evidence plus human approval before a report is submission-ready.
It performs no live exploitation and no autonomous submission.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventType(str, Enum):
    DOMAIN = "domain_discovered"
    SUBDOMAIN = "subdomain_discovered"
    SERVICE = "service_observed"
    REPOSITORY = "repository_discovered"
    ENDPOINT = "endpoint_discovered"
    PARAMETER = "parameter_discovered"
    API_SCHEMA = "api_schema_discovered"
    STATIC_FINDING = "static_finding"
    DYNAMIC_OBSERVATION = "dynamic_observation"
    OAST_INTERACTION = "oast_interaction"
    REPRODUCED_FINDING = "reproduced_finding"
    REPORT_READY = "report_ready"


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    type: EventType
    scope_id: str
    engagement_id: str
    source_module: str
    asset_key: str = ""
    parent_event_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    observed_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    payload: dict = Field(default_factory=dict)

    @field_validator("scope_id", "engagement_id", "source_module")
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("scope, engagement, and source module are required")
        return value

    @model_validator(mode="after")
    def expiry_after_observation(self) -> "SecurityEvent":
        if self.expires_at is not None and self.expires_at <= self.observed_at:
            raise ValueError("expires_at must be later than observed_at")
        return self

    def fingerprint(self) -> str:
        material = {
            "schema": "aegis-event/v1", "type": self.type.value,
            "scope": self.scope_id, "engagement": self.engagement_id,
            "asset": self.asset_key.lower().strip(), "source": self.source_module,
            "payload": self.payload,
        }
        raw = json.dumps(material, sort_keys=True, default=str, separators=(",", ":"))
        return "evt1:" + hashlib.sha256(raw.encode()).hexdigest()


EventHandler = Callable[[SecurityEvent], Iterable[SecurityEvent] | None]


class EventBus:
    """Deterministic recursive router with scope, expiry, lineage, and dedup gates."""
    def __init__(self, *, scope_id: str, engagement_id: str, max_lineage: int = 32):
        if not scope_id or not engagement_id or max_lineage < 1:
            raise ValueError("valid scope, engagement, and lineage limit are required")
        self.scope_id, self.engagement_id, self.max_lineage = scope_id, engagement_id, max_lineage
        self._handlers: dict[EventType, list[tuple[str, EventHandler]]] = defaultdict(list)
        self._seen: dict[str, str] = {}
        self._events: list[SecurityEvent] = []
        self._audit: list[dict] = []

    def subscribe(self, event_type: EventType, module: str, handler: EventHandler) -> None:
        if not module.strip():
            raise ValueError("module name is required")
        self._handlers[event_type].append((module.strip(), handler))
        self._handlers[event_type].sort(key=lambda row: row[0])

    def publish(self, event: SecurityEvent) -> list[SecurityEvent]:
        queue, emitted = deque([event]), []
        while queue:
            current = queue.popleft()
            if current.scope_id != self.scope_id or current.engagement_id != self.engagement_id:
                raise PermissionError("event does not belong to this scope and engagement")
            if current.expires_at and current.expires_at <= utcnow():
                raise ValueError("expired event")
            if len(current.parent_event_ids) > self.max_lineage:
                raise ValueError("event lineage limit exceeded")
            fingerprint = current.fingerprint()
            if fingerprint in self._seen:
                self._audit.append({"action": "duplicate_suppressed", "event": current.event_id,
                                    "duplicate_of": self._seen[fingerprint]})
                continue
            self._seen[fingerprint] = current.event_id
            self._events.append(current)
            emitted.append(current)
            for module, handler in self._handlers.get(current.type, ()):
                for child in handler(current) or ():
                    if current.event_id not in child.parent_event_ids:
                        child = child.model_copy(update={"parent_event_ids":
                                                         (*child.parent_event_ids, current.event_id)})
                    self._audit.append({"action": "routed", "event": current.event_id,
                                        "consumer": module, "child": child.event_id})
                    queue.append(child)
        return emitted

    def events(self) -> list[SecurityEvent]:
        return list(self._events)

    def audit_log(self) -> list[dict]:
        return list(self._audit)


class NodeKind(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    SERVICE = "service"
    REPOSITORY = "repository"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    API_SCHEMA = "api_schema"
    FINDING = "finding"
    EVIDENCE = "evidence"


class EdgeKind(str, Enum):
    OWNS = "owns"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    CONTAINS = "contains"
    DISCOVERED_BY = "discovered_by"
    DERIVED_FROM = "derived_from"
    AFFECTS = "affects"
    REPRODUCES = "reproduces"


@dataclass
class GraphNode:
    key: str
    kind: NodeKind
    attributes: dict = field(default_factory=dict)
    provenance: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    confidence: float = 1.0


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: EdgeKind
    provenance: str
    confidence: float = 1.0


_EVENT_KIND = {
    EventType.DOMAIN: NodeKind.DOMAIN, EventType.SUBDOMAIN: NodeKind.SUBDOMAIN,
    EventType.SERVICE: NodeKind.SERVICE, EventType.REPOSITORY: NodeKind.REPOSITORY,
    EventType.ENDPOINT: NodeKind.ENDPOINT, EventType.PARAMETER: NodeKind.PARAMETER,
    EventType.API_SCHEMA: NodeKind.API_SCHEMA, EventType.STATIC_FINDING: NodeKind.FINDING,
    EventType.DYNAMIC_OBSERVATION: NodeKind.EVIDENCE, EventType.OAST_INTERACTION: NodeKind.EVIDENCE,
    EventType.REPRODUCED_FINDING: NodeKind.FINDING, EventType.REPORT_READY: NodeKind.EVIDENCE,
}


class AttackSurfaceGraph:
    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str, str], GraphEdge] = {}

    def ingest(self, event: SecurityEvent) -> GraphNode | None:
        kind = _EVENT_KIND.get(event.type)
        if kind is None or not event.asset_key:
            return None
        node = self.nodes.get(event.asset_key)
        if node is None:
            node = GraphNode(event.asset_key, kind, confidence=event.confidence,
                             first_seen=event.observed_at, last_seen=event.observed_at)
            self.nodes[node.key] = node
        elif node.kind != kind:
            raise ValueError("graph node kind conflict")
        node.attributes.update(event.payload)
        node.provenance.add(event.source_module)
        node.last_seen = max(node.last_seen, event.observed_at)
        node.confidence = max(node.confidence, event.confidence)
        try:
            relation = EdgeKind(event.payload.get("relation", "derived_from"))
        except ValueError:
            relation = EdgeKind.DERIVED_FROM
        for parent in event.payload.get("parent_asset_keys", ()):
            if parent in self.nodes:
                edge = GraphEdge(parent, node.key, relation, event.source_module, event.confidence)
                self.edges[(parent, node.key, relation.value)] = edge
        return node

    def neighbors(self, key: str, edge_kind: EdgeKind | None = None) -> list[GraphNode]:
        targets = {e.target for e in self.edges.values()
                   if e.source == key and (edge_kind is None or e.kind == edge_kind)}
        return [self.nodes[target] for target in sorted(targets)]


@dataclass(frozen=True)
class WorkOpportunity:
    opportunity_id: str
    expected_bounty: Decimal | None
    p_valid: float
    p_accepted: float
    uniqueness: float = 1.0
    duplicate_risk: float = 0.0
    report_quality: float = 1.0
    information_gain: float = 0.0
    model_cost: Decimal = Decimal(0)
    scanner_cost: Decimal = Decimal(0)
    review_cost: Decimal = Decimal(0)


@dataclass(frozen=True)
class WorkScore:
    opportunity_id: str
    gross_ev: Decimal
    total_cost: Decimal
    net_ev: Decimal
    information_value: Decimal
    priority: Decimal
    profitable: bool


def score_opportunity(item: WorkOpportunity) -> WorkScore:
    for name in ("p_valid", "p_accepted", "uniqueness", "duplicate_risk",
                 "report_quality", "information_gain"):
        if not 0 <= getattr(item, name) <= 1:
            raise ValueError(f"{name} must be in [0, 1]")
    bounty = item.expected_bounty or Decimal(0)
    gross = (Decimal(str(item.p_valid)) * Decimal(str(item.p_accepted)) * bounty
             * Decimal(str(item.uniqueness)) * Decimal(str(1 - item.duplicate_risk))
             * Decimal(str(item.report_quality)))
    cost = item.model_cost + item.scanner_cost + item.review_cost
    net = gross - cost
    information = Decimal(str(item.information_gain)) * max(bounty, Decimal("1"))
    return WorkScore(item.opportunity_id, gross, cost, net, information, net + information, net > 0)


def rank_opportunities(items: Iterable[WorkOpportunity]) -> list[WorkScore]:
    return sorted((score_opportunity(item) for item in items),
                  key=lambda row: (-row.priority, -row.net_ev, row.opportunity_id))


class ReproductionState(str, Enum):
    CANDIDATE = "candidate"
    SOURCE_VALIDATED = "source_validated"
    APPLICATION_STARTED = "application_started"
    REQUEST_EXECUTED = "request_executed"
    ORACLE_PASSED = "oracle_passed"
    LOCALLY_REPRODUCED = "locally_reproduced"
    INDEPENDENTLY_VERIFIED = "independently_verified"
    HUMAN_APPROVED = "human_approved"
    SUBMISSION_READY = "submission_ready"
    REJECTED = "rejected"


_TRANSITIONS = {
    ReproductionState.CANDIDATE: {ReproductionState.SOURCE_VALIDATED, ReproductionState.REJECTED},
    ReproductionState.SOURCE_VALIDATED: {ReproductionState.APPLICATION_STARTED, ReproductionState.REJECTED},
    ReproductionState.APPLICATION_STARTED: {ReproductionState.REQUEST_EXECUTED, ReproductionState.REJECTED},
    ReproductionState.REQUEST_EXECUTED: {ReproductionState.ORACLE_PASSED, ReproductionState.REJECTED},
    ReproductionState.ORACLE_PASSED: {ReproductionState.LOCALLY_REPRODUCED, ReproductionState.REJECTED},
    ReproductionState.LOCALLY_REPRODUCED: {ReproductionState.INDEPENDENTLY_VERIFIED, ReproductionState.REJECTED},
    ReproductionState.INDEPENDENTLY_VERIFIED: {ReproductionState.HUMAN_APPROVED, ReproductionState.REJECTED},
    ReproductionState.HUMAN_APPROVED: {ReproductionState.SUBMISSION_READY, ReproductionState.REJECTED},
    ReproductionState.SUBMISSION_READY: set(), ReproductionState.REJECTED: set(),
}


class FindingLifecycle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    state: ReproductionState = ReproductionState.CANDIDATE
    history: list[dict] = Field(default_factory=list)

    def transition(self, state: ReproductionState, *, actor: str, reason: str,
                   evidence_refs: tuple[str, ...] = ()) -> None:
        if state not in _TRANSITIONS[self.state]:
            raise ValueError(f"invalid transition {self.state.value} -> {state.value}")
        evidence_states = {ReproductionState.SOURCE_VALIDATED, ReproductionState.REQUEST_EXECUTED,
                           ReproductionState.ORACLE_PASSED, ReproductionState.LOCALLY_REPRODUCED,
                           ReproductionState.INDEPENDENTLY_VERIFIED}
        if state in evidence_states and not evidence_refs:
            raise ValueError(f"{state.value} requires evidence")
        if state == ReproductionState.HUMAN_APPROVED and actor.startswith("agent:"):
            raise PermissionError("an agent cannot issue human approval")
        self.history.append({"from": self.state.value, "to": state.value, "actor": actor,
                             "reason": reason, "evidence_refs": list(evidence_refs),
                             "at": utcnow().isoformat()})
        self.state = state


@dataclass(frozen=True)
class CapturedResponse:
    identity: str
    status_code: int
    body: Any
    side_effects: tuple[str, ...] = ()

    def text(self) -> str:
        return json.dumps(self.body, sort_keys=True, default=str) if isinstance(self.body, (dict, list)) else str(self.body)


@dataclass(frozen=True)
class DifferentialResult:
    passed: bool
    finding_class: str
    reason: str
    confidence: float
    evidence: dict


def authorization_differential(owner: CapturedResponse, alternate: CapturedResponse,
                               nonexistent: CapturedResponse, *, canary: str) -> DifferentialResult:
    if not canary or owner.identity == alternate.identity:
        raise ValueError("a canary and two distinct identities are required")
    owner_has, alternate_has, missing_has = canary in owner.text(), canary in alternate.text(), canary in nonexistent.text()
    evidence = {"owner_status": owner.status_code, "alternate_status": alternate.status_code,
                "nonexistent_status": nonexistent.status_code,
                "alternate_received_canary": alternate_has, "nonexistent_received_canary": missing_has}
    if owner_has and alternate_has and not missing_has and alternate.status_code < 400:
        return DifferentialResult(True, "cross_identity_data_exposure",
                                  "alternate identity received owner-only canary", 0.98, evidence)
    if alternate.side_effects and alternate.side_effects != nonexistent.side_effects:
        return DifferentialResult(True, "cross_identity_state_change",
                                  "alternate identity caused protected side effect", 0.94, evidence)
    return DifferentialResult(False, "not_reproduced", "no controlled cross-identity impact", 0.15, evidence)


_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s]+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"), re.compile(r"(?i)(x-api-key:\s*)[^\s]+"),
)


def redact_text(value: str) -> str:
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(r"\1<redacted>", value)
    return value


@dataclass(frozen=True)
class EvidenceArtifact:
    name: str
    content: str


class EvidenceBundleWriter:
    def __init__(self, root: str | Path, finding_id: str, commit_sha: str, scope_digest: str):
        self.root, self.finding_id = Path(root), finding_id
        self.commit_sha, self.scope_digest = commit_sha, scope_digest

    def write(self, artifacts: Iterable[EvidenceArtifact]) -> Path:
        directory = self.root / f"finding-{self.finding_id}"
        directory.mkdir(parents=True, exist_ok=False)
        manifest = {"schema": "aegis-evidence/v1", "finding_id": self.finding_id,
                    "commit_sha": self.commit_sha, "scope_digest": self.scope_digest,
                    "created_at": utcnow().isoformat(), "artifacts": []}
        for artifact in artifacts:
            name = Path(artifact.name).name
            if name != artifact.name or not name:
                raise ValueError("unsafe artifact name")
            body = redact_text(artifact.content)
            path = directory / name
            path.write_text(body, encoding="utf-8")
            os.chmod(path, 0o600)
            manifest["artifacts"].append({"name": name,
                "sha256": hashlib.sha256(body.encode()).hexdigest()})
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        manifest["bundle_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return directory

"""Policy-derived real hunting campaign coordination over the canonical runtime.

This module deliberately does not grant authority.  It translates exact, operator-
reviewed policy facts into auditable decisions; active execution still requires the
PolicyEngine to mint a signed ExecutionGrant for the scoped executor.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping, Protocol

from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, RiskClass, mint_execution_grant
from aegis.ai.jarvis.hunter_techniques import (
    TECHNIQUES,
    HunterTechnique,
    TechniqueDefinition,
)
from aegis.ai.jarvis.universal_mission import compile_opportunity_mission
from aegis.ai.jarvis.universal_runtime import canonical_asset_kind, opportunity_for_asset
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.authorization import Authorization, AuthorizationValidator
from aegis.policy.consequence import ConsequenceTier
from aegis.policy.decisions import ActionRequest
from aegis.policy.engine import PolicyEngine
from aegis.policy.killswitch import KillSwitch
from aegis.policy.scope import ScopeGuard
from aegis.scheduler.profit import rank

from .operator_manifest import (
    ImmutableRunStore,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)
from .operator_workflow import (
    AuthorizationSigner,
    PreparedOperatorRun,
    policy_snapshot_document,
    prepare_operator_run,
)


class CampaignRunnerError(RuntimeError):
    """A campaign could not be prepared without weakening a safety invariant."""


class DecisionStatus(str, Enum):
    AUTHORIZED = "authorized"
    WAITING_FOR_PREREQUISITE = "waiting_for_prerequisite"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    DENIED_POLICY_AMBIGUOUS = "denied_policy_ambiguous"
    DENIED_ASSET_INELIGIBLE = "denied_asset_ineligible"
    DENIED_OPERATOR_APPROVAL = "denied_operator_approval"
    DENIED_BACKEND_UNSAFE = "denied_backend_unsafe"
    DENIED_CONSTRAINT_UNENFORCEABLE = "denied_constraint_unenforceable"


class PermissionEffect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PolicyEvidence:
    source_reference: str
    snapshot_timestamp: str
    snapshot_digest: str
    rule_id: str
    adapter_version: str
    evidence_span: str

    def __post_init__(self) -> None:
        if not all(asdict(self).values()):
            raise ValueError("policy evidence provenance must be complete")


@dataclass(frozen=True, slots=True)
class TypedTechniquePermission:
    technique: HunterTechnique
    asset: str
    context: str
    effect: PermissionEffect
    policy_action: str
    typed_constraints: Mapping[str, Any]
    evidence: PolicyEvidence

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["technique"] = self.technique.value
        value["effect"] = self.effect.value
        return value


@dataclass(frozen=True, slots=True)
class OperatorTechniqueApproval:
    approval_id: str
    campaign_id: str
    technique: HunterTechnique
    asset: str
    context: str
    identity_refs: tuple[str, ...]
    valid_from: str
    valid_until: str
    key_id: str
    signature: str = ""
    version: int = 1

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("operator approval version must be positive")

    def signing_payload(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "campaign_id": self.campaign_id,
            "technique": self.technique.value,
            "asset": self.asset,
            "context": self.context,
            "identity_refs": list(self.identity_refs),
            "version": self.version,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    def valid_at(self, now: datetime) -> bool:
        try:
            start = datetime.fromisoformat(self.valid_from)
            end = datetime.fromisoformat(self.valid_until)
        except ValueError:
            return False
        if start.tzinfo is None or end.tzinfo is None:
            return False
        return start <= now <= end


def sign_operator_approval(
    approval: OperatorTechniqueApproval, signer: AuthorizationSigner,
) -> OperatorTechniqueApproval:
    """Sign an exact campaign/technique/asset/context approval receipt."""
    if approval.signature:
        raise ValueError("operator approval is already signed")
    return replace(
        approval,
        key_id=signer.key_id,
        signature=signer.sign(approval.signing_payload()),
    )


@dataclass(frozen=True, slots=True)
class BackendCapability:
    worker_capability: str
    backend: str
    backend_version: str
    available: bool
    safe: bool
    enforceable_constraints: tuple[str, ...]
    satisfied_prerequisites: tuple[str, ...] = ()
    unavailable_reason: str = ""

    def __post_init__(self) -> None:
        if not all((self.worker_capability, self.backend, self.backend_version)):
            raise ValueError("backend capability identity and version are required")
        if type(self.available) is not bool or type(self.safe) is not bool:
            raise ValueError("backend availability and safety must be explicit booleans")


@dataclass(frozen=True, slots=True)
class TechniqueRequest:
    technique: HunterTechnique
    asset: str
    context: str = "default"
    identity_refs: tuple[str, ...] = ()
    execution_inputs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        forbidden = {"password", "token", "secret", "credential", "api_key"}
        if forbidden & {str(key).casefold() for key in self.execution_inputs}:
            raise ValueError("campaign execution inputs may contain references, not credentials")


@dataclass(frozen=True, slots=True)
class CampaignRequest:
    campaign_id: str
    operator_id: str
    techniques: tuple[TechniqueRequest, ...]
    budgets: RunBudgets

    def __post_init__(self) -> None:
        if not self.campaign_id or not self.operator_id or not self.techniques:
            raise ValueError("campaign identity and requested techniques are required")
        keys = [(item.technique, item.asset, item.context) for item in self.techniques]
        if len(keys) != len(set(keys)):
            raise ValueError("campaign technique, asset, and context requests must be unique")


@dataclass(frozen=True, slots=True)
class TechniqueAuthorizationDecision:
    decision_id: str
    version: int
    campaign_id: str
    technique: HunterTechnique
    program: str
    asset: str
    context: str
    policy_snapshot_digest: str
    policy_rule_ids: tuple[str, ...]
    policy_adapter_version: str
    policy_evidence: tuple[Mapping[str, Any], ...]
    operator_approval_id: str | None
    identity_refs: tuple[str, ...]
    execution_input_digest: str
    backend: str | None
    backend_version: str | None
    policy_action: str | None
    typed_constraints: Mapping[str, Any]
    budgets: Mapping[str, Any]
    status: DecisionStatus
    denial_reason: str | None
    grant_id: str | None = None
    computed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["technique"] = self.technique.value
        value["status"] = self.status.value
        return value

    @property
    def digest(self) -> str:
        return document_digest(self.document())


@dataclass(frozen=True, slots=True)
class PreparedCampaign:
    operator_run: PreparedOperatorRun
    request: CampaignRequest
    decisions: tuple[TechniqueAuthorizationDecision, ...]
    opportunities: tuple[Any, ...]
    missions: tuple[Any, ...]


class ProgramSnapshotProvider(Protocol):
    def __call__(self) -> ProgramSnapshot: ...


_IDENTITY_PREREQUISITES = {
    "two_controlled_identities",
    "two_controlled_roles",
    "two_controlled_tenants",
    "two_controlled_clients",
    "controlled_client",
    "synthetic_account",
}

_CONSTRAINTS_BY_TECHNIQUE: dict[HunterTechnique, frozenset[str]] = {
    HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL: frozenset({
        "max_concurrency", "max_attempts", "owned_object_refs", "state_verification",
    }),
    HunterTechnique.SSRF_URL_CONSUMER: frozenset({
        "allowed_destinations", "max_callbacks", "callback_timeout_seconds",
    }),
    HunterTechnique.SSRF_ASYNC_CALLBACK: frozenset({
        "allowed_destinations", "max_callbacks", "callback_timeout_seconds",
    }),
    HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR: frozenset({
        "allowed_destinations", "max_callbacks", "callback_timeout_seconds",
    }),
    HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL: frozenset({
        "max_upload_bytes", "allowed_content_types", "cleanup_required",
    }),
}


def _policy_action(definition: TechniqueDefinition) -> str:
    if definition.risk_class is RiskClass.OFFLINE:
        return "source_analysis"
    if definition.technique in {
        HunterTechnique.SSRF_URL_CONSUMER,
        HunterTechnique.SSRF_ASYNC_CALLBACK,
        HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR,
    }:
        return "server_side_request_forgery"
    if definition.technique is HunterTechnique.AUTH_TENANT_DIFFERENTIAL:
        return "cross_tenant_proof"
    if definition.technique is HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL:
        return "upload_benign_marker"
    if definition.risk_class is RiskClass.READ_ONLY:
        return "authenticated_testing"
    return "safe_state_change"


def _required_constraints(definition: TechniqueDefinition) -> frozenset[str]:
    base = {"max_requests", "max_cost_usd"}
    if definition.risk_class is not RiskClass.OFFLINE:
        base.update({"allowed_destinations", "allowed_methods"})
    return frozenset(base) | _CONSTRAINTS_BY_TECHNIQUE.get(
        definition.technique, frozenset(),
    )


def _constraint_semantic_error(
    definition: TechniqueDefinition,
    constraints: Mapping[str, Any],
    request: CampaignRequest,
    asset: str,
) -> str | None:
    try:
        if definition.risk_class is not RiskClass.OFFLINE:
            destinations = tuple(str(item) for item in constraints["allowed_destinations"])
            methods = tuple(str(item).upper() for item in constraints["allowed_methods"])
            scope = ScopeGuard([asset])
            if not destinations or any(not scope.is_allowed(item) for item in destinations):
                return "every active destination must remain within the selected asset scope"
            supported = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
            if not methods or any(item not in supported for item in methods):
                return "active methods must be explicit and supported"
        if definition.technique is HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL and (
            int(constraints["max_concurrency"]) > request.budgets.max_concurrent_sessions
            or int(constraints["max_attempts"]) > request.budgets.max_attempts
            or not constraints["owned_object_refs"]
            or constraints["state_verification"] is not True
        ):
            return "race bounds, owned objects, and state verification are not enforceable"
        if definition.technique in {
            HunterTechnique.SSRF_URL_CONSUMER,
            HunterTechnique.SSRF_ASYNC_CALLBACK,
            HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR,
        } and (
            int(constraints["max_callbacks"]) <= 0
            or float(constraints["callback_timeout_seconds"]) <= 0
        ):
            return "OAST callback count and timeout must be positive"
        if definition.technique is HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL and (
            int(constraints["max_upload_bytes"]) <= 0
            or not constraints["allowed_content_types"]
            or constraints["cleanup_required"] is not True
        ):
            return "upload size, content types, and cleanup must be enforceable"
    except (KeyError, TypeError, ValueError):
        return "technique-specific constraints are malformed"
    return None


class CampaignDecisionEvaluator:
    """Compute typed decisions; ambiguous prose and partial matches always deny."""

    def __init__(self, approval_verifier: Any) -> None:
        self.approval_verifier = approval_verifier

    def evaluate(
        self,
        snapshot: ProgramSnapshot,
        request: CampaignRequest,
        technique_request: TechniqueRequest,
        *,
        permissions: tuple[TypedTechniquePermission, ...],
        approvals: tuple[OperatorTechniqueApproval, ...],
        backends: tuple[BackendCapability, ...],
        version: int = 1,
        now: datetime | None = None,
    ) -> TechniqueAuthorizationDecision:
        observed = (now or datetime.now(UTC)).astimezone(UTC)
        definition = TECHNIQUES[technique_request.technique]
        policy_digest = document_digest(policy_snapshot_document(snapshot))
        base: dict[str, Any] = {
            "version": version,
            "campaign_id": request.campaign_id,
            "technique": technique_request.technique,
            "program": snapshot.rules.handle,
            "asset": technique_request.asset,
            "context": technique_request.context,
            "policy_snapshot_digest": policy_digest,
            "policy_rule_ids": (),
            "policy_adapter_version": "",
            "policy_evidence": (),
            "operator_approval_id": None,
            "identity_refs": technique_request.identity_refs,
            "execution_input_digest": document_digest(dict(technique_request.execution_inputs)),
            "backend": None,
            "backend_version": None,
            "policy_action": None,
            "typed_constraints": {},
            "budgets": asdict(request.budgets),
            "computed_at": observed.isoformat(),
        }

        def finish(status: DecisionStatus, reason: str, **changes: Any):
            values = base | changes
            identity = "\x1f".join((
                request.campaign_id, technique_request.technique.value,
                technique_request.asset, technique_request.context, str(version), policy_digest,
                str(base["execution_input_digest"]),
            ))
            return TechniqueAuthorizationDecision(
                decision_id="campaign-decision:" + sha256(identity.encode()).hexdigest()[:24],
                status=status, denial_reason=None if status is DecisionStatus.AUTHORIZED else reason,
                **values,
            )

        if snapshot.source in {"reports/programs.json", "candidate-registry"}:
            return finish(
                DecisionStatus.DENIED_POLICY_AMBIGUOUS,
                "candidate program data is not an authoritative policy source",
            )
        if (
            snapshot.authorization_expires_at <= observed
            or observed - snapshot.retrieved_at > timedelta(hours=1)
        ):
            return finish(
                DecisionStatus.DENIED_POLICY_AMBIGUOUS,
                "policy and scope snapshot is stale or expired",
            )
        if snapshot.rules.submission_state.strip().casefold() not in {"open", "active", "public"}:
            return finish(
                DecisionStatus.DENIED_POLICY_AMBIGUOUS,
                "program is not explicitly open or active",
            )
        if not snapshot.rules.automation_allowed or not snapshot.rules.ai_allowed:
            return finish(
                DecisionStatus.DENIED,
                "current program rules prohibit automated or AI-assisted testing",
            )
        eligible = {
            asset.identifier: asset for asset in snapshot.rules.in_scope
            if asset.eligible_for_submission
        }
        asset = eligible.get(technique_request.asset)
        if asset is None:
            return finish(
                DecisionStatus.DENIED_ASSET_INELIGIBLE,
                "asset is not an explicitly eligible row in the current scope snapshot",
            )
        if canonical_asset_kind(asset).value not in definition.compatible_asset_types:
            return finish(
                DecisionStatus.DENIED_ASSET_INELIGIBLE,
                "technique is incompatible with the selected asset type",
            )

        matches = tuple(permission for permission in permissions if (
            permission.technique is technique_request.technique
            and permission.asset == technique_request.asset
            and permission.context == technique_request.context
            and permission.evidence.snapshot_digest == policy_digest
            and permission.evidence.source_reference == snapshot.source
            and permission.evidence.snapshot_timestamp == snapshot.retrieved_at.isoformat()
        ))
        if len(matches) != 1:
            return finish(
                DecisionStatus.DENIED_POLICY_AMBIGUOUS,
                "no single exact typed policy permission matches technique, asset, context, and snapshot",
            )
        permission = matches[0]
        evidence_changes = {
            "policy_rule_ids": (permission.evidence.rule_id,),
            "policy_adapter_version": permission.evidence.adapter_version,
            "policy_evidence": (asdict(permission.evidence),),
            "policy_action": permission.policy_action,
            "typed_constraints": dict(permission.typed_constraints),
        }
        if permission.effect is PermissionEffect.DENY:
            return finish(DecisionStatus.DENIED, "current typed policy rule denies execution", **evidence_changes)
        expected_action = _policy_action(definition)
        if permission.policy_action != expected_action:
            return finish(
                DecisionStatus.DENIED_POLICY_AMBIGUOUS,
                "typed permission action does not match the canonical technique action",
                **evidence_changes,
            )

        approval_matches = tuple(approval for approval in approvals if (
            approval.campaign_id == request.campaign_id
            and approval.technique is technique_request.technique
            and approval.asset == technique_request.asset
            and approval.context == technique_request.context
            and approval.identity_refs == technique_request.identity_refs
        ))
        valid_approvals = tuple(approval for approval in approval_matches if (
            approval.valid_at(observed)
            and self.approval_verifier.verify(
                approval.signing_payload(), approval.signature, approval.key_id,
            )
        ))
        if len(valid_approvals) != 1:
            return finish(
                DecisionStatus.DENIED_OPERATOR_APPROVAL,
                "one valid exact operator approval receipt is required",
                **evidence_changes,
            )
        approval = valid_approvals[0]
        evidence_changes["operator_approval_id"] = approval.approval_id

        backend_matches = tuple(
            backend for backend in backends
            if backend.worker_capability == definition.worker_capability
        )
        if not backend_matches:
            return finish(
                DecisionStatus.UNAVAILABLE, "no registered backend implements the capability",
                **evidence_changes,
            )
        if len(backend_matches) != 1:
            return finish(
                DecisionStatus.DENIED_BACKEND_UNSAFE,
                "backend capability resolution is ambiguous",
                **evidence_changes,
            )
        backend = backend_matches[0]
        backend_changes = evidence_changes | {
            "backend": backend.backend, "backend_version": backend.backend_version,
        }
        if not backend.available:
            return finish(
                DecisionStatus.UNAVAILABLE,
                backend.unavailable_reason or "backend is unavailable",
                **backend_changes,
            )
        if not backend.safe:
            return finish(
                DecisionStatus.DENIED_BACKEND_UNSAFE,
                "backend cannot enforce the technique safety contract",
                **backend_changes,
            )
        missing_prerequisites = set(definition.required_prerequisites) - set(
            backend.satisfied_prerequisites
        )
        identity_needed = bool(_IDENTITY_PREREQUISITES & set(definition.required_prerequisites))
        if identity_needed and not technique_request.identity_refs:
            missing_prerequisites.add("operator_controlled_identity")
        if missing_prerequisites:
            return finish(
                DecisionStatus.WAITING_FOR_PREREQUISITE,
                "missing prerequisites: " + ", ".join(sorted(missing_prerequisites)),
                **backend_changes,
            )

        required = _required_constraints(definition)
        supplied = set(permission.typed_constraints)
        unenforceable = required - supplied
        backend_missing = required - set(backend.enforceable_constraints)
        if unenforceable or backend_missing:
            missing = sorted(unenforceable | backend_missing)
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                "required constraints are absent or unenforceable: " + ", ".join(missing),
                **backend_changes,
            )
        constraints = dict(permission.typed_constraints)
        try:
            requested_requests = int(constraints["max_requests"])
            requested_cost = float(constraints["max_cost_usd"])
        except (TypeError, ValueError):
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                "request and cost constraints must be numeric",
                **backend_changes,
            )
        if requested_requests <= 0 or requested_cost < 0:
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                "request constraint must be positive and cost cannot be negative",
                **backend_changes,
            )
        if requested_requests > request.budgets.max_requests:
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                "technique request budget exceeds the campaign budget",
                **backend_changes,
            )
        if requested_cost > request.budgets.max_cost_usd:
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                "technique cost budget exceeds the campaign budget",
                **backend_changes,
            )
        semantic_error = _constraint_semantic_error(
            definition, constraints, request, technique_request.asset,
        )
        if semantic_error:
            return finish(
                DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE,
                semantic_error,
                **backend_changes,
            )
        return finish(DecisionStatus.AUTHORIZED, "", **backend_changes)


def prepare_campaign(
    snapshot: ProgramSnapshot,
    request: CampaignRequest,
    *,
    permissions: tuple[TypedTechniquePermission, ...],
    approvals: tuple[OperatorTechniqueApproval, ...],
    backends: tuple[BackendCapability, ...],
    signer: AuthorizationSigner,
    store: ImmutableRunStore,
    effectiveness_repository: Any | None = None,
    now: datetime | None = None,
) -> PreparedCampaign:
    """Evaluate, persist, rank, and compile a campaign without executing it."""
    evaluator = CampaignDecisionEvaluator(signer.verifier())
    decisions = tuple(evaluator.evaluate(
        snapshot, request, item, permissions=permissions, approvals=approvals,
        backends=backends, now=now,
    ) for item in request.techniques)
    authorized = tuple(item for item in decisions if item.status is DecisionStatus.AUTHORIZED)
    if not authorized:
        raise CampaignRunnerError("campaign has no authorized executable techniques")
    selected_assets = tuple(dict.fromkeys(item.asset for item in authorized))
    identities = tuple(dict.fromkeys(
        identity for item in request.techniques for identity in item.identity_refs
    ))
    actions = tuple(sorted({str(item.policy_action) for item in authorized}))
    approval_actions = tuple(sorted({
        str(item.policy_action) for item in authorized
        if TECHNIQUES[item.technique].risk_class is RiskClass.CONTROLLED_STATE_CHANGE
    }))
    prepared = prepare_operator_run(
        snapshot,
        selected_assets=selected_assets,
        operator_id=request.operator_id,
        mode=RunMode.CAMPAIGN,
        budgets=request.budgets,
        signer=signer,
        store=store,
        controlled_identity_refs=identities,
        now=now,
        permitted_actions=actions,
        approval_required_for=approval_actions,
        operator_selections={
            "campaign_id": request.campaign_id,
            "requested_techniques": [item.technique.value for item in request.techniques],
        },
    )
    asset_by_name = {asset.identifier: asset for asset in prepared.program.in_scope}
    request_by_key = {
        (item.technique, item.asset, item.context): item for item in request.techniques
    }
    opportunities = []
    for decision in authorized:
        technique_request = request_by_key[
            (decision.technique, decision.asset, decision.context)
        ]
        definition = TECHNIQUES[decision.technique]
        base = opportunity_for_asset(
            prepared.program,
            asset_by_name[decision.asset],
            scope_digest=prepared.manifest.scope_digest,
            authorization_id=str(prepared.manifest.authorization["authorization_id"]),
        )
        technique_id = "opp:" + sha256(
            f"{base.opportunity_id}\x1f{decision.technique.value}\x1f{decision.context}".encode()
        ).hexdigest()[:20]
        opportunities.append(replace(
            base,
            opportunity_id=technique_id,
            weakness_family=decision.technique.value,
            metadata={
                **dict(base.metadata),
                "technique": decision.technique.value,
                "context": decision.context,
                "decision_id": decision.decision_id,
                "decision_digest": decision.digest,
                "worker_capability": definition.worker_capability,
                "risk_class": definition.risk_class.value,
                "evidence_requirements": list(definition.evidence_requirements),
                "expected_requests": int(decision.typed_constraints["max_requests"]),
                "execution_inputs": dict(technique_request.execution_inputs),
                "execution_input_digest": decision.execution_input_digest,
            },
        ))
    ranked_pairs = tuple(rank(opportunities))
    ranked = tuple(item for item, _score in ranked_pairs)
    score_by_id = {
        item.opportunity_id: result.net_expected_value for item, result in ranked_pairs
    }
    missions = tuple(compile_opportunity_mission(item) for item in ranked)
    for decision in decisions:
        path, digest = store.persist_evidence(
            prepared.manifest.run_id,
            {"kind": "technique_authorization_decision", **decision.document()},
        )
        store.append_event(
            prepared.manifest.run_id, "technique_authorization_decided", RunStatus.AUTHORIZED,
            {"decision_id": decision.decision_id, "decision_version": decision.version,
             "status": decision.status.value, "evidence_ref": path,
             "evidence_digest": digest},
        )
    store.append_event(
        prepared.manifest.run_id, "campaign_missions_compiled", RunStatus.PLANNED,
        {"campaign_id": request.campaign_id,
         "opportunity_ids": [item.opportunity_id for item in ranked],
         "mission_ids": [item.mission_id for item in missions],
         "actual_ranking": [item.opportunity_id for item in ranked],
         "execution_performed": False},
    )
    if effectiveness_repository is not None:
        try:
            from aegis.effectiveness.shadow import ShadowCandidate, build_shadow_batch

            shadow = build_shadow_batch(
                effectiveness_repository,
                tuple(ShadowCandidate(
                    item.opportunity_id,
                    str(item.metadata["technique"]),
                    score_by_id[item.opportunity_id],
                ) for item in ranked),
                batch_id=f"campaign:{request.campaign_id}:{prepared.manifest.run_id}",
                idempotency_key=f"campaign-shadow:{prepared.manifest.run_id}",
            )
            inserted = effectiveness_repository.record_shadow_batch(shadow)
            store.append_event(
                prepared.manifest.run_id, "campaign_shadow_ranking_recorded", RunStatus.PLANNED,
                {"batch_id": shadow.batch_id, "inserted": inserted,
                 "shadow_ranking": [
                     entry.opportunity_id for entry in sorted(
                         shadow.entries, key=lambda entry: entry.learned_rank,
                     )
                 ]},
            )
        except Exception as exc:
            store.append_event(
                prepared.manifest.run_id, "effectiveness_learning_degraded", RunStatus.PLANNED,
                {"error_type": type(exc).__name__, "execution_authority_changed": False},
            )
    else:
        store.append_event(
            prepared.manifest.run_id, "effectiveness_learning_degraded", RunStatus.PLANNED,
            {"error_type": "EffectivenessRepositoryUnavailable",
             "execution_authority_changed": False},
        )
    return PreparedCampaign(prepared, request, decisions, ranked, missions)


def _consumed_budget(store: ImmutableRunStore, run_id: str) -> tuple[int, float, int]:
    requests = 0
    cost = 0.0
    attempts = 0
    for event in store.events(run_id):
        requests += int(event.detail.get("requests_consumed", 0) or 0)
        cost += float(event.detail.get("cost_consumed", 0.0) or 0.0)
        attempts += int(event.detail.get("attempts_consumed", 0) or 0)
    return requests, cost, attempts


def _persist_decision(
    store: ImmutableRunStore,
    run_id: str,
    decision: TechniqueAuthorizationDecision,
) -> None:
    path, digest = store.persist_evidence(
        run_id, {"kind": "technique_authorization_decision", **decision.document()},
    )
    store.append_event(
        run_id, "technique_authorization_decided", RunStatus.AUTHORIZED,
        {"decision_id": decision.decision_id, "decision_version": decision.version,
         "status": decision.status.value, "evidence_ref": path,
         "evidence_digest": digest},
    )


def execute_campaign(
    prepared: PreparedCampaign,
    *,
    snapshot_provider: ProgramSnapshotProvider,
    permissions: tuple[TypedTechniquePermission, ...],
    approvals: tuple[OperatorTechniqueApproval, ...],
    backends: tuple[BackendCapability, ...],
    store: ImmutableRunStore,
    runtime: Any,
    availability: Any,
    authorization_verifier: Any,
    grant_verifier: Any,
    kill_switch: KillSwitch | None = None,
    executor_kwargs: Mapping[str, Any] | None = None,
    effectiveness_repository: Any | None = None,
    effectiveness_recorder: Any | None = None,
    now: datetime | None = None,
) -> tuple[Any, ...]:
    """Execute compiled missions with fresh scope, policy, grant, and budgets per task.

    A changed policy snapshot is recomputed and recorded as a new decision version,
    then execution stops.  The operator must prepare a fresh signed run rather than
    silently reusing an authorization derived from the earlier snapshot.
    """
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    manifest = prepared.operator_run.manifest
    store.verify(manifest.run_id)
    authorization = Authorization.model_validate(manifest.authorization)
    if AuthorizationValidator(authorization_verifier, require_signature=True).validate(
        authorization, observed,
    ):
        raise CampaignRunnerError("campaign authorization is stale or invalid")
    prior_events = store.events(manifest.run_id)
    completed = {
        str(event.detail.get("task_id")) for event in prior_events
        if event.event_type == "campaign_task_completed"
    }
    first_task_ids = {plan.tasks[0].task_id for plan in prepared.missions if plan.tasks}
    if first_task_ids and first_task_ids <= completed and any(
        event.event_type == "campaign_execution_complete" for event in prior_events
    ):
        return ()
    started = datetime.fromisoformat(manifest.created_at)
    if started.tzinfo is None:
        raise CampaignRunnerError("campaign manifest timestamp is not timezone-aware")
    evaluator = CampaignDecisionEvaluator(authorization_verifier)
    request_by_key = {
        (item.technique.value, item.asset, item.context): item
        for item in prepared.request.techniques
    }
    decision_by_id = {item.decision_id: item for item in prepared.decisions}
    policy_engine = PolicyEngine(
        authorization=authorization,
        verifier=authorization_verifier,
        kill_switch=kill_switch or KillSwitch(),
    )
    outcomes: list[Any] = []
    for plan in prepared.missions:
        if not plan.tasks:
            continue
        task = plan.tasks[0]
        if task.task_id in completed:
            continue
        task_observed = (now or datetime.now(UTC)).astimezone(UTC)
        if AuthorizationValidator(
            authorization_verifier, require_signature=True,
        ).validate(authorization, task_observed):
            raise CampaignRunnerError("campaign authorization became stale before execution")
        requests_used, cost_used, attempts_used = _consumed_budget(store, manifest.run_id)
        elapsed = max(0.0, (task_observed - started).total_seconds())
        if (
            attempts_used >= manifest.budgets.max_attempts
            or requests_used + task.expected_requests > manifest.budgets.max_requests
            or cost_used + task.expected_cost_usd > manifest.budgets.max_cost_usd
            or elapsed >= manifest.budgets.max_duration_seconds
        ):
            store.append_event(
                manifest.run_id, "campaign_budget_exhausted", RunStatus.FAILED,
                {"task_id": task.task_id, "requests_consumed": 0,
                 "cost_consumed": 0.0, "attempts_consumed": 0},
            )
            raise CampaignRunnerError("monotonic campaign budget is exhausted")

        current = snapshot_provider()
        current_policy_digest = document_digest(policy_snapshot_document(current))
        decision_id = str((task.payload or {}).get("authorization_decision_id") or "")
        previous = decision_by_id.get(decision_id)
        if previous is None:
            raise CampaignRunnerError("mission is not linked to an authorization decision")
        key = (previous.technique.value, previous.asset, previous.context)
        technique_request = request_by_key.get(key)
        if technique_request is None:
            raise CampaignRunnerError("mission decision is not linked to the campaign request")
        if current_policy_digest != previous.policy_snapshot_digest:
            revised = evaluator.evaluate(
                current, prepared.request, technique_request,
                permissions=permissions, approvals=approvals, backends=backends,
                version=previous.version + 1, now=task_observed,
            )
            _persist_decision(store, manifest.run_id, revised)
            store.append_event(
                manifest.run_id, "campaign_policy_changed", RunStatus.REVOKED,
                {"task_id": task.task_id, "previous_decision_id": previous.decision_id,
                 "replacement_decision_id": revised.decision_id,
                 "replacement_status": revised.status.value},
            )
            raise CampaignRunnerError(
                "policy snapshot changed; fresh signed authorization is required",
            )
        current_decision = evaluator.evaluate(
            current, prepared.request, technique_request,
            permissions=permissions, approvals=approvals, backends=backends,
            version=previous.version, now=task_observed,
        )
        if current_decision.status is not DecisionStatus.AUTHORIZED:
            _persist_decision(store, manifest.run_id, current_decision)
            raise CampaignRunnerError(
                f"technique authorization is no longer executable: {current_decision.status.value}",
            )
        if (
            current_decision.policy_action != previous.policy_action
            or dict(current_decision.typed_constraints) != dict(previous.typed_constraints)
            or current_decision.operator_approval_id != previous.operator_approval_id
            or current_decision.backend != previous.backend
            or current_decision.backend_version != previous.backend_version
        ):
            _persist_decision(store, manifest.run_id, current_decision)
            raise CampaignRunnerError(
                "campaign authority inputs changed; fresh signed authorization is required",
            )
        execution_decision = previous
        definition = TECHNIQUES[execution_decision.technique]
        risk_tier = {
            RiskClass.OFFLINE: ConsequenceTier.PASSIVE,
            RiskClass.READ_ONLY: ConsequenceTier.NON_INVASIVE_ACTIVE,
            RiskClass.CONTROLLED_STATE_CHANGE: ConsequenceTier.STATE_CHANGING,
        }.get(definition.risk_class)
        if risk_tier is None:
            raise CampaignRunnerError("forbidden risk class cannot execute")
        action_request = ActionRequest(
            target=task.asset_locator,
            action=str(execution_decision.policy_action),
            tier_hint=risk_tier,
            description=f"{definition.worker_capability}:{task.action}",
            identity=technique_request.identity_refs[0] if technique_request.identity_refs else None,
            estimated_cost=task.expected_cost_usd,
            touches_production=definition.risk_class is not RiskClass.OFFLINE,
            request_id="campaign:" + sha256(
                f"{manifest.run_id}:{plan.mission_id}:{task.task_id}".encode()
            ).hexdigest()[:24],
        )
        preflight = policy_engine.authorize(action_request, now=task_observed, record=False)
        if preflight.required_approvals:
            action_request.approvals = frozenset(preflight.required_approvals)
        policy_decision = policy_engine.authorize(action_request, now=task_observed)
        if not policy_decision.allowed:
            store.append_event(
                manifest.run_id, "campaign_policy_blocked", RunStatus.FAILED,
                {"task_id": task.task_id, "decision": policy_decision.as_dict()},
            )
            raise CampaignRunnerError("canonical PolicyEngine denied the campaign task")
        constraints = {
            **dict(execution_decision.typed_constraints),
            "campaign_id": prepared.request.campaign_id,
            "technique": execution_decision.technique.value,
            "asset": execution_decision.asset,
            "context": execution_decision.context,
            "decision_digest": execution_decision.digest,
            "operator_approval_id": execution_decision.operator_approval_id,
            "execution_input_digest": execution_decision.execution_input_digest,
        }
        allowed_destinations = tuple(
            str(item) for item in constraints.get("allowed_destinations", ())
        )
        allowed_methods = tuple(
            str(item) for item in constraints.get("allowed_methods", ())
        )
        state_change = definition.risk_class is RiskClass.CONTROLLED_STATE_CHANGE
        network = definition.risk_class is not RiskClass.OFFLINE
        remaining_budget = Budget(
            max_cost_usd=max(0.0, manifest.budgets.max_cost_usd - cost_used),
            max_requests=max(0, manifest.budgets.max_requests - requests_used),
        )
        grant = mint_execution_grant(
            policy_decision,
            scope_digest=manifest.scope_digest,
            budget=remaining_budget,
            verifier=grant_verifier,
            network=network,
            state_change=state_change,
            human_approval=True,
            now=task_observed,
            allowed_destinations=allowed_destinations,
            allowed_methods=allowed_methods,
            constraints=constraints,
        )
        store.append_event(
            manifest.run_id, "campaign_execution_grant_minted", RunStatus.RUNNING,
            {"task_id": task.task_id, "decision_id": execution_decision.decision_id,
             "grant": grant._payload() | {"signature": grant.signature},
             "requests_consumed": 0, "cost_consumed": 0.0, "attempts_consumed": 0},
        )
        envelope = AuthorizationEnvelope(
            scope_digest=manifest.scope_digest,
            network_allowed=network,
            state_change_allowed=state_change,
            human_approval=True,
            budget=remaining_budget,
            grant=grant,
        )
        result = runtime.execute_first(
            plan,
            authorization=envelope,
            availability=availability,
            **dict(executor_kwargs or {}),
        )
        reserved_requests = max(0, task.expected_requests)
        reserved_cost = max(0.0, task.expected_cost_usd)
        if result.outcome is None:
            store.append_event(
                manifest.run_id, "campaign_task_not_completed", RunStatus.FAILED,
                {"task_id": task.task_id, "mission_id": plan.mission_id,
                 "disposition": result.disposition.value, "reason": result.reason,
                 "requests_consumed": reserved_requests,
                 "cost_consumed": reserved_cost, "attempts_consumed": 1},
            )
            outcomes.append(result)
            continue
        outcome_value = asdict(result.outcome) if hasattr(
            result.outcome, "__dataclass_fields__"
        ) else result.outcome
        outcome_document = json.loads(json.dumps(outcome_value, default=str))
        evidence_ref, evidence_digest = store.persist_evidence(manifest.run_id, {
            "schema_version": 1,
            "kind": "campaign_task_evidence",
            "campaign_id": prepared.request.campaign_id,
            "run_id": manifest.run_id,
            "mission_id": plan.mission_id,
            "opportunity_id": plan.opportunity_id,
            "task_id": task.task_id,
            "technique": execution_decision.technique.value,
            "asset": execution_decision.asset,
            "scope_digest": manifest.scope_digest,
            "policy_snapshot_digest": execution_decision.policy_snapshot_digest,
            "authorization_id": authorization.authorization_id,
            "grant": grant._payload() | {"signature": grant.signature},
            "outcome": outcome_document,
            "requests_consumed": reserved_requests,
            "cost_consumed": reserved_cost,
        })
        policy_engine.commit(policy_decision, action_request, now=task_observed)
        store.append_event(
            manifest.run_id, "campaign_task_completed", RunStatus.RUNNING,
            {"task_id": task.task_id, "mission_id": plan.mission_id,
             "opportunity_id": plan.opportunity_id,
             "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
             "requests_consumed": reserved_requests,
             "cost_consumed": reserved_cost, "attempts_consumed": 1},
        )
        if effectiveness_repository is not None:
            try:
                from aegis.effectiveness.service import ingest_lineage_document

                manifest_document = manifest.document()
                manifest_document["manifest_digest"] = document_digest(manifest_document)
                ingest_lineage_document(effectiveness_repository, {
                    "manifest": manifest_document,
                    "lineage": {
                        "run_id": manifest.run_id,
                        "mission_id": plan.mission_id,
                        "opportunity_id": plan.opportunity_id,
                        "technique": execution_decision.technique.value,
                        "program_id": execution_decision.program,
                        "asset_id": execution_decision.asset,
                        "weakness_family": execution_decision.technique.value,
                        "asset_class": plan.asset_kind,
                        "authentication_mode": (
                            "authenticated" if execution_decision.identity_refs
                            else "unauthenticated"
                        ),
                        "execution_mode": (
                            "static_offline" if definition.risk_class is RiskClass.OFFLINE
                            else "dynamic"
                        ),
                        "evidence_digest": evidence_digest,
                        "created_at": manifest.created_at,
                        "observed_at": task_observed.isoformat(),
                    },
                    "facts": ["opportunity_generated", "runtime_observed"],
                })
            except Exception as exc:
                store.append_event(
                    manifest.run_id, "effectiveness_learning_degraded", RunStatus.RUNNING,
                    {"task_id": task.task_id, "error_type": type(exc).__name__,
                     "execution_authority_changed": False},
                )
        if effectiveness_recorder is not None:
            try:
                effectiveness_recorder({
                    "run_id": manifest.run_id,
                    "mission_id": plan.mission_id,
                    "opportunity_id": plan.opportunity_id,
                    "technique": execution_decision.technique.value,
                    "program": execution_decision.program,
                    "asset": execution_decision.asset,
                    "evidence_digest": evidence_digest,
                })
            except Exception as exc:
                store.append_event(
                    manifest.run_id, "effectiveness_learning_degraded", RunStatus.RUNNING,
                    {"task_id": task.task_id, "error_type": type(exc).__name__},
                )
        outcomes.append(result)
    store.append_event(
        manifest.run_id, "campaign_execution_complete",
        RunStatus.EXECUTION_COMPLETE_OUTCOMES_PENDING,
        {"campaign_id": prepared.request.campaign_id,
         "completed_results": sum(item.outcome is not None for item in outcomes),
         "human_submission_required": True},
    )
    return tuple(outcomes)

"""Canonical fixture exercises projected into the arsenal coverage ledger."""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, mint_execution_grant
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.mission_capabilities import (
    ExecutionClass,
    MissionWorkerRegistry,
    WorkerCapability,
)
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionScheduler, MissionTask
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.policy.consequence import ConsequenceTier
from aegis.policy.decisions import ActionRequest
from aegis.policy.engine import PolicyEngine
from aegis.policy.signing import HmacSignatureVerifier
from aegis.production.operator_manifest import (
    ImmutableRunStore,
    OperatorRunManifest,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)

from .fixture_authority import (
    LOCAL_FIXTURE_ONLY,
    LocalFixtureSignatureVerifier,
    signed_fixture_authorization,
)
from .inventory import ArsenalInventoryBuilder
from .ledger import CoverageRepository
from .llm_lab import lab_summary, run_lab_cases
from .models import ArsenalCoverageState, CapabilityCoverageRecord, CapabilityMode

FIXTURE_CAPABILITY = "jarvis:arsenal:llm-security-fixture"
FIXTURE_POLICY_SNAPSHOT = {
    "authorization_class": LOCAL_FIXTURE_ONLY,
    "permitted_actions": ["source_analysis"],
    "prohibited_real_targets": True,
}


@dataclass(frozen=True, slots=True)
class ExerciseResult:
    run_id: str
    mission_id: str
    task_id: str
    capability_id: str
    result: ArsenalCoverageState
    evidence_ref: str
    evidence_digest: str
    coverage_recorded: bool
    coverage_recording_degraded: bool
    summary: Mapping[str, Any]

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["result"] = self.result.value
        return value


class _LabExecutorProvider:
    def __init__(self, policy_engine: PolicyEngine, grant_verifier) -> None:
        self.policy_engine = policy_engine
        self.grant_verifier = grant_verifier

    def runtime_executors(self):
        def execute(task, plan, authorization):
            grant = authorization.grant
            if grant is None:
                raise PermissionError("fixture execution requires a signed grant")
            constraints = dict(grant.constraints or {})
            if constraints.get("authorization_class") != LOCAL_FIXTURE_ONLY:
                raise PermissionError("fixture grant has the wrong authorization class")
            if constraints.get("capability_id") != "fixture:ai/llm-security-boundary":
                raise PermissionError("fixture grant is not bound to this capability")
            return lab_summary(run_lab_cases(
                policy_engine=self.policy_engine,
                valid_grant=grant,
                grant_verifier=self.grant_verifier,
            ))

        return {FIXTURE_CAPABILITY: execute}


def _manifest(run_id: str, authorization, *, scope_digest: str) -> OperatorRunManifest:
    policy_snapshot = FIXTURE_POLICY_SNAPSHOT
    scope_snapshot = {"assets": ["127.0.0.1"], "network_isolation": "loopback-only"}
    if scope_digest != document_digest(scope_snapshot):
        raise ValueError("fixture scope digest is not bound to the immutable scope snapshot")
    return OperatorRunManifest(
        schema_version=1, run_id=run_id, mode=RunMode.ARSENAL_FIXTURE,
        created_at=datetime.now(UTC).isoformat(), operator_id="local-fixture-operator",
        program_handle="aegis-local-fixtures", program_source="built-in deterministic fixtures",
        selected_assets=("127.0.0.1",), canary_asset=None, controlled_identity_refs=(),
        policy_snapshot=policy_snapshot, policy_digest=document_digest(policy_snapshot),
        scope_snapshot=scope_snapshot, scope_digest=scope_digest,
        operator_selections={"capabilities": ["fixture:ai/llm-security-boundary"]},
        budgets=RunBudgets(max_requests=1, requests_per_second=1.0, max_cost_usd=0.0,
                           max_duration_seconds=900, max_attempts=1),
        authorization=authorization.model_dump(mode="json"),
    )


def execute_llm_fixture(
    *,
    runs_dir: str | Path,
    coverage_repository: CoverageRepository | None = None,
) -> ExerciseResult:
    """Run the 16-case lab through MissionPlan -> PolicyEngine -> grant -> executor."""
    raw = HmacSignatureVerifier({
        "fixture-auth": secrets.token_bytes(32), "grant": secrets.token_bytes(32),
    })
    verifier = LocalFixtureSignatureVerifier(raw)
    authorization = signed_fixture_authorization(verifier)
    policy_engine = PolicyEngine(authorization=authorization, verifier=verifier)
    request = ActionRequest(
        target="127.0.0.1", action="source_analysis", tier_hint=ConsequenceTier.PASSIVE,
        description="deterministic local AI/LLM security boundary exercise",
        touches_production=False, request_id="arsenal:llm-security-fixture",
    )
    decision = policy_engine.authorize(request)
    if not decision.allowed:
        raise PermissionError("PolicyEngine denied the local fixture exercise")

    scope_digest = document_digest({
        "assets": ["127.0.0.1"], "network_isolation": "loopback-only",
    })
    grant = mint_execution_grant(
        decision, scope_digest=scope_digest, budget=Budget(0.0, 1, 0.0), verifier=verifier,
        constraints={
            "authorization_class": LOCAL_FIXTURE_ONLY,
            "capability_id": "fixture:ai/llm-security-boundary",
            "fixture_version": "llm-security-fixture-v1",
            "oracle_version": "boundary-oracle-v1",
        },
    )
    now = datetime.now(UTC)
    key = sha256(f"{now.isoformat()}:{grant.nonce}".encode()).hexdigest()[:16]
    run_id = f"arsenal-{now.strftime('%Y%m%dT%H%M%SZ')}-{key[:8]}"
    mission_id = f"arsenal-llm-{key}"
    task_id = f"{mission_id}-execute"
    store = ImmutableRunStore(runs_dir)
    store.create(_manifest(run_id, authorization, scope_digest=scope_digest))
    store.append_event(run_id, "arsenal_fixture_authorized", RunStatus.AUTHORIZED, {
        "policy_decision": decision.as_dict(), "grant": grant._payload(),
        "grant_signature_digest": sha256(grant.signature.encode()).hexdigest(),
    })
    task = MissionTask(
        task_id, "reproduction", "execute_llm_security_fixture", payload={
            "authorization_class": LOCAL_FIXTURE_ONLY,
            "fixture_version": "llm-security-fixture-v1",
        }, opportunity_id=f"fixture-opp-{key}", asset_id="fixture:ai-lab",
        asset_kind="ai_model", asset_locator="127.0.0.1",
        executor_capability=FIXTURE_CAPABILITY, risk="offline", expected_requests=0,
        expected_cost_usd=0.0, evidence_required=("deterministic_oracle_results",),
        idempotency_key=f"{mission_id}:{task_id}",
    )
    plan = MissionPlan(
        mission_id, scope_digest, "Validate canonical AI/LLM security boundaries",
        (task,), opportunity_id=task.opportunity_id, program_id="aegis-local-fixtures",
        asset_id=task.asset_id, asset_kind=task.asset_kind,
        authorization_id=authorization.authorization_id,
    )
    state = JarvisStateStore(":memory:")
    scheduler = MissionScheduler(state)
    plan = scheduler.create(plan)
    provider = _LabExecutorProvider(policy_engine, verifier)
    runtime = UniversalMissionRuntime(
        scheduler, grant_verifier=verifier,
        workers=MissionWorkerRegistry((WorkerCapability(
            FIXTURE_CAPABILITY, ExecutionClass.INTERNAL_EXECUTOR, asset_kinds=("ai_model",),
            risk_classes=("offline",),
        ),)), executor_providers=(provider,),
    )
    store.append_event(run_id, "arsenal_task_started", RunStatus.RUNNING, {
        "mission_id": mission_id, "task_id": task_id,
        "capability_id": "fixture:ai/llm-security-boundary",
    })
    outcome = runtime.execute_first(
        plan,
        authorization=AuthorizationEnvelope(
            scope_digest, budget=Budget(0.0, 1, 0.0), grant=grant,
        ),
        availability=CapabilityAvailability(),
    )
    summary = dict(outcome.outcome or {})
    passed = (
        outcome.disposition.value == "ready"
        and summary.get("verdict") == "AI/LLM SECURITY VALIDATION PASS"
    )
    evidence = {
        "kind": "arsenal_fixture_execution", "capability_id": "fixture:ai/llm-security-boundary",
        "mode": CapabilityMode.FIXTURE.value, "run_id": run_id, "mission_id": mission_id,
        "task_id": task_id, "policy_decision": decision.as_dict(),
        "execution_grant_payload": grant._payload(), "runtime_disposition": outcome.disposition.value,
        "runtime_reason": outcome.reason, "summary": summary,
        "negative_control_status": "PASSED" if passed else "FAILED",
        "execution_performed": outcome.disposition.value == "ready",
    }
    evidence_ref, evidence_digest = store.persist_evidence(run_id, evidence)
    state_value = ArsenalCoverageState.EXECUTED_PASS if passed else ArsenalCoverageState.UNAVAILABLE
    store.append_event(run_id, "arsenal_task_completed", RunStatus.COMPLETED if passed else RunStatus.FAILED, {
        "capability_id": "fixture:ai/llm-security-boundary", "mode": CapabilityMode.FIXTURE.value,
        "mission_id": mission_id, "task_id": task_id, "backend": "canonical-llm-lab",
        "backend_version": "1", "policy_snapshot_digest": document_digest(
            FIXTURE_POLICY_SNAPSHOT
        ),
        "asset": "127.0.0.1", "authorization_decision": decision.request_id or "",
        "execution_grant_id": grant.nonce, "evidence_ref": evidence_ref,
        "evidence_digest": evidence_digest, "result": state_value.value,
        "negative_control_status": "PASSED" if passed else "FAILED", "finding_ids": [],
    })
    coverage_recorded = False
    degraded = False
    if coverage_repository is not None:
        record = CapabilityCoverageRecord(
            coverage_record_id=f"acr:{sha256((run_id + task_id).encode()).hexdigest()[:24]}",
            idempotency_key=f"arsenal:{run_id}:{task_id}",
            capability_id="fixture:ai/llm-security-boundary", mode=CapabilityMode.FIXTURE,
            tool_name="aegis-llm-lab", tool_version="1", technique_id="ai-llm-boundary",
            asset_classes=("ai_model",), implementation_path="aegis.arsenal.llm_lab",
            backend="canonical-llm-lab", backend_version="1", backend_health="HEALTHY",
            policy_snapshot_digest=document_digest(FIXTURE_POLICY_SNAPSHOT),
            asset="127.0.0.1",
            authorization_decision=decision.request_id or "", operator_approval_id=None,
            execution_grant_id=grant.nonce, run_id=run_id, mission_id=mission_id, task_id=task_id,
            executed=outcome.disposition.value == "ready", execution_timestamp=now.isoformat(),
            evidence_digest=evidence_digest, result=state_value,
            negative_control_status="PASSED" if passed else "FAILED",
            error_or_block_reason="" if passed else outcome.reason,
        )
        try:
            _, coverage_recorded = coverage_repository.record(record)
        except Exception as exc:
            degraded = True
            store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
                "error_class": type(exc).__name__, "execution_result_remains_canonical": True,
            })
    else:
        degraded = True
        store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
            "error_class": "CoverageRepositoryUnavailable",
            "execution_result_remains_canonical": True,
        })
    store.verify(run_id)
    state.close()
    return ExerciseResult(
        run_id, mission_id, task_id, "fixture:ai/llm-security-boundary", state_value,
        evidence_ref, evidence_digest, coverage_recorded, degraded, summary,
    )


def record_blocked_fixture(
    capability_id: str,
    *,
    state_value: ArsenalCoverageState,
    reason: str,
    runs_dir: str | Path,
    coverage_repository: CoverageRepository | None = None,
) -> ExerciseResult:
    """Persist a planned fixture that cannot honestly reach grant issuance/execution."""
    if state_value in {
        ArsenalCoverageState.EXECUTED_PASS,
        ArsenalCoverageState.EXECUTED_FINDING,
    }:
        raise ValueError("blocked fixture cannot use an executed terminal state")
    definitions = {
        item.capability_id: item for item in ArsenalInventoryBuilder().build()
    }
    definition = definitions.get(capability_id)
    if definition is None:
        raise ValueError(f"unknown fixture capability: {capability_id}")
    now = datetime.now(UTC)
    key = sha256(f"{capability_id}:{now.isoformat()}".encode()).hexdigest()[:16]
    run_id = f"arsenal-{now.strftime('%Y%m%dT%H%M%SZ')}-{key[:8]}"
    mission_id = f"arsenal-blocked-{key}"
    task_id = f"{mission_id}-execute"
    raw = HmacSignatureVerifier({"fixture-auth": secrets.token_bytes(32)})
    verifier = LocalFixtureSignatureVerifier(raw)
    authorization = signed_fixture_authorization(verifier)
    scope_snapshot = {"assets": ["127.0.0.1"], "network_isolation": "loopback-only"}
    scope_digest = document_digest(scope_snapshot)
    store = ImmutableRunStore(runs_dir)
    manifest = OperatorRunManifest(
        1, run_id, RunMode.ARSENAL_FIXTURE, now.isoformat(), "local-fixture-operator",
        "aegis-local-fixtures", "built-in deterministic fixtures", ("127.0.0.1",),
        None, (), FIXTURE_POLICY_SNAPSHOT, document_digest(FIXTURE_POLICY_SNAPSHOT),
        scope_snapshot, scope_digest, {"capabilities": [capability_id]},
        RunBudgets(1, 1.0, 0.0, max_duration_seconds=1, max_attempts=1),
        authorization.model_dump(mode="json"),
    )
    store.create(manifest)
    task = MissionTask(
        task_id, "reproduction", "execute_blocked_arsenal_fixture",
        payload={"authorization_class": LOCAL_FIXTURE_ONLY, "capability_id": capability_id},
        opportunity_id=f"fixture-opp-{key}", asset_id="fixture:blocked",
        asset_kind=(definition.supported_asset_classes[0]
                    if definition.supported_asset_classes else "source_code"),
        asset_locator="127.0.0.1", executor_capability=(
            definition.executor_provider or "unavailable"
        ), risk="offline", expected_cost_usd=0.0,
        evidence_required=("blocking_reason",), idempotency_key=f"{mission_id}:{task_id}",
    )
    plan = MissionPlan(
        mission_id, scope_digest, f"Blocked fixture for {capability_id}", (task,),
        opportunity_id=task.opportunity_id, program_id="aegis-local-fixtures",
        asset_id=task.asset_id, asset_kind=task.asset_kind,
        authorization_id=authorization.authorization_id,
    )
    scheduler_state = JarvisStateStore(":memory:")
    MissionScheduler(scheduler_state).create(plan)
    evidence = {
        "kind": "arsenal_fixture_blocked", "capability_id": capability_id,
        "mode": CapabilityMode.FIXTURE.value, "run_id": run_id,
        "mission_id": mission_id, "task_id": task_id,
        "execution_performed": False, "execution_grant_issued": False,
        "coverage_state": state_value.value, "blocking_reason": reason,
    }
    evidence_ref, evidence_digest = store.persist_evidence(run_id, evidence)
    store.append_event(run_id, "arsenal_task_blocked", RunStatus.FAILED, {
        "capability_id": capability_id, "mission_id": mission_id, "task_id": task_id,
        "result": state_value.value, "blocking_reason": reason,
        "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
        "execution_grant_id": None,
    })
    recorded = False
    degraded = coverage_repository is None
    backend = definition.tool_backends[0] if definition.tool_backends else None
    if coverage_repository is not None:
        record = CapabilityCoverageRecord(
            f"acr:{sha256((run_id + task_id).encode()).hexdigest()[:24]}",
            f"arsenal:{run_id}:{task_id}", capability_id, CapabilityMode.FIXTURE,
            backend.tool_name if backend else "", "",
            definition.technique_ids[0] if definition.technique_ids else "",
            definition.supported_asset_classes, definition.implementation_paths[0],
            backend.backend_id if backend else "", backend.adapter_version if backend else "",
            "UNAVAILABLE", document_digest(FIXTURE_POLICY_SNAPSHOT), "127.0.0.1",
            "prerequisite-resolution", None, None, run_id, mission_id, task_id, False,
            None, None, state_value, (), reason, "PREREQUISITE_UNSATISFIED", "NOT_RUN",
        )
        try:
            _, recorded = coverage_repository.record(record)
        except Exception as exc:
            degraded = True
            store.append_event(run_id, "coverage_recording_degraded", RunStatus.FAILED, {
                "error_class": type(exc).__name__, "execution_result_remains_canonical": True,
            })
    if coverage_repository is None:
        store.append_event(run_id, "coverage_recording_degraded", RunStatus.FAILED, {
            "error_class": "CoverageRepositoryUnavailable",
            "execution_result_remains_canonical": True,
        })
    store.verify(run_id)
    scheduler_state.close()
    return ExerciseResult(
        run_id, mission_id, task_id, capability_id, state_value,
        evidence_ref, evidence_digest, recorded, degraded,
        {"execution_performed": False, "blocking_reason": reason},
    )


def exercise_inventory() -> tuple[str, ...]:
    """Return fixture-executable capability IDs without executing or targeting anything."""
    return tuple(
        item.capability_id for item in ArsenalInventoryBuilder().build()
        if item.fixture_executable
    )


def write_result(result: ExerciseResult, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result.document(), indent=2, sort_keys=True) + "\n")


__all__ = [
    "ExerciseResult", "execute_llm_fixture", "exercise_inventory",
    "record_blocked_fixture", "write_result",
]

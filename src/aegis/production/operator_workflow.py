"""Operator-selected, freshly authorized dry-run workflow over canonical missions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    RiskClass,
    mint_execution_grant,
)
from aegis.ai.jarvis.universal_mission import compile_opportunity_mission
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime, opportunities_for_program
from aegis.ingest.program import ProgramRules
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.authorization import Authorization, AuthorizationValidator, TestIdentity
from aegis.policy.consequence import ConsequenceTier
from aegis.policy.decisions import ActionRequest
from aegis.policy.engine import PolicyEngine
from aegis.policy.killswitch import KillSwitch

from .operator_manifest import (
    ImmutableRunStore,
    OperatorRunManifest,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)


class OperatorWorkflowError(RuntimeError):
    pass


class AuthorizationSigner(Protocol):
    key_id: str

    def sign(self, payload: dict) -> str: ...

    def verifier(self): ...


@dataclass(frozen=True, slots=True)
class PreparedOperatorRun:
    manifest: OperatorRunManifest
    program: ProgramRules


def prepare_operator_run(
    snapshot: ProgramSnapshot,
    *,
    selected_assets: tuple[str, ...],
    operator_id: str,
    mode: RunMode,
    budgets: RunBudgets,
    signer: AuthorizationSigner,
    store: ImmutableRunStore,
    controlled_identity_refs: tuple[str, ...] = (),
    parent_dry_run_id: str | None = None,
    now: datetime | None = None,
    max_snapshot_age: timedelta = timedelta(hours=1),
) -> PreparedOperatorRun:
    """Validate operator choices and persist a fresh signed authorization snapshot."""
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    if snapshot.source in {"reports/programs.json", "candidate-registry"}:
        raise OperatorWorkflowError("candidate registry is not an authorization source")
    if snapshot.expired or observed - snapshot.retrieved_at > max_snapshot_age:
        raise OperatorWorkflowError("program policy/scope snapshot is stale or expired")
    if not selected_assets or len(set(selected_assets)) != len(selected_assets):
        raise OperatorWorkflowError("operator must explicitly select unique assets")
    if mode is RunMode.LIVE_CANARY and len(selected_assets) != 1:
        raise OperatorWorkflowError("live canary requires exactly one selected asset")
    available = {
        asset.identifier: asset for asset in snapshot.rules.in_scope
        if asset.eligible_for_submission
    }
    if any(asset not in available for asset in selected_assets):
        raise OperatorWorkflowError("selected asset is not in the refreshed current scope")
    if mode is RunMode.LIVE_CANARY and not snapshot.rules.automation_allowed:
        raise OperatorWorkflowError("current program policy prohibits automated testing")

    authorization_id = f"operator:{store.new_run_id()}"
    policy_snapshot = {
        "source": snapshot.source,
        "source_hash": snapshot.source_hash,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "expires_at": snapshot.authorization_expires_at.isoformat(),
        "policy_text": snapshot.rules.policy_text,
        "automation_allowed": snapshot.rules.automation_allowed,
        "ai_allowed": snapshot.rules.ai_allowed,
        "rate_limit_rps": snapshot.rules.rate_limit_rps,
        "conflicts": list(snapshot.rules.conflicts),
    }
    scope_snapshot = {
        "program_handle": snapshot.rules.handle,
        "selected_assets": list(selected_assets),
        "in_scope": [asset.model_dump(mode="json") for asset in snapshot.rules.in_scope],
        "out_of_scope": [asset.model_dump(mode="json") for asset in snapshot.rules.out_of_scope],
    }
    scope_digest = document_digest(scope_snapshot)
    selected = [
        available[name].model_copy(update={
            "scope_digest": scope_digest,
            "authorization_id": authorization_id,
            "provenance": [*available[name].provenance, snapshot.source, snapshot.source_hash],
        })
        for name in selected_assets
    ]
    program = snapshot.rules.model_copy(update={"in_scope": selected})
    valid_until = min(snapshot.authorization_expires_at, observed + timedelta(hours=24))
    draft = program.to_authorization_draft(
        customer_id=operator_id,
        authorization_id=authorization_id,
        valid_from=observed.isoformat(),
        valid_until=valid_until.isoformat(),
        permitted_actions=["passive_discovery"] if mode is RunMode.DRY_RUN else [
            "passive_discovery", "authenticated_testing", "synthetic_data_access",
        ],
    )
    draft.pop("_meta", None)
    draft["targets"] = list(selected_assets)
    draft["rate_limits"] = {
        "requests_per_second": min(
            budgets.requests_per_second,
            snapshot.rules.rate_limit_rps or budgets.requests_per_second,
        ),
        "max_concurrent_sessions": budgets.max_concurrent_sessions,
    }
    draft["spend_budget"] = budgets.max_cost_usd
    draft["test_identities"] = [
        TestIdentity(role="controlled", creds_ref=reference).model_dump(mode="json")
        for reference in controlled_identity_refs
    ]
    authorization = Authorization.model_validate(draft)
    signature = signer.sign(authorization.signing_payload())
    authorization = authorization.model_copy(update={
        "signature": signature, "signing_key_id": signer.key_id,
    })
    reasons = AuthorizationValidator(signer.verifier(), require_signature=True).validate(
        authorization, observed,
    )
    if reasons:
        raise OperatorWorkflowError("fresh authorization did not validate")
    run_id = authorization_id.split(":", 1)[1]
    manifest = OperatorRunManifest(
        schema_version=1, run_id=run_id, mode=mode, created_at=observed.isoformat(),
        operator_id=operator_id, program_handle=program.handle,
        program_source=snapshot.source, selected_assets=selected_assets,
        canary_asset=selected_assets[0] if mode is RunMode.LIVE_CANARY else None,
        controlled_identity_refs=controlled_identity_refs,
        policy_snapshot=policy_snapshot, policy_digest=document_digest(policy_snapshot),
        scope_snapshot=scope_snapshot, scope_digest=scope_digest,
        operator_selections={
            "program": program.handle,
            "assets": list(selected_assets),
            "parent_dry_run_id": parent_dry_run_id,
        },
        budgets=budgets, authorization=authorization.model_dump(mode="json"),
    )
    store.create(manifest)
    store.append_event(run_id, "scope_refreshed", RunStatus.SCOPE_REFRESHED, {
        "source_hash": snapshot.source_hash, "scope_digest": scope_digest,
    })
    store.append_event(run_id, "authorization_signed", RunStatus.AUTHORIZED, {
        "authorization_id": authorization_id, "signing_key_id": signer.key_id,
    })
    return PreparedOperatorRun(manifest, program)


def compile_dry_run(prepared: PreparedOperatorRun, store: ImmutableRunStore):
    """Rank and compile canonical opportunities; intentionally execute nothing."""
    if prepared.manifest.mode is not RunMode.DRY_RUN:
        raise OperatorWorkflowError("dry-run compiler requires a dry-run manifest")
    opportunities = opportunities_for_program(
        prepared.program, scope_digest=prepared.manifest.scope_digest,
        authorization_id=str(prepared.manifest.authorization["authorization_id"]),
    )
    missions = tuple(
        sorted(
            (compile_opportunity_mission(item) for item in opportunities),
            key=lambda mission: mission.expected_net_value_usd,
            reverse=True,
        )
    )
    store.append_event(prepared.manifest.run_id, "missions_compiled", RunStatus.PLANNED, {
        "opportunity_ids": [item.opportunity_id for item in opportunities],
        "mission_ids": [item.mission_id for item in missions],
        "execution_performed": False,
    })
    return missions


def compile_live_canary(
    prepared: PreparedOperatorRun,
    store: ImmutableRunStore,
    *,
    canary_url: str | None = None,
    method: str | None = None,
):
    if prepared.manifest.mode is not RunMode.LIVE_CANARY:
        raise OperatorWorkflowError("live-canary compiler requires a live-canary manifest")
    opportunities = opportunities_for_program(
        prepared.program, scope_digest=prepared.manifest.scope_digest,
        authorization_id=str(prepared.manifest.authorization["authorization_id"]),
    )
    missions = tuple(compile_opportunity_mission(item) for item in opportunities)
    if (canary_url is None) != (method is None):
        raise OperatorWorkflowError("live canary URL and method must be supplied together")
    if canary_url is not None and method is not None:
        from urllib.parse import urlsplit

        from aegis.ai.jarvis.supervised_canary_executor import CAPABILITY

        if len(missions) != 1:
            raise OperatorWorkflowError("live canary must compile exactly one selected asset")
        normalized_method = method.upper()
        parts = urlsplit(canary_url)
        if normalized_method not in {"GET", "HEAD", "OPTIONS"}:
            raise OperatorWorkflowError("first live canary permits GET, HEAD, or OPTIONS only")
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.hostname.casefold() != prepared.manifest.canary_asset.casefold()
        ):
            raise OperatorWorkflowError("canary URL must be exact HTTPS on the selected asset")
        original = missions[0]
        original_task = original.tasks[0]
        task = replace(
            original_task,
            action="supervised_http_observation",
            executor_capability=CAPABILITY,
            risk=RiskClass.READ_ONLY.value,
            expected_requests=1,
            expected_cost_usd=0.0,
            payload={"method": normalized_method, "url": canary_url},
            evidence_required=("response_status", "response_digest", "scope_check"),
            success_criteria=("one exact read-only request completed",),
            failure_criteria=("redirect left selected asset", "grant or budget rejected"),
            stop_loss_criteria=("scope drift", "kill switch", "unexpected redirect"),
        )
        missions = (replace(
            original,
            objective="prove one bounded supervised read-only request through canonical egress",
            tasks=(task,),
        ),)
    store.append_event(prepared.manifest.run_id, "canary_missions_compiled", RunStatus.PLANNED, {
        "mission_ids": [mission.mission_id for mission in missions], "execution_performed": False,
        "canary_url": canary_url, "method": method.upper() if method else None,
    })
    return missions


def execute_live_canary(
    prepared: PreparedOperatorRun,
    plan,
    *,
    store: ImmutableRunStore,
    runtime: UniversalMissionRuntime,
    availability,
    authorization_verifier,
    grant_verifier,
    kill_switch: KillSwitch | None = None,
    now: datetime | None = None,
    executor_kwargs: dict | None = None,
):
    """Revalidate immediately, mint one policy-derived grant, and execute one safe task."""
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    store.verify(prepared.manifest.run_id)
    if prepared.manifest.mode is not RunMode.LIVE_CANARY:
        raise OperatorWorkflowError("execution requires a live-canary manifest")
    authorization = Authorization.model_validate(prepared.manifest.authorization)
    reasons = AuthorizationValidator(authorization_verifier, require_signature=True).validate(
        authorization, observed,
    )
    if reasons:
        raise OperatorWorkflowError("authorization became stale or invalid before execution")
    if (
        plan.scope_digest != prepared.manifest.scope_digest
        or plan.authorization_id != authorization.authorization_id
        or not plan.tasks
        or plan.tasks[0].asset_locator != prepared.manifest.canary_asset
    ):
        raise OperatorWorkflowError("mission scope, authorization, or selected canary changed")
    task = plan.tasks[0]
    prior = store.events(prepared.manifest.run_id)
    if any(event.detail.get("task_id") == task.task_id and event.event_type == "task_completed"
           for event in prior):
        raise OperatorWorkflowError("completed task will not be executed twice")
    if task.risk not in {RiskClass.OFFLINE.value, RiskClass.READ_ONLY.value}:
        raise OperatorWorkflowError("state-changing canary requires a separate signed approval")
    if task.expected_requests > prepared.manifest.budgets.max_requests:
        raise OperatorWorkflowError("task request estimate exceeds the immutable run budget")
    if task.expected_cost_usd > prepared.manifest.budgets.max_cost_usd:
        raise OperatorWorkflowError("task cost estimate exceeds the immutable run budget")

    network = task.risk == RiskClass.READ_ONLY.value
    action = "authenticated_testing" if network else "passive_discovery"
    request = ActionRequest(
        target=task.asset_locator, action=action,
        tier_hint=ConsequenceTier.NON_INVASIVE_ACTIVE if network else ConsequenceTier.PASSIVE,
        description=f"{task.executor_capability}:{task.action}",
        estimated_cost=task.expected_cost_usd, touches_production=network,
        request_id="canary:" + sha256(
            f"{prepared.manifest.run_id}:{plan.mission_id}:{task.task_id}".encode()
        ).hexdigest()[:24],
    )
    decision = PolicyEngine(
        authorization=authorization, verifier=authorization_verifier,
        kill_switch=kill_switch or KillSwitch(),
    ).authorize(request, now=observed)
    if not decision.allowed:
        store.append_event(prepared.manifest.run_id, "policy_blocked", RunStatus.FAILED, {
            "task_id": task.task_id, "decision": decision.as_dict(),
        })
        raise OperatorWorkflowError("canonical PolicyEngine denied the canary task")
    budget = Budget(
        max_cost_usd=prepared.manifest.budgets.max_cost_usd,
        max_requests=prepared.manifest.budgets.max_requests,
    )
    canary_destination = str((task.payload or {}).get("url") or "")
    canary_method = str((task.payload or {}).get("method") or "")
    grant = mint_execution_grant(
        decision, scope_digest=prepared.manifest.scope_digest, budget=budget,
        verifier=grant_verifier, network=network, state_change=False, human_approval=False,
        now=observed, ttl_seconds=900,
        allowed_destinations=(canary_destination,) if network and canary_destination else (),
        allowed_methods=(canary_method,) if network and canary_method else (),
    )
    store.append_event(prepared.manifest.run_id, "execution_grant_minted", RunStatus.RUNNING, {
        "task_id": task.task_id, "method": canary_method,
        "destination": canary_destination,
        "grant": grant._payload() | {"signature": grant.signature},
    })
    envelope = AuthorizationEnvelope(
        scope_digest=prepared.manifest.scope_digest, budget=budget, grant=grant,
    )
    result = runtime.execute_first(
        plan, authorization=envelope, availability=availability, **(executor_kwargs or {}),
    )
    outcome = result.outcome
    if result.outcome is None:
        store.append_event(prepared.manifest.run_id, "task_not_completed", RunStatus.FAILED, {
            "task_id": task.task_id, "mission_id": plan.mission_id,
            "disposition": result.disposition.value, "reason": result.reason,
            "requests_executed": 0,
        })
        return result
    outcome_document = asdict(outcome) if hasattr(outcome, "__dataclass_fields__") else outcome
    if hasattr(getattr(outcome, "evidence", None), "model_dump"):
        outcome_document["evidence"] = outcome.evidence.model_dump(mode="json")
    evidence_document = {
        "schema_version": 1,
        "run_id": prepared.manifest.run_id,
        "mission_id": plan.mission_id,
        "task_id": task.task_id,
        "scope_digest": prepared.manifest.scope_digest,
        "grant_digest": sha256(repr(grant._payload()).encode()).hexdigest(),
        "target": str((task.payload or {}).get("url") or task.asset_locator),
        "method": str((task.payload or {}).get("method") or ""),
        "identity_ref": (
            prepared.manifest.controlled_identity_refs[0]
            if prepared.manifest.controlled_identity_refs else None
        ),
        "request_budget_before": prepared.manifest.budgets.max_requests,
        "request_budget_after": prepared.manifest.budgets.max_requests - 1,
        "cost_consumed": 0.0,
        "scope_check": "PASS",
        "grant_check": "PASS",
        "rate_check": "PASS",
        "kill_switch_check": "PASS",
        "outcome": outcome_document,
    }
    evidence_ref, evidence_digest = store.persist_evidence(
        prepared.manifest.run_id, evidence_document,
    )
    store.append_event(prepared.manifest.run_id, "evidence_persisted", RunStatus.RUNNING, {
        "task_id": task.task_id, "evidence_ref": evidence_ref,
        "evidence_digest": evidence_digest,
    })
    store.append_event(prepared.manifest.run_id, "task_completed", RunStatus.COMPLETED, {
        "task_id": task.task_id, "mission_id": plan.mission_id,
        "disposition": result.disposition.value, "reason": result.reason,
        "evidence_digest": evidence_digest, "requests_executed": 1,
    })
    return result


def resume_operator_run(
    store: ImmutableRunStore,
    run_id: str,
    *,
    refreshed_snapshot: ProgramSnapshot,
    authorization_verifier,
    now: datetime | None = None,
) -> PreparedOperatorRun:
    """Resume only when the chain, signed authorization, and current scope still agree."""
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    manifest = store.load_manifest(run_id)
    authorization = Authorization.model_validate(manifest.authorization)
    if AuthorizationValidator(authorization_verifier, require_signature=True).validate(
        authorization, observed,
    ):
        raise OperatorWorkflowError("authorization is stale or invalid; resume denied")
    if refreshed_snapshot.expired or observed - refreshed_snapshot.retrieved_at > timedelta(hours=1):
        raise OperatorWorkflowError("current program scope must be refreshed before resume")
    if (
        refreshed_snapshot.rules.handle != manifest.program_handle
        or refreshed_snapshot.source_hash != manifest.policy_snapshot.get("source_hash")
    ):
        raise OperatorWorkflowError("program policy changed; create a fresh authorized run")
    current = {
        asset.identifier: asset for asset in refreshed_snapshot.rules.in_scope
        if asset.eligible_for_submission
    }
    if any(asset not in current for asset in manifest.selected_assets):
        raise OperatorWorkflowError("selected asset is no longer in current scope")
    selected = [
        current[name].model_copy(update={
            "scope_digest": manifest.scope_digest,
            "authorization_id": str(manifest.authorization["authorization_id"]),
        }) for name in manifest.selected_assets
    ]
    program = refreshed_snapshot.rules.model_copy(update={"in_scope": selected})
    store.append_event(run_id, "run_resumed", RunStatus.RUNNING, {
        "previous_event_digest": store.events(run_id)[-1].digest,
        "scope_digest": manifest.scope_digest,
    })
    return PreparedOperatorRun(manifest, program)

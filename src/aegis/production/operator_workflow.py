"""Operator-selected, freshly authorized dry-run workflow over canonical missions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from aegis.ai.jarvis.universal_mission import compile_opportunity_mission
from aegis.ai.jarvis.universal_runtime import opportunities_for_program
from aegis.ingest.program import ProgramRules
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.authorization import Authorization, AuthorizationValidator, TestIdentity

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
        operator_selections={"program": program.handle, "assets": list(selected_assets)},
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

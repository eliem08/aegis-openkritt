from datetime import UTC, datetime, timedelta

import pytest

from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.signing import Ed25519Signer
from aegis.production.operator_manifest import ImmutableRunStore, RunBudgets, RunMode
from aegis.production.operator_workflow import (
    OperatorWorkflowError,
    compile_dry_run,
    prepare_operator_run,
)


def snapshot(source="hackerone:operator-refresh"):
    now = datetime.now(UTC)
    rules = ProgramRules(
        handle="demo", policy_text="Limit testing to 1 request per second.",
        rate_limit_rps=1.0,
        in_scope=[ScopeAsset(
            identifier="api.example.test", asset_type=AssetType.API,
            eligible_for_submission=True,
        )],
    )
    return ProgramSnapshot(
        rules=rules, source=source, source_hash="a" * 64, retrieved_at=now,
        authorization_expires_at=now + timedelta(hours=2),
    )


def test_candidate_registry_cannot_authorize_a_run(tmp_path):
    with pytest.raises(OperatorWorkflowError, match="not an authorization source"):
        prepare_operator_run(
            snapshot("reports/programs.json"), selected_assets=("api.example.test",),
            operator_id="operator", mode=RunMode.DRY_RUN, budgets=RunBudgets(10, 1, 1),
            signer=Ed25519Signer.generate("operator"), store=ImmutableRunStore(tmp_path),
        )


def test_dry_run_persists_signed_scope_and_compiles_without_execution(tmp_path):
    store = ImmutableRunStore(tmp_path)
    prepared = prepare_operator_run(
        snapshot(), selected_assets=("api.example.test",), operator_id="operator",
        mode=RunMode.DRY_RUN, budgets=RunBudgets(10, 2, 1),
        signer=Ed25519Signer.generate("operator"), store=store,
    )
    missions = compile_dry_run(prepared, store)
    assert missions and all(m.scope_digest == prepared.manifest.scope_digest for m in missions)
    events = store.events(prepared.manifest.run_id)
    assert events[-1].detail["execution_performed"] is False
    assert prepared.manifest.authorization["signature"]
    assert prepared.manifest.authorization["rate_limits"]["requests_per_second"] == 1.0


def test_live_canary_requires_one_current_asset(tmp_path):
    with pytest.raises(OperatorWorkflowError, match="exactly one"):
        prepare_operator_run(
            snapshot(), selected_assets=("api.example.test", "other.example.test"),
            operator_id="operator", mode=RunMode.LIVE_CANARY,
            budgets=RunBudgets(10, 1, 1), signer=Ed25519Signer.generate("operator"),
            store=ImmutableRunStore(tmp_path),
        )

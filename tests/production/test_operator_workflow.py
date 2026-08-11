from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.supervised_canary_executor import SupervisedCanaryOutcome
from aegis.ai.jarvis.universal_runtime import MissionExecutionResult
from aegis.cli import main as cli_main
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset
from aegis.ingest.source import ProgramSnapshot
from aegis.model.evidence import EvidenceBundle, InteractionStep
from aegis.policy.signing import Ed25519Signer, HmacSignatureVerifier
from aegis.production.operator_manifest import ImmutableRunStore, RunBudgets, RunMode
from aegis.production.operator_workflow import (
    OperatorWorkflowError,
    compile_dry_run,
    compile_live_canary,
    execute_live_canary,
    prepare_operator_run,
    resume_operator_run,
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


class FakeRuntime:
    def __init__(self, grant_verifier):
        self.grant_verifier = grant_verifier
        self.calls = 0

    def execute_first(self, plan, *, authorization, availability, **kwargs):
        assert authorization.grant.verify(self.grant_verifier)
        assert authorization.grant.state_change_allowed is False
        payload = plan.tasks[0].payload or {}
        if payload.get("url"):
            assert authorization.grant.allowed_destinations == (payload["url"],)
            assert authorization.grant.allowed_methods == (payload["method"],)
        self.calls += 1
        outcome = {"evidence": "controlled"}
        if payload.get("url"):
            outcome = SupervisedCanaryOutcome(
                payload["method"], payload["url"], 200, "a" * 64, 2,
                payload["url"], 0,
                EvidenceBundle(
                    steps=[InteractionStep(summary="test", request="GET /", response="200")],
                    observed="ok", expected="ok", replay_ref="test", confidence=1.0,
                ),
            )
        return MissionExecutionResult(
            plan, CapabilityDisposition.READY, "bounded read-only canary completed",
            outcome,
        )


def live_prepared(tmp_path):
    store = ImmutableRunStore(tmp_path)
    signer = Ed25519Signer.generate("operator")
    prepared = prepare_operator_run(
        snapshot(), selected_assets=("api.example.test",), operator_id="operator",
        mode=RunMode.LIVE_CANARY, budgets=RunBudgets(10, 1, 1),
        signer=signer, store=store,
    )
    plan = compile_live_canary(prepared, store)[0]
    first, *rest = plan.tasks
    plan = replace(plan, tasks=(replace(first, risk="read_only", expected_requests=1), *rest))
    return store, signer, prepared, plan


def test_live_canary_revalidates_and_executes_once(tmp_path):
    store, signer, prepared, plan = live_prepared(tmp_path)
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    runtime = FakeRuntime(grants)
    result = execute_live_canary(
        prepared, plan, store=store, runtime=runtime, availability=None,
        authorization_verifier=signer.verifier(), grant_verifier=grants,
    )
    assert result.outcome and runtime.calls == 1
    assert store.verify(prepared.manifest.run_id)["last_status"] == "completed"
    with pytest.raises(OperatorWorkflowError, match="will not be executed twice"):
        execute_live_canary(
            prepared, plan, store=store, runtime=runtime, availability=None,
            authorization_verifier=signer.verifier(), grant_verifier=grants,
        )


def test_live_canary_compiles_one_exact_read_only_request_and_persists_evidence(tmp_path):
    store = ImmutableRunStore(tmp_path)
    signer = Ed25519Signer.generate("operator")
    prepared = prepare_operator_run(
        snapshot(), selected_assets=("api.example.test",), operator_id="operator",
        mode=RunMode.LIVE_CANARY, budgets=RunBudgets(1, 0.1, 0.01),
        signer=signer, store=store,
    )
    plan = compile_live_canary(
        prepared, store, canary_url="https://api.example.test/", method="GET",
    )[0]
    assert len(plan.tasks) == 1
    assert plan.tasks[0].risk == "read_only"
    assert plan.tasks[0].payload == {"method": "GET", "url": "https://api.example.test/"}
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    result = execute_live_canary(
        prepared, plan, store=store, runtime=FakeRuntime(grants), availability=None,
        authorization_verifier=signer.verifier(), grant_verifier=grants,
    )
    assert result.outcome
    evidence_dir = tmp_path / prepared.manifest.run_id / "evidence"
    assert len(list(evidence_dir.glob("*.json"))) == 1


def test_live_canary_fails_closed_on_stale_auth_or_state_change(tmp_path):
    store, signer, prepared, plan = live_prepared(tmp_path)
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    with pytest.raises(OperatorWorkflowError, match="stale or invalid"):
        execute_live_canary(
            prepared, plan, store=store, runtime=FakeRuntime(grants), availability=None,
            authorization_verifier=signer.verifier(), grant_verifier=grants,
            now=datetime.now(UTC) + timedelta(days=1),
        )
    changed = replace(plan, tasks=(replace(plan.tasks[0], risk="controlled_state_change"), *plan.tasks[1:]))
    with pytest.raises(OperatorWorkflowError, match="separate signed approval"):
        execute_live_canary(
            prepared, changed, store=store, runtime=FakeRuntime(grants), availability=None,
            authorization_verifier=signer.verifier(), grant_verifier=grants,
        )


def test_resume_verifies_chain_authorization_and_refreshed_scope(tmp_path):
    store, signer, prepared, _plan = live_prepared(tmp_path)
    resumed = resume_operator_run(
        store, prepared.manifest.run_id, refreshed_snapshot=snapshot(),
        authorization_verifier=signer.verifier(),
    )
    assert resumed.manifest.run_id == prepared.manifest.run_id
    changed = snapshot().model_copy(update={"source_hash": "b" * 64})
    with pytest.raises(OperatorWorkflowError, match="policy changed"):
        resume_operator_run(
            store, prepared.manifest.run_id, refreshed_snapshot=changed,
            authorization_verifier=signer.verifier(),
        )


def test_operator_cli_displays_selection_before_authorizing(tmp_path, capsys):
    path = tmp_path / "snapshot.json"
    path.write_text(snapshot().model_dump_json(), encoding="utf-8")
    result = cli_main([
        "production", "operator", "dry-run", "--snapshot", str(path),
        "--program", "demo", "--asset", "api.example.test", "--operator-id", "operator",
        "--max-requests", "10", "--requests-per-second", "1", "--max-cost-usd", "1",
        "--runs-dir", str(tmp_path / "runs"),
    ])
    assert result == 2
    output = capsys.readouterr().out
    assert '"selected_assets"' in output and "selection not confirmed" in output
    assert not (tmp_path / "runs").exists()

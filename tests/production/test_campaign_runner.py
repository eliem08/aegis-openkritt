import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest

from aegis.ai.jarvis.hunter_techniques import TECHNIQUES, HunterTechnique
from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.universal_runtime import MissionExecutionResult
from aegis.cli import main as cli_main
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.signing import Ed25519Signer, HmacSignatureVerifier
from aegis.production.campaign_runner import (
    BackendCapability,
    CampaignDecisionEvaluator,
    CampaignRequest,
    CampaignRunnerError,
    DecisionStatus,
    OperatorTechniqueApproval,
    PermissionEffect,
    PolicyEvidence,
    TechniqueRequest,
    TypedTechniquePermission,
    execute_campaign,
    prepare_campaign,
    sign_operator_approval,
)
from aegis.production.operator_manifest import ImmutableRunStore, RunBudgets, document_digest
from aegis.production.operator_workflow import policy_snapshot_document

TECHNIQUE = HunterTechnique.RECON_ANALYTICS_CORRELATION
ASSET = "example.test"


def snapshot(*, source: str = "hackerone:authoritative-api") -> ProgramSnapshot:
    now = datetime.now(UTC)
    return ProgramSnapshot(
        rules=ProgramRules(
            handle="demo",
            policy_text="Automated offline analysis of the listed domain is permitted.",
            in_scope=[ScopeAsset(
                identifier=ASSET,
                asset_type=AssetType.URL,
                raw_asset_type="DOMAIN",
                eligible_for_submission=True,
            )],
        ),
        source=source,
        source_hash="a" * 64,
        retrieved_at=now,
        authorization_expires_at=now + timedelta(hours=2),
    )


def inputs(signer: Ed25519Signer):
    current = snapshot()
    digest = document_digest(policy_snapshot_document(current))
    request = CampaignRequest(
        "campaign-001", "operator-1", (TechniqueRequest(TECHNIQUE, ASSET),),
        RunBudgets(20, 1.0, 10.0, max_duration_seconds=21600),
    )
    permission = TypedTechniquePermission(
        TECHNIQUE, ASSET, "default", PermissionEffect.PERMIT, "source_analysis",
        {"max_requests": 5, "max_cost_usd": 1.0},
        PolicyEvidence(
            current.source, current.retrieved_at.isoformat(), digest,
            "rule:offline-analysis", "test-adapter/1", "structured scope row 1",
        ),
    )
    now = datetime.now(UTC)
    approval = sign_operator_approval(OperatorTechniqueApproval(
        "approval-1", request.campaign_id, TECHNIQUE, ASSET, "default", (),
        (now - timedelta(minutes=1)).isoformat(),
        (now + timedelta(hours=1)).isoformat(), signer.key_id,
    ), signer)
    definition = TECHNIQUES[TECHNIQUE]
    backend = BackendCapability(
        definition.worker_capability, "internal-research", "1.0", True, True,
        ("max_requests", "max_cost_usd"),
        definition.required_prerequisites,
    )
    return current, request, permission, approval, backend


def test_exact_policy_asset_approval_and_backend_authorize_and_compile(tmp_path):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    prepared = prepare_campaign(
        current, request, permissions=(permission,), approvals=(approval,),
        backends=(backend,), signer=signer, store=ImmutableRunStore(tmp_path),
    )
    assert prepared.decisions[0].status is DecisionStatus.AUTHORIZED
    assert prepared.missions[0].tasks[0].executor_capability == backend.worker_capability
    assert prepared.missions[0].tasks[0].payload["authorization_decision_digest"]
    events = ImmutableRunStore(tmp_path).events(prepared.operator_run.manifest.run_id)
    compiled = next(event for event in events if event.event_type == "campaign_missions_compiled")
    assert compiled.detail["execution_performed"] is False


def test_ambiguous_policy_never_grants_permission():
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    evaluator = CampaignDecisionEvaluator(signer.verifier())
    result = evaluator.evaluate(
        current, request, request.techniques[0], permissions=(permission, permission),
        approvals=(approval,), backends=(backend,),
    )
    assert result.status is DecisionStatus.DENIED_POLICY_AMBIGUOUS


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("asset", DecisionStatus.DENIED_ASSET_INELIGIBLE),
        ("approval", DecisionStatus.DENIED_OPERATOR_APPROVAL),
        ("unsafe", DecisionStatus.DENIED_BACKEND_UNSAFE),
        ("unavailable", DecisionStatus.UNAVAILABLE),
        ("constraint", DecisionStatus.DENIED_CONSTRAINT_UNENFORCEABLE),
    ],
)
def test_campaign_intersection_fails_closed(mutation, expected):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    technique_request = request.techniques[0]
    if mutation == "asset":
        technique_request = replace(technique_request, asset="not-in-scope.test")
    elif mutation == "approval":
        approval = replace(approval, signature="tampered")
    elif mutation == "unsafe":
        backend = replace(backend, safe=False)
    elif mutation == "unavailable":
        backend = replace(backend, available=False, unavailable_reason="tool absent")
    elif mutation == "constraint":
        backend = replace(backend, enforceable_constraints=("max_requests",))
    result = CampaignDecisionEvaluator(signer.verifier()).evaluate(
        current, request, technique_request, permissions=(permission,),
        approvals=(approval,), backends=(backend,),
    )
    assert result.status is expected


def test_snapshot_change_invalidates_old_typed_permission():
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    changed = current.model_copy(update={"source_hash": "b" * 64})
    result = CampaignDecisionEvaluator(signer.verifier()).evaluate(
        changed, request, request.techniques[0], permissions=(permission,),
        approvals=(approval,), backends=(backend,), version=2,
    )
    assert result.status is DecisionStatus.DENIED_POLICY_AMBIGUOUS
    assert result.version == 2


def test_no_authorized_technique_creates_no_manifest(tmp_path):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    permission = replace(permission, effect=PermissionEffect.DENY)
    with pytest.raises(CampaignRunnerError, match="no authorized"):
        prepare_campaign(
            current, request, permissions=(permission,), approvals=(approval,),
            backends=(backend,), signer=signer, store=ImmutableRunStore(tmp_path),
        )
    assert not list(tmp_path.iterdir())


class FakeRuntime:
    def __init__(self, verifier):
        self.verifier = verifier
        self.calls = 0

    def execute_first(self, plan, *, authorization, availability, **kwargs):
        grant = authorization.grant
        assert grant.verify(self.verifier)
        assert grant.constraints["technique"] == TECHNIQUE.value
        assert grant.constraints["operator_approval_id"] == "approval-1"
        self.calls += 1
        return MissionExecutionResult(
            plan, CapabilityDisposition.READY, "completed", {"candidate": "controlled"},
        )


def test_execution_uses_fresh_scope_policy_grant_and_is_resume_safe(tmp_path):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    store = ImmutableRunStore(tmp_path)
    prepared = prepare_campaign(
        current, request, permissions=(permission,), approvals=(approval,),
        backends=(backend,), signer=signer, store=store,
    )
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    runtime = FakeRuntime(grants)
    results = execute_campaign(
        prepared, snapshot_provider=lambda: current, permissions=(permission,),
        approvals=(approval,), backends=(backend,), store=store, runtime=runtime,
        availability=None, authorization_verifier=signer.verifier(),
        grant_verifier=grants,
    )
    assert results[0].outcome == {"candidate": "controlled"}
    assert runtime.calls == 1
    assert store.verify(prepared.operator_run.manifest.run_id)["last_status"] == (
        "execution_complete_outcomes_pending"
    )
    resumed = execute_campaign(
        prepared, snapshot_provider=lambda: current, permissions=(permission,),
        approvals=(approval,), backends=(backend,), store=store, runtime=runtime,
        availability=None, authorization_verifier=signer.verifier(),
        grant_verifier=grants,
    )
    assert resumed == ()
    assert runtime.calls == 1


def test_changed_policy_appends_recomputed_decision_and_stops(tmp_path):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    store = ImmutableRunStore(tmp_path)
    prepared = prepare_campaign(
        current, request, permissions=(permission,), approvals=(approval,),
        backends=(backend,), signer=signer, store=store,
    )
    changed = current.model_copy(update={"source_hash": "b" * 64})
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    with pytest.raises(CampaignRunnerError, match="policy snapshot changed"):
        execute_campaign(
            prepared, snapshot_provider=lambda: changed, permissions=(permission,),
            approvals=(approval,), backends=(backend,), store=store,
            runtime=FakeRuntime(grants), availability=None,
            authorization_verifier=signer.verifier(), grant_verifier=grants,
        )
    events = store.events(prepared.operator_run.manifest.run_id)
    assert events[-1].event_type == "campaign_policy_changed"
    assert events[-1].detail["replacement_status"] == "denied_policy_ambiguous"


class UnavailableEffectivenessRepository:
    def record_shadow_batch(self, batch):
        raise ConnectionError("postgres unavailable")


def test_effectiveness_outage_degrades_learning_without_blocking_execution(tmp_path):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    store = ImmutableRunStore(tmp_path)
    repository = UnavailableEffectivenessRepository()
    prepared = prepare_campaign(
        current, request, permissions=(permission,), approvals=(approval,),
        backends=(backend,), signer=signer, store=store,
        effectiveness_repository=repository,
    )
    grants = HmacSignatureVerifier({"grant": "g" * 32})
    results = execute_campaign(
        prepared, snapshot_provider=lambda: current, permissions=(permission,),
        approvals=(approval,), backends=(backend,), store=store,
        runtime=FakeRuntime(grants), availability=None,
        authorization_verifier=signer.verifier(), grant_verifier=grants,
        effectiveness_repository=repository,
    )
    assert results[0].outcome is not None
    degraded = [event for event in store.events(prepared.operator_run.manifest.run_id)
                if event.event_type == "effectiveness_learning_degraded"]
    assert len(degraded) == 2
    assert all(event.detail.get("execution_authority_changed") is False for event in degraded)


def test_campaign_cli_displays_exact_selection_before_creating_authority(tmp_path, capsys):
    signer = Ed25519Signer.generate("operator")
    current, request, permission, approval, backend = inputs(signer)
    snapshot_path = tmp_path / "snapshot.json"
    campaign_path = tmp_path / "campaign.json"
    snapshot_path.write_text(current.model_dump_json(), encoding="utf-8")
    approval_document = asdict(approval)
    approval_document["technique"] = approval.technique.value
    backend_document = asdict(backend)
    campaign_path.write_text(json.dumps({
        "campaign_id": request.campaign_id,
        "operator_id": request.operator_id,
        "budgets": asdict(request.budgets),
        "techniques": [{
            "technique": TECHNIQUE.value, "asset": ASSET, "context": "default",
            "identity_refs": [], "execution_inputs": {},
        }],
        "permissions": [permission.document()],
        "approvals": [approval_document],
        "backends": [backend_document],
    }), encoding="utf-8")
    result = cli_main([
        "production", "operator", "campaign", "--snapshot", str(snapshot_path),
        "--program", "demo", "--campaign-manifest", str(campaign_path),
    ])
    assert result == 2
    output = capsys.readouterr().out
    assert '"campaign_id": "campaign-001"' in output
    assert "no authorization or run manifest was created" in output

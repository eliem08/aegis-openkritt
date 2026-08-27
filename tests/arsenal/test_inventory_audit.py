import json
from datetime import UTC, datetime

from aegis.arsenal.audit import build_audit, render_markdown
from aegis.arsenal.inventory import ArsenalInventoryBuilder
from aegis.arsenal.models import ArsenalCoverageState, CapabilityMode
from aegis.policy.signing import Ed25519Signer
from aegis.production.operator_manifest import (
    ImmutableRunStore,
    OperatorRunManifest,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)


class HealthyRuntime:
    def inspect(self, *, name, binary, version_override="", refresh=False):
        from aegis.ai.tool_runtime import ToolRuntimeRecord, ToolRuntimeStatus

        return ToolRuntimeRecord(
            name, binary, f"/tools/{binary}", "tool 1.2.3", "a" * 64,
            ToolRuntimeStatus.READY, "healthy", datetime.now(UTC).isoformat(),
        )


def test_inventory_federates_tools_assets_adapters_and_all_hunter_techniques():
    definitions = ArsenalInventoryBuilder().build()
    ids = {item.capability_id for item in definitions}

    assert "tool:semgrep/code" in ids
    assert "asset:codeql/cross-file-dataflow" in ids
    assert "adapter:subfinder/passive-discovery" in ids
    assert "hunter:js_route_recovery" in ids
    assert len({item.capability_id for item in definitions}) == len(definitions)
    for definition in definitions:
        assert definition.source_registries
        assert definition.provenance


def test_audit_is_non_targeting_and_separates_current_health_from_history(tmp_path):
    report = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    document = report.document()

    assert document["metrics"]["implemented_capability_count"] == len(report.definitions)
    assert document["metrics"]["authorized_real_executed_count"] == 0
    assert all(item.current_state is ArsenalCoverageState.WAITING_FOR_PREREQUISITE
               for item in report.health if item.tool_name)
    assert "Capability matrix" in render_markdown(report)


def test_historical_execution_requires_verified_manifest_event_and_evidence(tmp_path):
    store = ImmutableRunStore(tmp_path)
    signer = Ed25519Signer.generate("operator")
    now = datetime.now(UTC)
    policy = {"program": "fixture"}
    scope = {"selected_assets": ["fixture://local"]}
    authorization = {
        "authorization_id": "fixture-auth", "signature": signer.sign({"fixture": True}),
    }
    manifest = OperatorRunManifest(
        1, "run-fixture", RunMode.DRY_RUN, now.isoformat(), "operator", "fixture",
        "local-fixture", ("fixture://local",), None, (), policy,
        document_digest(policy), scope, document_digest(scope), {},
        RunBudgets(1, 1.0, 0.0), authorization,
    )
    store.create(manifest)
    evidence_ref, evidence_digest = store.persist_evidence("run-fixture", {
        "kind": "arsenal_task_evidence", "capability_id": "tool:semgrep/code",
        "run_id": "run-fixture", "mission_id": "mission-1", "task_id": "task-1",
        "asset": "fixture://local", "policy_snapshot_digest": document_digest(policy),
        "grant": {"nonce": "grant-1", "constraints": {}}, "execution_performed": True,
    })
    store.append_event(
        "run-fixture", "arsenal_task_completed", RunStatus.COMPLETED,
        {"mission_id": "mission-1", "task_id": "task-1",
         "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
         "result": ArsenalCoverageState.EXECUTED_PASS.value},
    )

    report = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())

    assert len(report.history) == 1
    assert report.history[0].mode is CapabilityMode.FIXTURE
    assert report.history[0].state is ArsenalCoverageState.EXECUTED_PASS


def test_failed_fixture_event_is_preserved_but_not_counted_as_execution(tmp_path):
    store = ImmutableRunStore(tmp_path)
    signer = Ed25519Signer.generate("operator")
    now = datetime.now(UTC)
    policy = {"program": "fixture"}
    scope = {"selected_assets": ["fixture://local"]}
    manifest = OperatorRunManifest(
        1, "run-failed", RunMode.ARSENAL_FIXTURE, now.isoformat(), "operator", "fixture",
        "local-fixture", ("fixture://local",), None, (), policy,
        document_digest(policy), scope, document_digest(scope), {},
        RunBudgets(1, 1.0, 0.0),
        {"authorization_id": "fixture-auth", "signature": signer.sign({"fixture": True})},
    )
    store.create(manifest)
    evidence_ref, evidence_digest = store.persist_evidence("run-failed", {
        "kind": "arsenal_task_evidence", "capability_id": "tool:semgrep/code",
        "run_id": "run-failed", "mission_id": "mission-1", "task_id": "task-1",
        "execution_performed": True, "summary": {"fixture_detection": False},
    })
    store.append_event("run-failed", "arsenal_task_completed", RunStatus.FAILED, {
        "mission_id": "mission-1", "task_id": "task-1",
        "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
        "result": ArsenalCoverageState.BACKEND_UNHEALTHY.value,
    })

    report = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())

    assert report.history == ()


def test_corrupt_historical_evidence_is_reported_not_counted(tmp_path):
    run = tmp_path / "broken"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"manifest_digest": "bad"}), encoding="utf-8")

    report = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())

    assert not report.history
    assert report.historical_evidence_errors[0]["historical_evidence_invalid"] is True

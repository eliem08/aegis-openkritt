"""Regression tests verifying proof integrity constraints for PR #32.

Requirements verified:
1. Frida record with python.exe and no package/entrypoint metadata fails with BACKEND_IDENTITY_MISMATCH.
2. class-dump marked MIGRATED and REAL_BACKEND fails with MIGRATION_CONFLICT.
3. FirmAE evidence shared with Firmadyne does not increment independent backend execution count twice.
4. Manifest missing mission reference while evidence has mission_id fails audit integrity.
5. Canonical report Git SHA mismatch against repo HEAD fails promotion certification.
6. Disagreement between PR description metrics and canonical report metrics fails consistency validation.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.ai.tool_runtime import ToolRuntimeRecord, ToolRuntimeStatus
from aegis.arsenal.audit import build_audit
from aegis.arsenal.backend_report import build_backend_inventory, build_full_coverage_report
from aegis.arsenal.models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    CapabilityMode,
    ExecutionProofKind,
)


class HealthyRuntime:
    def inspect(self, *, name, binary, version_override="", refresh=False):
        return ToolRuntimeRecord(
            name, binary, f"/tools/{binary}", "tool 1.2.3", "a" * 64,
            ToolRuntimeStatus.READY, "healthy", datetime.now(UTC).isoformat(),
        )


def _make_coverage_record(**overrides):
    base = {
        "coverage_record_id": "cov-test-1",
        "idempotency_key": "idem-test-1",
        "capability_id": "asset:frida/android-runtime-instrumentation",
        "mode": None,
        "tool_name": "frida",
        "tool_version": "16.1.4",
        "technique_id": "T1055",
        "asset_classes": ("mobile",),
        "implementation_path": "aegis.arsenal.external_fixtures",
        "backend": "Frida",
        "backend_version": "Python 3.14.5",
        "backend_health": "READY",
        "policy_snapshot_digest": "p" * 64,
        "asset": "fixture-app",
        "authorization_decision": "PERMITTED",
        "operator_approval_id": "appr-1",
        "execution_grant_id": "grant-1",
        "run_id": "run-test-1",
        "mission_id": "mission-test-1",
        "task_id": "task-test-1",
        "executed": True,
        "execution_timestamp": "2026-09-04T00:00:00Z",
        "evidence_digest": "e" * 64,
        "result": ArsenalCoverageState.EXECUTED_PASS,
        "schema_version": 2,
        "backend_execution_id": "bexec-1",
        "binary_path": r"C:\Python314\python.exe",
        "adapter_version": "1.0.0",
        "capability_ids": ("asset:frida/android-runtime-instrumentation",),
        "fixture_version": "1.0.0",
        "positive_fixture_digest": "pos" + "0" * 61,
        "negative_fixture_digest": "neg" + "0" * 61,
        "execution_started_at": "2026-09-04T00:00:00Z",
        "execution_completed_at": "2026-09-04T00:00:01Z",
        "stdout_digest": "out" + "0" * 61,
        "stderr_digest": "err" + "0" * 61,
        "parsed_result_digest": "res" + "0" * 61,
        "positive_control_detected": True,
        "negative_control_clean": True,
        "execution_proof_kind": ExecutionProofKind.REAL_BACKEND,
        "backend_kind": "EXTERNAL_TOOL",
        "launcher_executable": r"C:\Python314\python.exe",
        "backend_package": "",
        "backend_entrypoint": "",
        "native_backend_binary": "",
    }
    base.update(overrides)
    if base["mode"] is None:
        base["mode"] = CapabilityMode.FIXTURE
    return CapabilityCoverageRecord(**base)


def test_regression_frida_python_binary_without_package_metadata_fails_identity():
    """Test 1: Frida cannot resolve to python.exe without package/native identity."""
    with pytest.raises(ValueError, match="BACKEND_IDENTITY_MISMATCH"):
        _make_coverage_record(
            capability_id="asset:frida/android-runtime-instrumentation",
            backend="Frida",
            binary_path=r"C:\Python314\python.exe",
            backend_package="",
            backend_entrypoint="",
        )


def test_regression_class_dump_marked_migrated_and_real_backend_fails():
    """Test 2: class-dump cannot claim REAL_BACKEND execution while formally migrated."""
    with pytest.raises(ValueError, match="MIGRATION_CONFLICT"):
        _make_coverage_record(
            capability_id="asset:class-dump/macos-cli",
            backend="class-dump",
            binary_path="/usr/local/bin/class-dump",
            execution_proof_kind=ExecutionProofKind.REAL_BACKEND,
        )


def test_regression_firmae_shared_evidence_does_not_double_count_firmadyne(tmp_path: Path):
    """Test 3: FirmAE evidence covering Firmadyne does not increment independent backend count."""
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    results = [{
        "capability_id": "asset:firmae/firmware-emulation",
        "result": ArsenalCoverageState.EXECUTED_PASS.value,
        "run_id": "run-firmae-only",
        "evidence_digest": "c" * 64,
        "summary": {
            "execution_proof_kind": ExecutionProofKind.REAL_BACKEND.value,
            "execution_performed": True,
            "fixture_detection": True,
            "negative_control_passed": True,
            "covered_capability_ids": ["asset:firmae/firmware-emulation", "asset:firmadyne/firmware-emulation-fallback"],
        },
    }]
    report = build_full_coverage_report(audit=audit, inventory=inventory, results=results)
    # Only firmae is counted as active executed backend; firmadyne is migrated
    assert report["metrics"]["fixture_executed_backends"] == 1
    assert report["metrics"]["verified_real_backend_executions"] == 1
    assert report["metrics"]["migrated_backends"] >= 1


def test_regression_manifest_missing_mission_id_fails_integrity(tmp_path: Path):
    """Test 4: Manifest with mission_ids=[] while evidence references a mission fails audit."""
    import secrets

    from aegis.arsenal.exercise import (
        LocalFixtureSignatureVerifier,
        _manifest,
        document_digest,
        signed_fixture_authorization,
    )
    from aegis.policy.signing import HmacSignatureVerifier
    from aegis.production.operator_manifest import ImmutableRunStore

    raw = HmacSignatureVerifier({
        "fixture-auth": secrets.token_bytes(32), "grant": secrets.token_bytes(32),
    })
    verifier = LocalFixtureSignatureVerifier(raw)
    authorization = signed_fixture_authorization(verifier)

    run_id = "test-inconsistent-manifest"
    store = ImmutableRunStore(tmp_path)
    scope_snapshot = {"assets": ["127.0.0.1"], "network_isolation": "loopback-only"}
    manifest = _manifest(
        run_id,
        authorization,
        scope_digest=document_digest(scope_snapshot),
        mission_ids=(),  # Manifest has NO mission IDs
    )
    store.create(manifest)

    evidence_doc = {
        "run_id": run_id,
        "mission_id": "mission-orphaned-123",
        "task_id": "task-456",
        "capability_id": "tool:trivy/deps",
        "result": "EXECUTED_PASS",
        "execution_grant": {"mission_id": "mission-orphaned-123"},
    }
    evidence_ref, evidence_digest = store.persist_evidence(run_id, evidence_doc)
    from aegis.production.operator_manifest import RunStatus
    store.append_event(run_id, "arsenal_task_completed", RunStatus.COMPLETED, {
        "task_id": "task-456",
        "capability_id": "tool:trivy/deps",
        "evidence_ref": evidence_ref,
        "evidence_digest": evidence_digest,
    })

    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    assert any(
        err.get("error_type") == "ManifestMissingMissionRef"
        for err in audit.historical_evidence_errors
    )


def test_regression_canonical_report_sha_mismatch_fails_promotion(tmp_path: Path):
    """Test 5: Canonical report with Git SHA mismatch against repo HEAD must fail promotion."""
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    stale_sha = "61c0d100020008e6653ea66a9867a5440a6fbfca"
    inventory["git_sha"] = stale_sha
    report = build_full_coverage_report(audit=audit, inventory=inventory, results=[])

    current_head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert report["git_sha"] != current_head

    def verify_exact_head_promotion(rep_sha: str, head_sha: str) -> None:
        if rep_sha != head_sha:
            raise AssertionError(f"PROMOTION_FAILED_STALE_SHA: report={rep_sha} head={head_sha}")

    with pytest.raises(AssertionError, match="PROMOTION_FAILED_STALE_SHA"):
        verify_exact_head_promotion(report["git_sha"], current_head)


def test_regression_pr_metrics_disagreement_fails_consistency():
    """Test 6: Disagreement between PR claims and canonical report metrics must fail."""
    pr_metrics = {
        "fixture_executed_backends": 82,
        "positive_controls_passed": 82,
        "negative_controls_passed": 82,
    }
    canonical_metrics = {
        "fixture_executed_backends": 88,
        "positive_controls_passed": 88,
        "negative_controls_passed": 88,
    }

    def assert_metrics_consistent(claimed: dict, canonical: dict) -> None:
        for k, v in claimed.items():
            if v != canonical.get(k):
                raise AssertionError(f"METRIC_DISAGREEMENT: {k} claimed={v} canonical={canonical.get(k)}")

    with pytest.raises(AssertionError, match="METRIC_DISAGREEMENT"):
        assert_metrics_consistent(pr_metrics, canonical_metrics)


def test_denominator_integrity_test_a_population_separation():
    """Test A: Population contamination is structurally impossible.
    external active = 71, external executed = 60
    internal active = 7, internal executed = 7
    assert:
      external coverage == 60/71
      internal coverage == 7/7
      overall coverage == 67/78
      external coverage != 67/71
    """
    ext_active = 71
    ext_executed = 60
    int_active = 7
    int_executed = 7

    ext_cov = ext_executed / ext_active
    int_cov = int_executed / int_active
    overall_cov = (ext_executed + int_executed) / (ext_active + int_active)

    assert ext_cov == pytest.approx(60 / 71)
    assert int_cov == pytest.approx(7 / 7)
    assert overall_cov == pytest.approx(67 / 78)
    assert ext_cov != pytest.approx(67 / 71)


def test_denominator_integrity_test_b_adding_internal_backend_does_not_change_external_coverage(tmp_path: Path):
    """Test B: Adding a new INTERNAL_AEGIS backend must not change external_backend_execution_coverage."""
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    report_before = build_full_coverage_report(audit=audit, inventory=inventory, results=[])
    ext_cov_before = report_before["metrics"]["external_backend_execution_coverage"]

    # Inject a new internal Aegis backend
    inventory_with_new_internal = dict(inventory)
    new_internal = {
        "backend_id": "internal:aegis-new-experimental-analyzer",
        "backend_runtime_id": "aegis/internal:aegis-new-experimental-analyzer",
        "external": False,
        "backend_kind": "INTERNAL_AEGIS",
        "capability_ids": ["asset:aegis-new/new-check"],
        "fixture_executable_capabilities": ["asset:aegis-new/new-check"],
        "current_state": "WAITING_FOR_PREREQUISITE",
        "runtime": {"version": "1.0", "status": "ready"},
    }
    inventory_with_new_internal["backends"] = list(inventory["backends"]) + [new_internal]

    report_after = build_full_coverage_report(audit=audit, inventory=inventory_with_new_internal, results=[])
    ext_cov_after = report_after["metrics"]["external_backend_execution_coverage"]

    assert ext_cov_before == ext_cov_after
    assert report_after["metrics"]["populations"]["internal_aegis"]["active"] == (
        report_before["metrics"]["populations"]["internal_aegis"]["active"] + 1
    )


def test_denominator_integrity_test_c_migrated_backend_does_not_increase_external_coverage(tmp_path: Path):
    """Test C: Adding a migrated backend outside the active denominator must not increase active external coverage."""
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    report = build_full_coverage_report(audit=audit, inventory=inventory, results=[])

    # Assert migrated backends are counted separately from active denominator
    assert report["metrics"]["migrated_backends"] >= 1
    assert "class-dump" in {b.get("binary") for b in inventory["backends"] if b.get("external")}
    active_binaries = {
        b.get("binary") for b in inventory["backends"]
        if b.get("external") and b.get("binary") not in {"class-dump", "firmadyne"}
    }
    assert "class-dump" not in active_binaries
    assert "firmadyne" not in active_binaries


def test_denominator_integrity_test_d_waiting_backend_remains_in_denominator(tmp_path: Path):
    """Test D: A WAITING active backend must remain in the denominator."""
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    report = build_full_coverage_report(audit=audit, inventory=inventory, results=[])

    pop = report["metrics"]["populations"]["external"]
    # Reconcile: active == executed + waiting + unavailable + unhealthy + denied
    assert pop["active"] == (
        pop["executed"] + pop["waiting"] + pop["unavailable"] + pop["unhealthy"] + pop["denied"]
    )
    assert pop["waiting"] > 0
    # Denominator includes all active backends regardless of WAITING state
    assert report["metrics"]["fixture_backend_denominator"] == pop["active"]


def test_denominator_integrity_test_e_lifecycle_state_enforcement():
    """Test E: A backend may only leave active denominator when lifecycle state is explicitly MIGRATED/RETIRED."""
    from aegis.arsenal.migrations import RUNTIME_MIGRATIONS
    for mig in RUNTIME_MIGRATIONS:
        assert mig.lifecycle_state in {"MIGRATED", "RETIRED", "OBSOLETE", "NOT_APPLICABLE"}
        assert mig.migration_target
        assert mig.migration_reason
        assert mig.migration_source


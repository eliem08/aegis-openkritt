from datetime import UTC, datetime

from aegis.ai.tool_runtime import ToolRuntimeRecord, ToolRuntimeStatus
from aegis.arsenal.audit import build_audit
from aegis.arsenal.backend_report import (
    build_backend_inventory,
    build_full_coverage_report,
    build_tool_lock,
)
from aegis.arsenal.models import ArsenalCoverageState, ExecutionProofKind


class HealthyRuntime:
    def inspect(self, *, name, binary, version_override="", refresh=False):
        return ToolRuntimeRecord(
            name, binary, f"/tools/{binary}", "tool 1.2.3", "a" * 64,
            ToolRuntimeStatus.READY, "healthy", datetime.now(UTC).isoformat(),
        )


def test_backend_inventory_groups_capabilities_by_physical_binary(tmp_path):
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    trivy = next(item for item in inventory["backends"] if item["backend_id"] == "external:trivy")

    assert {"tool:trivy/deps", "tool:trivy/secrets"}.issubset(trivy["capability_ids"])
    assert trivy["capability_count"] >= 2
    assert trivy["runtime"]["resolved_path"] == "/tools/trivy"
    assert inventory["metrics"]["unique_external_backend_count"] < len(audit.definitions)


def test_tool_lock_contains_only_resolved_external_executables(tmp_path):
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    lock = build_tool_lock(inventory, image_digest="sha256:" + "a" * 64)

    assert lock["tools"]
    assert all(item["executable_path"].startswith("/tools/") for item in lock["tools"])
    assert all(item["container_digest"].startswith("sha256:") for item in lock["tools"])


def test_full_report_keeps_capability_and_backend_denominators_distinct(tmp_path):
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    results = [{
        "capability_id": "tool:trivy/deps",
        "result": ArsenalCoverageState.EXECUTED_PASS.value,
        "run_id": "run-1",
        "evidence_digest": "b" * 64,
        "summary": {
            "execution_proof_kind": ExecutionProofKind.REAL_BACKEND.value,
            "execution_performed": True,
            "fixture_detection": True,
            "negative_control_passed": True,
            "covered_capability_ids": [
                "tool:trivy/deps", "asset:trivy/filesystem-security-scan",
            ],
        },
    }]

    report = build_full_coverage_report(
        audit=audit, inventory=inventory, results=results,
        image_digest="sha256:" + "c" * 64,
    )

    assert report["metrics"]["fixture_executed_capabilities"] == 2
    assert report["metrics"]["fixture_executed_backends"] == 1
    assert report["metrics"]["fixture_capability_denominator"] >= 1
    assert report["metrics"]["fixture_backend_denominator"] >= 1
    assert report["metrics"]["authorized_real_execution_coverage"] is None
    assert report["verdict"] == "FIXTURE ARSENAL PARTIALLY VERIFIED"


def test_full_report_does_not_credit_mock_execution(tmp_path):
    audit = build_audit(runs_dir=tmp_path, runtime_manager=HealthyRuntime())
    inventory = build_backend_inventory(audit, runtime_manager=HealthyRuntime())
    report = build_full_coverage_report(
        audit=audit,
        inventory=inventory,
        results=[{
            "capability_id": "tool:trivy/deps",
            "result": ArsenalCoverageState.EXECUTED_PASS.value,
            "summary": {
                "execution_proof_kind": ExecutionProofKind.UNIT_MOCK.value,
                "execution_performed": True,
                "fixture_detection": True,
                "negative_control_passed": True,
            },
        }],
    )

    assert report["metrics"]["fixture_executed_backends"] == 0
    assert report["metrics"]["fixture_executed_capabilities"] == 0

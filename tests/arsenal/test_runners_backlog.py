import json

from aegis.arsenal.backlog import build_never_executed_backlog
from aegis.arsenal.runners import (
    RUNNER_PROFILES,
    backend_runtime_id,
    runner_profile_for_binary,
    runner_readiness,
)


def test_runtime_identity_and_runner_mapping_are_stable():
    assert backend_runtime_id("analyzeHeadless") == "ghidra/headless"
    assert backend_runtime_id("forge") == "foundry/forge"
    assert runner_profile_for_binary("nmap") == "arsenal-network-lab"
    assert runner_profile_for_binary("otool") == "arsenal-macos-ios"
    assert runner_profile_for_binary("semgrep") == "arsenal-linux"


def test_runner_readiness_lists_all_required_profiles(monkeypatch):
    monkeypatch.delenv("AEGIS_CLOUD_LAB_AUTHORIZATION", raising=False)
    document = runner_readiness(
        backend_runtimes={"arsenal-network-lab": ("nmap/network-lab",)},
        executable_runtimes={"arsenal-network-lab": ()},
    )
    names = {item["runner_profile"] for item in document["profiles"]}
    assert names == {item.runner_profile for item in RUNNER_PROFILES}
    cloud = next(
        item for item in document["profiles"]
        if item["runner_profile"] == "arsenal-cloud-lab"
    )
    assert cloud["status"] == "WAITING_FOR_PREREQUISITE"
    assert "environment:AEGIS_CLOUD_LAB_AUTHORIZATION" in cloud["missing_prerequisites"]
    network = next(
        item for item in document["profiles"]
        if item["runner_profile"] == "arsenal-network-lab"
    )
    assert network["status"] == "WAITING_FOR_PREREQUISITE"
    assert network["backend_runtimes_not_yet_executed"] == ["nmap/network-lab"]


def test_backlog_is_derived_from_inventory_and_evidence():
    inventory = {
        "backends": [{
            "backend_id": "external:example",
            "backend_runtime_id": "example/linux-cli",
            "external": True,
            "binary": "example",
            "capability_ids": ["asset:example/check"],
            "fixture_executable_capabilities": ["asset:example/check"],
            "expected_versions": ["1.2.3"],
            "executor_providers": ["executor"],
            "fixture_providers": ["fixture"],
            "implementation_paths": ["src/aegis/parser.py"],
            "runtime": {
                "status": "unavailable", "resolved_path": "", "version": "",
                "reason": "binary not found",
            },
            "current_state": "UNAVAILABLE",
            "prerequisite": "",
        }],
    }
    coverage = {
        "never_executed_backend_ids": ["external:example"],
        "executions": [{
            "capability_id": "asset:example/check", "result": "UNAVAILABLE",
            "summary": {"blocking_reason": "fixture runner missing"},
        }],
    }
    backlog = build_never_executed_backlog(inventory, coverage)
    assert backlog["metrics"]["backlog_count"] == 1
    row = backlog["backends"][0]
    assert row["backend_runtime_id"] == "example/linux-cli"
    assert row["exact_failure"] == "fixture runner missing"
    assert row["missing_runtime"] is True
    assert row["estimated_closure_class"] == "A"
    assert row["installation_required"] is True
    assert row["fixture_required"] is False
    assert row["parser_required"] is False
    assert "install and pin runtime" in row["remediation"]
    json.dumps(backlog)


def test_executed_backend_is_removed_from_backlog():
    inventory = {
        "backends": [{
            "backend_id": "external:example", "external": True, "binary": "example",
            "capability_ids": ["asset:example/check"],
            "runtime": {"status": "ready", "resolved_path": "/bin/example"},
        }],
    }
    coverage = {"executions": [{
        "capability_id": "asset:example/check", "result": "EXECUTED_PASS",
    }]}
    assert build_never_executed_backlog(inventory, coverage)["backends"] == []

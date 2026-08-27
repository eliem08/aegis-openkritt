"""Real local scanner fixture execution through the canonical mission runtime."""

from __future__ import annotations

import secrets
import tempfile
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

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
from aegis.ai.tool_bridge import ToolBridge
from aegis.ai.tool_registry import TOOLS
from aegis.ai.tool_runtime import ToolRuntimeManager
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

from .exercise import ExerciseResult
from .fixture_authority import (
    LOCAL_FIXTURE_ONLY,
    LocalFixtureSignatureVerifier,
    signed_fixture_authorization,
)
from .inventory import ArsenalInventoryBuilder
from .ledger import CoverageRepository
from .models import ArsenalCoverageState, CapabilityCoverageRecord, CapabilityMode

TOOL_FIXTURE_CAPABILITY = "jarvis:arsenal:tool-fixture"

_POSITIVE_FIXTURES = {
    "app.py": "import os\ndef unsafe(value):\n    return os.system(value)\n",
    "app.js": "const cp=require('child_process'); module.exports=x=>cp.exec(x);\n",
    "main.go": "package main\nimport (\"os/exec\")\nfunc main(){exec.Command(\"sh\",\"-c\",\"input\").Run()}\n",
    "unsafe.php": "<?php $pdo->query(\"SELECT * FROM users WHERE id=\".$_GET['id']);\n",
    "Unsafe.sol": (
        "pragma solidity ^0.8.0; contract Unsafe { mapping(address=>uint) b; "
        "function w() public {(bool ok,)=msg.sender.call{value:b[msg.sender]}(''); "
        "require(ok); b[msg.sender]=0;} }\n"
    ),
    "main.tf": (
        "resource \"aws_s3_bucket\" \"x\" { bucket=\"aegis-fixture\" }\n"
        "resource \"aws_s3_bucket_public_access_block\" \"x\" { "
        "bucket=aws_s3_bucket.x.id block_public_acls=false }\n"
    ),
    "package.json": (
        '{"name":"aegis-positive-fixture","version":"1.0.0",'
        '"dependencies":{"lodash":"4.17.19"}}\n'
    ),
    "Gemfile.lock": "GEM\n  specs:\n    rails (5.2.0)\nDEPENDENCIES\n  rails (= 5.2.0)\n",
}
_NEGATIVE_FIXTURES = {
    "app.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
    "app.js": "module.exports=(left,right)=>left+right;\n",
    "main.go": 'package main\nimport "fmt"\nfunc main(){fmt.Println("fixture")}\n',
    "safe.php": "<?php function add(int $a,int $b): int { return $a+$b; }\n",
    "Safe.sol": (
        "pragma solidity ^0.8.0; contract Safe { function add(uint a,uint b) "
        "public pure returns(uint){return a+b;} }\n"
    ),
    "main.tf": 'terraform { required_version = ">= 1.5.0" }\n',
    "package.json": '{"name":"aegis-negative-fixture","version":"1.0.0"}\n',
}


def _materialize_builtin_fixtures() -> tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory(prefix="aegis-arsenal-fixture-")
    root = Path(temporary.name)
    for control, documents in (("positive", _POSITIVE_FIXTURES),
                               ("negative", _NEGATIVE_FIXTURES)):
        directory = root / control
        directory.mkdir()
        for name, content in documents.items():
            (directory / name).write_text(content, encoding="utf-8")
    return temporary, root


def _definition(capability_id: str):
    matches = [
        item for item in ArsenalInventoryBuilder().build()
        if item.capability_id == capability_id and item.capability_id.startswith("tool:")
    ]
    if len(matches) != 1 or not matches[0].tool_backends:
        raise ValueError(f"unknown tool fixture capability: {capability_id}")
    return matches[0]


class _ToolFixtureProvider:
    def __init__(self, *, capability_id: str, tool_name: str, bridge: ToolBridge,
                 positive: Path, negative: Path) -> None:
        self.capability_id = capability_id
        self.tool_name = tool_name
        self.bridge = bridge
        self.positive = positive
        self.negative = negative

    def runtime_executors(self):
        def execute(task, plan, authorization):
            grant = authorization.grant
            constraints = dict(grant.constraints if grant else {})
            if (
                grant is None
                or constraints.get("authorization_class") != LOCAL_FIXTURE_ONLY
                or constraints.get("capability_id") != self.capability_id
            ):
                raise PermissionError("tool fixture grant is missing or bound to another capability")
            tool = next(item for item in TOOLS if item.name == self.tool_name)
            positive = self.bridge.scan(str(self.positive), tools=[tool])[0]
            negative = self.bridge.scan(str(self.negative), tools=[tool])[0]
            return {
                "tool": self.tool_name,
                "positive": {
                    "ran": positive.ran, "finding_count": len(positive.findings),
                    "error": positive.error, "runtime": positive.runtime,
                },
                "negative": {
                    "ran": negative.ran, "finding_count": len(negative.findings),
                    "error": negative.error, "runtime": negative.runtime,
                },
                "fixture_detection": bool(positive.findings),
                "negative_control_passed": negative.ran and not negative.findings,
            }

        return {TOOL_FIXTURE_CAPABILITY: execute}


def execute_tool_fixture(
    capability_id: str,
    *,
    runs_dir: str | Path,
    coverage_repository: CoverageRepository | None = None,
    bridge: ToolBridge | None = None,
    fixture_root: str | Path | None = None,
) -> ExerciseResult:
    definition = _definition(capability_id)
    backend = definition.tool_backends[0]
    temporary = None
    if fixture_root:
        root = Path(fixture_root)
    else:
        temporary, root = _materialize_builtin_fixtures()
    positive, negative = root / "positive", root / "negative"
    if not positive.is_dir() or not negative.is_dir():
        raise FileNotFoundError("both positive and negative scanner fixture directories are required")

    raw = HmacSignatureVerifier({
        "fixture-auth": secrets.token_bytes(32), "grant": secrets.token_bytes(32),
    })
    verifier = LocalFixtureSignatureVerifier(raw)
    authorization = signed_fixture_authorization(verifier)
    policy_engine = PolicyEngine(authorization=authorization, verifier=verifier)
    decision = policy_engine.authorize(ActionRequest(
        target="127.0.0.1", action="source_analysis", tier_hint=ConsequenceTier.PASSIVE,
        description=f"local fixture exercise for {capability_id}", touches_production=False,
        request_id=f"arsenal:{capability_id}",
    ))
    if not decision.allowed:
        raise PermissionError("PolicyEngine denied the local scanner fixture")
    scope_document = {"assets": ["127.0.0.1"], "network_isolation": "loopback-only"}
    scope_digest = document_digest(scope_document)
    grant = mint_execution_grant(
        decision, scope_digest=scope_digest, budget=Budget(), verifier=verifier,
        constraints={
            "authorization_class": LOCAL_FIXTURE_ONLY, "capability_id": capability_id,
            "positive_fixture_digest": document_digest({"path": str(positive.resolve())}),
            "negative_fixture_digest": document_digest({"path": str(negative.resolve())}),
        },
    )
    now = datetime.now(UTC)
    suffix = sha256(f"{capability_id}:{now.isoformat()}:{grant.nonce}".encode()).hexdigest()[:12]
    run_id = f"arsenal-{now.strftime('%Y%m%dT%H%M%SZ')}-{suffix[:8]}"
    mission_id, task_id = f"arsenal-tool-{suffix}", f"arsenal-tool-{suffix}-execute"
    policy_snapshot = {
        "authorization_class": LOCAL_FIXTURE_ONLY, "permitted_actions": ["source_analysis"],
        "prohibited_real_targets": True,
    }
    store = ImmutableRunStore(runs_dir)
    store.create(OperatorRunManifest(
        1, run_id, RunMode.ARSENAL_FIXTURE, now.isoformat(), "local-fixture-operator",
        "aegis-local-fixtures", "built-in deterministic fixtures", ("127.0.0.1",), None, (),
        policy_snapshot, document_digest(policy_snapshot), scope_document, scope_digest,
        {"capabilities": [capability_id]},
        RunBudgets(1, 1.0, 0.0, max_duration_seconds=1200, max_attempts=1),
        authorization.model_dump(mode="json"),
    ))
    store.append_event(run_id, "arsenal_fixture_authorized", RunStatus.AUTHORIZED, {
        "capability_id": capability_id, "policy_decision": decision.as_dict(),
        "grant": grant._payload(),
    })
    task = MissionTask(
        task_id, "reproduction", "execute_scanner_fixture",
        payload={"authorization_class": LOCAL_FIXTURE_ONLY, "capability_id": capability_id},
        opportunity_id=f"fixture-opp-{suffix}", asset_id="fixture:source-code",
        asset_kind="source_code", asset_locator="127.0.0.1",
        executor_capability=TOOL_FIXTURE_CAPABILITY, risk="offline", expected_cost_usd=0.0,
        evidence_required=("positive_fixture", "negative_control"),
        idempotency_key=f"{mission_id}:{task_id}",
    )
    plan = MissionPlan(
        mission_id, scope_digest, f"Exercise {capability_id} against local controls", (task,),
        opportunity_id=task.opportunity_id, program_id="aegis-local-fixtures",
        asset_id=task.asset_id, asset_kind=task.asset_kind,
        authorization_id=authorization.authorization_id,
    )
    state_store = JarvisStateStore(":memory:")
    scheduler = MissionScheduler(state_store)
    provider = _ToolFixtureProvider(
        capability_id=capability_id, tool_name=backend.tool_name,
        bridge=bridge or ToolBridge(
            timeout=300, runtime_manager=ToolRuntimeManager(version_timeout=15.0),
        ), positive=positive, negative=negative,
    )
    runtime = UniversalMissionRuntime(
        scheduler, grant_verifier=verifier,
        workers=MissionWorkerRegistry((WorkerCapability(
            TOOL_FIXTURE_CAPABILITY, ExecutionClass.INTERNAL_EXECUTOR,
            asset_kinds=("source_code",), risk_classes=("offline",),
        ),)), executor_providers=(provider,),
    )
    plan = scheduler.create(plan)
    store.append_event(run_id, "arsenal_task_started", RunStatus.RUNNING, {
        "capability_id": capability_id, "mission_id": mission_id, "task_id": task_id,
    })
    execution = runtime.execute_first(
        plan, authorization=AuthorizationEnvelope(scope_digest, budget=Budget(), grant=grant),
        availability=CapabilityAvailability(artifact_available=True),
    )
    summary = dict(execution.outcome or {})
    actually_ran = bool(summary.get("positive", {}).get("ran")) and bool(
        summary.get("negative", {}).get("ran")
    )
    result_state = (
        ArsenalCoverageState.EXECUTED_PASS if actually_ran
        else ArsenalCoverageState.BACKEND_UNHEALTHY
    )
    negative_status = (
        "PASSED" if summary.get("negative_control_passed")
        else "FAILED" if actually_ran else "NOT_RUN"
    )
    evidence = {
        "kind": "arsenal_tool_fixture_execution", "capability_id": capability_id,
        "mode": CapabilityMode.FIXTURE.value, "run_id": run_id, "mission_id": mission_id,
        "task_id": task_id, "policy_decision": decision.as_dict(),
        "execution_grant_payload": grant._payload(), "runtime_disposition": execution.disposition.value,
        "runtime_reason": execution.reason, "summary": summary,
        "negative_control_status": negative_status, "execution_performed": actually_ran,
    }
    evidence_ref, evidence_digest = store.persist_evidence(run_id, evidence)
    store.append_event(run_id, "arsenal_task_completed", RunStatus.COMPLETED, {
        "capability_id": capability_id, "mode": CapabilityMode.FIXTURE.value,
        "mission_id": mission_id, "task_id": task_id, "backend": backend.tool_name,
        "backend_version": str(summary.get("positive", {}).get("runtime", {}).get("version", "")),
        "policy_snapshot_digest": document_digest(policy_snapshot), "asset": "127.0.0.1",
        "authorization_decision": decision.request_id or "", "execution_grant_id": grant.nonce,
        "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
        "result": result_state.value, "negative_control_status": negative_status,
        "finding_ids": [], "fixture_detection": bool(summary.get("fixture_detection")),
    })
    recorded, degraded = False, coverage_repository is None
    if coverage_repository is not None:
        record = CapabilityCoverageRecord(
            f"acr:{sha256((run_id + task_id).encode()).hexdigest()[:24]}",
            f"arsenal:{run_id}:{task_id}", capability_id, CapabilityMode.FIXTURE,
            backend.tool_name, str(summary.get("positive", {}).get("runtime", {}).get("version", "")),
            definition.technique_ids[0] if definition.technique_ids else "", ("source_code",),
            definition.implementation_paths[0], backend.backend_id, backend.adapter_version,
            "HEALTHY" if actually_ran else "UNHEALTHY", document_digest(policy_snapshot),
            "127.0.0.1", decision.request_id or "", None, grant.nonce, run_id, mission_id,
            task_id, actually_ran, now.isoformat() if actually_ran else None,
            evidence_digest if actually_ran else None, result_state, (),
            "" if actually_ran else str(summary.get("positive", {}).get("error", execution.reason)),
            None if actually_ran else "TOOL_CRASH", negative_status,
        )
        try:
            _, recorded = coverage_repository.record(record)
        except Exception as exc:
            degraded = True
            store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
                "error_class": type(exc).__name__, "execution_result_remains_canonical": True,
            })
    if coverage_repository is None:
        store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
            "error_class": "CoverageRepositoryUnavailable",
            "execution_result_remains_canonical": True,
        })
    store.verify(run_id)
    state_store.close()
    result = ExerciseResult(
        run_id, mission_id, task_id, capability_id, result_state, evidence_ref, evidence_digest,
        recorded, degraded, summary,
    )
    if temporary is not None:
        temporary.cleanup()
    return result


__all__ = ["execute_tool_fixture"]
